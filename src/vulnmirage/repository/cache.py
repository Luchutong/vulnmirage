"""Read-only bare repository cache with explicit fetch and domain allowlisting."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

from ..config import NetworkConfig
from ..errors import RepositoryError
from ..hashing import safe_slug, sha256_text, stable_id
from ..locking import FileLock
from .git import commit_exists, git_output, is_git_repository, run_git

_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class NormalizedRepository:
    original_url: str
    kind: str  # "local" | "remote"
    canonical: str
    clone_url: str
    host: str | None


def _strip_git_suffix(path: str) -> str:
    return path[:-4] if path.endswith(".git") else path


def _looks_like_windows_path(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:[\\/]", value)) or value.startswith("\\\\")


def _local_path(url: str) -> Path | None:
    if url.startswith("file://"):
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc.lower() not in {"", "localhost"}:
            raise RepositoryError(
                "file:// URLs with a remote host are not supported",
                details={"repo_url": url},
            )
        path = unquote(parsed.path)
        if os.name == "nt" and re.match(r"^/[A-Za-z]:", path):
            path = path[1:]
        return Path(path)
    if _looks_like_windows_path(url):
        return Path(url)
    if url.startswith("/") or url.startswith("./") or url.startswith("../"):
        return Path(url)
    if Path(url).exists():
        return Path(url)
    return None


def normalize_repository_url(url: str, network: NetworkConfig) -> NormalizedRepository:
    raw = url.strip()
    if not raw or any(char in raw for char in "\r\n\x00"):
        raise RepositoryError("repository URL is empty or contains control characters")

    local = _local_path(raw)
    if local is not None:
        if not network.allow_local_repositories:
            raise RepositoryError(
                "local repositories are disabled by configuration",
                details={"repo_url": raw},
            )
        resolved = local.expanduser()
        if not resolved.is_absolute():
            resolved = (Path.cwd() / resolved).resolve()
        if not resolved.exists():
            raise RepositoryError(
                "local repository path does not exist",
                details={"repo_url": raw, "path": str(resolved)},
            )
        return NormalizedRepository(
            original_url=raw,
            kind="local",
            canonical=f"local:{resolved.as_posix()}",
            clone_url=resolved.as_uri(),
            host=None,
        )

    parsed = urlparse(raw)
    if parsed.scheme not in {"https"}:
        raise RepositoryError(
            "only https and local repository URLs are supported in v0.1",
            details={"repo_url": raw, "scheme": parsed.scheme or None},
        )
    if parsed.username or parsed.password:
        raise RepositoryError(
            "credentials in repository URLs are not allowed; use a credential helper",
            details={"repo_url": raw.split("@")[-1]},
        )
    if not parsed.hostname:
        raise RepositoryError("repository URL has no host", details={"repo_url": raw})
    host = parsed.hostname.lower()
    allowed = network.allowed_clone_domains
    if not any(host == domain or host.endswith("." + domain) for domain in allowed):
        raise RepositoryError(
            "repository host is not in network.allowed_clone_domains",
            details={"host": host, "allowed": allowed},
        )
    path = _strip_git_suffix(parsed.path.rstrip("/"))
    if not path or path == "/":
        raise RepositoryError("repository URL has no path", details={"repo_url": raw})
    canonical = f"https://{host}{path}".lower()
    return NormalizedRepository(
        original_url=raw,
        kind="remote",
        canonical=canonical,
        clone_url=raw,
        host=host,
    )


class RepositoryCache:
    def __init__(self, root: Path, network: NetworkConfig) -> None:
        self.root = Path(root)
        self.network = network

    def _ensure_enabled(self) -> None:
        if not self.network.materialization_enabled:
            raise RepositoryError(
                "repository materialization is disabled by network.materialization_enabled"
            )

    def cache_path(self, repo: NormalizedRepository) -> Path:
        key = sha256_text(repo.canonical)
        slug = safe_slug(repo.canonical.replace("https://", "").replace("local:", "local-"))
        return self.root / f"{slug[:36]}-{key[:12]}.git"

    def ensure(self, url: str, *, fetch: bool = False) -> tuple[NormalizedRepository, Path]:
        self._ensure_enabled()
        repo = normalize_repository_url(url, self.network)
        path = self.cache_path(repo)
        self.root.mkdir(parents=True, exist_ok=True)
        lock_path = path.with_name(path.name + ".lock")
        with FileLock(lock_path):
            if not path.exists():
                self._clone(repo, path)
            else:
                self._verify_bare(path)
                if fetch:
                    self._fetch(path, repo)
        return repo, path

    def _verify_bare(self, path: Path) -> None:
        proc = run_git(["rev-parse", "--is-bare-repository"], cwd=path, check=False, timeout=30)
        if proc.returncode != 0 or proc.stdout.strip() != "true":
            raise RepositoryError(
                "repository cache entry is not a bare git repository",
                details={"cache_path": str(path)},
            )

    def _clone(self, repo: NormalizedRepository, destination: Path) -> None:
        temp_parent = destination.parent
        temp_dir = Path(
            tempfile.mkdtemp(prefix=f".{destination.name}.clone-", dir=str(temp_parent))
        )
        try:
            run_git(
                ["clone", "--mirror", "--", repo.clone_url, str(temp_dir / "repo.git")],
                timeout=1800,
            )
            cloned = temp_dir / "repo.git"
            self._verify_bare(cloned)
            if destination.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
                return
            os.replace(cloned, destination)
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _fetch(self, path: Path, repo: NormalizedRepository) -> None:
        run_git(["fetch", "--prune", "origin"], cwd=path, timeout=1800)

    def verify_commit(self, path: Path, commit: str) -> None:
        if not _COMMIT_RE.match(commit):
            raise RepositoryError(
                "commit must be a full 40-character hexadecimal hash",
                details={"commit": commit},
            )
        if not commit_exists(path, commit):
            raise RepositoryError(
                "vulnerable commit is not present in the cached repository; "
                "fetch explicitly with a fresh cache or verify the commit hash",
                details={"commit": commit, "cache_path": str(path)},
            )

    def refs_snapshot(self, path: Path) -> str:
        output = git_output(
            ["for-each-ref", "--format=%(refname) %(objectname)"],
            cwd=path,
        )
        return sha256_text(output)


def cache_key_for_url(url: str) -> str:
    return stable_id("REPO", url, length=12).split("-", 1)[1]
