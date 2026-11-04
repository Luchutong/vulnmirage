"""Exact-commit source archives instead of clones.

Why this module exists
----------------------
A clone -- even a ``--depth 1`` clone of one commit -- gives the audited agent a
Git object store.  Future commits, other branches and the *fix* commit are then
reachable with ``git log``/``git cat-file``, which is an answer channel that no
prompt-level rule can close.  The benchmark therefore materializes a repository
snapshot from the hosting provider's **archive endpoint for one commit**:

* the archive is fetched once, pinned by commit and cached by content hash;
* only file content is unpacked -- there is no ``.git`` directory;
* nested history (submodules copied as repositories, vendored ``.git``) is
  detected and reported rather than silently trusted;
* extraction is bounded and refuses traversal, absolute paths, links and device
  entries, so a hostile archive cannot write outside the snapshot root.

Identity is recorded twice on purpose: the archive's byte digest pins the exact
download, and the normalized tree digest pins the *content*.  A provider that
re-packs the same commit changes the former and not the latter; a repository that
moves changes neither.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from pydantic import BaseModel, ConfigDict, Field

from ..config import ArchiveProviderConfig, ExtractionLimitsConfig
from ..errors import RepositoryError
from ..hashing import atomic_write_json, sha256_file, utc_now_iso
from ..paths import ensure_within, normalize_relpath

ARCHIVE_SCHEMA_VERSION = "1.0"

#: Directories/files that mean "this snapshot carries version history".
_HISTORY_MARKERS = (".git", ".svn", ".hg", ".bzr", ".gitmodules.bak")

_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


# --------------------------------------------------------------------------- models
class ArchiveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    slug: str
    commit: str
    url: str
    host: str
    source_id: str


class ArchiveDownload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = ARCHIVE_SCHEMA_VERSION
    provider: str
    source_id: str
    commit: str
    requested_url: str
    final_url: str
    redirect_chain: list[str] = Field(default_factory=list)
    host: str
    http_status: int
    content_type: str | None = None
    bytes: int
    sha256: str
    downloaded_at: str = Field(default_factory=utc_now_iso)
    reused_cache: bool = False


class ExtractionRejection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entry: str
    reason: str


class ExtractionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = ARCHIVE_SCHEMA_VERSION
    root: str
    strip_prefix: str | None = None
    file_count: int
    total_bytes: int
    directories: int = 0
    tree_sha256: str
    rejected: list[ExtractionRejection] = Field(default_factory=list)
    truncated: bool = False
    limits: dict[str, object] = Field(default_factory=dict)
    extracted_at: str = Field(default_factory=utc_now_iso)


# ----------------------------------------------------------------------- provider
def parse_repo_url(repo_url: str) -> tuple[str, str, str]:
    """Return ``(host, owner, name)`` from an https repository URL."""
    parsed = urllib.parse.urlparse(repo_url.strip())
    if parsed.scheme not in {"https", "http"}:
        raise RepositoryError(
            "repository URL must be http(s)", details={"repo_url": repo_url}
        )
    host = (parsed.hostname or "").lower()
    parts = [item for item in parsed.path.split("/") if item]
    if len(parts) < 2:
        raise RepositoryError(
            "repository URL does not contain owner/name", details={"repo_url": repo_url}
        )
    name = parts[-1]
    if name.endswith(".git"):
        name = name[: -len(".git")]
    owner = "/".join(parts[:-1])
    return host, owner, name


def resolve_archive_request(
    repo_url: str,
    commit: str,
    *,
    provider: ArchiveProviderConfig | None = None,
) -> ArchiveRequest:
    """Build the archive request for one exact commit.

    Unsupported providers raise instead of guessing a URL: downloading the wrong
    ref and calling it the snapshot is worse than failing the task.
    """
    config = provider or ArchiveProviderConfig()
    commit = (commit or "").strip()
    if not commit:
        raise RepositoryError("commit is required to resolve an archive")
    if config.name in {"local_zip", "local_tree"}:
        # Local fixtures: the "repository URL" is a path on this machine.
        candidate = Path(repo_url)
        if not candidate.is_absolute():
            candidate = (Path.cwd() / candidate).resolve()
        if config.name == "local_zip" and not candidate.is_file():
            raise RepositoryError(
                "local_zip provider needs an existing archive", details={"path": str(candidate)}
            )
        if config.name == "local_tree" and not candidate.is_dir():
            raise RepositoryError(
                "local_tree provider needs an existing directory", details={"path": str(candidate)}
            )
        slug = candidate.name or "fixture"
        return ArchiveRequest(
            provider=config.name,
            slug=slug,
            commit=commit,
            url=candidate.as_uri(),
            host="local",
            source_id=f"{slug}@{commit[:12]}",
        )
    host, owner, name = parse_repo_url(repo_url)
    slug = f"{owner}/{name}"
    if config.name == "github":
        if host not in {"github.com", "www.github.com"}:
            raise RepositoryError(
                "github archive provider cannot serve this host",
                details={"host": host, "repo_url": repo_url},
            )
        url = f"https://codeload.github.com/{owner}/{name}/zip/{commit}"
        archive_host = "codeload.github.com"
    elif config.name == "gitlab":
        if "gitlab" not in host:
            raise RepositoryError(
                "gitlab archive provider cannot serve this host",
                details={"host": host, "repo_url": repo_url},
            )
        url = f"https://{host}/{owner}/{name}/-/archive/{commit}/{name}-{commit}.zip"
        archive_host = host
    elif config.name == "local_zip":
        # ``repo_url`` is reused as the local archive location for fixtures.
        candidate = Path(repo_url)
        if not candidate.is_absolute():
            candidate = (Path.cwd() / candidate).resolve()
        url = candidate.as_uri()
        archive_host = "local"
    elif config.name == "local_tree":
        candidate = Path(repo_url)
        if not candidate.is_absolute():
            candidate = (Path.cwd() / candidate).resolve()
        url = candidate.as_uri()
        archive_host = "local"
    else:  # pragma: no cover - guarded by the config literal
        raise RepositoryError("unsupported archive provider", details={"provider": config.name})
    return ArchiveRequest(
        provider=config.name,
        slug=slug,
        commit=commit,
        url=url,
        host=archive_host,
        source_id=f"{slug.replace('/', '_')}@{commit[:12]}",
    )


def source_cache_key(request: ArchiveRequest) -> str:
    """Content-addressed cache key: repository slug + exact commit."""
    digest = hashlib.sha256(f"{request.slug}\x1f{request.commit}".encode()).hexdigest()
    safe_slug = request.slug.replace("/", "_")[:64]
    return f"{safe_slug}-{digest[:12]}"


# ---------------------------------------------------------------------- download
@dataclass(frozen=True)
class TransportResponse:
    status: int
    final_url: str
    redirect_chain: tuple[str, ...]
    content_type: str | None
    path: Path


#: ``transport(url, destination, *, timeout, max_bytes, max_redirects, verify_tls)``
ArchiveTransport = Callable[..., TransportResponse]


class _AllowlistRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str], max_redirects: int) -> None:
        super().__init__()
        self.allowed_hosts = allowed_hosts
        self.max_redirects = max_redirects
        self.chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102, ANN001
        host = (urllib.parse.urlparse(newurl).hostname or "").lower()
        if host not in self.allowed_hosts:
            raise RepositoryError(
                "archive redirect targets a host outside the allowlist",
                details={"host": host, "allowed": sorted(self.allowed_hosts)},
            )
        if len(self.chain) >= self.max_redirects:
            raise RepositoryError(
                "archive download exceeded the redirect budget",
                details={"max_redirects": self.max_redirects, "chain": self.chain},
            )
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def urllib_transport(
    url: str,
    destination: Path,
    *,
    timeout: float,
    max_bytes: int,
    max_redirects: int,
    verify_tls: bool,
    allowed_hosts: Iterable[str] = (),
) -> TransportResponse:
    """Stream ``url`` to ``destination`` with a hard byte ceiling."""
    allowed = {item.lower() for item in allowed_hosts}
    handler = _AllowlistRedirectHandler(allowed or {(urllib.parse.urlparse(url).hostname or "")}, max_redirects)
    opener = urllib.request.build_opener(handler)
    request = urllib.request.Request(url, headers={"User-Agent": "vulnmirage-archive/1.0"})
    written = 0
    try:
        with opener.open(request, timeout=timeout) as response:  # noqa: S310 - scheme validated
            status = int(getattr(response, "status", 200))
            final_url = response.geturl()
            content_type = response.headers.get("Content-Type")
            with destination.open("wb") as handle:
                while True:
                    chunk = response.read(256 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_bytes:
                        raise RepositoryError(
                            "archive exceeds the configured byte budget",
                            details={"max_bytes": max_bytes},
                        )
                    handle.write(chunk)
    except urllib.error.HTTPError as exc:
        raise RepositoryError(
            "archive download returned an HTTP error",
            details={"url": url, "status": exc.code},
        ) from exc
    except urllib.error.URLError as exc:
        raise RepositoryError(
            "archive download failed", details={"url": url, "error": str(exc.reason)}
        ) from exc
    return TransportResponse(
        status=status,
        final_url=final_url,
        redirect_chain=tuple(handler.chain),
        content_type=content_type,
        path=destination,
    )


def _file_transport(
    url: str,
    destination: Path,
    *,
    timeout: float,
    max_bytes: int,
    max_redirects: int,
    verify_tls: bool,
    allowed_hosts: Iterable[str] = (),
) -> TransportResponse:
    """Local-file transport used by fixtures and by ``local_zip`` providers."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"file", ""}:
        raise RepositoryError("local transport only serves file URLs", details={"url": url})
    source = Path(urllib.request.url2pathname(parsed.path)) if parsed.scheme == "file" else Path(url)
    if not source.is_file():
        raise RepositoryError("local archive does not exist", details={"path": str(source)})
    if source.stat().st_size > max_bytes:
        raise RepositoryError(
            "local archive exceeds the configured byte budget",
            details={"bytes": source.stat().st_size, "max_bytes": max_bytes},
        )
    shutil.copyfile(source, destination)
    return TransportResponse(
        status=200,
        final_url=source.as_uri(),
        redirect_chain=(),
        content_type="application/zip",
        path=destination,
    )


def _looks_like_zip(path: Path) -> bool:
    with path.open("rb") as handle:
        head = handle.read(4)
    return head in _ZIP_MAGIC


def download_archive(
    request: ArchiveRequest,
    destination: Path,
    *,
    provider: ArchiveProviderConfig | None = None,
    transport: ArchiveTransport | None = None,
) -> ArchiveDownload:
    """Download one exact-commit archive and verify what actually arrived."""
    config = provider or ArchiveProviderConfig()
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + ".part")
    if partial.exists():
        partial.unlink()

    local = request.provider in {"local_zip"}
    chosen = transport or (_file_transport if local else urllib_transport)
    last_error: Exception | None = None
    response: TransportResponse | None = None
    for attempt in range(config.retries + 1):
        try:
            response = chosen(
                request.url,
                partial,
                timeout=float(config.timeout_seconds),
                max_bytes=config.max_bytes,
                max_redirects=config.max_redirects,
                verify_tls=config.verify_tls,
                allowed_hosts=tuple(config.allowed_hosts) + tuple([request.host]),
            )
            break
        except RepositoryError as exc:
            last_error = exc
            if partial.exists():
                partial.unlink()
            if attempt >= config.retries:
                raise
    if response is None:  # pragma: no cover - defensive
        raise RepositoryError("archive download produced no response", details={"url": request.url})

    size = partial.stat().st_size
    if size == 0:
        partial.unlink()
        raise RepositoryError("archive download is empty", details={"url": request.url})
    if size > config.max_bytes:
        partial.unlink()
        raise RepositoryError(
            "archive exceeds the configured byte budget",
            details={"bytes": size, "max_bytes": config.max_bytes},
        )
    if not _looks_like_zip(partial):
        partial.unlink()
        raise RepositoryError(
            "downloaded payload is not a zip archive",
            details={"url": request.url, "content_type": response.content_type},
        )
    digest = sha256_file(partial)
    os.replace(partial, destination)
    return ArchiveDownload(
        provider=request.provider,
        source_id=request.source_id,
        commit=request.commit,
        requested_url=request.url,
        final_url=response.final_url,
        redirect_chain=list(response.redirect_chain),
        host=(urllib.parse.urlparse(response.final_url).hostname or request.host),
        http_status=response.status,
        content_type=response.content_type,
        bytes=size,
        sha256=digest,
    )


# ------------------------------------------------------------------- extraction
def _entry_kind(member: zipfile.ZipInfo) -> str:
    mode = member.external_attr >> 16
    if member.is_dir() or member.filename.endswith("/"):
        return "dir"
    if mode and stat.S_ISLNK(mode):
        return "symlink"
    if mode and (stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode)):
        return "device"
    return "file"


def _normalize_entry(name: str) -> str:
    text = name.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return normalize_relpath(text)


def _common_prefix(names: list[str]) -> str | None:
    """Return the single top-level directory, if every entry lives under it.

    Hosting providers ship an explicit directory entry for that root
    (``repo-<sha>/``), which normalizes to a bare name with no separator.  A listing
    of ``{repo-<sha>, repo-<sha>/lib/x.ex}`` is still one rooted snapshot, so a bare
    entry equal to the candidate prefix must not defeat the strip: leaving it in
    place buries every path one level deep, and then every oracle location resolves
    to "file not found" while looking like a clean extraction.
    """
    nested = [name for name in names if "/" in name]
    if not nested:
        return None
    firsts = {name.split("/", 1)[0] for name in nested}
    if len(firsts) != 1:
        return None
    prefix = firsts.pop()
    for name in names:
        if name == prefix:
            continue
        if not name.startswith(prefix + "/"):
            return None
    return prefix


def safe_extract(
    archive_path: Path,
    destination: Path,
    *,
    limits: ExtractionLimitsConfig | None = None,
) -> ExtractionResult:
    """Unpack an untrusted archive into ``destination`` with a hard budget.

    Every rejected entry is recorded; the extraction continues so that one hostile
    member cannot hide the rest of the snapshot, and the caller decides whether a
    rejection blocks the run.
    """
    config = limits or ExtractionLimitsConfig()
    archive_path = Path(archive_path)
    destination = Path(destination)
    if destination.exists():
        ensure_within(destination.parent, destination)
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)

    rejections: list[ExtractionRejection] = []
    planned: list[tuple[zipfile.ZipInfo, str, str]] = []
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        if len(members) > config.max_files * 2:
            raise RepositoryError(
                "archive declares more entries than the file budget allows",
                details={"entries": len(members), "max_files": config.max_files},
            )
        normalized: list[str] = []
        for member in members:
            kind = _entry_kind(member)
            if kind in {"symlink", "device"}:
                rejections.append(
                    ExtractionRejection(entry=member.filename, reason=f"{kind} entry rejected")
                )
                continue
            try:
                relative = _normalize_entry(member.filename)
            except Exception as exc:  # UnsafePathError
                rejections.append(
                    ExtractionRejection(entry=member.filename, reason=str(exc))
                )
                continue
            if relative.count("/") + 1 > config.max_path_depth:
                rejections.append(
                    ExtractionRejection(entry=member.filename, reason="path depth budget exceeded")
                )
                continue
            normalized.append(relative)
            planned.append((member, relative, kind))

        strip_prefix = _common_prefix(sorted(normalized)) if config.strip_single_root else None

        seen: set[str] = set()
        files = 0
        total = 0
        directories = 0
        for member, relative, kind in planned:
            target_rel = relative
            if strip_prefix and target_rel == strip_prefix:
                # the root directory entry itself: it is the prefix, not content
                continue
            if strip_prefix and target_rel.startswith(strip_prefix + "/"):
                target_rel = target_rel[len(strip_prefix) + 1 :]
            if not target_rel:
                continue
            key = target_rel.lower()
            if key in seen:
                rejections.append(
                    ExtractionRejection(
                        entry=member.filename,
                        reason="case-insensitive path collision with another entry",
                    )
                )
                continue
            seen.add(key)
            target = destination.joinpath(*target_rel.split("/"))
            if not str(target.resolve(strict=False)).startswith(
                str(destination.resolve(strict=False))
            ):
                rejections.append(
                    ExtractionRejection(entry=member.filename, reason="entry escapes the root")
                )
                continue
            if kind == "dir":
                target.mkdir(parents=True, exist_ok=True)
                directories += 1
                continue
            files += 1
            if files > config.max_files:
                raise RepositoryError(
                    "archive exceeds the entry budget",
                    details={"max_files": config.max_files},
                )
            if member.file_size > config.max_file_bytes:
                rejections.append(
                    ExtractionRejection(
                        entry=member.filename,
                        reason=f"file size {member.file_size} exceeds {config.max_file_bytes}",
                    )
                )
                files -= 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with archive.open(member) as source, target.open("wb") as handle:
                while True:
                    chunk = source.read(256 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > config.max_file_bytes:
                        raise RepositoryError(
                            "archive member exceeded the per-file budget while expanding",
                            details={"entry": member.filename, "max_file_bytes": config.max_file_bytes},
                        )
                    total += len(chunk)
                    if total > config.max_total_bytes:
                        raise RepositoryError(
                            "archive exceeded the total byte budget while expanding",
                            details={"max_total_bytes": config.max_total_bytes},
                        )
                    handle.write(chunk)
            mode = (member.external_attr >> 16) & 0o777
            if mode:
                try:
                    os.chmod(target, mode | 0o600)
                except OSError:  # pragma: no cover - platform dependent
                    pass

    return ExtractionResult(
        root=destination.as_posix(),
        strip_prefix=strip_prefix,
        file_count=files,
        total_bytes=total,
        directories=directories,
        tree_sha256=tree_digest(destination),
        rejected=rejections,
        limits={
            "max_files": config.max_files,
            "max_total_bytes": config.max_total_bytes,
            "max_file_bytes": config.max_file_bytes,
            "max_path_depth": config.max_path_depth,
            "strip_single_root": config.strip_single_root,
        },
    )


# ----------------------------------------------------------------- tree identity
def _iter_tree(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_dir():
            continue
        yield path


def tree_digest(root: Path, *, exclude_dirs: Iterable[str] = _HISTORY_MARKERS) -> str:
    """Canonical content digest of a snapshot tree (path + bytes, order-stable)."""
    root = Path(root)
    excluded = set(exclude_dirs)
    digest = hashlib.sha256()
    for path in _iter_tree(root):
        relative = path.relative_to(root)
        if excluded.intersection(relative.parts):
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\x00")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\x00")
        digest.update(str(path.stat().st_size).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def find_history_metadata(root: Path) -> list[str]:
    """Return every snapshot path that carries version history."""
    root = Path(root)
    found: list[str] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.name in _HISTORY_MARKERS:
            found.append(path.relative_to(root).as_posix())
    return found


def copy_snapshot_tree(source: Path, destination: Path) -> str:
    """Copy an already-unpacked snapshot (``local_tree`` provider / fixtures)."""
    source = Path(source)
    destination = Path(destination)
    if not source.is_dir():
        raise RepositoryError("snapshot source directory does not exist", details={"path": str(source)})
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, symlinks=False)
    return tree_digest(destination)


# ------------------------------------------------------------------------ cache
class ArchiveCache:
    """One directory per (repository, commit); never keyed by branch or tag."""

    def __init__(self, root: Path, config: ArchiveConfigLike | None = None) -> None:
        self.root = Path(root)
        self.config = config

    def entry_dir(self, request: ArchiveRequest) -> Path:
        path = self.root / source_cache_key(request)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def archive_path(self, request: ArchiveRequest) -> Path:
        return self.entry_dir(request) / f"{request.commit}.zip"

    def record_path(self, request: ArchiveRequest) -> Path:
        return self.entry_dir(request) / "download.json"

    def tree_dir(self, request: ArchiveRequest) -> Path:
        return self.entry_dir(request) / "tree"

    def load_record(self, request: ArchiveRequest) -> ArchiveDownload | None:
        path = self.record_path(request)
        if not path.is_file():
            return None
        import json

        try:
            return ArchiveDownload.model_validate(json.loads(path.read_text(encoding="utf-8")))
        except Exception:  # pragma: no cover - corrupt cache entry
            return None

    def store_record(self, request: ArchiveRequest, record: ArchiveDownload) -> Path:
        path = self.record_path(request)
        atomic_write_json(path, record)
        return path


class ArchiveConfigLike:  # pragma: no cover - typing helper
    provider: ArchiveProviderConfig
    limits: ExtractionLimitsConfig


__all__ = [
    "ARCHIVE_SCHEMA_VERSION",
    "ArchiveDownload",
    "ArchiveCache",
    "ArchiveRequest",
    "ExtractionRejection",
    "ExtractionResult",
    "copy_snapshot_tree",
    "download_archive",
    "find_history_metadata",
    "parse_repo_url",
    "resolve_archive_request",
    "safe_extract",
    "source_cache_key",
    "tree_digest",
    "urllib_transport",
]
