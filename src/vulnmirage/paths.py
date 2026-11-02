"""Path normalization and containment checks.

Every file written by an operator or harness goes through :func:`safe_join`.
The check operates on the *resolved* path so a symlink cannot escape the
intended root.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .errors import UnsafePathError

_WINDOWS_DRIVE_RE = r"^[A-Za-z]:"
_FORBIDDEN_PARTS = {".git"}


def project_root() -> Path:
    """Return the checkout/installation root that contains ``prompts/`` etc."""
    return Path(__file__).resolve().parents[2]


def normalize_relpath(path: str | Path) -> str:
    """Normalize a repository-relative path to POSIX form and validate it."""
    if isinstance(path, Path):
        raw = path.as_posix()
    else:
        raw = str(path)
    if "\x00" in raw:
        raise UnsafePathError("path contains NUL byte", details={"path": raw})
    raw = raw.replace("\\", "/")
    if raw.startswith("/") or raw.startswith("//"):
        raise UnsafePathError("absolute paths are not allowed", details={"path": raw})
    if len(raw) >= 2 and raw[1] == ":" and raw[0].isalpha():
        raise UnsafePathError("Windows drive paths are not allowed", details={"path": raw})
    parts: list[str] = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise UnsafePathError("parent traversal ('..') is not allowed", details={"path": raw})
        parts.append(part)
    if not parts:
        raise UnsafePathError("path is empty after normalization", details={"path": raw})
    return PurePosixPath(*parts).as_posix()


def is_safe_relpath(path: str) -> bool:
    try:
        normalize_relpath(path)
    except UnsafePathError:
        return False
    return True


def _resolved_under(root: Path, candidate: Path) -> bool:
    try:
        root_resolved = root.resolve(strict=True)
    except OSError:
        root_resolved = root.resolve(strict=False)
    try:
        candidate_resolved = candidate.resolve(strict=False)
    except OSError:
        candidate_resolved = candidate.absolute()
    root_cmp = os.path.normcase(str(root_resolved))
    cand_cmp = os.path.normcase(str(candidate_resolved))
    try:
        return os.path.commonpath([root_cmp, cand_cmp]) == root_cmp
    except ValueError:  # different drives on Windows
        return False


def safe_join(root: Path, relative: str | Path, *, allow_git: bool = False) -> Path:
    """Join ``relative`` under ``root`` or raise :class:`UnsafePathError`."""
    rel = normalize_relpath(relative)
    parts = PurePosixPath(rel).parts
    if not allow_git and any(part in _FORBIDDEN_PARTS for part in parts):
        raise UnsafePathError("paths inside .git are protected", details={"path": rel})
    root = Path(root)
    candidate = root.joinpath(*parts)
    # Check the deepest existing ancestor for symlink escapes, then the full path.
    if not _resolved_under(root, candidate):
        raise UnsafePathError(
            "resolved path escapes the allowed root",
            details={"path": rel, "root": str(root)},
        )
    return candidate


def ensure_within(root: Path, candidate: Path, *, must_exist: bool = False) -> Path:
    """Validate that an already-constructed path is inside ``root``."""
    candidate = Path(candidate)
    if must_exist and not candidate.exists():
        raise UnsafePathError("path does not exist", details={"path": str(candidate)})
    if not _resolved_under(Path(root), candidate):
        raise UnsafePathError(
            "path escapes the expected root",
            details={"path": str(candidate), "root": str(root)},
        )
    return candidate


def posix_relative(path: Path, root: Path) -> str:
    return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()


def windows_long_path(path: Path) -> str:
    """Return a path string usable with Windows APIs when >260 chars.

    ``\\\\?\\`` prefixes require an absolute, normalized path.
    """
    text = str(Path(path).resolve())
    if os.name == "nt" and len(text) >= 240 and not text.startswith("\\\\?\\"):
        return "\\\\?\\" + text
    return text


@dataclass(frozen=True)
class WorkspacePaths:
    root: Path
    cache: Path
    normalized: Path
    worktrees: Path
    instances: Path
    runs: Path
    reports: Path
    logs: Path
    releases: Path
    quarantine: Path

    @classmethod
    def from_config(cls, workspace_root: str | Path, repo_cache: str | Path) -> "WorkspacePaths":
        root = Path(workspace_root).expanduser()
        if not root.is_absolute():
            root = (Path.cwd() / root).resolve()
        cache = Path(repo_cache).expanduser()
        if not cache.is_absolute():
            cache = (Path.cwd() / cache).resolve()
        return cls(
            root=root,
            cache=cache,
            normalized=root / "normalized",
            worktrees=root / "worktrees",
            instances=root / "instances",
            runs=root / "runs",
            reports=root / "reports",
            logs=root / "logs",
            releases=root / "releases",
            quarantine=root / "quarantine",
        )

    def ensure_layout(self) -> None:
        for path in (
            self.root,
            self.cache,
            self.normalized,
            self.worktrees,
            self.instances,
            self.runs,
            self.reports,
            self.logs,
            self.releases,
            self.quarantine,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def instance_dir(self, instance_id: str) -> Path:
        return safe_join(self.instances, instance_id)

    def instance_worktree(self, instance_id: str) -> Path:
        return self.worktrees / instance_id / "repo"

    def run_dir(self, run_id: str) -> Path:
        return safe_join(self.runs, run_id)

    def as_dict(self) -> dict[str, str]:
        return {
            "root": self.root.as_posix(),
            "cache": self.cache.as_posix(),
            "normalized": self.normalized.as_posix(),
            "worktrees": self.worktrees.as_posix(),
            "instances": self.instances.as_posix(),
            "runs": self.runs.as_posix(),
            "reports": self.reports.as_posix(),
            "logs": self.logs.as_posix(),
            "releases": self.releases.as_posix(),
            "quarantine": self.quarantine.as_posix(),
        }
