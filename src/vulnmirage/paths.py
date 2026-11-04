"""Path normalization and containment checks.

Every file written by an operator or harness goes through :func:`safe_join`.
The check operates on the *resolved* path so a symlink cannot escape the
intended root.
"""

from __future__ import annotations

import os
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
