"""Isolated git worktrees; the cache repository is never checked out in place."""

from __future__ import annotations

import shutil
from pathlib import Path

from ..errors import RepositoryError, UnsafePathError
from ..paths import ensure_within
from .git import current_head, run_git


def create_worktree(
    cache_repo: Path,
    commit: str,
    destination: Path,
    *,
    worktrees_root: Path,
    force: bool = False,
) -> Path:
    """Create a detached worktree at ``destination`` from ``cache_repo``."""
    cache_repo = Path(cache_repo).resolve()
    destination = Path(destination)
    destination = destination if destination.is_absolute() else (Path.cwd() / destination)
    destination = destination.resolve()
    worktrees_root = Path(worktrees_root).resolve()
    ensure_within(worktrees_root, destination)
    if destination == cache_repo or cache_repo in destination.parents:
        raise RepositoryError(
            "refusing to create a worktree inside the cache repository",
            details={"cache": str(cache_repo), "destination": str(destination)},
        )
    if destination.exists():
        if not force:
            raise RepositoryError(
                "worktree destination already exists",
                details={"destination": str(destination)},
            )
        remove_path(destination, worktrees_root=worktrees_root)
        run_git(["worktree", "prune"], cwd=cache_repo, check=False, timeout=120)
    destination.parent.mkdir(parents=True, exist_ok=True)
    run_git(
        ["worktree", "add", "--detach", str(destination), commit],
        cwd=cache_repo,
        timeout=1800,
    )
    head = current_head(destination)
    if head.lower() != commit.lower():
        raise RepositoryError(
            "worktree HEAD does not match the requested commit",
            details={"expected": commit, "actual": head},
        )
    return destination


def remove_path(path: Path, *, worktrees_root: Path) -> None:
    """Delete a directory only if it is inside the managed worktrees root."""
    path = Path(path).resolve()
    worktrees_root = Path(worktrees_root).resolve()
    try:
        ensure_within(worktrees_root, path)
    except UnsafePathError as exc:
        raise RepositoryError(
            "refusing to delete a path outside the worktrees root",
            details={"path": str(path), "root": str(worktrees_root)},
            cause=exc,
        ) from exc
    if path == worktrees_root:
        raise RepositoryError("refusing to delete the worktrees root")
    if path.exists():
        shutil.rmtree(path)


def remove_worktree(cache_repo: Path, destination: Path, *, worktrees_root: Path) -> None:
    destination = Path(destination).resolve()
    ensure_within(Path(worktrees_root), destination)
    proc = run_git(
        ["worktree", "remove", "--force", str(destination)],
        cwd=Path(cache_repo),
        check=False,
        timeout=300,
    )
    if proc.returncode != 0:
        remove_path(destination, worktrees_root=worktrees_root)
        run_git(["worktree", "prune"], cwd=Path(cache_repo), check=False, timeout=120)


def prune_worktrees(cache_repo: Path) -> None:
    run_git(["worktree", "prune"], cwd=Path(cache_repo), check=False, timeout=120)
