"""Safe, argv-only git subprocess wrapper.

No command in this module ever uses a shell.  Commands that can mutate or push
to a *remote* repository are rejected before a process is spawned.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..errors import RepositoryError

FORBIDDEN_GIT_SUBCOMMANDS = {
    "push",
    "pull",
    "request-pull",
    "send-email",
    "submodule",
    "credential",
    "daemon",
    "upload-pack",
    "receive-pack",
    "filter-branch",
    "filter-repo",
    "replace",
}

# ``git remote add/set-url/remove`` would let a benchmark run rewrite where a
# cached repository points; generation never needs this.
_FORBIDDEN_REMOTE_SUBCOMMANDS = {"add", "set-url", "remove", "rm", "rename", "prune"}

_GIT_ENV_ALLOWLIST = [
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "SYSTEMDRIVE",
]


def git_executable() -> str:
    executable = shutil.which("git")
    if not executable:
        raise RepositoryError("git executable not found on PATH")
    return executable


def _git_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env: dict[str, str] = {}
    for key in _GIT_ENV_ALLOWLIST:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "echo",
            "GIT_PAGER": "cat",
            "LC_ALL": os.environ.get("LC_ALL", "C"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_ADVICE": "0",
        }
    )
    if extra:
        env.update(extra)
    return env


def _first_non_option(args: Sequence[str]) -> str | None:
    for arg in args:
        if not arg.startswith("-"):
            return arg
    return None


def _strip_global_options(args: Sequence[str]) -> list[str]:
    """Return arguments after git's global ``-c``/``-C`` style options."""
    remaining = list(args)
    index = 0
    while index < len(remaining):
        arg = remaining[index]
        if arg in {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}:
            index += 2
            continue
        if arg.startswith(("--git-dir=", "--work-tree=", "--namespace=", "--exec-path=")):
            index += 1
            continue
        break
    return remaining[index:]


def _check_command(args: Sequence[str]) -> None:
    effective = _strip_global_options(args)
    subcommand = _first_non_option(effective)
    if subcommand is None:
        return
    if subcommand in FORBIDDEN_GIT_SUBCOMMANDS:
        raise RepositoryError(
            f"git subcommand {subcommand!r} is forbidden (remote-write safety policy)",
            details={"git_args": list(args)},
        )
    if subcommand == "remote":
        rest = effective[list(effective).index("remote") + 1 :]
        action = _first_non_option(rest)
        if action in _FORBIDDEN_REMOTE_SUBCOMMANDS:
            raise RepositoryError(
                f"git remote {action!r} is forbidden",
                details={"git_args": list(args)},
            )
    if subcommand == "config":
        # Reject global/system config writes; local config reads are fine.
        for flag in ("--global", "--system"):
            if flag in args:
                raise RepositoryError(
                    f"git config {flag} is forbidden",
                    details={"git_args": list(args)},
                )


def run_git(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: int = 120,
    check: bool = True,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run git without a shell and return the completed process."""
    _check_command(args)
    # Force LF worktrees so generated patches are portable across developer
    # machines with core.autocrlf enabled.  Long paths help deep workspaces on
    # Windows without weakening any path checks.
    argv = [
        git_executable(),
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.eol=lf",
        "-c",
        "core.safecrlf=false",
        "-c",
        "core.longpaths=true",
        *args,
    ]
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            env=_git_env(extra_env),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RepositoryError(
            f"git command timed out after {timeout}s",
            details={"git_args": list(args)},
            cause=exc,
        ) from exc
    except OSError as exc:
        raise RepositoryError(
            f"failed to execute git: {exc}",
            details={"git_args": list(args)},
            cause=exc,
        ) from exc
    if check and proc.returncode != 0:
        raise RepositoryError(
            "git command failed",
            details={
                "git_args": list(args),
                "cwd": str(cwd) if cwd else None,
                "exit_code": proc.returncode,
                "stderr": (proc.stderr or "")[-4000:],
            },
        )
    return proc


def git_output(args: Sequence[str], *, cwd: Path | None = None, timeout: int = 120) -> str:
    return run_git(args, cwd=cwd, timeout=timeout).stdout.strip()


def is_git_repository(path: Path) -> bool:
    if not Path(path).exists():
        return False
    proc = run_git(
        ["rev-parse", "--is-inside-work-tree"],
        cwd=Path(path),
        check=False,
        timeout=30,
    )
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def current_head(repo: Path) -> str:
    return git_output(["rev-parse", "HEAD"], cwd=repo)


def commit_exists(repo: Path, commit: str) -> bool:
    proc = run_git(["cat-file", "-e", f"{commit}^{{commit}}"], cwd=repo, check=False, timeout=30)
    return proc.returncode == 0


def status_porcelain(repo: Path) -> list[tuple[str, str]]:
    """Return ``(status, path)`` entries for both sides of renames."""
    proc = run_git(["status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=repo)
    raw = proc.stdout
    if not raw:
        return []
    parts = raw.split("\x00")
    entries: list[tuple[str, str]] = []
    index = 0
    while index < len(parts):
        item = parts[index]
        if not item:
            index += 1
            continue
        status = item[:2]
        path = item[3:] if len(item) > 3 else item
        entries.append((status.strip(), path.replace("\\", "/")))
        if "R" in status or "C" in status:
            if index + 1 < len(parts) and parts[index + 1]:
                entries.append((status.strip(), parts[index + 1].replace("\\", "/")))
                index += 1
        index += 1
    return sorted(entries)


def tree_hash(repo: Path, *, include_untracked: bool = True) -> str:
    """Hash the staged tree without touching the worktree's real index."""
    import tempfile

    with tempfile.TemporaryDirectory(prefix="vulnmirage-index-") as temporary:
        index_path = Path(temporary) / "index"
        env = {"GIT_INDEX_FILE": str(index_path)}
        run_git(["read-tree", "HEAD"], cwd=repo, extra_env=env)
        if include_untracked:
            run_git(["add", "-A", "--", "."], cwd=repo, extra_env=env, timeout=300)
        return git_output(["write-tree"], cwd=repo)


def worktree_digest(repo: Path) -> str:
    """Stable digest of every visible file except ``.git``.

    This catches unauthorized writes that ``git status`` would hide (e.g. files
    matched by ``.gitignore``).
    """
    import hashlib

    root = Path(repo).resolve()
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if ".git" in path.relative_to(root).parts:
            continue
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        if path.is_symlink():
            digest.update(b"symlink:")
            digest.update(os.readlink(path).encode("utf-8", "replace"))
        elif path.is_file():
            digest.update(b"file:")
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
        elif path.is_dir():
            digest.update(b"dir")
        digest.update(b"\x00")
    return digest.hexdigest()


def list_files(repo: Path) -> list[str]:
    proc = run_git(["ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=repo)
    return sorted(item.replace("\\", "/") for item in proc.stdout.split("\x00") if item)


def show_file(repo: Path, relative: str, *, commit: str | None = None) -> str:
    args = ["show", f"{commit}:{relative}"] if commit else ["show", f"HEAD:{relative}"]
    return run_git(args, cwd=repo).stdout
