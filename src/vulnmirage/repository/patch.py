"""Deterministic patch generation and patch application."""

from __future__ import annotations

import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..errors import RepositoryError
from ..hashing import atomic_write_text, sha256_file, sha256_text
from ..paths import ensure_within
from .git import git_output, run_git, tree_hash


class ChangedFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    status: str
    old_path: str | None = None


class PatchArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patch_file: str
    patch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    base_tree_sha256: str = Field(pattern=r"^[0-9a-f]{40}$")
    variant_tree_sha256: str = Field(pattern=r"^[0-9a-f]{40}$")
    files_changed: list[ChangedFile] = Field(default_factory=list)
    stats: dict[str, int] = Field(default_factory=dict)
    patch_text: str | None = None

    @property
    def paths(self) -> list[str]:
        return sorted({item.path for item in self.files_changed})


def _parse_name_status(raw: str) -> list[ChangedFile]:
    parts = [item for item in raw.split("\x00") if item]
    files: list[ChangedFile] = []
    index = 0
    while index < len(parts):
        status = parts[index]
        if index + 1 >= len(parts):
            break
        first = parts[index + 1].replace("\\", "/")
        if status.startswith(("R", "C")):
            if index + 2 >= len(parts):
                break
            second = parts[index + 2].replace("\\", "/")
            files.append(ChangedFile(path=second, status=status[0], old_path=first))
            index += 3
        else:
            files.append(ChangedFile(path=first, status=status[0]))
            index += 2
    return sorted(files, key=lambda item: item.path)


def create_patch_artifact(repo_root: Path) -> PatchArtifact:
    """Compute the worktree-vs-HEAD diff without writing a file."""
    repo_root = Path(repo_root).resolve()
    base_tree = git_output(["rev-parse", "HEAD^{tree}"], cwd=repo_root)
    with tempfile.TemporaryDirectory(prefix="vulnmirage-diff-") as temporary:
        env = {"GIT_INDEX_FILE": str(Path(temporary) / "index")}
        run_git(["read-tree", "HEAD"], cwd=repo_root, extra_env=env)
        run_git(["add", "-A", "--", "."], cwd=repo_root, extra_env=env, timeout=300)
        diff = run_git(
            ["diff", "--cached", "--no-color", "--no-ext-diff", "--binary", "HEAD"],
            cwd=repo_root,
            extra_env=env,
            timeout=300,
        ).stdout
        raw_name_status = run_git(
            ["diff", "--cached", "--name-status", "-z", "HEAD"],
            cwd=repo_root,
            extra_env=env,
            timeout=300,
        ).stdout
        variant_tree = git_output(["write-tree"], cwd=repo_root)
    stats = {"files": len(_parse_name_status(raw_name_status)), "lines": len(diff.splitlines())}
    return PatchArtifact(
        patch_file="",
        patch_sha256=sha256_text(diff),
        base_tree_sha256=base_tree,
        variant_tree_sha256=variant_tree,
        files_changed=_parse_name_status(raw_name_status),
        stats=stats,
        patch_text=diff,
    )


def write_patch_artifact(artifact: PatchArtifact, patch_path: Path) -> PatchArtifact:
    patch_path = Path(patch_path)
    text = artifact.patch_text or ""
    atomic_write_text(patch_path, text)
    return artifact.model_copy(
        update={
            "patch_file": patch_path.as_posix(),
            "patch_sha256": sha256_file(patch_path),
            "patch_text": None,
        }
    )


def generate_patch(repo_root: Path, patch_path: Path) -> PatchArtifact:
    """Write a unified diff of the worktree against HEAD and hash both trees."""
    artifact = create_patch_artifact(repo_root)
    return write_patch_artifact(artifact, patch_path)


def apply_patch(repo_root: Path, patch_path: Path) -> None:
    repo_root = Path(repo_root).resolve()
    patch_path = Path(patch_path).resolve()
    if not repo_root.is_dir():
        raise RepositoryError("repository root does not exist", details={"repo": str(repo_root)})
    if not patch_path.is_file():
        raise RepositoryError("patch file does not exist", details={"patch": str(patch_path)})
    check = run_git(
        ["apply", "--check", "--whitespace=nowarn", str(patch_path)],
        cwd=repo_root,
        check=False,
        timeout=300,
    )
    if check.returncode != 0:
        raise RepositoryError(
            "patch does not apply cleanly to the repository",
            details={"patch": str(patch_path), "stderr": check.stderr[-4000:]},
        )
    run_git(
        ["apply", "--whitespace=nowarn", str(patch_path)],
        cwd=repo_root,
        timeout=300,
    )


def patch_sha256(path: Path) -> str:
    return sha256_file(Path(path))


def ensure_patch_inside(patch_file: Path, instance_dir: Path) -> Path:
    return ensure_within(instance_dir, patch_file, must_exist=True)
