"""Repository integrity checks: commit, worktree tree hashes and patch hashes."""

from __future__ import annotations

import time

from ..hashing import sha256_file, utc_now_iso
from ..models import CheckStatus
from ..repository.cache import RepositoryCache
from ..repository.git import git_output, is_git_repository, status_porcelain, tree_hash, worktree_digest
from ..store import InstanceStore
from .context import ValidationContext, new_started, result


def check_repository_integrity(ctx: ValidationContext):
    started = new_started()
    began = time.monotonic()
    errors: list[str] = []
    details: dict[str, object] = {}
    repo = ctx.repo
    if not repo.is_dir() or not is_git_repository(repo):
        return result(
            "repository_integrity",
            CheckStatus.FAIL,
            started,
            time.monotonic() - began,
            details={"errors": ["worktree is not a git repository"], "repo": str(repo)},
        )
    head = git_output(["rev-parse", "HEAD"], cwd=repo)
    head_tree = git_output(["rev-parse", "HEAD^{tree}"], cwd=repo)
    details.update({"head": head, "head_tree": head_tree})
    if head.lower() != ctx.instance.repository.vulnerable_commit.lower():
        errors.append("worktree HEAD does not match the manifest commit")
    if ctx.state.base_tree_sha256 and head_tree != ctx.state.base_tree_sha256:
        errors.append("HEAD tree does not match the recorded base tree")
    calculated_tree = tree_hash(repo)
    details["variant_tree_sha256"] = calculated_tree
    if ctx.state.variant_tree_sha256 and calculated_tree != ctx.state.variant_tree_sha256:
        errors.append("worktree tree hash differs from the recorded variant tree")
    calculated_digest = worktree_digest(repo)
    details["repository_tree_sha256"] = calculated_digest
    if calculated_digest != ctx.instance.repository_tree_sha256:
        errors.append("worktree content digest differs from the instance manifest")

    status = status_porcelain(repo)
    details["dirty"] = status
    if ctx.is_clean and status:
        errors.append("clean worktree is not clean")

    if not ctx.is_clean:
        patch_path = ctx.store.resolve_artifact(ctx.instance.patch_file or "")
        if not patch_path.is_file():
            errors.append("patch file is missing")
        else:
            digest = sha256_file(patch_path)
            details["patch_sha256"] = digest
            if ctx.state.patch_sha256 and digest != ctx.state.patch_sha256:
                errors.append("patch file hash differs from the recorded patch hash")

    cache_path_value = ctx.state.notes.get("cache_path")
    if cache_path_value and ctx.state.cache_refs_sha256:
        cache_path = ctx.state.notes.get("cache_path")
        try:
            cache = RepositoryCache(
                ctx.loaded.paths.cache, ctx.config.network
            )
            from pathlib import Path

            snapshot = cache.refs_snapshot(Path(str(cache_path)))
            details["cache_refs_sha256"] = snapshot
            if snapshot != ctx.state.cache_refs_sha256:
                errors.append("cached repository refs changed after materialization")
        except Exception as exc:  # noqa: BLE001
            details["cache_check_error"] = str(exc)
            errors.append(f"could not verify cache integrity: {exc}")

    duration = time.monotonic() - began
    return result(
        "repository_integrity",
        CheckStatus.PASS if not errors else CheckStatus.FAIL,
        started,
        duration,
        details={"errors": errors, **details},
    )
