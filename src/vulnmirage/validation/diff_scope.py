"""Diff-scope enforcement: every change must stay in allowed paths."""

from __future__ import annotations

import time
from pathlib import PurePosixPath

from ..models import CheckStatus
from ..paths import is_safe_relpath
from ..repository.git import status_porcelain
from .context import ValidationContext, new_started, result

_FORBIDDEN_FILENAMES = {
    "oracle.json",
    "validation.json",
    "manipulation.json",
    "decoys.json",
    "state.json",
    "instance.json",
}


def check_diff_scope(ctx: ValidationContext):
    started = new_started()
    began = time.monotonic()
    errors: list[str] = []
    status = status_porcelain(ctx.repo)
    changed_paths = sorted({path for _, path in status})
    details: dict[str, object] = {
        "changed_paths": changed_paths,
        "status": [{"status": code, "path": path} for code, path in status],
    }
    if ctx.is_clean:
        if changed_paths:
            errors.append("clean instance has uncommitted changes")
        return result(
            "diff_scope",
            CheckStatus.PASS if not errors else CheckStatus.FAIL,
            started,
            time.monotonic() - began,
            details={"errors": errors, **details},
        )

    if ctx.manipulation is None and not ctx.is_benign:
        errors.append("adversarial instance has no manipulation spec")
        allowed: set[str] = set()
    elif ctx.manipulation is not None:
        allowed = set(ctx.manipulation.files_touched)
    else:
        # Benign structural controls carry no manipulation; their scope is the
        # recorded patch plan.
        meta = ctx.patch_meta or {}
        allowed = set(meta.get("allowed_paths", []))
        if not allowed:
            errors.append("benign control has no recorded allowed paths")
    details["allowed_paths"] = sorted(allowed)
    for path in changed_paths:
        if not is_safe_relpath(path):
            errors.append(f"unsafe changed path: {path}")
        if path not in allowed:
            errors.append(f"change outside allowed_paths: {path}")
        name = PurePosixPath(path).name
        if name in _FORBIDDEN_FILENAMES:
            errors.append(f"reserved benchmark file written into the repository: {path}")
        if ".git" in PurePosixPath(path).parts:
            errors.append(f"git metadata was modified: {path}")

    patch_meta = ctx.patch_meta
    if patch_meta is None:
        errors.append("patch metadata (patch_meta.json) is missing")
    else:
        patch_paths = sorted({item["path"] for item in patch_meta.get("files_changed", [])})
        details["patch_paths"] = patch_paths
        if patch_paths != changed_paths:
            errors.append("worktree changes do not match the recorded patch")
        for path in patch_paths:
            if path not in allowed:
                errors.append(f"recorded patch path outside allowed_paths: {path}")

    duration = time.monotonic() - began
    return result(
        "diff_scope",
        CheckStatus.PASS if not errors else CheckStatus.FAIL,
        started,
        duration,
        details={"errors": errors, **details},
    )
