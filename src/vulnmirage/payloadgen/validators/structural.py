"""Structural validation: the edit can be applied, exactly once, inside the tree.

A payload that silently fails to apply produces a "variant" identical to the clean
tree, and the experiment then compares C with C while calling it an attack.  Every
check here exists to make that outcome impossible rather than unlikely.
"""

from __future__ import annotations

from pathlib import Path

from ...errors import UnsafePathError
from ...paths import normalize_relpath
from ..contracts import ValidatorResult
from .base import ValidationInputs

_PROTECTED_ROLES = {"vendor", "generated", "config"}
_PROTECTED_NAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
}


def _fail(reason: str, **evidence: object) -> ValidatorResult:
    return ValidatorResult(
        validator="structural", status="fail", required=True, reason=reason, evidence=dict(evidence)
    )


def validate(inputs: ValidationInputs) -> ValidatorResult:
    candidate = inputs.candidate
    context = inputs.context
    text = candidate.rendered_text
    if not text.strip():
        return _fail("payload renders to an empty string")
    if candidate.target_file is None:
        return _fail("payload has no target file")
    try:
        relative = normalize_relpath(candidate.target_file)
    except UnsafePathError as exc:
        return _fail("target path is unsafe", detail=str(exc), path=candidate.target_file)
    if relative != candidate.target_file:
        return _fail("target path is not normalized", path=candidate.target_file)

    if candidate.estimated_files > context.budget.max_files_changed:
        return _fail(
            "payload changes more files than the tier budget allows",
            files=candidate.estimated_files,
            budget=context.budget.max_files_changed,
        )
    if candidate.estimated_lines > context.budget.max_inserted_lines:
        return _fail(
            "payload inserts more lines than the tier budget allows",
            lines=candidate.estimated_lines,
            budget=context.budget.max_inserted_lines,
        )
    if len(text) > context.budget.max_payload_chars:
        return _fail(
            "payload is larger than the tier budget allows",
            chars=len(text),
            budget=context.budget.max_payload_chars,
        )

    root = inputs.repo_root
    if root is not None:
        role = context.index.role_of(relative) if context.index else "other"
        if role in _PROTECTED_ROLES:
            return _fail("target file is in a protected area of the repository", role=role, path=relative)
        if Path(relative).name in _PROTECTED_NAMES:
            return _fail("target file is a lockfile", path=relative)
        target = Path(root) / relative
        if candidate.edit_op == "create":
            if target.exists():
                return _fail("create targets an existing path", path=relative)
        else:
            if not target.is_file():
                return _fail("append/insert targets a missing file", path=relative)
            if candidate.edit_op == "insert_before":
                if not candidate.anchor:
                    return _fail("insert_before has no anchor", path=relative)
                body = target.read_text(encoding="utf-8", errors="replace")
                occurrences = body.count(candidate.anchor)
                if occurrences != 1:
                    return _fail(
                        "anchor is not unique in the target file",
                        path=relative,
                        occurrences=occurrences,
                    )
    return ValidatorResult(
        validator="structural",
        status="pass",
        required=True,
        reason="the edit applies to one safe path with a unique anchor",
        evidence={"path": relative, "op": candidate.edit_op},
    )


__all__ = ["validate"]
