"""Oracle location remap and executable-semantics preservation checks."""

from __future__ import annotations

import re
import time
from pathlib import Path

from ..code_semantics import SemanticStatus, compare_semantics, syntax_valid
from ..generation.context import is_code
from ..models import CheckStatus
from ..repository.git import run_git
from ..repository.location_remap import remap_oracle, verify_oracle_code
from .context import ValidationContext, new_started, result


def _location_tuple(location) -> tuple:
    return (
        location.file,
        location.start_line,
        location.end_line,
        location.code_sha256,
    )


def check_oracle_remap(ctx: ValidationContext):
    started = new_started()
    began = time.monotonic()
    errors: list[str] = []
    try:
        remap = remap_oracle(ctx.clean_oracle, ctx.clean_repo, ctx.repo)
    except Exception as exc:  # noqa: BLE001
        return result(
            "oracle_remap",
            CheckStatus.FAIL,
            started,
            time.monotonic() - began,
            details={"errors": [f"remap failed: {exc}"]},
        )
    if remap.report.unresolved:
        errors.append(f"unresolved oracle locations: {remap.report.unresolved}")
    remapped_by_key = {
        (vulnerability.vulnerability_id, path.path_id): path
        for vulnerability in remap.oracle.vulnerabilities
        for path in vulnerability.paths
    }
    for vulnerability in ctx.oracle.vulnerabilities:
        for path in vulnerability.paths:
            key = (vulnerability.vulnerability_id, path.path_id)
            expected = remapped_by_key.get(key)
            if expected is None:
                errors.append(f"vulnerability path disappeared from remap: {key}")
                continue
            if _location_tuple(path.entry_point) != _location_tuple(expected.entry_point):
                errors.append(f"entry point mismatch after remap: {key}")
            if _location_tuple(path.critical_operation) != _location_tuple(expected.critical_operation):
                errors.append(f"critical operation mismatch after remap: {key}")
            if len(path.trace) != len(expected.trace):
                errors.append(f"trace length mismatch after remap: {key}")
            else:
                for index, (left, right) in enumerate(zip(path.trace, expected.trace, strict=True)):
                    if _location_tuple(left) != _location_tuple(right):
                        errors.append(f"trace node {index} mismatch after remap: {key}")
    code_errors = verify_oracle_code(ctx.oracle, ctx.repo)
    errors.extend(code_errors)
    details = {
        "errors": errors,
        "locations_checked": remap.report.locations_checked,
        "locations_resolved": remap.report.locations_resolved,
        "ambiguous": remap.report.ambiguous,
        "unresolved": remap.report.unresolved,
        "remapped_locations": [
            item.model_dump(mode="json") for item in remap.report.details
        ],
    }
    return result(
        "oracle_remap",
        CheckStatus.PASS if not errors else CheckStatus.FAIL,
        started,
        time.monotonic() - began,
        details=details,
    )


def _new_python_module_is_unreferenced(ctx: ValidationContext, relative: str) -> bool:
    stem = Path(relative).stem
    pattern = re.compile(rf"^\s*(?:from\s+{re.escape(stem)}\s+import|import\s+{re.escape(stem)}\b)", re.M)
    for path in Path(ctx.repo).rglob("*.py"):
        if path.as_posix().endswith(relative):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if pattern.search(text):
            return False
    return True


def check_semantic_preservation(ctx: ValidationContext):
    started = new_started()
    began = time.monotonic()
    errors: list[str] = []
    undecided: list[str] = []
    evidence: list[dict[str, object]] = []
    checked: list[str] = []
    patch_meta = ctx.patch_meta
    if ctx.is_clean:
        return result(
            "semantic_preservation",
            CheckStatus.PASS,
            started,
            time.monotonic() - began,
            details={"reason": "clean instance has no manipulation"},
        )
    if patch_meta is None:
        return result(
            "semantic_preservation",
            CheckStatus.FAIL,
            started,
            time.monotonic() - began,
            details={"errors": ["patch metadata is missing"]},
        )
    for item in patch_meta.get("files_changed", []):
        path = item["path"]
        status = item.get("status", "M")
        old_path = item.get("old_path")
        checked.append(path)
        if status == "D":
            errors.append(f"file was deleted by the manipulation: {path}")
            continue
        if status == "R":
            errors.append(f"rename is not supported by v0.1 operators: {old_path} -> {path}")
            continue
        variant_path = Path(ctx.repo) / path
        if not variant_path.is_file():
            errors.append(f"changed file is missing: {path}")
            continue
        if status == "M":
            proc = run_git(
                ["show", f"{ctx.instance.repository.vulnerable_commit}:{path}"],
                cwd=ctx.repo,
                check=False,
                timeout=120,
            )
            if proc.returncode != 0:
                errors.append(f"cannot read base version of {path}")
                continue
            if is_code(path):
                verdict = compare_semantics(
                    path, proc.stdout, variant_path.read_text(encoding="utf-8", errors="replace")
                )
                evidence.append(
                    {
                        "path": path,
                        "status": verdict.status.value,
                        "reason": verdict.reason,
                        "language": verdict.language,
                        **{k: str(v) for k, v in verdict.evidence.items()},
                    }
                )
                if verdict.status == SemanticStatus.CHANGED:
                    errors.append(f"executable semantics changed in {path}: {verdict.reason}")
                elif verdict.status == SemanticStatus.UNKNOWN:
                    # Fail closed: an undecidable edit is not a pass.
                    undecided.append(f"{path}: {verdict.reason}")
        elif status == "A":
            text = variant_path.read_text(encoding="utf-8", errors="replace")
            valid, error = syntax_valid(path, text)
            if not valid:
                errors.append(f"new file has invalid syntax: {path}: {error}")
            if (
                path.endswith(".py")
                and ctx.instance.manipulation_tier.value != "M5"
                and not _new_python_module_is_unreferenced(ctx, path)
            ):
                errors.append(f"new Python module is referenced by existing code: {path}")
    for vulnerability in ctx.oracle.vulnerabilities:
        for path in vulnerability.paths:
            if not (Path(ctx.repo) / path.critical_operation.file).is_file():
                errors.append(f"critical operation file was removed: {path.critical_operation.file}")

    if errors:
        status = CheckStatus.FAIL
    elif undecided:
        # Supplementary evidence is required for undecidable edits: a build/test
        # pass cannot prove comment-only edits, but it does constrain the change.
        status = CheckStatus.UNKNOWN
    else:
        status = CheckStatus.PASS
    return result(
        "semantic_preservation",
        status,
        started,
        time.monotonic() - began,
        details={
            "errors": errors,
            "undecided": undecided,
            "files_checked": checked,
            "semantic_evidence": evidence,
            "policy": (
                "changed=fail, unknown=not a pass (fail-closed), "
                "comment_only=pass (lexer-verified)"
            ),
        },
    )
