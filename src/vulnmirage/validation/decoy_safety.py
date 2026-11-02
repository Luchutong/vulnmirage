"""Automated safety validation for M5 vulnerability decoys."""

from __future__ import annotations

import time

from ..models import CheckStatus
from .command_support import outcome_details, run_commands_in_copy
from .context import ValidationContext, new_started, result


def _overlaps(left, right, tolerance: int) -> bool:
    if left.file != right.file:
        return False
    if left.start_line <= right.end_line and right.start_line <= left.end_line:
        return True
    return min(abs(left.start_line - right.start_line), abs(left.end_line - right.end_line)) <= tolerance


def check_decoy_safety(ctx: ValidationContext):
    started = new_started()
    began = time.monotonic()
    errors: list[str] = []
    details: dict[str, object] = {"decoys": []}
    if ctx.decoys:
        tolerance = ctx.config.matching.line_tolerance
        real_locations = []
        for vulnerability in ctx.oracle.vulnerabilities:
            for path in vulnerability.paths:
                real_locations.append(
                    (vulnerability.vulnerability_id, path.path_id, "entry_point", path.entry_point)
                )
                real_locations.append(
                    (
                        vulnerability.vulnerability_id,
                        path.path_id,
                        "critical_operation",
                        path.critical_operation,
                    )
                )
                for index, node in enumerate(path.trace):
                    real_locations.append(
                        (
                            vulnerability.vulnerability_id,
                            path.path_id,
                            f"trace[{index}]",
                            node,
                        )
                    )
        for decoy in ctx.decoys:
            decoy_details: dict[str, object] = {
                "decoy_id": decoy.decoy_id,
                "verified_safe": decoy.verified_safe,
            }
            for vulnerability_id, path_id, label, location in real_locations:
                if _overlaps(decoy.apparent_critical_operation, location, tolerance):
                    errors.append(
                        f"decoy {decoy.decoy_id} apparent critical operation overlaps real oracle "
                        f"{vulnerability_id}/{path_id}/{label}"
                    )
            if _overlaps(decoy.apparent_critical_operation, decoy.false_bridge, 0):
                errors.append(f"decoy {decoy.decoy_id} false bridge overlaps its apparent sink")
            outcomes, _ = run_commands_in_copy(
                ctx.loaded,
                ctx.repo,
                decoy.safety_validator_commands,
                label=f"{ctx.instance.instance_id}-decoy-{decoy.decoy_id}",
                log_dir=ctx.log_dir / f"decoy-{decoy.decoy_id}",
            )
            decoy_details["checks"] = [outcome_details(item) for item in outcomes]
            for outcome in outcomes:
                if not outcome.passed:
                    errors.append(
                        f"decoy safety validator failed for {decoy.decoy_id}: "
                        f"{outcome.argv} exit {outcome.exit_code}"
                    )
            safe = all(item.passed for item in outcomes)
            decoy_details["verified_safe"] = safe
            details["decoys"].append(decoy_details)
        from ..hashing import canonical_json, sha256_text

        updated = [
            decoy.model_copy(
                update={
                    "verified_safe": bool(decoy_details["verified_safe"]),
                    "validation_log_sha256": (
                        sha256_text(canonical_json(decoy_details["checks"]))
                        if decoy_details["verified_safe"]
                        else None
                    ),
                }
            )
            for decoy, decoy_details in zip(
                ctx.decoys, details["decoys"], strict=True
            )
        ]
        ctx.store.write_decoys(ctx.instance.instance_id, updated)
        if ctx.state.decoy_sha256:
            from ..hashing import sha256_file

            ctx.state = ctx.state.model_copy(
                update={"decoy_sha256": sha256_file(ctx.store.decoy_path(ctx.instance.instance_id))}
            )
            ctx.store.save_state(ctx.state)
    elif ctx.is_adversarial and ctx.instance.manipulation_tier.value == "M5":
        errors.append("M5 instance has no decoy records")
    else:
        return result(
            "decoy_safety",
            CheckStatus.SKIP,
            started,
            time.monotonic() - began,
            details={"reason": "no decoys in this instance"},
        )
    details["errors"] = errors
    return result(
        "decoy_safety",
        CheckStatus.PASS if not errors else CheckStatus.FAIL,
        started,
        time.monotonic() - began,
        details=details,
    )
