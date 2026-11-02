"""Validation of SafeTargetContracts bound to an instance.

A false-positive instance is release-eligible only when every bound safe target
has an executed validator and a recorded log digest, or (for M5) a decoy whose
safety validator passed.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from ..generation.safe_targets import execute_safe_target_validation
from ..hashing import atomic_write_json
from ..models import AttackGoal, CheckStatus, SafeTargetContract
from .context import ValidationContext, new_started, result


def _load_declared(ctx: ValidationContext) -> list[SafeTargetContract]:
    path = ctx.store.instance_dir(ctx.instance.instance_id) / "safe_targets.json"
    contracts: list[SafeTargetContract] = []
    if path.is_file():
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload.get("safe_targets", payload) if isinstance(payload, dict) else payload
        for item in items:
            try:
                contracts.append(SafeTargetContract.model_validate(item))
            except Exception:
                continue
    if not contracts:
        contracts = list(ctx.oracle.all_safe_targets())
    if ctx.manipulation is not None:
        known = {item.safe_target_id for item in contracts}
        for item in ctx.manipulation.safe_targets:
            if item.safe_target_id not in known:
                contracts.append(item)
                known.add(item.safe_target_id)
    return contracts


def check_safe_targets(ctx: ValidationContext):
    started = new_started()
    began = time.monotonic()
    errors: list[str] = []
    contracts = _load_declared(ctx)
    goal = ctx.manipulation.attack_goal if ctx.manipulation is not None else None
    requires_safe = goal == AttackGoal.FALSE_POSITIVE
    details: dict[str, object] = {
        "goal": goal.value if goal else None,
        "declared": len(contracts),
        "requires_validated_safe_target": requires_safe,
    }
    if ctx.is_clean or ctx.is_benign or (goal is None and not contracts):
        return result(
            "safe_targets",
            CheckStatus.SKIP,
            started,
            time.monotonic() - began,
            details={**details, "reason": "no safe targets declared"},
        )
    # Re-execute validators on the instance worktree so the stored contract is
    # backed by evidence produced for *this* tree.
    executed = execute_safe_target_validation(
        contracts,
        loaded=ctx.loaded,
        repo_root=ctx.repo,
        log_dir=ctx.log_dir / "safe_targets",
        instance_id=ctx.instance.instance_id,
    )
    validated = executed.validated
    atomic_write_json(
        ctx.store.instance_dir(ctx.instance.instance_id) / "safe_targets.json",
        {"safe_targets": [item.model_dump(mode="json") for item in executed.contracts]},
    )
    details["validated"] = [item.safe_target_id for item in validated]
    details["validation_log_sha256"] = executed.log_sha256
    details["validation_log"] = str(executed.log_path) if executed.log_path else None
    details["contracts"] = executed.details
    for contract in executed.rejected:
        errors.append(f"safe target {contract.safe_target_id} did not validate")
    if requires_safe:
        has_verified_decoy = any(item.verified_safe for item in ctx.decoys)
        if not validated and not has_verified_decoy:
            errors.append(
                "false-positive instance has no validated safe target "
                "(reason: no_validated_safe_target)"
            )
        target_found = {item.cwe for item in validated}
        if not target_found and not has_verified_decoy:
            errors.append("no validated safe target covers the target CWE")
    details["errors"] = errors
    status = CheckStatus.PASS if not errors else CheckStatus.FAIL
    return result("safe_targets", status, started, time.monotonic() - began, details=details)


def safe_target_summary(ctx: ValidationContext) -> dict[str, object]:
    contracts = _load_declared(ctx)
    return {
        "declared": [item.safe_target_id for item in contracts],
        "validated": [item.safe_target_id for item in contracts if item.validated_safe],
    }
