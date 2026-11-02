"""Schema and cross-reference validation of one benchmark instance."""

from __future__ import annotations

import json
import time

import jsonschema

from ..models import (
    BenchmarkInstance,
    CanonicalVulnerabilityOracle,
    CheckStatus,
    DecoyRecord,
    ManipulationSpec,
)
from ..schemas import build_schema
from .context import ValidationContext, new_started, result


def check_schema(ctx: ValidationContext):
    started = new_started()
    began = time.monotonic()
    errors: list[str] = []
    try:
        jsonschema.validate(
            instance=ctx.instance.model_dump(mode="json"),
            schema=build_schema(BenchmarkInstance),
        )
        jsonschema.validate(
            instance=ctx.oracle.model_dump(mode="json"),
            schema=build_schema(CanonicalVulnerabilityOracle),
        )
        if ctx.manipulation is not None:
            jsonschema.validate(
                instance=ctx.manipulation.model_dump(mode="json"),
                schema=build_schema(ManipulationSpec),
            )
        for decoy in ctx.decoys:
            jsonschema.validate(
                instance=decoy.model_dump(mode="json"),
                schema=build_schema(DecoyRecord),
            )
    except jsonschema.ValidationError as exc:
        errors.append(f"jsonschema: {exc.message} at {list(exc.absolute_path)}")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"schema validation failed: {exc}")

    if ctx.instance.oracle_ref != ctx.oracle.oracle_id:
        errors.append("instance.oracle_ref does not match the stored oracle")
    if ctx.state.instance_id != ctx.instance.instance_id:
        errors.append("state.instance_id does not match the manifest")
    if ctx.state.pair_id != ctx.instance.pair_id:
        errors.append("state.pair_id does not match the manifest")
    if ctx.state.oracle_id != ctx.oracle.oracle_id:
        errors.append("state.oracle_id does not match the stored oracle")
    if ctx.is_adversarial:
        if ctx.instance.pair_id != ctx.clean_instance.pair_id:
            errors.append("adversarial instance is not paired with its clean instance")
        if ctx.instance.repository.vulnerable_commit != ctx.clean_instance.repository.vulnerable_commit:
            errors.append("pair uses different vulnerable commits")
        if ctx.instance.manipulation_ref is None:
            errors.append("adversarial instance has no manipulation_ref")
    elif ctx.is_benign:
        if ctx.instance.pair_id != ctx.clean_instance.pair_id:
            errors.append("benign control is not paired with its clean instance")
        if ctx.instance.repository.vulnerable_commit != ctx.clean_instance.repository.vulnerable_commit:
            errors.append("benign control uses a different vulnerable commit")
        if ctx.instance.group_id is None:
            errors.append("benign control has no group_id")
    task_path = ctx.store.resolve_artifact(ctx.instance.task_file)
    if not task_path.is_file() or not task_path.read_text(encoding="utf-8").strip():
        errors.append("task file is missing or empty")
    if ctx.is_clean and ctx.instance.patch_file is not None:
        errors.append("clean instance unexpectedly has a patch")
    if not ctx.is_clean:
        patch_path = ctx.store.resolve_artifact(ctx.instance.patch_file or "")
        if not patch_path.is_file() or patch_path.stat().st_size == 0:
            errors.append("variant instance patch is missing or empty")

    try:
        json.loads(json.dumps(ctx.instance.model_dump(mode="json")))
    except (TypeError, ValueError) as exc:
        errors.append(f"instance is not JSON serializable: {exc}")

    duration = time.monotonic() - began
    return result(
        "schema",
        CheckStatus.PASS if not errors else CheckStatus.FAIL,
        started,
        duration,
        details={"errors": errors, "vulnerability_count": len(ctx.oracle.vulnerabilities)},
    )
