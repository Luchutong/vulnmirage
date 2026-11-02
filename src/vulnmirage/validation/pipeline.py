"""Validation pipeline and release-eligibility policy."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any, Callable

from ..config import LoadedConfig
from ..errors import ValidationError as VMValidationError
from ..hashing import atomic_write_json, sha256_file, utc_now_iso
from ..logging import get_logger
from ..models import (
    BenchmarkInstance,
    CheckStatus,
    Stage,
    ValidationReport,
    ValidationResult,
    VariantKind,
)
from ..store import InstanceState, InstanceStore, now_iso
from .build import check_build, check_functional_tests
from .context import ValidationContext, new_started, result
from .decoy_safety import check_decoy_safety
from .diff_scope import check_diff_scope
from .evidence_contract import check_evidence_contract
from .integrity import check_repository_integrity
from .oracle_invariance import check_oracle_remap, check_semantic_preservation
from .poc import check_poc_replay, check_regression
from .reports_checks import check_leakage, check_new_vulnerability_scanner
from .safe_targets import check_safe_targets
from .schema import check_schema

_LOG = get_logger("validation")


def _resolve_clean(
    loaded: LoadedConfig,
    store: InstanceStore,
    instance: BenchmarkInstance,
    clean_instance_id: str | None,
) -> BenchmarkInstance:
    if instance.variant_kind == VariantKind.CLEAN:
        return instance
    if clean_instance_id:
        clean = store.load_instance(clean_instance_id)
        if clean.pair_id != instance.pair_id:
            raise VMValidationError(
                "explicit clean instance is not in the same pair",
                details={"clean": clean.instance_id, "pair": instance.pair_id},
            )
        return clean
    for candidate in store.pair_instances(instance.pair_id):
        if candidate.variant_kind == VariantKind.CLEAN:
            return candidate
    raise VMValidationError(
        "adversarial instance has no clean pair instance",
        details={"instance_id": instance.instance_id, "pair_id": instance.pair_id},
    )


def _build_context(
    loaded: LoadedConfig,
    instance_id: str,
    profile: str | None,
    clean_instance_id: str | None,
) -> ValidationContext:
    store = InstanceStore(loaded.paths)
    instance = store.load_instance(instance_id)
    state = store.load_state(instance_id)
    oracle = store.load_oracle(instance_id)
    manipulation = store.load_manipulation(instance_id)
    decoys = store.load_decoys(instance_id)
    clean = _resolve_clean(loaded, store, instance, clean_instance_id)
    clean_oracle = store.load_oracle(clean.instance_id)
    repo = store.repo_dir(instance_id)
    clean_repo = store.repo_dir(clean.instance_id)
    if not repo.is_dir():
        raise VMValidationError(
            "instance worktree is missing", details={"repo": str(repo)}
        )
    if not clean_repo.is_dir():
        raise VMValidationError(
            "clean worktree is missing", details={"repo": str(clean_repo)}
        )
    selected_profile = profile or loaded.config.validation.profile
    if selected_profile not in {"trace-grounded", "executable-ground-truth", "strict"}:
        raise VMValidationError(f"unknown validation profile: {selected_profile}")
    log_dir = store.instance_dir(instance_id) / "logs" / "validation"
    log_dir.mkdir(parents=True, exist_ok=True)
    return ValidationContext(
        loaded=loaded,
        store=store,
        instance=instance,
        state=state,
        oracle=oracle,
        clean_instance=clean,
        clean_oracle=clean_oracle,
        manipulation=manipulation,
        decoys=decoys,
        repo=repo,
        clean_repo=clean_repo,
        profile=selected_profile,
        log_dir=log_dir,
    )


def _run_check(name: str, function: Callable, ctx: ValidationContext) -> ValidationResult:
    started = new_started()
    began = time.monotonic()
    try:
        return function(ctx)
    except Exception as exc:  # noqa: BLE001 - validation records errors, never crashes
        _LOG.exception("validation check failed", extra={"context": {"check": name}})
        return result(
            name,
            CheckStatus.ERROR,
            started,
            time.monotonic() - began,
            details={"error": f"{type(exc).__name__}: {exc}"},
        )


def _status(results: dict[str, ValidationResult], name: str) -> CheckStatus | None:
    item = results.get(name)
    return item.status if item else None


def _policy(
    ctx: ValidationContext,
    results: list[ValidationResult],
) -> tuple[bool, bool, str, dict[str, Any]]:
    """Return ``(ground_truth_preserved, release_eligible, validation_level, details)``."""
    by_name = {item.check_name: item for item in results}
    profile = ctx.profile
    config = ctx.config.validation

    required = [
        "schema",
        "repository_integrity",
        "diff_scope",
        "oracle_remap",
        "evidence_contract",
        "semantic_preservation",
    ]
    ground_errors: list[str] = []
    for name in required:
        if _status(by_name, name) != CheckStatus.PASS:
            ground_errors.append(f"{name} did not pass")
    semantic_status = _status(by_name, "semantic_preservation")
    if semantic_status == CheckStatus.UNKNOWN:
        supplementary = all(
            _status(by_name, name) == CheckStatus.PASS
            for name in ("build", "functional_tests", "poc_replay")
        )
        if profile == "strict" or not supplementary:
            ground_errors.append(
                "semantic_preservation is undecidable; fail-closed (reason: "
                "semantic_unknown). Supplementary build+test+PoC evidence is "
                "required when the profile is not strict."
            )
    for name, allowed_skip in (
        ("poc_replay", True),
        ("regression", True),
        ("decoy_safety", True),
        ("new_vulnerability_scanner", True),
    ):
        status = _status(by_name, name)
        if status is None:
            ground_errors.append(f"{name} was not executed")
        elif status == CheckStatus.FAIL or status == CheckStatus.ERROR:
            ground_errors.append(f"{name} did not pass")
        elif status == CheckStatus.SKIP and not allowed_skip:
            ground_errors.append(f"{name} was skipped")
    goal = ctx.manipulation.attack_goal if ctx.manipulation is not None else None
    safe_status = _status(by_name, "safe_targets")
    if goal is not None and goal.value == "false_positive":
        if safe_status != CheckStatus.PASS:
            ground_errors.append(
                "false-positive instance has no validated safe target "
                "(reason: no_validated_safe_target)"
            )
    elif safe_status in {CheckStatus.FAIL, CheckStatus.ERROR}:
        ground_errors.append("safe target validation failed")
    ground_truth_preserved = not ground_errors

    def command_ok(name: str, required_by_config: bool, required_by_profile: bool) -> bool:
        status = _status(by_name, name)
        if status == CheckStatus.PASS:
            return True
        if status == CheckStatus.SKIP:
            return not (required_by_config or required_by_profile)
        return False

    executable_profile = profile in {"executable-ground-truth", "strict"}
    build_ok = command_ok(
        "build",
        config.require_build,
        executable_profile,
    )
    tests_ok = command_ok(
        "functional_tests",
        config.require_tests,
        executable_profile,
    )
    poc_ok = command_ok(
        "poc_replay",
        config.require_poc,
        executable_profile,
    )
    leakage_ok = _status(by_name, "leakage") == CheckStatus.PASS
    scanner_status = _status(by_name, "new_vulnerability_scanner")
    scanner_ok = scanner_status in {CheckStatus.PASS, CheckStatus.SKIP}
    has_decoys = bool(ctx.decoys)
    m5 = ctx.instance.manipulation_tier.value == "M5"
    decoy_status = _status(by_name, "decoy_safety")
    decoy_ok = True
    if has_decoys or m5:
        decoy_ok = decoy_status == CheckStatus.PASS
        if m5 and config.require_decoy_safety_for_m5 and not has_decoys:
            decoy_ok = False

    poc_result = by_name.get("poc_replay")
    executed = bool(poc_result and poc_result.status == CheckStatus.PASS and poc_result.details.get("executed"))
    if executed:
        validation_level = "executable_ground_truth"
    elif ctx.oracle.validation_level == "unverified":
        validation_level = "unverified"
    else:
        validation_level = "trace_grounded"

    release_eligible = (
        ground_truth_preserved
        and _status(by_name, "evidence_contract") == CheckStatus.PASS
        and build_ok
        and tests_ok
        and poc_ok
        and leakage_ok
        and decoy_ok
        and scanner_ok
        and validation_level != "unverified"
    )
    details = {
        "profile": profile,
        "ground_truth_errors": ground_errors,
        "schema_passed": _status(by_name, "schema") == CheckStatus.PASS,
        "repository_integrity_passed": _status(by_name, "repository_integrity")
        == CheckStatus.PASS,
        "diff_scope_passed": _status(by_name, "diff_scope") == CheckStatus.PASS,
        "oracle_remap_passed": _status(by_name, "oracle_remap") == CheckStatus.PASS,
        "evidence_contract_complete": _status(by_name, "evidence_contract")
        == CheckStatus.PASS,
        "semantic_preservation_passed": _status(by_name, "semantic_preservation")
        == CheckStatus.PASS,
        "semantic_preservation_status": (
            _status(by_name, "semantic_preservation").value
            if _status(by_name, "semantic_preservation") is not None
            else None
        ),
        "safe_targets_passed": _status(by_name, "safe_targets") == CheckStatus.PASS,
        "safe_targets_status": (
            _status(by_name, "safe_targets").value
            if _status(by_name, "safe_targets") is not None
            else None
        ),
        "build_policy_satisfied": build_ok,
        "functional_policy_satisfied": tests_ok,
        "poc_policy_satisfied": poc_ok,
        "leakage_passed": leakage_ok,
        "decoy_policy_satisfied": decoy_ok,
        "new_vulnerability_scanner_satisfied": scanner_ok,
        "poc_executed": executed,
        "checks": {
            name: {
                "status": item.status.value,
                "duration_seconds": round(item.duration_seconds, 4),
            }
            for name, item in by_name.items()
        },
    }
    return ground_truth_preserved, release_eligible, validation_level, details


def _ground_truth_result(
    ctx: ValidationContext,
    results: list[ValidationResult],
    preserved: bool,
    policy_details: dict[str, Any],
):
    started = new_started()
    return result(
        "ground_truth_invariance",
        CheckStatus.PASS if preserved else CheckStatus.FAIL,
        started,
        0.0,
        details={
            "errors": policy_details.get("ground_truth_errors", []),
            "mandatory_checks": [
                "schema",
                "repository_integrity",
                "diff_scope",
                "oracle_remap",
                "evidence_contract",
                "safe_targets",
                "semantic_preservation",
            ],
            "optional_checks": [
                "poc_replay",
                "regression",
                "decoy_safety",
                "new_vulnerability_scanner",
            ],
        },
    )


def _quarantine(ctx: ValidationContext, report_path: Path) -> Path | None:
    if ctx.instance.variant_kind == VariantKind.CLEAN and ctx.state.release_eligible:
        return None
    source = ctx.store.instance_dir(ctx.instance.instance_id)
    destination = ctx.loaded.paths.quarantine / ctx.instance.instance_id
    try:
        if destination.exists():
            shutil.rmtree(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, destination)
        atomic_write_json(
            destination / "quarantine.json",
            {
                "instance_id": ctx.instance.instance_id,
                "reason": "validation did not satisfy the release policy",
                "validation_report": report_path.name,
                "quarantined_at": now_iso(),
            },
        )
        return destination
    except OSError:
        return None


def validate_instance(
    *,
    loaded: LoadedConfig,
    instance_id: str,
    profile: str | None = None,
    clean_instance_id: str | None = None,
) -> dict[str, Any]:
    loaded.paths.ensure_layout()
    ctx = _build_context(loaded, instance_id, profile, clean_instance_id)
    original_stage = ctx.state.stage
    if original_stage != Stage.FROZEN.value:
        ctx.store.update_stage(instance_id, Stage.VALIDATING, detail=f"profile={ctx.profile}")
        ctx.state = ctx.store.load_state(instance_id)

    checks: list[ValidationResult] = [
        _run_check("schema", check_schema, ctx),
        _run_check("repository_integrity", check_repository_integrity, ctx),
        _run_check("diff_scope", check_diff_scope, ctx),
        _run_check("oracle_remap", check_oracle_remap, ctx),
        _run_check("evidence_contract", check_evidence_contract, ctx),
        _run_check("safe_targets", check_safe_targets, ctx),
        _run_check("semantic_preservation", check_semantic_preservation, ctx),
        _run_check("build", check_build, ctx),
        _run_check("functional_tests", check_functional_tests, ctx),
        _run_check("poc_replay", check_poc_replay, ctx),
        _run_check("regression", check_regression, ctx),
        _run_check("decoy_safety", check_decoy_safety, ctx),
        _run_check("leakage", check_leakage, ctx),
        _run_check("new_vulnerability_scanner", check_new_vulnerability_scanner, ctx),
    ]
    ctx.state = ctx.store.load_state(instance_id)
    ground_truth_preserved, release_eligible, validation_level, policy_details = _policy(
        ctx, checks
    )
    checks.append(_ground_truth_result(ctx, checks, ground_truth_preserved, policy_details))
    checks.append(
        result(
            "release_eligibility",
            CheckStatus.PASS if release_eligible else CheckStatus.FAIL,
            new_started(),
            0.0,
            details=policy_details,
        )
    )

    # Upgrade the stored oracle's validation level only when a real executable
    # replay succeeded.  It is never downgraded silently.
    if validation_level == "executable_ground_truth" and ctx.oracle.validation_level != validation_level:
        ctx.oracle = ctx.oracle.model_copy(update={"validation_level": validation_level})
        ctx.store.write_oracle(instance_id, ctx.oracle)
        ctx.state = ctx.state.model_copy(
            update={"oracle_sha256": sha256_file(ctx.store.oracle_path(instance_id))}
        )
        if ctx.instance.variant_kind == VariantKind.CLEAN:
            aligned = ctx.loaded.paths.normalized / f"{ctx.oracle.oracle_id}.aligned.json"
            if aligned.is_file():
                atomic_write_json(aligned, ctx.oracle)

    report = ValidationReport(
        instance_id=instance_id,
        results=checks,
        ground_truth_preserved=ground_truth_preserved,
        release_eligible=release_eligible,
        validation_level=validation_level,
    ).with_digest()
    report_path = ctx.store.validation_path(instance_id)
    atomic_write_json(report_path, report)

    if original_stage == Stage.FROZEN.value and release_eligible:
        new_stage = Stage.FROZEN.value
    elif release_eligible:
        new_stage = Stage.VALIDATED.value
    else:
        new_stage = Stage.REJECTED.value
    if new_stage != Stage.FROZEN.value or original_stage != Stage.FROZEN.value:
        ctx.state = ctx.state.model_copy(
            update={
                "stage": new_stage,
                "updated_at": now_iso(),
                "validation_report_sha256": report.report_sha256,
                "validation_status": "pass" if release_eligible else "fail",
                "release_eligible": release_eligible,
            }
        )
        try:
            ctx.store.save_state(ctx.state)
        except Exception:
            # Frozen states forbid most transitions; keep the frozen stage but
            # persist the validation outcome.
            ctx.state = ctx.state.model_copy(
                update={
                    "stage": original_stage,
                    "updated_at": now_iso(),
                    "validation_report_sha256": report.report_sha256,
                    "validation_status": "pass" if release_eligible else "fail",
                    "release_eligible": release_eligible,
                }
            )
            ctx.store.save_state(ctx.state, allow_transition=False)

    quarantine_path = None
    if not release_eligible:
        quarantine_path = _quarantine(ctx, report_path)
    _LOG.info(
        "validation completed",
        extra={
            "context": {
                "instance_id": instance_id,
                "release_eligible": release_eligible,
                "ground_truth_preserved": ground_truth_preserved,
                "validation_level": validation_level,
            }
        },
    )
    return {
        "ok": True,
        "instance_id": instance_id,
        "profile": ctx.profile,
        "release_eligible": release_eligible,
        "ground_truth_preserved": ground_truth_preserved,
        "validation_level": validation_level,
        "report_sha256": report.report_sha256,
        "report_path": str(report_path),
        "quarantine_path": str(quarantine_path) if quarantine_path else None,
        "stage": new_stage,
        "checks": [
            {
                "name": item.check_name,
                "status": item.status.value,
                "duration_seconds": round(item.duration_seconds, 4),
                "details": item.details,
            }
            for item in checks
        ],
        "report": report.model_dump(mode="json"),
    }
