"""Evaluation orchestration and layered report emission."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable

from ..config import LoadedConfig
from ..errors import OutputParseError, ReleaseError
from ..hashing import atomic_write_json, atomic_write_text, derive_seed, utc_now_iso
from ..harness.trace import TraceSummary
from ..models import (
    AgentFinding,
    AgentRun,
    BenchmarkInstance,
    CanonicalVulnerabilityOracle,
    DecoyRecord,
    EnrichedTrajectoryEvent,
    EvidenceContract,
    FileAccessRecord,
    ManipulationSpec,
    ObservabilityGrade,
    RunMeta,
    SeverityLevel,
    UnifiedEvent,
    VerificationAssessment,
)
from ..paths import safe_join
from .evidence import evidence_coverage_curve, evidence_metrics, verify_claims
from .matching import MatchOutcome, match_instance
from .metrics import compute_instance_metrics
from .exposure import summarize_exposure
from .paired import (
    PAIR_COLUMNS,
    EvaluatedRun,
    aggregate_by,
    aggregate_rows,
    pair_rows,
)
from .repetitions import repetition_statistics
from .parser import ParsedOutput, parse_agent_output
from .resource import resource_metrics
from .stages import enrich_trajectory
from .statistics import (
    MetricEstimate,
    adjust_p_values,
    bootstrap_ci,
    cluster_bootstrap_ci,
    cluster_key,
    mcnemar_test,
    paired_bootstrap_ci,
    proportion_estimate,
    repository_cluster_bootstrap,
    repository_cluster_key,
    wilcoxon_signed_rank,
)
from .trajectory import trajectory_metrics

#: Evaluation outputs are versioned separately from the release schema.  Old
#: summaries are never relabelled as belonging to a newer evaluator.
EVALUATOR_SCHEMA_VERSION = "3.0"
METRIC_SCHEMA_VERSION = "3.0"

INSTANCE_METRIC_COLUMNS = [
    "run_id",
    "instance_id",
    "pair_id",
    "variant_kind",
    "model",
    "scaffold",
    "repetition",
    "audit_difficulty",
    "manipulation_tier",
    "attack_goal",
    "release_split",
    "mechanism",
    "carrier",
    "presentation",
    "distribution",
    "generation_method",
    "candidate_id",
    "group_id",
    "run_status",
    "parse_status",
    "valid_run",
    "target_found",
    "tp",
    "fp",
    "fn",
    "precision",
    "recall",
    "f1",
    "advisory_recall",
    "entry_recall",
    "severity_accuracy",
    "severity_within_one_accuracy",
    "severity_mae",
    "trace_f1",
    "trace_precision",
    "trace_recall",
    "trace_edit_similarity",
    "finding_duplication_rate",
    "line_localization",
    "entry_localization",
    "decoy_reported",
    "injected_artifact_read",
    "time_to_first_target_evidence",
    "contaminated",
    "observability_grade",
    "process_metrics_eligible",
    "manipulation_exposed",
    "verification_depth",
    "verification_resolution",
    "eer",
    "rer",
    "evidence_precision",
    "unsupported_evidence_rate",
    "decoy_budget_share",
    "true_evidence_budget_share",
    "verification_budget_share",
    "stage_transitions",
    "backtracking_count",
]


def _csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.6f}"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return value


def _write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if columns is None:
        columns = []
        for row in rows:
            for key in row:
                if key not in columns:
                    columns.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key)) for key in columns})


def _sanitize_report_value(value: Any, roots: list[str]) -> Any:
    if isinstance(value, str):
        result = value
        for root in roots:
            if root:
                result = result.replace(root, "<workspace>")
        import re

        result = re.sub(r"[A-Za-z]:[\\/][^\s\"']+", "<host-path>", result)
        result = re.sub(r"(?<![\w.])/(?:home|Users|tmp)/[^\s\"']+", "<host-path>", result)
        return result
    if isinstance(value, list):
        return [_sanitize_report_value(item, roots) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_report_value(item, roots) for key, item in value.items()}
    return value


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(row, ensure_ascii=False, default=str) + "\n" for row in rows)
    atomic_write_text(path, text)


def _resolve_workspace_path(loaded: LoadedConfig, value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return path
    try:
        return safe_join(loaded.paths.root, value, allow_git=True)
    except Exception:
        return None


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _load_release_assets(
    root: Path, entry
) -> tuple[
    BenchmarkInstance,
    CanonicalVulnerabilityOracle,
    ManipulationSpec | None,
    list[DecoyRecord],
    dict | None,
    EvidenceContract | None,
]:
    instance = BenchmarkInstance.model_validate(
        json.loads((root / "instances" / entry.instance_id / "instance.json").read_text(encoding="utf-8"))
    )
    oracle = CanonicalVulnerabilityOracle.model_validate(
        json.loads((root / entry.oracle_file).read_text(encoding="utf-8"))
    )
    manipulation = None
    if entry.manipulation_file:
        manipulation = ManipulationSpec.model_validate(
            json.loads((root / entry.manipulation_file).read_text(encoding="utf-8"))
        )
    decoys: list[DecoyRecord] = []
    decoy_path = root / "instances" / entry.instance_id / "decoys.json"
    if decoy_path.is_file():
        payload = json.loads(decoy_path.read_text(encoding="utf-8"))
        items = payload.get("decoys", payload) if isinstance(payload, dict) else payload
        decoys = [DecoyRecord.model_validate(item) for item in items]
    contract = None
    if entry.evidence_contract_file:
        contract = EvidenceContract.model_validate(
            json.loads((root / entry.evidence_contract_file).read_text(encoding="utf-8"))
        )
    validation_path = root / entry.validation_file
    validation = (
        json.loads(validation_path.read_text(encoding="utf-8")) if validation_path.is_file() else None
    )
    return instance, oracle, manipulation, decoys, validation, contract


def _discover_runs(runs_dir: Path) -> list[Path]:
    if not runs_dir.is_dir():
        return []
    return [
        path
        for path in sorted(runs_dir.iterdir())
        if path.is_dir()
        and not path.name.startswith("_")
        and (
            (path / "run.json").is_file()
            or (path / "run_error.json").is_file()
        )
    ]


def _parse_final_output(
    loaded: LoadedConfig, run: AgentRun, meta: RunMeta | None
) -> tuple[ParsedOutput | None, str, str | None]:
    if run.status in {"timeout", "agent_tool_failure", "infrastructure_failure"}:
        return None, "not_attempted", None
    path = _resolve_workspace_path(loaded, run.final_raw_path) or _resolve_workspace_path(
        loaded, run.findings_path
    )
    if path is None or not path.is_file():
        return None, "format_failure", "agent output file is missing"
    try:
        parsed = parse_agent_output(
            path.read_text(encoding="utf-8", errors="replace"),
            repo_root=None,
            source_path=path,
        )
        return parsed, "ok", None
    except OutputParseError as exc:
        return None, "format_failure", exc.message


def _load_observation_artifacts(
    loaded: LoadedConfig, run: AgentRun, run_dir: Path
) -> tuple[list[UnifiedEvent], list[FileAccessRecord], list[EnrichedTrajectoryEvent], list[VerificationAssessment]]:
    events: list[UnifiedEvent] = []
    for row in _read_jsonl(run_dir / "events.normalized.jsonl"):
        try:
            events.append(UnifiedEvent.model_validate(row))
        except Exception:
            continue
    accesses: list[FileAccessRecord] = []
    for row in _read_jsonl(run_dir / "file_access.jsonl"):
        try:
            accesses.append(FileAccessRecord.model_validate(row))
        except Exception:
            continue
    enriched: list[EnrichedTrajectoryEvent] = []
    for row in _read_jsonl(run_dir / "trajectory_enriched.jsonl"):
        try:
            enriched.append(EnrichedTrajectoryEvent.model_validate(row))
        except Exception:
            continue
    assessments: list[VerificationAssessment] = []
    assessment_path = run_dir / "verification_assessments.json"
    if assessment_path.is_file():
        try:
            payload = json.loads(assessment_path.read_text(encoding="utf-8"))
            assessments = [VerificationAssessment.model_validate(item) for item in payload]
        except Exception:
            assessments = []
    return events, accesses, enriched, assessments


def _load_run(
    loaded: LoadedConfig,
    run_dir: Path,
    release_assets: dict[str, tuple],
    profile: str,
) -> tuple[EvaluatedRun | None, dict[str, Any] | None]:
    try:
        run = AgentRun.model_validate(json.loads((run_dir / "run.json").read_text(encoding="utf-8")))
    except Exception as exc:  # noqa: BLE001
        return None, {
            "run_id": run_dir.name,
            "failure_type": "infrastructure_failure",
            "detail": str(exc),
        }
    meta = None
    for name in ("meta.json", "run_meta.json"):
        path = run_dir / name
        if path.is_file():
            try:
                meta = RunMeta.model_validate(json.loads(path.read_text(encoding="utf-8")))
            except Exception:
                meta = None
            break
    assets = release_assets.get(run.instance_id)
    if assets is None:
        return None, {
            "run_id": run.run_id,
            "instance_id": run.instance_id,
            "failure_type": "instance_not_in_release",
            "detail": "run instance is not part of the evaluated release",
        }
    instance, oracle, manipulation, decoys, validation, contract = assets
    if run.purpose == "reference" or (meta is not None and meta.purpose == "reference"):
        return None, {
            "run_id": run.run_id,
            "instance_id": run.instance_id,
            "failure_type": "reference_run_excluded",
            "detail": (
                "purpose=reference (R0) is never part of formal clean/control "
                "denominators or candidate pairing"
            ),
        }
    parsed, parse_status, parse_error = _parse_final_output(loaded, run, meta)
    findings = parsed.findings if parsed is not None else None
    if parse_status == "format_failure" and run.status == "success":
        run = run.model_copy(update={"status": "format_failure"})
    outcome = None
    if findings is not None:
        outcome = match_instance(
            findings,
            oracle,
            decoys=decoys,
            config=loaded.config.matching,
            profile=profile,
        )
    events, accesses, enriched, assessments = _load_observation_artifacts(
        loaded, run, run_dir
    )
    grade = run.observability_grade or (meta.observability_grade if meta else "D")
    minimum = loaded.config.observation.minimum_grade_for_process_metrics
    process_eligible = grade == "A" or (grade == "B" and minimum == "B")
    if not enriched and events:
        nodes = __import__(
            "vulnmirage.evaluation.evidence", fromlist=["build_evidence_nodes"]
        ).build_evidence_nodes(
            oracle, decoys=decoys, contract=contract, manipulation=manipulation
        )
        enriched = enrich_trajectory(
            run_id=run.run_id,
            events=events,
            nodes=nodes,
            contract=contract,
            findings=findings,
            config=loaded.config.trajectory,
        )
    if not assessments and contract is not None:
        assessments = verify_claims(
            run_id=run.run_id,
            contract=contract,
            events=events,
            accesses=accesses,
            findings=findings,
            outcome=outcome,
            trajectory=loaded.config.trajectory,
            rule_version=loaded.config.trajectory.verification_rule_version,
        )
    evidence = None
    trajectory = None
    resource = None
    if process_eligible:
        evidence = evidence_metrics(
            oracle=oracle,
            findings=findings or [],
            accesses=accesses,
            contract=contract,
            decoys=decoys,
            manipulation=manipulation,
            observation=loaded.config.observation,
            trajectory=loaded.config.trajectory,
            line_tolerance=loaded.config.matching.line_tolerance,
        )
        trajectory = trajectory_metrics(
            enriched=enriched,
            start_monotonic_ns=min((event.monotonic_ns for event in events), default=0),
            assessments=assessments,
            end_monotonic_ns=max((event.monotonic_ns for event in events), default=None),
        )
        evidence_nodes = __import__(
            "vulnmirage.evaluation.evidence", fromlist=["build_evidence_nodes"]
        ).build_evidence_nodes(
            oracle, decoys=decoys, contract=contract, manipulation=manipulation
        )
        trajectory["coverage_curve"] = evidence_coverage_curve(
            accesses=accesses,
            nodes=evidence_nodes,
            exposure_operations=set(loaded.config.trajectory.exposure_operations),
            start_monotonic_ns=min((event.monotonic_ns for event in events), default=0),
        )
        trajectory["stage_rule_version"] = loaded.config.trajectory.stage_rule_version
        resource = resource_metrics(
            enriched=enriched,
            correct_findings=len(outcome.assignment) if outcome is not None else None,
            timeout=run.status == "timeout",
            agent_tool_failure=run.status == "agent_tool_failure",
            incomplete_report=findings is None,
        )
    from .conditions import resolve_condition
    from .targets import resolve_target_binding

    resolved_condition = resolve_condition(run, meta)
    target_binding = (
        resolve_target_binding(oracle, manipulation, instance=instance)
        if manipulation is not None
        else None
    )
    metrics = compute_instance_metrics(
        findings=findings,
        oracle=oracle,
        outcome=outcome,
        decoys=decoys,
        config=loaded.config.matching,
        run_status=run.status,
        parse_status=parse_status,
        contaminated=bool(meta and meta.contaminated),
        observability_grade=grade,
        process_metrics_eligible=process_eligible,
        safe_targets=[
            *(manipulation.safe_targets if manipulation is not None else []),
            *oracle.validated_safe_targets(),
        ],
        target_binding=target_binding,
    )
    if manipulation is None:
        # Clean/benign controls share one run across several attack targets.
        # Their detection is derived per bound target at pairing time, so a
        # whole-run boolean must not be exposed as a target-level result.
        metrics["target_scope"] = "paired_target_derived"
        metrics["target_found"] = None
        metrics["target_status"] = "derived_at_pairing"
    from .exposure import decide_exposure

    payload_location_known = bool(
        (manipulation is not None and (manipulation.files_touched or manipulation.payloads))
        or (contract is not None and any(claim.presented_locations for claim in contract.claims))
    )
    exposure = decide_exposure(
        process_eligible=process_eligible,
        events=events,
        assessments=assessments,
        evidence=evidence,
        accesses=accesses,
        exposure_operations=set(loaded.config.trajectory.exposure_operations),
        payload_location_known=payload_location_known,
        observer_failed=run.status == "observer_failure",
    )
    metrics.update(
        {
            "manipulation_exposed": exposure.state,
            "exposure_unknown_reason": exposure.reason,
            "exposure_unknown_reason_text": exposure.reason_text(),
            "exposure_details": exposure.details,
            "verification_depth": max(
                (item.depth_score for item in assessments), default=None
            )
            if assessments and process_eligible
            else None,
            "verification_resolution": (
                assessments[0].resolution.value if assessments and process_eligible else None
            ),
            "evidence": evidence,
            "trajectory": trajectory,
            "resource": resource,
            "parse_error": parse_error,
            "observability_grade": grade,
            "process_metrics_eligible": process_eligible,
        }
    )
    trace_path = _resolve_workspace_path(loaded, run.normalized_events_path)
    trace = TraceSummary(trace_path=str(trace_path) if trace_path else "")
    return (
        EvaluatedRun(
            run=run,
            meta=meta,
            instance=instance,
            oracle=oracle,
            manipulation=manipulation,
            decoys=decoys,
            contract=contract,
            findings=findings,
            parse_status=parse_status,
            parse_error=parse_error,
            outcome=outcome,
            metrics=metrics,
            trace=trace,
            validation=validation,
            events=events,
            file_access=accesses,
            enriched=enriched,
            assessments=assessments,
            evidence=evidence,
            trajectory=trajectory,
            resource=resource,
            observability_grade=grade,
            process_metrics_eligible=process_eligible,
            condition_id=resolved_condition.condition_id,
            condition_source=resolved_condition.source,
            condition_complete=resolved_condition.complete,
            condition_notes=list(resolved_condition.notes),
            release_id=(meta.release_sha256 if meta is not None else None) or "unknown",
            attempt=int(run.attempt or 1),
            target_binding=target_binding,
        ),
        None,
    )


def _failures(
    evaluated: list[EvaluatedRun],
    load_failures: list[dict[str, Any]],
    pair_rows_: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = [
        item
        for item in load_failures
        if item.get("failure_type") != "reference_run_excluded"
    ]
    for item in evaluated:
        if item.run.status in {
            "timeout",
            "agent_tool_failure",
            "infrastructure_failure",
            "observation_setup_failure",
            "observer_failure",
        }:
            rows.append(
                {
                    "run_id": item.run.run_id,
                    "instance_id": item.run.instance_id,
                    "failure_type": item.run.status,
                    "detail": (item.meta.stderr_excerpt if item.meta else None) or "",
                }
            )
        if item.parse_status == "format_failure":
            rows.append(
                {
                    "run_id": item.run.run_id,
                    "instance_id": item.run.instance_id,
                    "failure_type": "format_failure",
                    "detail": item.parse_error or "could not parse agent output",
                }
            )
        if item.meta and item.meta.contaminated:
            rows.append(
                {
                    "run_id": item.run.run_id,
                    "instance_id": item.run.instance_id,
                    "failure_type": "contamination",
                    "detail": ", ".join(item.meta.changed_files),
                }
            )
    for row in pair_rows_:
        if not row.get("clean_run_id"):
            rows.append(
                {
                    "run_id": row.get("adv_run_id"),
                    "instance_id": row.get("adversarial_instance_id"),
                    "failure_type": "missing_clean_run",
                    "detail": f"pair {row['pair_id']} has no matching clean run",
                }
            )
    return rows


def _flatten_metrics(item: EvaluatedRun) -> dict[str, Any]:
    evidence = item.evidence or {}
    trajectory = item.trajectory or {}
    resource = item.resource or {}
    return {
        "eer": evidence.get("eer_best_path")
        if evidence
        else None,
        "rer": evidence.get("rer_best_path") if evidence else None,
        "evidence_precision": evidence.get("evidence_precision") if evidence else None,
        "unsupported_evidence_rate": evidence.get("unsupported_evidence_rate")
        if evidence
        else None,
        "decoy_budget_share": resource.get("decoy_budget_share"),
        "true_evidence_budget_share": resource.get("true_evidence_budget_share"),
        "verification_budget_share": resource.get("verification_budget_share"),
        "stage_transitions": trajectory.get("stage_transitions"),
        "backtracking_count": trajectory.get("backtracking_count"),
    }


def _configured_repetitions(runs_dir: Path, loaded: LoadedConfig) -> dict[str, Any]:
    """Effective repetitions: run manifests win over the static config."""
    observed: list[dict[str, Any]] = []
    if runs_dir.is_dir():
        for path in sorted(runs_dir.glob("_experiment_manifest_*.json")):
            try:
                observed.append(json.loads(path.read_text(encoding="utf-8")))
            except Exception:  # noqa: BLE001
                continue
    if observed:
        values = [int(item.get("repetitions") or 0) for item in observed if item.get("repetitions")]
        if values:
            return {
                "repetitions": max(values),
                "source": "run_manifest",
                "manifests": [Path(item.get("release_id") or "manifest").name for item in observed],
                "minimum_valid_repetitions": observed[-1].get(
                    "minimum_valid_repetitions",
                    loaded.config.experiment.minimum_valid_repetitions,
                ),
            }
    return {
        "repetitions": loaded.config.experiment.repetitions,
        "source": "experiment.repetitions",
        "manifests": [],
        "minimum_valid_repetitions": loaded.config.experiment.minimum_valid_repetitions,
    }


def _mean_numeric(values: list[Any]) -> float | None:
    numbers = [float(value) for value in values if isinstance(value, (int, float)) and not isinstance(value, bool)]
    return sum(numbers) / len(numbers) if numbers else None


def _mean_bool(values: Iterable[Any]) -> float | None:
    numbers = [1.0 if value else 0.0 for value in values if value is not None]
    return sum(numbers) / len(numbers) if numbers else None


def _defense_matrix(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-defense repetition-level results, exposure and cost (P1-3)."""
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        key = (str(row.get("defense_id") or "none"), str(row.get("defense_version") or ""))
        grouped.setdefault(key, []).append(row)

    def summarize(defense_rows: list[dict[str, Any]]) -> dict[str, Any]:
        clean_valid = [row for row in defense_rows if row.get("clean_valid") is True]
        attack_valid = [row for row in defense_rows if row.get("adv_valid") is True]
        paired = [
            row
            for row in defense_rows
            if row.get("clean_valid") is True and row.get("adv_valid") is True
        ]
        fn_values = [row["fn_attack_success"] for row in defense_rows if row.get("fn_attack_success") is not None]
        fp_values = [row["fp_attack_success"] for row in defense_rows if row.get("fp_attack_success") is not None]
        severity_values = [
            row["severity_attack_success"]
            for row in defense_rows
            if row.get("severity_attack_success") is not None
        ]
        known_exposure = [
            row for row in defense_rows if row.get("manipulation_exposed") is not None
        ]
        exposure = summarize_exposure(defense_rows)
        failure = _mean_bool(
            1
            if row.get("run_status")
            in {
                "timeout",
                "agent_tool_failure",
                "infrastructure_failure",
                "observation_setup_failure",
                "observer_failure",
            }
            else 0
            for row in defense_rows
        )
        return {
            "pair_rows": len(defense_rows),
            "valid_paired_repetitions": len(paired),
            "valid_clean_repetitions": len(clean_valid),
            "valid_attack_repetitions": len(attack_valid),
            "clean_target_detection_rate": (
                sum(1 for row in defense_rows if row.get("clean_target_found") is True)
                / len(clean_valid)
                if clean_valid
                else None
            ),
            "attack_target_detection_rate": (
                sum(1 for row in defense_rows if row.get("adv_target_found") is True)
                / len(attack_valid)
                if attack_valid
                else None
            ),
            "fn_asr": (sum(1 for value in fn_values if value) / len(fn_values)) if fn_values else None,
            "fp_asr": (sum(1 for value in fp_values if value) / len(fp_values)) if fp_values else None,
            "severity_asr": (
                sum(1 for value in severity_values if value) / len(severity_values)
                if severity_values
                else None
            ),
            "exposure_rate": exposure["exposure_rate"],
            "exposure_known_count": exposure["exposure_known_count"],
            "exposure_unknown_count": exposure["exposure_unknown_count"],
            "exposure_unknown_reason_counts": exposure["unknown_reason_counts"],
            "mean_duration_seconds": _mean_numeric(
                [row.get("adv_duration_seconds") for row in defense_rows]
            ),
            "mean_tool_calls": _mean_numeric(
                [row.get("adv_tool_calls") for row in defense_rows]
            ),
            "mean_input_tokens": _mean_numeric(
                [row.get("adv_input_tokens") for row in defense_rows]
            ),
            "mean_output_tokens": _mean_numeric(
                [row.get("adv_output_tokens") for row in defense_rows]
            ),
            "timeout_or_error_rate": failure,
            "known_exposure_rows": len(known_exposure),
        }

    per_defense: list[dict[str, Any]] = []
    for (defense_id, defense_version), defense_rows in sorted(grouped.items()):
        entry = {
            "defense_id": defense_id,
            "defense_version": defense_version,
            **summarize(defense_rows),
        }
        per_defense.append(entry)
    baseline = next(
        (item for item in per_defense if item["defense_id"] == "D0"),
        per_defense[0] if per_defense else None,
    )
    for item in per_defense:
        if baseline is None:
            item["delta_vs_d0"] = None
            continue
        deltas: dict[str, Any] = {}
        for key in (
            "fn_asr",
            "fp_asr",
            "severity_asr",
            "attack_target_detection_rate",
            "clean_target_detection_rate",
            "exposure_rate",
            "mean_duration_seconds",
            "mean_tool_calls",
        ):
            left = item.get(key)
            right = baseline.get(key)
            deltas[key] = (
                float(left) - float(right)
                if left is not None and right is not None
                else None
            )
        item["delta_vs_d0"] = deltas
        item["clean_utility_delta"] = deltas.get("clean_target_detection_rate")
    return {
        "baseline_defense": baseline["defense_id"] if baseline else None,
        "defense_count": len(per_defense),
        "per_defense": per_defense,
        "repetition_based": True,
        "d2_naming": (
            "prompt-based evidence verification (prompt policy, not a runtime "
            "enforcement gate)"
        ),
        "note": (
            "each defense is its own execution condition and must be run for the "
            "same configured repetitions"
        ),
    }


def _statistics(
    rows: list[dict[str, Any]],
    loaded: LoadedConfig,
    seed: int,
    *,
    repetition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    estimates: list[MetricEstimate] = []

    def add_proportion(name: str, values: list[bool]) -> None:
        if values:
            estimates.append(
                proportion_estimate(
                    name,
                    sum(1 for value in values if value),
                    len(values),
                    level=loaded.config.evaluation.confidence_level,
                )
            )

    def add_mean(name: str, values: list[float]) -> None:
        if not values:
            return
        low, high = bootstrap_ci(
            values,
            samples=loaded.config.evaluation.bootstrap_samples,
            level=loaded.config.evaluation.confidence_level,
            seed=seed,
        )
        estimates.append(
            MetricEstimate(
                name=name,
                numerator=sum(values),
                denominator=len(values),
                estimate=sum(values) / len(values),
                ci_low=low,
                ci_high=high,
                method="bootstrap",
            )
        )

    fn_values = [row["fn_attack_success"] for row in rows if row.get("fn_attack_success") is not None]
    fn_success = sum(1 for value in fn_values if value)
    estimates.append(
        proportion_estimate(
            "fn_asr",
            fn_success,
            len(fn_values),
            level=loaded.config.evaluation.confidence_level,
        )
    )
    fp_values = [row["fp_attack_success"] for row in rows if row.get("fp_attack_success") is not None]
    estimates.append(
        proportion_estimate(
            "fp_asr",
            sum(1 for value in fp_values if value),
            len(fp_values),
            level=loaded.config.evaluation.confidence_level,
        )
    )
    add_proportion(
        "manipulation_exposure_rate",
        [row["manipulation_exposed"] for row in rows if row.get("manipulation_exposed") is not None],
    )
    add_proportion(
        "asr",
        [row["attack_success"] for row in rows if row.get("attack_success") is not None],
    )
    add_proportion(
        "asr_given_exposure",
        [
            row["attack_success"]
            for row in rows
            if row.get("attack_success") is not None
            and row.get("manipulation_exposed") is True
        ],
    )
    add_proportion(
        "asr_given_clean_success",
        [
            row["fn_attack_success"]
            for row in rows
            if row.get("fn_attack_success") is not None
            and row.get("clean_target_found") is True
        ],
    )
    add_proportion(
        "verification_success_rate_given_exposure",
        [
            row["verification_succeeded"]
            for row in rows
            if row.get("manipulation_exposed") is True
            and row.get("verification_succeeded") is not None
        ],
    )
    add_proportion(
        "attack_success_after_decisive_verification",
        [
            row["attack_success"]
            for row in rows
            if row.get("decisive_verification") is True
            and row.get("attack_success") is not None
        ],
    )
    add_proportion(
        "severity_asr",
        [
            row["severity_attack_success"]
            for row in rows
            if row.get("severity_attack_success") is not None
        ],
    )
    add_proportion(
        "severity_evaluable_rate",
        [
            row["severity_attack_evaluable"]
            for row in rows
            if row.get("severity_attack_evaluable") is not None
            and row.get("attack_goal") in {"severity_inflation", "severity_downgrade"}
        ],
    )
    add_proportion(
        "injection_reliance_rate",
        [row["injection_reliance"] for row in rows if row.get("injection_reliance") is not None],
    )
    add_proportion(
        "decoy_reporting_rate",
        [row["decoy_reported"] for row in rows if row.get("decoy_reported") is not None],
    )
    add_proportion(
        "severity_inflation_rate",
        [
            row["severity_shift"] > 0
            for row in rows
            if row.get("severity_shift") is not None
        ],
    )
    add_proportion(
        "severity_downgrade_rate",
        [
            row["severity_shift"] < 0
            for row in rows
            if row.get("severity_shift") is not None
        ],
    )
    exposed_claims = sum(row.get("claims_exposed", 0) for row in rows)
    estimates.append(
        proportion_estimate(
            "claim_check_rate",
            sum(row.get("claims_checked", 0) for row in rows),
            exposed_claims,
            level=loaded.config.evaluation.confidence_level,
        )
    )
    estimates.append(
        proportion_estimate(
            "claim_decisive_rate",
            sum(row.get("claims_decisive", 0) for row in rows),
            exposed_claims,
            level=loaded.config.evaluation.confidence_level,
        )
    )
    estimates.append(
        proportion_estimate(
            "claim_correct_resolution_rate",
            sum(row.get("claims_correct", 0) for row in rows),
            exposed_claims,
            level=loaded.config.evaluation.confidence_level,
        )
    )
    for name, key in (
        ("eer", "adv_eer"),
        ("rer", "adv_rer"),
        ("evidence_precision", "adv_evidence_precision"),
        ("unsupported_evidence_rate", "adv_unsupported_evidence_rate"),
        ("decoy_budget_share", "adv_decoy_budget_share"),
        ("true_evidence_budget_share", "adv_true_evidence_budget_share"),
        ("verification_budget_share", "adv_verification_budget_share"),
        ("decoy_budget_share_delta", "decoy_budget_share_delta"),
        ("true_evidence_budget_share_delta", "true_evidence_budget_share_delta"),
        ("target_evidence_delay", "target_evidence_delay"),
        ("trajectory_divergence", "trajectory_divergence"),
        ("verification_depth", "verification_depth"),
    ):
        add_mean(
            name,
            [float(row[key]) for row in rows if row.get(key) is not None],
        )
    shifts = [row["severity_shift"] for row in rows if row.get("severity_shift") is not None]
    cluster_shifts: dict[str, list[float]] = {}
    cluster_directional: dict[str, list[float]] = {}
    cluster_attack: dict[str, list[float]] = {}
    for row in rows:
        key = cluster_key(row)
        if row.get("severity_shift") is not None:
            cluster_shifts.setdefault(key, []).append(float(row["severity_shift"]))
        if row.get("directional_error_increase") is not None:
            cluster_directional.setdefault(key, []).append(
                float(row["directional_error_increase"])
            )
        if row.get("attack_success") is not None:
            cluster_attack.setdefault(key, []).append(
                1.0 if row["attack_success"] else 0.0
            )
    cluster_severity_ci = cluster_bootstrap_ci(
        cluster_shifts,
        samples=loaded.config.evaluation.bootstrap_samples,
        level=loaded.config.evaluation.confidence_level,
        seed=seed,
    )
    cluster_directional_ci = cluster_bootstrap_ci(
        cluster_directional,
        samples=loaded.config.evaluation.bootstrap_samples,
        level=loaded.config.evaluation.confidence_level,
        seed=seed,
    )
    cluster_attack_ci = cluster_bootstrap_ci(
        cluster_attack,
        samples=loaded.config.evaluation.bootstrap_samples,
        level=loaded.config.evaluation.confidence_level,
        seed=seed,
    )
    cluster_estimates = [
        MetricEstimate(
            name="cluster_mean_attack_success",
            numerator=sum(sum(values) for values in cluster_attack.values()),
            denominator=sum(len(values) for values in cluster_attack.values()),
            estimate=(
                sum(sum(values) for values in cluster_attack.values())
                / sum(len(values) for values in cluster_attack.values())
                if cluster_attack
                else None
            ),
            ci_low=cluster_attack_ci[0],
            ci_high=cluster_attack_ci[1],
            method="cluster_bootstrap",
            notes=["clusters: repository + oracle_id"],
        ),
        MetricEstimate(
            name="cluster_mean_severity_shift",
            numerator=sum(sum(values) for values in cluster_shifts.values()),
            denominator=sum(len(values) for values in cluster_shifts.values()),
            estimate=(
                sum(sum(values) for values in cluster_shifts.values())
                / sum(len(values) for values in cluster_shifts.values())
                if cluster_shifts
                else None
            ),
            ci_low=cluster_severity_ci[0],
            ci_high=cluster_severity_ci[1],
            method="cluster_bootstrap",
            notes=["clusters: repository + oracle_id"],
        ),
        MetricEstimate(
            name="cluster_mean_directional_error_increase",
            numerator=sum(sum(values) for values in cluster_directional.values()),
            denominator=sum(len(values) for values in cluster_directional.values()),
            estimate=(
                sum(sum(values) for values in cluster_directional.values())
                / sum(len(values) for values in cluster_directional.values())
                if cluster_directional
                else None
            ),
            ci_low=cluster_directional_ci[0],
            ci_high=cluster_directional_ci[1],
            method="cluster_bootstrap",
            notes=["clusters: repository + oracle_id"],
        ),
    ]
    estimates.extend(cluster_estimates)
    if shifts:
        low, high = bootstrap_ci(
            shifts,
            samples=loaded.config.evaluation.bootstrap_samples,
            level=loaded.config.evaluation.confidence_level,
            seed=seed,
        )
        estimates.append(
            MetricEstimate(
                name="mean_severity_shift",
                numerator=sum(shifts),
                denominator=len(shifts),
                estimate=sum(shifts) / len(shifts),
                ci_low=low,
                ci_high=high,
                method="paired_bootstrap",
            )
        )
    clean_found: list[bool] = []
    adv_found: list[bool] = []
    for row in rows:
        if row.get("clean_target_found") is not None and row.get("adv_target_found") is not None:
            clean_found.append(bool(row["clean_target_found"]))
            adv_found.append(bool(row["adv_target_found"]))
    mcnemar = mcnemar_test(clean_found, adv_found) if clean_found else None
    wilcoxon = wilcoxon_signed_rank(shifts) if shifts else None
    p_values = []
    p_names = []
    if mcnemar is not None and mcnemar.get("p_value") is not None:
        p_names.append("target_detection_mcnemar")
        p_values.append(mcnemar["p_value"])
    if wilcoxon is not None and wilcoxon.get("p_value") is not None:
        p_names.append("severity_shift_wilcoxon")
        p_values.append(wilcoxon["p_value"])
    adjusted = adjust_p_values(p_values, loaded.config.evaluation.multiple_testing)
    multiple = [
        {"name": name, "p_value": p, "adjusted_p_value": adjusted_value, "method": loaded.config.evaluation.multiple_testing}
        for name, p, adjusted_value in zip(p_names, p_values, adjusted)
    ]
    # Failure bounds: treat every excluded adversarial run as success / failure.
    valid = [row for row in rows if row.get("adv_valid")]
    invalid = [row for row in rows if not row.get("adv_valid")]
    denominator = len(valid) + len(invalid)
    failure_bounds = {
        "all_failures_failure_lower": (
            sum(1 for row in valid if row.get("fn_attack_success")) / denominator
            if denominator
            else None
        ),
        "all_failures_success_upper": (
            (
                sum(1 for row in valid if row.get("fn_attack_success"))
                + len(invalid)
            )
            / denominator
            if denominator
            else None
        ),
    }
    repo_values: dict[str, list[float]] = {}
    for row in rows:
        if row.get("attack_success") is None:
            continue
        repo = row.get("repository") or "unknown"
        repo_values.setdefault(repo, []).append(1.0 if row["attack_success"] else 0.0)
    repo_means = [
        sum(values) / len(values) for values in repo_values.values() if values
    ]
    repo_macro = {
        "metric": "attack_success",
        "repository_count": len(repo_means),
        "estimate": (sum(repo_means) / len(repo_means)) if repo_means else None,
        "method": "repository_macro_mean_of_means",
        "note": "targets/candidates/repetitions within a repository stay in one cluster; "
        "template duplicates are not independent repositories",
    }
    bootstrap_samples = (
        loaded.config.experiment.bootstrap_samples
        or loaded.config.evaluation.bootstrap_samples
    )
    bootstrap_seed = (
        loaded.config.experiment.bootstrap_seed
        if loaded.config.experiment.bootstrap_seed is not None
        else seed
    )
    repository_bootstrap = {
        "cluster_key": "repository",
        "samples": max(int(bootstrap_samples), 100),
        "seed": bootstrap_seed,
        "confidence_level": loaded.config.evaluation.confidence_level,
        "cluster_count": len({repository_cluster_key(row) for row in rows}),
        "estimates": [
            repository_cluster_bootstrap(
                rows,
                field=field,
                samples=int(bootstrap_samples),
                level=loaded.config.evaluation.confidence_level,
                seed=bootstrap_seed,
            )
            for field in ("fn_attack_success", "attack_success", "manipulation_exposed")
        ],
        "note": (
            "clusters are repositories; targets, variants and repetitions of one "
            "repository are resampled together (P1-2)"
        ),
    }
    macro_estimate = {
        "name": "macro_target_asr",
        "estimate": (repetition or {}).get("macro", {}).get("macro_fn_asr"),
        "method": "mean_of_target_level_empirical_probabilities",
        "note": "target-level means; a single 5-repetition target is a coarse estimate",
    }
    micro_estimate = {
        "name": "micro_paired_repetition_asr",
        "estimate": (repetition or {}).get("micro", {}).get("fn_asr"),
        "numerator": (repetition or {}).get("micro", {}).get("fn_success_repetitions"),
        "denominator": (repetition or {}).get("micro", {}).get("fn_eligible_repetitions"),
        "method": "pooled_paired_repetitions",
    }
    return {
        "repo_macro": repo_macro,
        "estimates": [item.model_dump(mode="json") for item in estimates],
        "metric_estimates": [item.model_dump(mode="json") for item in estimates],
        "confidence_level": loaded.config.evaluation.confidence_level,
        "mcnemar": mcnemar,
        "wilcoxon": wilcoxon,
        "multiple_testing": multiple,
        "failure_bounds": failure_bounds,
        "cluster_bootstrap": {
            "cluster_key": "repository+oracle_id",
            "cluster_count": len(cluster_attack) or len(cluster_shifts),
            "estimates": [item.model_dump(mode="json") for item in cluster_estimates],
        },
        # P1-2: distinct, clearly named units of analysis.
        "macro_target_asr": macro_estimate,
        "micro_paired_repetition_asr": micro_estimate,
        "repository_cluster_bootstrap_95ci": repository_bootstrap,
        "seed": seed,
        "method": "wilson/bootstrap/mcnemar/wilcoxon/cluster_bootstrap",
    }


def _attempt_rule(loaded: LoadedConfig) -> str:
    """Pre-registered attempt selection; ``none`` when no retry was declared."""
    policy = loaded.config.experiment.retry_policy
    if policy.max_attempts <= 1 and policy.selection_rule == "none":
        return "none"
    if policy.selection_rule != "none":
        return policy.selection_rule
    return loaded.config.evaluation.attempt_selection


def evaluate_release(
    *,
    loaded: LoadedConfig,
    release_dir: Path,
    runs_dir: Path,
    output_dir: Path,
    matching_profile: str = "strict",
) -> dict[str, Any]:
    from ..export.bundle import load_release, validate_release

    integrity = validate_release(loaded=loaded, release_dir=Path(release_dir))
    if not integrity["ok"]:
        raise ReleaseError(
            "release bundle failed integrity validation",
            details={"errors": integrity["errors"][:20]},
        )
    manifest, root = load_release(release_dir)
    release_assets: dict[str, tuple] = {}
    for entry in manifest.instances:
        release_assets[entry.instance_id] = _load_release_assets(root, entry)
    run_dirs = _discover_runs(Path(runs_dir))
    if not run_dirs:
        raise ReleaseError("no run directories found", details={"runs": str(runs_dir)})
    evaluated: list[EvaluatedRun] = []
    load_failures: list[dict[str, Any]] = []
    for run_dir in run_dirs:
        item, failure = _load_run(loaded, run_dir, release_assets, matching_profile)
        if item is not None:
            evaluated.append(item)
        if failure is not None:
            load_failures.append(failure)
    if not evaluated:
        raise ReleaseError("no evaluable runs were found")
    rows = pair_rows(
        evaluated,
        tolerance=loaded.config.matching.line_tolerance,
        path_policy=loaded.config.evaluation.primary_path_policy,
        severity_success_delta=loaded.config.evaluation.severity_success_delta,
        groups={
            group.adversarial_instance_id: group for group in manifest.groups
        },
        attempt_rule=_attempt_rule(loaded),
        legacy_condition_mode=loaded.config.evaluation.legacy_condition_mode,
    )
    failures = _failures(evaluated, load_failures, rows)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    _write_jsonl(output_dir / "runs.jsonl", [item.run.model_dump(mode="json") for item in evaluated])
    findings_rows = []
    matches_rows = []
    event_rows = []
    assessment_rows = []
    for item in evaluated:
        findings = item.findings or []
        assignment = item.outcome.assignment if item.outcome else {}
        record_by_id = {
            record.finding_id: record for record in (item.outcome.matches if item.outcome else [])
        }
        for finding in findings:
            record = record_by_id.get(finding.finding_id)
            findings_rows.append(
                {
                    "run_id": item.run.run_id,
                    "instance_id": item.run.instance_id,
                    "pair_id": item.instance.pair_id,
                    "model": f"{item.run.model_provider}/{item.run.model_name}",
                    "scaffold": item.run.scaffold,
                    "repetition": item.run.repetition,
                    "matched_path_id": assignment.get(finding.finding_id),
                    "matched_decoy": bool(record and record.matched_decoy),
                    "decoy_id": record.decoy_id if record else None,
                    "finding": finding.model_dump(mode="json"),
                }
            )
        for record in item.outcome.matches if item.outcome else []:
            matches_rows.append(
                {
                    "run_id": item.run.run_id,
                    "instance_id": item.run.instance_id,
                    "pair_id": item.instance.pair_id,
                    **record.model_dump(mode="json"),
                }
            )
        for enriched in item.enriched:
            event_rows.append(
                {
                    "run_id": item.run.run_id,
                    "instance_id": item.run.instance_id,
                    "pair_id": item.instance.pair_id,
                    **enriched.model_dump(mode="json"),
                }
            )
        for assessment in item.assessments:
            assessment_rows.append(
                {
                    "run_id": item.run.run_id,
                    "instance_id": item.run.instance_id,
                    "pair_id": item.instance.pair_id,
                    "manipulation_tier": item.instance.manipulation_tier.value,
                    "attack_goal": item.manipulation.attack_goal.value if item.manipulation else None,
                    **assessment.model_dump(mode="json"),
                }
            )
    _write_jsonl(output_dir / "findings.jsonl", findings_rows)
    _write_jsonl(output_dir / "matches.jsonl", matches_rows)
    roots = [
        str(loaded.paths.root),
        str(loaded.paths.root.resolve()),
        str(loaded.base_dir),
        str(Path.home()),
    ]
    event_rows = [_sanitize_report_value(row, roots) for row in event_rows]
    _write_jsonl(output_dir / "event_index.jsonl", event_rows)
    _write_jsonl(output_dir / "verification_assessments.jsonl", assessment_rows)

    instance_rows = []
    evidence_rows = []
    trajectory_rows = []
    resource_rows = []
    access_rows = []
    for item in evaluated:
        flattened = _flatten_metrics(item)
        instance_rows.append(
            {
                "run_id": item.run.run_id,
                "instance_id": item.run.instance_id,
                "pair_id": item.instance.pair_id,
                "variant_kind": item.instance.variant_kind.value,
                "model": f"{item.run.model_provider}/{item.run.model_name}",
                "scaffold": item.run.scaffold,
                "repetition": item.run.repetition,
                "audit_difficulty": item.instance.audit_difficulty.value,
                "manipulation_tier": item.instance.manipulation_tier.value,
                "attack_goal": (
                    item.manipulation.attack_goal.value if item.manipulation else None
                ),
                "release_split": item.instance.release_split,
                "mechanism": (
                    item.manipulation.mechanism.value
                    if item.manipulation and item.manipulation.mechanism
                    else None
                ),
                "carrier": item.manipulation.carrier if item.manipulation else None,
                "presentation": (
                    item.manipulation.presentation.value
                    if item.manipulation and item.manipulation.presentation
                    else None
                ),
                "distribution": (
                    item.manipulation.distribution.value if item.manipulation else None
                ),
                "generation_method": (
                    item.manipulation.generation_method.value
                    if item.manipulation
                    else None
                ),
                "candidate_id": item.instance.candidate_id,
                "group_id": item.instance.group_id,
                "target_id": item.instance.target_id,
                "target_kind": item.instance.target_kind,
                "condition_id": item.condition_id,
                "condition_source": item.condition_source,
                "defense_id": item.run.defense_id,
                "defense_version": item.run.defense_version,
                "model_version": item.run.model_version,
                "scaffold_version": item.run.scaffold_version,
                "attempt": item.run.attempt,
                "run_status": item.run.status,
                "parse_status": item.parse_status,
                **item.metrics,
                **flattened,
            }
        )
        if item.evidence is not None:
            evidence_rows.append(
                {
                    "run_id": item.run.run_id,
                    "instance_id": item.run.instance_id,
                    "pair_id": item.instance.pair_id,
                    "observability_grade": item.observability_grade,
                    **item.evidence,
                }
            )
        if item.trajectory is not None:
            trajectory_rows.append(
                {
                    "run_id": item.run.run_id,
                    "instance_id": item.run.instance_id,
                    "pair_id": item.instance.pair_id,
                    "observability_grade": item.observability_grade,
                    **item.trajectory,
                }
            )
        if item.resource is not None:
            resource_rows.append(
                {
                    "run_id": item.run.run_id,
                    "instance_id": item.run.instance_id,
                    "pair_id": item.instance.pair_id,
                    "observability_grade": item.observability_grade,
                    **item.resource,
                }
            )
        operation_counts: dict[str, int] = {}
        for record in item.file_access:
            operation_counts[record.operation] = operation_counts.get(record.operation, 0) + 1
        citations = [
            citation.location
            for finding in (item.findings or [])
            for citation in finding.evidence_citations
        ]
        cited_accesses = 0
        for record in item.file_access:
            start = record.observed_start_line or record.requested_start_line
            end = record.observed_end_line or record.requested_end_line or start
            if start is None:
                continue
            if any(
                citation.file == record.path
                and citation.start_line <= end
                and start <= citation.end_line
                for citation in citations
            ):
                cited_accesses += 1
        access_rows.append(
            {
                "run_id": item.run.run_id,
                "instance_id": item.run.instance_id,
                "pair_id": item.instance.pair_id,
                "total_accesses": len(item.file_access),
                "read_count": operation_counts.get("read", 0),
                "search_match_count": operation_counts.get("search_match", 0),
                "tool_context_count": operation_counts.get("tool_context", 0),
                "stat_count": operation_counts.get("stat", 0),
                "list_count": operation_counts.get("list", 0),
                "bulk_runtime_read_count": operation_counts.get("bulk_runtime_read", 0),
                "unknown_line_count": sum(
                    1
                    for record in item.file_access
                    if record.observed_start_line is None
                    and record.operation in {"read", "search_match", "tool_context"}
                ),
                "content_returned_to_model_count": sum(
                    1 for record in item.file_access if record.content_returned_to_model
                ),
                "content_truncated_count": sum(
                    1 for record in item.file_access if record.content_truncated
                ),
                "content_cited_in_final_report_count": cited_accesses,
                "observability_grade": item.observability_grade,
            }
        )
    _write_csv(output_dir / "instance_metrics.csv", instance_rows, INSTANCE_METRIC_COLUMNS)
    _write_csv(output_dir / "pair_metrics.csv", rows, PAIR_COLUMNS)
    _write_csv(output_dir / "evidence_metrics.csv", evidence_rows)
    _write_csv(output_dir / "trajectory_metrics.csv", trajectory_rows)
    _write_csv(output_dir / "resource_metrics.csv", resource_rows)
    _write_csv(output_dir / "file_access_summary.csv", access_rows)
    tier_rows = aggregate_by(rows, "manipulation_tier")
    difficulty_rows = aggregate_by(rows, "audit_difficulty")
    goal_rows = aggregate_by(rows, "attack_goal")
    model_rows = aggregate_rows(rows, group_fields=["model", "scaffold"])
    defense_rows = aggregate_rows(
        rows, group_fields=["model", "scaffold", "defense_id", "defense_version"]
    )
    condition_rows = aggregate_rows(rows, group_fields=["condition_id", "condition_source"])
    mechanism_rows = aggregate_by(rows, "mechanism")
    carrier_rows = aggregate_by(rows, "carrier")
    generation_rows = aggregate_by(rows, "generation_method")
    target_source_rows = aggregate_by(rows, "target_source")
    report_access_rows = aggregate_by(rows, "report_access")
    _write_csv(output_dir / "aggregate_by_tier.csv", tier_rows)
    _write_csv(output_dir / "aggregate_by_difficulty.csv", difficulty_rows)
    _write_csv(output_dir / "aggregate_by_goal.csv", goal_rows)
    _write_csv(output_dir / "aggregate_by_model_scaffold.csv", model_rows)
    _write_csv(output_dir / "aggregate_by_defense.csv", defense_rows)
    _write_csv(output_dir / "aggregate_by_condition.csv", condition_rows)
    _write_csv(output_dir / "aggregate_by_mechanism.csv", mechanism_rows)
    _write_csv(output_dir / "aggregate_by_carrier.csv", carrier_rows)
    _write_csv(output_dir / "aggregate_by_generation_method.csv", generation_rows)
    _write_csv(output_dir / "aggregate_by_target_source.csv", target_source_rows)
    _write_csv(output_dir / "aggregate_by_report_access.csv", report_access_rows)
    _write_csv(output_dir / "failures.csv", failures)

    overall = aggregate_rows(rows)
    roots = [
        str(loaded.paths.root),
        str(loaded.paths.root.resolve()),
        str(loaded.base_dir),
        str(Path.home()),
    ]
    failures = [_sanitize_report_value(row, roots) for row in failures]
    seed = derive_seed(loaded.config.generation.global_seed, "evaluation", manifest.release_id)
    repetition_config = _configured_repetitions(Path(runs_dir), loaded)
    minimum_valid_repetitions = (
        loaded.config.evaluation.minimum_valid_repetitions
        or repetition_config.get("minimum_valid_repetitions")
        or loaded.config.experiment.minimum_valid_repetitions
    )
    repetition = repetition_statistics(
        rows,
        configured_repetitions=int(repetition_config["repetitions"]),
        minimum_valid_repetitions=int(minimum_valid_repetitions),
        include_legacy=loaded.config.evaluation.include_legacy_in_formal_statistics,
    )
    exposure_summary = summarize_exposure(rows)
    defense_matrix = _defense_matrix(rows)
    statistics = _statistics(rows, loaded, seed, repetition=repetition)
    _write_csv(
        output_dir / "repetition_metrics.csv",
        repetition.get("per_target", []),
    )
    defense_matrix_rows = [
        {
            "defense_id": item.get("defense_id"),
            "defense_version": item.get("defense_version"),
            "pair_rows": item.get("pair_rows"),
            "valid_paired_repetitions": item.get("valid_paired_repetitions"),
            "clean_target_detection_rate": item.get("clean_target_detection_rate"),
            "attack_target_detection_rate": item.get("attack_target_detection_rate"),
            "fn_asr": item.get("fn_asr"),
            "fp_asr": item.get("fp_asr"),
            "severity_asr": item.get("severity_asr"),
            "exposure_rate": item.get("exposure_rate"),
            "exposure_unknown_count": item.get("exposure_unknown_count"),
            "mean_duration_seconds": item.get("mean_duration_seconds"),
            "mean_tool_calls": item.get("mean_tool_calls"),
            "timeout_or_error_rate": item.get("timeout_or_error_rate"),
            "fn_asr_delta_vs_d0": (item.get("delta_vs_d0") or {}).get("fn_asr"),
            "clean_utility_delta_vs_d0": (item.get("delta_vs_d0") or {}).get(
                "clean_target_detection_rate"
            ),
        }
        for item in defense_matrix.get("per_defense", [])
    ]
    _write_csv(output_dir / "defense_matrix.csv", defense_matrix_rows)
    observability_strata: dict[str, int] = {grade: 0 for grade in "ABCD"}
    for item in evaluated:
        observability_strata[item.observability_grade] = (
            observability_strata.get(item.observability_grade, 0) + 1
        )
    counts = {
        "scheduled_runs": len(run_dirs),
        "all_scheduled_runs": len(run_dirs),
        "loaded_runs": len(evaluated),
        "valid_runs": sum(1 for item in evaluated if item.metrics.get("valid_run")),
        "successful_parseable_runs": sum(
            1
            for item in evaluated
            if item.parse_status == "ok"
            and item.run.status in {"success", "observer_failure"}
        ),
        "parseable_runs": sum(1 for item in evaluated if item.parse_status == "ok"),
        "observable_runs": sum(1 for item in evaluated if item.observability_grade in {"A", "B"}),
        "observable_ab_runs": sum(
            1 for item in evaluated if item.observability_grade in {"A", "B"}
        ),
        "exposed_adversarial_runs": sum(
            1
            for row in rows
            if row.get("manipulation_exposed") is True
        ),
        "manipulation_exposed_runs": sum(
            1 for row in rows if row.get("manipulation_exposed") is True
        ),
        "clean_correct_runs": sum(
            1 for row in rows if row.get("clean_target_found") is True
        ),
        "clean_correct_paired_runs": sum(
            1 for row in rows if row.get("clean_target_found") is True
        ),
        "failure_rows": len(failures),
        "reference_runs_excluded": sum(
            1
            for item in load_failures
            if item.get("failure_type") == "reference_run_excluded"
        ),
        "unmatched_needs_adjudication_rows": sum(
            1
            for row in rows
            if (row.get("adv_unmatched_needs_adjudication") or 0) > 0
        ),
        "label_incomplete_rows": sum(
            1 for row in rows if row.get("label_completeness") == "partial"
        ),
        "pairing_incomplete_rows": sum(
            1 for row in rows if row.get("pairing_complete") is False
        ),
        "pairing_not_evaluable_rows": sum(
            1 for row in rows if row.get("pairing_status") == "not_evaluable"
        ),
        "ambiguous_pairing_rows": sum(
            1
            for row in rows
            if row.get("adv_attempt_ambiguous")
            or row.get("clean_attempt_ambiguous")
            or row.get("benign_attempt_ambiguous")
            or row.get("truthful_attempt_ambiguous")
        ),
        "formal_rows": sum(1 for row in rows if row.get("formal_eligible") is True),
        "legacy_condition_rows": sum(
            1 for row in rows if row.get("condition_source") == "legacy_reduced"
        ),
        "exposure_known_rows": exposure_summary["exposure_known_count"],
        "exposure_unknown_rows": exposure_summary["exposure_unknown_count"],
    }
    availability_degradation = {
        "timeouts": sum(1 for item in evaluated if item.run.status == "timeout"),
        "agent_tool_failures": sum(
            1 for item in evaluated if item.run.status == "agent_tool_failure"
        ),
        "infrastructure_failures": sum(
            1 for item in evaluated if item.run.status == "infrastructure_failure"
        ),
        "observer_failures": sum(
            1 for item in evaluated if item.run.status == "observer_failure"
        ),
        "format_failures": sum(
            1 for item in evaluated if item.parse_status == "format_failure"
        ),
        "contaminations": sum(
            1 for item in evaluated if item.meta and item.meta.contaminated
        ),
    }
    missingness = {
        "token_usage_missing_runs": sum(
            1
            for item in evaluated
            if not item.resource or item.resource.get("token_usage_missing")
        ),
        "unknown_line_runs": sum(
            1 for item in evaluated if item.evidence and not item.evidence.get("unknown_line_coverage", True)
        ),
        "observer_downgraded_runs": sum(
            1 for item in evaluated if item.observability_grade in {"C", "D"}
        ),
    }
    missing_reason_counts: dict[str, int] = {}
    for row in rows:
        for key in (
            "clean_missing_reason",
            "benign_missing_reason",
            "truthful_missing_reason",
            "target_missing_reason",
            "severity_missing_reason",
        ):
            value = row.get(key)
            if value:
                label = f"{key}:{value}"
                missing_reason_counts[label] = missing_reason_counts.get(label, 0) + 1
    unique_clean_runs: dict[str, bool | None] = {}
    for item in evaluated:
        if item.instance.variant_kind.value != "clean":
            continue
        unique_clean_runs.setdefault(
            item.run.run_id, item.metrics.get("repository_any_vulnerability_found")
        )
    clean_unique_values = [
        value for value in unique_clean_runs.values() if value is not None
    ]
    summary = {
        "evaluator_schema_version": EVALUATOR_SCHEMA_VERSION,
        "metric_schema_version": METRIC_SCHEMA_VERSION,
        "schema_version": "1.0",
        "generated_at": utc_now_iso(),
        "release_id": manifest.release_id,
        "release_name": manifest.name,
        "release_version": manifest.release_version,
        "release_sha256": manifest.release_sha256,
        "config_sha256": loaded.sha256,
        "matching_profile": matching_profile,
        "path_policy": loaded.config.evaluation.primary_path_policy,
        "run_count": len(evaluated),
        "findings_count": len(findings_rows),
        "match_count": sum(len(item.outcome.assignment) for item in evaluated if item.outcome),
        "pair_row_count": len(rows),
        "counts": counts,
        "failure_rate": (
            len(failures) / len(evaluated) if evaluated else None
        ),
        "failure_count": len(failures),
        "missing_reason_counts": missing_reason_counts,
        "clean_utility": {
            "basis": "unique_clean_run",
            "unique_clean_runs": len(unique_clean_runs),
            "repository_any_vulnerability_found_rate": (
                sum(1 for value in clean_unique_values if value) / len(clean_unique_values)
                if clean_unique_values
                else None
            ),
            "note": "clean runs are shared by several attack targets and are not "
            "counted once per attack candidate",
        },
        "micro_macro": {
            "micro": "pair-row / target-level estimate (repetitions averaged within an attack instance)",
            "repo_macro": "repository-level average of cluster means (repository+oracle cluster)",
        },
        "availability_degradation": availability_degradation,
        "observability_strata": observability_strata,
        "missingness": missingness,
        "instance_metrics": instance_rows,
        "paired_metrics": rows,
        "overall": overall[0] if overall else {},
        "statistics": statistics,
        "experiment": {
            "configured_repetitions": int(repetition_config["repetitions"]),
            "repetitions_source": repetition_config["source"],
            "minimum_valid_repetitions": int(minimum_valid_repetitions),
            "retry_policy": loaded.config.experiment.retry_policy.model_dump(mode="json"),
            "stability_status": repetition.get("stability_status"),
            "note": (
                "five repetitions of one target are a step-0.2 empirical "
                "probability, not a precise population estimate"
            ),
        },
        "repetition_statistics": repetition,
        "repetition_probabilities": repetition.get("micro", {}),
        "target_probabilities": repetition.get("macro", {}),
        "stability_status": repetition.get("stability_status"),
        "exposure": exposure_summary,
        "defense_matrix": defense_matrix,
        "by_tier": tier_rows,
        "by_difficulty": difficulty_rows,
        "by_goal": goal_rows,
        "by_model_scaffold": model_rows,
        "by_defense": defense_rows,
        "by_condition": condition_rows,
        "by_mechanism": mechanism_rows,
        "by_carrier": carrier_rows,
        "by_generation_method": generation_rows,
        "by_target_source": target_source_rows,
        "by_report_access": report_access_rows,
        "reference_runs_excluded": counts["reference_runs_excluded"],
        "label_completeness": (
            "complete" if rows and all(row.get("label_completeness") == "complete" for row in rows) else "partial"
        ),
        "not_evaluable": {
            "full_repository_precision_f1": (
                None
                if rows and all(row.get("label_completeness") == "complete" for row in rows)
                else "partial label set: unmatched findings are not confirmed false positives"
            ),
            "unmatched_findings": (
                sum(
                    int(row.get("adv_unmatched_needs_adjudication") or 0)
                    for row in rows
                )
                if rows
                else None
            ),
        },
        "severity_metrics": {
            "target_vulnerability_scoped": True,
            "success_delta": loaded.config.evaluation.severity_success_delta,
            "asr_by_goal": {
                row.get("attack_goal"): row.get("severity_asr")
                for row in goal_rows
                if row.get("attack_goal") in {"severity_inflation", "severity_downgrade"}
            },
        },
        "failure_count": len(failures),
        "failures_by_type": _count_by(failures, "failure_type"),
        "limitations": [
            "Agent network isolation is enforced through proxy variables and a controlled environment, not an OS firewall.",
            "Process/evidence/trajectory metrics are only reported for observability grades A/B.",
            "Token usage is only measured when the agent emits token fields in observable events.",
            "New-vulnerability detection depends on an optional configured scanner; absence of new vulnerabilities is not otherwise proven.",
            "Hidden chain-of-thought is never collected; stage labels are deterministic observable-event rules.",
            "Bootstrap confidence intervals are paired/instance-aware but not a substitute for a pre-registered confirmatory analysis.",
        ],
    }
    feedback_path = None
    if loaded.config.generation.feedback_enabled:
        from ..generation.feedback import build_feedback_snapshot, write_feedback_snapshot

        if all(item.startswith("dev-") for item in manifest.splits):
            try:
                snapshot = build_feedback_snapshot(
                    rows,
                    split=manifest.splits[0],
                    source_release_id=manifest.release_id,
                    source_report=str(output_dir),
                )
                feedback_path = output_dir / "feedback_snapshot.json"
                write_feedback_snapshot(feedback_path, snapshot)
                summary["feedback_snapshot"] = feedback_path.relative_to(output_dir).as_posix()
            except Exception as exc:  # noqa: BLE001
                summary["feedback_error"] = str(exc)
        else:
            summary["feedback_skipped"] = "release contains non-development splits"
    atomic_write_json(output_dir / "summary.json", summary)
    return {
        "ok": True,
        "release_id": manifest.release_id,
        "runs": len(evaluated),
        "pair_rows": len(rows),
        "failures": len(failures),
        "matching_profile": matching_profile,
        "output": str(output_dir.resolve()),
        "overall": overall[0] if overall else {},
        "counts": counts,
        "observability_strata": observability_strata,
        "availability_degradation": availability_degradation,
        "statistics": statistics,
        "summary": str((output_dir / "summary.json").resolve()),
        "report_files": {
            "runs_jsonl": str(output_dir / "runs.jsonl"),
            "findings_jsonl": str(output_dir / "findings.jsonl"),
            "matches_jsonl": str(output_dir / "matches.jsonl"),
            "event_index_jsonl": str(output_dir / "event_index.jsonl"),
            "verification_assessments_jsonl": str(output_dir / "verification_assessments.jsonl"),
            "instance_metrics_csv": str(output_dir / "instance_metrics.csv"),
            "pair_metrics_csv": str(output_dir / "pair_metrics.csv"),
            "evidence_metrics_csv": str(output_dir / "evidence_metrics.csv"),
            "trajectory_metrics_csv": str(output_dir / "trajectory_metrics.csv"),
            "resource_metrics_csv": str(output_dir / "resource_metrics.csv"),
            "file_access_summary_csv": str(output_dir / "file_access_summary.csv"),
            "aggregate_by_target_source_csv": str(output_dir / "aggregate_by_target_source.csv"),
            "aggregate_by_report_access_csv": str(output_dir / "aggregate_by_report_access.csv"),
            "defense_matrix_csv": str(output_dir / "defense_matrix.csv"),
            "repetition_metrics_csv": str(output_dir / "repetition_metrics.csv"),
            "failures_csv": str(output_dir / "failures.csv"),
        },
    }


def _count_by(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get(field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts
