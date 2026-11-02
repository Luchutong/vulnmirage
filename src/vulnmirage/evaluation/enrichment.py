"""Post-hoc oracle enrichment for one completed agent run."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import LoadedConfig
from ..hashing import sha256_file, sha256_text
from ..harness.base import PreparedRun, RawRunResult
from ..harness.observation import ObservationBundle
from ..models import (
    AgentRun,
    BenchmarkInstance,
    CanonicalVulnerabilityOracle,
    DecoyRecord,
    EvidenceContract,
    ManipulationSpec,
    VerificationAssessment,
)
from ..store import InstanceStore
from .evidence import (
    build_evidence_nodes,
    evidence_coverage_curve,
    evidence_metrics,
    verify_claims,
)
from .matching import MatchOutcome, match_instance
from .metrics import compute_instance_metrics
from .parser import ParsedOutput
from .resource import resource_metrics
from .stages import enrich_trajectory
from .trajectory import sequence_distance, role_sequence, trajectory_metrics


@dataclass
class EnrichmentResult:
    run: AgentRun
    outcome: MatchOutcome | None
    assessments: list[VerificationAssessment]
    evidence: dict[str, Any] | None
    trajectory: dict[str, Any] | None
    resource: dict[str, Any] | None
    metrics: dict[str, Any]
    enriched_count: int
    artifact_sha256: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def enrich_run(
    *,
    loaded: LoadedConfig,
    store: InstanceStore,
    run: AgentRun,
    prepared: PreparedRun,
    raw_result: RawRunResult,
    instance: BenchmarkInstance,
    oracle: CanonicalVulnerabilityOracle,
    manipulation: ManipulationSpec | None,
    decoys: list[DecoyRecord],
    contract: EvidenceContract | None,
    parsed: ParsedOutput | None,
    observation: ObservationBundle,
    parse_status: str,
    parse_error: str | None,
    end_monotonic_ns: int | None = None,
) -> EnrichmentResult:
    run_dir = prepared.run_dir
    findings = parsed.findings if parsed is not None else None
    outcome = None
    if findings is not None:
        outcome = match_instance(
            findings,
            oracle,
            decoys=decoys,
            config=loaded.config.matching,
            profile=loaded.config.evaluation.primary_match,
        )
    process_eligible = observation.process_metrics_eligible
    notes: list[str] = []
    if not process_eligible:
        notes.append(
            "observability grade below process-metric threshold; evidence/trajectory/resource metrics are not reported"
        )
    nodes = build_evidence_nodes(
        oracle, decoys=decoys, contract=contract, manipulation=manipulation
    )
    enriched = enrich_trajectory(
        run_id=run.run_id,
        events=observation.normalized.primary_events,
        nodes=nodes,
        contract=contract,
        findings=findings,
        config=loaded.config.trajectory,
    )
    evidence = None
    trajectory = None
    resource = None
    assessments: list[VerificationAssessment] = []
    if process_eligible:
        evidence = evidence_metrics(
            oracle=oracle,
            findings=findings or [],
            accesses=observation.normalized.file_access,
            contract=contract,
            decoys=decoys,
            manipulation=manipulation,
            observation=loaded.config.observation,
            trajectory=loaded.config.trajectory,
            line_tolerance=loaded.config.matching.line_tolerance,
        )
        trajectory = trajectory_metrics(
            enriched=enriched,
            start_monotonic_ns=raw_result.started_monotonic_ns,
            assessments=assessments,
            end_monotonic_ns=end_monotonic_ns,
        )
    if contract is not None:
        assessments = verify_claims(
            run_id=run.run_id,
            contract=contract,
            events=observation.normalized.events,
            accesses=observation.normalized.file_access,
            findings=findings,
            outcome=outcome,
            trajectory=loaded.config.trajectory,
            rule_version=loaded.config.trajectory.verification_rule_version,
        )
    if process_eligible:
        trajectory = trajectory_metrics(
            enriched=enriched,
            start_monotonic_ns=raw_result.started_monotonic_ns,
            assessments=assessments,
            end_monotonic_ns=end_monotonic_ns,
        )
        trajectory["coverage_curve"] = evidence_coverage_curve(
            accesses=observation.normalized.file_access,
            nodes=nodes,
            exposure_operations=set(loaded.config.trajectory.exposure_operations),
            start_monotonic_ns=raw_result.started_monotonic_ns,
        )
        trajectory["stage_rule_version"] = loaded.config.trajectory.stage_rule_version
        resource = resource_metrics(
            enriched=enriched,
            correct_findings=(
                len(outcome.assignment) if outcome is not None else None
            ),
            timeout=run.status == "timeout",
            agent_tool_failure=run.status == "agent_tool_failure",
            incomplete_report=findings is None,
        )
        evidence["exposed_claim_count"] = len(
            {
                claim_id
                for assessment in assessments
                if assessment.exposure_event_ids
                for claim_id in [assessment.claim_id]
            }
        )
    metrics = compute_instance_metrics(
        findings=findings,
        oracle=oracle,
        outcome=outcome,
        decoys=decoys,
        config=loaded.config.matching,
        run_status=run.status,
        parse_status=parse_status,
        contaminated=raw_result.contaminated,
        observability_grade=observation.grade.value,
        process_metrics_eligible=process_eligible,
    )
    metrics["verification_depth"] = (
        max((assessment.depth_score for assessment in assessments), default=None)
        if assessments and process_eligible
        else None
    )
    metrics["verification_resolution"] = (
        assessments[0].resolution.value if assessments and process_eligible else None
    )
    metrics["manipulation_exposed"] = (
        any(assessment.exposure_event_ids for assessment in assessments)
        if assessments and process_eligible
        else None
    )
    metrics["observability_grade"] = observation.grade.value
    metrics["process_metrics_eligible"] = process_eligible
    metrics["evidence"] = evidence
    metrics["trajectory"] = trajectory
    metrics["resource"] = resource
    metrics["parse_error"] = parse_error

    from ..hashing import atomic_write_json
    from ..models import EnrichedTrajectoryEvent

    findings_path = prepared.findings_path or (run_dir / "findings.json")
    if not findings_path.is_file():
        # The harness artifact contract normally writes findings.json (with an
        # explicit status and parse metadata) before enrichment.  Only produce a
        # minimal legacy-compatible file when it is absent, and never render a
        # failed parse as a successful empty report.
        failed = parsed is None
        atomic_write_json(
            findings_path,
            {
                "schema_version": "1.0",
                "status": "ok" if not failed else (parse_status or "invalid"),
                "failed": failed,
                "excluded_from_metrics": failed,
                "findings": (
                    parsed.envelope.findings if parsed is not None else []
                ),
                "audit_summary": (
                    parsed.envelope.audit_summary.model_dump(mode="json")
                    if parsed is not None
                    else {
                        "files_reviewed": [],
                        "limitations": [parse_error or "agent output could not be parsed"],
                        "overall_confidence": 0.0,
                    }
                ),
                "parse_status": parse_status,
                "parse_error": parse_error,
            },
        )
    trajectory_path = prepared.trajectory_path or (run_dir / "trajectory_enriched.jsonl")
    trajectory_path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(
        item.model_dump_json() + "\n" for item in enriched
    )
    trajectory_path.write_text(text, encoding="utf-8")
    assessments_path = prepared.verification_path or (run_dir / "verification_assessments.json")
    atomic_write_json(assessments_path, [item.model_dump(mode="json") for item in assessments])
    matches_path = prepared.matches_path or (run_dir / "matches.json")
    atomic_write_json(
        matches_path,
        {
            "profile": loaded.config.evaluation.primary_match,
            "outcome": outcome.model_dump(mode="json") if outcome is not None else None,
            "finding_count": len(findings or []),
        },
    )
    metrics_path = prepared.metrics_path or (run_dir / "metrics.json")
    atomic_write_json(metrics_path, metrics)

    artifact_sha256 = {
        **observation.artifact_sha256,
        "findings.json": sha256_file(findings_path) if findings_path.is_file() else None,
        "trajectory_enriched.jsonl": sha256_file(trajectory_path),
        "verification_assessments.json": sha256_file(assessments_path),
        "matches.json": sha256_file(matches_path),
        "metrics.json": sha256_file(metrics_path),
        "final_raw.txt": sha256_file(run_dir / "final_raw.txt")
        if (run_dir / "final_raw.txt").is_file()
        else None,
    }
    artifact_sha256 = {
        key: value for key, value in artifact_sha256.items() if value is not None
    }
    updated = run.model_copy(
        update={
            "findings_path": _relative_to_workspace(loaded, findings_path)
            if findings_path.is_file()
            else None,
            "enriched_trajectory_path": _relative_to_workspace(loaded, trajectory_path),
            "verification_assessments_path": _relative_to_workspace(loaded, assessments_path),
            "observability_grade": observation.grade.value,
            "event_count": len(observation.primary_events),
            "file_access_count": len(observation.normalized.file_access),
            "tool_call_count": len(
                [event for event in observation.normalized.tool_calls if event.event_type.value == "tool_call"]
            ),
            "artifact_sha256": artifact_sha256,
            "input_tokens": metrics["resource"]["input_tokens"] if metrics.get("resource") else None,
            "output_tokens": metrics["resource"]["output_tokens"] if metrics.get("resource") else None,
            "tool_tokens": None,
        }
    )
    return EnrichmentResult(
        run=updated,
        outcome=outcome,
        assessments=assessments,
        evidence=evidence,
        trajectory=trajectory,
        resource=resource,
        metrics=metrics,
        enriched_count=len(enriched),
        artifact_sha256=artifact_sha256,
        notes=notes,
    )


def _relative_to_workspace(loaded: LoadedConfig, path: Path) -> str:
    try:
        return path.resolve().relative_to(loaded.paths.root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def pair_divergence(clean_sequence: list[str], adv_sequence: list[str]) -> float | None:
    return sequence_distance(clean_sequence, adv_sequence)
