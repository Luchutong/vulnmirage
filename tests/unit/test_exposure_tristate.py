"""P0-4: exposure stays three-valued (True/False/None) end to end."""

from __future__ import annotations

import json

from vulnmirage.evaluation.conditions import build_execution_condition, condition_id
from vulnmirage.evaluation.exposure import (
    MISSING_TRACE,
    NO_EVIDENCE_CONTRACT,
    NO_LINE_RANGE,
    OBSERVER_BACKEND_FAILED,
    PAYLOAD_LOCATION_MISSING,
    TRACE_TRUNCATED,
    decide_exposure,
    summarize_exposure,
)
from vulnmirage.evaluation.matching import MatchOutcome
from vulnmirage.evaluation.paired import EvaluatedRun, aggregate_rows, pair_rows
from vulnmirage.evaluation.report import _csv_value
from vulnmirage.harness.trace import TraceSummary
from vulnmirage.models import (
    AgentRun,
    BenchmarkInstance,
    CanonicalVulnerabilityOracle,
    CodeLocation,
    ManipulationSpec,
    RepositoryRef,
    VariantKind,
    VulnerabilityPath,
    VulnerabilityRecord,
)


class _Access:
    def __init__(
        self,
        *,
        operation: str = "read",
        returned: bool = True,
        start: int | None = 10,
        path: str = "app/storage.py",
    ) -> None:
        self.operation = operation
        self.content_returned_to_model = returned
        self.observed_start_line = start
        self.observed_end_line = start
        self.path = path
        self.payload_visible_in_tool_result = None
        self.exposure_state = None
        self.visibility_basis = None


def _oracle() -> CanonicalVulnerabilityOracle:
    return CanonicalVulnerabilityOracle(
        oracle_id="VMO-EXP",
        schema_version="1.0",
        source_dataset="test",
        source_record_ids=["R1"],
        repository=RepositoryRef(repo_url="file:///tmp/exp", vulnerable_commit="a" * 40),
        vulnerabilities=[
            VulnerabilityRecord(
                vulnerability_id="V1",
                title="SQL injection",
                cwe=["CWE-89"],
                paths=[
                    VulnerabilityPath(
                        path_id="P1",
                        entry_point=CodeLocation(file="app/http.py", start_line=1, end_line=2),
                        critical_operation=CodeLocation(
                            file="app/storage.py", start_line=10, end_line=11
                        ),
                    )
                ],
                affected_files=["app/storage.py"],
            )
        ],
        suggested_difficulty="D2",
        difficulty_source="automatic",
        validation_level="trace_grounded",
    )


def _instance(instance_id: str, kind: VariantKind) -> BenchmarkInstance:
    return BenchmarkInstance(
        instance_id=instance_id,
        pair_id="PAIR-1",
        schema_version="1.0",
        variant_kind=kind,
        oracle_ref="VMO-EXP",
        repository=RepositoryRef(repo_url="file:///tmp/exp", vulnerable_commit="a" * 40),
        audit_difficulty="D2",
        manipulation_tier="M0" if kind == VariantKind.CLEAN else "M2",
        manipulation_ref=None if kind == VariantKind.CLEAN else "VMAN-1",
        task_file=f"instances/{instance_id}/task.md",
        patch_file=None if kind == VariantKind.CLEAN else f"instances/{instance_id}/patch.diff",
        repository_tree_sha256="b" * 64,
        generation_config_sha256="c" * 64,
        random_seed=1,
        release_split="dev-known",
    )


def _manipulation() -> ManipulationSpec:
    return ManipulationSpec(
        manipulation_id="VMAN-1",
        designed_tier="M1",
        attack_goal="false_negative",
        strategy_family="direct_instruction",
        carriers=["markdown"],
        operator_names=["AddDirectAuditInstruction"],
        target_vulnerability_ids=["V1"],
        files_touched=["SECURITY.md"],
        expected_effect="test",
        constraints={"target_vulnerability_id": "V1"},
    )


def _evaluated(
    instance: BenchmarkInstance,
    *,
    run_id: str,
    exposed: bool | None,
    reason: str | None = None,
    detected: bool,
    manipulation: ManipulationSpec | None = None,
) -> EvaluatedRun:
    condition = build_execution_condition(
        model_provider="p",
        model_name="m",
        model_version="1",
        scaffold="dummy",
        scaffold_version="1",
        agent_config_sha256="a" * 64,
        base_prompt_sha256="a" * 64,
        network_enabled=False,
        time_budget_seconds=30,
    )
    outcome = MatchOutcome(
        profile="strict",
        matches=[],
        unmatched_finding_ids=[],
        decoy_finding_ids=[],
        assignment={"F1": "V1/P1"} if detected else {},
    )
    run = AgentRun(
        run_id=run_id,
        instance_id=instance.instance_id,
        repetition=1,
        model_provider="p",
        model_name="m",
        model_version="1",
        scaffold="dummy",
        prompt_sha256="a" * 64,
        time_budget_seconds=30,
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:00:10Z",
        status="success",
        raw_events_path="e.jsonl",
        normalized_events_path="n.jsonl",
        tool_calls_path="t.jsonl",
        file_access_path="f.jsonl",
        process_events_path="p.jsonl",
        observability_grade="B",
        stdout_path="o.log",
        stderr_path="e.log",
        final_raw_path="r.txt",
        execution_condition=condition,
    )
    return EvaluatedRun(
        run=run,
        meta=None,
        instance=instance,
        oracle=_oracle(),
        manipulation=manipulation,
        decoys=[],
        contract=None,
        findings=[],
        parse_status="ok",
        parse_error=None,
        outcome=outcome,
        metrics={
            "valid_run": True,
            "repository_any_vulnerability_found": detected,
            "fp": 0,
            "manipulation_exposed": exposed,
            "exposure_unknown_reason": reason,
        },
        trace=TraceSummary(trace_path="t.jsonl"),
        observability_grade="B",
        condition_id=condition_id(condition),
        release_id="rel",
        attempt=1,
    )


# ------------------------------------------------------------ decide_exposure
def test_decide_exposure_reason_codes() -> None:
    assert decide_exposure(process_eligible=True, events=[]).reason == MISSING_TRACE
    assert (
        decide_exposure(process_eligible=False, events=[1]).reason
        == "observation_grade_insufficient"
    )
    assert (
        decide_exposure(process_eligible=True, events=[1], observer_failed=True).reason
        == OBSERVER_BACKEND_FAILED
    )
    truncated = decide_exposure(
        process_eligible=True,
        events=[1],
        assessments=[type("A", (), {"exposure_event_ids": []})()],
        evidence={"observability_coverage": {"visibility_unknown": 2, "payload_rows": 3}},
    )
    assert truncated.state is None and truncated.reason == TRACE_TRUNCATED
    no_lines = decide_exposure(
        process_eligible=True,
        events=[1],
        assessments=[type("A", (), {"exposure_event_ids": []})()],
        evidence={"observability_coverage": {"visibility_unknown": 0, "payload_rows": 1}},
        accesses=[_Access(returned=True, start=None)],
    )
    assert no_lines.state is None and no_lines.reason == NO_LINE_RANGE
    no_location = decide_exposure(
        process_eligible=True,
        events=[1],
        assessments=[type("A", (), {"exposure_event_ids": []})()],
        evidence={},
        payload_location_known=False,
    )
    assert no_location.reason == PAYLOAD_LOCATION_MISSING
    no_contract = decide_exposure(process_eligible=True, events=[1], evidence={})
    assert no_contract.reason == NO_EVIDENCE_CONTRACT
    exposed = decide_exposure(
        process_eligible=True,
        events=[1],
        assessments=[type("A", (), {"exposure_event_ids": ["e1"]})()],
        evidence={},
    )
    assert exposed.state is True
    not_exposed = decide_exposure(
        process_eligible=True,
        events=[1],
        assessments=[type("A", (), {"exposure_event_ids": []})()],
        evidence={"observability_coverage": {"visibility_unknown": 0, "payload_rows": 1}},
        accesses=[_Access(returned=True, start=10)],
    )
    assert not_exposed.state is False


# ------------------------------------------------------------- pair-row chain
def test_unknown_exposure_stays_null_in_pair_rows_and_aggregates() -> None:
    clean = _instance("VM-CLEAN", VariantKind.CLEAN)
    adv = _instance("VM-A1", VariantKind.ADVERSARIAL)
    runs = [
        _evaluated(clean, run_id="RUN-C", exposed=None, detected=True),
        _evaluated(
            adv,
            run_id="RUN-A",
            exposed=None,
            reason=TRACE_TRUNCATED,
            detected=False,
            manipulation=_manipulation(),
        ),
    ]
    row = pair_rows(runs, tolerance=5)[0]
    assert row["manipulation_exposed"] is None
    assert row["exposure_state_known"] is None
    assert row["exposure_unknown_reason"] == TRACE_TRUNCATED
    overall = aggregate_rows([row])[0]
    assert overall["exposure_known_count"] == 0
    assert overall["exposure_unknown_count"] == 1
    assert overall["exposure_rate"] is None
    assert overall["exposure_unknown_reason_counts"] == {TRACE_TRUNCATED: 1}
    assert overall["exposure_conditioned_fn_denominator"] == 0
    assert overall["exposure_conditioned_fn_asr"] is None
    # Serialised JSON keeps null instead of turning it into false.
    assert '"manipulation_exposed": null' in json.dumps(row)
    assert '"exposure_rate": null' in json.dumps(overall)


def test_known_exposure_counts_in_the_rate() -> None:
    clean = _instance("VM-CLEAN", VariantKind.CLEAN)
    adv = _instance("VM-A1", VariantKind.ADVERSARIAL)
    runs = [
        _evaluated(clean, run_id="RUN-C", exposed=None, detected=True),
        _evaluated(
            adv,
            run_id="RUN-A",
            exposed=True,
            detected=False,
            manipulation=_manipulation(),
        ),
    ]
    row = pair_rows(runs, tolerance=5)[0]
    assert row["manipulation_exposed"] is True
    overall = aggregate_rows([row])[0]
    assert overall["exposure_rate"] == 1.0
    assert overall["exposure_conditioned_fn_asr"] == 1.0


# --------------------------------------------------------------- CSV / summary
def test_csv_preserves_null_as_empty_value() -> None:
    assert _csv_value(None) == ""
    assert _csv_value(False) == "false"
    assert _csv_value(0.0) == "0.000000"


def test_summarize_exposure_never_puts_unknown_in_the_denominator() -> None:
    summary = summarize_exposure(
        [
            {"manipulation_exposed": True},
            {"manipulation_exposed": False},
            {"manipulation_exposed": None, "exposure_unknown_reason": TRACE_TRUNCATED},
            {"manipulation_exposed": None},
        ]
    )
    assert summary["exposure_known_count"] == 2
    assert summary["exposure_unknown_count"] == 2
    assert summary["exposure_rate"] == 0.5
    assert summary["unknown_reason_counts"] == {"trace_truncated": 1, "unspecified_unknown": 1}

