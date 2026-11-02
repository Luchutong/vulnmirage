"""VariantGroup pairing: each attack candidate uses its own control run."""

from __future__ import annotations

from vulnmirage.config import MatchingConfig
from vulnmirage.evaluation.matching import match_instance
from vulnmirage.evaluation.paired import EvaluatedRun, pair_rows
from vulnmirage.harness.trace import TraceSummary
from vulnmirage.models import (
    AgentRun,
    VariantGroup,
    VariantKind,
)
from tests.support import make_instance, make_manipulation, make_oracle
from vulnmirage.models import ManipulationSpec


def _run(instance, *, purpose: str = "evaluation") -> AgentRun:
    return AgentRun(
        run_id=f"RUN-{instance.instance_id}",
        instance_id=instance.instance_id,
        repetition=1,
        model_provider="provider",
        model_name="model",
        scaffold="dummy",
        prompt_sha256="a" * 64,
        time_budget_seconds=30,
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:00:10Z",
        status="success",
        raw_events_path="events.raw.jsonl",
        normalized_events_path="events.normalized.jsonl",
        tool_calls_path="tool_calls.jsonl",
        file_access_path="file_access.jsonl",
        process_events_path="process_events.jsonl",
        observability_grade="D",
        stdout_path="stdout.log",
        stderr_path="stderr.log",
        final_raw_path="final_raw.txt",
        purpose=purpose,
    )


def _evaluated(instance, *, purpose: str = "evaluation", target_found: bool = False):
    oracle = make_oracle()
    manipulation = (
        make_manipulation()
        if instance.variant_kind.value == "adversarial"
        else None
    )
    outcome = match_instance([], oracle, config=MatchingConfig())
    return EvaluatedRun(
        run=_run(instance, purpose=purpose),
        meta=None,
        instance=instance,
        oracle=oracle,
        manipulation=manipulation,
        decoys=[],
        contract=None,
        findings=[],
        parse_status="ok",
        parse_error=None,
        outcome=outcome,
        metrics={
            "valid_run": True,
            "target_found": target_found,
            "fp": 0,
            "confirmed_false_positives": 0,
            "unmatched_needs_adjudication": 0,
            "label_completeness": "partial",
        },
        trace=TraceSummary(trace_path="trace.jsonl"),
        observability_grade="D",
    )


def _adversarial(instance_id: str, group_id: str):
    return make_instance(
        instance_id=instance_id, kind=VariantKind.ADVERSARIAL
    ).model_copy(update={"group_id": group_id, "candidate_id": f"cand-{instance_id}"})


def _benign(instance_id: str, group_id: str, kind: str = "benign"):
    from vulnmirage.models import BenchmarkInstance, RepositoryRef

    return BenchmarkInstance(
        instance_id=instance_id,
        pair_id="PAIR-1",
        schema_version="1.0",
        variant_kind=VariantKind.BENIGN_CONTROL,
        oracle_ref="VMO-TEST00000001",
        repository=RepositoryRef(
            repo_url="file:///tmp/fixture", vulnerable_commit="a" * 40
        ),
        audit_difficulty="D2",
        manipulation_tier="M2",
        manipulation_ref=None,
        task_file=f"instances/{instance_id}/task.md",
        patch_file=f"instances/{instance_id}/patch.diff",
        repository_tree_sha256="b" * 64,
        generation_config_sha256="c" * 64,
        random_seed=42,
        release_split="dev-known",
        group_id=group_id,
        control_kind=kind,
    )


def test_two_attack_variants_pair_with_their_own_controls() -> None:
    clean = make_instance(instance_id="VM-CLEAN")
    a1 = _adversarial("VM-A1", "GROUP-1")
    a2 = _adversarial("VM-A2", "GROUP-2")
    b1 = _benign("VM-A1-B", "GROUP-1")
    b2 = _benign("VM-A2-B", "GROUP-2")
    t1 = _benign("VM-A1-T", "GROUP-1", kind="truthful_security")
    runs = [_evaluated(clean), _evaluated(a1), _evaluated(a2), _evaluated(b1), _evaluated(b2), _evaluated(t1)]
    groups = {
        "VM-A1": VariantGroup(
            group_id="GROUP-1",
            oracle_id="VMO-TEST00000001",
            pair_id=clean.pair_id,
            clean_instance_id=clean.instance_id,
            adversarial_instance_id="VM-A1",
            benign_instance_id="VM-A1-B",
            truthful_security_instance_id="VM-A1-T",
        ),
        "VM-A2": VariantGroup(
            group_id="GROUP-2",
            oracle_id="VMO-TEST00000001",
            pair_id=clean.pair_id,
            clean_instance_id=clean.instance_id,
            adversarial_instance_id="VM-A2",
            benign_instance_id="VM-A2-B",
        ),
    }
    rows = pair_rows(runs, tolerance=5, groups=groups)
    assert len(rows) == 2
    by_id = {row["adversarial_instance_id"]: row for row in rows}
    assert by_id["VM-A1"]["benign_instance_id"] == "VM-A1-B"
    assert by_id["VM-A2"]["benign_instance_id"] == "VM-A2-B"
    assert by_id["VM-A1"]["truthful_security_instance_id"] == "VM-A1-T"
    assert by_id["VM-A2"]["truthful_security_instance_id"] is None
    assert by_id["VM-A1"]["clean_instance_id"] == clean.instance_id
    assert by_id["VM-A1"]["pairing_source"] == "variant_group"
    assert by_id["VM-A1"]["pairing_complete"] is True


def test_group_id_fallback_still_selects_the_matching_control() -> None:
    clean = make_instance(instance_id="VM-CLEAN")
    a1 = _adversarial("VM-A1", "GROUP-1")
    b1 = _benign("VM-A1-B", "GROUP-1")
    b2 = _benign("VM-A2-B", "GROUP-2")
    rows = pair_rows(
        [_evaluated(clean), _evaluated(a1), _evaluated(b1), _evaluated(b2)],
        tolerance=5,
    )
    assert len(rows) == 1
    assert rows[0]["benign_instance_id"] == "VM-A1-B"
    assert rows[0]["clean_instance_id"] == clean.instance_id


def test_reference_run_is_excluded_from_formal_pairing() -> None:
    clean = make_instance(instance_id="VM-CLEAN")
    a1 = _adversarial("VM-A1", "GROUP-1")
    reference = make_instance(instance_id="VM-REF").model_copy(
        update={"variant_kind": VariantKind.CLEAN}
    )
    rows = pair_rows(
        [_evaluated(clean), _evaluated(a1), _evaluated(reference, purpose="reference")],
        tolerance=5,
    )
    assert len(rows) == 1
    assert rows[0]["adversarial_instance_id"] == "VM-A1"
    assert all(row["run_purpose"] != "reference" for row in rows)
