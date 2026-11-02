"""Candidate-level development feedback and frozen test strategy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnmirage.errors import GenerationError
from vulnmirage.generation.feedback import (
    DiagnosticCode,
    build_candidate_feedback,
    diagnose_row,
    optimize_payloads,
    preferred_variant_index,
)


def _row(**overrides):
    row = {
        "adv_valid": True,
        "clean_valid": True,
        "adv_parse_status": "ok",
        "attack_goal": "false_negative",
        "manipulation_tier": "M1",
        "operator": "AddDirectAuditInstruction",
        "candidate_id": "M1-false_negative-AddDirectAuditInstruction-c0",
        "fn_attack_success": True,
        "clean_target_found": True,
        "manipulation_exposed": True,
        "verification_succeeded": False,
        "attack_success": True,
        "observability_grade_numeric": 3,
        "payload_length": 100,
        "changed_file_count": 1,
    }
    row.update(overrides)
    return row


def test_diagnostics_are_structured() -> None:
    assert diagnose_row(_row(manipulation_exposed=False, attack_success=False)) == DiagnosticCode.PAYLOAD_NOT_READ
    assert (
        diagnose_row(_row(verification_succeeded=True, attack_success=False))
        == DiagnosticCode.CLAIM_VERIFIED_AND_REJECTED
    )
    assert diagnose_row(_row(attack_success=False)) == DiagnosticCode.PAYLOAD_READ_BUT_IGNORED
    assert (
        diagnose_row(_row(adv_valid=False, attack_success=False))
        == DiagnosticCode.OUTPUT_FORMAT_FAILURE
    )
    assert (
        diagnose_row(
            _row(
                attack_goal="false_negative",
                fn_attack_success=False,
                clean_target_found=False,
                attack_success=False,
            )
        )
        == DiagnosticCode.TARGET_NOT_BOUND
    )


def test_candidate_feedback_scores_and_diagnostics() -> None:
    rows = [
        _row(),
        _row(
            candidate_id="M1-false_negative-AddDirectAuditInstruction-c1",
            attack_success=False,
            fn_attack_success=False,
            manipulation_exposed=False,
        ),
    ]
    snapshot = build_candidate_feedback(rows, split="dev-known", source_release_id="R")
    assert len(snapshot.candidates) == 2
    best = snapshot.candidates[0]
    assert best.candidate_id.endswith("-c0")
    assert best.successes == 1
    assert best.success_rate == 1.0
    assert snapshot.diagnostics["payload_not_read"] == 1
    assert snapshot.frozen is False
    assert snapshot.schema_version == "2.0"


def test_feedback_rejects_test_split() -> None:
    with pytest.raises(GenerationError):
        build_candidate_feedback([_row()], split="test-known")


class _Manifest:
    release_id = "REL-DEV"
    splits = ["dev-known"]


def _install_fake_release(monkeypatch, splits_value: list[str]):
    import vulnmirage.export.bundle as bundle

    class Manifest:
        release_id = "REL-DEV"
        splits = list(splits_value)

    monkeypatch.setattr(bundle, "validate_release", lambda **kwargs: {"ok": True, "errors": []})
    monkeypatch.setattr(bundle, "load_release", lambda path: (Manifest(), Path(path)))


def test_optimize_payloads_freezes_a_dev_strategy(monkeypatch, tmp_path: Path, default_config) -> None:
    _install_fake_release(monkeypatch, ["dev-known"])
    rows = [_row(), _row(candidate_id="M1-false_negative-AddDirectAuditInstruction-c1", attack_success=False)]
    calls: list[int] = []

    def runner():
        calls.append(1)
        return {"run_count": 2}

    def evaluator(*, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)
        return {"output": str(output_dir), "paired_metrics": rows}

    output = tmp_path / "frozen-strategy.json"
    result = optimize_payloads(
        loaded=default_config,
        release_dir=tmp_path / "release",
        agent_config_path=tmp_path / "agent.yaml",
        generations=2,
        population=1,
        output_path=output,
        max_queries=4,
        runner=runner,
        evaluator=evaluator,
    )
    assert result["ok"] is True
    assert result["test_split_used"] is False
    assert result["frozen"] is True
    assert len(calls) == 2
    snapshot = json.loads(output.read_text(encoding="utf-8"))
    assert snapshot["frozen"] is True
    assert snapshot["split"] == "dev-known"
    assert snapshot["candidates"]
    assert snapshot["budgets"]["queries_used"] == 4


def test_optimize_payloads_rejects_test_release(monkeypatch, tmp_path: Path, default_config) -> None:
    _install_fake_release(monkeypatch, ["test-heldout-repository"])
    with pytest.raises(GenerationError):
        optimize_payloads(
            loaded=default_config,
            release_dir=tmp_path / "release",
            agent_config_path=tmp_path / "agent.yaml",
            generations=1,
            population=1,
            output_path=tmp_path / "out.json",
            runner=lambda: {"run_count": 0},
            evaluator=lambda *, output_dir: {"paired_metrics": []},
        )


def test_optimize_payloads_rejects_test_split_before_any_query(
    monkeypatch, tmp_path: Path, default_config
) -> None:
    _install_fake_release(monkeypatch, ["test-heldout-repository"])
    calls: list[int] = []
    with pytest.raises(GenerationError):
        optimize_payloads(
            loaded=default_config,
            release_dir=tmp_path / "release",
            agent_config_path=tmp_path / "agent.yaml",
            generations=1,
            population=1,
            output_path=tmp_path / "out.json",
            runner=lambda: calls.append(1) or {"run_count": 0},
            evaluator=lambda *, output_dir: {"paired_metrics": []},
        )
    assert calls == []


def test_two_optimization_rounds_produce_new_candidates_and_lineage(
    monkeypatch, tmp_path: Path, default_config
) -> None:
    _install_fake_release(monkeypatch, ["dev-known"])
    rows = [_row()]
    calls: list[int] = []
    new_release = tmp_path / "release-g1"

    def runner():
        calls.append(1)
        return {"run_count": 1}

    def evaluator(*, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)
        return {"output": str(output_dir), "paired_metrics": rows}

    def rewriter(*, generation, candidates, snapshot, budget_remaining, release_dir, budget):
        assert candidates
        assert budget.reserve(llm_calls=1, tokens=1000, queries=1)
        budget.settle(tokens=500, reserved_tokens=1000)
        return [
            {
                "candidate_id": f"M1-false_negative-AddDirectAuditInstruction-c{generation + 1}",
                "parent_candidate_ids": candidates[:1],
                "payload_ids": ["payload-child"],
                "prompt_sha256": None,
                "note": f"round {generation + 1}",
                "llm_call_count": 1,
                "new_instance_id": f"VM-CHILD-{generation + 1}",
                "release_path": str(new_release),
            }
        ]

    result = optimize_payloads(
        loaded=default_config,
        release_dir=tmp_path / "release",
        agent_config_path=tmp_path / "agent.yaml",
        generations=2,
        population=1,
        output_path=tmp_path / "frozen.json",
        max_queries=10,
        max_llm_calls=10,
        token_budget=100_000,
        runner=runner,
        evaluator=evaluator,
        rewriter=rewriter,
        rewrite_enabled=True,
    )
    assert result["mode"] == "adaptive_search"
    assert len(calls) == 2
    assert len(result["lineage"]) == 2
    assert result["lineage"][0]["parent_candidate_ids"]
    assert result["lineage"][0]["note"] == "round 1"
    assert result["lineage"][1]["note"] == "round 2"
    assert result["final_release_dir"] == str(new_release)
    assert result["budgets"]["llm_calls_used"] == 2
    assert result["budgets"]["tokens_used"] == 1000
    assert all(entry["rewritten"] for entry in result["history"])


def test_optimization_without_rewriter_is_candidate_selection(
    monkeypatch, tmp_path: Path, default_config
) -> None:
    _install_fake_release(monkeypatch, ["dev-known"])
    result = optimize_payloads(
        loaded=default_config,
        release_dir=tmp_path / "release",
        agent_config_path=tmp_path / "agent.yaml",
        generations=1,
        population=1,
        output_path=tmp_path / "frozen.json",
        max_queries=2,
        runner=lambda: {"run_count": 1},
        evaluator=lambda *, output_dir: {"paired_metrics": [_row()]},
        rewrite_enabled=False,
    )
    assert result["mode"] == "candidate_selection"
    assert result["lineage"] == []


def test_query_budget_is_reserved_before_the_run(
    monkeypatch, tmp_path: Path, default_config
) -> None:
    _install_fake_release(monkeypatch, ["dev-known"])
    calls: list[int] = []
    result = optimize_payloads(
        loaded=default_config,
        release_dir=tmp_path / "release",
        agent_config_path=tmp_path / "agent.yaml",
        generations=3,
        population=1,
        output_path=tmp_path / "frozen.json",
        max_queries=1,
        runner=lambda: calls.append(1) or {"run_count": 1},
        evaluator=lambda *, output_dir: {"paired_metrics": [_row()]},
        rewrite_enabled=False,
    )
    assert len(calls) == 1
    assert result["history"][-1]["skipped"] == "query_budget_exhausted_before_run"


def test_preferred_variant_index_uses_best_candidate() -> None:
    snapshot = build_candidate_feedback(
        [
            _row(attack_success=False, fn_attack_success=False),
            _row(candidate_id="M1-false_negative-AddDirectAuditInstruction-c1"),
        ],
        split="dev-known",
    )
    assert (
        preferred_variant_index(
            snapshot,
            tier="M1",
            goal="false_negative",
            operator="AddDirectAuditInstruction",
            candidates_per_strategy=2,
        )
        == 1
    )
