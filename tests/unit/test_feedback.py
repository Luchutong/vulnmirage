from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnmirage.errors import GenerationError
from vulnmirage.generation.feedback import (
    FeedbackSnapshot,
    build_feedback_snapshot,
    load_feedback,
    row_success,
    select_operator,
)
from vulnmirage.generation.payload_registry import load_payload_registry
from vulnmirage.models import AttackGoal, ManipulationTier


def test_row_success_metrics() -> None:
    assert row_success({"adv_valid": True, "clean_valid": True, "fn_attack_success": True}, "false_negative") == 1.0
    assert row_success({"adv_valid": True, "clean_valid": True, "fn_attack_success": False}, "false_negative") == 0.0
    assert row_success({"adv_valid": False, "clean_valid": True, "fn_attack_success": True}, "false_negative") is None
    assert row_success({"adv_valid": True, "clean_valid": True, "severity_shift": -2}, "severity_downgrade") == 1.0
    assert row_success({"adv_valid": True, "clean_valid": True, "severity_shift": 2}, "severity_inflation") == 1.0


def test_build_and_select_feedback() -> None:
    rows = [
        {
            "manipulation_tier": "M1",
            "attack_goal": "false_negative",
            "operator": "AddDirectAuditInstruction",
            "adv_valid": True,
            "clean_valid": True,
            "fn_attack_success": True,
        },
        {
            "manipulation_tier": "M1",
            "attack_goal": "false_negative",
            "operator": "InsertNonExecutableString",
            "adv_valid": True,
            "clean_valid": True,
            "fn_attack_success": False,
        },
    ]
    snapshot = build_feedback_snapshot(rows, split="dev-known", source_release_id="R")
    assert snapshot.by_operator["M1|false_negative|AddDirectAuditInstruction"] == 1.0
    selected = select_operator(
        ManipulationTier.M1_DIRECT,
        AttackGoal.FALSE_NEGATIVE,
        ["InsertNonExecutableString", "AddDirectAuditInstruction"],
        snapshot,
    )
    assert selected == "AddDirectAuditInstruction"
    assert (
        select_operator(
            ManipulationTier.M1_DIRECT,
            AttackGoal.FALSE_NEGATIVE,
            ["InsertNonExecutableString", "AddDirectAuditInstruction"],
            None,
        )
        == "InsertNonExecutableString"
    )


def test_feedback_snapshot_must_be_dev(tmp_path: Path) -> None:
    snapshot = FeedbackSnapshot(split="test-known", created_at="2026-01-01T00:00:00Z")
    path = tmp_path / "feedback.json"
    path.write_text(snapshot.model_dump_json(), encoding="utf-8")
    with pytest.raises(GenerationError):
        load_feedback(path)
    with pytest.raises(GenerationError):
        build_feedback_snapshot([], split="test-known")


def test_payload_registry_split_filtering(project_root: Path) -> None:
    registry, _ = load_payload_registry(project_root / "payloads" / "registry.yaml")
    dev = registry.filter_for_split("dev-known")
    assert all(item.strategy_split == "public_known" for item in dev.payloads)
    heldout = registry.model_copy(
        update={
            "payloads": [
                registry.payloads[0].model_copy(update={"strategy_split": "heldout_strategy"}),
                *registry.payloads[1:],
            ]
        }
    )
    dev_visible = heldout.filter_for_split("dev-known")
    assert registry.payloads[0].payload_id not in {item.payload_id for item in dev_visible.payloads}
    test_visible = heldout.filter_for_split("test-heldout-strategy")
    assert registry.payloads[0].payload_id in {item.payload_id for item in test_visible.payloads}
