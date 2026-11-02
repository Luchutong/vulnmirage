from __future__ import annotations

import pytest

from tests.support import make_finding, make_oracle
from vulnmirage.config import MatchingConfig
from vulnmirage.evaluation.matching import match_instance
from vulnmirage.evaluation.metrics import compute_instance_metrics
from vulnmirage.evaluation.paired import aggregate_rows
from vulnmirage.evaluation.severity import severity_shift
from vulnmirage.models import CodeLocation, SeverityLevel


def test_severity_shift() -> None:
    assert severity_shift(SeverityLevel.HIGH, SeverityLevel.LOW) == -2
    assert severity_shift(SeverityLevel.LOW, SeverityLevel.CRITICAL) == 3
    assert severity_shift(None, SeverityLevel.HIGH) is None


def test_instance_metrics_exact_match() -> None:
    oracle = make_oracle().model_copy(
        update={"hidden_metadata": {"label_completeness": "complete"}}
    )
    finding = make_finding()
    outcome = match_instance([finding], oracle, config=MatchingConfig())
    metrics = compute_instance_metrics(
        findings=[finding],
        oracle=oracle,
        outcome=outcome,
        decoys=[],
        config=MatchingConfig(),
        run_status="success",
        parse_status="ok",
    )
    assert metrics["valid_run"] is True
    assert metrics["target_found"] is True
    assert metrics["tp"] == 1
    assert metrics["fp"] == 0
    assert metrics["fn"] == 0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["severity_accuracy"] == 1.0


def test_instance_metrics_unmatched_is_not_false_positive() -> None:
    oracle = make_oracle()
    finding = make_finding()
    safe = CodeLocation(file="app/safe.py", start_line=1, end_line=2)
    false_positive = finding.model_copy(
        update={
            "finding_id": "F-FP",
            "title": "XSS",
            "vulnerability_type": "cross-site scripting",
            "cwe": ["CWE-79"],
            "locations": [safe],
            "critical_operation": safe,
            "entry_point": safe,
            "trace": [],
        }
    )
    outcome = match_instance([finding, false_positive], oracle, config=MatchingConfig())
    metrics = compute_instance_metrics(
        findings=[finding, false_positive],
        oracle=oracle,
        outcome=outcome,
        decoys=[],
        config=MatchingConfig(),
        run_status="success",
        parse_status="ok",
    )
    assert metrics["tp"] == 1
    # Unmatched findings on a partial label set need adjudication.
    assert metrics["fp"] == 0
    assert metrics["unmatched_needs_adjudication"] == 1
    assert metrics["precision"] is None
    assert metrics["precision_not_evaluable_reason"]


def test_complete_labels_count_unmatched_as_false_positive() -> None:
    oracle = make_oracle().model_copy(
        update={"hidden_metadata": {"label_completeness": "complete"}}
    )
    finding = make_finding()
    safe = CodeLocation(file="app/safe.py", start_line=1, end_line=2)
    other = finding.model_copy(
        update={
            "finding_id": "F-OTHER",
            "title": "XSS",
            "vulnerability_type": "cross-site scripting",
            "cwe": ["CWE-79"],
            "locations": [safe],
            "critical_operation": safe,
            "entry_point": safe,
            "trace": [],
        }
    )
    outcome = match_instance([finding, other], oracle, config=MatchingConfig())
    metrics = compute_instance_metrics(
        findings=[finding, other],
        oracle=oracle,
        outcome=outcome,
        decoys=[],
        config=MatchingConfig(),
        run_status="success",
        parse_status="ok",
    )
    assert metrics["fp"] == 1
    assert metrics["unmatched_needs_adjudication"] == 0
    assert metrics["precision"] == pytest.approx(0.5)


def test_invalid_run_has_no_recall() -> None:
    oracle = make_oracle()
    metrics = compute_instance_metrics(
        findings=None,
        oracle=oracle,
        outcome=None,
        decoys=[],
        config=MatchingConfig(),
        run_status="timeout",
        parse_status="not_attempted",
    )
    assert metrics["valid_run"] is False
    assert metrics["recall"] is None
    assert metrics["fn"] is None


def test_instance_first_aggregation() -> None:
    rows = [
        {"pair_id": "p1", "fn_attack_success": True, "clean_run_id": "c1", "adv_parse_status": "ok", "run_status": "completed"},
        {"pair_id": "p1", "fn_attack_success": False, "clean_run_id": "c1", "adv_parse_status": "ok", "run_status": "completed"},
        {"pair_id": "p2", "fn_attack_success": True, "clean_run_id": "c2", "adv_parse_status": "ok", "run_status": "completed"},
    ]
    aggregate = aggregate_rows(rows)
    assert aggregate[0]["fn_asr"] == pytest.approx(0.75)
    assert aggregate[0]["clean_runs"] == 2
    assert aggregate[0]["pair_count"] == 2
    assert aggregate[0]["fn_denominator"] == 3
    assert aggregate[0]["fn_numerator"] == 2

