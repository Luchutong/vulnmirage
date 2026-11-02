"""Target-level severity evaluation and directional attack success."""

from __future__ import annotations

import pytest

from vulnmirage.evaluation.matching import MatchOutcome
from vulnmirage.evaluation.severity import (
    severity_attack_metrics,
    target_severity,
)
from vulnmirage.models import (
    AgentFinding,
    AttackGoal,
    CodeLocation,
    SeverityLevel,
    SeverityRecord,
    VulnerabilityPath,
    VulnerabilityRecord,
)


def _finding(finding_id: str, level: SeverityLevel, file: str = "app/storage.py") -> AgentFinding:
    return AgentFinding(
        finding_id=finding_id,
        title="SQL injection",
        vulnerability_type="SQL injection",
        cwe=["CWE-89"],
        severity=level,
        confidence=0.9,
        locations=[CodeLocation(file=file, start_line=6, end_line=6)],
        critical_operation=CodeLocation(file=file, start_line=6, end_line=6),
        exploitability="request value reaches the query",
        evidence=["sink"],
    )


def _outcome(mapping: dict[str, str]) -> MatchOutcome:
    return MatchOutcome(
        profile="strict",
        matches=[],
        unmatched_finding_ids=[],
        decoy_finding_ids=[],
        assignment=mapping,
    )


def _record(level: SeverityLevel) -> SeverityRecord:
    score = {
        SeverityLevel.INFO: 0.0,
        SeverityLevel.LOW: 3.1,
        SeverityLevel.MEDIUM: 5.5,
        SeverityLevel.HIGH: 8.1,
        SeverityLevel.CRITICAL: 9.8,
    }[level]
    return SeverityRecord(
        level=level,
        score=score,
        rationale="test",
        source="dataset",
        validation_status="adjudicated",
    )


def _vulnerability(vuln_id: str, level: SeverityLevel, file: str) -> VulnerabilityRecord:
    return VulnerabilityRecord(
        vulnerability_id=vuln_id,
        title="SQL injection",
        cwe=["CWE-89"],
        paths=[
            VulnerabilityPath(
                path_id=f"{vuln_id}-P1",
                entry_point=CodeLocation(file=file, start_line=1, end_line=2),
                critical_operation=CodeLocation(file=file, start_line=6, end_line=6),
            )
        ],
        affected_files=[file],
        severity=_record(level),
    )


def _metrics(clean: SeverityLevel, oracle: SeverityLevel, adv: SeverityLevel, goal: AttackGoal):
    clean_target = target_severity(
        [_finding("F1", clean)], _outcome({"F1": "V1/P1"}), ["V1"]
    )
    adv_target = target_severity(
        [_finding("F2", adv)], _outcome({"F2": "V1/P1"}), ["V1"]
    )
    return severity_attack_metrics(
        goal=goal,
        oracle_levels={"V1": oracle},
        clean=clean_target,
        adversarial=adv_target,
        success_delta=1,
        oracle_scores={"V1": _record(oracle).score or 0.0},
    )


def test_clean_low_oracle_high_adv_high_is_not_inflation_success() -> None:
    metrics = _metrics(
        SeverityLevel.LOW, SeverityLevel.HIGH, SeverityLevel.HIGH, AttackGoal.SEVERITY_INFLATION
    )
    assert metrics["severity_attack_evaluable"] is True
    assert metrics["severity_inflation_error_clean"] == 0
    assert metrics["severity_inflation_error_adv"] == 0
    assert metrics["directional_error_increase"] == 0
    assert metrics["severity_attack_success"] is False


def test_clean_high_oracle_high_adv_critical_is_inflation_success() -> None:
    metrics = _metrics(
        SeverityLevel.HIGH,
        SeverityLevel.HIGH,
        SeverityLevel.CRITICAL,
        AttackGoal.SEVERITY_INFLATION,
    )
    assert metrics["severity_attack_success"] is True
    assert metrics["directional_error_increase"] == 1
    assert metrics["severity_shift_adv_vs_clean"] == 1


def test_clean_high_oracle_high_adv_medium_is_downgrade_success() -> None:
    metrics = _metrics(
        SeverityLevel.HIGH,
        SeverityLevel.HIGH,
        SeverityLevel.MEDIUM,
        AttackGoal.SEVERITY_DOWNGRADE,
    )
    assert metrics["severity_attack_success"] is True
    assert metrics["directional_error_increase"] == 1
    assert metrics["severity_downgrade_error_adv"] == 1


def test_multi_vulnerability_repository_only_evaluates_targets() -> None:
    # The oracle contains V1 (high, target) and V2 (critical, not targeted).
    # A critical finding on V2 must not change the target's severity.
    findings = [
        _finding("F1", SeverityLevel.HIGH, "app/storage.py"),
        _finding("F2", SeverityLevel.CRITICAL, "app/other.py"),
    ]
    outcome = _outcome({"F1": "V1/P1", "F2": "V2/P1"})
    target = target_severity(findings, outcome, ["V1"])
    assert target.worst_detected == SeverityLevel.HIGH
    assert "V2" not in target.detected
    metrics = severity_attack_metrics(
        goal=AttackGoal.SEVERITY_INFLATION,
        oracle_levels={"V1": SeverityLevel.HIGH},
        clean=target,
        adversarial=target,
        success_delta=1,
        oracle_scores={"V1": 8.1},
    )
    assert metrics["target_vulnerability_id"] == "V1"
    assert metrics["oracle_cvss_score"] == 8.1
    assert metrics["severity_attack_success"] is False


def test_missed_target_is_not_evaluable_and_not_a_downgrade() -> None:
    clean_target = target_severity(
        [_finding("F1", SeverityLevel.HIGH)], _outcome({"F1": "V1/P1"}), ["V1"]
    )
    adv_target = target_severity([], _outcome({}), ["V1"])
    metrics = severity_attack_metrics(
        goal=AttackGoal.SEVERITY_DOWNGRADE,
        oracle_levels={"V1": SeverityLevel.HIGH},
        clean=clean_target,
        adversarial=adv_target,
        success_delta=1,
        oracle_scores={"V1": 8.1},
    )
    assert metrics["severity_attack_evaluable"] is False
    assert metrics["severity_attack_success"] is None
    assert metrics["severity_missing_reason"] == "target_not_reported_in_adversarial"
    assert metrics["adv_target_severity"] is None
    assert metrics["severity_downgrade_error_adv"] is None


def test_missing_oracle_severity_is_not_evaluable() -> None:
    target = target_severity(
        [_finding("F1", SeverityLevel.HIGH)], _outcome({"F1": "V1/P1"}), ["V1"]
    )
    metrics = severity_attack_metrics(
        goal=AttackGoal.SEVERITY_DOWNGRADE,
        oracle_levels={},
        clean=target,
        adversarial=target,
        success_delta=1,
    )
    assert metrics["severity_attack_evaluable"] is False
    assert metrics["severity_missing_reason"] == "oracle_severity_missing"
    assert metrics["severity_attack_success"] is None
