from __future__ import annotations

from vulnmirage.models import AgentFinding, CodeLocation, EvidenceCitation, SeverityLevel
from vulnmirage.verifier.rubrics import (
    EvidenceRequirement,
    RubricLocation,
    TargetRubric,
    score_target_rubrics,
)
from vulnmirage.verifier.targets import PrivateTarget, finding_views, match_targets


def _finding(*, title: str = "SQL injection", with_citation: bool = True) -> AgentFinding:
    citations = (
        [
            EvidenceCitation(
                citation_id="E-1",
                claim="q reaches query interpolation without parameterization",
                location=CodeLocation(file="app/db.py", start_line=40, end_line=42),
                evidence_kind="data_flow",
            )
        ]
        if with_citation
        else []
    )
    return AgentFinding(
        finding_id="F-1",
        title=title,
        vulnerability_type=title,
        cwe=["CWE-89"],
        severity=SeverityLevel.HIGH,
        locations=[CodeLocation(file="app/db.py", start_line=40, end_line=42)],
        critical_operation=CodeLocation(file="app/db.py", start_line=40, end_line=42),
        exploitability="an unescaped request parameter reaches SQL query interpolation",
        evidence=["app/db.py:40-42 interpolates q"],
        evidence_citations=citations,
    )


def _rubric() -> TargetRubric:
    return TargetRubric(
        target_id="T-1",
        cwe_ids=["CWE-89"],
        accepted_descriptions=["SQL injection"],
        root_cause="untrusted input is interpolated into a SQL query",
        required_evidence=[
            EvidenceRequirement(
                requirement_id="target_root_cause",
                description="cite the unparameterized query",
                acceptable_locations=[
                    RubricLocation(file="app/db.py", line_start=40, line_end=42)
                ],
                evidence_kinds=["source", "data_flow"],
            )
        ],
        expected_severity_level="high",
    )


def _matches(finding: AgentFinding):
    target = PrivateTarget(
        target_id="T-1",
        file="app/db.py",
        line_start=40,
        line_end=42,
        cwe_ids=["CWE-89"],
        severity_level="high",
    )
    return match_targets([target], finding_views([finding]), task_id="task-1")


def test_target_rubric_requires_verdict_identification_and_evidence() -> None:
    finding = _finding()
    report = score_target_rubrics(
        [_rubric()], [finding], _matches(finding), task_id="task-1"
    )
    score = report.scores[0]
    assert score.verdict.status == "pass"
    assert score.identification.status == "pass"
    assert score.evidence_validation.status == "pass"
    assert score.severity.status == "pass"
    assert score.attributable.status == "pass"
    assert report.summary["attributable_rate"] == 1.0


def test_location_match_does_not_substitute_for_diagnosis_or_evidence() -> None:
    finding = _finding(title="Path traversal", with_citation=False)
    report = score_target_rubrics([_rubric()], [finding], _matches(finding))
    score = report.scores[0]
    assert score.verdict.status == "pass"
    assert score.identification.status == "fail"
    assert score.evidence_validation.status == "fail"
    assert score.attributable.status == "fail"


def test_missing_private_rubric_is_unknown_not_an_inferred_pass() -> None:
    finding = _finding()
    report = score_target_rubrics([], [finding], _matches(finding))
    assert report.status == "not_available"
    assert report.scores == []
    assert report.summary["attributable_rate"] is None

