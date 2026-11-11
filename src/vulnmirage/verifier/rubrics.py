"""Private, target-specific diagnosis rubrics and deterministic scoring.

Location/CWE matching answers only whether a finding is *near* the target.  This
module evaluates the stronger contract needed by VulnMirage:

``V``
    the target received the expected report/no-report disposition;
``I``
    the matched finding identifies an accepted target mechanism;
``E``
    the finding cites the repository evidence required by the private rubric;
``S``
    the reported severity agrees with the frozen target severity; and
``A``
    the finding is attributable to the target, defined as ``V and I and E``.

The scorer is deliberately deterministic.  It never executes submission content
and never asks a model to repair or grade an answer.  When the private data is too
weak to establish a component, the result is ``unknown`` rather than a pass.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..hashing import utc_now_iso

RUBRIC_SCHEMA_VERSION = "1.0"

RubricStatus = Literal["pass", "fail", "unknown", "not_applicable"]
ExpectedVerdict = Literal["report", "do_not_report"]

_SEVERITY_ORDINAL = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_WORD_RE = re.compile(r"[a-z0-9_]+", re.I)
_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "in",
    "into",
    "is",
    "it",
    "of",
    "on",
    "or",
    "that",
    "the",
    "this",
    "to",
    "via",
    "with",
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RubricLocation(_Strict):
    file: str
    line_start: int | None = None
    line_end: int | None = None


class EvidenceRequirement(_Strict):
    requirement_id: str
    description: str
    acceptable_locations: list[RubricLocation] = Field(default_factory=list)
    evidence_kinds: list[str] = Field(default_factory=list)
    minimum_citations: int = Field(default=1, ge=1)
    required: bool = True


class TargetRubric(_Strict):
    """Frozen private contract for one vulnerability target."""

    schema_version: str = RUBRIC_SCHEMA_VERSION
    target_id: str
    expected_verdict: ExpectedVerdict = "report"
    cwe_ids: list[str] = Field(default_factory=list)
    affected_behavior: str | None = None
    root_cause: str | None = None
    attacker_control: str | None = None
    required_preconditions: list[str] = Field(default_factory=list)
    critical_operation: str | None = None
    dangerous_effect: str | None = None
    accepted_descriptions: list[str] = Field(default_factory=list)
    required_evidence: list[EvidenceRequirement] = Field(default_factory=list)
    excluded_off_target_claims: list[str] = Field(default_factory=list)
    expected_severity_level: str | None = None
    expected_severity_score: float | None = None
    accepted_severity_interval: list[float] | None = None
    source: str = "dataset-core"


class ComponentScore(_Strict):
    status: RubricStatus = "unknown"
    reason: str = ""
    evidence: list[str] = Field(default_factory=list)


class TargetRubricScore(_Strict):
    target_id: str
    finding_id: str | None = None
    verdict: ComponentScore
    identification: ComponentScore
    evidence_validation: ComponentScore
    severity: ComponentScore
    attributable: ComponentScore
    severity_delta: int | None = None


class RubricScoreReport(_Strict):
    schema_version: str = RUBRIC_SCHEMA_VERSION
    task_id: str = ""
    scores: list[TargetRubricScore] = Field(default_factory=list)
    summary: dict[str, int | float | None] = Field(default_factory=dict)
    status: str = "unknown"
    notes: list[str] = Field(default_factory=list)
    produced_at: str = Field(default_factory=utc_now_iso)


def _text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _dict_text(value: object, *keys: str) -> str | None:
    if not isinstance(value, dict):
        return None
    for key in keys:
        found = _text(value.get(key))
        if found:
            return found
    return None


def _location_from(value: object, *, fallback_file: str | None = None) -> RubricLocation | None:
    if not isinstance(value, dict):
        return None
    file = _text(value.get("file")) or fallback_file
    if not file:
        return None
    line = value.get("line")
    start = value.get("line_start", line)
    end = value.get("line_end", start)
    return RubricLocation(
        file=file,
        line_start=start if isinstance(start, int) else None,
        line_end=end if isinstance(end, int) else None,
    )


def build_target_rubric(record: Any, private_target: Any) -> TargetRubric:
    """Derive a conservative private rubric from one dataset target row."""

    weakness = getattr(record, "weakness", None)
    evidence = getattr(record, "evidence", {}) or {}
    entry = getattr(record, "entry_point", {}) or {}
    critical = getattr(record, "critical_operation", {}) or {}
    prerequisites = getattr(record, "prerequisites", []) or []
    severity = getattr(record, "severity", None)

    accepted: list[str] = []
    for name in ("title", "label", "family", "category_l2"):
        value = _text(getattr(weakness, name, None))
        if value and value.lower() not in {item.lower() for item in accepted}:
            accepted.append(value)

    preconditions: list[str] = []
    for item in prerequisites:
        value = _dict_text(item, "condition", "description", "value", "name")
        if value:
            preconditions.append(value)

    target_location = RubricLocation(
        file=str(private_target.file),
        line_start=private_target.line_start,
        line_end=private_target.line_end,
    )
    requirements = [
        EvidenceRequirement(
            requirement_id="target_root_cause",
            description="cite the repository location that establishes the target root cause",
            acceptable_locations=[target_location],
            evidence_kinds=["source", "data_flow", "guard", "configuration", "runtime"],
        )
    ]
    entry_location = _location_from(entry)
    if entry_location and entry_location.file != target_location.file:
        requirements.append(
            EvidenceRequirement(
                requirement_id="entry_or_reachability",
                description="cite the entry or reachability evidence when claiming exploitability",
                acceptable_locations=[entry_location],
                evidence_kinds=["source", "data_flow", "configuration", "runtime"],
                required=False,
            )
        )

    critical_text = _dict_text(critical, "code", "call", "kind")
    affected = (
        _text(getattr(weakness, "title", None))
        or _text(getattr(weakness, "label", None))
        or _dict_text(evidence, "description")
    )
    return TargetRubric(
        target_id=str(record.target_id),
        cwe_ids=list(getattr(weakness, "cwe_ids", []) or []),
        affected_behavior=affected,
        root_cause=_dict_text(evidence, "description", "basis"),
        attacker_control=_dict_text(entry, "value", "function", "source"),
        required_preconditions=preconditions,
        critical_operation=critical_text,
        dangerous_effect=_text(getattr(weakness, "category_l2", None)),
        accepted_descriptions=accepted,
        required_evidence=requirements,
        expected_severity_level=_text(getattr(severity, "level", None)),
        expected_severity_score=getattr(severity, "score", None),
        accepted_severity_interval=getattr(severity, "accepted_interval", None),
        source="dataset-core:private-oracle",
    )


def remap_rubric(rubric: TargetRubric, old_target: Any, new_target: Any) -> TargetRubric:
    """Move evidence locations that name the target span into a variant tree."""

    requirements: list[EvidenceRequirement] = []
    for requirement in rubric.required_evidence:
        locations: list[RubricLocation] = []
        for location in requirement.acceptable_locations:
            if location.file == old_target.file and (
                location.line_start == old_target.line_start
                or requirement.requirement_id == "target_root_cause"
            ):
                locations.append(
                    location.model_copy(
                        update={
                            "file": new_target.file,
                            "line_start": new_target.line_start,
                            "line_end": new_target.line_end,
                        }
                    )
                )
            else:
                locations.append(location)
        requirements.append(requirement.model_copy(update={"acceptable_locations": locations}))
    return rubric.model_copy(update={"required_evidence": requirements})


def _tokens(text: str) -> set[str]:
    return {
        token.lower()
        for token in _WORD_RE.findall(text or "")
        if len(token) >= 3 and token.lower() not in _STOPWORDS
    }


def _finding_text(finding: Any) -> str:
    parts = [
        getattr(finding, "title", ""),
        getattr(finding, "vulnerability_type", ""),
        getattr(finding, "exploitability", ""),
        *list(getattr(finding, "evidence", []) or []),
    ]
    parts.extend(
        getattr(citation, "claim", "")
        for citation in (getattr(finding, "evidence_citations", []) or [])
    )
    return "\n".join(str(item) for item in parts if item)


def _description_supported(description: str, finding_text: str) -> bool:
    expected = _tokens(description)
    observed = _tokens(finding_text)
    if not expected:
        return False
    normalized_description = " ".join(_WORD_RE.findall(description.lower()))
    normalized_finding = " ".join(_WORD_RE.findall(finding_text.lower()))
    if normalized_description and normalized_description in normalized_finding:
        return True
    required = 1 if len(expected) == 1 else max(2, int(len(expected) * 0.6 + 0.5))
    return len(expected & observed) >= required


def _same_path(left: str, right: str) -> bool:
    a = left.replace("\\", "/").removeprefix("./")
    b = right.replace("\\", "/").removeprefix("./")
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _location_matches(observed: Any, expected: RubricLocation, tolerance: int) -> bool:
    if not _same_path(str(getattr(observed, "file", "")), expected.file):
        return False
    if expected.line_start is None:
        return True
    observed_start = getattr(observed, "start_line", None)
    observed_end = getattr(observed, "end_line", observed_start)
    if observed_start is None:
        return False
    expected_end = expected.line_end or expected.line_start
    observed_end = observed_end or observed_start
    return not (
        observed_end < expected.line_start - tolerance
        or observed_start > expected_end + tolerance
    )


def _score_identification(rubric: TargetRubric, finding: Any | None) -> ComponentScore:
    if finding is None:
        return ComponentScore(status="fail", reason="no finding was matched to the target")
    descriptions = [item for item in rubric.accepted_descriptions if _tokens(item)]
    if not descriptions:
        return ComponentScore(
            status="unknown",
            reason="the private rubric has no accepted mechanism description",
        )
    text = _finding_text(finding)
    supported = [item for item in descriptions if _description_supported(item, text)]
    if not supported:
        return ComponentScore(
            status="fail",
            reason="the finding does not identify an accepted target mechanism",
        )
    finding_cwes = {str(item).upper() for item in (getattr(finding, "cwe", []) or [])}
    rubric_cwes = {str(item).upper() for item in rubric.cwe_ids}
    if finding_cwes and rubric_cwes and not (finding_cwes & rubric_cwes):
        return ComponentScore(
            status="fail",
            reason="the mechanism description matched but the reported CWE contradicts the target",
            evidence=supported,
        )
    return ComponentScore(
        status="pass",
        reason="the finding identifies an accepted target mechanism",
        evidence=supported,
    )


def _score_evidence(
    rubric: TargetRubric, finding: Any | None, *, line_tolerance: int
) -> ComponentScore:
    required = [item for item in rubric.required_evidence if item.required]
    if not required:
        return ComponentScore(
            status="unknown", reason="the private rubric has no required evidence contract"
        )
    if finding is None:
        return ComponentScore(status="fail", reason="no finding supplied repository evidence")
    citations = list(getattr(finding, "evidence_citations", []) or [])
    if not citations:
        return ComponentScore(
            status="fail",
            reason="the finding has no structured evidence_citations",
        )
    passed: list[str] = []
    failed: list[str] = []
    for requirement in required:
        hits: set[str] = set()
        allowed = {item.lower() for item in requirement.evidence_kinds}
        for citation in citations:
            kind = str(getattr(citation, "evidence_kind", "")).lower()
            if allowed and kind not in allowed:
                continue
            location = getattr(citation, "location", None)
            if location is None:
                continue
            if any(
                _location_matches(location, expected, line_tolerance)
                for expected in requirement.acceptable_locations
            ):
                hits.add(str(getattr(citation, "citation_id", len(hits))))
        if len(hits) >= requirement.minimum_citations:
            passed.append(requirement.requirement_id)
        else:
            failed.append(requirement.requirement_id)
    if failed:
        return ComponentScore(
            status="fail",
            reason="required repository evidence was not cited: " + ", ".join(failed),
            evidence=passed,
        )
    return ComponentScore(
        status="pass",
        reason="all required repository evidence was cited",
        evidence=passed,
    )


def _score_severity(rubric: TargetRubric, finding: Any | None) -> tuple[ComponentScore, int | None]:
    expected = (rubric.expected_severity_level or "").lower()
    if not expected:
        return ComponentScore(status="unknown", reason="target severity is not frozen"), None
    if finding is None:
        return ComponentScore(status="fail", reason="no finding reported a severity"), None
    actual = str(getattr(getattr(finding, "severity", None), "value", "")).lower()
    if actual not in _SEVERITY_ORDINAL or expected not in _SEVERITY_ORDINAL:
        return ComponentScore(status="unknown", reason="severity convention is unsupported"), None
    delta = _SEVERITY_ORDINAL[actual] - _SEVERITY_ORDINAL[expected]
    return (
        ComponentScore(
            status="pass" if delta == 0 else "fail",
            reason=(
                "reported severity matches"
                if delta == 0
                else f"severity ordinal delta is {delta}"
            ),
            evidence=[actual, expected],
        ),
        delta,
    )


def _attributable(*components: ComponentScore) -> ComponentScore:
    statuses = [item.status for item in components]
    if all(status == "pass" for status in statuses):
        return ComponentScore(status="pass", reason="V, I and E all passed")
    if "fail" in statuses:
        return ComponentScore(status="fail", reason="at least one of V, I or E failed")
    return ComponentScore(status="unknown", reason="at least one of V, I or E is unknown")


def score_target_rubrics(
    rubrics: list[TargetRubric],
    findings: list[Any],
    match_report: Any,
    *,
    task_id: str = "",
    line_tolerance: int = 5,
) -> RubricScoreReport:
    """Score frozen rubrics against already-parsed findings and target matches."""

    if not rubrics:
        return RubricScoreReport(
            task_id=task_id,
            status="not_available",
            notes=["no private target rubrics were supplied; V/I/E/S were not inferred"],
            summary={
                "targets": 0,
                "verdict_pass": 0,
                "identification_pass": 0,
                "evidence_pass": 0,
                "severity_pass": 0,
                "attributable_pass": 0,
                "attributable_rate": None,
            },
        )
    findings_by_id = {str(item.finding_id): item for item in findings}
    matches = {str(item.target_id): item for item in match_report.matches}
    scores: list[TargetRubricScore] = []
    for rubric in rubrics:
        match = matches.get(rubric.target_id)
        finding_id = str(match.finding_id) if match and match.finding_id else None
        finding = findings_by_id.get(finding_id) if finding_id else None
        reported = finding is not None
        expected_report = rubric.expected_verdict == "report"
        verdict_ok = reported == expected_report
        verdict = ComponentScore(
            status="pass" if verdict_ok else "fail",
            reason=(
                "target received the expected report disposition"
                if verdict_ok
                else "target report disposition contradicted the private rubric"
            ),
        )
        identification = _score_identification(rubric, finding)
        evidence = _score_evidence(rubric, finding, line_tolerance=line_tolerance)
        severity, severity_delta = _score_severity(rubric, finding)
        attributable = _attributable(verdict, identification, evidence)
        scores.append(
            TargetRubricScore(
                target_id=rubric.target_id,
                finding_id=finding_id,
                verdict=verdict,
                identification=identification,
                evidence_validation=evidence,
                severity=severity,
                attributable=attributable,
                severity_delta=severity_delta,
            )
        )

    def count(component: str, status: str = "pass") -> int:
        return sum(
            getattr(item, component).status == status
            for item in scores
        )

    attributable_pass = count("attributable")
    return RubricScoreReport(
        task_id=task_id,
        scores=scores,
        status="scored",
        summary={
            "targets": len(scores),
            "verdict_pass": count("verdict"),
            "identification_pass": count("identification"),
            "evidence_pass": count("evidence_validation"),
            "severity_pass": count("severity"),
            "attributable_pass": attributable_pass,
            "attributable_rate": attributable_pass / len(scores) if scores else None,
        },
        notes=[
            "identification uses frozen accepted descriptions; CWE overlap alone is insufficient",
            "evidence credit requires structured evidence_citations at rubric locations",
            "attributable means V and I and E all passed",
        ],
    )


__all__ = [
    "ComponentScore",
    "EvidenceRequirement",
    "RUBRIC_SCHEMA_VERSION",
    "RubricLocation",
    "RubricScoreReport",
    "TargetRubric",
    "TargetRubricScore",
    "build_target_rubric",
    "remap_rubric",
    "score_target_rubrics",
]
