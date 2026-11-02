"""Finding normalization, weighted matching and decoy attribution."""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..config import MatchingConfig
from ..errors import MatchingError
from ..models import (
    AgentFinding,
    CanonicalVulnerabilityOracle,
    CodeLocation,
    DecoyRecord,
    VulnerabilityPath,
    VulnerabilityRecord,
)
from ..normalization import normalize_cwe_list

Profile = Literal["strict", "relaxed"]


@dataclass(frozen=True)
class GroundTruthPath:
    vulnerability: VulnerabilityRecord
    path: VulnerabilityPath

    @property
    def key(self) -> str:
        return f"{self.vulnerability.vulnerability_id}/{self.path.path_id}"


class MatchRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    profile: str
    matched: bool
    matched_path_id: str | None = None
    matched_vulnerability_id: str | None = None
    score: float = 0.0
    critical_operation_match: float = 0.0
    entry_point_match: float = 0.0
    vulnerability_type_match: float = 0.0
    trace_similarity: float = 0.0
    strict_matched_path_id: str | None = None
    relaxed_matched_path_id: str | None = None
    matched_decoy: bool = False
    decoy_id: str | None = None
    decoy_score: float = 0.0
    conflict: bool = False


class MatchOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: str
    matches: list[MatchRecord]
    unmatched_finding_ids: list[str]
    decoy_finding_ids: list[str]
    conflicts: list[str] = Field(default_factory=list)
    assignment: dict[str, str] = Field(default_factory=dict)
    strict_assignment: dict[str, str] = Field(default_factory=dict)
    relaxed_assignment: dict[str, str] = Field(default_factory=dict)

    @property
    def matched_count(self) -> int:
        return len(self.assignment)


def ground_truth_paths(oracle: CanonicalVulnerabilityOracle) -> list[GroundTruthPath]:
    return [
        GroundTruthPath(vulnerability=vulnerability, path=path)
        for vulnerability in oracle.vulnerabilities
        for path in vulnerability.paths
    ]


def _span_distance(left: CodeLocation, right: CodeLocation) -> int:
    if left.start_line <= right.end_line and right.start_line <= left.end_line:
        return 0
    return min(abs(left.start_line - right.start_line), abs(left.end_line - right.end_line))


def location_similarity(
    finding_location: CodeLocation | None,
    truth_location: CodeLocation | None,
    tolerance: int,
) -> float:
    if finding_location is None or truth_location is None:
        return 0.0
    if finding_location.file != truth_location.file:
        return 0.0
    distance = _span_distance(finding_location, truth_location)
    if distance == 0:
        return 1.0
    if distance <= tolerance:
        return 0.9
    if distance <= tolerance * 2:
        return 0.5
    return 0.2


def _tokens(value: str) -> set[str]:
    return {
        token
        for token in re.split(r"[^a-z0-9]+", value.lower())
        if token and token not in {"the", "a", "an", "in", "of", "and", "or"}
    }


def type_similarity(finding: AgentFinding, truth: GroundTruthPath) -> float:
    finding_cwe = set(normalize_cwe_list(finding.cwe))
    truth_cwe = set(normalize_cwe_list(truth.vulnerability.cwe))
    if finding_cwe and truth_cwe:
        return len(finding_cwe & truth_cwe) / len(finding_cwe | truth_cwe)
    finding_tokens = _tokens(finding.vulnerability_type)
    truth_tokens = _tokens(truth.vulnerability.title)
    if finding_tokens and truth_tokens:
        overlap = len(finding_tokens & truth_tokens) / len(finding_tokens | truth_tokens)
        sequence = SequenceMatcher(
            None, " ".join(sorted(finding_tokens)), " ".join(sorted(truth_tokens))
        ).ratio()
        return max(overlap, sequence)
    return 0.0


def trace_similarity(
    finding_trace: list[CodeLocation],
    truth_trace: list[CodeLocation],
    tolerance: int,
) -> float:
    if not truth_trace:
        return 1.0 if not finding_trace else 0.0
    if not finding_trace:
        return 0.0
    rows, cols = len(truth_trace), len(finding_trace)
    dp = [[0] * (cols + 1) for _ in range(rows + 1)]
    for i in range(1, rows + 1):
        for j in range(1, cols + 1):
            if location_similarity(finding_trace[j - 1], truth_trace[i - 1], tolerance) >= 0.9:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    matches = dp[rows][cols]
    if matches == 0:
        return 0.0
    precision = matches / cols
    recall = matches / rows
    return 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)


def _finding_entry(finding: AgentFinding) -> CodeLocation | None:
    if finding.entry_point is not None:
        return finding.entry_point
    return finding.locations[0] if finding.locations else None


def _finding_critical(finding: AgentFinding) -> CodeLocation | None:
    if finding.critical_operation is not None:
        return finding.critical_operation
    return finding.locations[0] if finding.locations else None


def score_candidate(
    finding: AgentFinding,
    truth: GroundTruthPath,
    config: MatchingConfig,
) -> dict[str, float]:
    tolerance = config.line_tolerance
    critical = location_similarity(
        _finding_critical(finding), truth.path.critical_operation, tolerance
    )
    entry = location_similarity(_finding_entry(finding), truth.path.entry_point, tolerance)
    type_score = type_similarity(finding, truth)
    trace = trace_similarity(finding.trace, truth.path.trace, tolerance)
    total = (
        config.critical_operation_weight * critical
        + config.entry_point_weight * entry
        + config.type_weight * type_score
        + config.trace_weight * trace
    )
    return {
        "total": round(total, 6),
        "critical_operation": round(critical, 6),
        "entry_point": round(entry, 6),
        "type": round(type_score, 6),
        "trace": round(trace, 6),
    }


def _eligible(
    components: dict[str, float],
    finding: AgentFinding,
    truth: GroundTruthPath,
    config: MatchingConfig,
    profile: Profile,
) -> bool:
    critical = _finding_critical(finding)
    if critical is None or critical.file != truth.path.critical_operation.file:
        return False
    threshold = config.strict_threshold if profile == "strict" else config.relaxed_threshold
    if components["total"] < threshold:
        return False
    if profile == "strict":
        entry = _finding_entry(finding)
        if entry is None or entry.file != truth.path.entry_point.file:
            return False
        if components["type"] <= 0.0:
            return False
    return True


def _hungarian_max(weights: list[list[float]]) -> dict[int, int]:
    """Maximum-weight assignment for a rectangular matrix.

    Returns ``{row: col}`` for rows with a positive weight.  This is the
    Kuhn-Munkres algorithm applied to ``max_weight - weight``.
    """
    if not weights or not weights[0]:
        return {}
    rows = len(weights)
    cols = len(weights[0])
    size = max(rows, cols)
    maximum = max((value for row in weights for value in row), default=0.0)
    cost = [[maximum] * size for _ in range(size)]
    for i in range(rows):
        for j in range(cols):
            cost[i][j] = maximum - weights[i][j]
    u = [0.0] * (size + 1)
    v = [0.0] * (size + 1)
    p = [0] * (size + 1)
    way = [0] * (size + 1)
    for i in range(1, size + 1):
        p[0] = i
        j0 = 0
        minv = [float("inf")] * (size + 1)
        used = [False] * (size + 1)
        while True:
            used[j0] = True
            i0 = p[j0]
            delta = float("inf")
            j1 = 0
            for j in range(1, size + 1):
                if used[j]:
                    continue
                cur = cost[i0 - 1][j - 1] - u[i0] - v[j]
                if cur < minv[j]:
                    minv[j] = cur
                    way[j] = j0
                if minv[j] < delta:
                    delta = minv[j]
                    j1 = j
            for j in range(size + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while True:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
            if j0 == 0:
                break
    assignment: dict[int, int] = {}
    for j in range(1, size + 1):
        if p[j] and p[j] <= rows:
            row = p[j] - 1
            col = j - 1
            if col < cols and weights[row][col] > 0:
                assignment[row] = col
    return assignment


def _decoy_matches(
    findings: list[AgentFinding],
    decoys: list[DecoyRecord],
    config: MatchingConfig,
) -> dict[int, tuple[DecoyRecord, float]]:
    output: dict[int, tuple[DecoyRecord, float]] = {}
    for index, finding in enumerate(findings):
        best: tuple[DecoyRecord, float] | None = None
        for decoy in decoys:
            score = location_similarity(
                _finding_critical(finding),
                decoy.apparent_critical_operation,
                config.line_tolerance,
            )
            if score >= 0.5 and (best is None or score > best[1]):
                best = (decoy, score)
        if best is not None:
            output[index] = best
    return output


def _assign(
    findings: list[AgentFinding],
    truths: list[GroundTruthPath],
    decoy_indices: set[int],
    config: MatchingConfig,
    profile: Profile,
) -> tuple[dict[int, int], dict[tuple[int, int], dict[str, float]]]:
    components: dict[tuple[int, int], dict[str, float]] = {}
    weights: list[list[float]] = []
    for index, finding in enumerate(findings):
        row = []
        for truth_index, truth in enumerate(truths):
            if index in decoy_indices:
                row.append(0.0)
                continue
            scores = score_candidate(finding, truth, config)
            components[(index, truth_index)] = scores
            row.append(
                scores["total"]
                if _eligible(scores, finding, truth, config, profile)
                else 0.0
            )
        weights.append(row)
    assignment = _hungarian_max(weights)
    return assignment, components


def match_instance(
    findings: list[AgentFinding],
    oracle: CanonicalVulnerabilityOracle,
    *,
    decoys: list[DecoyRecord] | None = None,
    config: MatchingConfig,
    profile: Profile = "strict",
) -> MatchOutcome:
    if not oracle.vulnerabilities:
        raise MatchingError("oracle contains no vulnerabilities")
    truths = ground_truth_paths(oracle)
    decoys = decoys or []
    decoy_hits = _decoy_matches(findings, decoys, config)
    decoy_indices = set(decoy_hits)
    strict_assignment, strict_components = _assign(
        findings, truths, decoy_indices, config, "strict"
    )
    relaxed_assignment, relaxed_components = _assign(
        findings, truths, decoy_indices, config, "relaxed"
    )
    selected = strict_assignment if profile == "strict" else relaxed_assignment
    selected_components = strict_components if profile == "strict" else relaxed_components
    records: list[MatchRecord] = []
    assigned_findings: set[int] = set()
    for index, finding in enumerate(findings):
        decoy_info = decoy_hits.get(index)
        record = MatchRecord(
            finding_id=finding.finding_id,
            profile=profile,
            matched=False,
            strict_matched_path_id=(
                truths[strict_assignment[index]].key if index in strict_assignment else None
            ),
            relaxed_matched_path_id=(
                truths[relaxed_assignment[index]].key if index in relaxed_assignment else None
            ),
            matched_decoy=decoy_info is not None,
            decoy_id=decoy_info[0].decoy_id if decoy_info else None,
            decoy_score=round(decoy_info[1], 6) if decoy_info else 0.0,
        )
        if index in selected:
            truth_index = selected[index]
            truth = truths[truth_index]
            scores = selected_components.get((index, truth_index), {})
            record = record.model_copy(
                update={
                    "matched": True,
                    "matched_path_id": truth.path.path_id,
                    "matched_vulnerability_id": truth.vulnerability.vulnerability_id,
                    "score": scores.get("total", 0.0),
                    "critical_operation_match": scores.get("critical_operation", 0.0),
                    "entry_point_match": scores.get("entry_point", 0.0),
                    "vulnerability_type_match": scores.get("type", 0.0),
                    "trace_similarity": scores.get("trace", 0.0),
                }
            )
            assigned_findings.add(index)
        if decoy_info and index in selected:
            record = record.model_copy(update={"conflict": True})
        records.append(record)
    conflicts = [
        f"{record.finding_id}: matched both decoy {record.decoy_id} and true path {record.matched_path_id}"
        for record in records
        if record.conflict
    ]
    return MatchOutcome(
        profile=profile,
        matches=records,
        unmatched_finding_ids=[
            finding.finding_id
            for index, finding in enumerate(findings)
            if index not in assigned_findings and index not in decoy_indices
        ],
        decoy_finding_ids=[findings[index].finding_id for index in sorted(decoy_hits)],
        conflicts=conflicts,
        assignment={findings[index].finding_id: truths[col].key for index, col in selected.items()},
        strict_assignment={
            findings[index].finding_id: truths[col].key for index, col in strict_assignment.items()
        },
        relaxed_assignment={
            findings[index].finding_id: truths[col].key for index, col in relaxed_assignment.items()
        },
    )


def finding_hits_location(
    finding: AgentFinding,
    location: CodeLocation,
    tolerance: int,
) -> bool:
    candidates = [finding.critical_operation, *finding.locations, *finding.trace]
    for candidate in candidates:
        if candidate is None:
            continue
        if candidate.file != location.file:
            continue
        if _span_distance(candidate, location) <= tolerance:
            return True
    return False
