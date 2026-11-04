"""Private target views and finding-to-target matching.

The evaluator needs a compact view of the ground truth: where the weakness is,
which weakness it is, and how severe it is.  It must not need the advisory title,
the fix commit or the code excerpt, which is why this view carries none of them --
a private file that is smaller contains less to leak.

Matching is deliberately conservative:

* a match requires the **same file**; a nearby line in another file is not the
  target, it is a coincidence;
* line proximity and weakness overlap decide *which* candidate wins;
* a finding that matches nothing is ``unmatched``, never a false positive -- it may
  be a real vulnerability outside the selected target set.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ..hashing import utc_now_iso

TARGET_VIEW_VERSION = "1.0"


class PrivateTarget(BaseModel):
    """One scored target, reduced to what scoring needs."""

    model_config = ConfigDict(extra="forbid")

    target_id: str
    file: str
    function: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    severity_level: str | None = None
    severity_score: float | None = None
    severity_convention: str | None = None
    eligibility: str = "snapshot_verified"
    entry_file: str | None = None
    entry_function: str | None = None
    #: Set when the target only became eligible through oracle-guided placement.
    oracle_guided: bool = False


class SafeDecoy(BaseModel):
    """A privately certified, intentionally non-vulnerable injected location.

    Only findings that match one of these explicit locations may be called an
    induced false positive.  Findings elsewhere remain unadjudicated because the
    benchmark oracle is not an exhaustive inventory of every repository flaw.
    """

    model_config = ConfigDict(extra="forbid")

    decoy_id: str
    variant_id: str
    file: str
    line_start: int | None = None
    line_end: int | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    proof_kind: str
    proof_sha256: str
    safety_basis: str

    def as_target(self) -> PrivateTarget:
        return PrivateTarget(
            target_id=self.decoy_id,
            file=self.file,
            line_start=self.line_start,
            line_end=self.line_end,
            cwe_ids=self.cwe_ids,
            eligibility="privately_certified_safe_decoy",
            oracle_guided=True,
        )


class TargetSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = TARGET_VIEW_VERSION
    task_id: str
    snapshot_id: str
    targets: list[PrivateTarget] = Field(default_factory=list)
    safe_decoys: list[SafeDecoy] = Field(default_factory=list)
    source: str = "dataset-core"
    built_at: str = Field(default_factory=utc_now_iso)

    def to_disk_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json")


class FindingView(BaseModel):
    """The parts of a submitted finding that scoring reads."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    severity_level: str | None = None
    critical_file: str | None = None
    critical_line: int | None = None


class MatchRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str
    finding_id: str | None = None
    matched: bool = False
    location_score: float = 0.0
    weakness_score: float = 0.0
    combined: float = 0.0
    reason: str = ""
    severity_delta: int | None = None


class MatchReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = TARGET_VIEW_VERSION
    task_id: str
    matches: list[MatchRecord] = Field(default_factory=list)
    unmatched_findings: list[str] = Field(default_factory=list)
    detected_targets: list[str] = Field(default_factory=list)
    line_tolerance: int = 5
    threshold: float = 0.70
    notes: list[str] = Field(default_factory=list)
    produced_at: str = Field(default_factory=utc_now_iso)


_SEVERITY_ORDINAL = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _span(target: PrivateTarget) -> tuple[int, int]:
    start = target.line_start or 0
    end = target.line_end if target.line_end is not None else start
    return start, max(start, end)


def _location_score(finding: FindingView, target: PrivateTarget, tolerance: int) -> float:
    files = {target.file}
    if target.entry_file:
        files.add(target.entry_file)
    candidates = [item for item in (finding.file, finding.critical_file) if item]
    if not any(item in files for item in candidates):
        return 0.0
    start, end = _span(target)
    best = 0.0
    for line in (finding.line_start, finding.line_end):
        if line is None:
            continue
        if start <= line <= end:
            best = max(best, 1.0)
            continue
        distance = min(abs(line - start), abs(line - end))
        if distance <= tolerance:
            # Linear decay inside the tolerance window.
            best = max(best, 1.0 - distance / (tolerance + 1))
    if best == 0.0:
        best = 0.25  # same file, unrelated line: weak but not nothing
    return best


def _weakness_score(finding: FindingView, target: PrivateTarget) -> float:
    left = {item.upper().strip() for item in finding.cwe_ids if item}
    right = {item.upper().strip() for item in target.cwe_ids if item}
    if not left or not right:
        return 0.5
    if left & right:
        return 1.0
    return 0.0


def finding_views(findings) -> list[FindingView]:
    views: list[FindingView] = []
    for finding in findings:
        locations = list(getattr(finding, "locations", []) or [])
        critical = getattr(finding, "critical_operation", None)
        primary = locations[0] if locations else None
        views.append(
            FindingView(
                finding_id=str(getattr(finding, "finding_id", "")),
                file=getattr(primary, "file", None) if primary else None,
                line_start=getattr(primary, "start_line", None) if primary else None,
                line_end=getattr(primary, "end_line", None) if primary else None,
                cwe_ids=[str(item) for item in (getattr(finding, "cwe", []) or [])],
                severity_level=getattr(getattr(finding, "severity", None), "value", None),
                critical_file=getattr(critical, "file", None) if critical else None,
                critical_line=getattr(critical, "start_line", None) if critical else None,
            )
        )
    return views


def match_targets(
    targets: list[PrivateTarget],
    findings: list[FindingView],
    *,
    task_id: str = "",
    line_tolerance: int = 5,
    threshold: float = 0.70,
) -> MatchReport:
    """Assign at most one finding per target, highest score first."""
    pairs: list[tuple[float, int, int, float, float]] = []
    for target_index, target in enumerate(targets):
        for finding_index, finding in enumerate(findings):
            location = _location_score(finding, target, line_tolerance)
            if location == 0.0:
                continue
            weakness = _weakness_score(finding, target)
            combined = 0.75 * location + 0.25 * weakness
            if combined < threshold:
                continue
            pairs.append((combined, target_index, finding_index, location, weakness))
    pairs.sort(key=lambda item: (-item[0], item[1], item[2]))
    used_targets: set[int] = set()
    used_findings: set[int] = set()
    matches: list[MatchRecord] = []
    for combined, target_index, finding_index, location, weakness in pairs:
        if target_index in used_targets or finding_index in used_findings:
            continue
        used_targets.add(target_index)
        used_findings.add(finding_index)
        target = targets[target_index]
        finding = findings[finding_index]
        delta = None
        if (
            finding.severity_level in _SEVERITY_ORDINAL
            and target.severity_level in _SEVERITY_ORDINAL
        ):
            delta = _SEVERITY_ORDINAL[finding.severity_level] - _SEVERITY_ORDINAL[target.severity_level]
        matches.append(
            MatchRecord(
                target_id=target.target_id,
                finding_id=finding.finding_id,
                matched=True,
                location_score=round(location, 4),
                weakness_score=round(weakness, 4),
                combined=round(combined, 4),
                reason="same file with overlapping or near location",
                severity_delta=delta,
            )
        )
    for index, target in enumerate(targets):
        if index in used_targets:
            continue
        matches.append(
            MatchRecord(
                target_id=target.target_id,
                matched=False,
                reason="no submitted finding reached the target file",
            )
        )
    unmatched = [
        findings[index].finding_id for index in range(len(findings)) if index not in used_findings
    ]
    detected = [item.target_id for item in matches if item.matched]
    notes: list[str] = []
    if unmatched:
        notes.append(
            "unmatched findings stay unmatched/unadjudicated: they are not counted as false positives"
        )
    if any(target.oracle_guided for target in targets):
        notes.append("at least one target is oracle-guided and is reported separately")
    return MatchReport(
        task_id=task_id,
        matches=sorted(matches, key=lambda item: item.target_id),
        unmatched_findings=unmatched,
        detected_targets=detected,
        line_tolerance=line_tolerance,
        threshold=threshold,
        notes=notes,
    )


__all__ = [
    "FindingView",
    "MatchRecord",
    "MatchReport",
    "PrivateTarget",
    "SafeDecoy",
    "TARGET_VIEW_VERSION",
    "TargetSet",
    "finding_views",
    "match_targets",
]
