"""Reference audit (R0) contracts.

A reference audit is *not* ground truth.  It is an advisory artifact produced by
an agent under a different role/session whose findings must be verified against
the fixed snapshot before any of them can influence generation.  The models here
keep the three layers separate:

1. :class:`ReferenceAudit` -- identity, provenance, budget and raw output of R0;
2. :class:`ReferenceFindingProfile` -- what the report *claims*, with the exact
   quote/event and an extraction confidence, still a ``report_claim``;
3. :class:`ReferenceFindingLink` -- the private verification verdict that ties a
   claim to a known vulnerability or a validated safe target.

Only (2) may reach the generator, and only through the allowlisted
:class:`~vulnmirage.generation.request.GeneratorRequest` projection.  (3) stays
private.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import SeverityLevel
from .finding import AgentFinding
from .repository import CodeLocation


class ReferenceSource(str, Enum):
    NONE = "none"
    IMPORT = "import"
    RUN = "run"


class ReferenceStatus(str, Enum):
    OK = "ok"
    FORMAT_FAILURE = "format_failure"
    TIMEOUT = "timeout"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"
    MISSING = "missing"
    INVALID = "invalid"


class ReferenceFindingLinkStatus(str, Enum):
    """Private verification verdict for one reported/known target.

    ``UNMATCHED_NEEDS_ADJUDICATION`` is deliberately distinct from
    ``CONFIRMED_FALSE_POSITIVE``: a finding that cannot be matched to the
    (partial) oracle is *unknown*, not a false positive, and is never counted as
    one until an independent adjudication adds it to the labels.
    """

    MATCHED_KNOWN_VULNERABILITY = "matched_known_vulnerability"
    KNOWN_TARGET_NOT_REPORTED = "known_target_not_reported"
    CONFIRMED_FALSE_POSITIVE = "confirmed_false_positive"
    UNMATCHED_NEEDS_ADJUDICATION = "unmatched_needs_adjudication"
    AMBIGUOUS_MATCH = "ambiguous_match"
    SEVERITY_DISAGREEMENT = "severity_disagreement"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class ReferenceBudget(BaseModel):
    """Acquisition budget.  ``None`` means *unknown*, never zero."""

    model_config = ConfigDict(extra="forbid")

    max_queries: int | None = Field(default=None, ge=0)
    queries_used: int | None = Field(default=None, ge=0)
    max_tokens: int | None = Field(default=None, ge=0)
    tokens_used: int | None = Field(default=None, ge=0)
    wall_clock_seconds: float | None = Field(default=None, ge=0.0)
    cost_usd: float | None = Field(default=None, ge=0.0)
    cost_known: bool = False

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ReferenceTraceObservation(BaseModel):
    """Trajectory-backed observations of R0.

    Every entry cites a real event id.  Without a native trace this object is
    ``available=False`` and no visited file/search term is inferred from the
    final report text.
    """

    model_config = ConfigDict(extra="forbid")

    available: bool = False
    importer: str | None = None
    observability_level: str = "none"
    visited_files: list[str] = Field(default_factory=list)
    read_ranges: list[dict[str, Any]] = Field(default_factory=list)
    search_terms: list[str] = Field(default_factory=list)
    commands: list[dict[str, Any]] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ReferenceAudit(BaseModel):
    """One R0 acquisition, with an identity independent of any formal run."""

    model_config = ConfigDict(extra="forbid")

    reference_audit_id: str
    purpose: Literal["reference"] = "reference"
    role: Literal["reference"] = "reference"
    source: ReferenceSource = ReferenceSource.IMPORT
    status: ReferenceStatus = ReferenceStatus.OK
    snapshot_id: str | None = None
    repository_tree_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    task_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    agent: str
    provider: str | None = None
    model: str | None = None
    model_version: str | None = None
    config_sha256: str | None = None
    repetition: int = Field(default=1, ge=1)
    seed: int | None = None
    session_id: str
    budget: ReferenceBudget = Field(default_factory=ReferenceBudget)
    report_access: Literal["none", "surrogate", "target"] = "target"
    trace_access: Literal["none", "observable"] = "none"
    raw_report_path: str | None = None
    raw_report_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    findings_path: str | None = None
    findings: list[AgentFinding] = Field(default_factory=list)
    trace: ReferenceTraceObservation = Field(default_factory=ReferenceTraceObservation)
    cache_key: str | None = None
    cache_hit: bool = False
    imported_at: str | None = None
    created_at: str | None = None
    source_reference: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)

    @field_validator(
        "reference_audit_id",
        "agent",
        "session_id",
    )
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @model_validator(mode="after")
    def _identity(self) -> "ReferenceAudit":
        if self.purpose != "reference" or self.role != "reference":
            raise ValueError("a ReferenceAudit must have purpose=role=reference")
        if self.status == ReferenceStatus.OK and not self.findings:
            # An empty but *successful* report is a real outcome only if the
            # acquisition recorded a parsed empty envelope; missing output is
            # never silently read as "no vulnerabilities".
            self.warnings.append("reference report parsed to an empty finding set")
        if self.report_access == "none" and self.findings:
            raise ValueError("report_access=none cannot carry imported findings")
        return self


class ReferenceFindingProfile(BaseModel):
    """One extracted report claim (still not a verified fact)."""

    model_config = ConfigDict(extra="forbid")

    profile_id: str
    reference_audit_id: str
    finding_id: str
    reported_type: str
    reported_cwe: list[str] = Field(default_factory=list)
    reported_severity: SeverityLevel | None = None
    severity_rationale: str | None = None
    reported_locations: list[CodeLocation] = Field(default_factory=list)
    reported_entry_point: CodeLocation | None = None
    reported_critical_operation: CodeLocation | None = None
    reported_trace: list[CodeLocation] = Field(default_factory=list)
    safe_judgment: str | None = None
    uncertainty: str | None = None
    verification_items: list[str] = Field(default_factory=list)
    source_excerpt: str | None = None
    extraction_method: str = "finding_envelope"
    extraction_confidence: Literal["high", "medium", "low"] = "high"
    status: Literal["report_claim"] = "report_claim"
    trace_backed: bool = False
    evidence_kind: str | None = None

    @field_validator("profile_id", "finding_id", "reported_type")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value


class ReferenceFindingLink(BaseModel):
    """Private verification verdict (evaluation-side only)."""

    model_config = ConfigDict(extra="forbid")

    link_id: str
    reference_audit_id: str
    finding_id: str | None = None
    status: ReferenceFindingLinkStatus
    vulnerability_id: str | None = None
    safe_target_id: str | None = None
    matched_path_id: str | None = None
    match_profile: str | None = None
    match_score: float | None = Field(default=None, ge=0.0, le=1.0)
    reported_severity: SeverityLevel | None = None
    oracle_severity: SeverityLevel | None = None
    severity_agrees: bool | None = None
    reasons: list[str] = Field(default_factory=list)
    needs_adjudication: bool = False
    verification_evidence: list[str] = Field(default_factory=list)


class BaselineAuditContext(BaseModel):
    """Everything the generator may know about R0, plus private verdicts."""

    model_config = ConfigDict(extra="forbid")

    audit: ReferenceAudit | None = None
    profiles: list[ReferenceFindingProfile] = Field(default_factory=list)
    links: list[ReferenceFindingLink] = Field(default_factory=list)
    target_source: Literal["oracle", "reference", "combined"] = "oracle"
    report_access: Literal["none", "surrogate", "target"] = "none"
    trace_access: Literal["none", "observable"] = "none"
    oracle_access: Literal["target_details", "none"] = "target_details"
    available: bool = False
    missing_reason: str | None = None
    reference_detected_target_ids: list[str] = Field(default_factory=list)
    unreported_known_target_ids: list[str] = Field(default_factory=list)
    confirmed_false_positive_target_ids: list[str] = Field(default_factory=list)
    adjudication_target_ids: list[str] = Field(default_factory=list)
    severity_disagreement_ids: list[str] = Field(default_factory=list)
    insufficient_evidence_target_ids: list[str] = Field(default_factory=list)
    extraction_notes: list[str] = Field(default_factory=list)

    def link_for_finding(self, finding_id: str) -> ReferenceFindingLink | None:
        for link in self.links:
            if link.finding_id == finding_id:
                return link
        return None

    def profile_for_finding(self, finding_id: str) -> ReferenceFindingProfile | None:
        for profile in self.profiles:
            if profile.finding_id == finding_id:
                return profile
        return None

    def generation_eligible_vulnerability_ids(self) -> list[str]:
        """Targets the current knowledge permission may expose to generation."""
        if self.report_access in {"surrogate", "target"}:
            matched = {
                link.vulnerability_id
                for link in self.links
                if link.status
                in {
                    ReferenceFindingLinkStatus.MATCHED_KNOWN_VULNERABILITY,
                    ReferenceFindingLinkStatus.SEVERITY_DISAGREEMENT,
                }
                and link.vulnerability_id
            }
            if self.target_source == "reference":
                return sorted(matched)
            return sorted(matched | set(self.unreported_known_target_ids))
        return []

    def blocked_reason_for(self, vulnerability_id: str) -> str | None:
        for link in self.links:
            if link.vulnerability_id != vulnerability_id:
                continue
            if link.status == ReferenceFindingLinkStatus.INSUFFICIENT_EVIDENCE:
                return "insufficient_evidence"
        for link in self.links:
            if link.vulnerability_id == vulnerability_id and link.status in {
                ReferenceFindingLinkStatus.UNMATCHED_NEEDS_ADJUDICATION,
                ReferenceFindingLinkStatus.AMBIGUOUS_MATCH,
            }:
                return link.status.value
        return None
