"""Agent finding output envelope."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import SeverityLevel
from .repository import CodeLocation


class EvidenceCitation(BaseModel):
    """A verifiable evidence claim supplied by the agent report."""

    model_config = ConfigDict(extra="forbid")

    citation_id: str
    claim: str
    location: CodeLocation
    evidence_kind: str

    @field_validator("evidence_kind")
    @classmethod
    def _kind(cls, value: str) -> str:
        allowed = {"source", "data_flow", "guard", "configuration", "test", "runtime"}
        if value not in allowed:
            raise ValueError(f"evidence_kind must be one of {sorted(allowed)}")
        return value


class AgentFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    vulnerability_type: str
    cwe: list[str] = Field(default_factory=list)
    severity: SeverityLevel
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    locations: list[CodeLocation]
    entry_point: CodeLocation | None = None
    critical_operation: CodeLocation | None = None
    trace: list[CodeLocation] = Field(default_factory=list)
    exploitability: str
    evidence: list[str] = Field(default_factory=list)
    evidence_citations: list[EvidenceCitation] = Field(default_factory=list)
    remediation: str | None = None

    @field_validator("finding_id", "title", "vulnerability_type", "exploitability")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @model_validator(mode="after")
    def _locations(self) -> "AgentFinding":
        if not self.locations:
            raise ValueError("a finding must report at least one location")
        return self


class AuditSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    files_reviewed: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    overall_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class FindingEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    findings: list[AgentFinding] = Field(default_factory=list)
    audit_summary: AuditSummary = Field(default_factory=AuditSummary)

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: str) -> str:
        if value != "1.0":
            raise ValueError("unsupported finding schema_version")
        return value


class AuditReportEnvelope(BaseModel):
    """Dual-output contract: one audit produces a report *and* findings.

    ``report_markdown`` is the agent's own prose report.  It is kept verbatim (as
    data) next to the structured findings so the evaluator can compare the two
    without a second model call, and so a narrative that contradicts the JSON is
    visible instead of being silently dropped.

    Unknown top-level keys are ignored rather than rejected: the audit contract
    constrains four keys, and a model that adds ``"notes"`` should not lose an
    otherwise valid run.  The parser records every ignored key so nothing is
    dropped silently.
    """

    model_config = ConfigDict(extra="ignore")

    schema_version: str = "1.0"
    report_markdown: str = ""
    findings: list[AgentFinding] = Field(default_factory=list)
    audit_summary: AuditSummary = Field(default_factory=AuditSummary)

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: str) -> str:
        if value != "1.0":
            raise ValueError("unsupported audit output schema_version")
        return value
