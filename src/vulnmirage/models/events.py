"""Unified observation event models and run artifact metadata."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..paths import normalize_relpath


class EventSource(str, Enum):
    NATIVE = "native_agent"
    WRAPPER = "command_wrapper"
    OS = "os_trace"
    SUPERVISOR = "process_supervisor"
    EVALUATOR = "posthoc_evaluator"


class EventType(str, Enum):
    RUN_START = "run_start"
    RUN_END = "run_end"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    FILE_ACCESS = "file_access"
    SEARCH = "search"
    COMMAND = "command"
    PROCESS_START = "process_start"
    PROCESS_END = "process_end"
    BUILD = "build"
    TEST = "test"
    POC = "poc"
    FINDING = "finding"
    TOOL_ERROR = "tool_error"
    FORMAT_ERROR = "format_error"
    TIMEOUT = "timeout"


class ObservabilityGrade(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"


class AuditStage(str, Enum):
    EXPLORE = "explore"
    HYPOTHESIZE = "hypothesize"
    EVIDENCE_COLLECTION = "evidence_collection"
    VERIFICATION = "verification"
    REPORTING = "reporting"


FILE_OPERATIONS = {
    "open",
    "read",
    "stat",
    "list",
    "search_match",
    "tool_context",
    "bulk_runtime_read",
}


def _relative_or_none(value: str | None) -> str | None:
    if value is None:
        return None
    if value in {"", "."}:
        return "."
    return normalize_relpath(value)


class UnifiedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    event_id: str
    run_id: str
    sequence: int = Field(ge=0)
    timestamp_utc: str
    monotonic_ns: int = Field(ge=0)
    event_type: EventType
    source: EventSource
    parent_event_id: str | None = None
    tool_call_id: str | None = None
    tool_name: str | None = None
    argv: list[str] | None = None
    cwd: str | None = None
    path: str | None = None
    operation: str | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    exit_code: int | None = None
    stdout_ref: str | None = None
    stderr_ref: str | None = None
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cwd", "path")
    @classmethod
    def _paths(cls, value: str | None) -> str | None:
        return _relative_or_none(value)

    @field_validator("operation")
    @classmethod
    def _operation(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if value not in FILE_OPERATIONS:
            raise ValueError(f"unknown file operation: {value}")
        return value


class FileAccessRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    run_id: str
    sequence: int
    timestamp_utc: str
    monotonic_ns: int
    path: str
    operation: str
    access_source: EventSource
    tool_call_id: str | None = None
    requested_start_line: int | None = None
    requested_end_line: int | None = None
    observed_start_line: int | None = None
    observed_end_line: int | None = None
    bytes_observed: int | None = None
    content_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    first_access: bool = False
    #: True only when a native tool result proves content reached the model.
    content_returned_to_model: bool = False
    content_truncated: bool = False
    #: How ``content_returned_to_model`` was established: explicit tool
    #: metadata, a native-source inference, or unknown (P1-2).
    returned_to_model_source: str | None = None
    #: Layered exposure semantics.  ``None`` means "not determinable" and must
    #: never be read as "the model did not see it".
    file_access_observed: bool | None = None
    payload_visible_in_tool_result: bool | None = None
    counterevidence_accessed: bool | None = None
    exposure_state: str | None = None
    visibility_basis: str | None = None
    #: Whether the location was cited in the final report (set by evaluation).
    content_cited_in_final_report: bool = False

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return normalize_relpath(value)

    @field_validator("operation")
    @classmethod
    def _operation(cls, value: str) -> str:
        if value not in FILE_OPERATIONS:
            raise ValueError(f"unknown file operation: {value}")
        return value


class RawEventEnvelope(BaseModel):
    """Immutable wrapper around one source event payload."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    event_id: str
    run_id: str
    source: EventSource
    source_event_id: str | None = None
    timestamp_utc: str
    monotonic_ns: int = Field(ge=0)
    raw_payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_payload: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)


class EnrichedTrajectoryEvent(BaseModel):
    """Derived event annotation; raw events are never rewritten."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    event: UnifiedEvent
    roles: list[str] = Field(default_factory=list)
    stage: str
    claim_ids: list[str] = Field(default_factory=list)
    node_ids: list[str] = Field(default_factory=list)
    derived_from: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RunArtifactSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    raw_events_sha256: str | None = None
    normalized_events_sha256: str | None = None
    tool_calls_sha256: str | None = None
    file_access_sha256: str | None = None
    process_events_sha256: str | None = None
    final_raw_sha256: str | None = None
    findings_sha256: str | None = None
    enriched_trajectory_sha256: str | None = None
    verification_assessments_sha256: str | None = None
    inputs: dict[str, str] = Field(default_factory=dict)
    outputs: dict[str, str] = Field(default_factory=dict)


class ObservabilityAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grade: ObservabilityGrade
    native_event_count: int = 0
    wrapper_event_count: int = 0
    os_event_count: int = 0
    notes: list[str] = Field(default_factory=list)
    process_metrics_eligible: bool = False


EventTypeLiteral = Literal[
    "run_start",
    "run_end",
    "tool_call",
    "tool_result",
    "file_access",
    "search",
    "command",
    "process_start",
    "process_end",
    "build",
    "test",
    "poc",
    "finding",
    "tool_error",
    "format_error",
    "timeout",
]
