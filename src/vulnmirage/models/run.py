"""Agent run manifest and run metadata."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AgentRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    instance_id: str
    repetition: int = Field(ge=1)
    model_provider: str
    model_name: str
    model_version: str | None = None
    scaffold: str
    scaffold_version: str | None = None
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_policy: dict[str, Any] = Field(default_factory=dict)
    token_budget: int | None = Field(default=None, ge=0)
    time_budget_seconds: int = Field(ge=1)
    network_enabled: bool = False
    started_at: str
    ended_at: str
    status: str
    findings_path: str | None = None
    raw_events_path: str
    normalized_events_path: str
    tool_calls_path: str
    file_access_path: str
    process_events_path: str
    enriched_trajectory_path: str | None = None
    verification_assessments_path: str | None = None
    observability_grade: str = Field(pattern=r"^[ABCD]$")
    stdout_path: str
    stderr_path: str
    final_raw_path: str
    event_count: int = Field(default=0, ge=0)
    file_access_count: int = Field(default=0, ge=0)
    tool_call_count: int = Field(default=0, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    tool_tokens: int | None = Field(default=None, ge=0)
    artifact_sha256: dict[str, str] = Field(default_factory=dict)
    #: ``reference`` runs (R0) never enter formal clean/control denominators.
    purpose: str = "evaluation"
    role: str | None = None
    observation_capabilities: dict[str, Any] = Field(default_factory=dict)
    artifact_manifest_path: str | None = None
    #: Exact execution-condition identity (P0-1).  ``execution_condition`` is a
    #: credential-free public descriptor; ``condition_id`` is its canonical hash.
    execution_condition: dict[str, Any] = Field(default_factory=dict)
    condition_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    condition_source: str | None = None
    #: Defense condition applied by the harness (never by the repository).
    defense_id: str | None = None
    defense_version: str | None = None
    #: Attempt index for this logical run (1 = first attempt).
    attempt: int = Field(default=1, ge=1)
    #: How often the logical cell was planned to run (P0-6).  Recorded per run
    #: so an evaluation can tell a 5-repetition cell from a partial one.
    planned_repetitions: int | None = Field(default=None, ge=1)
    #: Wall-clock ordering hint for deterministic attempt selection.
    external_file_sha256: dict[str, str] = Field(default_factory=dict)
    isolation_enforcement: str | None = None
    audit_scope: dict[str, Any] = Field(default_factory=dict)

    @field_validator("run_id", "instance_id", "model_provider", "model_name", "scaffold", "status")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value


class RunMeta(BaseModel):
    """Supplementary, non-spec run state kept next to ``run.json``."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    instance_id: str
    pair_id: str
    repetition: int
    agent_config_sha256: str
    release_sha256: str | None = None
    instance_manifest_sha256: str
    task_sha256: str
    repo_tree_sha256_before: str
    repo_tree_sha256_after: str | None = None
    repo_dirty_before: bool = False
    contaminated: bool = False
    changed_files: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    timed_out: bool = False
    duration_seconds: float = 0.0
    parse_status: str = "not_attempted"
    parse_error: str | None = None
    output_sha256: str | None = None
    trace_sha256: str | None = None
    network_enabled: bool = False
    sandbox_notes: list[str] = Field(default_factory=list)
    stderr_excerpt: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    # Observation / pairwise execution metadata.
    observability_grade: str | None = None
    native_event_count: int = 0
    normalized_event_count: int = 0
    file_access_count: int = 0
    tool_call_count: int = 0
    observer_notes: list[str] = Field(default_factory=list)
    pair_order_seed: int | None = None
    pair_order_index: int | None = None
    derived_inputs_sha256: dict[str, str] = Field(default_factory=dict)
    artifact_sha256: dict[str, str] = Field(default_factory=dict)
    raw_events_frozen: bool = False
    purpose: str = "evaluation"
    role: str | None = None
    observation_capabilities: dict[str, Any] = Field(default_factory=dict)
    artifact_manifest_sha256: str | None = None
    #: Exact execution-condition identity (P0-1).
    execution_condition: dict[str, Any] = Field(default_factory=dict)
    condition_id: str | None = None
    condition_source: str | None = None
    external_file_sha256: dict[str, str] = Field(default_factory=dict)
    defense: dict[str, Any] = Field(default_factory=dict)
    inference: dict[str, Any] = Field(default_factory=dict)
    attempt: int = Field(default=1, ge=1)
    isolation: dict[str, Any] = Field(default_factory=dict)
    task_template_sha256: str | None = None
    defense_instructions_sha256: str | None = None
    effective_prompt_sha256: str | None = None
    #: Repetition plan and pre-registered attempt policy (P0-6 / P0-1 #5).
    planned_repetitions: int | None = Field(default=None, ge=1)
    attempt_selection_rule: str | None = None
    retry_policy: dict[str, Any] = Field(default_factory=dict)
    container_cleanup: dict[str, Any] = Field(default_factory=dict)
