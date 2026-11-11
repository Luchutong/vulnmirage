"""Generation contracts: condition, candidate, validation, selection, manifest.

These models are the evidence trail the design asks for (§10, §13).  Two rules
make them more than bookkeeping:

* a candidate is only selectable when **every required validator returned
  ``pass``** -- ``unknown`` is not a pass, because "we could not check" and "we
  checked" are different claims;
* the selection record names the policy, the scores, the eliminated candidates
  and the tie-break *before* any victim run exists, so a later reader can tell a
  pre-registered choice from a choice made after seeing a result.
"""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator

from ..hashing import sha256_text, utc_now_iso
from ..tiers import Tier

GENERATION_SCHEMA_VERSION = "1.0"

ValidationStatus = Literal["pass", "fail", "unknown", "not_applicable"]
VALIDATION_STATUSES: tuple[str, ...] = ("pass", "fail", "unknown", "not_applicable")

EditOp = Literal["create", "append", "insert_before"]


class ConditionSpec(BaseModel):
    """One executable condition: the clean baseline or one attacked variant."""

    model_config = ConfigDict(extra="forbid")

    condition_id: str
    kind: Literal["clean", "attacked"] = "attacked"
    taxonomy_version: str | None = None
    threat_model_id: str | None = None
    objective: str = "none"
    method_id: str | None = None
    primary_mechanism: str | None = None
    surface: dict[str, str] | None = None
    intensity: str | None = None
    dose: dict[str, object] | None = None
    realization_id: str | None = None
    generator_tier: Tier = Field(
        default="T0", validation_alias=AliasChoices("generator_tier", "tier")
    )
    generator_profile: str = "default"
    candidate_budget: int = Field(default=1, ge=1, le=64)
    selection_policy: str = "semantic_fit_then_deterministic_tiebreak"
    victim_feedback: bool = False

    @model_validator(mode="after")
    def _feedback_only_at_t4(self) -> ConditionSpec:
        # Design §17.2: victim feedback belongs to T4's separate protocol.
        if self.victim_feedback and self.generator_tier != "T4":
            raise ValueError("victim_feedback is only defined for tier T4")
        return self

    @property
    def tier(self) -> Tier:
        return self.generator_tier


class ExperimentCell(BaseModel):
    """The frozen dimensions of one run; nothing is inferred at execution time."""

    model_config = ConfigDict(extra="forbid")

    dataset_version: str
    task_id: str
    target_id: str | None = None
    condition_id: str
    taxonomy_version: str | None = None
    threat_model_id: str | None = None
    objective: str = "none"
    method_id: str | None = None
    primary_mechanism: str | None = None
    surface: dict[str, str] | None = None
    intensity: str | None = None
    dose: dict[str, object] | None = None
    realization_id: str | None = None
    generator_tier: Tier = Field(
        default="T0", validation_alias=AliasChoices("generator_tier", "tier")
    )
    victim_model: str | None = None
    scaffold_version: str = "unknown"
    prompt_version: str = "unknown"
    audit_budget_seconds: int = 0
    repetition: int = 1
    run_order_seed: int = 0

    @property
    def tier(self) -> Tier:
        return self.generator_tier


class CandidatePayload(BaseModel):
    """A rendered, structured edit before it is applied to a tree."""

    model_config = ConfigDict(extra="forbid")

    candidate_id: str
    variant_id: str
    method_id: str
    realization_id: str | None = None
    objective: str = "none"
    primary_mechanism: str | None = None
    surface: dict[str, str] | None = None
    intensity: str | None = None
    dose: dict[str, object] | None = None
    generator_tier: Tier = Field(validation_alias=AliasChoices("generator_tier", "tier"))
    seed: int = 0
    generator: str
    carrier: str
    target_file: str | None = None
    edit_op: EditOp = "create"
    anchor: str | None = None
    rendered_text: str
    content_sha256: str = ""
    rationale: str = ""
    #: Which context fields this candidate actually used.  A tier is only
    #: credible if the generator can name what it read.
    context_fields_used: list[str] = Field(default_factory=list)
    #: How the placement was chosen.  Formal T0 uses ``static_public_index``;
    #: compatibility callers may still expose ``legacy_target_anchor``.
    placement_basis: str = "template"
    estimated_files: int = 1
    estimated_lines: int = 1
    estimated_tokens: int = 0
    provenance: dict[str, str] = Field(default_factory=dict)

    @property
    def tier(self) -> Tier:
        return self.generator_tier

    def finalized(self) -> CandidatePayload:
        text = self.rendered_text
        lines = max(1, text.count("\n") + (0 if text.endswith("\n") else 1))
        return self.model_copy(
            update={
                "content_sha256": sha256_text(text),
                "estimated_lines": lines,
                "estimated_tokens": max(1, len(text) // 4),
            }
        )


class ValidatorResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validator: str
    status: ValidationStatus
    required: bool = True
    reason: str = ""
    evidence: dict[str, object] = Field(default_factory=dict)


class CandidateValidation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_id: str
    results: list[ValidatorResult] = Field(default_factory=list)
    validated_at: str = Field(default_factory=utc_now_iso)

    def blocking(self) -> list[ValidatorResult]:
        """Results that forbid selection: required and not ``pass``."""
        return [item for item in self.results if item.required and item.status != "pass"]

    @property
    def selectable(self) -> bool:
        return not self.blocking()

    @property
    def summary(self) -> dict[str, str]:
        return {item.validator: item.status for item in self.results}


class SelectionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy: str
    scores: dict[str, float] = Field(default_factory=dict)
    ranked: list[str] = Field(default_factory=list)
    selected_id: str | None = None
    eliminated: dict[str, str] = Field(default_factory=dict)
    tie_break: str = "candidate_id_ascending"
    notes: list[str] = Field(default_factory=list)


class GenerationManifest(BaseModel):
    """Freeze record for one condition: inputs, candidates, verdict, choice."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = GENERATION_SCHEMA_VERSION
    task_id: str
    snapshot_id: str
    variant_id: str
    condition_id: str
    taxonomy_version: str | None = None
    threat_model_id: str | None = None
    objective: str = "none"
    method_id: str
    primary_mechanism: str | None = None
    surface: dict[str, str] | None = None
    intensity: str | None = None
    dose: dict[str, object] | None = None
    realization_id: str | None = None
    generator_tier: Tier = Field(validation_alias=AliasChoices("generator_tier", "tier"))
    seed: int
    generator_version: str
    clean_tree_sha256: str
    index_sha256: str | None = None
    oracle_view_sha256: str | None = None
    input_hashes: dict[str, str] = Field(default_factory=dict)
    candidate_budget: int = 1
    candidates: list[CandidatePayload] = Field(default_factory=list)
    validations: list[CandidateValidation] = Field(default_factory=list)
    selection: SelectionRecord = Field(default_factory=lambda: SelectionRecord(policy="none"))
    variant_tree_sha256: str | None = None
    remap_sha256: str | None = None
    generated_at: str = Field(default_factory=utc_now_iso)
    notes: list[str] = Field(default_factory=list)

    @property
    def tier(self) -> Tier:
        return self.generator_tier

    def validation_for(self, candidate_id: str) -> CandidateValidation | None:
        for item in self.validations:
            if item.candidate_id == candidate_id:
                return item
        return None


class AdaptationQuery(BaseModel):
    """One T3/T4 optimization query, kept apart from formal repetitions."""

    model_config = ConfigDict(extra="forbid")

    query_id: str
    phase: Literal["adaptation", "evaluation"] = "adaptation"
    candidate_id: str | None = None
    model: str | None = None
    prompt_sha256: str | None = None
    answer_sha256: str | None = None
    tokens: int = 0
    cost_units: float = 0.0
    wall_clock_seconds: float = 0.0
    stop_reason: str | None = None
    recorded_at: str = Field(default_factory=utc_now_iso)


__all__ = [
    "AdaptationQuery",
    "CandidatePayload",
    "CandidateValidation",
    "ConditionSpec",
    "EditOp",
    "ExperimentCell",
    "GENERATION_SCHEMA_VERSION",
    "GenerationManifest",
    "SelectionRecord",
    "VALIDATION_STATUSES",
    "ValidationStatus",
    "ValidatorResult",
]
