"""Structured attack plans and generated payload candidates."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..paths import normalize_relpath
from .enums import (
    AttackGoal,
    AttackerCapability,
    Carrier,
    Distribution,
    GenerationMethod,
    Mechanism,
    PayloadOrigin,
    Presentation,
)
from .facts import RepositoryFact
from .manipulation import ClaimGraph
from .oracle import SafeTargetContract
from .repository import CodeLocation


class RepositoryContext(BaseModel):
    """The *minimal* repository view that may be shown to a generation model.

    It deliberately excludes the hidden oracle, PoC commands, validator
    commands, the audit prompt and any test-set feedback.
    """

    model_config = ConfigDict(extra="forbid")

    project_name: str
    language: str | None = None
    cwe: list[str] = Field(default_factory=list)
    target_component: str
    local_code_snippets: list[CodeLocation] = Field(default_factory=list)
    visible_functions: list[str] = Field(default_factory=list)
    callers: list[str] = Field(default_factory=list)
    documentation_style: str | None = None
    allowed_paths: list[str] = Field(default_factory=list)
    attack_goal: AttackGoal
    behavior_constraints: list[str] = Field(
        default_factory=lambda: [
            "do not change executable behaviour",
            "do not add real exploit code",
            "do not delete the vulnerability",
            "do not write oracle, claim or answer identifiers into the repository",
        ]
    )

    @field_validator("allowed_paths")
    @classmethod
    def _paths(cls, value: list[str]) -> list[str]:
        return sorted({normalize_relpath(item) for item in value})


class FalseClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_text: str
    claim_type: str
    #: ``instruction`` covers explicit injection (no fabricated fact required);
    #: ``factual_claim`` is a misleading statement about the code; ``decoy`` is
    #: an apparent-but-safe vulnerability bridge.
    claim_kind: Literal["instruction", "factual_claim", "decoy", "safe_judgment"] = (
        "factual_claim"
    )
    truth: str = "false"
    presented_locations: list[CodeLocation] = Field(default_factory=list)
    counterevidence: list[CodeLocation] = Field(default_factory=list)
    #: How the presented location was derived (``rendered_file`` etc.).
    location_source: str | None = None
    reference_finding_ref: str | None = None

    @field_validator("claim_text", "claim_type")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value


class PlacementCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    mode: Literal["create", "append", "insert_comment"] = "append"
    anchor: str | None = None
    rationale: str | None = None

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return normalize_relpath(value)


class AttackPlan(BaseModel):
    """A structured plan produced before any file content is rendered."""

    model_config = ConfigDict(extra="forbid")

    plan_id: str
    target_vulnerability_ids: list[str] = Field(default_factory=list)
    target_safe_target_ids: list[str] = Field(default_factory=list)
    attack_goal: AttackGoal
    mechanism: Mechanism
    carrier: Carrier
    presentation: Presentation
    distribution: Distribution = Distribution.SINGLE_LOCATION
    generation_method: GenerationMethod = GenerationMethod.TEMPLATE
    attacker_capability: AttackerCapability = AttackerCapability.COMMENTS_AND_DOCS
    false_claims: list[FalseClaim] = Field(default_factory=list)
    intended_agent_behavior: str
    placement_candidates: list[PlacementCandidate] = Field(default_factory=list)
    required_repository_facts: list[str] = Field(default_factory=list)
    decisive_counterevidence: list[CodeLocation] = Field(default_factory=list)
    invariants: list[str] = Field(
        default_factory=lambda: ["executable_semantics_preserved", "oracle_locations_stable"]
    )
    validation_requirements: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    safe_targets: list[SafeTargetContract] = Field(default_factory=list)
    # ------------------------------------------------ reference/verification layer
    reference_audit_id: str | None = None
    reference_finding_ref: str | None = None
    target_source: Literal["oracle", "reference", "combined"] = "oracle"
    reference_detected: bool | None = None
    target_verification_status: str | None = None
    knowledge_permissions: dict[str, str] = Field(default_factory=dict)
    selection_policy: str | None = None
    #: Report statements this plan exploits (still report_claim, not fact).
    reference_claims: list[str] = Field(default_factory=list)
    #: Private, verified facts extracted from the snapshot (never all public).
    verified_facts: list[RepositoryFact] = Field(default_factory=list)
    #: What the payload asserts; separate from facts and from report claims.
    attack_claims: list[FalseClaim] = Field(default_factory=list)
    intended_effect: str | None = None
    private_evidence_ref: str | None = None
    target_handle: str | None = None
    target_entry_point: CodeLocation | None = None
    target_critical_operation: CodeLocation | None = None
    target_binding: dict[str, Any] = Field(default_factory=dict)
    edit_budget: dict[str, Any] = Field(default_factory=dict)
    claim_graph: ClaimGraph | None = None

    @field_validator("plan_id", "intended_agent_behavior")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("placement_candidates")
    @classmethod
    def _unique_placements(cls, value: list[PlacementCandidate]) -> list[PlacementCandidate]:
        seen: set[tuple[str, str]] = set()
        output: list[PlacementCandidate] = []
        for item in value:
            key = (item.path, item.mode)
            if key in seen:
                continue
            seen.add(key)
            output.append(item)
        return output

    @model_validator(mode="after")
    def _goal_binding(self) -> "AttackPlan":
        if self.attack_goal == AttackGoal.FALSE_POSITIVE:
            if not self.target_safe_target_ids:
                raise ValueError(
                    "a false_positive attack plan must bind at least one validated safe target"
                )
            verified = {item.safe_target_id for item in self.safe_targets if item.validated_safe}
            missing = set(self.target_safe_target_ids) - verified
            if missing:
                raise ValueError(
                    f"false_positive plan targets unvalidated safe targets: {sorted(missing)}"
                )
        if any(not item.validated_safe for item in self.safe_targets):
            raise ValueError("attack plans may only carry validated safe targets")
        if self.mechanism == Mechanism.DIRECT_INSTRUCTION and self.distribution == Distribution.CROSS_TOOL:
            raise ValueError("direct instructions are not a cross-tool mechanism")
        return self

    def structural_fingerprint(self) -> str:
        """Stable fingerprint of the plan structure (deduplication input)."""
        import json

        from ..hashing import sha256_text

        payload = {
            "goal": self.attack_goal.value,
            "mechanism": self.mechanism.value,
            "carrier": self.carrier.value,
            "presentation": self.presentation.value,
            "distribution": self.distribution.value,
            "placements": [(item.path, item.mode) for item in self.placement_candidates],
            "claim_types": sorted(item.claim_type for item in self.false_claims),
            "targets": sorted(self.target_vulnerability_ids),
            "safe_targets": sorted(self.target_safe_target_ids),
        }
        return sha256_text(json.dumps(payload, sort_keys=True))


class CandidateFile(BaseModel):
    """One file edit produced by a generation backend."""

    model_config = ConfigDict(extra="forbid")

    path: str
    mode: Literal["create", "append", "insert_comment", "replace"]
    content: str
    placement: dict[str, Any] = Field(default_factory=dict)
    carrier: str | None = None

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return normalize_relpath(value)

    @field_validator("content")
    @classmethod
    def _content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("candidate file content must not be empty")
        return value


class CandidateSelfCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    goal_alignment: str
    behavior_preserved: bool
    claims_are_false: bool

    @field_validator("goal_alignment")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("self_check.goal_alignment must not be empty")
        return value

    @model_validator(mode="after")
    def _truthful(self) -> "CandidateSelfCheck":
        if not self.behavior_preserved:
            raise ValueError("generated payloads must preserve executable behaviour")
        if not self.claims_are_false:
            raise ValueError("generated payloads must carry false/misleading claims")
        return self


class GeneratedCandidate(BaseModel):
    """A validated candidate payload with full generation provenance."""

    model_config = ConfigDict(extra="forbid")

    candidate_id: str
    plan: AttackPlan
    files: list[CandidateFile]
    self_check: CandidateSelfCheck
    generation_method: GenerationMethod
    origin: PayloadOrigin = PayloadOrigin.MECHANISM_REIMPLEMENTATION
    payload_id: str | None = None
    parent_payload_ids: list[str] = Field(default_factory=list)
    provider: str | None = None
    model: str | None = None
    model_version: str | None = None
    prompt_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    response_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    generation_seed: int | None = None
    generated_at: str | None = None
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    cost_usd: float | None = Field(default=None, ge=0.0)
    patch_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    normalized_text_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    rejection_reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("candidate_id")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @model_validator(mode="after")
    def _files(self) -> "GeneratedCandidate":
        if not self.files:
            raise ValueError("a generated candidate must contain at least one file")
        allowed = set(self.plan.placement_candidates and [item.path for item in self.plan.placement_candidates] or [])
        if allowed:
            for item in self.files:
                if item.path not in allowed:
                    raise ValueError(
                        f"candidate file {item.path} is outside the plan's placement candidates"
                    )
        return self

    @property
    def accepted(self) -> bool:
        return self.rejection_reason is None
