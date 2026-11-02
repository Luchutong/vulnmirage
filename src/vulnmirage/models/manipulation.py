"""Manipulation provenance, orthogonal specs, claim graphs and decoy records."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..paths import normalize_relpath
from .enums import (
    AttackGoal,
    AttackerCapability,
    Carrier,
    Distribution,
    GenerationMethod,
    ManipulationTier,
    Mechanism,
    PayloadOrigin,
    Presentation,
)
from .oracle import SafeTargetContract, ValidatorCommand
from .repository import CodeLocation


class LiteratureSource(BaseModel):
    """A published technique that a payload borrows from.

    Only the *mechanism* is reproduced unless the original text and licence
    permit verbatim redistribution; see :class:`PayloadProvenance`.
    """

    model_config = ConfigDict(extra="forbid")

    paper_title: str
    paper_url: str | None = None
    borrowed_component: str
    original_carrier: str | None = None
    original_attack_goal: str | None = None

    @field_validator("paper_title", "borrowed_component")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value


class AdaptationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verbatim_copy: bool = False
    repository_specific: bool = False
    changes: list[str] = Field(default_factory=list)
    adaptation_notes: str | None = None

    @model_validator(mode="after")
    def _verbatim(self) -> "AdaptationRecord":
        if self.verbatim_copy and self.changes:
            raise ValueError("a verbatim copy cannot also list adaptations")
        return self


class PayloadProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload_id: str
    origin: PayloadOrigin
    source_title: str | None = None
    source_url: str | None = None
    source_license: str | None = None
    parent_payload_ids: list[str] = Field(default_factory=list)
    generator_name: str | None = None
    generator_version: str | None = None
    prompt_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    response_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    random_seed: int | None = None
    generated_at: str | None = None
    provider: str | None = None
    model: str | None = None
    model_version: str | None = None
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    cost_usd: float | None = Field(default=None, ge=0.0)
    literature_sources: list[LiteratureSource] = Field(default_factory=list)
    adaptation: AdaptationRecord | None = None

    @model_validator(mode="after")
    def _verbatim_license(self) -> "PayloadProvenance":
        if self.origin == PayloadOrigin.PUBLISHED_VERBATIM:
            if not self.source_url or not self.source_license:
                raise ValueError(
                    "published_verbatim payloads require source_url and an explicit source_license"
                )
        if self.origin == PayloadOrigin.ADAPTIVE_GENERATED and not self.parent_payload_ids:
            raise ValueError("adaptive payloads must record their parent payload ids")
        return self


class ClaimNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: str
    file: str
    line: int = Field(ge=1)
    claim: str
    carrier: str

    @field_validator("file")
    @classmethod
    def _file(cls, value: str) -> str:
        return normalize_relpath(value)


class ClaimEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    relation: str = "supports"
    rationale: str | None = None

    @field_validator("relation")
    @classmethod
    def _relation(cls, value: str) -> str:
        if value not in {"references", "supports", "contradicts"}:
            raise ValueError("relation must be references, supports or contradicts")
        return value


class ClaimGraph(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nodes: list[ClaimNode] = Field(default_factory=list)
    edges: list[ClaimEdge] = Field(default_factory=list)

    @model_validator(mode="after")
    def _graph(self) -> "ClaimGraph":
        ids = [node.node_id for node in self.nodes]
        if len(ids) != len(set(ids)):
            raise ValueError("claim graph node_ids must be unique")
        known = set(ids)
        for edge in self.edges:
            if edge.source not in known or edge.target not in known:
                raise ValueError("claim graph edge references an unknown node")
        if len(self.nodes) >= 2 and not self.edges:
            raise ValueError("a distributed claim graph needs at least one edge")
        return self


class ManipulationSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manipulation_id: str
    #: Legacy tier label.  Tiers are *not* a single increasing difficulty axis.
    designed_tier: ManipulationTier
    attack_goal: AttackGoal
    strategy_family: str
    #: Orthogonal taxonomy (schema v2).
    mechanism: Mechanism | None = None
    carrier: str | None = None
    presentation: Presentation | None = None
    distribution: Distribution = Distribution.SINGLE_LOCATION
    generation_method: GenerationMethod = GenerationMethod.TEMPLATE
    attacker_capability: AttackerCapability = AttackerCapability.COMMENTS_AND_DOCS
    carriers: list[str]
    operator_names: list[str] = Field(default_factory=list)
    payloads: list[PayloadProvenance] = Field(default_factory=list)
    target_vulnerability_ids: list[str] = Field(default_factory=list)
    target_safe_target_ids: list[str] = Field(default_factory=list)
    target_decoy_ids: list[str] = Field(default_factory=list)
    files_touched: list[str] = Field(default_factory=list)
    evidence_contract_ref: str | None = None
    constraints: dict[str, Any] = Field(default_factory=dict)
    expected_effect: str
    claim_graph: ClaimGraph | None = None
    #: Validated safe targets bound to this manipulation (false-positive only).
    safe_targets: list[SafeTargetContract] = Field(default_factory=list)

    @field_validator("manipulation_id", "strategy_family", "expected_effect")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("files_touched", "carriers")
    @classmethod
    def _paths(cls, value: list[str]) -> list[str]:
        return sorted({normalize_relpath(item) for item in value})

    @model_validator(mode="after")
    def _tier_consistency(self) -> "ManipulationSpec":
        if self.designed_tier == ManipulationTier.M0_CLEAN:
            if self.operator_names or self.payloads or self.files_touched:
                raise ValueError("M0 clean specs must not contain operators, payloads or touched files")
        else:
            if not self.operator_names:
                raise ValueError("adversarial manipulation specs require at least one operator")
        if self.carrier is None and self.carriers:
            self.carrier = Carrier(_carrier_from_legacy(self.carriers[0])).value
        if self.attack_goal == AttackGoal.FALSE_POSITIVE and self.designed_tier != ManipulationTier.M0_CLEAN:
            known = {item.safe_target_id for item in self.safe_targets}
            for target_id in self.target_safe_target_ids:
                if known and target_id not in known:
                    raise ValueError(
                        f"target_safe_target_ids references unknown safe target {target_id}"
                    )
        if any(not item.validated_safe for item in self.safe_targets):
            raise ValueError(
                "a manipulation may only bind validated safe targets; set validated_safe=true "
                "after the validator executed"
            )
        return self


_LEGACY_CARRIER_MAP = {
    "markdown": Carrier.MARKDOWN.value,
    "comment": Carrier.CODE_COMMENT.value,
    "string": Carrier.STRING_LITERAL.value,
    "source_identifier": Carrier.SOURCE_IDENTIFIER.value,
    "configuration": Carrier.CONFIGURATION.value,
    "test": Carrier.TEST.value,
    "example_code": Carrier.EXAMPLE_CODE.value,
}


def _carrier_from_legacy(value: str) -> str:
    return _LEGACY_CARRIER_MAP.get(str(value).strip().lower(), Carrier.MARKDOWN.value)


class DecoyRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decoy_id: str
    apparent_vulnerability_type: str
    apparent_entry_point: CodeLocation | None = None
    apparent_trace: list[CodeLocation] = Field(default_factory=list)
    apparent_critical_operation: CodeLocation
    false_bridge: CodeLocation
    safety_argument: str
    safety_validator_commands: list[ValidatorCommand]
    verified_safe: bool = False
    validation_log_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("decoy_id", "apparent_vulnerability_type", "safety_argument")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @model_validator(mode="after")
    def _safety(self) -> "DecoyRecord":
        if not self.safety_validator_commands:
            raise ValueError("a safe decoy requires an automated safety validator")
        if self.verified_safe is True and not self.safety_validator_commands:
            raise ValueError("verified_safe requires validation commands")
        if self.apparent_critical_operation.same_span(self.false_bridge):
            raise ValueError("false_bridge must be distinct from the apparent critical operation")
        return self
