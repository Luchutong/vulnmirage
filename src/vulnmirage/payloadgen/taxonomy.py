"""Canonical attack taxonomy models.

The taxonomy describes *what attack is being evaluated*.  Generator capability
tiers, candidate budgets and model calls are provenance and deliberately do not
appear in these models.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

TAXONOMY_VERSION = "vm-atk-1.0"

Objective = Literal[
    "O-FN",
    "O-FP",
    "O-SEV-D",
    "O-SEV-I",
    "O-EV",
    "O-SCOPE",
    "O-AVAIL",
]
MechanismClass = Literal["M1", "M2", "M3", "M4", "M5"]
SurfaceArtifact = Literal[
    "S-DOC",
    "S-RULE",
    "S-COMMENT",
    "S-CODE",
    "S-CONFIG",
    "S-TEST",
    "S-META",
    "S-GENERATED",
    "S-TOOL",
]
SurfaceZone = Literal[
    "Z-AUTO",
    "Z-ROOT",
    "Z-TARGET",
    "Z-ENTRY",
    "Z-SINK",
    "Z-PATH",
    "Z-PERIPHERAL",
]
Intensity = Literal["I0", "I1", "I2", "I3", "I4"]
DoseDirectness = Literal["implicit", "explicit"]

_PRIMARY_RE = re.compile(r"^M[1-5]\.[1-9][0-9]*$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AttackSurface(_Strict):
    artifact: SurfaceArtifact
    zone: SurfaceZone

    @property
    def identity(self) -> str:
        return f"{self.artifact}-{self.zone}"


class MechanismSpec(_Strict):
    class_id: MechanismClass = Field(alias="class")
    primary: str
    modifiers: list[str] = Field(default_factory=list)

    @field_validator("primary")
    @classmethod
    def _primary_id(cls, value: str) -> str:
        if not _PRIMARY_RE.fullmatch(value):
            raise ValueError("primary mechanism must look like M2.1")
        return value

    @model_validator(mode="after")
    def _primary_belongs_to_class(self) -> MechanismSpec:
        if not self.primary.startswith(self.class_id + "."):
            raise ValueError("primary mechanism does not belong to mechanism class")
        return self


class CausalHypothesis(_Strict):
    exposure: str = Field(min_length=1)
    uptake: str = Field(min_length=1)
    behavior: str = Field(min_length=1)
    outcome: str = Field(min_length=1)
    alternative_explanations: list[str] = Field(default_factory=list)


class IntensityProfile(_Strict):
    description: str = Field(min_length=1)
    max_claims: int = Field(default=1, ge=1, le=16)
    max_supporting_evidence: int = Field(default=0, ge=0, le=32)


class RealizationDose(_Strict):
    """Auditable dose supplied by one concrete realization.

    These counts are author-declared structural properties of the payload, not a
    post-hoc estimate of how persuasive it was. Catalog validation checks them
    against both the method-specific profile and the generic I0-I4 ordering.
    """

    claim_count: int = Field(ge=1, le=16)
    supporting_evidence_count: int = Field(ge=0, le=32)
    directness: DoseDirectness
    reinforcement_count: int = Field(default=0, ge=0, le=16)


class EvaluationContract(_Strict):
    primary_metric: str = Field(min_length=1)
    intermediate_metrics: list[str] = Field(default_factory=list)


class AttackMethod(_Strict):
    taxonomy_version: str = TAXONOMY_VERSION
    method_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    mechanism: MechanismSpec
    supported_objectives: list[Objective] = Field(min_length=1)
    causal_hypothesis: CausalHypothesis
    supported_surfaces: list[AttackSurface] = Field(min_length=1)
    intensity_profiles: dict[Intensity, IntensityProfile]
    evaluation_contract: EvaluationContract
    source_urls: list[str] = Field(default_factory=list)

    @field_validator("taxonomy_version")
    @classmethod
    def _taxonomy_version(cls, value: str) -> str:
        if value != TAXONOMY_VERSION:
            raise ValueError(f"unsupported taxonomy_version {value!r}")
        return value

    @field_validator("supported_objectives")
    @classmethod
    def _unique_objectives(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("supported_objectives contains duplicates")
        return value

    @model_validator(mode="after")
    def _complete_intensity_ladder(self) -> AttackMethod:
        expected = {"I0", "I1", "I2", "I3", "I4"}
        if set(self.intensity_profiles) != expected:
            raise ValueError("every method must define the complete I0-I4 intensity ladder")
        previous_claims = 0
        previous_evidence = 0
        for intensity in ("I0", "I1", "I2", "I3", "I4"):
            profile = self.intensity_profiles[intensity]  # type: ignore[index]
            if profile.max_claims < previous_claims:
                raise ValueError("intensity max_claims must be monotone from I0 to I4")
            if profile.max_supporting_evidence < previous_evidence:
                raise ValueError(
                    "intensity max_supporting_evidence must be monotone from I0 to I4"
                )
            previous_claims = profile.max_claims
            previous_evidence = profile.max_supporting_evidence
        return self


class MutationConstraints(_Strict):
    max_files_changed: int = Field(default=1, ge=1, le=16)
    executable_behavior_must_remain_equivalent: bool = True


class ThreatModel(_Strict):
    schema_version: str = "1.0"
    taxonomy_version: str = TAXONOMY_VERSION
    threat_model_id: str = Field(min_length=1)
    attacker_controls: list[str] = Field(min_length=1)
    oracle_access: list[str] = Field(default_factory=list)
    feedback_access: Literal["none", "surrogate", "victim"] = "none"
    mutation_constraints: MutationConstraints = Field(default_factory=MutationConstraints)
    forbidden_capabilities: list[str] = Field(default_factory=list)

    @field_validator("taxonomy_version")
    @classmethod
    def _taxonomy_version(cls, value: str) -> str:
        if value != TAXONOMY_VERSION:
            raise ValueError(f"unsupported taxonomy_version {value!r}")
        return value


class AttackConditionIdentity(_Strict):
    """Taxonomy identity frozen before generation or victim execution."""

    taxonomy_version: str = TAXONOMY_VERSION
    threat_model_id: str
    objective: Objective
    method_id: str
    primary_mechanism: str
    surface: AttackSurface
    intensity: Intensity
    realization_id: str


__all__ = [
    "AttackConditionIdentity",
    "AttackMethod",
    "AttackSurface",
    "CausalHypothesis",
    "DoseDirectness",
    "EvaluationContract",
    "Intensity",
    "IntensityProfile",
    "MechanismClass",
    "MechanismSpec",
    "MutationConstraints",
    "Objective",
    "RealizationDose",
    "SurfaceArtifact",
    "SurfaceZone",
    "TAXONOMY_VERSION",
    "ThreatModel",
]
