"""Benchmark instance manifest and clean/benign/adversarial variant groups."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..paths import normalize_relpath
from .enums import AuditDifficulty, ManipulationTier, VariantKind
from .repository import RepositoryRef

_SPLIT_RE = re.compile(r"^(dev|test)-[a-z0-9][a-z0-9-]*$")


class BenchmarkInstance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: str
    pair_id: str
    schema_version: str
    variant_kind: VariantKind
    oracle_ref: str
    repository: RepositoryRef
    audit_difficulty: AuditDifficulty
    manipulation_tier: ManipulationTier
    manipulation_ref: str | None = None
    evidence_contract_ref: str | None = None
    task_file: str
    patch_file: str | None = None
    repository_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generation_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    random_seed: int
    release_split: str
    #: Structural control grouping (clean/benign/adversarial triple).
    group_id: str | None = None
    candidate_id: str | None = None
    generation_method: str | None = None
    #: ``benign`` or ``truthful_security`` for control variants.
    control_kind: str | None = None
    #: Single attack target (P0-2).  ``eligible_target_ids`` is the candidate
    #: set the generator considered and is never used for scoring.
    target_id: str | None = None
    target_kind: str | None = None
    eligible_target_ids: list[str] = Field(default_factory=list)
    #: Defense condition is an execution condition, not an instance property;
    #: these fields exist only for diagnostics of generated controls.
    defense_id_at_generation: str | None = None

    @field_validator("instance_id", "pair_id", "oracle_ref")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("task_file")
    @classmethod
    def _task_file(cls, value: str) -> str:
        return normalize_relpath(value)

    @field_validator("patch_file")
    @classmethod
    def _patch_file(cls, value: str | None) -> str | None:
        return normalize_relpath(value) if value else value

    @field_validator("release_split")
    @classmethod
    def _split(cls, value: str) -> str:
        if not _SPLIT_RE.match(value):
            raise ValueError("release_split must look like dev-known or test-heldout-repository")
        return value

    @model_validator(mode="after")
    def _variant(self) -> "BenchmarkInstance":
        if self.variant_kind == VariantKind.CLEAN:
            if self.patch_file is not None:
                raise ValueError("clean instances must not have a patch")
            if self.manipulation_tier != ManipulationTier.M0_CLEAN:
                raise ValueError("clean instances must be M0")
            if self.manipulation_ref is not None:
                raise ValueError("clean instances must not reference a manipulation")
        elif self.variant_kind == VariantKind.BENIGN_CONTROL:
            if self.patch_file is None:
                raise ValueError("benign control instances require a patch")
            if self.manipulation_tier == ManipulationTier.M0_CLEAN:
                raise ValueError("benign control instances mirror an adversarial tier")
            if self.manipulation_ref is not None:
                raise ValueError(
                    "benign control instances must not reference an adversarial manipulation"
                )
        else:
            if self.patch_file is None:
                raise ValueError("adversarial instances require a patch")
            if self.manipulation_tier == ManipulationTier.M0_CLEAN:
                raise ValueError("adversarial instances cannot be M0")
            if self.manipulation_ref is None:
                raise ValueError("adversarial instances require a manipulation_ref")
        if self.group_id is not None and not self.group_id.strip():
            raise ValueError("group_id must not be blank")
        return self


class VariantGroup(BaseModel):
    """One clean/benign/adversarial triple sharing carrier and placement."""

    model_config = ConfigDict(extra="forbid")

    group_id: str
    oracle_id: str
    pair_id: str
    clean_instance_id: str
    adversarial_instance_id: str
    benign_instance_id: str | None = None
    truthful_security_instance_id: str | None = None
    attack_goal: str | None = None
    mechanism: str | None = None
    carrier: str | None = None
    presentation: str | None = None
    distribution: str | None = None
    candidate_id: str | None = None
    target_id: str | None = None
    target_kind: str | None = None
    eligible_target_ids: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @field_validator("group_id", "oracle_id", "pair_id", "clean_instance_id", "adversarial_instance_id")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @model_validator(mode="after")
    def _distinct(self) -> "VariantGroup":
        ids = {self.clean_instance_id, self.adversarial_instance_id}
        expected = 2
        for optional in (self.benign_instance_id, self.truthful_security_instance_id):
            if optional:
                ids.add(optional)
                expected += 1
        if len(ids) != expected:
            raise ValueError("group instance ids must be distinct")
        return self


class InstanceGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    groups: list[VariantGroup] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique(self) -> "InstanceGroup":
        ids = [group.group_id for group in self.groups]
        if len(ids) != len(set(ids)):
            raise ValueError("group_id values must be unique")
        return self

    def by_adversarial(self, instance_id: str) -> VariantGroup | None:
        for group in self.groups:
            if group.adversarial_instance_id == instance_id:
                return group
        return None
