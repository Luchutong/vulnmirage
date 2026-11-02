"""Dataset adapter interface (schema v2).

The adapter contract is intentionally staged so that a new dataset can be added
without touching the generation pipeline:

* :meth:`DatasetAdapter.inspect` reports what the source contains;
* :meth:`DatasetAdapter.iter_raw_records` streams raw cases;
* :meth:`DatasetAdapter.validate_source` returns machine-readable issues;
* :meth:`DatasetAdapter.normalize` produces canonical oracles;
* :meth:`DatasetAdapter.describe` reports capabilities.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..models import AttackGoal, CanonicalVulnerabilityOracle


class DatasetCapabilities(BaseModel):
    """What a dataset can support, derived from its records."""

    model_config = ConfigDict(extra="forbid")

    dataset_name: str
    languages: list[str] = Field(default_factory=list)
    has_severity: bool = False
    has_adjudicated_severity: bool = False
    has_safe_targets: bool = False
    has_validated_safe_targets: bool = False
    has_fix_commits: bool = False
    has_poc_commands: bool = False
    has_regression_commands: bool = False
    has_split_groups: bool = False
    has_validation_level: bool = False
    has_attack_plans: bool = False
    supported_goals: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    def supports_goal(self, goal: AttackGoal | str) -> bool:
        value = goal.value if isinstance(goal, AttackGoal) else str(goal)
        return value in self.supported_goals


class DatasetIssue(BaseModel):
    """A structured import issue (never a bare string)."""

    model_config = ConfigDict(extra="forbid")

    code: str
    severity: Literal["error", "warning"] = "error"
    message: str
    case_id: str | None = None
    path: str | None = None
    line: int | None = Field(default=None, ge=1)
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("code", "message")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @property
    def blocking(self) -> bool:
        return self.severity == "error"


class DatasetInspection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_name: str
    manifest_path: str
    cases_path: str
    case_count: int = 0
    split_group_count: int = 0
    repository_count: int = 0
    sample_case_ids: list[str] = Field(default_factory=list)
    capabilities: DatasetCapabilities
    issues: list[DatasetIssue] = Field(default_factory=list)

    @model_validator(mode="after")
    def _summary(self) -> "DatasetInspection":
        if self.case_count < 0:
            raise ValueError("case_count must be non-negative")
        if self.split_group_count > self.case_count:
            raise ValueError("split_group_count cannot exceed case_count")
        return self


class RawRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    index: int = Field(ge=0)
    case_id: str | None = None
    payload: dict[str, Any]

    @field_validator("payload")
    @classmethod
    def _payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("raw record payload must be a mapping")
        return value


class NormalizationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_name: str
    oracles: list[CanonicalVulnerabilityOracle] = Field(default_factory=list)
    issues: list[DatasetIssue] = Field(default_factory=list)
    eligibility: dict[str, Any] = Field(default_factory=dict)

    @property
    def errors(self) -> list[DatasetIssue]:
        return [item for item in self.issues if item.blocking]

    @property
    def warnings(self) -> list[DatasetIssue]:
        return [item for item in self.issues if not item.blocking]

    @property
    def ok(self) -> bool:
        return not self.errors and bool(self.oracles)


class DatasetAdapter(ABC):
    name: str

    @abstractmethod
    def inspect(self) -> DatasetInspection:
        ...

    @abstractmethod
    def iter_raw_records(self) -> Iterator[RawRecord]:
        ...

    @abstractmethod
    def normalize(self) -> NormalizationResult:
        ...

    @abstractmethod
    def validate_source(self) -> list[DatasetIssue]:
        ...

    @abstractmethod
    def describe(self) -> DatasetCapabilities:
        ...

    @property
    @abstractmethod
    def manifest_path(self) -> Path:
        ...
