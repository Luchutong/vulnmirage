"""Validation result/report models and report hashing."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..hashing import canonical_json, sha256_text
from .enums import CheckStatus, ValidationLevel


class ValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_name: str
    status: CheckStatus
    started_at: str
    duration_seconds: float = Field(ge=0.0)
    command: list[str] | None = None
    exit_code: int | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("check_name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("check_name must not be empty")
        return value


class ValidationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: str
    results: list[ValidationResult]
    ground_truth_preserved: bool
    release_eligible: bool
    validation_level: str
    report_sha256: str = Field(default="", pattern=r"^[0-9a-f]{0,64}$")

    def compute_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"report_sha256"})
        return sha256_text(canonical_json(payload))

    def with_digest(self) -> "ValidationReport":
        return self.model_copy(update={"report_sha256": self.compute_sha256()})

    @field_validator("validation_level")
    @classmethod
    def _level(cls, value: str) -> str:
        allowed = {item.value for item in ValidationLevel}
        if value not in allowed:
            raise ValueError(f"validation_level must be one of {sorted(allowed)}")
        return value

    def result(self, name: str) -> ValidationResult | None:
        for item in self.results:
            if item.check_name == name:
                return item
        return None
