"""Strict compatibility matrix for (mechanism, strategy, carrier, goal) tuples.

A payload that is declared compatible with every attack goal but whose content
does not change with the goal is a measurement artefact, not an attack.
Generation therefore refuses any combination absent from
``payloads/compatibility.yaml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..errors import ConfigError, GenerationError
from ..models import (
    AttackGoal,
    Carrier,
    Mechanism,
    SafeTargetProofMethod,
)


class CompatibilityError(GenerationError):
    """Raised when a requested combination is not in the compatibility matrix."""


class CompatibilityEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mechanism: Mechanism
    strategy_family: str
    carriers: list[Carrier]
    supported_goals: list[AttackGoal]
    supported_languages: list[str] = Field(default_factory=lambda: ["*"])
    required_context: list[str] = Field(default_factory=list)
    required_oracle_fields: list[str] = Field(default_factory=list)
    required_safe_target: bool = False
    required_validators: bool = False
    notes: str | None = None

    @field_validator("strategy_family")
    @classmethod
    def _family(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("strategy_family must not be empty")
        return value

    @field_validator("carriers", "supported_goals")
    @classmethod
    def _nonempty(cls, value: list) -> list:
        if not value:
            raise ValueError("must not be empty")
        return list(dict.fromkeys(value))

    @field_validator("supported_languages")
    @classmethod
    def _languages(cls, value: list[str]) -> list[str]:
        cleaned = sorted({item.strip().lower() for item in value if item.strip()})
        return cleaned or ["*"]

    @model_validator(mode="after")
    def _fp_binding(self) -> "CompatibilityEntry":
        if (
            AttackGoal.FALSE_POSITIVE in self.supported_goals
            and self.mechanism != Mechanism.SAFE_DECOY
            and not self.required_safe_target
        ):
            raise ValueError(
                "entries that support false_positive must require a validated safe target"
            )
        if self.required_safe_target and AttackGoal.FALSE_POSITIVE not in self.supported_goals:
            raise ValueError("required_safe_target is only meaningful for false_positive entries")
        if self.required_validators and not (
            self.required_safe_target or self.mechanism == Mechanism.SAFE_DECOY
        ):
            raise ValueError("required_validators requires a safe target or a safe decoy")
        if self.mechanism == Mechanism.SAFE_DECOY and set(self.supported_goals) - {
            AttackGoal.FALSE_POSITIVE,
            AttackGoal.VERIFICATION_DIVERSION,
        }:
            raise ValueError("safe decoys may only target false_positive or verification_diversion")
        return self


class MechanismRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_goals: list[AttackGoal]
    allowed_carriers: list[Carrier]
    requires_false_claim_text: bool = True

    @model_validator(mode="after")
    def _nonempty(self) -> "MechanismRule":
        if not self.allowed_goals or not self.allowed_carriers:
            raise ValueError("mechanism rules require allowed goals and carriers")
        return self


class CompatibilityMatrix(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    matrix_version: str
    mechanism_rules: dict[Mechanism, MechanismRule]
    entries: list[CompatibilityEntry]
    source_path: str | None = None

    @model_validator(mode="after")
    def _unique(self) -> "CompatibilityMatrix":
        if self.schema_version != "1.0":
            raise ValueError("compatibility matrix schema_version must be 1.0")
        keys = [(entry.strategy_family, entry.mechanism.value) for entry in self.entries]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate (strategy_family, mechanism) entries")
        for entry in self.entries:
            rule = self.mechanism_rules.get(entry.mechanism)
            if rule is None:
                raise ValueError(f"no mechanism rule for {entry.mechanism.value}")
            extra_goals = set(entry.supported_goals) - set(rule.allowed_goals)
            if extra_goals:
                raise ValueError(
                    f"{entry.strategy_family} declares goals outside its mechanism rule: "
                    f"{sorted(goal.value for goal in extra_goals)}"
                )
            extra_carriers = set(entry.carriers) - set(rule.allowed_carriers)
            if extra_carriers:
                raise ValueError(
                    f"{entry.strategy_family} declares carriers outside its mechanism rule: "
                    f"{sorted(carrier.value for carrier in extra_carriers)}"
                )
        return self

    # ------------------------------------------------------------------ lookup
    def entry(self, mechanism: Mechanism, strategy_family: str) -> CompatibilityEntry | None:
        for entry in self.entries:
            if entry.mechanism == mechanism and entry.strategy_family == strategy_family:
                return entry
        return None

    def supports(
        self,
        *,
        mechanism: Mechanism,
        strategy_family: str,
        carrier: str | Carrier,
        goal: AttackGoal,
        language: str | None = None,
    ) -> bool:
        try:
            self.require(
                mechanism=mechanism,
                strategy_family=strategy_family,
                carrier=carrier,
                goal=goal,
                language=language,
            )
            return True
        except CompatibilityError:
            return False

    def require(
        self,
        *,
        mechanism: Mechanism,
        strategy_family: str,
        carrier: str | Carrier,
        goal: AttackGoal,
        language: str | None = None,
    ) -> CompatibilityEntry:
        carrier_value = carrier.value if isinstance(carrier, Carrier) else str(carrier)
        entry = self.entry(mechanism, strategy_family)
        if entry is None:
            raise CompatibilityError(
                "no compatibility entry for this strategy family and mechanism",
                details={
                    "mechanism": mechanism.value,
                    "strategy_family": strategy_family,
                    "available": sorted(
                        f"{item.mechanism.value}:{item.strategy_family}" for item in self.entries
                    ),
                },
            )
        if goal not in entry.supported_goals:
            raise CompatibilityError(
                "attack goal is not supported by this strategy",
                details={
                    "mechanism": mechanism.value,
                    "strategy_family": strategy_family,
                    "goal": goal.value,
                    "supported_goals": [item.value for item in entry.supported_goals],
                },
            )
        if carrier_value not in {item.value for item in entry.carriers}:
            raise CompatibilityError(
                "carrier is not supported by this strategy",
                details={
                    "strategy_family": strategy_family,
                    "carrier": carrier_value,
                    "supported_carriers": [item.value for item in entry.carriers],
                },
            )
        if language and "*" not in entry.supported_languages:
            if language.lower() not in entry.supported_languages:
                raise CompatibilityError(
                    "language is not supported by this strategy",
                    details={
                        "strategy_family": strategy_family,
                        "language": language,
                        "supported_languages": entry.supported_languages,
                    },
                )
        rule = self.mechanism_rules[mechanism]
        if goal not in rule.allowed_goals:
            raise CompatibilityError(
                "mechanism does not allow this attack goal",
                details={
                    "mechanism": mechanism.value,
                    "goal": goal.value,
                    "allowed_goals": [item.value for item in rule.allowed_goals],
                },
            )
        return entry

    def requirements(
        self, *, mechanism: Mechanism, strategy_family: str, goal: AttackGoal
    ) -> CompatibilityEntry:
        entry = self.entry(mechanism, strategy_family)
        if entry is None:
            raise CompatibilityError(
                "no compatibility entry",
                details={"mechanism": mechanism.value, "strategy_family": strategy_family},
            )
        return entry

    def check_binding(
        self,
        *,
        mechanism: Mechanism,
        strategy_family: str,
        goal: AttackGoal,
        has_validated_safe_target: bool,
        has_safe_decoy: bool,
        has_severity: bool,
        has_validators: bool,
        carrier: str,
        language: str | None,
    ) -> None:
        """Check runtime binding requirements in addition to static compatibility."""
        entry = self.require(
            mechanism=mechanism,
            strategy_family=strategy_family,
            carrier=carrier,
            goal=goal,
            language=language,
        )
        if goal == AttackGoal.FALSE_POSITIVE:
            if entry.required_safe_target and not has_validated_safe_target:
                raise CompatibilityError(
                    "false_positive generation requires a validated safe target",
                    details={
                        "strategy_family": strategy_family,
                        "mechanism": mechanism.value,
                        "reason": "no_validated_safe_target",
                    },
                )
            if mechanism == Mechanism.SAFE_DECOY and not has_safe_decoy:
                raise CompatibilityError(
                    "safe decoy generation requires an executable safety validator",
                    details={"reason": "no_safe_decoy_validator"},
                )
        if entry.required_validators and not has_validators:
            raise CompatibilityError(
                "this strategy requires executable validators",
                details={"strategy_family": strategy_family},
            )
        if goal in {AttackGoal.SEVERITY_INFLATION, AttackGoal.SEVERITY_DOWNGRADE}:
            if "severity" in entry.required_oracle_fields and not has_severity:
                raise CompatibilityError(
                    "severity attacks require an adjudicated oracle severity",
                    details={"reason": "severity_missing", "goal": goal.value},
                )


def load_compatibility_matrix(path: Path) -> CompatibilityMatrix:
    path = Path(path)
    if not path.is_file():
        raise ConfigError("compatibility matrix not found", details={"path": str(path)})
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError("invalid compatibility matrix YAML", details={"error": str(exc)}) from exc
    if not isinstance(raw, dict):
        raise ConfigError("compatibility matrix root must be a mapping")
    try:
        matrix = CompatibilityMatrix.model_validate(raw)
    except Exception as exc:
        raise ConfigError(
            f"invalid compatibility matrix: {exc}", details={"path": str(path)}
        ) from exc
    return matrix.model_copy(update={"source_path": str(path)})


def matrix_summary(matrix: CompatibilityMatrix) -> dict[str, Any]:
    return {
        "matrix_version": matrix.matrix_version,
        "entry_count": len(matrix.entries),
        "mechanisms": sorted({entry.mechanism.value for entry in matrix.entries}),
        "strategy_families": sorted({entry.strategy_family for entry in matrix.entries}),
        "requires_safe_target": sorted(
            entry.strategy_family for entry in matrix.entries if entry.required_safe_target
        ),
        "source": matrix.source_path,
    }
