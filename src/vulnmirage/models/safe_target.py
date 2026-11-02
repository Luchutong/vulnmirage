"""Verified-safe targets and per-case evaluation eligibility.

A *safe target* is a code location that has been proven -- by a validator that
actually executed -- not to contain the vulnerability class it appears to have.
Only such targets may be used as false-positive ground truth.  Being absent
from the oracle's ``affected_files`` is **not** evidence of safety and is never
accepted as a substitute.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import AttackGoal


class EvaluationEligibility(BaseModel):
    """Which attack goals a case can legitimately participate in.

    This is computed by the dataset adapter (and re-checked by the generation
    pipeline) so that a case without adjudicated severity can never silently
    enter a severity experiment, and a case without a verified safe target can
    never silently enter a false-positive experiment.
    """

    model_config = ConfigDict(extra="forbid")

    false_negative: bool = True
    false_positive: bool = False
    severity_inflation: bool = False
    severity_downgrade: bool = False
    evidence_corruption: bool = True
    verification_diversion: bool = True
    reasons: dict[str, str] = Field(default_factory=dict)

    @field_validator(
        "false_negative",
        "false_positive",
        "severity_inflation",
        "severity_downgrade",
        "evidence_corruption",
        "verification_diversion",
    )
    @classmethod
    def _bool(cls, value: bool) -> bool:
        return bool(value)

    def allows(self, goal: AttackGoal | str) -> bool:
        value = goal.value if isinstance(goal, AttackGoal) else str(goal)
        mapping = {
            AttackGoal.FALSE_NEGATIVE.value: self.false_negative,
            AttackGoal.FALSE_POSITIVE.value: self.false_positive,
            AttackGoal.SEVERITY_INFLATION.value: self.severity_inflation,
            AttackGoal.SEVERITY_DOWNGRADE.value: self.severity_downgrade,
            AttackGoal.EVIDENCE_CORRUPTION.value: self.evidence_corruption,
            AttackGoal.VERIFICATION_DIVERSION.value: self.verification_diversion,
        }
        return bool(mapping.get(value, False))

    def enabled_goals(self) -> list[str]:
        return [goal.value for goal in AttackGoal if self.allows(goal)]

    def blocked_goals(self) -> dict[str, str]:
        return {
            goal.value: self.reasons.get(goal.value, "not eligible for this attack goal")
            for goal in AttackGoal
            if not self.allows(goal)
        }


class EligibilityReport(BaseModel):
    """Eligibility decisions for one case, with machine-readable reasons."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    eligibility: EvaluationEligibility
    safe_target_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _sorted(self) -> "EligibilityReport":
        self.safe_target_ids = sorted(set(self.safe_target_ids))
        return self
