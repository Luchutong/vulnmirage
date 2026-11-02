"""Operator registry, orthogonal taxonomy and compatibility-aware selection."""

from __future__ import annotations

from ..errors import UnsupportedTierError
from ..models import AttackGoal, Carrier, ManipulationTier, Mechanism
from .base import ManipulationOperator, OperatorTools
from .m1_direct import AddDirectAuditInstruction, InsertDirectComment, InsertNonExecutableString
from .m2_semantic import (
    FalseDeploymentClaim,
    FalseFixStatusClaim,
    FalsePrivilegeClaim,
    FalseReachabilityClaim,
    SeverityAnchorClaim,
)
from .m3_distributed import DistributedClaimOperator
from .m4_representation import AddRepresentationComment, AddUnreferencedRepresentationHelper
from .m5_decoy import SafeDecoyOperator
from .m6_hybrid import CompositeOperator, children_for_goal

OPERATOR_CLASSES: dict[str, type[ManipulationOperator]] = {
    cls.name: cls
    for cls in (
        AddDirectAuditInstruction,
        InsertDirectComment,
        InsertNonExecutableString,
        FalseFixStatusClaim,
        FalseReachabilityClaim,
        FalseDeploymentClaim,
        FalsePrivilegeClaim,
        SeverityAnchorClaim,
        DistributedClaimOperator,
        AddUnreferencedRepresentationHelper,
        AddRepresentationComment,
        SafeDecoyOperator,
        CompositeOperator,
    )
}

#: Operator -> matrix-facing carrier (the class-level ``carriers`` tuple keeps
#: the legacy template-carrier vocabulary used by context building).
_OPERATOR_CARRIER: dict[str, Carrier] = {
    "AddDirectAuditInstruction": Carrier.MARKDOWN,
    "InsertDirectComment": Carrier.CODE_COMMENT,
    "InsertNonExecutableString": Carrier.STRING_LITERAL,
    "FalseFixStatusClaim": Carrier.MARKDOWN,
    "FalseReachabilityClaim": Carrier.MARKDOWN,
    "FalseDeploymentClaim": Carrier.MARKDOWN,
    "FalsePrivilegeClaim": Carrier.MARKDOWN,
    "SeverityAnchorClaim": Carrier.MARKDOWN,
    "DistributedClaimOperator": Carrier.MARKDOWN,
    "AddUnreferencedRepresentationHelper": Carrier.STRING_LITERAL,
    "AddRepresentationComment": Carrier.CODE_COMMENT,
    "SafeDecoyOperator": Carrier.STRING_LITERAL,
    "CompositeOperator": Carrier.MARKDOWN,
}

GOAL_OPERATOR: dict[ManipulationTier, dict[AttackGoal, str]] = {
    ManipulationTier.M1_DIRECT: {
        AttackGoal.FALSE_NEGATIVE: "AddDirectAuditInstruction",
        AttackGoal.FALSE_POSITIVE: "InsertNonExecutableString",
        AttackGoal.SEVERITY_INFLATION: "AddDirectAuditInstruction",
        AttackGoal.SEVERITY_DOWNGRADE: "AddDirectAuditInstruction",
        AttackGoal.EVIDENCE_CORRUPTION: "InsertDirectComment",
        AttackGoal.VERIFICATION_DIVERSION: "InsertNonExecutableString",
    },
    ManipulationTier.M2_SEMANTIC_CLAIM: {
        AttackGoal.FALSE_NEGATIVE: "FalseFixStatusClaim",
        AttackGoal.FALSE_POSITIVE: "FalseDeploymentClaim",
        AttackGoal.SEVERITY_INFLATION: "SeverityAnchorClaim",
        AttackGoal.SEVERITY_DOWNGRADE: "FalsePrivilegeClaim",
        AttackGoal.EVIDENCE_CORRUPTION: "FalseReachabilityClaim",
        AttackGoal.VERIFICATION_DIVERSION: "FalseReachabilityClaim",
    },
    ManipulationTier.M3_DISTRIBUTED: {
        AttackGoal.FALSE_NEGATIVE: "DistributedClaimOperator",
        AttackGoal.FALSE_POSITIVE: "DistributedClaimOperator",
        AttackGoal.EVIDENCE_CORRUPTION: "DistributedClaimOperator",
        AttackGoal.VERIFICATION_DIVERSION: "DistributedClaimOperator",
    },
    ManipulationTier.M4_PROGRAM_REPRESENTATION: {
        AttackGoal.FALSE_NEGATIVE: "AddUnreferencedRepresentationHelper",
        AttackGoal.FALSE_POSITIVE: "AddRepresentationComment",
        AttackGoal.EVIDENCE_CORRUPTION: "AddUnreferencedRepresentationHelper",
        AttackGoal.VERIFICATION_DIVERSION: "AddUnreferencedRepresentationHelper",
    },
    ManipulationTier.M5_SAFE_DECOY: {
        AttackGoal.FALSE_POSITIVE: "SafeDecoyOperator",
        AttackGoal.VERIFICATION_DIVERSION: "SafeDecoyOperator",
    },
    ManipulationTier.M6_HYBRID_ADAPTIVE: {
        AttackGoal.FALSE_NEGATIVE: "CompositeOperator",
        AttackGoal.FALSE_POSITIVE: "CompositeOperator",
        AttackGoal.EVIDENCE_CORRUPTION: "CompositeOperator",
        AttackGoal.VERIFICATION_DIVERSION: "CompositeOperator",
    },
}

OPERATOR_CANDIDATES: dict[ManipulationTier, dict[AttackGoal, list[str]]] = {
    ManipulationTier.M1_DIRECT: {
        AttackGoal.FALSE_NEGATIVE: ["AddDirectAuditInstruction", "InsertDirectComment", "InsertNonExecutableString"],
        AttackGoal.FALSE_POSITIVE: ["InsertNonExecutableString", "InsertDirectComment", "AddDirectAuditInstruction"],
        AttackGoal.SEVERITY_INFLATION: ["AddDirectAuditInstruction"],
        AttackGoal.SEVERITY_DOWNGRADE: ["AddDirectAuditInstruction"],
        AttackGoal.EVIDENCE_CORRUPTION: ["InsertDirectComment", "InsertNonExecutableString", "AddDirectAuditInstruction"],
        AttackGoal.VERIFICATION_DIVERSION: ["InsertNonExecutableString", "InsertDirectComment", "AddDirectAuditInstruction"],
    },
    ManipulationTier.M2_SEMANTIC_CLAIM: {
        AttackGoal.FALSE_NEGATIVE: ["FalseFixStatusClaim", "FalseReachabilityClaim"],
        AttackGoal.FALSE_POSITIVE: ["FalseDeploymentClaim"],
        AttackGoal.SEVERITY_INFLATION: ["SeverityAnchorClaim"],
        AttackGoal.SEVERITY_DOWNGRADE: ["FalsePrivilegeClaim"],
        AttackGoal.EVIDENCE_CORRUPTION: ["FalseReachabilityClaim", "FalseDeploymentClaim"],
        AttackGoal.VERIFICATION_DIVERSION: ["FalseReachabilityClaim", "FalseDeploymentClaim"],
    },
    ManipulationTier.M3_DISTRIBUTED: {
        goal: ["DistributedClaimOperator"]
        for goal in (
            AttackGoal.FALSE_NEGATIVE,
            AttackGoal.FALSE_POSITIVE,
            AttackGoal.EVIDENCE_CORRUPTION,
            AttackGoal.VERIFICATION_DIVERSION,
        )
    },
    ManipulationTier.M4_PROGRAM_REPRESENTATION: {
        AttackGoal.FALSE_NEGATIVE: ["AddUnreferencedRepresentationHelper", "AddRepresentationComment"],
        AttackGoal.FALSE_POSITIVE: ["AddRepresentationComment"],
        AttackGoal.EVIDENCE_CORRUPTION: ["AddUnreferencedRepresentationHelper", "AddRepresentationComment"],
        AttackGoal.VERIFICATION_DIVERSION: ["AddUnreferencedRepresentationHelper", "AddRepresentationComment"],
    },
    ManipulationTier.M5_SAFE_DECOY: {
        AttackGoal.FALSE_POSITIVE: ["SafeDecoyOperator"],
        AttackGoal.VERIFICATION_DIVERSION: ["SafeDecoyOperator"],
    },
    ManipulationTier.M6_HYBRID_ADAPTIVE: {
        goal: ["CompositeOperator"]
        for goal in (
            AttackGoal.FALSE_NEGATIVE,
            AttackGoal.FALSE_POSITIVE,
            AttackGoal.EVIDENCE_CORRUPTION,
            AttackGoal.VERIFICATION_DIVERSION,
        )
    },
}


def operator_class_for(tier: ManipulationTier, goal: AttackGoal) -> type[ManipulationOperator]:
    mapping = GOAL_OPERATOR.get(tier)
    if mapping is None:
        raise UnsupportedTierError(
            f"tier {tier.value} is not implemented in this build; supported tiers: "
            + ", ".join(sorted(item.value for item in GOAL_OPERATOR)),
            details={"tier": tier.value, "goal": goal.value},
        )
    name = mapping.get(goal)
    if name is None:
        raise UnsupportedTierError(
            f"goal {goal.value} is not implemented for tier {tier.value}",
            details={"tier": tier.value, "goal": goal.value},
        )
    return OPERATOR_CLASSES[name]


def build_operator(
    tier: ManipulationTier,
    goal: AttackGoal,
    tools: OperatorTools,
) -> ManipulationOperator:
    return build_operator_by_name(GOAL_OPERATOR[tier][goal], tools, goal=goal)


def build_operator_by_name(
    name: str,
    tools: OperatorTools,
    *,
    goal: AttackGoal,
) -> ManipulationOperator:
    cls = OPERATOR_CLASSES.get(name)
    if cls is None:
        raise UnsupportedTierError(f"operator {name!r} is not implemented")
    if cls is CompositeOperator:
        return CompositeOperator(tools, children_for_goal(goal, tools))
    return cls(tools)


def operator_carrier(name: str) -> Carrier:
    return _OPERATOR_CARRIER.get(name, Carrier.MARKDOWN)


def operator_candidates_for(tier: ManipulationTier, goal: AttackGoal) -> list[str]:
    return list(OPERATOR_CANDIDATES.get(tier, {}).get(goal, []))


def compatible_operator_candidates(
    tier: ManipulationTier, goal: AttackGoal, matrix
) -> list[str]:
    """Filter operator candidates through the compatibility matrix."""
    output: list[str] = []
    for name in operator_candidates_for(tier, goal):
        cls = OPERATOR_CLASSES[name]
        carrier = operator_carrier(name)
        if matrix.supports(
            mechanism=cls.mechanism,
            strategy_family=cls.strategy_family,
            carrier=carrier,
            goal=goal,
        ):
            output.append(name)
    return output


def supported_tiers() -> list[str]:
    return sorted(item.value for item in GOAL_OPERATOR)


def operator_catalog() -> list[dict[str, object]]:
    return [
        {
            "name": cls.name,
            "tier": cls.tier.value,
            "carriers": list(cls.carriers),
            "strategy_family": cls.strategy_family,
            "mechanism": cls.mechanism.value,
            "presentation": cls.default_presentation.value,
            "supported_goals": [goal.value for goal in cls.supported_goals],
            "distribution": cls.distribution.value,
            "attacker_capability": cls.attacker_capability.value,
            "matrix_carrier": operator_carrier(cls.name).value,
        }
        for cls in sorted(OPERATOR_CLASSES.values(), key=lambda item: item.name)
    ]
