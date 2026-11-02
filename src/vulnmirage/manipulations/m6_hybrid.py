"""M6 composite operator: combine verified children and revalidate the result."""

from __future__ import annotations

import random
from pathlib import Path

from ..errors import GenerationError
from ..generation.context import build_context
from ..models import AttackGoal, Distribution, ManipulationTier, Mechanism, Presentation
from .base import ChangePlan, ManipulationOperator, OperatorTools
from .m2_semantic import (
    FalseDeploymentClaim,
    FalseFixStatusClaim,
    FalsePrivilegeClaim,
    FalseReachabilityClaim,
    SeverityAnchorClaim,
)
from .m4_representation import AddRepresentationComment, AddUnreferencedRepresentationHelper


def children_for_goal(goal: AttackGoal, tools: OperatorTools) -> list[ManipulationOperator]:
    # A composite is bounded by its children's compatibility: a false-positive
    # composite pairs the deployment claim with the representation *comment*
    # (which supports false positives), never with the uncalled helper.
    if goal == AttackGoal.FALSE_POSITIVE:
        return [FalseDeploymentClaim(tools), AddRepresentationComment(tools)]
    claim_cls = {
        AttackGoal.FALSE_NEGATIVE: FalseFixStatusClaim,
        AttackGoal.SEVERITY_INFLATION: SeverityAnchorClaim,
        AttackGoal.SEVERITY_DOWNGRADE: FalsePrivilegeClaim,
        AttackGoal.EVIDENCE_CORRUPTION: FalseReachabilityClaim,
        AttackGoal.VERIFICATION_DIVERSION: FalseReachabilityClaim,
    }[goal]
    return [claim_cls(tools), AddUnreferencedRepresentationHelper(tools)]


class CompositeOperator(ManipulationOperator):
    name = "CompositeOperator"
    tier = ManipulationTier.M6_HYBRID_ADAPTIVE
    strategy_family = "hybrid"
    carriers = ("markdown", "comment", "string")
    mechanism = Mechanism.SEMANTIC_MISINFORMATION
    default_presentation = Presentation.ARCHITECTURE_NOTE
    distribution = Distribution.CROSS_FILE
    expected_effect = (
        "A semantic claim and an unreferenced normalization representation reinforce "
        "each other; all checks are re-run on the combined result."
    )

    def __init__(self, tools: OperatorTools, children: list[ManipulationOperator]) -> None:
        super().__init__(tools)
        if len(children) < 2:
            raise ValueError("a composite operator requires at least two children")
        names = [child.name for child in children]
        if len(names) != len(set(names)):
            raise ValueError("composite children must be distinct")
        self.children = children
        self._last_child_plans: list[tuple[ManipulationOperator, ChangePlan]] = []

    def supports(self, context) -> bool:
        return all(child.supports(context) for child in self.children)

    def payload_texts(self) -> list[str]:
        texts = list(super().payload_texts())
        for child in self.children:
            texts.extend(child.payload_texts())
        return texts

    def plan(self, repo_root: Path, oracle, spec, rng: random.Random) -> ChangePlan:
        child_plans: list[tuple[ManipulationOperator, ChangePlan]] = []
        occupied: dict[str, str] = {}
        files = []
        allowed: set[str] = set()
        payloads = []
        decoys = []
        safe_locations = []
        safe_targets = []
        claim_graph = None
        child_metadata = []
        for child in self.children:
            plan = child.plan(repo_root, oracle, spec, rng)
            child_plans.append((child, plan))
            for planned in plan.files:
                if planned.path in occupied:
                    raise GenerationError(
                        "composite children write to conflicting paths",
                        details={
                            "path": planned.path,
                            "first": occupied[planned.path],
                            "second": child.name,
                        },
                    )
                occupied[planned.path] = child.name
                files.append(planned)
            for path in plan.allowed_paths:
                if path in allowed and path not in occupied:
                    raise GenerationError(
                        "composite children have overlapping allowed paths",
                        details={"path": path, "second": child.name},
                    )
                allowed.add(path)
            payloads.extend(plan.payloads)
            decoys.extend(plan.decoys)
            safe_locations.extend(plan.target_safe_locations)
            safe_targets.extend(plan.safe_targets)
            claim_graph = claim_graph or plan.claim_graph
            child_metadata.append(
                {
                    "operator": child.name,
                    "files": [item.path for item in plan.files],
                    "payload_ids": [item.payload_id for item in plan.payloads],
                    "claim_graph": bool(plan.claim_graph),
                    "decoys": [item.decoy_id for item in plan.decoys],
                }
            )
        self._last_child_plans = child_plans
        return ChangePlan(
            operator_name=self.name,
            tier=self.tier,
            files=files,
            allowed_paths=sorted(allowed),
            payloads=payloads,
            decoys=decoys,
            claim_graph=claim_graph,
            safe_targets=safe_targets,
            target_safe_locations=safe_locations,
            metadata={
                "children": child_metadata,
                "revalidation": "all checks re-run on the combined worktree",
                "strategy": "semantic_claim+representation",
                "safe_target_ids": [item.safe_target_id for item in safe_targets],
            },
        )

    def validate_local(self, repo_root: Path, plan: ChangePlan):
        checks = super().validate_local(repo_root, plan)
        for child, child_plan in self._last_child_plans:
            checks.extend(child.validate_local(repo_root, child_plan))
        return checks
