"""M2 semantic-claim operators (natural repository prose, no direct overrides)."""

from __future__ import annotations

import random
from pathlib import Path

from ..generation.context import (
    GenerationContext,
    build_context,
    is_code,
)
from ..models import (
    AttackGoal,
    ManipulationTier,
    Mechanism,
    PayloadProvenance,
    Presentation,
)
from .base import (
    ChangePlan,
    ManipulationOperator,
    PlannedFile,
    plan_append,
    plan_comment_insertion,
)


class SemanticClaimOperator(ManipulationOperator):
    """Common behavior for M2 claim carriers."""

    tier = ManipulationTier.M2_SEMANTIC_CLAIM
    carriers = ("markdown",)
    claim_file = "SECURITY.md"
    include_comment = False
    mechanism = Mechanism.SEMANTIC_MISINFORMATION
    default_presentation = Presentation.MAINTENANCE_NOTE
    expected_effect = "A natural-looking project claim misleads the auditor's security conclusion."

    def supports(self, context: GenerationContext) -> bool:
        return True

    def _contexts(self, oracle, repo_root: Path, spec):
        goal = spec.attack_goal
        if goal == AttackGoal.FALSE_POSITIVE:
            contracts = self.validated_safe_targets(
                spec, code_only=self.include_comment
            )
            contract = contracts[0]
            context = self.safe_target_context(
                oracle, repo_root, contract, spec, "markdown"
            )
            return context, contract.file, contract.location, contracts
        from ..generation.targets import select_target_from_spec

        vulnerability, path = select_target_from_spec(oracle, spec)
        target = path.critical_operation.file
        context = build_context(
            oracle,
            repo_root,
            attack_goal=goal,
            carrier="markdown",
            target_file=target,
            target_vulnerability_id=vulnerability.vulnerability_id,
            path_id=path.path_id,
        )
        return context, target, None, []

    def plan(self, repo_root: Path, oracle, spec, rng: random.Random) -> ChangePlan:
        context, target_file, safe_loc, contracts = self._contexts(oracle, repo_root, spec)
        files: list[PlannedFile] = []
        payloads: list[PayloadProvenance] = []
        payload_ids: list[str] = []

        text, provenance, payload_id = self.render_payload(
            strategy_family=self.strategy_family,
            goal=spec.attack_goal,
            carrier="markdown",
            context=context,
            rng=rng,
        )
        payloads.append(provenance)
        payload_ids.append(payload_id)
        doc = plan_append(
            repo_root,
            self.claim_file,
            text,
            carrier="markdown",
            description=f"{self.name} document claim",
        )
        files.append(doc)

        if self.include_comment and is_code(target_file):
            comment_text, comment_prov, comment_id = self.render_payload(
                strategy_family=self.strategy_family,
                goal=spec.attack_goal,
                carrier="comment",
                context=context,
                rng=rng,
            )
            payloads.append(comment_prov)
            payload_ids.append(comment_id)
            files.append(
                plan_comment_insertion(
                    repo_root,
                    target_file,
                    comment_text,
                    carrier="comment",
                    description=f"{self.name} code comment",
                )
            )

        allowed = sorted({item.path for item in files})
        return ChangePlan(
            operator_name=self.name,
            tier=self.tier,
            files=files,
            allowed_paths=allowed,
            payloads=payloads,
            safe_targets=contracts,
            target_safe_locations=[safe_loc] if safe_loc else [],
            metadata={
                "target_file": target_file,
                "payload_ids": payload_ids,
                "target_kind": "safe" if safe_loc else "vulnerable",
                "claim_file": self.claim_file,
                "claim_type": self.strategy_family,
                "safe_target_ids": [item.safe_target_id for item in contracts],
            },
        )


class FalseFixStatusClaim(SemanticClaimOperator):
    name = "FalseFixStatusClaim"
    strategy_family = "false_fix_status"
    claim_file = "SECURITY.md"
    default_presentation = Presentation.MAINTENANCE_NOTE
    expected_effect = "Documentation falsely states the target vulnerability has already been fixed."


class FalseReachabilityClaim(SemanticClaimOperator):
    name = "FalseReachabilityClaim"
    strategy_family = "false_reachability"
    carriers = ("markdown", "comment")
    claim_file = "docs/architecture.md"
    include_comment = True
    default_presentation = Presentation.ARCHITECTURE_NOTE
    expected_effect = "Documentation and a comment falsely claim the dangerous path is gated or unreachable."


class FalseDeploymentClaim(SemanticClaimOperator):
    name = "FalseDeploymentClaim"
    strategy_family = "false_deployment"
    claim_file = "docs/deployment.md"
    default_presentation = Presentation.SECURITY_NOTICE
    expected_effect = "Documentation falsely claims a safe component is publicly exposed and exploitable."


class FalsePrivilegeClaim(SemanticClaimOperator):
    name = "FalsePrivilegeClaim"
    strategy_family = "false_privilege"
    carriers = ("markdown", "comment")
    claim_file = "SECURITY.md"
    include_comment = True
    default_presentation = Presentation.SECURITY_NOTICE
    expected_effect = "Documentation falsely claims exploitation requires a trusted administrative role."


class SeverityAnchorClaim(SemanticClaimOperator):
    name = "SeverityAnchorClaim"
    strategy_family = "severity_anchor"
    claim_file = "docs/severity_policy.md"
    default_presentation = Presentation.AUDIT_RECORD
    expected_effect = "A fabricated review record anchors the auditor's severity judgement."
