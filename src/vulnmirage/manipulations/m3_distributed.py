"""M3 distributed semantic manipulation with an explicit claim graph."""

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
    ClaimEdge,
    ClaimGraph,
    ClaimNode,
    CodeLocation,
    Distribution,
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


def _line_of(content: str, needle: str) -> int:
    target = needle.strip().split("\n")[0]
    for number, line in enumerate(content.split("\n"), start=1):
        if line.strip() == target.strip() or (target and target in line):
            return number
    return 1


class DistributedClaimOperator(ManipulationOperator):
    name = "DistributedClaimOperator"
    tier = ManipulationTier.M3_DISTRIBUTED
    strategy_family = "distributed_security"
    carriers = ("markdown", "comment")
    mechanism = Mechanism.SEMANTIC_MISINFORMATION
    default_presentation = Presentation.ARCHITECTURE_NOTE
    distribution = Distribution.CROSS_FILE
    expected_effect = (
        "A mutually-reinforcing false claim is distributed across repository policy, "
        "architecture documentation and a code comment."
    )

    def supports(self, context: GenerationContext) -> bool:
        return True

    def plan(self, repo_root: Path, oracle, spec, rng: random.Random) -> ChangePlan:
        goal = spec.attack_goal
        safe_loc: CodeLocation | None = None
        contracts = []
        if goal == AttackGoal.FALSE_POSITIVE:
            contracts = self.validated_safe_targets(spec, code_only=True)
            contract = contracts[0]
            context = self.safe_target_context(
                oracle, repo_root, contract, spec, "markdown"
            )
            target_file = contract.file
            safe_loc = contract.location
        else:
            from ..generation.targets import select_target_from_spec

            vulnerability, path = select_target_from_spec(oracle, spec)
            target_file = path.critical_operation.file
            context = build_context(
                oracle,
                repo_root,
                attack_goal=goal,
                carrier="markdown",
                target_file=target_file,
                target_vulnerability_id=vulnerability.vulnerability_id,
                path_id=path.path_id,
            )
        if not is_code(target_file):
            raise ValueError("distributed comment target is not code")

        payloads: list[PayloadProvenance] = []
        payload_ids: list[str] = []
        files: list[PlannedFile] = []
        node_specs: list[tuple[str, str, str, str]] = []

        security_text, prov, pid = self.render_payload(
            strategy_family="distributed_security",
            goal=goal,
            carrier="markdown",
            context=context,
            rng=rng,
        )
        payloads.append(prov)
        payload_ids.append(pid)
        security_file = "SECURITY.md"
        security_plan = plan_append(
            repo_root,
            security_file,
            security_text,
            carrier="markdown",
            description="distributed claim: policy node",
        )
        files.append(security_plan)
        node_specs.append(("n-security", security_file, security_text, "markdown"))

        architecture_text, prov, pid = self.render_payload(
            strategy_family="distributed_architecture",
            goal=goal,
            carrier="markdown",
            context=context,
            rng=rng,
        )
        payloads.append(prov)
        payload_ids.append(pid)
        architecture_file = "docs/architecture.md"
        architecture_plan = plan_append(
            repo_root,
            architecture_file,
            architecture_text,
            carrier="markdown",
            description="distributed claim: architecture node",
        )
        files.append(architecture_plan)
        node_specs.append(("n-architecture", architecture_file, architecture_text, "markdown"))

        comment_text, prov, pid = self.render_payload(
            strategy_family="distributed_comment",
            goal=goal,
            carrier="comment",
            context=context,
            rng=rng,
        )
        payloads.append(prov)
        payload_ids.append(pid)
        comment_plan = plan_comment_insertion(
            repo_root,
            target_file,
            comment_text,
            carrier="comment",
            description="distributed claim: code comment node",
        )
        files.append(comment_plan)
        node_specs.append(("n-comment", target_file, comment_text, "comment"))

        nodes = [
            ClaimNode(
                node_id=node_id,
                file=file,
                line=_line_of(next(item.content for item in files if item.path == file), text),
                claim=text.strip().split("\n")[0][:300],
                carrier=carrier,
            )
            for node_id, file, text, carrier in node_specs
        ]
        graph = ClaimGraph(
            nodes=nodes,
            edges=[
                ClaimEdge(
                    source="n-security",
                    target="n-architecture",
                    relation="references",
                    rationale="SECURITY.md points to the guard in the architecture document.",
                ),
                ClaimEdge(
                    source="n-architecture",
                    target="n-comment",
                    relation="supports",
                    rationale="The architecture note justifies the code comment.",
                ),
                ClaimEdge(
                    source="n-comment",
                    target="n-security",
                    relation="supports",
                    rationale="The code comment reinforces the closed-audit status.",
                ),
            ],
        )
        return ChangePlan(
            operator_name=self.name,
            tier=self.tier,
            files=files,
            allowed_paths=sorted({item.path for item in files}),
            payloads=payloads,
            claim_graph=graph,
            safe_targets=contracts,
            target_safe_locations=[safe_loc] if safe_loc else [],
            metadata={
                "target_file": target_file,
                "payload_ids": payload_ids,
                "target_kind": "safe" if safe_loc else "vulnerable",
                "claim_graph_nodes": len(nodes),
                "safe_target_ids": [item.safe_target_id for item in contracts],
            },
        )
