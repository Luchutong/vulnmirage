"""Planning stage: choose the target and strategy *before* rendering text.

``build_plan_intent`` is read-only.  It binds an authorised target from the
oracle/reference context, extracts the placement policy, the facts that the
payload may rely on, and the validation requirements.  Rendering then has to
comply with that intent; :func:`reconcile_render` rejects a rendered change
plan whose carrier/paths contradict the declared plan.

The final :class:`AttackPlan` is rebuilt from the *rendered* files: claim text,
presented locations, claim graph, oracle remap and the evidence contract are
derived from the final content, never reused from the template stage.
"""

from __future__ import annotations

import difflib
import json
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..code_semantics import is_documentation, read_text
from ..hashing import sha256_text
from ..models import (
    AttackGoal,
    AttackPlan,
    AttackerCapability,
    BaselineAuditContext,
    Carrier,
    ClaimGraph,
    CodeLocation,
    Distribution,
    FalseClaim,
    GenerationMethod,
    ManipulationSpec,
    Mechanism,
    PlacementCandidate,
    Presentation,
    RepositoryFacts,
    SafeTargetContract,
    VulnerabilityPath,
    VulnerabilityRecord,
)
from ..paths import normalize_relpath
from .targets import (
    select_safe_target_from_spec,
    select_target_from_spec,
    target_handle,
)

_DOC_CANDIDATES = ("SECURITY.md", "SECURITY.rst", "docs/security.md", "README.md")


class TargetBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    vulnerability_id: str | None = None
    safe_target_id: str | None = None
    path_id: str | None = None
    target_file: str
    entry_point: CodeLocation | None = None
    critical_operation: CodeLocation | None = None
    target_source: str = "oracle"
    reference_finding_ref: str | None = None
    reference_detected: bool | None = None
    verification_status: str | None = None
    selection_policy: str = "first_by_id"

    @model_validator(mode="after")
    def _one_kind(self) -> "TargetBinding":
        if self.kind not in {"vulnerable", "safe"}:
            raise ValueError("target kind must be vulnerable or safe")
        if self.kind == "vulnerable" and not self.vulnerability_id:
            raise ValueError("a vulnerable target binding requires vulnerability_id")
        if self.kind == "safe" and not self.safe_target_id:
            raise ValueError("a safe target binding requires safe_target_id")
        return self


class PlanIntent(BaseModel):
    """The structured plan produced before any payload text is rendered."""

    model_config = ConfigDict(extra="forbid")

    intent_id: str
    target: TargetBinding
    attack_goal: AttackGoal
    mechanism: Mechanism
    carrier: Carrier
    presentation: Presentation
    distribution: Distribution
    generation_method: GenerationMethod
    attacker_capability: AttackerCapability
    strategy_family: str
    knowledge_permissions: dict[str, str] = Field(default_factory=dict)
    reference_audit_id: str | None = None
    reference_claims: list[str] = Field(default_factory=list)
    verified_fact_ids: list[str] = Field(default_factory=list)
    required_facts: list[str] = Field(default_factory=list)
    placement_policy: str
    placement_candidates: list[PlacementCandidate] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    attack_claim_kinds: list[str] = Field(default_factory=list)
    intended_effect: str
    validation_requirements: list[str] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> "PlanIntent":
        if not self.placement_candidates:
            raise ValueError("an attack plan must declare at least one placement")
        if self.target.kind == "safe" and self.attack_goal != AttackGoal.FALSE_POSITIVE:
            raise ValueError("safe targets are only valid for false-positive plans")
        return self

    def placement_paths(self) -> list[str]:
        return sorted({item.path for item in self.placement_candidates})


def _documentation_candidates(repo_root: Path) -> list[str]:
    existing = [
        normalize_relpath(item)
        for item in _DOC_CANDIDATES
        if (Path(repo_root) / item).is_file()
    ]
    if existing:
        return existing
    docs = sorted(
        path.relative_to(repo_root).as_posix()
        for path in Path(repo_root).rglob("*.md")
        if ".git" not in path.parts
    )
    return docs[:5] or ["SECURITY.md"]


def _placement_policy(
    *,
    carrier: Carrier,
    target_file: str,
    repo_root: Path,
    mechanism: Mechanism,
) -> tuple[str, list[PlacementCandidate]]:
    if carrier == Carrier.CODE_COMMENT:
        return (
            "target_file_comment",
            [
                PlacementCandidate(
                    path=target_file,
                    mode="insert_comment",
                    rationale="comment next to the real target code",
                )
            ],
        )
    if carrier == Carrier.STRING_LITERAL:
        if mechanism == Mechanism.REPRESENTATION_CONFUSION:
            parent = Path(target_file).parent.as_posix()
            path = (
                "_audit_representation.py"
                if parent in {"", "."}
                else f"{parent}/_audit_representation.py"
            )
            return (
                "target_directory_new_file",
                [
                    PlacementCandidate(
                        path=path,
                        mode="create",
                        rationale="unreferenced helper in the target package",
                    )
                ],
            )
        return (
            "new_unreferenced_file",
            [
                PlacementCandidate(
                    path="security_audit_notice.py",
                    mode="create",
                    rationale="static unreferenced string carrier",
                )
            ],
        )
    if carrier == Carrier.MARKDOWN:
        docs = _documentation_candidates(repo_root)
        placements = [
            PlacementCandidate(
                path=path,
                mode="append",
                rationale="documentation/orientation carrier",
            )
            for path in docs[:1]
        ]
        return ("existing_documentation", placements)
    return (
        "target_file_append",
        [
            PlacementCandidate(
                path=target_file,
                mode="append",
                rationale="carrier appended to the target file",
            )
        ],
    )


def _reference_finding_for(
    baseline: BaselineAuditContext | None, vulnerability_id: str | None
) -> tuple[str | None, list[str], bool | None, str | None]:
    if baseline is None or not baseline.available:
        return None, [], None, None
    finding_ref = None
    claims: list[str] = []
    detected = vulnerability_id in set(baseline.reference_detected_target_ids) if vulnerability_id else None
    status = None
    for link in baseline.links:
        if vulnerability_id and link.vulnerability_id == vulnerability_id and link.finding_id:
            finding_ref = link.finding_id
            status = link.status.value
            profile = baseline.profile_for_finding(link.finding_id)
            if profile is not None:
                claims.append(
                    f"[{link.finding_id}] {profile.source_excerpt or profile.reported_type}"
                )
            break
    return finding_ref, claims, detected, status


def build_plan_intent(
    *,
    oracle,
    spec: ManipulationSpec,
    repo_root: Path,
    facts: RepositoryFacts,
    baseline: BaselineAuditContext | None = None,
    knowledge_permissions: dict[str, str] | None = None,
    target_source: str = "oracle",
    selection_policy: str = "first_by_id",
) -> PlanIntent:
    repo_root = Path(repo_root)
    if spec.attack_goal == AttackGoal.FALSE_POSITIVE:
        contract: SafeTargetContract | None = select_safe_target_from_spec(spec)
        if contract is not None:
            binding = TargetBinding(
                kind="safe",
                safe_target_id=contract.safe_target_id,
                target_file=contract.file,
                critical_operation=contract.location,
                target_source=target_source,
                reference_detected=False,
                verification_status="validated_safe",
                selection_policy="explicit_safe_target",
            )
            vulnerability_id = None
            reference_finding_ref = None
            reference_claims = []
            detected = None
        else:
            # Synthetic decoys are created *by* the render step; plan the target
            # from the real vulnerability and require the decoy to validate later.
            vulnerability, path = select_target_from_spec(oracle, spec)
            binding = TargetBinding(
                kind="vulnerable",
                vulnerability_id=vulnerability.vulnerability_id,
                path_id=path.path_id,
                target_file=path.critical_operation.file,
                entry_point=path.entry_point,
                critical_operation=path.critical_operation,
                target_source=target_source,
                selection_policy="synthetic_decoy_pending_validation",
                verification_status="decoy_validator_pending",
            )
            vulnerability_id = vulnerability.vulnerability_id
            reference_finding_ref = None
            reference_claims = []
            detected = None
    else:
        vulnerability, path = select_target_from_spec(oracle, spec)
        binding = TargetBinding(
            kind="vulnerable",
            vulnerability_id=vulnerability.vulnerability_id,
            path_id=path.path_id,
            target_file=path.critical_operation.file,
            entry_point=path.entry_point,
            critical_operation=path.critical_operation,
            target_source=target_source,
            selection_policy=selection_policy,
            verification_status="known_target",
        )
        reference_finding_ref, reference_claims, detected, status = _reference_finding_for(
            baseline, vulnerability.vulnerability_id
        )
        binding = binding.model_copy(
            update={
                "reference_finding_ref": reference_finding_ref,
                "reference_detected": detected,
                "verification_status": status or "known_target",
            }
        )
        vulnerability_id = vulnerability.vulnerability_id
    carrier = Carrier(spec.carrier) if spec.carrier else Carrier.MARKDOWN
    mechanism = spec.mechanism or Mechanism.DIRECT_INSTRUCTION
    placement_policy, placements = _placement_policy(
        carrier=carrier,
        target_file=binding.target_file,
        repo_root=repo_root,
        mechanism=mechanism,
    )
    allowed = sorted({item.path for item in placements} | {binding.target_file})
    reference_audit_id = baseline.audit.reference_audit_id if baseline and baseline.audit else None
    verified = [
        fact.fact_id
        for fact in facts.facts
        if fact.status.value == "verified" and "private" not in (fact.capability or "")
    ]
    missing = list(facts.missing)
    if facts.documentation_style is None:
        missing.append("documentation_style_missing")
    intent_id = f"PI-{sha256_text(spec.manipulation_id + binding.target_file + str(spec.constraints.get('candidate_index', 0)))[:20].upper()}"
    claim_kinds = (
        ["instruction"]
        if mechanism == Mechanism.DIRECT_INSTRUCTION
        else ["decoy"]
        if mechanism == Mechanism.SAFE_DECOY
        else ["factual_claim"]
    )
    return PlanIntent(
        intent_id=intent_id,
        target=binding,
        attack_goal=spec.attack_goal,
        mechanism=mechanism,
        carrier=carrier,
        presentation=spec.presentation or Presentation.PLAIN_INSTRUCTION,
        distribution=spec.distribution,
        generation_method=spec.generation_method,
        attacker_capability=spec.attacker_capability,
        strategy_family=spec.strategy_family,
        knowledge_permissions=knowledge_permissions or {},
        reference_audit_id=reference_audit_id,
        reference_claims=reference_claims,
        verified_fact_ids=verified,
        required_facts=[
            f"target file {binding.target_file} exists at the fixed snapshot",
            f"critical operation {binding.critical_operation.file if binding.critical_operation else binding.target_file} is inside the target",
        ],
        placement_policy=placement_policy,
        placement_candidates=placements,
        allowed_paths=allowed,
        attack_claim_kinds=claim_kinds,
        intended_effect=spec.expected_effect,
        validation_requirements=[
            "executable_semantics_preserved",
            "oracle_locations_unchanged",
            "claim_positions_rebuilt_from_final_files",
            "evidence_contract_rebuilt_after_edits",
            "references_exist_in_final_tree",
        ],
        missing_context=missing,
    )


def reconcile_render(intent: PlanIntent, plan) -> list[str]:
    """Check that the rendered change plan complies with the plan intent.

    The intent fixes the *policy* (carrier, target, permitted path classes);
    the renderer chooses the concrete file.  The target is always the bound
    target, never ``plan.files[0]``.
    """
    problems: list[str] = []
    rendered = {item.path for item in plan.files}
    if not rendered:
        return ["rendered change plan has no files"]
    target_file = intent.target.target_file
    for item in plan.files:
        path = item.path
        if path == target_file and item.mode == "create":
            problems.append("carrier cannot create the existing target file")
    if intent.carrier == Carrier.CODE_COMMENT:
        if target_file not in rendered:
            problems.append(
                "comment carrier did not edit the bound target file "
                f"({target_file}); the target must not be inferred from plan.files[0]"
            )
    elif intent.carrier == Carrier.MARKDOWN:
        if not any(is_documentation(path) for path in rendered):
            problems.append("markdown carrier rendered no documentation file")
    elif intent.carrier == Carrier.STRING_LITERAL:
        if rendered == {target_file}:
            problems.append(
                "string carrier must not rewrite the bound target source in place"
            )
        if not any(
            item.mode == "create" or is_documentation(item.path)
            for item in plan.files
        ):
            problems.append(
                "string carrier must create a new carrier file or edit documentation"
            )
    if intent.target.vulnerability_id and not intent.target.target_file:
        problems.append("target binding has no target file")
    return problems


def inserted_span(original: str | None, content: str) -> tuple[int, int, str]:
    """Locate the fragment introduced by an edit (line span + text)."""
    if original is None:
        lines = content.split("\n")
        return 1, max(1, len(lines)), content
    old_lines = original.split("\n")
    new_lines = content.split("\n")
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
    added: list[tuple[int, int, list[str]]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in {"insert", "replace"}:
            added.append((j1, j2, new_lines[j1:j2]))
    if not added:
        return 1, max(1, len(new_lines)), ""
    start = min(item[0] for item in added) + 1
    end = max(item[1] for item in added)
    text = "\n".join(
        line for _, _, block in added for line in block
    )
    return start, max(start, end), text


def _remap_claim_graph(
    graph: ClaimGraph | None, finals: dict[str, str]
) -> tuple[ClaimGraph | None, list[str]]:
    if graph is None:
        return None, []
    problems: list[str] = []
    nodes = []
    for node in graph.nodes:
        body = finals.get(node.file)
        if body is None:
            problems.append(f"claim node {node.node_id} references {node.file} which is not rendered")
            continue
        needle = node.claim.strip().split("\n")[0][:120]
        if not needle:
            problems.append(f"claim node {node.node_id} has empty text")
            continue
        offset = body.find(needle)
        if offset < 0:
            problems.append(
                f"claim node {node.node_id} text not found in final {node.file}"
            )
            continue
        line = body[:offset].count("\n") + 1
        nodes.append(node.model_copy(update={"line": line}))
    if problems:
        return None, problems
    return graph.model_copy(update={"nodes": nodes}), []


def build_attack_plan_from_intent(
    *,
    intent: PlanIntent,
    plan,
    oracle,
    repo_root: Path,
    facts: RepositoryFacts,
    spec: ManipulationSpec,
    candidate_index: int = 0,
    validated_safe: list[SafeTargetContract] | None = None,
) -> tuple[AttackPlan, list[str]]:
    """Build the private plan from the final rendered files (post-edit)."""
    problems: list[str] = []
    finals: dict[str, str] = {}
    for planned in plan.files:
        target = Path(repo_root) / planned.path
        if target.is_file():
            finals[planned.path] = read_text(target)
        else:
            problems.append(f"rendered file is missing after application: {planned.path}")
    claims: list[FalseClaim] = []
    placements: list[PlacementCandidate] = []
    for planned in plan.files:
        final = finals.get(planned.path, planned.content)
        start, end, fragment = inserted_span(planned.original_content, final)
        claim_text = (fragment or planned.description or "repository claim").strip()
        claims.append(
            FalseClaim(
                claim_text=claim_text[:2000],
                claim_type=spec.strategy_family,
                claim_kind=intent.attack_claim_kinds[0],
                truth="false",
                presented_locations=[
                    CodeLocation(file=planned.path, start_line=start, end_line=end)
                ],
                location_source="final_rendered_file",
                reference_finding_ref=intent.target.reference_finding_ref,
            )
        )
        mode = (
            "create"
            if planned.mode == "create"
            else "insert_comment"
            if planned.carrier in {"comment", "code_comment"}
            else "append"
        )
        placements.append(
            PlacementCandidate(
                path=planned.path,
                mode=mode,
                rationale=planned.description,
            )
        )
    claim_graph, graph_problems = _remap_claim_graph(plan.claim_graph, finals)
    problems.extend(graph_problems)
    handle = target_handle(
        intent.intent_id,
        intent.target.vulnerability_id or intent.target.safe_target_id or "target",
    )
    for index, claim in enumerate(claims):
        claims[index] = claim.model_copy(update={"reference_finding_ref": claim.reference_finding_ref})
    attack_plan = AttackPlan(
        plan_id=f"PLAN-{sha256_text(intent.intent_id + json.dumps(sorted(finals)))[:24].upper()}",
        target_vulnerability_ids=(
            [intent.target.vulnerability_id] if intent.target.vulnerability_id else []
        ),
        target_safe_target_ids=[
            item.safe_target_id for item in (validated_safe or [])
        ],
        attack_goal=intent.attack_goal,
        mechanism=intent.mechanism,
        carrier=intent.carrier,
        presentation=intent.presentation,
        distribution=intent.distribution,
        generation_method=intent.generation_method,
        attacker_capability=intent.attacker_capability,
        false_claims=claims,
        attack_claims=list(claims),
        intended_agent_behavior=spec.expected_effect,
        intended_effect=intent.intended_effect,
        placement_candidates=placements,
        required_repository_facts=intent.required_facts,
        decisive_counterevidence=[
            location
            for location in [
                intent.target.critical_operation,
                intent.target.entry_point,
            ]
            if location is not None
        ],
        validation_requirements=intent.validation_requirements,
        provenance={
            "manipulation_id": spec.manipulation_id,
            "payload_ids": [item.payload_id for item in plan.payloads],
            "seed": spec.constraints.get("seed"),
            "candidate_index": candidate_index,
            "intent_id": intent.intent_id,
            "placement_policy": intent.placement_policy,
            "claim_graph_rebuilt": claim_graph is not None,
        },
        safe_targets=[item for item in (validated_safe or []) if item.validated_safe],
        reference_audit_id=intent.reference_audit_id,
        reference_finding_ref=intent.target.reference_finding_ref,
        target_source=intent.target.target_source,  # type: ignore[arg-type]
        reference_detected=intent.target.reference_detected,
        target_verification_status=intent.target.verification_status,
        knowledge_permissions=intent.knowledge_permissions,
        selection_policy=intent.target.selection_policy,
        reference_claims=list(intent.reference_claims),
        verified_facts=[
            fact for fact in facts.facts if fact.fact_id in set(intent.verified_fact_ids)
        ],
        private_evidence_ref=f"evidence/{spec.manipulation_id}.json",
        target_handle=handle,
        target_entry_point=intent.target.entry_point,
        target_critical_operation=intent.target.critical_operation,
        target_binding={
            "kind": intent.target.kind,
            "vulnerability_id": intent.target.vulnerability_id,
            "safe_target_id": intent.target.safe_target_id,
            "file": intent.target.target_file,
            "path_id": intent.target.path_id,
            "source": intent.target.target_source,
        },
        claim_graph=claim_graph,
    )
    return attack_plan, problems
