"""M4 behavior-preserving program-representation manipulation."""

from __future__ import annotations

import random
from pathlib import Path

from ..code_semantics import read_text
from ..generation.context import (
    GenerationContext,
    build_context,
    is_code,
    language_for,
)
from ..models import (
    AttackGoal,
    CheckStatus,
    ManipulationTier,
    Mechanism,
    Presentation,
    ValidationResult,
)
from ..paths import safe_join
from .base import (
    ChangePlan,
    ManipulationOperator,
    plan_comment_insertion,
    plan_new_file,
)


def _validate_unreferenced(repo_root: Path, planned_path: str, operator_name: str) -> ValidationResult:
    from ..hashing import utc_now_iso

    from ..code_semantics import read_text as _read

    if not planned_path.endswith(".py"):
        return ValidationResult(
            check_name=f"operator:{operator_name}:unreferenced:{planned_path}",
            status=CheckStatus.PASS,
            started_at=utc_now_iso(),
            duration_seconds=0.0,
            details={},
        )
    stem = Path(planned_path).stem
    imported = False
    for candidate in Path(repo_root).rglob("*.py"):
        if candidate.as_posix().endswith(planned_path):
            continue
        try:
            body = _read(candidate)
        except Exception:
            continue
        if f"import {stem}" in body or f"from {stem}" in body:
            imported = True
            break
    return ValidationResult(
        check_name=f"operator:{operator_name}:unreferenced:{planned_path}",
        status=CheckStatus.PASS if not imported else CheckStatus.FAIL,
        started_at=utc_now_iso(),
        duration_seconds=0.0,
        details={} if not imported else {"error": "new module is imported by existing code"},
    )


class AddUnreferencedRepresentationHelper(ManipulationOperator):
    name = "AddUnreferencedRepresentationHelper"
    tier = ManipulationTier.M4_PROGRAM_REPRESENTATION
    strategy_family = "representation_helper"
    carriers = ("string",)
    mechanism = Mechanism.REPRESENTATION_CONFUSION
    default_presentation = Presentation.CODE_EXPLANATION
    expected_effect = (
        "An uncalled normalization helper creates surface evidence of mitigation "
        "without changing any executable path."
    )

    def supports(self, context: GenerationContext) -> bool:
        return context.language == "python"

    def plan(self, repo_root: Path, oracle, spec, rng: random.Random) -> ChangePlan:
        contracts = []
        if spec.attack_goal == AttackGoal.FALSE_POSITIVE:
            contracts = self.validated_safe_targets(spec, code_only=True)
            contract = contracts[0]
            context = self.safe_target_context(
                oracle, repo_root, contract, spec, "string"
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
                attack_goal=spec.attack_goal,
                carrier="string",
                target_file=target_file,
                target_vulnerability_id=vulnerability.vulnerability_id,
                path_id=path.path_id,
            )
            safe_loc = None
        if language_for(target_file) != "python":
            raise ValueError("M4 helper operator currently supports Python repositories only")
        text, provenance, payload_id = self.render_payload(
            strategy_family=self.strategy_family,
            goal=spec.attack_goal,
            carrier="string",
            context=context,
            rng=rng,
        )
        parent = Path(target_file).parent
        if parent.as_posix() == ".":
            relative = "_audit_representation.py"
        else:
            relative = (parent / "_audit_representation.py").as_posix()
        relative = _unique_path(repo_root, relative)
        planned = plan_new_file(
            relative,
            text,
            carrier="string",
            description="unreferenced normalization representation",
            repo_root=repo_root,
        )
        return ChangePlan(
            operator_name=self.name,
            tier=self.tier,
            files=[planned],
            allowed_paths=[relative],
            payloads=[provenance],
            safe_targets=contracts,
            target_safe_locations=[safe_loc] if safe_loc else [],
            metadata={
                "target_file": target_file,
                "payload_id": payload_id,
                "new_module": relative,
                "target_kind": "safe" if safe_loc else "vulnerable",
                "safe_target_ids": [item.safe_target_id for item in contracts],
            },
        )

    def validate_local(self, repo_root: Path, plan: ChangePlan):
        checks = super().validate_local(repo_root, plan)
        for planned in plan.files:
            checks.append(_validate_unreferenced(repo_root, planned.path, self.name))
        return checks


class AddRepresentationComment(ManipulationOperator):
    name = "AddRepresentationComment"
    tier = ManipulationTier.M4_PROGRAM_REPRESENTATION
    strategy_family = "representation_comment"
    carriers = ("comment",)
    mechanism = Mechanism.REPRESENTATION_CONFUSION
    default_presentation = Presentation.CODE_EXPLANATION
    expected_effect = (
        "A code comment presents a normalization/sanitization representation that "
        "does not match the executable call graph."
    )

    def supports(self, context: GenerationContext) -> bool:
        return context.language is not None

    def plan(self, repo_root: Path, oracle, spec, rng: random.Random) -> ChangePlan:
        contracts = []
        if spec.attack_goal == AttackGoal.FALSE_POSITIVE:
            contracts = self.validated_safe_targets(spec, code_only=True)
            contract = contracts[0]
            if not is_code(contract.file):
                raise ValueError("validated safe target is not a code file")
            context = self.safe_target_context(
                oracle, repo_root, contract, spec, "comment"
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
                attack_goal=spec.attack_goal,
                carrier="comment",
                target_file=target_file,
                target_vulnerability_id=vulnerability.vulnerability_id,
                path_id=path.path_id,
            )
            safe_loc = None
        text, provenance, payload_id = self.render_payload(
            strategy_family=self.strategy_family,
            goal=spec.attack_goal,
            carrier="comment",
            context=context,
            rng=rng,
        )
        planned = plan_comment_insertion(
            repo_root,
            target_file,
            text,
            carrier="comment",
            description="representation comment",
        )
        return ChangePlan(
            operator_name=self.name,
            tier=self.tier,
            files=[planned],
            allowed_paths=[target_file],
            payloads=[provenance],
            safe_targets=contracts,
            target_safe_locations=[safe_loc] if safe_loc else [],
            metadata={
                "target_file": target_file,
                "payload_id": payload_id,
                "target_kind": "safe" if safe_loc else "vulnerable",
                "safe_target_ids": [item.safe_target_id for item in contracts],
            },
        )


def _unique_path(repo_root: Path, relative: str) -> str:
    path = Path(relative)
    candidate = path
    counter = 2
    while safe_join(Path(repo_root), candidate.as_posix()).exists():
        candidate = path.with_name(f"{path.stem}_{counter}{path.suffix}")
        counter += 1
    return candidate.as_posix()
