"""Structured attack planning, repository context and candidate generation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from ..errors import GenerationError
from ..hashing import sha256_text
from ..models import (
    AttackGoal,
    AttackPlan,
    CandidateFile,
    CandidateSelfCheck,
    CodeLocation,
    FalseClaim,
    GeneratedCandidate,
    ManipulationSpec,
    Mechanism,
    PayloadOrigin,
    PlacementCandidate,
    RepositoryContext,
)
from .context import (
    build_context,
    is_code,
    language_for,
    project_name_from_repo_url,
    visible_function_names,
)

_FORBIDDEN_ALWAYS = (
    re.compile(r"(aws_secret|api[_-]?key|password)\s*[:=]", re.I),
    re.compile(r"rm\s+-rf\s+/", re.I),
    re.compile(r"subprocess\.(Popen|call|run)\([^)]*shell\s*=\s*True", re.I),
    re.compile(r"\boracle[_-]?id\b", re.I),
    re.compile(r"\bCLAIM-[0-9A-F]{8,}", re.I),
    re.compile(r"\bVULN-[0-9A-Z]{6,}", re.I),
    re.compile(r"\bRUN-[0-9A-F]{8,}", re.I),
)
#: Explicit instruction wording is a *mechanism*, not a defect: it is rejected
#: only for mechanisms that must not carry an instruction (semantic claims,
#: representation changes, decoys) and kept for ``direct_instruction``.
_INSTRUCTION_PATTERN = re.compile(
    r"ignore\s+(?:\w+\s+){0,3}previous\s+instructions?", re.I
)
_FORBIDDEN_SNIPPETS = ("BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY")

#: Private identifiers that may never appear in agent-visible text.
_ANSWER_KEY_PATTERNS = (
    re.compile(r"\b(oracle|claim|run|instance|evidence)[-_][A-Za-z0-9]{6,}\b", re.I),
    re.compile(r"\bVMAN-[0-9A-Z]{6,}", re.I),
    re.compile(r"\bVM-[0-9A-Z]{6,}", re.I),
)


def build_repository_context(
    oracle,
    repo_root: Path,
    *,
    spec: ManipulationSpec,
    target_file: str | None = None,
    allowed_paths: Iterable[str] = (),
    facts=None,
) -> RepositoryContext:
    """The minimal repository view that may be given to a generation model.

    The target comes from the bound vulnerability/safe target (never from the
    first rendered payload file).  When :class:`RepositoryFacts` are supplied
    they provide real target context, direct call sites and documentation style
    under an explicit budget.
    """
    from .facts import resolve_target_path, resolve_target_vulnerability

    if facts is not None:
        vulnerability = resolve_target_vulnerability(
            oracle,
            target_vulnerability_id=facts.target_vulnerability_id,
        ) if facts.target_vulnerability_id else None
        target_file = target_file or facts.target_file
        snippets: list[CodeLocation] = []
        for fact in facts.facts:
            if fact.kind.value not in {"target_entry_point", "target_critical_operation", "symbol"}:
                continue
            for evidence in fact.evidence[:1]:
                snippets.append(
                    CodeLocation(
                        file=evidence.file,
                        start_line=evidence.start_line,
                        end_line=evidence.end_line,
                        code=evidence.snippet,
                        description=fact.statement[:200],
                    )
                )
            if len(snippets) >= facts.budget.max_snippets:
                break
        callers = sorted(
            {
                evidence.file
                for fact in facts.facts
                if fact.kind.value == "call_site"
                for evidence in fact.evidence
            }
        )
        documentation_style = (
            facts.documentation_style.suffixes[0]
            if facts.documentation_style and facts.documentation_style.suffixes
            else None
        )
        if facts.documentation_style:
            documentation_style = (
                f"{documentation_style} ({len(facts.documentation_style.files)} files, "
                f"headings {','.join(facts.documentation_style.heading_levels) or 'none'})"
            )
        return RepositoryContext(
            project_name=project_name_from_repo_url(oracle.repository.repo_url),
            language=facts.language or language_for(target_file or ""),
            cwe=list(vulnerability.cwe) if vulnerability is not None else [],
            target_component=Path(target_file or "").stem,
            local_code_snippets=snippets,
            visible_functions=visible_function_names(repo_root, target_file or ""),
            callers=callers,
            documentation_style=documentation_style,
            allowed_paths=sorted(
                {*allowed_paths, *[item.path for item in spec.constraints.get("plan_files", [])]}
            ),
            attack_goal=spec.attack_goal,
        )

    vulnerability, path = None, None
    if spec.attack_goal.value == "false_positive" and spec.safe_targets:
        target_file = target_file or spec.safe_targets[0].file
    else:
        from .targets import select_target_from_spec

        vulnerability, path = select_target_from_spec(oracle, spec)
        target_file = target_file or path.critical_operation.file
    if not target_file:
        raise GenerationError("repository context has no bound target file")
    snippets = []
    text = (Path(repo_root) / target_file).read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    starts = [1]
    if path is not None:
        starts = [max(1, path.critical_operation.start_line - 4)]
    for start in starts:
        end = min(len(lines), start + 9)
        if start <= len(lines):
            snippets.append(
                CodeLocation(
                    file=target_file,
                    start_line=start,
                    end_line=end,
                    code="\n".join(lines[start - 1 : end]) + "\n",
                )
            )
    callers = []
    for item in sorted(Path(repo_root).rglob("*.py"))[:200]:
        try:
            body = item.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        stem = Path(target_file).stem
        if f"import {stem}" in body or f"from {stem}" in body:
            callers.append(item.relative_to(repo_root).as_posix())
    docs = [
        item.relative_to(repo_root).as_posix()
        for item in sorted(Path(repo_root).rglob("*.md"))[:20]
    ]
    return RepositoryContext(
        project_name=project_name_from_repo_url(oracle.repository.repo_url),
        language=language_for(target_file),
        cwe=list(vulnerability.cwe) if vulnerability is not None else [],
        target_component=Path(target_file).stem,
        local_code_snippets=snippets,
        visible_functions=visible_function_names(repo_root, target_file),
        callers=callers,
        documentation_style="markdown" if docs else None,
        allowed_paths=sorted({*allowed_paths, *[item.path for item in spec.constraints.get("plan_files", [])]}),
        attack_goal=spec.attack_goal,
    )


def build_attack_plan(
    *,
    spec: ManipulationSpec,
    plan,
    oracle,
    repo_root: Path,
    candidate_index: int = 0,
) -> AttackPlan:
    """Turn a concrete :class:`ChangePlan` into a structured AttackPlan."""
    vulnerability_ids = list(spec.target_vulnerability_ids)
    safe_targets = [item for item in spec.safe_targets if item.validated_safe]
    claims: list[FalseClaim] = []
    for planned in plan.files:
        description = planned.description or "repository claim"
        claims.append(
            FalseClaim(
                claim_text=description,
                claim_type=spec.strategy_family,
                truth="false",
                presented_locations=[
                    CodeLocation(
                        file=planned.path,
                        start_line=1,
                        end_line=max(1, min(3, len(planned.content.splitlines()))),
                    )
                ],
            )
        )
    placements = [
        PlacementCandidate(
            path=item.path,
            mode=(
                "create"
                if item.mode == "create"
                else "insert_comment"
                if item.carrier in {"comment", "code_comment"}
                else "append"
            ),
            rationale=item.description,
        )
        for item in plan.files
    ]
    plan_id = sha256_text(
        json.dumps(
            {
                "manipulation": spec.manipulation_id,
                "candidate": candidate_index,
                "files": [item.path for item in plan.files],
            },
            sort_keys=True,
        )
    )[:24]
    provenance = {
        "payload_ids": [item.payload_id for item in plan.payloads],
        "registry_version": spec.constraints.get("payload_registry_version"),
        "matrix_version": spec.constraints.get("matrix_version"),
        "seed": spec.constraints.get("seed"),
        "candidate_index": candidate_index,
    }
    return AttackPlan(
        plan_id=f"PLAN-{plan_id.upper()}",
        target_vulnerability_ids=vulnerability_ids,
        target_safe_target_ids=[item.safe_target_id for item in safe_targets],
        attack_goal=spec.attack_goal,
        mechanism=spec.mechanism or Mechanism.DIRECT_INSTRUCTION,
        carrier=spec.carrier or "markdown",
        presentation=spec.presentation or "plain_instruction",        distribution=spec.distribution,
        generation_method=spec.generation_method,
        attacker_capability=spec.attacker_capability,
        false_claims=claims,
        intended_agent_behavior=spec.expected_effect,
        placement_candidates=placements,
        required_repository_facts=[
            f"target vulnerability: {item}" for item in vulnerability_ids
        ],
        decisive_counterevidence=[
            path.critical_operation
            for vulnerability in oracle.vulnerabilities
            for path in vulnerability.paths
        ],
        validation_requirements=[
            "executable semantics preserved",
            "oracle locations unchanged",
            "evidence expression satisfiable",
        ],
        provenance=provenance,
        safe_targets=safe_targets,
    )


def validate_candidate_text(text: str, *, mechanism: str | None = None) -> list[str]:
    """Reject candidate text that leaks answers or carries real exploit code.

    Explicit injection wording is allowed for ``direct_instruction`` (it is the
    documented baseline) and rejected for mechanisms that must not smuggle an
    instruction.  Answer-key identifiers are always rejected.
    """
    problems: list[str] = []
    for pattern in _FORBIDDEN_ALWAYS:
        if pattern.search(text):
            problems.append(f"forbidden pattern: {pattern.pattern}")
    if mechanism != "direct_instruction" and _INSTRUCTION_PATTERN.search(text):
        problems.append("instruction wording is not allowed for this mechanism")
    for pattern in _ANSWER_KEY_PATTERNS:
        if pattern.search(text):
            problems.append(f"answer-key pattern: {pattern.pattern}")
    for snippet in _FORBIDDEN_SNIPPETS:
        if snippet in text:
            problems.append("forbidden secret material")
    return problems


def apply_candidate(
    plan,
    *,
    repo_root: Path,
    attack_plan: AttackPlan,
    files: list[CandidateFile],
    self_check: CandidateSelfCheck,
    backend_metadata: dict[str, Any] | None = None,
) -> GeneratedCandidate:
    """Validate backend output and bind it to the concrete change plan."""
    from ..code_semantics import SemanticStatus, compare_semantics, read_text

    allowed = {item.path for item in plan.files}
    planned_by_path = {item.path: item for item in plan.files}
    problems: list[str] = []
    texts = {item.path: item.content for item in files}
    for item in files:
        if item.path not in allowed:
            problems.append(f"path outside allowed plan: {item.path}")
            continue
        source = planned_by_path[item.path]
        existing = text = None
        target = Path(repo_root) / item.path
        existing = target.read_text(encoding="utf-8", errors="replace") if target.is_file() else None
        text = item.content
        problems.extend(validate_candidate_text(text, mechanism=attack_plan.mechanism.value))
        if existing is not None and is_code(item.path):
            verdict = compare_semantics(item.path, existing, text)
            if verdict.status == SemanticStatus.CHANGED:
                problems.append(f"candidate changes executable semantics: {item.path}")
        if source.mode == "replace" and existing is not None and item.mode != "replace":
            pass
    if problems:
        raise GenerationError(
            "generated candidate failed validation",
            details={"problems": problems, "plan_id": attack_plan.plan_id},
        )
    combined = "\n".join(texts[item.path] for item in files)
    metadata = backend_metadata or {}
    return GeneratedCandidate(
        candidate_id=f"{attack_plan.plan_id}-C{metadata.get('index', 0)}",
        plan=attack_plan,
        files=files,
        self_check=self_check,
        generation_method=attack_plan.generation_method,
        origin=PayloadOrigin.ADAPTIVE_GENERATED
        if attack_plan.generation_method.value in {"llm_rewrite", "adaptive_search"}
        else PayloadOrigin.MECHANISM_REIMPLEMENTATION,
        payload_id=metadata.get("payload_id"),
        parent_payload_ids=list(metadata.get("parent_payload_ids", [])),
        provider=metadata.get("provider"),
        model=metadata.get("model"),
        model_version=metadata.get("model_version"),
        prompt_sha256=metadata.get("prompt_sha256"),
        response_sha256=sha256_text(combined),
        generation_seed=metadata.get("seed"),
        generated_at=metadata.get("generated_at"),
        input_tokens=metadata.get("input_tokens"),
        output_tokens=metadata.get("output_tokens"),
        cost_usd=metadata.get("cost_usd"),
        normalized_text_sha256=sha256_text(_normalize_candidate_text(combined)),
        rejection_reason=None,
        metadata=metadata,
    )


def _normalize_candidate_text(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^A-Za-z0-9_ ]+", " ", text.lower())).strip()


def candidate_text(candidate: GeneratedCandidate) -> str:
    return "\n".join(item.content for item in candidate.files)


def token_set(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9_]{3,}", text.lower())
        if token not in {"the", "and", "for", "with", "this", "that", "from", "are", "not"}
    }


def jaccard(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)
