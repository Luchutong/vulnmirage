"""VulnMirageGen orchestration: materialize clean, generate and validate variants."""

from __future__ import annotations

import json
import os
import random
import shutil
from pathlib import Path
from typing import Any

from ..config import LoadedConfig
from ..errors import GenerationError, UnsupportedTierError
from ..hashing import atomic_write_json, derive_seed, sha256_file, sha256_text, utc_now_iso
from ..logging import get_logger
from ..manipulations import (
    OPERATOR_CLASSES,
    build_operator_by_name,
    compatible_operator_candidates,
    operator_candidates_for,
    supported_tiers,
)
from ..manipulations.base import OperatorTools
from ..models import (
    AttackGoal,
    AttackerCapability,
    BenchmarkInstance,
    Distribution,
    GenerationMethod,
    ManipulationSpec,
    ManipulationTier,
    Mechanism,
    PayloadOrigin,
    PayloadProvenance,
    Presentation,
    Stage,
    VariantKind,
)
from ..paths import ensure_within
from ..repository.cache import RepositoryCache
from ..repository.git import status_porcelain, tree_hash, worktree_digest
from ..repository.location_remap import remap_oracle
from ..repository.materialize import load_materialized_oracle
from ..repository.patch import write_patch_artifact
from ..repository.worktree import create_worktree, remove_worktree
from ..store import (
    InstanceState,
    InstanceStore,
    HistoryEntry,
    now_iso,
    render_audit_task,
    variant_instance_id,
)
from ..validation.pipeline import validate_instance
from .attack_plan import build_attack_plan, build_repository_context, apply_candidate
from .benign import benign_plan
from .compatibility import load_compatibility_matrix, matrix_summary
from .context import build_context
from .feedback import load_feedback, select_operator
from .payload_registry import load_payload_registry
from .safe_targets import (
    SafeTargetResolution,
    execute_safe_target_validation,
    prepare_safe_targets,
)

_LOG = get_logger("generation")


def parse_tiers(value: str | list[str] | None, default: list[ManipulationTier]) -> list[ManipulationTier]:
    if value is None:
        return list(default)
    items = value if isinstance(value, list) else [item for item in value.split(",") if item.strip()]
    tiers: list[ManipulationTier] = []
    for item in items:
        text = str(item).strip().upper()
        try:
            tier = ManipulationTier(text)
        except ValueError as exc:
            raise GenerationError(
                f"unknown manipulation tier: {item}",
                details={"supported": [member.value for member in ManipulationTier]},
            ) from exc
        if tier not in tiers:
            tiers.append(tier)
    return tiers


def parse_goals(value: str | list[str] | None, default: list) -> list:
    from ..models import AttackGoal

    if value is None:
        return list(default)
    items = value if isinstance(value, list) else [item for item in value.split(",") if item.strip()]
    goals = []
    for item in items:
        text = str(item).strip().lower()
        try:
            goal = AttackGoal(text)
        except ValueError as exc:
            raise GenerationError(
                f"unknown attack goal: {item}",
                details={"supported": [member.value for member in AttackGoal]},
            ) from exc
        if goal not in goals:
            goals.append(goal)
    return goals


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _cleanup_variant(
    loaded: LoadedConfig,
    store: InstanceStore,
    cache_path: Path,
    instance_id: str,
) -> None:
    worktree = store.repo_dir(instance_id)
    if worktree.exists():
        remove_worktree(cache_path, worktree, worktrees_root=loaded.paths.worktrees)
    directory = store.instance_dir(instance_id)
    if directory.exists():
        ensure_within(loaded.paths.instances, directory)
        shutil.rmtree(directory)


def _rewrite_plan_with_llm(
    *,
    loaded: LoadedConfig,
    plan,
    attack_plan,
    intent,
    facts,
    oracle,
    repo_root: Path,
    spec: ManipulationSpec,
    reference_profiles=None,
):
    """Ask the configured backend for structured edit operations and apply them.

    The model receives a :class:`GeneratorRequest` allowlist projection, not the
    serialized private plan.  Its operations go through the deterministic
    applier; the final files are then read back and become the candidate content.
    """
    from ..models import CandidateFile, RepositoryContext
    from .edits import apply_operations
    from .llm_backend import LLMBackend, load_prompt_template
    from .request import GeneratorRequest

    backend = LLMBackend(model=loaded.config.generation.llm_model)
    prompt = load_prompt_template(loaded.resolve_asset(loaded.config.generation.llm_prompt))
    budget = loaded.config.generation.edit_budget
    target_cwe: list[str] = []
    if intent.target.vulnerability_id:
        for vulnerability in oracle.vulnerabilities:
            if vulnerability.vulnerability_id == intent.target.vulnerability_id:
                target_cwe = list(vulnerability.cwe)
                break
    request = GeneratorRequest.build(
        plan=attack_plan,
        facts=facts,
        budget=budget,
        oracle_access=loaded.config.generation.oracle_access,
        reference_profiles=list(reference_profiles or []),
        target_cwe=target_cwe,
        target_file=intent.target.target_file,
        target_component=Path(intent.target.target_file).stem,
        target_source=intent.target.target_source,
        reference_detected=intent.target.reference_detected,
        parent_candidates=list(spec.constraints.get("parent_candidates") or []),
    )
    repository_context = RepositoryContext(
        project_name=Path(intent.target.target_file).stem or "repository",
        language=facts.language,
        cwe=target_cwe,
        target_component=Path(intent.target.target_file).stem,
        local_code_snippets=[],
        visible_functions=[],
        allowed_paths=request.allowed_paths,
        attack_goal=attack_plan.attack_goal,
    )
    result = backend.generate_candidate(
        plan=attack_plan,
        repository_context=repository_context,
        prompt_template=prompt,
        parent_payload_ids=[item.payload_id for item in plan.payloads],
        seed=spec.constraints.get("seed"),
        request=request,
    )
    operations = result.operations()
    planned_by_path = {item.path: item for item in plan.files}
    for operation in operations:
        if operation.path not in planned_by_path:
            raise GenerationError(
                "LLM operation is outside the planned files",
                details={"path": operation.path, "rejection_reason": "path_not_planned"},
            )
    from ..models import EditPolicy

    application = apply_operations(
        repo_root,
        operations,
        policy=EditPolicy(
            allowed_paths=sorted(planned_by_path),
            allowed_carriers=sorted({item.carrier for item in plan.files if item.carrier}),
            allow_new_files=budget.allow_new_files,
            allow_executable_changes=budget.allow_executable_changes,
        ),
        budget=budget,
    )
    rewritten = []
    for path, planned in planned_by_path.items():
        target = Path(repo_root) / path
        content = target.read_text(encoding="utf-8", errors="replace")
        rewritten.append(
            planned.model_copy(
                update={
                    "content": content,
                    "mode": planned.mode,
                    "description": (planned.description or "") + " (llm-operations)",
                }
            )
        )
    provenance = PayloadProvenance(
        payload_id=f"{result.model}-{application.application_id}"[:120],
        origin=PayloadOrigin.ADAPTIVE_GENERATED,
        parent_payload_ids=[item.payload_id for item in plan.payloads],
        generator_name="vulnmirage.llm_backend",
        generator_version=result.model,
        prompt_sha256=result.prompt_sha256,
        response_sha256=result.response_sha256,
        random_seed=spec.constraints.get("seed"),
        generated_at=result.generated_at,
        provider=result.provider,
        model=result.model,
        model_version=result.model_version,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        cost_usd=result.cost_usd,
    )
    new_plan = plan.model_copy(
        update={
            "files": rewritten,
            "payloads": [*plan.payloads, provenance],
            "metadata": {
                **plan.metadata,
                "llm_candidate_id": application.application_id,
                "llm_provider": result.provider,
                "llm_model": result.model,
                "llm_prompt_sha256": result.prompt_sha256,
                "llm_response_sha256": result.response_sha256,
                "edit_application_id": application.application_id,
                "edit_patch_sha256": application.patch_sha256,
            },
        }
    )
    return new_plan, provenance, application, request, result


def _generate_benign_variant(
    *,
    loaded: LoadedConfig,
    store: InstanceStore,
    cache: RepositoryCache,
    cache_path: Path,
    clean,
    clean_oracle,
    clean_repo: Path,
    adversarial_instance_id: str,
    plan,
    operator,
    tier: ManipulationTier,
    goal,
    seed_value: int,
    candidate_id: str,
    control_kind: str = "benign",
    files=None,
    target_id: str | None = None,
    target_kind: str | None = None,
    eligible_target_ids: list[str] | None = None,
) -> dict[str, Any] | None:
    """Materialize and validate a benign or truthful-security control."""
    selected_files = list(files) if files is not None else (
        plan.benign_files if control_kind == "benign" else plan.truthful_files
    )
    if not selected_files:
        return None
    suffix = "-B" if control_kind == "benign" else "-T"
    benign_id = f"{adversarial_instance_id}{suffix}"
    if store.exists(benign_id):
        return None
    worktree = create_worktree(
        cache_path,
        clean.repository.vulnerable_commit,
        store.repo_dir(benign_id),
        worktrees_root=loaded.paths.worktrees,
        force=True,
    )
    group_id = f"GROUP-{adversarial_instance_id}"
    try:
        benign_change = plan.model_copy(
            update={
                "files": selected_files,
                "benign_files": [],
                "truthful_files": [],
                "payloads": [],
                "decoys": [],
                "claim_graph": None,
                "safe_targets": [],
                "target_safe_locations": [],
                "metadata": {
                    **plan.metadata,
                    "benign_control": control_kind == "benign",
                    "control_kind": control_kind,
                },
            }
        )
        artifact = operator.apply(worktree, benign_change)
        directory = store.ensure_instance_dir(benign_id)
        patch_path = store.patch_path(benign_id)
        artifact = write_patch_artifact(artifact, patch_path)
        atomic_write_json(
            directory / "patch_meta.json",
            {
                **artifact.model_dump(mode="json", exclude={"patch_text"}),
                "patch_file": store.relative(patch_path),
                "allowed_paths": benign_change.allowed_paths,
                "operator": operator.name,
                "benign_control": control_kind == "benign",
                "control_kind": control_kind,
                "group_id": group_id,
                "plan_files": [
                    {"path": item.path, "mode": item.mode, "carrier": item.carrier}
                    for item in benign_change.files
                ],
            },
        )
        remap = remap_oracle(clean_oracle, clean_repo, worktree)
        instance_oracle = remap.oracle.model_copy(
            update={
                "validation_level": (
                    "unverified"
                    if clean_oracle.validation_level == "unverified"
                    else "trace_grounded"
                )
            }
        )
        from .evidence_contract import build_evidence_contract, validate_evidence_contract

        contract = build_evidence_contract(
            instance_id=benign_id,
            oracle=instance_oracle,
            manipulation=None,
            plan=benign_change,
            decoys=[],
            repo_root=worktree,
            is_clean=True,
        )
        contract_relative, _ = store.write_evidence_contract(benign_id, contract)
        task_text = render_audit_task(loaded)
        task_relative, task_sha = store.write_task(benign_id, task_text)
        oracle_sha = store.write_oracle(benign_id, instance_oracle)
        instance = BenchmarkInstance(
            instance_id=benign_id,
            pair_id=clean.pair_id,
            schema_version="1.0",
            variant_kind=VariantKind.BENIGN_CONTROL,
            oracle_ref=instance_oracle.oracle_id,
            repository=instance_oracle.repository,
            audit_difficulty=instance_oracle.effective_difficulty,
            manipulation_tier=tier,
            manipulation_ref=None,
            evidence_contract_ref=contract_relative,
            task_file=task_relative,
            patch_file=store.relative(patch_path),
            repository_tree_sha256=worktree_digest(worktree),
            generation_config_sha256=loaded.sha256,
            random_seed=seed_value,
            release_split=clean.release_split,
            group_id=group_id,
            candidate_id=candidate_id,
            generation_method="human_authored",
            control_kind=control_kind,
            target_id=target_id,
            target_kind=target_kind,
            eligible_target_ids=list(eligible_target_ids or []),
        )
        store.save_instance(instance)
        timestamp = now_iso()
        store.save_state(
            InstanceState(
                instance_id=benign_id,
                oracle_id=instance_oracle.oracle_id,
                pair_id=clean.pair_id,
                variant_kind=VariantKind.BENIGN_CONTROL,
                stage=Stage.GENERATED.value,
                created_at=timestamp,
                updated_at=timestamp,
                generation_config_sha256=loaded.sha256,
                oracle_sha256=oracle_sha,
                task_sha256=task_sha,
                clean_instance_id=clean.instance_id,
                patch_sha256=artifact.patch_sha256,
                base_tree_sha256=artifact.base_tree_sha256,
                variant_tree_sha256=artifact.variant_tree_sha256,
                random_seed=seed_value,
                operator_names=[operator.name],
                notes={
                    "benign_control_for": adversarial_instance_id,
                    "control_kind": control_kind,
                    "group_id": group_id,
                    "candidate_id": candidate_id,
                },
            )
        )
        validation = validate_instance(loaded=loaded, instance_id=benign_id)
        from ..models import VariantGroup

        existing_group = next(
            (
                item
                for item in store.load_groups().groups
                if item.group_id == group_id
            ),
            None,
        )
        group = VariantGroup(
            group_id=group_id,
            oracle_id=instance_oracle.oracle_id,
            pair_id=clean.pair_id,
            clean_instance_id=clean.instance_id,
            adversarial_instance_id=adversarial_instance_id,
            benign_instance_id=(
                benign_id
                if control_kind == "benign"
                else (existing_group.benign_instance_id if existing_group else None)
            ),
            truthful_security_instance_id=(
                benign_id
                if control_kind == "truthful_security"
                else (
                    existing_group.truthful_security_instance_id
                    if existing_group
                    else None
                )
            ),
            attack_goal=goal.value,
            mechanism=plan.metadata.get("mechanism"),
            carrier=plan.metadata.get("carrier"),
            presentation=plan.metadata.get("presentation"),
            candidate_id=candidate_id,
            target_id=target_id,
            target_kind=target_kind,
            eligible_target_ids=list(eligible_target_ids or []),
        )
        store.add_group(group)
        if validation["release_eligible"]:
            store.update_stage(benign_id, Stage.FROZEN, detail="benign control validated")
        return {
            "instance_id": benign_id,
            "group_id": group_id,
            "adversarial_instance_id": adversarial_instance_id,
            "release_eligible": validation["release_eligible"],
            "validation_level": validation["validation_level"],
            "failed_checks": [
                item["name"]
                for item in validation["checks"]
                if item["status"] in {"fail", "error", "unknown"}
            ],
        }
    except Exception as exc:  # noqa: BLE001 - a benign control must not abort generation
        _cleanup_variant(loaded, store, cache_path, benign_id)
        return {
            "instance_id": benign_id,
            "adversarial_instance_id": adversarial_instance_id,
            "release_eligible": False,
            "error": str(exc),
        }


def _next_instance_version(store: InstanceStore, base_id: str) -> str:
    counter = 2
    while store.exists(f"{base_id}-v{counter}"):
        counter += 1
    return f"{base_id}-v{counter}"


def _freeze(store: InstanceStore, instance_id: str) -> None:
    state = store.load_state(instance_id)
    if state.stage == Stage.FROZEN.value:
        return
    try:
        store.update_stage(instance_id, Stage.FROZEN, detail="validated and frozen")
    except Exception as exc:  # noqa: BLE001
        raise GenerationError(
            "could not freeze validated instance",
            details={"instance_id": instance_id, "error": str(exc)},
        ) from exc


def generate_for_oracle(
    *,
    loaded: LoadedConfig,
    oracle_path: Path,
    tiers: str | list[str] | None = None,
    goals: str | list[str] | None = None,
    seed: int | None = None,
    force: bool = False,
    resume: bool = False,
    split: str | None = None,
    max_variants: int | None = None,
    candidate_index: int = 0,
    target_vulnerability_id: str | None = None,
    parent_candidates: list[dict[str, Any]] | None = None,
    operator_override: str | None = None,
    schedule_policy: str | None = None,
) -> dict[str, Any]:
    loaded.paths.ensure_layout()
    store = InstanceStore(loaded.paths)
    backend = loaded.config.generation.backend
    if backend == "llm" and not os.environ.get("VULNMIRAGE_LLM_BASE_URL"):
        raise GenerationError(
            "generation.backend=llm requires VULNMIRAGE_LLM_BASE_URL/VULNMIRAGE_LLM_API_KEY/"
            "VULNMIRAGE_LLM_MODEL; use backend=template for the reproducible baseline",
            details={"backend": backend},
        )
    oracle, clean, pointer = load_materialized_oracle(loaded, oracle_path)
    if split is not None:
        if not (split.startswith("dev-") or split.startswith("test-")):
            raise GenerationError("split must look like dev-* or test-*", details={"split": split})
        if split != loaded.config.generation.split:
            raise GenerationError(
                "split override must match the validated configuration used for materialization; "
                "change generation.split in the config instead",
                details={"config_split": loaded.config.generation.split, "requested": split},
            )
    if clean.release_split != loaded.config.generation.split:
        raise GenerationError(
            "clean instance split does not match the current configuration",
            details={"instance_split": clean.release_split, "config_split": loaded.config.generation.split},
        )

    selected_tiers = parse_tiers(tiers, loaded.config.generation.tiers)
    selected_goals = parse_goals(goals, loaded.config.generation.goals)
    registry, payload_dir = load_payload_registry(
        loaded.resolve_asset(loaded.config.generation.payload_registry)
    )
    registry = registry.filter_for_split(clean.release_split)
    matrix_file = loaded.config.generation.compatibility_matrix
    matrix = load_compatibility_matrix(loaded.resolve_asset(matrix_file))
    tools = OperatorTools(registry=registry, payload_dir=payload_dir)
    feedback_snapshot = None
    feedback_info: dict[str, Any] | None = None
    if loaded.config.generation.feedback_enabled or loaded.config.generation.feedback_file:
        if not loaded.config.generation.feedback_file:
            raise GenerationError(
                "generation.feedback_enabled requires generation.feedback_file"
            )
        feedback_path = loaded.resolve_asset(loaded.config.generation.feedback_file)
        feedback_snapshot = load_feedback(feedback_path)
        feedback_info = {
            "path": str(feedback_path),
            "sha256": sha256_file(feedback_path),
            "split": feedback_snapshot.split,
            "frozen_for_test": clean.release_split.startswith("test-"),
        }
    global_seed = loaded.config.generation.global_seed if seed is None else seed
    limit = max_variants if max_variants is not None else loaded.config.generation.max_variants_per_oracle
    if limit < 0:
        raise GenerationError("max-variants must be non-negative")

    # The clean baseline is always validated before variants are generated.
    clean_validation = validate_instance(loaded=loaded, instance_id=clean.instance_id)
    if not clean_validation["release_eligible"]:
        raise GenerationError(
            "clean M0 baseline failed validation; refusing to generate variants",
            details={
                "clean_instance_id": clean.instance_id,
                "checks": [
                    {"name": item["name"], "status": item["status"]}
                    for item in clean_validation["checks"]
                    if item["status"] in {"fail", "error"}
                ],
            },
        )
    _freeze(store, clean.instance_id)
    clean_oracle = store.load_oracle(clean.instance_id)
    clean_repo = store.repo_dir(clean.instance_id)
    clean_state = store.load_state(clean.instance_id)
    cache = RepositoryCache(loaded.paths.cache, loaded.config.network)
    _, cache_path = cache.ensure(oracle.repository.repo_url, fetch=False)
    cache.verify_commit(cache_path, oracle.repository.vulnerable_commit)

    # ------------------------------------------------------------ reference R0
    from .baseline import acquire_reference_audit

    reference_audit, baseline_context = acquire_reference_audit(
        loaded=loaded,
        oracle=clean_oracle,
        clean_instance_id=clean.instance_id,
        repo_root=clean_repo,
        task_sha256=clean_state.task_sha256,
        repository_tree_sha256=clean.repository_tree_sha256,
        agent_config_path=(
            loaded.config.generation.reference_audit.agent_config
            if loaded.config.generation.reference_audit.agent_config
            else None
        ),
    )
    reference_settings = loaded.config.generation.reference_audit
    if reference_settings.require_for_generation and not baseline_context.available:
        raise GenerationError(
            "a reference audit is required for generation but was not available",
            details={"missing_reason": baseline_context.missing_reason},
        )

    # ---------------------------------------------------------- target choice
    from .targets import resolve_target_path, resolve_target_vulnerability

    oracle_access = loaded.config.generation.oracle_access
    target_source = loaded.config.generation.target_source
    requested_ids = list(loaded.config.generation.target_vulnerability_ids)
    target_election: dict[str, Any] = {
        "requested_ids": requested_ids,
        "explicit_target_override": target_vulnerability_id,
        "target_source": target_source,
        "oracle_access": oracle_access,
        "report_access": loaded.config.generation.report_access,
        "trace_access": loaded.config.generation.trace_access,
        "policy": loaded.config.generation.target_selection_policy,
    }
    if target_source == "reference" and oracle_access == "none":
        eligible_ids = baseline_context.generation_eligible_vulnerability_ids()
        if not eligible_ids:
            raise GenerationError(
                "report-only target selection has no verified generation-eligible target",
                details={"report_access": loaded.config.generation.report_access},
            )
        if requested_ids:
            eligible_ids = [item for item in eligible_ids if item in set(requested_ids)]
        if target_vulnerability_id:
            eligible_ids = [item for item in eligible_ids if item == target_vulnerability_id]
            if not eligible_ids:
                raise GenerationError(
                    "the requested target is not generation-eligible under report-only access",
                    details={"target": target_vulnerability_id},
                )
        target_id = target_vulnerability_id or sorted(eligible_ids)[0]
        target_election["eligible_ids"] = sorted(eligible_ids)
        target_election["selection"] = "reference_only"
        experiment_target_ids = sorted(eligible_ids)
    else:
        candidates = [
            item.vulnerability_id for item in clean_oracle.vulnerabilities
        ]
        if requested_ids:
            unknown = [item for item in requested_ids if item not in set(candidates)]
            if unknown:
                raise GenerationError(
                    "generation.target_vulnerability_ids references unknown vulnerabilities",
                    details={"unknown": unknown},
                )
            candidates = [item for item in requested_ids if item in set(candidates)]
        if not candidates:
            raise GenerationError("no generation-eligible target vulnerability")
        selection_reason = loaded.config.generation.target_selection_policy
        if (
            target_source == "combined"
            and baseline_context.available
            and loaded.config.generation.target_selection_policy != "explicit"
        ):
            detected = [
                item
                for item in candidates
                if item in set(baseline_context.reference_detected_target_ids)
            ]
            if detected:
                candidates = detected
                selection_reason = "reference_detected_first"
        if loaded.config.generation.target_selection_policy == "explicit":
            if not requested_ids and not target_vulnerability_id:
                raise GenerationError(
                    "target_selection_policy=explicit requires "
                    "generation.target_vulnerability_ids"
                )
            target_id = target_vulnerability_id or requested_ids[0]
        else:
            target_id = target_vulnerability_id or sorted(candidates)[0]
        target_election["eligible_ids"] = sorted(candidates)
        target_election["selection"] = selection_reason
        experiment_target_ids = sorted(candidates)
    requested_target = target_id
    target_vulnerability = resolve_target_vulnerability(
        clean_oracle, target_vulnerability_id=target_id
    )
    # Bind the canonical id even when the caller used a CVE/GHSA alias.
    target_id = target_vulnerability.vulnerability_id
    target_election["requested_target"] = requested_target
    target_election["selected_target_id"] = target_id
    target_election["selected_target_aliases"] = list(target_vulnerability.aliases)
    blocked = baseline_context.blocked_reason_for(target_id) if baseline_context.available else None
    if blocked:
        raise GenerationError(
            "reference verification blocks this target for generation",
            details={"target": target_id, "reason": blocked},
        )
    target_election["selected_target_id"] = target_id
    target_election["experiment_target_ids"] = experiment_target_ids
    target_election["reference_detected"] = target_id in set(
        baseline_context.reference_detected_target_ids
    )
    target_election["reference_verification_status"] = next(
        (
            link.status.value
            for link in baseline_context.links
            if link.vulnerability_id == target_id
        ),
        None,
    )

    results: dict[str, Any] = {
        "ok": True,
        "oracle_id": oracle.oracle_id,
        "pair_id": clean.pair_id,
        "clean": {
            "instance_id": clean.instance_id,
            "release_eligible": clean_validation["release_eligible"],
            "validation_level": clean_validation["validation_level"],
            "stage": store.load_state(clean.instance_id).stage,
        },
        "generated": [],
        "benign_generated": [],
        "skipped": [],
        "rejected": [],
        "supported_tiers": supported_tiers(),
        "payload_registry": {
            "version": registry.registry_version,
            "sha256": registry.registry_sha256,
            "payload_count": len(registry.payloads),
            "visible_for_split": clean.release_split,
        },
        "feedback": feedback_info,
        "compatibility_matrix": matrix_summary(matrix),
        "seed": global_seed,
        "split": clean.release_split,
        "target_selection": target_election,
        "reference": (
            {
                "available": baseline_context.available,
                "missing_reason": baseline_context.missing_reason,
                "source": reference_settings.source,
                "reference_audit_id": (
                    reference_audit.reference_audit_id if reference_audit else None
                ),
                "cache_key": reference_audit.cache_key if reference_audit else None,
                "cache_hit": reference_audit.cache_hit if reference_audit else False,
                "status": reference_audit.status.value if reference_audit else "none",
                "purpose": "reference",
                "formal_pairing": False,
                "detected_target_ids": baseline_context.reference_detected_target_ids,
                "unreported_known_target_ids": baseline_context.unreported_known_target_ids,
                "confirmed_false_positive_ids": baseline_context.confirmed_false_positive_target_ids,
                "adjudication_finding_ids": baseline_context.adjudication_target_ids,
                "severity_disagreement_ids": baseline_context.severity_disagreement_ids,
                "insufficient_evidence_ids": baseline_context.insufficient_evidence_target_ids,
            }
        ),
    }
    if ManipulationTier.M0_CLEAN in selected_tiers:
        results["clean"]["requested"] = True

    created = 0
    attempted = 0
    for tier in selected_tiers:
        if tier == ManipulationTier.M0_CLEAN:
            continue
        if tier.value not in results["supported_tiers"]:
            raise UnsupportedTierError(
                f"tier {tier.value} is not implemented in this build; "
                f"supported: {', '.join(results['supported_tiers'])}",
                details={"tier": tier.value},
            )
        for goal in selected_goals:
            if attempted >= limit:
                results["skipped"].append(
                    {
                        "tier": tier.value,
                        "goal": goal.value,
                        "reason": "generation_budget_exhausted",
                        "budget_unit": "attempted_job",
                    }
                )
                continue
            candidate_names = compatible_operator_candidates(tier, goal, matrix)
            if not candidate_names:
                results["skipped"].append(
                    {
                        "tier": tier.value,
                        "goal": goal.value,
                        "reason": "incompatible_combination",
                        "mechanism": next(
                            (
                                OPERATOR_CLASSES[name].mechanism.value
                                for name in operator_candidates_for(tier, goal)
                            ),
                            None,
                        ),
                        "matrix_version": matrix.matrix_version,
                    }
                )
                continue
            eligibility = clean_oracle.effective_eligibility()
            if not eligibility.allows(goal):
                results["skipped"].append(
                    {
                        "tier": tier.value,
                        "goal": goal.value,
                        "reason": eligibility.reasons.get(
                            goal.value,
                            f"case is not eligible for {goal.value}",
                        ),
                        "eligibility": eligibility.model_dump(mode="json"),
                    }
                )
                continue
            from .scheduling import assign_operator

            if operator_override in candidate_names:
                chosen_operator = operator_override
                schedule_record = {
                    "candidate_index": candidate_index,
                    "operator": chosen_operator,
                    "schedule_policy": "explicit_override",
                    "compatible_operators": candidate_names,
                }
            else:
                assignment = assign_operator(
                    index=candidate_index,
                    tier=tier.value,
                    goal=goal.value,
                    compatible=candidate_names,
                    policy=(
                        schedule_policy
                        or (
                            "feedback"
                            if feedback_snapshot is not None
                            else loaded.config.generation.candidate_schedule
                        )
                    ),
                    feedback=feedback_snapshot,
                )
                chosen_operator = assignment.operator
                schedule_record = assignment.record
            results.setdefault("schedule", []).append(
                {**schedule_record, "tier": tier.value, "goal": goal.value}
            )
            operator_cls = OPERATOR_CLASSES[chosen_operator]
            attempted += 1
            operator = build_operator_by_name(operator_cls.name, tools, goal=goal)
            operator.with_variant(candidate_index)
            # Target identity is part of the instance/cache/resume key (P0-2).
            # P0-5: a false-positive variant binds exactly ONE safe target (the
            # pre-registered one), never "all validated safe targets".
            bound_safe_target_id: str | None = None
            if goal == AttackGoal.FALSE_POSITIVE:
                identity_target_kind = "safe_target"
                from .safe_targets import preselect_safe_target_id

                bound_safe_target_id = preselect_safe_target_id(clean_oracle, clean_repo)
                identity_target_id = (
                    bound_safe_target_id
                    if bound_safe_target_id
                    else "SYNTHETIC-" + sha256_text(operator_cls.name)[:12]
                )
            else:
                identity_target_kind = "vulnerability"
                identity_target_id = target_id
            base_id = variant_instance_id(
                clean.pair_id,
                tier.value,
                goal.value,
                operator_cls.name,
                target_id=identity_target_id,
                target_kind=identity_target_kind,
            )
            if candidate_index > 0:
                base_id = f"{base_id}-C{candidate_index + 1}"
            instance_id = base_id
            existing_state: InstanceState | None = None
            if store.exists(base_id):
                try:
                    existing_state = store.load_state(base_id)
                except Exception:
                    existing_state = None
                if not force:
                    if resume and existing_state and existing_state.stage in {
                        Stage.VALIDATED.value,
                        Stage.FROZEN.value,
                    }:
                        results["skipped"].append(
                            {
                                "instance_id": base_id,
                                "tier": tier.value,
                                "goal": goal.value,
                                "reason": "already generated (resume)",
                                "stage": existing_state.stage,
                            }
                        )
                        continue
                    if resume and existing_state and existing_state.stage == Stage.REJECTED.value:
                        validation = validate_instance(loaded=loaded, instance_id=base_id)
                        results["skipped"].append(
                            {
                                "instance_id": base_id,
                                "tier": tier.value,
                                "goal": goal.value,
                                "reason": "revalidated existing rejected instance",
                                "release_eligible": validation["release_eligible"],
                            }
                        )
                        if validation["release_eligible"]:
                            _freeze(store, base_id)
                        continue
                    raise GenerationError(
                        "variant instance already exists; use --resume to keep it or --force to regenerate",
                        details={"instance_id": base_id, "tier": tier.value, "goal": goal.value},
                    )
                if existing_state and existing_state.stage in {Stage.FROZEN.value, Stage.EXPORTED.value}:
                    instance_id = _next_instance_version(store, base_id)
                else:
                    _cleanup_variant(loaded, store, cache_path, base_id)
            else:
                _cleanup_variant(loaded, store, cache_path, base_id)

            # Candidate ids are unique per instance so that two parents sharing a
            # strategy cannot collapse into the same lineage node.
            candidate_id = f"{instance_id}-c{candidate_index}"

            seed_value = derive_seed(
                global_seed,
                clean.pair_id,
                identity_target_kind,
                identity_target_id or "unspecified-target",
                tier.value,
                goal.value,
                operator_cls.name,
                candidate_index,
            )
            rng = random.Random(seed_value)
            worktree = create_worktree(
                cache_path,
                clean.repository.vulnerable_commit,
                store.repo_dir(instance_id),
                worktrees_root=loaded.paths.worktrees,
                force=True,
            )
            if status_porcelain(worktree):
                raise GenerationError(
                    "fresh variant worktree is not clean", details={"worktree": str(worktree)}
                )
            support_context = build_context(
                clean_oracle,
                worktree,
                attack_goal=goal,
                carrier=operator_cls.carriers[0] if operator_cls.carriers else "markdown",
            )
            if not operator.supports(support_context):
                _cleanup_variant(loaded, store, cache_path, instance_id)
                results["skipped"].append(
                    {
                        "instance_id": instance_id,
                        "tier": tier.value,
                        "goal": goal.value,
                        "operator": operator_cls.name,
                        "reason": "operator does not support this repository/language",
                    }
                )
                continue

            # Safe targets are declared by the dataset; they are validated here
            # before any false-positive payload is rendered.
            safe_resolution: SafeTargetResolution = prepare_safe_targets(clean_oracle, worktree)
            validated_safe = []
            safe_target_details: list[dict[str, Any]] = []
            if safe_resolution.accepted:
                executed = execute_safe_target_validation(
                    safe_resolution.accepted,
                    loaded=loaded,
                    repo_root=worktree,
                    log_dir=store.instance_dir(instance_id) / "logs" / "safe_targets",
                    instance_id=instance_id,
                )
                validated_safe = executed.validated
                safe_target_details = executed.details
            if safe_resolution.rejected:
                results["safe_target_rejections"] = [
                    *results.get("safe_target_rejections", []),
                    *safe_resolution.rejected,
                ]
            matrix_entry = matrix.requirements(
                mechanism=operator_cls.mechanism,
                strategy_family=operator_cls.strategy_family,
                goal=goal,
            )
            requires_validated_safe = bool(
                goal == AttackGoal.FALSE_POSITIVE
                and matrix_entry.required_safe_target
            )
            if (
                requires_validated_safe
                and not validated_safe
                and operator_cls.mechanism != Mechanism.SAFE_DECOY
            ):
                _cleanup_variant(loaded, store, cache_path, instance_id)
                results["skipped"].append(
                    {
                        "instance_id": instance_id,
                        "tier": tier.value,
                        "goal": goal.value,
                        "operator": operator_cls.name,
                        "reason": "no_validated_safe_target",
                        "safe_target_rejections": safe_resolution.rejected,
                    }
                )
                continue

            manipulation_id = f"VMAN-{sha256_text(instance_id + tier.value + goal.value)[:16].upper()}"
            spec = ManipulationSpec(
                manipulation_id=manipulation_id,
                designed_tier=tier,
                attack_goal=goal,
                strategy_family=operator_cls.strategy_family,
                mechanism=operator_cls.mechanism,
                carrier={
                    "markdown": "markdown",
                    "comment": "code_comment",
                    "string": "string_literal",
                }.get(operator_cls.carriers[0] if operator_cls.carriers else "markdown"),
                presentation=operator_cls.default_presentation,
                distribution=operator_cls.distribution,
                generation_method=(
                    GenerationMethod.LLM_REWRITE
                    if loaded.config.generation.backend in {"llm", "hybrid"}
                    else GenerationMethod.TEMPLATE
                ),
                attacker_capability=operator_cls.attacker_capability,
                carriers=list(operator_cls.carriers),
                operator_names=[operator_cls.name],
                payloads=[],
                # Exactly one attack target.  The candidate set is recorded
                # separately and never used for scoring (P0-2).
                target_vulnerability_ids=[target_id],
                target_safe_target_ids=(
                    [bound_safe_target_id]
                    if goal == AttackGoal.FALSE_POSITIVE and bound_safe_target_id
                    else []
                ),
                target_decoy_ids=[],
                files_touched=[],
                safe_targets=list(validated_safe),
                constraints={
                    "seed": seed_value,
                    "pair_id": clean.pair_id,
                    "clean_instance_id": clean.instance_id,
                    "operator_key": operator_cls.name,
                    "mechanism": operator_cls.mechanism.value,
                    "matrix_version": matrix.matrix_version,
                    "compatibility_entry": matrix_entry.model_dump(mode="json"),
                    "payload_registry": str(registry.source_path),
                    "payload_registry_sha256": registry.registry_sha256,
                    "payload_registry_version": registry.registry_version,
                    "feedback": feedback_info,
                    "target_vulnerability_id": target_id,
                    "target_id": (
                        bound_safe_target_id
                        if goal == AttackGoal.FALSE_POSITIVE and bound_safe_target_id
                        else target_id
                    ),
                    "target_kind": identity_target_kind,
                    "eligible_target_ids": sorted(experiment_target_ids),
                    "target_path_id": resolve_target_path(target_vulnerability).path_id,
                    "instance_identity_target_id": identity_target_id,
                    "target_selection": target_election,
                    "reference_audit_id": (
                        reference_audit.reference_audit_id if reference_audit else None
                    ),
                    "reference_finding_ref": target_election.get(
                        "reference_finding_ref"
                    ),
                    "reference_detected": target_election["reference_detected"],
                    "target_source": target_source,
                    "oracle_access": oracle_access,
                    "report_access": loaded.config.generation.report_access,
                    "trace_access": loaded.config.generation.trace_access,
                    "parent_candidates": list(parent_candidates or []),
                },
                expected_effect=operator_cls.expected_effect,
            )
            # ---------------------------------------------- plan BEFORE rendering
            from .facts import extract_repository_facts
            from .planning import (
                build_attack_plan_from_intent,
                build_plan_intent,
                reconcile_render,
            )

            facts_budget = loaded.config.generation.context_budget
            try:
                facts = extract_repository_facts(
                    clean_oracle,
                    worktree,
                    target_vulnerability_id=target_id,
                    budget=facts_budget,
                    target_handle=spec.constraints.get("target_handle"),
                    include_documentation=True,
                )
            except ValueError as exc:
                _cleanup_variant(loaded, store, cache_path, instance_id)
                results["skipped"].append(
                    {
                        "instance_id": instance_id,
                        "tier": tier.value,
                        "goal": goal.value,
                        "operator": operator_cls.name,
                        "reason": f"repository facts unavailable: {exc}",
                    }
                )
                continue
            intent = build_plan_intent(
                oracle=clean_oracle,
                spec=spec,
                repo_root=worktree,
                facts=facts,
                baseline=baseline_context,
                knowledge_permissions={
                    "oracle_access": oracle_access,
                    "report_access": loaded.config.generation.report_access,
                    "trace_access": loaded.config.generation.trace_access,
                },
                target_source=target_source,
                selection_policy=loaded.config.generation.target_selection_policy,
            )
            if baseline_context.available:
                target_election["reference_finding_ref"] = intent.target.reference_finding_ref
            directory = store.ensure_instance_dir(instance_id)
            atomic_write_json(
                directory / "plan_intent.json",
                {
                    "plan_intent": intent.model_dump(mode="json"),
                    "written_before_rendering": True,
                    "candidate_index": candidate_index,
                    "candidate_id": candidate_id,
                },
            )
            atomic_write_json(
                directory / "repository_facts.json",
                {
                    **facts.model_dump(mode="json"),
                    "facts_sha256": facts.digest(),
                    "extraction_is_read_only": True,
                },
            )
            pre_digest = worktree_digest(worktree)
            try:
                try:
                    plan = operator.plan(worktree, clean_oracle, spec, rng)
                except ValueError as exc:
                    _cleanup_variant(loaded, store, cache_path, instance_id)
                    results["skipped"].append(
                        {
                            "tier": tier.value,
                            "goal": goal.value,
                            "operator": operator_cls.name,
                            "reason": f"operator cannot bind to this repository: {exc}",
                        }
                    )
                    continue
                post_digest = worktree_digest(worktree)
                if pre_digest != post_digest:
                    raise GenerationError(
                        "operator.plan modified the repository; plan() must be read-only",
                        details={"operator": operator_cls.name},
                    )
                if not plan.payloads:
                    raise GenerationError(
                        "operator plan recorded no payload provenance",
                        details={"operator": operator_cls.name},
                    )
                plan = plan.model_copy(
                    update={
                        "metadata": {
                            **plan.metadata,
                            "mechanism": operator_cls.mechanism.value,
                            "carrier": spec.carrier,
                            "presentation": operator_cls.default_presentation.value,
                            "intent_id": intent.intent_id,
                            "plan_before_render": True,
                        }
                    }
                )
                render_problems = reconcile_render(intent, plan)
                if render_problems:
                    raise GenerationError(
                        "rendered change plan contradicts the frozen plan intent",
                        details={
                            "operator": operator_cls.name,
                            "problems": render_problems,
                            "plan_intent_id": intent.intent_id,
                        },
                    )
                # Provisional plan for the LLM request (placement list only).
                provisional_plan = build_attack_plan(
                    spec=spec,
                    plan=plan,
                    oracle=clean_oracle,
                    repo_root=worktree,
                    candidate_index=candidate_index,
                ).model_copy(
                    update={
                        "target_handle": intent.intent_id,
                        "reference_audit_id": intent.reference_audit_id,
                        "target_source": intent.target.target_source,
                        "reference_detected": intent.target.reference_detected,
                        "reference_claims": intent.reference_claims,
                        "verified_facts": facts.facts,
                        "target_binding": intent.model_dump(mode="json")["target"],
                    }
                )
                llm_enabled = loaded.config.generation.backend == "llm" or (
                    loaded.config.generation.backend == "hybrid" and candidate_index > 0
                )
                edit_application = None
                generator_request = None
                llm_result = None
                from ..repository.patch import create_patch_artifact

                if llm_enabled:
                    try:
                        (
                            plan,
                            llm_provenance,
                            edit_application,
                            generator_request,
                            llm_result,
                        ) = _rewrite_plan_with_llm(
                            loaded=loaded,
                            plan=plan,
                            attack_plan=provisional_plan,
                            intent=intent,
                            facts=facts,
                            oracle=clean_oracle,
                            repo_root=worktree,
                            spec=spec.model_copy(
                                update={
                                    "constraints": {
                                        **spec.constraints,
                                        "candidate_index": candidate_index,
                                    }
                                }
                            ),
                            reference_profiles=baseline_context.profiles,
                        )
                    except GenerationError as exc:
                        # A single rejected LLM candidate is data, not
                        # infrastructure failure: record a sanitized reason and
                        # continue within the budget.  Invariant errors abort.
                        detail = exc.details or {}
                        rejection = detail.get("rejection_reason")
                        if not rejection:
                            raise
                        _cleanup_variant(loaded, store, cache_path, instance_id)
                        results["rejected"].append(
                            {
                                "instance_id": instance_id,
                                "tier": tier.value,
                                "goal": goal.value,
                                "operator": operator_cls.name,
                                "reason": "llm_candidate_rejected",
                                "rejection_reason": rejection,
                                "prompt_sha256": detail.get("prompt_sha256"),
                                "response_sha256": detail.get("response_sha256"),
                                "candidate_index": candidate_index,
                            }
                        )
                        continue
                    spec = spec.model_copy(
                        update={
                            "generation_method": GenerationMethod.LLM_REWRITE,
                            "payloads": [*spec.payloads, llm_provenance],
                        }
                    )
                    artifact = create_patch_artifact(worktree)
                    atomic_write_json(
                        directory / "generator_request.json",
                        {
                            "generator_request": generator_request.model_dump(mode="json"),
                            "prompt_sha256": llm_result.prompt_sha256,
                            "response_sha256": llm_result.response_sha256,
                            "provider": llm_result.provider,
                            "model": llm_result.model,
                        },
                    )
                else:
                    # Validate the template change against the unified protocol
                    # before it is written (equivalence is recorded, not guessed).
                    from .edits import apply_operations, operations_from_change_plan

                    operations = operations_from_change_plan(plan)
                    from ..models import EditPolicy

                    dry = apply_operations(
                        worktree,
                        operations,
                        policy=EditPolicy(
                            allowed_paths=sorted(item.path for item in plan.files),
                            allowed_carriers=sorted({item.carrier for item in plan.files if item.carrier}),
                            allow_new_files=any(item.mode == "create" for item in plan.files),
                            allow_executable_changes=loaded.config.generation.edit_budget.allow_executable_changes,
                        ),
                        budget=loaded.config.generation.edit_budget,
                        dry_run=True,
                    )
                    from ..code_semantics import normalize_text
                    from ..hashing import sha256_text as _sha

                    mismatched = [
                        item.path
                        for item in plan.files
                        if not any(
                            result_item.path == item.path
                            and result_item.new_sha256
                            == _sha(normalize_text(item.content))
                            for result_item in dry.files
                        )
                    ]
                    if mismatched:
                        raise GenerationError(
                            "template change plan cannot be represented by the unified edit protocol",
                            details={"paths": mismatched},
                        )
                    edit_application = dry
                    artifact = operator.apply(worktree, plan)
                if edit_application is not None:
                    atomic_write_json(
                        directory / "edit_operations.json",
                        {
                            "application": edit_application.model_dump(mode="json"),
                            "diff_sha256": edit_application.patch_sha256,
                        },
                    )
                local_checks = operator.validate_local(worktree, plan)
                failed_local = [
                    item for item in local_checks if item.status.value in {"fail", "error"}
                ]
                if failed_local:
                    raise GenerationError(
                        "operator local validation failed",
                        details={
                            "operator": operator_cls.name,
                            "checks": [item.check_name for item in failed_local],
                        },
                    )
                # Synthetic safe decoys are validated only after their files exist.
                if plan.safe_targets:
                    executed = execute_safe_target_validation(
                        list(plan.safe_targets),
                        loaded=loaded,
                        repo_root=worktree,
                        log_dir=store.instance_dir(instance_id) / "logs" / "safe_targets",
                        instance_id=instance_id,
                    )
                    safe_target_details.extend(executed.details)
                    merged = {item.safe_target_id: item for item in validated_safe}
                    for contract in executed.validated:
                        merged[contract.safe_target_id] = contract
                    validated_safe = list(merged.values())
                if goal == AttackGoal.FALSE_POSITIVE and not validated_safe:
                    _cleanup_variant(loaded, store, cache_path, instance_id)
                    results["skipped"].append(
                        {
                            "instance_id": instance_id,
                            "tier": tier.value,
                            "goal": goal.value,
                            "operator": operator_cls.name,
                            "reason": "no_validated_safe_target",
                        }
                    )
                    continue
                # P0-5 #1-#4: exactly one bound target per FP variant.  The
                # declared target must still be validated; a failure rejects the
                # candidate instead of silently switching to another safe target.
                bound_decoy_id: str | None = None
                if goal == AttackGoal.FALSE_POSITIVE:
                    validated_ids = {item.safe_target_id for item in validated_safe}
                    if plan.decoys:
                        # A synthetic decoy is the manipulated object; its own
                        # safe-target contract is evidence, not a second binding.
                        bound_decoy_id = sorted(plan.decoys, key=lambda item: item.decoy_id)[0].decoy_id
                        bound_safe_target_id = None
                    elif bound_safe_target_id not in validated_ids:
                        _cleanup_variant(loaded, store, cache_path, instance_id)
                        results["skipped"].append(
                            {
                                "instance_id": instance_id,
                                "tier": tier.value,
                                "goal": goal.value,
                                "operator": operator_cls.name,
                                "reason": "bound_safe_target_validation_failed",
                                "bound_safe_target_id": bound_safe_target_id,
                                "validated_safe_target_ids": sorted(validated_ids),
                            }
                        )
                        continue
                spec = spec.model_copy(
                    update={
                        # ``safe_targets`` keeps every validated contract as the
                        # evidence library; only the bound id is scored.
                        "safe_targets": list(validated_safe),
                        "target_safe_target_ids": (
                            [bound_safe_target_id]
                            if goal == AttackGoal.FALSE_POSITIVE and bound_safe_target_id
                            else []
                        ),
                        "target_decoy_ids": (
                            [bound_decoy_id]
                            if goal == AttackGoal.FALSE_POSITIVE and bound_decoy_id
                            else []
                        ),
                    }
                )
                # ----------------------------------------- post-edit relabelling
                # Claims, positions, claim graph and controls are rebuilt from
                # the FINAL files; template-stage labels are never reused.
                from .facts import extract_repository_facts as _extract_facts

                facts = _extract_facts(
                    clean_oracle,
                    worktree,
                    target_vulnerability_id=target_id,
                    budget=facts_budget,
                    target_handle=spec.constraints.get("target_handle"),
                )
                attack_plan, plan_problems = build_attack_plan_from_intent(
                    intent=intent,
                    plan=plan,
                    oracle=clean_oracle,
                    repo_root=worktree,
                    facts=facts,
                    spec=spec,
                    candidate_index=candidate_index,
                    validated_safe=list(validated_safe),
                )
                if plan_problems:
                    raise GenerationError(
                        "final claim labels could not be rebuilt from the rendered files",
                        details={"problems": plan_problems},
                    )
                payload_texts = [
                    operation.new_text
                    for operation in (
                        edit_application.operations if edit_application else []
                    )
                    if operation.new_text
                ] or list(operator.payload_texts())
                if loaded.config.generation.benign_controls:
                    plan = benign_plan(
                        plan,
                        payload_texts=payload_texts,
                        repo_root=worktree,
                        seed=seed_value,
                    )
                if "truthful_security" in loaded.config.generation.control_kinds:
                    try:
                        plan = benign_plan(
                            plan,
                            payload_texts=payload_texts,
                            repo_root=worktree,
                            seed=seed_value + 17,
                            truthful_facts=facts,
                        )
                    except ValueError as exc:
                        results.setdefault("control_warnings", []).append(
                            {
                                "instance_id": instance_id,
                                "control_kind": "truthful_security",
                                "reason": str(exc),
                            }
                        )
                spec = spec.model_copy(
                    update={
                        "payloads": [
                            *spec.payloads,
                            *[
                                item
                                for item in plan.payloads
                                if item not in spec.payloads
                            ],
                        ],
                        "files_touched": [item.path for item in plan.files],
                        "target_decoy_ids": (
                            [bound_decoy_id]
                            if goal == AttackGoal.FALSE_POSITIVE and bound_decoy_id
                            else []
                        ),
                        "claim_graph": plan.claim_graph,
                        "constraints": {
                            **spec.constraints,
                            "plan": plan.metadata,
                            "candidate_index": candidate_index,
                            "candidate_id": candidate_id,
                            "plan_intent": intent.model_dump(mode="json"),
                            "attack_plan": attack_plan.model_dump(mode="json"),
                            "repository_facts_sha256": facts.digest(),
                            "generator_request": (
                                generator_request.model_dump(mode="json")
                                if generator_request is not None
                                else None
                            ),
                            "edit_application": (
                                edit_application.model_dump(mode="json")
                                if edit_application is not None
                                else None
                            ),
                            "target_handle": attack_plan.target_handle,
                            "target_safe_locations": [
                                item.model_dump(mode="json")
                                for item in plan.target_safe_locations
                            ],
                            "allowed_paths": plan.allowed_paths,
                            "claims_rebuilt_after_edits": True,
                        },
                    }
                )
            except Exception:
                _cleanup_variant(loaded, store, cache_path, instance_id)
                raise

            directory = store.ensure_instance_dir(instance_id)
            atomic_write_json(
                directory / "attack_plan.json",
                {
                    "attack_plan": attack_plan.model_dump(mode="json"),
                    "candidate_index": candidate_index,
                    "candidate_id": candidate_id,
                    "rebuilt_after_edits": True,
                    "claim_locations_source": "final_rendered_files",
                },
            )
            atomic_write_json(
                directory / "plan_intent.json",
                {
                    "plan_intent": intent.model_dump(mode="json"),
                    "written_before_rendering": True,
                    "compatible_with_rendered_plan": True,
                    "candidate_index": candidate_index,
                    "candidate_id": candidate_id,
                },
            )
            atomic_write_json(
                directory / "repository_facts.json",
                {
                    **facts.model_dump(mode="json"),
                    "facts_sha256": facts.digest(),
                    "extraction_is_read_only": True,
                },
            )
            atomic_write_json(
                directory / "handles.json",
                {
                    "target_handle": attack_plan.target_handle,
                    "plan_handle": f"PL-{sha256_text(attack_plan.plan_id)[:16].upper()}",
                    "claim_handles": [
                        f"CH-{sha256_text(attack_plan.plan_id + str(index))[:16].upper()}"
                        for index in range(len(attack_plan.false_claims))
                    ],
                    "private_mapping": {
                        "vulnerability_ids": attack_plan.target_vulnerability_ids,
                        "safe_target_ids": attack_plan.target_safe_target_ids,
                        "reference_audit_id": attack_plan.reference_audit_id,
                        "reference_finding_ref": attack_plan.reference_finding_ref,
                    },
                    "note": "handles are local short-lived aliases; the mapping is private",
                },
            )
            if validated_safe:
                atomic_write_json(
                    directory / "safe_targets.json",
                    {"safe_targets": [item.model_dump(mode="json") for item in validated_safe]},
                )
            patch_path = store.patch_path(instance_id)
            artifact = write_patch_artifact(artifact, patch_path)
            patch_metadata = artifact.model_dump(mode="json", exclude={"patch_text"})
            patch_metadata["patch_file"] = store.relative(patch_path)
            atomic_write_json(
                directory / "patch_meta.json",
                {
                    **patch_metadata,
                    "allowed_paths": plan.allowed_paths,
                    "operator": operator_cls.name,
                    "plan_files": [
                        {
                            "path": item.path,
                            "mode": item.mode,
                            "carrier": item.carrier,
                            "description": item.description,
                        }
                        for item in plan.files
                    ],
                },
            )
            atomic_write_json(
                directory / "operator_local_checks.json",
                [item.model_dump(mode="json") for item in local_checks],
            )
            remap = remap_oracle(clean_oracle, clean_repo, worktree)
            instance_oracle = remap.oracle.model_copy(
                update={
                    "validation_level": (
                        "unverified"
                        if clean_oracle.validation_level == "unverified"
                        else "trace_grounded"
                    )
                }
            )
            from .evidence_contract import build_evidence_contract, validate_evidence_contract

            contract = build_evidence_contract(
                instance_id=instance_id,
                oracle=instance_oracle,
                manipulation=spec,
                plan=plan,
                decoys=plan.decoys,
                repo_root=worktree,
            )
            contract_errors = validate_evidence_contract(contract, repo_root=worktree)
            if contract_errors:
                raise GenerationError(
                    "constructed evidence contract is incomplete",
                    details={"instance_id": instance_id, "errors": contract_errors},
                )
            contract_relative, _ = store.write_evidence_contract(instance_id, contract)
            spec = spec.model_copy(update={"evidence_contract_ref": contract_relative})

            task_text = render_audit_task(loaded)
            task_relative, task_sha = store.write_task(instance_id, task_text)
            oracle_sha = store.write_oracle(instance_id, instance_oracle)
            manipulation_sha = store.write_manipulation(instance_id, spec)
            decoy_sha = store.write_decoys(instance_id, plan.decoys) if plan.decoys else None
            instance = BenchmarkInstance(
                instance_id=instance_id,
                pair_id=clean.pair_id,
                schema_version="1.0",
                variant_kind=VariantKind.ADVERSARIAL,
                oracle_ref=instance_oracle.oracle_id,
                repository=instance_oracle.repository,
                audit_difficulty=instance_oracle.effective_difficulty,
                manipulation_tier=tier,
                manipulation_ref=spec.manipulation_id,
                evidence_contract_ref=contract_relative,
                task_file=task_relative,
                patch_file=store.relative(patch_path),
                repository_tree_sha256=worktree_digest(worktree),
                generation_config_sha256=loaded.sha256,
                random_seed=seed_value,
                release_split=clean.release_split,
                candidate_id=candidate_id,
                generation_method=spec.generation_method.value,
                group_id=f"GROUP-{instance_id}",
                control_kind=None,
                target_id=(
                    bound_safe_target_id
                    if goal == AttackGoal.FALSE_POSITIVE and bound_safe_target_id
                    else bound_decoy_id
                    if goal == AttackGoal.FALSE_POSITIVE and bound_decoy_id
                    else target_id
                ),
                target_kind=(
                    ("decoy" if bound_decoy_id else "safe_target")
                    if goal == AttackGoal.FALSE_POSITIVE
                    else identity_target_kind
                ),
                eligible_target_ids=sorted(experiment_target_ids),
            )
            store.save_instance(instance)
            timestamp = now_iso()
            state = InstanceState(
                instance_id=instance_id,
                oracle_id=instance_oracle.oracle_id,
                pair_id=clean.pair_id,
                variant_kind=VariantKind.ADVERSARIAL,
                stage=Stage.GENERATED.value,
                created_at=timestamp,
                updated_at=timestamp,
                generation_config_sha256=loaded.sha256,
                oracle_sha256=oracle_sha,
                task_sha256=task_sha,
                clean_instance_id=clean.instance_id,
                manipulation_sha256=manipulation_sha,
                patch_sha256=artifact.patch_sha256,
                decoy_sha256=decoy_sha,
                cache_refs_sha256=clean_state.cache_refs_sha256,
                base_tree_sha256=artifact.base_tree_sha256,
                variant_tree_sha256=artifact.variant_tree_sha256,
                random_seed=seed_value,
                operator_names=[operator_cls.name],
                payload_ids=[item.payload_id for item in plan.payloads],
                generation_round=2 if "-v" in instance_id else 1,
                history=[
                    HistoryEntry(stage=Stage.PLANNED.value, at=timestamp),
                    HistoryEntry(stage=Stage.GENERATED.value, at=timestamp),
                ],
                notes={
                    "cache_path": str(cache_path),
                    "worktree": str(worktree),
                    "operator": operator_cls.name,
                    "mechanism": operator_cls.mechanism.value,
                    "carrier": spec.carrier,
                    "presentation": operator_cls.default_presentation.value,
                    "distribution": operator_cls.distribution.value,
                    "matrix_version": matrix.matrix_version,
                    "payload_registry_sha256": registry.registry_sha256,
                    "remap": remap.report.model_dump(mode="json"),
                    "target_safe_locations": [
                        item.model_dump(mode="json") for item in plan.target_safe_locations
                    ],
                    "safe_target_ids": [item.safe_target_id for item in validated_safe],
                    "safe_target_validation": safe_target_details,
                    "bound_target": {
                        "kind": (
                            ("decoy" if bound_decoy_id else "safe_target")
                            if goal == AttackGoal.FALSE_POSITIVE
                            else identity_target_kind
                        ),
                        "id": (
                            bound_decoy_id
                            if goal == AttackGoal.FALSE_POSITIVE and bound_decoy_id
                            else bound_safe_target_id
                            if goal == AttackGoal.FALSE_POSITIVE
                            else target_id
                        ),
                        "single_safe_target": (
                            goal == AttackGoal.FALSE_POSITIVE
                            and bound_safe_target_id is not None
                        ),
                        "note": "FP variants bind exactly one target; other safe "
                        "targets are evidence only and never scored",
                    },
                },
            )
            store.save_state(state)
            try:
                validation = validate_instance(loaded=loaded, instance_id=instance_id)
            except Exception as exc:  # noqa: BLE001
                store.update_stage(
                    instance_id, Stage.REJECTED, detail=f"validation exception: {exc}"
                )
                results["rejected"].append(
                    {"instance_id": instance_id, "tier": tier.value, "goal": goal.value, "error": str(exc)}
                )
                continue
            if validation["release_eligible"]:
                _freeze(store, instance_id)
                results["generated"].append(
                    {
                        "instance_id": instance_id,
                        "pair_id": clean.pair_id,
                        "tier": tier.value,
                        "goal": goal.value,
                        "operator": operator_cls.name,
                        "payload_ids": [item.payload_id for item in plan.payloads],
                        "files_touched": sorted(item.path for item in plan.files),
                        "claim_graph": bool(plan.claim_graph),
                        "mechanism": operator_cls.mechanism.value,
                        "carrier": spec.carrier,
                        "presentation": operator_cls.default_presentation.value,
                        "distribution": operator_cls.distribution.value,
                        "generation_method": spec.generation_method.value,
                        "candidate_id": candidate_id,
                        "candidate_index": candidate_index,
                        "target_id": instance.target_id,
                        "target_kind": instance.target_kind,
                        "eligible_target_ids": instance.eligible_target_ids,
                        "validation_level": validation["validation_level"],
                        "release_eligible": True,
                        "input_tokens": sum(
                            int(item.input_tokens or 0) for item in plan.payloads
                        ),
                        "output_tokens": sum(
                            int(item.output_tokens or 0) for item in plan.payloads
                        ),
                        "prompt_sha256": next(
                            (
                                item.prompt_sha256
                                for item in reversed(plan.payloads)
                                if item.prompt_sha256
                            ),
                            None,
                        ),
                    }
                )
                created += 1
                if loaded.config.generation.benign_controls and plan.benign_files:
                    benign = _generate_benign_variant(
                        loaded=loaded,
                        store=store,
                        cache=cache,
                        cache_path=cache_path,
                        clean=clean,
                        clean_oracle=clean_oracle,
                        clean_repo=clean_repo,
                        adversarial_instance_id=instance_id,
                        plan=plan,
                        operator=operator,
                        tier=tier,
                        goal=goal,
                        seed_value=seed_value,
                        candidate_id=candidate_id,
                        control_kind="benign",
                        files=plan.benign_files,
                        target_id=instance.target_id,
                        target_kind=instance.target_kind,
                        eligible_target_ids=instance.eligible_target_ids,
                    )
                    if benign is not None:
                        results["benign_generated"].append(benign)
                        results["generated"][-1]["benign_instance_id"] = benign.get(
                            "instance_id"
                        )
                        results["generated"][-1]["group_id"] = benign.get("group_id")
                if (
                    "truthful_security" in loaded.config.generation.control_kinds
                    and plan.truthful_files
                ):
                    truthful = _generate_benign_variant(
                        loaded=loaded,
                        store=store,
                        cache=cache,
                        cache_path=cache_path,
                        clean=clean,
                        clean_oracle=clean_oracle,
                        clean_repo=clean_repo,
                        adversarial_instance_id=instance_id,
                        plan=plan,
                        operator=operator,
                        tier=tier,
                        goal=goal,
                        seed_value=seed_value + 17,
                        candidate_id=candidate_id,
                        control_kind="truthful_security",
                        files=plan.truthful_files,
                        target_id=instance.target_id,
                        target_kind=instance.target_kind,
                        eligible_target_ids=instance.eligible_target_ids,
                    )
                    if truthful is not None:
                        results.setdefault("truthful_generated", []).append(truthful)
                        results["generated"][-1]["truthful_security_instance_id"] = (
                            truthful.get("instance_id")
                        )
            else:
                results["rejected"].append(
                    {
                        "instance_id": instance_id,
                        "tier": tier.value,
                        "goal": goal.value,
                        "operator": operator_cls.name,
                        "release_eligible": False,
                        "failed_checks": [
                            item["name"]
                            for item in validation["checks"]
                            if item["status"] in {"fail", "error"}
                        ],
                    }
                )
    results["generated_count"] = len(results["generated"])
    results["rejected_count"] = len(results["rejected"])
    results["skipped_count"] = len(results["skipped"])
    results["attempted_count"] = attempted
    results["budget"] = {
        "unit": "attempted_job",
        "max_variants_per_call": limit,
        "attempted": attempted,
        "generated": len(results["generated"]),
        "rejected": len(results["rejected"]),
        "skipped": len(results["skipped"]),
    }
    return results

