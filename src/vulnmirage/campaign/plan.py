"""The campaign plan: what is frozen before the first run.

``control/plan.json`` is the control plane.  It records which task is being run,
which variants were declared, how many repetitions each cell gets, and which
invariants are on for every cell.  It deliberately contains **no target ids, no
advisory titles and no fix commits**: the plan is control data, and control data
gets published and copied around, so it is written as if it might leak.

Planning is offline: it reads the task index, hashes the normalized task prompt and
writes the plan.  It never downloads a repository and never calls a model.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..campaign.task_prompt import (
    TASK_PROMPT_RULE_VERSION,
    build_effective_task,
    output_contract_section,
)
from ..campaign.variants import default_variants
from ..config import LoadedConfig, VariantSpecConfig
from ..errors import CampaignError
from ..hashing import atomic_write_json, sha256_file, sha256_text, stable_id, utc_now_iso
from ..ingest.dataset_core import DatasetCore, load_dataset_core
from ..repository.archive import resolve_archive_request

PLAN_SCHEMA_VERSION = "3.0"


class PlanVariant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    variant_id: str
    base_variant_id: str = ""
    target_ref: str | None = None
    condition_id: str = ""
    kind: str
    generator_tier: str = "T0"
    realization_id: str | None = None
    method_id: str | None = None
    taxonomy_version: str | None = None
    threat_model_id: str | None = None
    objective: str = "none"
    primary_mechanism: str | None = None
    surface: dict[str, str] | None = None
    intensity: str | None = None
    dose: dict[str, object] | None = None
    reproduction_status: str | None = None
    source_url: str | None = None
    carrier: str | None = None
    generator_profile: str = "default"
    candidate_budget: int = 1
    selection_policy: str = "semantic_fit_then_deterministic_tiebreak"
    edit_count: int = 0
    edit_paths: list[str] = Field(default_factory=list)

    @property
    def tier(self) -> str:
        return self.generator_tier

    @property
    def payload_id(self) -> str | None:
        return self.realization_id

    @property
    def goal(self) -> str:
        return self.objective

    @property
    def knowledge(self) -> str:
        return "oracle_guided" if self.generator_tier in {"T2", "T3", "T4"} else "public_context"


class PlanTierProfile(BaseModel):
    """The generation rules a tier is frozen with (design §5.1)."""

    model_config = ConfigDict(extra="forbid")

    tier: str
    generator_profile: str = "default"
    candidate_budget: int = 1
    selection_policy: str = "semantic_fit_then_deterministic_tiebreak"
    #: ``None`` means the method's own placement limit applies.
    max_files_changed: int | None = None
    max_inserted_lines: int | None = None
    max_payload_chars: int | None = None
    max_model_calls: int = 0


class PlanGeneration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seed: int = 0
    candidate_budget: int = 3
    require_candidate_validation: bool = True
    tier_profiles: dict[str, PlanTierProfile] = Field(default_factory=dict)


class VariantSetDefinition(BaseModel):
    """One pre-registered group of conditions for a single research question."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["2.0"] = "2.0"
    taxonomy_version: Literal["vm-atk-1.0"] = "vm-atk-1.0"
    threat_model_id: str = Field(min_length=1)
    primary_objective: str = Field(
        pattern=r"^O-(FN|FP|SEV-D|SEV-I|EV|SCOPE|AVAIL)$"
    )
    variant_set_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    research_question: str = Field(min_length=1)
    variants: list[VariantSpecConfig]


class PlanTarget(BaseModel):
    """Opaque target identity frozen without publishing the oracle target id."""

    model_config = ConfigDict(extra="forbid")

    target_ref: str
    ordinal: int = Field(ge=0)


class PlanRunCell(BaseModel):
    """One pre-randomized audit cell in the order it must execute."""

    model_config = ConfigDict(extra="forbid")

    order: int = Field(ge=0)
    repetition: int = Field(ge=1)
    variant_id: str


class PlanTask(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str
    snapshot_id: str
    repo_id: str
    repo_url: str
    commit_sha: str
    archive_source_id: str
    primary_language: str | None = None
    target_count: int = 0
    eligible_target_count: int = 0
    selected_target_count: int = 0
    targets: list[PlanTarget] = Field(default_factory=list)
    source_prompt_sha256: str
    effective_prompt_sha256: str
    task_prompt_rule_version: str
    variants: list[PlanVariant] = Field(default_factory=list)
    repetitions: int = 1
    run_order: list[PlanRunCell] = Field(default_factory=list)


class PlanBudget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repetitions: int = 1
    max_tasks: int = 1
    max_workers: int = 1
    audits_per_task: int = 0
    note: str = (
        "one run per declared clean or attack variant per repetition; "
        "the count is fixed before any result is seen"
    )


class PlanInvariants(BaseModel):
    """Run conditions that are **not** experimental variables."""

    model_config = ConfigDict(extra="forbid")

    oracle_isolation: str = "always_on"
    workspace_containment: str = "always_on"
    egress_probe: str = "always_on"
    history_absent: str = "always_on"
    fresh_state: str = "always_on"
    task_prompt: str = "identical across every variant of a task"
    scoring: str = "after the run, in the verifier process"
    note: str = (
        "these are enforced for the clean baseline and every injected variant; a run that "
        "does not satisfy them is ineligible, it is not an attack outcome"
    )


class PlanDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = PLAN_SCHEMA_VERSION
    created_at: str = Field(default_factory=utc_now_iso)
    config_sha256: str
    dataset_root: str
    dataset_manifest_sha256: str | None = None
    tasks_file: str | None = None
    oracle_file: str | None = None
    archive_root: str
    variant_set_id: str = "inline"
    variant_set_file: str | None = None
    variant_set_sha256: str | None = None
    research_question: str = ""
    taxonomy_version: str | None = None
    threat_model_id: str | None = None
    primary_objective: str | None = None
    payload_assets_sha256: dict[str, str] = Field(default_factory=dict)
    task_prompt_rule_version: str = TASK_PROMPT_RULE_VERSION
    generation: PlanGeneration = Field(default_factory=PlanGeneration)
    tasks: list[PlanTask] = Field(default_factory=list)
    budget: PlanBudget = Field(default_factory=PlanBudget)
    invariants: PlanInvariants = Field(default_factory=PlanInvariants)
    notes: list[str] = Field(default_factory=list)


def plan_path(archive_root: Path) -> Path:
    return Path(archive_root) / "control" / "plan.json"


def load_variant_set(loaded: LoadedConfig) -> VariantSetDefinition | None:
    config = loaded.config.campaign
    if not config.variants_file:
        return None
    path = loaded.resolve_asset(config.variants_file)
    import yaml

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise CampaignError("variant set must be a mapping", details={"path": str(path)})
    forbidden_identity_keys = {
        "tier",
        "payload_id",
        "goal",
        "knowledge",
        "method_id",
        "carrier",
        "objective",
    }
    authored_identity = {
        str(item.get("variant_id") or "<missing>"): sorted(
            forbidden_identity_keys & set(item)
        )
        for item in (payload.get("variants") or [])
        if isinstance(item, dict) and forbidden_identity_keys & set(item)
    }
    if authored_identity:
        raise CampaignError(
            "variant rows may not override catalog-derived attack identity",
            details={"path": str(path), "fields": authored_identity},
        )
    try:
        definition = VariantSetDefinition.model_validate(payload)
    except Exception as exc:
        raise CampaignError(
            "invalid variant set", details={"path": str(path), "error": str(exc)}
        ) from exc
    if not definition.variants:
        raise CampaignError("variant set declares no variants", details={"path": str(path)})
    unregistered = [
        item.variant_id
        for item in definition.variants
        if item.kind == "attack" and not item.realization_id
    ]
    if unregistered:
        raise CampaignError(
            "formal attack variants must reference a registered realization",
            details={"path": str(path), "variant_ids": unregistered},
        )
    inline_attacks = [
        item.variant_id
        for item in definition.variants
        if item.kind == "attack" and item.edits
    ]
    if inline_attacks:
        raise CampaignError(
            "formal variant sets may not contain arbitrary inline attack edits",
            details={"path": str(path), "variant_ids": inline_attacks},
        )
    clean_ids = [item.variant_id for item in definition.variants if item.kind == "clean"]
    if clean_ids != ["C"]:
        raise CampaignError(
            "variant set must declare exactly one clean baseline named C",
            details={"path": str(path), "clean_variant_ids": clean_ids},
        )
    from ..payloadgen import validate_payload_references

    catalog = loaded.resolve_asset(config.payload_catalog) if config.payload_catalog else None
    validate_payload_references(
        definition.variants,
        catalog,
        threat_model_id=definition.threat_model_id,
        primary_objective=definition.primary_objective,
    )
    return definition


def _variant_specs(loaded: LoadedConfig) -> list[VariantSpecConfig]:
    config = loaded.config.campaign
    definition = load_variant_set(loaded)
    if definition is not None:
        return list(definition.variants)
    if config.variants:
        specs = list(config.variants)
        from ..payloadgen import validate_payload_references

        catalog = (
            loaded.resolve_asset(config.payload_catalog) if config.payload_catalog else None
        )
        validate_payload_references(specs, catalog)
        return specs
    return default_variants()


def _plan_variant(
    spec: VariantSpecConfig,
    methods: dict[str, object],
    generation: PlanGeneration | None = None,
    *,
    variant_id: str | None = None,
    target_ref: str | None = None,
    threat_model_id: str | None = None,
) -> PlanVariant:
    method = methods.get(str(spec.payload_id)) if spec.payload_id else None
    placement = getattr(method, "placement", None)
    output_path = getattr(method, "output_path", None)
    if spec.payload_id:
        edit_paths = (
            [str(output_path)]
            if output_path
            else [
                "<verified-target-source-file>"
                if placement == "target_file_footer"
                else "<resolved>"
            ]
        )
    else:
        edit_paths = sorted({edit.path for edit in spec.edits})
    tier = str(spec.generator_tier)
    profile = generation.tier_profiles.get(tier) if generation else None
    return PlanVariant(
        variant_id=variant_id or spec.variant_id,
        base_variant_id=spec.variant_id,
        target_ref=target_ref,
        condition_id=variant_id or spec.variant_id,
        kind=spec.kind,
        generator_tier=tier,
        realization_id=spec.realization_id,
        method_id=spec.method_id or getattr(method, "method_id", None),
        taxonomy_version=("vm-atk-1.0" if method else None),
        threat_model_id=threat_model_id,
        objective=getattr(method, "objective", spec.objective),
        primary_mechanism=getattr(method, "primary_mechanism", None),
        surface=(
            method.surface.model_dump(mode="json")  # type: ignore[union-attr]
            if method is not None
            else None
        ),
        intensity=getattr(method, "intensity", None),
        dose=(
            method.dose.model_dump(mode="json")  # type: ignore[union-attr]
            if method is not None
            else None
        ),
        reproduction_status=getattr(method, "reproduction_status", None),
        source_url=getattr(method, "source_url", None),
        carrier=spec.carrier or getattr(method, "carrier", None),
        generator_profile=(profile.generator_profile if profile else "default"),
        candidate_budget=(profile.candidate_budget if profile else 1),
        selection_policy=(
            profile.selection_policy
            if profile
            else "semantic_fit_then_deterministic_tiebreak"
        ),
        edit_count=(1 if spec.realization_id else len(spec.edits)),
        edit_paths=edit_paths,
    )


def plan_generation(loaded: LoadedConfig) -> PlanGeneration:
    """Freeze the generation envelope: seed, tier profiles, budgets."""
    generation = loaded.config.campaign.generation
    profiles = {
        tier: PlanTierProfile(
            tier=profile.tier,
            generator_profile=profile.generator_profile,
            candidate_budget=profile.candidate_budget,
            selection_policy=profile.selection_policy,
            max_files_changed=profile.max_files_changed,
            max_inserted_lines=profile.max_inserted_lines,
            max_payload_chars=profile.max_payload_chars,
            max_model_calls=profile.max_model_calls,
        )
        for tier, profile in sorted(generation.tier_profiles.items())
    }
    return PlanGeneration(
        seed=generation.seed,
        candidate_budget=generation.candidate_budget,
        require_candidate_validation=generation.require_candidate_validation,
        tier_profiles=profiles,
    )


def generation_asset_hashes(loaded: LoadedConfig) -> dict[str, str]:
    """Hash every external file that can change a generated variant."""
    config = loaded.config.campaign
    result: dict[str, str] = {}
    if config.payload_catalog:
        from ..payloadgen import payload_asset_hashes

        result.update(payload_asset_hashes(loaded.resolve_asset(config.payload_catalog)))
    if config.variants_file:
        variants_path = loaded.resolve_asset(config.variants_file)
        result[f"variants:{variants_path.name}"] = sha256_file(variants_path)
    return dict(sorted(result.items()))


def build_plan(
    loaded: LoadedConfig,
    *,
    dataset_root: str | Path | None = None,
    task_ids: list[str] | None = None,
    limit: int | None = None,
    archive_root: str | Path | None = None,
    target_limit: int | None = None,
    write: bool = True,
) -> PlanDoc:
    """Read the task index and freeze the campaign plan."""
    config = loaded.config
    if limit is not None and limit < 1:
        raise CampaignError("--limit must be at least 1", details={"limit": limit})
    if target_limit is not None and not 1 <= target_limit <= 500:
        raise CampaignError(
            "--target-limit must be between 1 and 500",
            details={"target_limit": target_limit},
        )
    root = dataset_root or config.campaign.dataset_root
    workspace = Path(archive_root or config.campaign.archive_root)
    if not workspace.is_absolute():
        workspace = (Path.cwd() / workspace).resolve()
    core: DatasetCore = load_dataset_core(
        Path(root),
        tasks_file=config.campaign.tasks_file,
        oracle_file=config.campaign.oracle_file,
        strict=True,
    )
    template = loaded.resolve_asset(config.campaign.audit_task_template)
    # Fail now, not mid-run, if the contract section disappeared from the template.
    output_contract_section(template)

    selected: list[str]
    if task_ids:
        missing = [item for item in task_ids if item not in core.tasks]
        if missing:
            raise CampaignError("unknown task_id(s)", details={"missing": missing})
        selected = list(task_ids)
    else:
        selected = core.task_ids()
    cap = limit if limit is not None else config.campaign.max_tasks_per_campaign
    selected = selected[:cap]
    if not selected:
        raise CampaignError("no task selected", details={"dataset_root": str(root)})

    specs = _variant_specs(loaded)
    variant_set = load_variant_set(loaded)
    generation = plan_generation(loaded)
    from ..tiers import is_implemented

    for spec in specs:
        if spec.kind != "attack":
            continue
        if not is_implemented(str(spec.tier)):
            from ..errors import UnsupportedTierError

            raise UnsupportedTierError(
                "this build implements T0-T2 only; refusing to plan the condition",
                details={"variant_id": spec.variant_id, "tier": spec.tier},
            )
        # A tier without a frozen profile would generate with an unstated budget.
        loaded.config.campaign.generation.profile_for(str(spec.tier))
    payload_methods: dict[str, object] = {}
    if config.campaign.payload_catalog:
        from ..payloadgen import load_payload_catalog

        payload_methods = load_payload_catalog(
            loaded.resolve_asset(config.campaign.payload_catalog)
        ).by_id()
    variant_ids = [item.variant_id for item in specs]
    duplicates = {variant_id for variant_id in variant_ids if variant_ids.count(variant_id) > 1}
    if duplicates:
        raise CampaignError("duplicate variant ids", details={"variant_ids": sorted(duplicates)})
    if not any(spec.kind == "clean" for spec in specs):
        raise CampaignError(
            "the plan needs a clean baseline variant",
            details={"variants": [spec.variant_id for spec in specs]},
        )

    tasks: list[PlanTask] = []
    for task_id in selected:
        task = core.task(task_id)
        effective = build_effective_task(core=core, task=task, template_path=template)
        request = resolve_archive_request(
            task.effective_repo_url, task.commit_sha, provider=config.archive.provider
        )
        eligible = core.eligible_targets(task_id)
        target_cap = (
            target_limit
            if target_limit is not None
            else config.campaign.max_targets_per_task
        )
        selected_targets = eligible[:target_cap]
        if not selected_targets:
            raise CampaignError(
                "task has no eligible target for a target-level experiment",
                details={"task_id": task_id},
            )
        plan_targets = [
            PlanTarget(
                target_ref=opaque_target_ref(task.snapshot_id, item.target_id),
                ordinal=index,
            )
            for index, item in enumerate(selected_targets)
        ]
        expanded_variants: list[PlanVariant] = []
        multiple_targets = len(plan_targets) > 1
        for target in plan_targets:
            for spec in specs:
                expanded_id = (
                    f"{spec.variant_id}--{target.target_ref}"
                    if multiple_targets
                    else spec.variant_id
                )
                expanded_variants.append(
                    _plan_variant(
                        spec,
                        payload_methods,
                        generation,
                        variant_id=expanded_id,
                        target_ref=target.target_ref,
                        threat_model_id=(variant_set.threat_model_id if variant_set else None),
                    )
                )
        run_cells = [
            (repetition, variant.variant_id)
            for repetition in range(1, config.campaign.repetitions + 1)
            for variant in expanded_variants
        ]
        run_cells.sort(
            key=lambda item: stable_id(
                "ORDER",
                generation.seed,
                task.task_id,
                item[0],
                item[1],
            )
        )
        tasks.append(
            PlanTask(
                task_id=task.task_id,
                snapshot_id=task.snapshot_id,
                repo_id=task.repo_id,
                repo_url=task.effective_repo_url,
                commit_sha=task.commit_sha,
                archive_source_id=request.source_id,
                primary_language=task.primary_language,
                target_count=len(core.targets(task_id)),
                eligible_target_count=len(eligible),
                selected_target_count=len(plan_targets),
                targets=plan_targets,
                source_prompt_sha256=effective.source_prompt_sha256,
                effective_prompt_sha256=effective.effective_prompt_sha256,
                task_prompt_rule_version=effective.rule_version,
                variants=expanded_variants,
                repetitions=config.campaign.repetitions,
                run_order=[
                    PlanRunCell(order=index, repetition=repetition, variant_id=variant_id)
                    for index, (repetition, variant_id) in enumerate(run_cells)
                ],
            )
        )

    manifest_sha = None
    manifest_file = Path(root) / "manifest.json"
    if manifest_file.is_file():
        manifest_sha = sha256_file(manifest_file)

    payload_hashes = generation_asset_hashes(loaded)

    doc = PlanDoc(
        config_sha256=loaded.sha256,
        dataset_root=Path(root).as_posix(),
        dataset_manifest_sha256=manifest_sha,
        tasks_file=core.tasks_file.name,
        oracle_file=core.oracle_file.name,
        archive_root=workspace.as_posix(),
        variant_set_id=(variant_set.variant_set_id if variant_set else "inline"),
        variant_set_file=config.campaign.variants_file,
        variant_set_sha256=(
            sha256_file(loaded.resolve_asset(config.campaign.variants_file))
            if config.campaign.variants_file
            else None
        ),
        research_question=(variant_set.research_question if variant_set else ""),
        taxonomy_version=(variant_set.taxonomy_version if variant_set else None),
        threat_model_id=(variant_set.threat_model_id if variant_set else None),
        primary_objective=(variant_set.primary_objective if variant_set else None),
        payload_assets_sha256=payload_hashes,
        task_prompt_rule_version=config.campaign.task_prompt_rule_version,
        generation=generation,
        tasks=tasks,
        budget=PlanBudget(
            repetitions=config.campaign.repetitions,
            max_tasks=config.campaign.max_tasks_per_campaign,
            max_workers=config.campaign.max_workers,
            audits_per_task=max(len(item.variants) for item in tasks)
            * config.campaign.repetitions,
        ),
        notes=[
            f"{len(tasks)} task(s) selected; empty results are still results",
            "the plan holds no target ids, advisory titles or fix commits",
            "variants are declared here and frozen before any run",
        ],
    )
    if write:
        path = plan_path(workspace)
        atomic_write_json(path, doc)
    return doc


def load_plan(path: str | Path) -> PlanDoc:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return PlanDoc.model_validate(payload)


def opaque_target_ref(snapshot_id: str, target_id: str) -> str:
    """Stable non-answer identifier used in public plan and archive paths."""
    return stable_id("TGT", snapshot_id, target_id)


def plan_fingerprint(doc: PlanDoc) -> str:
    return sha256_text(doc.model_dump_json())


def plan_task(doc: PlanDoc, task_id: str) -> PlanTask:
    for item in doc.tasks:
        if item.task_id == task_id:
            return item
    raise CampaignError(
        "task is not part of this plan",
        details={"task_id": task_id, "planned": [item.task_id for item in doc.tasks]},
    )


__all__ = [
    "PLAN_SCHEMA_VERSION",
    "PlanBudget",
    "PlanDoc",
    "PlanInvariants",
    "PlanTask",
    "PlanTarget",
    "PlanRunCell",
    "PlanVariant",
    "VariantSetDefinition",
    "build_plan",
    "generation_asset_hashes",
    "load_plan",
    "load_variant_set",
    "plan_fingerprint",
    "plan_path",
    "plan_task",
    "opaque_target_ref",
]
