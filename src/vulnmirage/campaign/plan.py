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

from pydantic import BaseModel, ConfigDict, Field

from ..campaign.task_prompt import (
    TASK_PROMPT_RULE_VERSION,
    build_effective_task,
    output_contract_section,
)
from ..campaign.variants import default_variants
from ..config import LoadedConfig, VariantSpecConfig
from ..errors import CampaignError
from ..hashing import atomic_write_json, sha256_file, sha256_text, utc_now_iso
from ..ingest.dataset_core import DatasetCore, load_dataset_core
from ..repository.archive import resolve_archive_request

PLAN_SCHEMA_VERSION = "1.1"


class PlanVariant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    variant_id: str
    kind: str
    payload_id: str | None = None
    method_id: str | None = None
    reproduction_status: str | None = None
    source_url: str | None = None
    carrier: str | None = None
    goal: str = "none"
    knowledge: str = "public_context"
    edit_count: int = 0
    edit_paths: list[str] = Field(default_factory=list)


class VariantSetDefinition(BaseModel):
    """One pre-registered group of conditions for a single research question."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    variant_set_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    research_question: str = Field(min_length=1)
    variants: list[VariantSpecConfig]


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
    source_prompt_sha256: str
    effective_prompt_sha256: str
    task_prompt_rule_version: str
    variants: list[PlanVariant] = Field(default_factory=list)
    repetitions: int = 1


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
    payload_assets_sha256: dict[str, str] = Field(default_factory=dict)
    task_prompt_rule_version: str = TASK_PROMPT_RULE_VERSION
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
    if isinstance(payload, list):
        payload = {
            "variant_set_id": path.stem,
            "research_question": "legacy variant list",
            "variants": payload,
        }
    elif isinstance(payload, dict):
        payload = dict(payload)
        payload.setdefault("variant_set_id", path.stem)
        payload.setdefault("research_question", "legacy variant set")
    else:
        raise CampaignError(
            "variant set must be a mapping or list", details={"path": str(path)}
        )
    try:
        definition = VariantSetDefinition.model_validate(payload)
    except Exception as exc:
        raise CampaignError(
            "invalid variant set", details={"path": str(path), "error": str(exc)}
        ) from exc
    if not definition.variants:
        raise CampaignError("variant set declares no variants", details={"path": str(path)})
    clean_ids = [item.variant_id for item in definition.variants if item.kind == "clean"]
    if clean_ids != ["C"]:
        raise CampaignError(
            "variant set must declare exactly one clean baseline named C",
            details={"path": str(path), "clean_variant_ids": clean_ids},
        )
    from ..payloadgen import validate_payload_references

    catalog = loaded.resolve_asset(config.payload_catalog) if config.payload_catalog else None
    validate_payload_references(definition.variants, catalog)
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


def _plan_variant(spec: VariantSpecConfig, methods: dict[str, object]) -> PlanVariant:
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
    return PlanVariant(
        variant_id=spec.variant_id,
        kind=spec.kind,
        payload_id=spec.payload_id,
        method_id=spec.method_id or getattr(method, "method_family", None),
        reproduction_status=getattr(method, "reproduction_status", None),
        source_url=getattr(method, "source_url", None),
        carrier=spec.carrier or getattr(method, "carrier", None),
        goal=getattr(method, "objective", spec.goal),
        knowledge=spec.knowledge,
        edit_count=(1 if spec.payload_id else len(spec.edits)),
        edit_paths=edit_paths,
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
    write: bool = True,
) -> PlanDoc:
    """Read the task index and freeze the campaign plan."""
    config = loaded.config
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
                source_prompt_sha256=effective.source_prompt_sha256,
                effective_prompt_sha256=effective.effective_prompt_sha256,
                task_prompt_rule_version=effective.rule_version,
                variants=[_plan_variant(spec, payload_methods) for spec in specs],
                repetitions=config.campaign.repetitions,
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
        payload_assets_sha256=payload_hashes,
        task_prompt_rule_version=config.campaign.task_prompt_rule_version,
        tasks=tasks,
        budget=PlanBudget(
            repetitions=config.campaign.repetitions,
            max_tasks=config.campaign.max_tasks_per_campaign,
            max_workers=config.campaign.max_workers,
            audits_per_task=len(specs) * config.campaign.repetitions,
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
    "PlanVariant",
    "VariantSetDefinition",
    "build_plan",
    "generation_asset_hashes",
    "load_plan",
    "load_variant_set",
    "plan_fingerprint",
    "plan_path",
    "plan_task",
]
