"""One task, from archive to archived artefacts and cleaned scratch.

The pipeline is deliberately linear and resumable.  Each phase writes its artefacts
and advances the persisted state; the next phase reads them from disk instead of
from memory, so an interrupted campaign can be resumed without repeating an audit
or silently changing a treatment.

Exposure is a **run invariant**, not a condition: every run -- clean or injected --
gets a fresh exposed root, an egress probe and an attestation, and a run
whose attestation fails is recorded as ineligible.  A failure there is an
infrastructure result, never an attack success.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..config import LoadedConfig
from ..errors import CampaignError, GenerationError, IsolationError, VerifierError
from ..hashing import (
    atomic_write_json,
    sha256_file,
    sha256_text,
    stable_id,
    utc_now_iso,
)
from ..ingest.dataset_core import (
    DatasetCore,
    TargetRecord,
    eligibility_level,
    load_dataset_core,
)
from ..isolation.attestation import (
    IsolationAttestation,
    run_attestation,
    write_attestation,
)
from ..isolation.channels import build_control_report
from ..isolation.layout import ExposureLayout
from ..isolation.network import build_restricted_agent_environment, probe_egress
from ..mechanism.analysis import (
    RunObservation,
    analyze_exposure,
    assess_mechanisms,
    compare_trajectories,
    write_analysis,
)
from ..repository.archive import (
    ArchiveCache,
    find_history_metadata,
    resolve_archive_request,
    safe_extract,
    tree_digest,
)
from ..verifier.service import evaluate_bundle
from ..campaign.plan import (
    PlanDoc,
    PlanTask,
    build_plan,
    generation_asset_hashes,
    load_plan,
    opaque_target_ref,
    plan_fingerprint,
    plan_path,
    plan_task,
)
from ..campaign.executor import ANSWER_FILENAMES, AuditExecutor, ExecutionResult, NullExecutor
from ..campaign.state import TaskState, TaskStateStore
from ..campaign.task_prompt import (
    build_effective_task,
    target_answer_tokens,
)
from ..campaign.variants import VariantBuild, build_variant
from ..payloadgen import (
    CandidatePayload,
    CandidateValidation,
    GenerationManifest,
    GenerationRequest,
    IndexLimits,
    PlacementHint,
    PublicTaskView,
    RepositoryIndex,
    TargetRemap,
    TierBudget,
    attach_remap,
    assert_view_is_clean,
    build_oracle_attack_view,
    build_repository_index,
    candidate_to_edit,
    generate_manifest,
    load_payload_catalog,
    remap_targets,
    selected_candidate,
)
from ..tiers import INDEXED_TIERS, ORACLE_VIEW_TIERS
from ..trace.normalize import normalize_trace

PIPELINE_SCHEMA_VERSION = "1.0"


# --------------------------------------------------------------------- models
class SourceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = PIPELINE_SCHEMA_VERSION
    task_id: str
    snapshot_id: str
    provider: str
    source_id: str
    commit: str
    requested_url: str
    final_url: str
    redirect_chain: list[str] = Field(default_factory=list)
    archive_sha256: str | None = None
    archive_bytes: int | None = None
    archive_reused_from_cache: bool = False
    strip_prefix: str | None = None
    file_count: int | None = None
    total_bytes: int | None = None
    tree_sha256: str | None = None
    tree_digest_source: str = "unpacked-archive"
    history_metadata: list[str] = Field(default_factory=list)
    rejected_entries: list[dict[str, str]] = Field(default_factory=list)
    downloaded_at: str | None = None
    extracted_at: str | None = None
    notes: list[str] = Field(default_factory=list)


class TaskManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = PIPELINE_SCHEMA_VERSION
    task_id: str
    snapshot_id: str
    repo_id: str
    variant_set_id: str = "inline"
    commit_sha: str
    archive_source_id: str
    task_prompt_rule_version: str
    source_prompt_sha256: str
    effective_prompt_sha256: str
    effective_prompt_chars: int
    transformations: list[dict[str, object]] = Field(default_factory=list)
    removed_tokens_count: int = 0
    target_count: int = 0
    scored_target_count: int = 0
    excluded_targets: list[dict[str, str]] = Field(default_factory=list)
    variants: list[str] = Field(default_factory=list)
    repetitions: int = 1
    isolation_mode: str = "workspace"
    egress_mode: str = "none"
    verifier_mode: str = "separate_process"
    created_at: str = Field(default_factory=utc_now_iso)
    notes: list[str] = Field(default_factory=list)


class VariantFreeze(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = PIPELINE_SCHEMA_VERSION
    task_id: str
    source_tree_sha256: str
    builds: list[VariantBuild] = Field(default_factory=list)
    frozen_at: str = Field(default_factory=utc_now_iso)
    note: str = "each variant was built independently from the same clean snapshot"


class RunRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = PIPELINE_SCHEMA_VERSION
    run_id: str
    task_id: str
    variant_set_id: str = "inline"
    variant_id: str
    target_ref: str | None = None
    variant_kind: str
    method_id: str | None = None
    carrier: str | None = None
    goal: str | None = None
    repetition: int = 1
    executed_at: str = Field(default_factory=utc_now_iso)
    execution_status: str = "not_run"
    exit_code: int | None = None
    duration_seconds: float | None = None
    tier: str | None = None
    model: str | None = None
    agent_profile: str | None = None
    agent_config_sha256: str | None = None
    agent_external_file_sha256: dict[str, str] = Field(default_factory=dict)
    isolation_eligibility: str = "unattested"
    exposure_root: str | None = None
    trace_status: str = "missing"
    trace_completeness: str = "missing"
    trace_events: int = 0


class ArtifactEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str | None = None
    bytes: int | None = None
    producer: str = "campaign"
    status: str = "ok"


# ------------------------------------------------------------------- pipeline
class CampaignRunner:
    def __init__(
        self,
        loaded: LoadedConfig,
        *,
        dataset_root: str | Path | None = None,
        archive_root: str | Path | None = None,
        executor: AuditExecutor | None = None,
        model_label: str | None = None,
        agent_env_names: tuple[str, ...] = (),
        agent_env_allowlist: tuple[str, ...] = (),
        trace_adapter: str = "none",
        agent_profile: str | None = None,
        agent_env_overrides: dict[str, str] | None = None,
        agent_config_sha256: str | None = None,
        agent_external_file_sha256: dict[str, str] | None = None,
    ) -> None:
        self.loaded = loaded
        self.config = loaded.config
        self.dataset_root = Path(dataset_root or self.config.campaign.dataset_root)
        root = Path(archive_root or self.config.campaign.archive_root)
        self.root = root if root.is_absolute() else (Path.cwd() / root).resolve()
        self.executor = executor or NullExecutor()
        self.model_label = model_label
        self.agent_env_names = agent_env_names
        self.agent_env_allowlist = agent_env_allowlist
        self.trace_adapter = trace_adapter
        self.agent_profile = agent_profile
        self.agent_env_overrides = dict(agent_env_overrides or {})
        self.agent_config_sha256 = agent_config_sha256
        self.agent_external_file_sha256 = dict(agent_external_file_sha256 or {})
        self.core: DatasetCore | None = None
        self._plan: PlanDoc | None = None

    # ------------------------------------------------------------------ helpers
    def core_index(self) -> DatasetCore:
        if self.core is None:
            self.core = load_dataset_core(
                self.dataset_root,
                tasks_file=self.config.campaign.tasks_file,
                oracle_file=self.config.campaign.oracle_file,
                strict=True,
            )
        return self.core

    def plan(
        self,
        *,
        task_ids: list[str] | None = None,
        limit: int | None = None,
        target_limit: int | None = None,
    ) -> PlanDoc:
        if self._plan is None:
            self._plan = build_plan(
                self.loaded,
                dataset_root=self.dataset_root,
                task_ids=task_ids,
                limit=limit,
                target_limit=target_limit,
                archive_root=self.root,
            )
        return self._plan

    def use_plan(self, plan: PlanDoc) -> None:
        """Attach the exact plan supplied by the CLI instead of rediscovering it."""
        self._plan = plan

    def load_or_plan(self) -> PlanDoc:
        if self._plan is not None:
            current_assets = generation_asset_hashes(self.loaded)
            if current_assets != self._plan.payload_assets_sha256:
                raise CampaignError(
                    "payload/variant assets changed after the campaign plan was frozen",
                    details={
                        "planned": self._plan.payload_assets_sha256,
                        "current": current_assets,
                    },
                )
            return self._plan
        path = plan_path(self.root)
        if path.is_file():
            self._plan = load_plan(path)
            current_assets = generation_asset_hashes(self.loaded)
            if current_assets != self._plan.payload_assets_sha256:
                raise CampaignError(
                    "payload/variant assets changed after the campaign plan was frozen",
                    details={
                        "planned": self._plan.payload_assets_sha256,
                        "current": current_assets,
                    },
                )
            return self._plan
        return self.plan()

    @property
    def private_root(self) -> Path:
        return self.root / self.config.verifier.private_dirname

    def task_archive_dir(self, task_id: str) -> Path:
        return self.root / "archives" / task_id

    def layout(self, task_id: str, run_id: str, variant_id: str, kind: str) -> ExposureLayout:
        return ExposureLayout(
            root=self.root,
            task_id=task_id,
            run_id=run_id,
            variant_id=variant_id,
            variant_kind=kind,
        )

    # -------------------------------------------------------------------- plan
    def write_plan(self, *, dry_run: bool = False, **kwargs: object) -> dict[str, object]:
        if dry_run:
            # Resolve everything (dataset, prompt, catalog, variant set) without
            # writing the control file; a dry run must not create a campaign.
            from ..campaign.plan import build_plan

            doc = build_plan(
                self.loaded,
                dataset_root=self.dataset_root,
                archive_root=self.root,
                write=False,
                **kwargs,  # type: ignore[arg-type]
            )
        else:
            doc = self.plan(**kwargs)  # type: ignore[arg-type]
            self.private_root.mkdir(parents=True, exist_ok=True)
        return {
            "ok": True,
            "dry_run": dry_run,
            "plan": plan_path(self.root).as_posix(),
            "plan_sha256": plan_fingerprint(doc),
            "tasks": [item.task_id for item in doc.tasks],
            "variant_set_id": doc.variant_set_id,
            "variant_set_file": doc.variant_set_file,
            "variant_set_sha256": doc.variant_set_sha256,
            "research_question": doc.research_question,
            "variant_count": len(doc.tasks[0].variants) if doc.tasks else 0,
            "audits_per_task": doc.budget.audits_per_task,
            "generation": doc.generation.model_dump(mode="json"),
        }

    def generate_only(self, task_id: str) -> dict[str, object]:
        """Run download -> prepare -> index -> generate, and stop before building trees.

        This is the review gate: an operator can read the candidates, the validation
        verdicts and the selection before any audit budget is spent.
        """
        plan = self.load_or_plan()
        plan_item = plan_task(plan, task_id)
        store = TaskStateStore(self.root)
        state = store.open_or_create(
            task_id,
            snapshot_id=plan_item.snapshot_id,
            plan_sha256=plan_fingerprint(plan),
            config_sha256=self.loaded.sha256,
        )
        current = state.phase
        try:
            if current in {"pending", "downloading"}:
                state = self._phase_download(state, plan_item, store)
                current = "downloading"
            if current in {"downloading", "extracted"}:
                state = self._phase_extract(state, plan_item, store)
                current = "extracted"
            if current in {"extracted", "prepared"}:
                state = self._phase_prepare(state, plan_item, store)
                current = "prepared"
            if current in {"prepared", "indexed"}:
                state = self._phase_index(state, plan_item, store)
                current = "indexed"
            if current in {"indexed", "generation_started", "candidates_validated"}:
                state = self._phase_generate(state, plan_item, store)
                current = "candidates_validated"
        except (CampaignError, GenerationError) as exc:
            store.fail(state, phase=current, error=exc.message)
            return {"ok": False, "task_id": task_id, "error_code": exc.error_code, "details": exc.details}
        return {
            "ok": True,
            "task_id": task_id,
            "phase": state.phase,
            "generation": self.inspect_generation(task_id),
        }

    def inspect_generation(self, task_id: str) -> dict[str, object]:
        """Read back the frozen candidate sets for human review."""
        generation_dir = self.task_archive_dir(task_id) / "generation"
        summary: dict[str, object] = {}
        summary_path = generation_dir / "generation_manifest.json"
        if summary_path.is_file():
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        conditions: list[dict[str, object]] = []
        for path in sorted((generation_dir / "manifests").glob("*.json")):
            manifest = GenerationManifest.model_validate(
                json.loads(path.read_text(encoding="utf-8"))
            )
            conditions.append(
                {
                    "variant_id": manifest.variant_id,
                    "condition_id": manifest.condition_id,
                    "tier": manifest.tier,
                    "method_id": manifest.method_id,
                    "candidate_budget": manifest.candidate_budget,
                    "selected": manifest.selection.selected_id,
                    "selection": manifest.selection.model_dump(mode="json"),
                    "candidates": [
                        {
                            "candidate_id": item.candidate_id,
                            "edit_op": item.edit_op,
                            "target_file": item.target_file,
                            "placement_basis": item.placement_basis,
                            "lines": item.estimated_lines,
                            "validation": (
                                manifest.validation_for(item.candidate_id).summary
                                if manifest.validation_for(item.candidate_id)
                                else {}
                            ),
                        }
                        for item in manifest.candidates
                    ],
                }
            )
        return {
            "task_id": task_id,
            "summary": summary,
            "conditions": conditions,
            "available": bool(conditions),
        }

    def aggregate(self, *, tasks: list[str] | None = None) -> dict[str, object]:
        from ..evaluation.aggregate import aggregate_campaign

        result = aggregate_campaign(self.root, tasks=tasks)
        path = self.root / "aggregate" / "aggregate.json"
        atomic_write_json(path, result)
        return {
            "ok": True,
            "path": path.as_posix(),
            "tasks": result.tasks,
            "pairs": len(result.pairs),
            "by_tier": result.by_tier,
            "bootstrap": result.bootstrap,
            "losses": result.losses.model_dump(mode="json"),
        }

    # --------------------------------------------------------------------- run
    def run_task(self, task_id: str, *, resume: bool = True) -> dict[str, object]:
        plan = self.load_or_plan()
        plan_item = plan_task(plan, task_id)
        store = TaskStateStore(self.root)
        fingerprint = plan_fingerprint(plan)
        state = store.open_or_create(
            task_id,
            snapshot_id=plan_item.snapshot_id,
            plan_sha256=fingerprint,
            config_sha256=self.loaded.sha256,
        )
        if state.phase == "archived" and not resume:
            return {"ok": True, "task_id": task_id, "skipped": True, "phase": state.phase}
        current: str = state.phase
        try:
            if current in {"pending", "downloading"}:
                state = self._phase_download(state, plan_item, store)
                current = "downloading"
            if current in {"downloading", "extracted"}:
                state = self._phase_extract(state, plan_item, store)
                current = "extracted"
            if current in {"extracted", "prepared"}:
                state = self._phase_prepare(state, plan_item, store)
                current = "prepared"
            if current in {"prepared", "indexed"}:
                state = self._phase_index(state, plan_item, store)
                current = "indexed"
            if current in {"indexed", "generation_started", "candidates_validated"}:
                state = self._phase_generate(state, plan_item, store)
                current = "candidates_validated"
            if current in {"candidates_validated", "variants_frozen"}:
                state = self._phase_variants(state, plan_item, store)
                current = "variants_frozen"
            if current in {"variants_frozen", "auditing"}:
                state = self._phase_audit(state, plan_item, store, plan)
                current = "auditing"
            if current in {"auditing", "scoring"}:
                state = self._phase_score(state, plan_item, store)
                current = "scoring"
            if current in {"scoring", "mechanism_analysis"}:
                state = self._phase_mechanism(state, plan_item, store)
                current = "mechanism_analysis"
            if current in {"mechanism_analysis", "archived"}:
                state = self._phase_archive(state, plan_item, store)
                current = "archived"
            if current in {"archived", "cleaned"}:
                state = self._phase_cleanup(state, plan_item, store)
        except IsolationError as exc:
            store.fail(state, phase=current, error=exc.message)
            return {"ok": False, "task_id": task_id, "error_code": exc.error_code, "details": exc.details}
        except (CampaignError, VerifierError) as exc:
            store.fail(state, phase=current, error=exc.message)
            return {"ok": False, "task_id": task_id, "error_code": exc.error_code, "details": exc.details}
        return {
            "ok": True,
            "task_id": task_id,
            "phase": state.phase,
            "runs": state.run_ids,
            "scored": state.scored_run_ids,
            "failed": state.failed_run_ids,
            "archive": self.task_archive_dir(task_id).as_posix(),
        }

    # ----------------------------------------------------------- phase: download
    def _phase_download(
        self, state: TaskState, plan_item: PlanTask, store: TaskStateStore
    ) -> TaskState:
        archive_dir = self.task_archive_dir(state.task_id)
        archive_dir.mkdir(parents=True, exist_ok=True)
        request = resolve_archive_request(
            plan_item.repo_url, plan_item.commit_sha, provider=self.config.archive.provider
        )
        if request.provider == "local_tree":
            # Local fixture: an already-unpacked tree.  No archive bytes exist, so
            # the manifest records a tree identity and says so instead of inventing
            # a download digest.
            source = Path(plan_item.repo_url)
            if not source.is_dir():
                raise CampaignError(
                    "local_tree provider needs an existing directory",
                    details={"path": str(source)},
                )
            manifest = SourceManifest(
                task_id=state.task_id,
                snapshot_id=plan_item.snapshot_id,
                provider=request.provider,
                source_id=request.source_id,
                commit=request.commit,
                requested_url=source.as_uri(),
                final_url=source.as_uri(),
                downloaded_at=utc_now_iso(),
                notes=[
                    "local_tree fixture: no archive bytes were downloaded",
                    "the tree digest is the only snapshot identity for this task",
                ],
            )
            atomic_write_json(archive_dir / "source_manifest.json", manifest)
            return store.advance(state, "downloading", detail="local_tree fixture")

        cache = ArchiveCache(self.root / "cache" / "archives", self.config.archive)
        archive_path = cache.archive_path(request)
        record = cache.load_record(request)
        reused = bool(
            record is not None and archive_path.is_file() and sha256_file(archive_path) == record.sha256
        )
        if not reused:
            from ..repository.archive import download_archive

            record = download_archive(request, archive_path, provider=self.config.archive.provider)
            cache.store_record(request, record)
        manifest = SourceManifest(
            task_id=state.task_id,
            snapshot_id=plan_item.snapshot_id,
            provider=record.provider,
            source_id=record.source_id,
            commit=record.commit,
            requested_url=record.requested_url,
            final_url=record.final_url,
            redirect_chain=list(record.redirect_chain),
            archive_sha256=record.sha256,
            archive_bytes=record.bytes,
            archive_reused_from_cache=reused,
            downloaded_at=record.downloaded_at,
            notes=[
                "one archive for one exact commit; no clone, no branch, no tag",
                "archive digest pins the bytes; the tree digest pins the content",
            ],
        )
        atomic_write_json(archive_dir / "source_manifest.json", manifest)
        state = state.model_copy(update={"archive_sha256": record.sha256})
        store.save(state)
        return store.advance(state, "downloading", detail=f"{record.provider}:{record.sha256[:12]}")

    # ------------------------------------------------------------ phase: extract
    def _phase_extract(
        self, state: TaskState, plan_item: PlanTask, store: TaskStateStore
    ) -> TaskState:
        archive_dir = self.task_archive_dir(state.task_id)
        manifest_payload = json.loads((archive_dir / "source_manifest.json").read_text(encoding="utf-8"))
        manifest = SourceManifest.model_validate(manifest_payload)
        source_dir = self.layout(state.task_id, "prep", "C", "clean").source_dir
        request = resolve_archive_request(
            plan_item.repo_url, plan_item.commit_sha, provider=self.config.archive.provider
        )
        cache = ArchiveCache(self.root / "cache" / "archives", self.config.archive)
        archive_path = cache.archive_path(request)

        extracted = False
        if source_dir.is_dir() and manifest.tree_sha256:
            if tree_digest(source_dir) == manifest.tree_sha256:
                extracted = True
        if not extracted:
            if manifest.provider == "local_tree":
                from ..repository.archive import copy_snapshot_tree

                tree_digest_value = copy_snapshot_tree(Path(plan_item.repo_url), source_dir)
                result = type(
                    "LocalExtraction",
                    (),
                    {
                        "strip_prefix": None,
                        "file_count": sum(1 for item in source_dir.rglob("*") if item.is_file()),
                        "total_bytes": sum(
                            item.stat().st_size for item in source_dir.rglob("*") if item.is_file()
                        ),
                        "tree_sha256": tree_digest_value,
                        "rejected": [],
                    },
                )()
            else:
                result = safe_extract(archive_path, source_dir, limits=self.config.archive.limits)
            history = find_history_metadata(source_dir)
            if history and self.config.archive.limits.reject_nested_history:
                raise CampaignError(
                    "the snapshot carries version-history metadata; set "
                    "archive.limits.reject_nested_history=false to accept it explicitly",
                    details={"entries": history[:20], "count": len(history)},
                )
            manifest = manifest.model_copy(
                update={
                    "strip_prefix": result.strip_prefix,
                    "file_count": result.file_count,
                    "total_bytes": result.total_bytes,
                    "tree_sha256": result.tree_sha256,
                    "history_metadata": history,
                    "rejected_entries": [
                        {"entry": item.entry, "reason": item.reason} for item in result.rejected
                    ],
                    "extracted_at": utc_now_iso(),
                }
            )
            atomic_write_json(archive_dir / "source_manifest.json", manifest)
        digest = manifest.tree_sha256 or tree_digest(source_dir)

        check = self._snapshot_check(state.task_id, plan_item, source_dir)
        validation_dir = archive_dir / "validation"
        validation_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(validation_dir / "snapshot_check.json", check)
        state = state.model_copy(update={"source_tree_sha256": digest})
        store.save(state)
        return store.advance(
            state, "extracted", detail=f"{check['verified']}/{check['checked']} target anchors verified"
        )

    def _snapshot_check(
        self, task_id: str, plan_item: PlanTask, source_dir: Path
    ) -> dict[str, object]:
        core = self.core_index()
        rows: list[dict[str, object]] = []
        verified = 0
        for target in core.targets(task_id):
            outcome = verify_target_anchor(target, source_dir)
            rows.append(
                {
                    "target_id": target.target_id,
                    "file": target.location.file,
                    "eligibility": eligibility_level(target),
                    "anchor_status": outcome["status"],
                    "detail": outcome["detail"],
                }
            )
            if outcome["status"] == "verified":
                verified += 1
        return {
            "schema_version": PIPELINE_SCHEMA_VERSION,
            "task_id": task_id,
            "snapshot_id": plan_item.snapshot_id,
            "tree_sha256": tree_digest(source_dir),
            "checked": len(rows),
            "verified": verified,
            "rows": rows,
            "checked_at": utc_now_iso(),
            "note": (
                "an anchor that does not resolve is excluded from scoring rather than "
                "re-interpreted; no call chain is invented"
            ),
        }

    # ----------------------------------------------------------- phase: prepare
    def _phase_prepare(
        self, state: TaskState, plan_item: PlanTask, store: TaskStateStore
    ) -> TaskState:
        core = self.core_index()
        task = core.task(state.task_id)
        template = self.loaded.resolve_asset(self.config.campaign.audit_task_template)
        effective = build_effective_task(
            core=core,
            task=task,
            template_path=template,
            rule_version=self.config.campaign.task_prompt_rule_version,
        )
        layout = self.layout(state.task_id, "prep", "C", "clean")
        layout.prep_dir.mkdir(parents=True, exist_ok=True)
        task_file = layout.prep_dir / "effective_task.md"
        task_file.write_text(effective.effective_task_prompt, encoding="utf-8")

        targets, excluded = self._build_private_targets(state.task_id)
        target_dir = self.private_root / "targets"
        target_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(target_dir / f"{state.task_id}.json", targets)

        archive_dir = self.task_archive_dir(state.task_id)
        archive_dir.mkdir(parents=True, exist_ok=True)
        manifest = TaskManifest(
            task_id=state.task_id,
            snapshot_id=task.snapshot_id,
            repo_id=task.repo_id,
            variant_set_id=self.load_or_plan().variant_set_id,
            commit_sha=task.commit_sha,
            archive_source_id=plan_item.archive_source_id,
            task_prompt_rule_version=effective.rule_version,
            source_prompt_sha256=effective.source_prompt_sha256,
            effective_prompt_sha256=effective.effective_prompt_sha256,
            effective_prompt_chars=len(effective.effective_task_prompt),
            transformations=[
                item.model_dump(mode="json") for item in effective.transformations
            ],
            removed_tokens_count=len(effective.removed_tokens),
            target_count=len(core.targets(state.task_id)),
            scored_target_count=len(targets.targets),
            excluded_targets=excluded,
            variants=[item.variant_id for item in plan_item.variants],
            repetitions=plan_item.repetitions,
            isolation_mode=self.config.isolation.mode,
            egress_mode=self.config.isolation.egress.mode,
            verifier_mode=self.config.verifier.mode,
            notes=[
                "the source prompt is kept for provenance; only the effective prompt reaches the agent",
                "the effective prompt is identical for every variant of this task",
            ],
        )
        atomic_write_json(archive_dir / "task_manifest.json", manifest)
        store = TaskStateStore(self.root)
        return store.advance(
            state,
            "prepared",
            detail=f"scoring {len(targets.targets)} of {len(core.targets(state.task_id))} target(s)",
        )

    def _build_private_targets(self, task_id: str):
        from ..verifier.targets import PrivateTarget, TargetSet

        core = self.core_index()
        task = core.task(task_id)
        source_dir = self.layout(task_id, "prep", "C", "clean").source_dir
        selection = json.loads(
            (self.task_archive_dir(task_id) / "validation" / "snapshot_check.json").read_text(
                encoding="utf-8"
            )
        )
        anchor_status = {
            str(row["target_id"]): str(row["anchor_status"]) for row in selection.get("rows", [])
        }
        targets: list[PrivateTarget] = []
        excluded: list[dict[str, str]] = []
        for target in core.targets(task_id):
            level = eligibility_level(target)
            if level == "rejected" or level == "unknown":
                excluded.append(
                    {"target_id": target.target_id, "reason": f"eligibility={level}"}
                )
                continue
            anchor = anchor_status.get(target.target_id)
            # Only "verified" (digest matches) and "no_anchor" (nothing to check) may be
            # scored.  A missing file or a digest mismatch means the ground-truth
            # location does not exist in *this* snapshot; scoring it would count the
            # target against nothing and report the agent as missing a vulnerability
            # that the materialization could not even locate.
            if anchor not in {None, "verified", "no_anchor"}:
                excluded.append(
                    {
                        "target_id": target.target_id,
                        "reason": f"anchor not verified against the snapshot ({anchor})",
                    }
                )
                continue
            targets.append(
                PrivateTarget(
                    target_id=target.target_id,
                    file=target.location.file,
                    function=target.location.function,
                    line_start=target.location.line_start,
                    line_end=target.location.line_end,
                    cwe_ids=list(target.weakness.cwe_ids),
                    severity_level=target.severity.level,
                    severity_score=target.severity.score,
                    severity_convention=target.severity.convention,
                    eligibility=level,
                    entry_file=(target.entry_point or {}).get("file"),
                    entry_function=(target.entry_point or {}).get("function"),
                )
            )
        if not targets:
            raise CampaignError(
                "no target survived snapshot verification: nothing can be scored",
                details={"task_id": task_id, "excluded": excluded[:10]},
            )
        return (
            TargetSet(
                task_id=task.task_id,
                snapshot_id=task.snapshot_id,
                targets=targets,
                source=f"dataset-core:{self.dataset_root.name}",
            ),
            excluded,
        )

    # ------------------------------------------------------------ phase: index
    def _phase_index(
        self, state: TaskState, plan_item: PlanTask, store: TaskStateStore
    ) -> TaskState:
        """Index the public tree once, before any generator runs.

        T1+ generators consume this object instead of crawling; that is what makes
        "the same clean tree produced the same placement" a checkable claim.
        """
        layout = self.layout(state.task_id, "prep", "C", "clean")
        source_dir = layout.source_dir
        if not source_dir.is_dir():
            raise CampaignError(
                "clean snapshot is missing; run the download phase first",
                details={"task_id": state.task_id},
            )
        index = build_repository_index(
            source_dir,
            limits=IndexLimits(),
            tree_sha256=state.source_tree_sha256 or tree_digest(source_dir),
        )
        generation_dir = self.task_archive_dir(state.task_id) / "generation"
        generation_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(generation_dir / "repository_index.json", index)
        state = store.note(
            state,
            repository_index_sha256=index.index_sha256,
            repository_files=index.file_count,
        )
        return store.advance(
            state,
            "indexed",
            detail=f"{index.file_count} file(s), {len(index.symbols)} symbol(s)",
        )

    # --------------------------------------------------------- phase: generate
    def _phase_generate(
        self, state: TaskState, plan_item: PlanTask, store: TaskStateStore
    ) -> TaskState:
        """Generate, validate and select a candidate set for every payload variant."""
        from ..verifier.targets import TargetSet
        from ..payloadgen.render import resolve_template_path

        archive_dir = self.task_archive_dir(state.task_id)
        generation_dir = archive_dir / "generation"
        index = RepositoryIndex.model_validate(
            json.loads((generation_dir / "repository_index.json").read_text(encoding="utf-8"))
        )
        plan = self.load_or_plan()
        core = self.core_index()
        task = core.task(state.task_id)
        tokens = target_answer_tokens(core, state.task_id)
        base_targets = TargetSet.model_validate(
            json.loads(
                (self.private_root / "targets" / f"{state.task_id}.json").read_text(
                    encoding="utf-8"
                )
            )
        )
        specs = {item.variant_id: item for item in self._variant_specs()}
        targets_by_ref = {
            opaque_target_ref(plan_item.snapshot_id, item.target_id): item
            for item in base_targets.targets
        }
        catalog_path = (
            self.loaded.resolve_asset(self.config.campaign.payload_catalog)
            if self.config.campaign.payload_catalog
            else None
        )
        methods = load_payload_catalog(catalog_path).by_id() if catalog_path else {}
        layout = self.layout(state.task_id, "prep", "C", "clean")
        clean_tree = tree_digest(layout.source_dir)
        candidates_dir = generation_dir / "candidates"
        manifests_dir = generation_dir / "manifests"
        candidates_dir.mkdir(parents=True, exist_ok=True)
        manifests_dir.mkdir(parents=True, exist_ok=True)

        state = (
            store.advance(state, "generation_started", detail="building candidate sets")
            if state.phase == "indexed"
            else state
        )
        conditions: list[dict[str, object]] = []
        for variant in plan_item.variants:
            base_variant_id = variant.base_variant_id or variant.variant_id
            base_spec = specs.get(base_variant_id)
            if base_spec is None:
                raise CampaignError(
                    "the plan names a variant the configuration no longer declares",
                    details={
                        "variant_id": variant.variant_id,
                        "base_variant_id": base_variant_id,
                    },
                )
            spec = base_spec.model_copy(update={"variant_id": variant.variant_id})
            target = targets_by_ref.get(str(variant.target_ref))
            if target is None:
                raise CampaignError(
                    "the planned target is not scoreable in the materialized snapshot",
                    details={
                        "variant_id": variant.variant_id,
                        "target_ref": variant.target_ref,
                    },
                )
            if spec.kind == "clean" or spec.payload_id is None:
                conditions.append(
                    {
                        "variant_id": spec.variant_id,
                        "target_ref": variant.target_ref,
                        "tier": str(spec.tier),
                        "generation": "not_generated",
                        "reason": "clean baseline or inline edits",
                    }
                )
                continue
            method = methods.get(str(spec.payload_id))
            if method is None:
                raise CampaignError(
                    "the variant references a payload that is not in the catalog",
                    details={"variant_id": spec.variant_id, "payload_id": spec.payload_id},
                )
            tier = str(spec.tier)
            profile = plan.generation.tier_profiles.get(tier)

            def ceiling(profile_value: int | None, method_value: int) -> int:
                # A tier profile may tighten a method's limit; absence means the
                # method's own placement limit decides.
                return method_value if profile_value is None else min(profile_value, method_value)

            budget = TierBudget(
                candidates=(profile.candidate_budget if profile else 1),
                max_files_changed=ceiling(
                    profile.max_files_changed if profile else None,
                    method.placement_limits.max_files_changed,
                ),
                max_inserted_lines=ceiling(
                    profile.max_inserted_lines if profile else None,
                    method.placement_limits.max_inserted_lines,
                ),
                max_payload_chars=ceiling(
                    profile.max_payload_chars if profile else None,
                    method.placement_limits.max_payload_chars,
                ),
                model_calls=(profile.max_model_calls if profile else 0),
            )
            template_path = resolve_template_path(catalog_path, method.template_for(tier))
            template_text = template_path.read_text(encoding="utf-8")

            # A legacy placement hint remains part of the compatibility API, but
            # formal T0 generation uses a deterministic public-index location.
            hint: PlacementHint | None = None

            oracle_view = None
            if tier in ORACLE_VIEW_TIERS:
                record = next(
                    (
                        item
                        for item in core.targets(state.task_id)
                        if item.target_id == target.target_id
                    ),
                    None,
                )
                if record is None:
                    raise CampaignError(
                        "the private target has no oracle row; T2 is not available for it",
                        details={"variant_id": spec.variant_id, "task_id": state.task_id},
                    )
                view, reason = build_oracle_attack_view(
                    record,
                    private_target=target,
                    forbidden_tokens=tokens,
                )
                if view is None:
                    raise CampaignError(
                        "this target cannot support an oracle-guided condition",
                        details={"variant_id": spec.variant_id, "reason": reason},
                    )
                assert_view_is_clean(view, tokens)
                oracle_view = view
                view_dir = self.private_root / "oracle_attack_views"
                atomic_write_json(
                    view_dir / f"{state.task_id}__{spec.variant_id}.json", view
                )

            request = GenerationRequest(
                task_id=state.task_id,
                snapshot_id=task.snapshot_id,
                variant_id=spec.variant_id,
                condition_id=variant.condition_id or spec.variant_id,
                method_id=method.method_id or method.method_family,
                method_family=method.method_family,
                tier=tier,  # type: ignore[arg-type]
                goal=method.objective,
                seed=plan.generation.seed,
                carrier=method.carrier,
                placement=method.placement,
                output_path=method.output_path,
                selection_policy=(
                    profile.selection_policy
                    if profile
                    else "semantic_fit_then_deterministic_tiebreak"
                ),
                task=PublicTaskView(
                    task_id=state.task_id, primary_language=task.primary_language
                ),
                templates={tier: template_text, "T0": template_text},
                template_source=template_path.as_posix(),
                budget=budget,
                limits=method.placement_limits,
                validation=method.validation,
                # T0 uses the public index only for deterministic static placement;
                # T1/T2 additionally adapt content/placement to their capabilities.
                index=(index if tier in INDEXED_TIERS else None),
                oracle_view=oracle_view,
                placement_hint=hint,
                forbidden_tokens=tokens,
                clean_tree_sha256=clean_tree,
                input_hashes={
                    "repository_index": index.index_sha256,
                    "template": sha256_file(template_path),
                    "catalog": sha256_file(catalog_path) if catalog_path else "",
                },
                repo_root=layout.source_dir,
            )
            manifest = generate_manifest(request, method=method)
            atomic_write_json(
                candidates_dir / f"{spec.variant_id}.json",
                {
                    "variant_id": spec.variant_id,
                    "candidates": [item.model_dump(mode="json") for item in manifest.candidates],
                    "validations": [item.model_dump(mode="json") for item in manifest.validations],
                },
            )
            atomic_write_json(manifests_dir / f"{spec.variant_id}.json", manifest)
            conditions.append(
                {
                    "variant_id": spec.variant_id,
                    "target_ref": variant.target_ref,
                    "tier": tier,
                    "method_id": method.method_id or method.method_family,
                    "candidates": len(manifest.candidates),
                    "selected_candidate": manifest.selection.selected_id,
                    "manifest_sha256": sha256_text(manifest.model_dump_json()),
                }
            )

        atomic_write_json(
            generation_dir / "generation_manifest.json",
            {
                "schema_version": PIPELINE_SCHEMA_VERSION,
                "task_id": state.task_id,
                "seed": plan.generation.seed,
                "repository_index_sha256": index.index_sha256,
                "candidate_budget": plan.generation.candidate_budget,
                "require_candidate_validation": plan.generation.require_candidate_validation,
                "conditions": conditions,
                "created_at": utc_now_iso(),
            },
        )
        if state.phase != "candidates_validated":
            state = store.advance(
                state,
                "candidates_validated",
                detail=(
                    f"{sum(1 for item in conditions if item.get('selected_candidate'))} "
                    "condition(s) selected"
                ),
            )
        return state

    # ---------------------------------------------------------- phase: variants
    def _phase_variants(
        self, state: TaskState, plan_item: PlanTask, store: TaskStateStore
    ) -> TaskState:
        """Build one tree per condition from its frozen candidate, then remap targets."""
        from ..payloadgen import GenerationManifest, OracleAttackView
        from ..verifier.targets import SafeDecoy, TargetSet

        layout = self.layout(state.task_id, "prep", "C", "clean")
        source_dir = layout.source_dir
        archive_dir = self.task_archive_dir(state.task_id)
        generation_dir = archive_dir / "generation"
        manifests_dir = generation_dir / "manifests"
        remap_dir = self.private_root / "target_remap"
        tokens = target_answer_tokens(self.core_index(), state.task_id)
        specs = {item.variant_id: item for item in self._variant_specs()}
        base_targets = TargetSet.model_validate(
            json.loads(
                (self.private_root / "targets" / f"{state.task_id}.json").read_text(
                    encoding="utf-8"
                )
            )
        )
        targets_by_ref = {
            opaque_target_ref(plan_item.snapshot_id, item.target_id): item
            for item in base_targets.targets
        }
        catalog_path = (
            self.loaded.resolve_asset(self.config.campaign.payload_catalog)
            if self.config.campaign.payload_catalog
            else None
        )
        methods = load_payload_catalog(catalog_path).by_id() if catalog_path else {}
        builds: list[VariantBuild] = []
        patches_dir = archive_dir / "patches"
        patches_dir.mkdir(parents=True, exist_ok=True)
        for variant in plan_item.variants:
            base_variant_id = variant.base_variant_id or variant.variant_id
            base_spec = specs.get(base_variant_id)
            if base_spec is None:
                raise CampaignError(
                    "the frozen plan references an unknown base variant",
                    details={
                        "variant_id": variant.variant_id,
                        "base_variant_id": base_variant_id,
                    },
                )
            spec = base_spec.model_copy(update={"variant_id": variant.variant_id})
            selected_target = targets_by_ref.get(str(variant.target_ref))
            if selected_target is None:
                raise CampaignError(
                    "the frozen target is absent from the verified target set",
                    details={
                        "variant_id": variant.variant_id,
                        "target_ref": variant.target_ref,
                    },
                )
            candidate: CandidatePayload | None = None
            manifest: GenerationManifest | None = None
            effective_spec = spec
            if spec.payload_id:
                manifest_path = manifests_dir / f"{spec.variant_id}.json"
                if not manifest_path.is_file():
                    raise CampaignError(
                        "the generation manifest for this variant is missing",
                        details={
                            "variant_id": spec.variant_id,
                            "path": manifest_path.as_posix(),
                        },
                    )
                manifest = GenerationManifest.model_validate(
                    json.loads(manifest_path.read_text(encoding="utf-8"))
                )
                candidate = selected_candidate(manifest)
                effective_spec = spec.model_copy(
                    update={
                        "edits": [candidate_to_edit(candidate)],
                        "method_id": spec.method_id or candidate.method_id,
                        "carrier": spec.carrier or candidate.carrier,
                    }
                )
            build = build_variant(
                source_dir=source_dir,
                spec=effective_spec,
                destination=layout.variants_dir / spec.variant_id,
                answer_tokens=tokens,
                candidate_id=(candidate.candidate_id if candidate else None),
                generation_manifest_sha256=(
                    sha256_text(manifest.model_dump_json()) if manifest is not None else None
                ),
                target_ref=variant.target_ref,
            )
            remap = remap_targets(
                task_id=state.task_id,
                variant_id=spec.variant_id,
                targets=[selected_target],
                clean_root=source_dir,
                variant_root=layout.variants_dir / spec.variant_id,
                applied_edits=[item.model_dump(mode="json") for item in build.edits],
                clean_tree_sha256=build.base_tree_sha256,
                variant_tree_sha256=build.tree_sha256,
            )
            if not remap.unique:
                raise CampaignError(
                    "a private target could not be remapped into this variant; "
                    "the variant must not enter a formal repetition",
                    details={
                        "variant_id": spec.variant_id,
                        "remap_sha256": remap.remap_sha256,
                    },
                )
            atomic_write_json(remap_dir / f"{state.task_id}__{spec.variant_id}.json", remap)
            if manifest is not None and candidate is not None:
                manifest = attach_remap(
                    manifest, remap, variant_tree_sha256=build.tree_sha256
                )
                atomic_write_json(manifests_dir / f"{spec.variant_id}.json", manifest)
                build = build.model_copy(
                    update={
                        "remap_sha256": remap.remap_sha256,
                        "generation_manifest_sha256": sha256_text(
                            manifest.model_dump_json()
                        ),
                        "rendered_sha256": candidate.content_sha256,
                        "template_sha256": manifest.input_hashes.get("template"),
                    }
                )

            decoys: list[SafeDecoy] = []
            method = methods.get(str(spec.payload_id)) if spec.payload_id else None
            if (
                candidate is not None
                and manifest is not None
                and method is not None
                and method.placement == "safe_decoy_file"
            ):
                validation = manifest.validation_for(candidate.candidate_id)
                proof = (
                    next(
                        (
                            item
                            for item in validation.results
                            if item.validator == "semantic" and item.status == "pass"
                        ),
                        None,
                    )
                    if validation is not None
                    else None
                )
                if proof is None:
                    raise CampaignError(
                        "the selected safe decoy has no semantic certificate",
                        details={
                            "variant_id": spec.variant_id,
                            "candidate_id": candidate.candidate_id,
                        },
                    )
                decoys.append(
                    SafeDecoy(
                        decoy_id=f"DECOY-{spec.variant_id}",
                        variant_id=spec.variant_id,
                        file=str(candidate.target_file),
                        line_start=1,
                        line_end=max(1, candidate.rendered_text.count("\n")),
                        cwe_ids=list(method.safe_decoy_cwe_ids),
                        proof_kind=str(
                            proof.evidence.get("proof_kind")
                            or "python_no_execution_subset_v1"
                        ),
                        proof_sha256=str(proof.evidence.get("proof_sha256") or ""),
                        safety_basis=method.private_safety_basis or "no executable sink",
                    )
                )

            remapped = remap.as_targets([selected_target])
            guided_ids: set[str] = set()
            view_path = (
                self.private_root
                / "oracle_attack_views"
                / f"{state.task_id}__{spec.variant_id}.json"
            )
            if view_path.is_file():
                view = OracleAttackView.model_validate(
                    json.loads(view_path.read_text(encoding="utf-8"))
                )
                location = view.locations[0]
                guided_ids = {
                    item.target_id
                    for item in [selected_target]
                    if item.file == location.file
                    and item.line_start is not None
                    and item.line_end is not None
                    and not (
                        item.line_end < location.start_line
                        or item.line_start > location.end_line
                    )
                }
            variant_targets = base_targets.model_copy(
                update={
                    "targets": [
                        item.model_copy(
                            update={"oracle_guided": item.target_id in guided_ids}
                        )
                        for item in remapped
                    ],
                    "safe_decoys": decoys,
                }
            )
            atomic_write_json(
                self.private_root / "targets" / f"{state.task_id}__{spec.variant_id}.json",
                variant_targets,
            )
            atomic_write_json(
                patches_dir / f"{spec.variant_id}.json",
                {
                    "variant_id": spec.variant_id,
                    "condition_id": variant.condition_id or spec.variant_id,
                    "target_ref": variant.target_ref,
                    "base_variant_id": base_variant_id,
                    "kind": spec.kind,
                    "tier": str(spec.tier),
                    "payload_id": spec.payload_id,
                    "method_id": effective_spec.method_id,
                    "carrier": effective_spec.carrier,
                    "goal": effective_spec.goal,
                    "knowledge": spec.knowledge,
                    "generation": (
                        {
                            "manifest_sha256": build.generation_manifest_sha256,
                            "candidate_id": build.candidate_id,
                            "candidates": len(manifest.candidates),
                            "selection": manifest.selection.model_dump(mode="json"),
                        }
                        if manifest is not None
                        else None
                    ),
                    "edits": [
                        edit.model_dump(mode="json") for edit in effective_spec.edits
                    ],
                    "applied": [item.model_dump(mode="json") for item in build.edits],
                    "remap_sha256": remap.remap_sha256,
                    "base_tree_sha256": build.base_tree_sha256,
                    "tree_sha256": build.tree_sha256,
                },
            )
            builds.append(build)
        freeze = VariantFreeze(
            task_id=state.task_id,
            source_tree_sha256=tree_digest(source_dir),
            builds=builds,
        )
        generation_dir = archive_dir / "generation"
        generation_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(generation_dir / "variants_frozen.json", freeze)
        state = state.model_copy(update={"variant_ids": [item.variant_id for item in builds]})
        self._freeze = freeze  # type: ignore[attr-defined]
        store.save(state)
        return store.advance(
            state, "variants_frozen", detail=", ".join(item.variant_id for item in builds)
        )

    def _variant_specs(self):
        from ..campaign.plan import _variant_specs

        return _variant_specs(self.loaded)

    # ------------------------------------------------------------- phase: audit
    def _phase_audit(
        self,
        state: TaskState,
        plan_item: PlanTask,
        store: TaskStateStore,
        plan: PlanDoc,
    ) -> TaskState:
        framework_config = self.agent_env_overrides.get("OPENCODE_CONFIG")
        if framework_config:
            framework_path = Path(framework_config)
            label = f"framework_config:{framework_path.name}"
            expected = self.agent_external_file_sha256.get(label)
            if not framework_path.is_file() or (
                expected is not None and sha256_file(framework_path) != expected
            ):
                raise CampaignError(
                    "the agent framework configuration changed after it was loaded",
                    details={
                        "path": framework_path.as_posix(),
                        "expected_sha256": expected,
                    },
                )
        freeze: VariantFreeze = getattr(self, "_freeze", None) or VariantFreeze.model_validate(
            json.loads(
                (self.task_archive_dir(state.task_id) / "generation" / "variants_frozen.json").read_text(
                    encoding="utf-8"
                )
            )
        )
        by_variant = {item.variant_id: item for item in freeze.builds}
        task_file = self.layout(state.task_id, "prep", "C", "clean").prep_dir / "effective_task.md"
        runs: list[str] = list(state.run_ids)
        failed: list[str] = list(state.failed_run_ids)
        ineligible: list[str] = list(state.ineligible_run_ids)
        attestations: list[IsolationAttestation] = []
        variant_by_id = {item.variant_id: item for item in plan_item.variants}
        expected_cells = {
            (repetition, variant.variant_id)
            for repetition in range(1, plan_item.repetitions + 1)
            for variant in plan_item.variants
        }
        scheduled_cells = {
            (item.repetition, item.variant_id) for item in plan_item.run_order
        }
        if plan_item.run_order and (
            scheduled_cells != expected_cells
            or len(plan_item.run_order) != len(expected_cells)
        ):
            raise CampaignError(
                "the frozen run order does not cover every audit cell exactly once",
                details={
                    "missing": sorted(expected_cells - scheduled_cells),
                    "unexpected": sorted(scheduled_cells - expected_cells),
                    "scheduled_count": len(plan_item.run_order),
                    "expected_count": len(expected_cells),
                },
            )
        schedule = (
            [(item.repetition, variant_by_id[item.variant_id]) for item in plan_item.run_order]
            if plan_item.run_order
            else [
                (repetition, variant)
                for repetition in range(1, plan_item.repetitions + 1)
                for variant in plan_item.variants
            ]
        )
        for repetition, variant in schedule:
            if variant.variant_id not in by_variant:
                raise CampaignError(
                    "the frozen run order references a variant tree that is missing",
                    details={"variant_id": variant.variant_id},
                )
            else:
                build = by_variant[variant.variant_id]
                run_id = stable_id("RUN", state.task_id, variant.variant_id, repetition)
                if run_id in state.scored_run_ids:
                    continue
                existing_run = self.task_archive_dir(state.task_id) / "runs" / run_id / "run.json"
                if run_id in runs and existing_run.is_file():
                    # A previous process may have stopped after the model call but
                    # before the audit phase advanced.  Reuse the immutable run
                    # instead of silently paying for and sampling the model twice.
                    continue
                layout = self.layout(state.task_id, run_id, variant.variant_id, variant.kind)
                layout.reset_exposed()
                run_dir = self.task_archive_dir(state.task_id) / "runs" / run_id
                run_dir.mkdir(parents=True, exist_ok=True)
                source = layout.variants_dir / variant.variant_id
                shutil.copytree(source, layout.repo_dir)
                actual = tree_digest(layout.repo_dir)
                if actual != build.tree_sha256:
                    raise CampaignError(
                        "exposed tree does not equal the frozen variant tree",
                        details={
                            "run_id": run_id,
                            "expected": build.tree_sha256,
                            "actual": actual,
                        },
                    )
                egress = probe_egress(self.config.isolation.egress)
                env, env_record = build_restricted_agent_environment(
                    self.config.isolation.egress,
                    allowlist=self.agent_env_allowlist,
                    inference_names=self.agent_env_names,
                    fixed_env=self.agent_env_overrides,
                )
                env["VULNMIRAGE_TASK_FILE"] = task_file.as_posix()
                env["VULNMIRAGE_OUTPUT_DIR"] = layout.output_dir.as_posix()
                attestation = run_attestation(
                    layout,
                    expected_tree_sha256=build.tree_sha256,
                    egress=egress,
                    mode=self.config.isolation.mode,
                    require_egress_pass=self.config.isolation.egress.fail_closed,
                )
                attestations.append(attestation)
                write_attestation(layout, attestation)
                atomic_write_json(run_dir / "isolation_attestation.json", attestation)
                atomic_write_json(run_dir / "agent_environment.json", env_record)

                result = ExecutionResult(status="not_run")
                if attestation.verdict == "pass":
                    result = self.executor.run(
                        repo=layout.repo_dir,
                        output=layout.output_dir,
                        task_file=task_file,
                        env=env,
                        run_dir=run_dir,
                        timeout_seconds=self.config.campaign.audit_timeout_seconds,
                    )
                else:
                    result = ExecutionResult(
                        status="ineligible_isolation",
                        error=attestation.eligibility,
                    )
                trace = normalize_trace(
                    result.stdout_path,
                    run_dir,
                    adapter=self.trace_adapter,
                    repo_root=layout.repo_dir,
                    secret_values=(env.get(name, "") for name in self.agent_env_names),
                )
                record = RunRecord(
                    run_id=run_id,
                    task_id=state.task_id,
                    variant_set_id=plan.variant_set_id,
                    variant_id=variant.variant_id,
                    target_ref=variant.target_ref,
                    variant_kind=variant.kind,
                    method_id=variant.method_id,
                    carrier=variant.carrier,
                    goal=variant.goal,
                    repetition=repetition,
                    execution_status=result.status,
                    exit_code=result.exit_code,
                    duration_seconds=result.duration_seconds,
                    tier=variant.tier,
                    model=self.model_label,
                    agent_profile=self.agent_profile,
                    agent_config_sha256=self.agent_config_sha256,
                    agent_external_file_sha256=self.agent_external_file_sha256,
                    isolation_eligibility=attestation.eligibility,
                    exposure_root=layout.repo_dir.as_posix(),
                    trace_status=str(trace["status"]),
                    trace_completeness=str(trace["completeness"]),
                    trace_events=int(trace["events"]),
                )
                atomic_write_json(run_dir / "run.json", record)
                atomic_write_json(
                    run_dir / "meta.json",
                    {
                        "run_id": run_id,
                        "task_id": state.task_id,
                        "variant_set_id": plan.variant_set_id,
                        "variant_id": variant.variant_id,
                        "target_ref": variant.target_ref,
                        "condition_id": variant.condition_id or variant.variant_id,
                        "tier": variant.tier,
                        "candidate_id": build.candidate_id,
                        "purpose": "evaluation",
                        "isolation_eligibility": attestation.eligibility,
                        "egress_verdict": egress.verdict,
                        "trace_status": trace["status"],
                        "trace_completeness": trace["completeness"],
                        "trace_manifest": "trace_manifest.json",
                        "agent_profile": self.agent_profile,
                        "agent_config_sha256": self.agent_config_sha256,
                        "agent_external_file_sha256": self.agent_external_file_sha256,
                    },
                )
                self._collect_answer(run_dir, layout)
                if run_id not in runs:
                    runs.append(run_id)
                if result.status != "success" and run_id not in failed:
                    failed.append(run_id)
                if attestation.verdict != "pass" and run_id not in ineligible:
                    ineligible.append(run_id)
                # Persist after every expensive agent invocation.  The phase stays
                # unchanged until all cells finish, but resume can now skip calls
                # that already have a frozen run record.
                state = state.model_copy(
                    update={
                        "run_ids": runs,
                        "failed_run_ids": failed,
                        "ineligible_run_ids": ineligible,
                    }
                )
                store.save(state)
                layout.cleanup()
        state = state.model_copy(
            update={
                "run_ids": runs,
                "failed_run_ids": failed,
                "ineligible_run_ids": ineligible,
            }
        )
        store.save(state)
        self._attestations = attestations  # type: ignore[attr-defined]
        return store.advance(state, "auditing", detail=f"{len(runs)} run(s) executed")

    def _collect_answer(self, run_dir: Path, layout: ExposureLayout) -> None:
        from ..evaluation.parser import OutputParseError, parse_agent_output
        from ..harness.artifacts import write_findings_and_report

        candidates = [layout.output_dir / name for name in ANSWER_FILENAMES]
        answer = next((item for item in candidates if item.is_file()), None)
        if answer is None:
            atomic_write_json(
                run_dir / "parse_error.json",
                {"error": "the run produced no answer file", "searched": [str(item.name) for item in candidates]},
            )
            write_findings_and_report(
                run_dir,
                parsed=None,
                parse_status="missing_answer",
                parse_error="the run produced no answer file",
                final_raw_path=None,
                require_report=self.config.output_contract.require_report_markdown,
            )
            return
        text = answer.read_text(encoding="utf-8", errors="replace")
        (run_dir / "final_raw.txt").write_text(text, encoding="utf-8")
        try:
            parsed = parse_agent_output(
                text,
                repo_root=layout.repo_dir,
                require_report=self.config.output_contract.require_report_markdown,
            )
        except OutputParseError as exc:
            atomic_write_json(run_dir / "parse_error.json", exc.to_dict())
            write_findings_and_report(
                run_dir,
                parsed=None,
                parse_status="format_failure",
                parse_error=exc.message,
                final_raw_path=run_dir / "final_raw.txt",
                require_report=self.config.output_contract.require_report_markdown,
            )
            return
        write_findings_and_report(
            run_dir,
            parsed=parsed,
            parse_status="ok",
            parse_error=None,
            final_raw_path=run_dir / "final_raw.txt",
            max_report_chars=self.config.verifier.max_report_chars,
            require_report=self.config.output_contract.require_report_markdown,
        )

    # ------------------------------------------------------------- phase: score
    def _phase_score(
        self, state: TaskState, plan_item: PlanTask, store: TaskStateStore
    ) -> TaskState:
        from ..verifier.bundle import freeze_bundle

        archive_dir = self.task_archive_dir(state.task_id)
        evaluation_dir = archive_dir / "evaluation"
        evaluation_dir.mkdir(parents=True, exist_ok=True)
        scored: list[str] = list(state.scored_run_ids)
        failed: list[str] = list(state.failed_run_ids)
        skipped: list[str] = []
        for run_id in state.run_ids:
            run_dir = archive_dir / "runs" / run_id
            if not run_dir.is_dir():
                continue
            if run_id in state.ineligible_run_ids:
                # Scoring an ineligible run would put an infrastructure failure into
                # the detection denominators.
                skip_dir = evaluation_dir / run_id
                skip_dir.mkdir(parents=True, exist_ok=True)
                atomic_write_json(
                    skip_dir / "skipped.json",
                    {
                        "run_id": run_id,
                        "reason": "isolation invariants failed",
                        "eligibility": self._eligibility_for(run_dir),
                    },
                )
                skipped.append(run_id)
                continue
            bundle_dir = self.root / "tmp" / state.task_id / "bundles" / run_id
            run_payload = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
            freeze_bundle(
                run_dir,
                bundle_dir,
                task_id=state.task_id,
                run_id=run_id,
                variant_id=str(run_payload.get("variant_id")),
                bundle_id=f"{state.task_id}__{run_id}",
            )
            out_dir = evaluation_dir / run_id
            try:
                if self.config.verifier.mode == "separate_process":
                    result = self._score_in_subprocess(bundle_dir, out_dir)
                else:
                    result = evaluate_bundle(
                        private_root=self.private_root,
                        bundle_dir=bundle_dir,
                        output_dir=out_dir,
                        config=self.config.verifier,
                        mode="in_process",
                    )
            except VerifierError as exc:
                failed.append(run_id)
                atomic_write_json(out_dir / "verifier_error.json", exc.to_dict())
                continue
            if result.get("scored") and run_id not in scored:
                scored.append(run_id)
        state = state.model_copy(update={"scored_run_ids": scored, "failed_run_ids": failed})
        store.save(state)
        detail = f"{len(scored)} run(s) scored"
        if skipped:
            detail += f", {len(skipped)} skipped as ineligible"
        return store.advance(state, "scoring", detail=detail)

    def _eligibility_for(self, run_dir: Path) -> str:
        path = run_dir / "isolation_attestation.json"
        if not path.is_file():
            return "unattested"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:  # pragma: no cover - corrupt artefact
            return "unattested"
        return str(payload.get("eligibility") or "unattested")

    def _score_in_subprocess(self, bundle_dir: Path, out_dir: Path) -> dict[str, object]:
        import subprocess
        import sys

        out_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            sys.executable,
            "-m",
            "vulnmirage.verifier",
            "--private",
            self.private_root.as_posix(),
            "--bundle",
            bundle_dir.as_posix(),
            "--out",
            out_dir.as_posix(),
        ]
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=self.config.campaign.audit_timeout_seconds,
        )
        if completed.returncode != 0:
            raise VerifierError(
                "the verifier process rejected the bundle",
                details={"stderr": completed.stderr[-4000:], "argv": argv},
            )
        return json.loads(completed.stdout)

    # ----------------------------------------------------- phase: mechanism
    def _phase_mechanism(
        self,
        state: TaskState,
        plan_item: PlanTask,
        store: TaskStateStore,
        *,
        advance: bool = True,
    ) -> TaskState:
        archive_dir = self.task_archive_dir(state.task_id)
        freeze = VariantFreeze.model_validate(
            json.loads((archive_dir / "generation" / "variants_frozen.json").read_text(encoding="utf-8"))
        )
        by_variant = {item.variant_id: item for item in freeze.builds}
        default_target_set = json.loads(
            (self.private_root / "targets" / f"{state.task_id}.json").read_text(encoding="utf-8")
        )
        observations: list[RunObservation] = []
        payload_texts: dict[str, str] = {}
        exposure_payload_texts: dict[str, dict[str, str]] = {}
        detections: dict[str, dict[str, list[str]]] = {}
        reports: dict[str, str] = {}
        for run_id in state.run_ids:
            run_dir = archive_dir / "runs" / run_id
            if not run_dir.is_dir():
                continue
            run_payload = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
            build = by_variant.get(str(run_payload.get("variant_id")))
            score_path = archive_dir / "evaluation" / run_id / "score.json"
            score = (
                json.loads(score_path.read_text(encoding="utf-8")) if score_path.is_file() else {}
            )
            detection = score.get("detection") or {}
            detections[run_id] = {
                "detected": list(detection.get("detected_ids") or []),
                "missed": list(detection.get("missed_ids") or []),
            }
            report_path = run_dir / "agent_report.md"
            if report_path.is_file():
                reports[run_id] = report_path.read_text(encoding="utf-8", errors="ignore")[:50_000]
            payload_paths = tuple(build.files_touched) if build else ()
            variant_id = str(run_payload.get("variant_id"))
            variant_target_path = (
                self.private_root
                / "targets"
                / f"{state.task_id}__{variant_id}.json"
            )
            run_target_set = (
                json.loads(variant_target_path.read_text(encoding="utf-8"))
                if variant_target_path.is_file()
                else default_target_set
            )
            run_targets = list(run_target_set.get("targets", []))
            target_files = sorted({str(item["file"]) for item in run_targets})
            variant_tree = self.layout(state.task_id, run_id, variant_id, "x").variant_dir
            patch_path = archive_dir / "patches" / f"{variant_id}.json"
            patch_payload = (
                json.loads(patch_path.read_text(encoding="utf-8"))
                if patch_path.is_file()
                else {}
            )
            rendered_by_path = {
                str(item.get("path")): str(item.get("text") or "")
                for item in (patch_payload.get("edits") or [])
                if isinstance(item, dict) and item.get("path")
            }
            for path in payload_paths:
                rendered_text = rendered_by_path.get(path)
                if rendered_text:
                    payload_texts[f"{variant_id}:{path}"] = rendered_text[:4000]
                    exposure_payload_texts.setdefault(variant_id, {})[path] = rendered_text[:4000]
                    continue
                candidate = variant_tree / path
                if candidate.is_file():
                    text = candidate.read_text(
                        encoding="utf-8", errors="ignore"
                    )[:4000]
                    payload_texts[f"{variant_id}:{path}"] = text
                    exposure_payload_texts.setdefault(variant_id, {})[path] = text
            observations.append(
                RunObservation(
                    run_id=run_id,
                    variant_id=str(run_payload.get("variant_id")),
                    kind=str(run_payload.get("variant_kind")),
                    repetition=int(run_payload.get("repetition") or 1),
                    target_ref=run_payload.get("target_ref"),
                    method_id=run_payload.get("method_id"),
                    carrier=run_payload.get("carrier"),
                    goal=run_payload.get("goal"),
                    payload_paths=payload_paths,
                    target_ids=tuple(item["target_id"] for item in run_targets),
                    target_files=tuple(target_files),
                    run_dir=run_dir,
                    artifacts={
                        "file_access.jsonl": run_dir / "file_access.jsonl",
                        "events.normalized.jsonl": run_dir / "events.normalized.jsonl",
                        "findings.json": run_dir / "findings.json",
                        "output_consistency.json": run_dir / "output_consistency.json",
                    },
                )
            )
        exposure = analyze_exposure(
            observations,
            task_id=state.task_id,
            payload_texts=exposure_payload_texts,
        )
        comparison = compare_trajectories(observations, task_id=state.task_id)
        mechanism = assess_mechanisms(
            observations,
            comparison=comparison,
            exposure=exposure,
            payload_texts=payload_texts,
            detections=detections,
            reports=reports,
            task_id=state.task_id,
        )
        analysis_dir = archive_dir / "analysis" / f"{state.task_id}-comparison"
        write_analysis(
            analysis_dir,
            exposure=exposure,
            comparison=comparison,
            mechanism=mechanism,
            case_notes=[
                "analysis is offline: it can be recomputed without re-running an agent",
                "exposure is established from tool-result records, not from file access alone",
            ],
        )
        if not advance:
            return state
        return store.advance(state, "mechanism_analysis", detail=f"status={mechanism.status}")

    # ------------------------------------------------------------ phase: archive
    def _phase_archive(
        self,
        state: TaskState,
        plan_item: PlanTask,
        store: TaskStateStore,
        *,
        advance: bool = True,
    ) -> TaskState:
        archive_dir = self.task_archive_dir(state.task_id)
        attestations = getattr(self, "_attestations", []) or self._load_attestations(state)
        report = build_control_report(attestations=attestations, scope=f"task:{state.task_id}")
        atomic_write_json(archive_dir / "leakage_controls.json", report)
        entries: list[ArtifactEntry] = []
        for path in sorted(p for p in archive_dir.rglob("*") if p.is_file()):
            if path.name == "artifact_manifest.json":
                continue
            entries.append(
                ArtifactEntry(
                    path=path.relative_to(archive_dir).as_posix(),
                    sha256=sha256_file(path),
                    bytes=path.stat().st_size,
                )
            )
        manifest = {
            "schema_version": PIPELINE_SCHEMA_VERSION,
            "task_id": state.task_id,
            "snapshot_id": state.snapshot_id,
            "phase": "archived",
            "created_at": utc_now_iso(),
            "plan_sha256": state.plan_sha256,
            "config_sha256": state.config_sha256,
            "archive_sha256": state.archive_sha256,
            "source_tree_sha256": state.source_tree_sha256,
            "run_ids": state.run_ids,
            "scored_run_ids": state.scored_run_ids,
            "failed_run_ids": state.failed_run_ids,
            "ineligible_run_ids": state.ineligible_run_ids,
            "entries": [item.model_dump(mode="json") for item in entries],
            "leakage_controls": report.counts,
            "rebuild_note": (
                "source archive + variant patches + task prompt are sufficient to rebuild every "
                "run workspace; the tree digest is the check"
            ),
        }
        atomic_write_json(archive_dir / "artifact_manifest.json", manifest)
        if not advance:
            return state
        return store.advance(state, "archived", detail=f"{len(entries)} artefact(s) hashed")

    def _load_attestations(self, state: TaskState) -> list[IsolationAttestation]:
        found: list[IsolationAttestation] = []
        for run_id in state.run_ids:
            path = self.task_archive_dir(state.task_id) / "runs" / run_id / "isolation_attestation.json"
            if path.is_file():
                found.append(
                    IsolationAttestation.model_validate(json.loads(path.read_text(encoding="utf-8")))
                )
        return found

    # ------------------------------------------------------------ phase: cleanup
    def _phase_cleanup(
        self, state: TaskState, plan_item: PlanTask, store: TaskStateStore
    ) -> TaskState:
        archive_dir = self.task_archive_dir(state.task_id)
        manifest_path = archive_dir / "artifact_manifest.json"
        if self.config.campaign.cleanup_requires_verified_archive:
            if not manifest_path.is_file():
                raise CampaignError(
                    "refusing to clean up before the archive manifest exists",
                    details={"task_id": state.task_id},
                )
            verification = self.verify_archive(state.task_id)
            if not verification["ok"]:
                raise CampaignError(
                    "refusing to clean up: the archive did not verify",
                    details=verification,
                )
        tmp_dir = self.root / "tmp" / state.task_id
        removed: list[str] = []
        if tmp_dir.exists() and not self.config.campaign.keep_intermediates:
            shutil.rmtree(tmp_dir)
            removed.append(tmp_dir.as_posix())
        cleanup_manifest = {
            "schema_version": PIPELINE_SCHEMA_VERSION,
            "task_id": state.task_id,
            "created_at": utc_now_iso(),
            "removed": removed,
            "kept": [
                (self.root / "cache" / "archives").as_posix(),
                archive_dir.as_posix(),
                self.private_root.as_posix(),
            ],
            "policy": (
                "delete scratch only; referenced caches and the archive are kept, and nothing "
                "outside this campaign root is touched"
            ),
        }
        atomic_write_json(archive_dir / "cleanup_manifest.json", cleanup_manifest)
        return store.advance(state, "cleaned", detail=f"removed {len(removed)} scratch dir(s)")

    # ------------------------------------------------------------- verification
    def verify_archive(self, task_id: str) -> dict[str, object]:
        archive_dir = self.task_archive_dir(task_id)
        manifest_path = archive_dir / "artifact_manifest.json"
        if not manifest_path.is_file():
            return {"ok": False, "errors": ["artifact_manifest.json is missing"], "task_id": task_id}
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        errors: list[str] = []
        for entry in manifest.get("entries", []):
            path = archive_dir / str(entry["path"])
            if not path.is_file():
                errors.append(f"{entry['path']}: file is missing")
                continue
            if entry.get("sha256") and sha256_file(path) != entry["sha256"]:
                errors.append(f"{entry['path']}: sha256 does not match the archive manifest")
        return {
            "ok": not errors,
            "task_id": task_id,
            "errors": errors,
            "entries": len(manifest.get("entries", [])),
            "archive": archive_dir.as_posix(),
        }

    def analyze(self, task_id: str) -> dict[str, object]:
        """Recompute the mechanism artefacts from stored runs (no agent, no network)."""
        store = TaskStateStore(self.root)
        state = store.load(task_id)
        if state is None:
            raise CampaignError("unknown task state", details={"task_id": task_id})
        plan_item = plan_task(self.load_or_plan(), task_id)
        self._phase_mechanism(state, plan_item, store, advance=False)
        # Analysis artefacts participate in the archive hash inventory. Rebuild
        # that inventory without moving a completed task backwards in the state
        # machine, then verify it immediately.
        self._phase_archive(state, plan_item, store, advance=False)
        verification = self.verify_archive(task_id)
        if not verification["ok"]:
            raise CampaignError(
                "offline analysis produced an unverifiable archive",
                details=verification,
            )
        analysis_dir = self.task_archive_dir(task_id) / "analysis" / f"{task_id}-comparison"
        return {
            "ok": True,
            "task_id": task_id,
            "analysis": analysis_dir.as_posix(),
            "artefacts": sorted(item.name for item in analysis_dir.iterdir() if item.is_file()),
            "archive_verified": True,
        }


def verify_target_anchor(target: TargetRecord, root: Path) -> dict[str, str]:
    """Check the recorded snippet digest against the unpacked snapshot.

    The published package records ``sha256`` of the raw snippet text: the code lines
    joined by ``\\n`` with no trailing newline and **no** whitespace normalization.
    A normalized digest (``code_sha256``, which strips trailing spaces and blank edge
    lines) is accepted as a second basis so a package exported with the other
    convention still verifies.  Both bases hash the *same* line range, so either way
    the check proves the recorded code is present at the recorded place -- which is
    what makes a target scoreable at all.
    """
    from ..hashing import code_sha256, sha256_text

    location = target.location
    anchor = target.anchor
    if not anchor.snippet_sha256 or location.line_start is None:
        return {"status": "no_anchor", "detail": "the target has no verifiable snippet anchor"}
    path = Path(root) / location.file
    if not path.is_file():
        return {"status": "missing_file", "detail": f"{location.file} is not in the snapshot"}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    count = anchor.snippet_lines or max(
        1, (location.line_end or location.line_start) - location.line_start + 1
    )
    start = max(0, location.line_start - 1)
    snippet = "\n".join(lines[start : start + count])
    if not snippet.strip():
        return {"status": "mismatch", "detail": "the recorded line range is empty in this snapshot"}
    if sha256_text(snippet) == anchor.snippet_sha256:
        return {"status": "verified", "detail": "raw snippet digest matches the snapshot"}
    if sha256_text(snippet + "\n") == anchor.snippet_sha256:
        return {"status": "verified", "detail": "raw snippet digest (with newline) matches the snapshot"}
    normalized = code_sha256(snippet)
    if normalized == anchor.snippet_sha256:
        return {"status": "verified", "detail": "normalized snippet digest matches the snapshot"}
    return {
        "status": "mismatch",
        "detail": (
            f"expected {anchor.snippet_sha256[:12]} got raw "
            f"{sha256_text(snippet)[:12]} / normalized {normalized[:12]}"
        ),
    }


__all__ = [
    "ArtifactEntry",
    "CampaignRunner",
    "PIPELINE_SCHEMA_VERSION",
    "RunRecord",
    "SourceManifest",
    "TaskManifest",
    "VariantFreeze",
    "verify_target_anchor",
]
