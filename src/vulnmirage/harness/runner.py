"""Execute a release with a configured agent adapter and full observation."""

from __future__ import annotations

import json
import os
import random
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from ..config import LoadedConfig, load_agent_config
from ..credentials import ensure_credentials
from ..errors import HarnessError, VulnMirageError
from ..export.bundle import (
    ReleaseInstanceEntry,
    ReleaseManifest,
    load_release,
    materialize_release_instance,
    validate_release,
)
from ..hashing import (
    atomic_write_json,
    derive_seed,
    sha256_file,
    sha256_text,
    stable_id,
    utc_now_iso,
)
from ..logging import get_logger
from ..models import (
    AgentRun,
    BenchmarkInstance,
    CanonicalVulnerabilityOracle,
    DecoyRecord,
    EvidenceContract,
    ManipulationSpec,
    ObservabilityGrade,
    RunMeta,
    VariantKind,
)
from ..repository.git import worktree_digest
from ..store import InstanceStore
from .base import AgentAdapter, RawRunResult
from .observation import ObservationBundle, observe_run
from .observation.base import freeze_file
from .observation.normalize import NormalizedObservation
from .opencode import OpenCodeAdapter
from .subprocess_agent import SubprocessAgentAdapter
from .trace import summarize_trace

_LOG = get_logger("harness")


def _remove_tree(path: Path) -> None:
    def onerror(func, target, exc_info):
        try:
            Path(target).chmod(0o666)
        except OSError:
            pass
        func(target)

    shutil.rmtree(path, onerror=onerror)


def _adapter_class(name: str):
    if name == "opencode":
        return OpenCodeAdapter
    return SubprocessAgentAdapter


def _relative(loaded: LoadedConfig, path: Path) -> str:
    try:
        return path.resolve().relative_to(loaded.paths.root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _load_manifest_instance(release_root: Path, instance_id: str) -> BenchmarkInstance:
    return BenchmarkInstance.model_validate(
        json.loads(
            (release_root / "instances" / instance_id / "instance.json").read_text(encoding="utf-8")
        )
    )


def _load_release_assets(
    release_root: Path, entry: ReleaseInstanceEntry
) -> tuple[BenchmarkInstance, CanonicalVulnerabilityOracle, ManipulationSpec | None, list[DecoyRecord], EvidenceContract | None]:
    instance = _load_manifest_instance(release_root, entry.instance_id)
    oracle = CanonicalVulnerabilityOracle.model_validate(
        json.loads((release_root / "oracles" / f"{entry.oracle_id}.json").read_text(encoding="utf-8"))
    )
    manipulation = None
    if entry.manipulation_file:
        manipulation = ManipulationSpec.model_validate(
            json.loads((release_root / entry.manipulation_file).read_text(encoding="utf-8"))
        )
    decoys: list[DecoyRecord] = []
    decoy_path = release_root / "instances" / entry.instance_id / "decoys.json"
    if decoy_path.is_file():
        payload = json.loads(decoy_path.read_text(encoding="utf-8"))
        items = payload.get("decoys", payload) if isinstance(payload, dict) else payload
        decoys = [DecoyRecord.model_validate(item) for item in items]
    contract = None
    if entry.evidence_contract_file:
        contract = EvidenceContract.model_validate(
            json.loads((release_root / entry.evidence_contract_file).read_text(encoding="utf-8"))
        )
    return instance, oracle, manipulation, decoys, contract


def _ensure_source(
    loaded: LoadedConfig,
    manifest: ReleaseManifest,
    release_root: Path,
    entry: ReleaseInstanceEntry,
) -> Path:
    source_root = loaded.paths.runs / "_sources" / manifest.release_id / entry.instance_id
    repo = source_root / "repo"
    if repo.is_dir():
        try:
            if worktree_digest(repo) == entry.repository_tree_sha256:
                return repo
        except Exception:
            pass
    if source_root.exists():
        _remove_tree(source_root)
    materialized = materialize_release_instance(
        loaded,
        manifest,
        entry,
        source_root,
        release_dir=release_root,
    )
    digest = worktree_digest(materialized)
    if digest != entry.repository_tree_sha256:
        raise HarnessError(
            "materialized release source does not match the manifest digest",
            details={
                "instance_id": entry.instance_id,
                "expected": entry.repository_tree_sha256,
                "actual": digest,
            },
        )
    return materialized


def _draft_run(
    *,
    loaded: LoadedConfig,
    entry: ReleaseInstanceEntry,
    release_root: Path,
    run_id: str,
    repetition: int,
    agent_config,
    purpose: str = "evaluation",
    planned_repetitions: int | None = None,
) -> AgentRun:
    task = release_root / "instances" / entry.instance_id / "task.md"
    prompt_sha = sha256_file(task)
    run_dir = loaded.paths.run_dir(run_id)
    return AgentRun(
        run_id=run_id,
        instance_id=entry.instance_id,
        repetition=repetition,
        planned_repetitions=planned_repetitions,
        model_provider=agent_config.model_provider,
        model_name=agent_config.model_name,
        model_version=agent_config.model_version,
        scaffold=agent_config.scaffold or agent_config.adapter,
        scaffold_version=agent_config.scaffold_version,
        prompt_sha256=prompt_sha,
        tool_policy={},
        time_budget_seconds=agent_config.timeout_seconds,
        network_enabled=agent_config.network_enabled,
        started_at=utc_now_iso(),
        ended_at=utc_now_iso(),
        status="pending",
        findings_path=None,
        raw_events_path=_relative(loaded, run_dir / "events.raw.jsonl"),
        normalized_events_path=_relative(loaded, run_dir / "events.normalized.jsonl"),
        tool_calls_path=_relative(loaded, run_dir / "tool_calls.jsonl"),
        file_access_path=_relative(loaded, run_dir / "file_access.jsonl"),
        process_events_path=_relative(loaded, run_dir / "process_events.jsonl"),
        observability_grade="D",
        stdout_path=_relative(loaded, run_dir / "stdout.log"),
        stderr_path=_relative(loaded, run_dir / "stderr.log"),
        final_raw_path=_relative(loaded, run_dir / "final_raw.txt"),
        purpose=purpose,
        role="reference" if purpose == "reference" else "evaluation",
    )


def _resolve_output(loaded: LoadedConfig, run: AgentRun) -> Path | None:
    if not run.findings_path:
        return None
    path = Path(run.findings_path)
    return path if path.is_absolute() else loaded.paths.root / path


def _write_meta(
    *,
    loaded: LoadedConfig,
    run: AgentRun,
    prepared,
    entry: ReleaseInstanceEntry,
    manifest: ReleaseManifest,
    instance: BenchmarkInstance,
    raw: RawRunResult,
    parse_status: str,
    parse_error: str | None,
    observation: ObservationBundle,
    artifact_sha256: dict[str, str],
    pair_order_seed: int,
    pair_order_index: int,
    agent_config_sha256: str,
    release_root: Path,
    purpose: str = "evaluation",
    observation_capabilities: dict[str, Any] | None = None,
    execution_condition: dict[str, Any] | None = None,
    condition_id: str | None = None,
    defense=None,
    external_file_sha256: dict[str, str] | None = None,
    inference: dict[str, Any] | None = None,
    isolation_metadata: dict[str, Any] | None = None,
    planned_repetitions: int | None = None,
    attempt_selection_rule: str | None = None,
    retry_policy: dict[str, Any] | None = None,
    container_cleanup: dict[str, Any] | None = None,
) -> RunMeta:
    run_dir = prepared.run_dir
    stderr_excerpt = ""
    if raw.stderr_path.is_file():
        stderr_excerpt = raw.stderr_path.read_text(encoding="utf-8", errors="replace")[-1000:]
    raw_frozen = False
    try:
        raw_path = run_dir / "events.raw.jsonl"
        raw_frozen = raw_path.is_file() and not (raw_path.stat().st_mode & 0o222)
    except OSError:
        raw_frozen = False
    return RunMeta(
        run_id=run.run_id,
        instance_id=run.instance_id,
        pair_id=instance.pair_id,
        repetition=run.repetition,
        agent_config_sha256=agent_config_sha256,
        release_sha256=manifest.release_sha256,
        instance_manifest_sha256=sha256_file(
            release_root / "instances" / entry.instance_id / "instance.json"
        )
        or entry.repository_tree_sha256,
        task_sha256=sha256_file(prepared.task_path) or run.prompt_sha256,
        repo_tree_sha256_before=raw.digest_before or entry.repository_tree_sha256,
        repo_tree_sha256_after=raw.digest_after,
        contaminated=raw.contaminated,
        changed_files=raw.changed_files,
        exit_code=raw.exit_code,
        timed_out=raw.timed_out,
        duration_seconds=raw.duration_seconds,
        parse_status=parse_status,
        parse_error=parse_error,
        output_sha256=artifact_sha256.get("final_raw.txt"),
        trace_sha256=artifact_sha256.get("trace.jsonl"),
        network_enabled=prepared.network_enabled,
        sandbox_notes=prepared.sandbox_notes,
        stderr_excerpt=stderr_excerpt,
        metadata={
            "argv": prepared.argv,
            "agent_argv": prepared.agent_argv,
            "agent_config": "redacted",
            "raw_events_frozen": raw_frozen,
            "isolation": isolation_metadata or {},
        },
        observability_grade=observation.grade.value,
        native_event_count=observation.native_count,
        normalized_event_count=len(observation.primary_events),
        file_access_count=len(observation.normalized.file_access),
        tool_call_count=len(observation.normalized.tool_calls),
        observer_notes=observation.notes + observation.errors,
        pair_order_seed=pair_order_seed,
        pair_order_index=pair_order_index,
        derived_inputs_sha256={
            "events.normalized.jsonl": observation.artifact_sha256.get(
                "events.raw.jsonl", ""
            ),
            "tool_calls.jsonl": observation.artifact_sha256.get(
                "events.normalized.jsonl", ""
            ),
            "file_access.jsonl": observation.artifact_sha256.get(
                "events.normalized.jsonl", ""
            ),
            "process_events.jsonl": observation.artifact_sha256.get(
                "events.normalized.jsonl", ""
            ),
            "findings.json": artifact_sha256.get("final_raw.txt", ""),
            "trajectory_enriched.jsonl": observation.artifact_sha256.get(
                "events.normalized.jsonl", ""
            ),
            "verification_assessments.json": observation.artifact_sha256.get(
                "events.normalized.jsonl", ""
            ),
            "matches.json": artifact_sha256.get("findings.json", ""),
            "metrics.json": artifact_sha256.get("findings.json", ""),
        },
        artifact_sha256=artifact_sha256,
        raw_events_frozen=raw_frozen,
        purpose=purpose,
        role="reference" if purpose == "reference" else "evaluation",
        observation_capabilities=observation_capabilities or {},
        execution_condition=execution_condition or {},
        condition_id=condition_id,
        condition_source="explicit",
        external_file_sha256=external_file_sha256 or {},
        defense=defense.identity if defense is not None else {},
        inference=inference or {},
        attempt=run.attempt,
        isolation={
            **(isolation_metadata or {}),
            "repository_write_detected": bool(raw.changed_files),
            "notes": list(prepared.sandbox_notes),
        },
        task_template_sha256=prepared.metadata.get("base_prompt_sha256")
        or sha256_file(prepared.task_path),
        defense_instructions_sha256=(
            defense.instructions_sha256 if defense is not None else None
        ),
        effective_prompt_sha256=prepared.metadata.get("effective_prompt_sha256")
        or sha256_file(prepared.task_path),
        planned_repetitions=planned_repetitions,
        attempt_selection_rule=attempt_selection_rule,
        retry_policy=retry_policy or {},
        container_cleanup=container_cleanup or {},
    )


def _run_one(
    *,
    loaded: LoadedConfig,
    manifest: ReleaseManifest,
    release_root: Path,
    entry: ReleaseInstanceEntry,
    source_repo: Path,
    agent_config,
    agent_config_sha256: str,
    agent_base_dir: Path,
    repetition: int,
    resume: bool,
    pair_order_seed: int,
    pair_order_index: int,
    purpose: str = "evaluation",
    defense=None,
    execution_condition: dict[str, Any] | None = None,
    external_file_sha256: dict[str, str] | None = None,
    planned_repetitions: int | None = None,
    attempt_selection_rule: str | None = None,
    retry_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from ..evaluation.conditions import condition_id as compute_condition_id

    store = InstanceStore(loaded.paths)
    condition_id = compute_condition_id(execution_condition)
    if condition_id is None:
        raise HarnessError("execution condition identity could not be computed")
    # Resume and run identity include the full condition, not only the agent
    # YAML hash: external config/prompt edits and defense changes create a new
    # logical run (P0-1/P0-4).
    base_run_id = stable_id(
        "RUN",
        manifest.release_id,
        entry.instance_id,
        repetition,
        condition_id,
    )
    run_id = base_run_id
    attempt = 1
    run_dir = loaded.paths.run_dir(run_id)
    if run_dir.exists() and (run_dir / "run.json").is_file():
        if resume:
            existing = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
            return {
                "run_id": run_id,
                "instance_id": entry.instance_id,
                "status": "skipped_existing",
                "existing_status": existing.get("status"),
            }
        while run_dir.exists():
            attempt += 1
            run_id = f"{base_run_id}-b{attempt}"
            run_dir = loaded.paths.run_dir(run_id)
    if run_dir.exists():
        _remove_tree(run_dir)
    run_dir.mkdir(parents=True)
    instance, oracle, manipulation, decoys, contract = _load_release_assets(release_root, entry)
    draft = _draft_run(
        loaded=loaded,
        entry=entry,
        release_root=release_root,
        run_id=run_id,
        repetition=repetition,
        agent_config=agent_config,
        purpose=purpose,
        planned_repetitions=planned_repetitions,
    ).model_copy(
        update={
            "execution_condition": execution_condition or {},
            "condition_id": condition_id,
            "condition_source": "explicit",
            "defense_id": defense.id if defense is not None else None,
            "defense_version": defense.version if defense is not None else None,
            "attempt": attempt,
            "external_file_sha256": external_file_sha256 or {},
            "isolation_enforcement": "subprocess_isolated_repo_copy_best_effort",
        }
    )
    adapter_class = _adapter_class(agent_config.adapter)
    adapter: AgentAdapter = adapter_class(
        loaded=loaded,
        agent_config=agent_config,
        store=store,
        agent_base_dir=agent_base_dir,
        defense=defense,
    )
    try:
        prepared = adapter.prepare(
            instance,
            draft,
            source_repo=source_repo,
            task_path=release_root / "instances" / entry.instance_id / "task.md",
        )
        raw = adapter.execute(prepared)
        run = adapter.collect(prepared, raw)
    except Exception as exc:  # noqa: BLE001
        import traceback

        failure_type = "infrastructure_failure"
        details = getattr(exc, "details", None) or {}
        if details.get("failure_type") == "observation_setup_failure":
            failure_type = "observation_setup_failure"
        atomic_write_json(
            run_dir / "run_error.json",
            {
                "run_id": run_id,
                "instance_id": entry.instance_id,
                "status": failure_type,
                "error": str(exc),
                "details": details,
                "traceback": traceback.format_exc(),
            },
        )
        return {
            "run_id": run_id,
            "instance_id": entry.instance_id,
            "status": failure_type,
            "error": str(exc),
            "failure_details": details,
        }

    try:
        observation = observe_run(
            loaded=loaded,
            prepared=prepared,
            raw=raw,
            native_trace_path=prepared.trace_path,
            os_trace_path=prepared.os_trace_path,
        )
    except Exception as exc:  # noqa: BLE001
        observation = ObservationBundle(
            normalized=NormalizedObservation(),
            grade=ObservabilityGrade.D,
            native_count=0,
            wrapper_count=0,
            os_count=0,
            notes=[f"observer failure: {exc}"],
        )
        raw = raw.__class__(**{**raw.__dict__, "status": "observer_failure"})

    parse_status = "not_attempted"
    parse_error = None
    parsed = None
    if run.status in {"timeout", "agent_tool_failure"}:
        output_path = None
    else:
        output_path = prepared.output_path
    if output_path is not None and output_path.is_file():
        try:
            from ..evaluation.parser import parse_agent_output

            parsed = parse_agent_output(
                output_path.read_text(encoding="utf-8", errors="replace"),
                repo_root=prepared.repo_dir,
                source_path=output_path,
            )
            atomic_write_json(run_dir / "parsed.json", parsed.model_dump(mode="json"))
            parse_status = "ok"
        except VulnMirageError as exc:
            parse_status = "format_failure"
            parse_error = exc.message
            atomic_write_json(
                run_dir / "parse_error.json",
                {"error_code": exc.error_code, "message": exc.message, "details": exc.details},
            )
    if parse_status == "format_failure" and raw.status == "success":
        raw = raw.__class__(**{**raw.__dict__, "status": "format_failure"})
    # Normalised findings + deterministic human report (never an LLM rewrite).
    from .artifacts import (
        build_artifact_manifest,
        observation_capabilities,
        write_findings_and_report,
    )

    final_raw_path = prepared.final_raw_path or (run_dir / "final_raw.txt")
    if not final_raw_path.is_file():
        final_raw_path = run_dir / "final_raw.txt"
    findings_info = write_findings_and_report(
        run_dir,
        parsed=parsed,
        parse_status=parse_status,
        parse_error=parse_error,
        final_raw_path=final_raw_path,
    )
    capabilities = observation_capabilities(
        events=observation.primary_events,
        file_access=observation.normalized.file_access,
        importer=observation.importer,
        grade=observation.grade.value,
        parse_status=parse_status,
    )
    if observation.grade.value not in {"A", "B"}:
        # Outcome remains valid; process metrics are not reported.
        pass
    from ..evaluation.enrichment import enrich_run

    try:
        enrichment = enrich_run(
            loaded=loaded,
            store=store,
            run=run,
            prepared=prepared,
            raw_result=raw,
            instance=instance,
            oracle=oracle,
            manipulation=manipulation,
            decoys=decoys,
            contract=contract,
            parsed=parsed,
            observation=observation,
            parse_status=parse_status,
            parse_error=parse_error,
            end_monotonic_ns=raw.started_monotonic_ns
            + int(raw.duration_seconds * 1_000_000_000),
        )
    except Exception as exc:  # noqa: BLE001
        import traceback

        atomic_write_json(
            run_dir / "run_error.json",
            {
                "run_id": run_id,
                "instance_id": entry.instance_id,
                "status": "infrastructure_failure",
                "error": f"enrichment failed: {exc}",
                "traceback": traceback.format_exc(),
            },
        )
        return {
            "run_id": run_id,
            "instance_id": entry.instance_id,
            "status": "infrastructure_failure",
            "error": f"enrichment failed: {exc}",
        }
    run = enrichment.run.model_copy(update={"status": raw.status})

    # Legacy trace summary retained for compatibility.
    trace_path = prepared.trace_path
    if trace_path.is_file():
        legacy_summary = summarize_trace(
            trace_path, manipulation=manipulation, decoys=decoys, oracle=oracle
        )
        atomic_write_json(run_dir / "trace_summary.json", legacy_summary)
    artifact_sha256 = dict(enrichment.artifact_sha256)
    trace_sha = sha256_file(trace_path) if trace_path.is_file() else None
    if trace_sha:
        artifact_sha256["trace.jsonl"] = trace_sha
    final_raw = run_dir / "final_raw.txt"
    if final_raw.is_file():
        artifact_sha256["final_raw.txt"] = sha256_file(final_raw)
    findings_raw = run_dir / "findings_raw.txt"
    if findings_raw.is_file():
        artifact_sha256["findings_raw.txt"] = sha256_file(findings_raw)
    isolation_metadata = (prepared.metadata or {}).get("isolation") or {
        "enforcement": "subprocess_isolated_repo_copy_best_effort"
    }
    container_cleanup = (prepared.metadata or {}).get("container_cleanup") or {}
    if container_cleanup:
        isolation_metadata = {**isolation_metadata, "container_cleanup": container_cleanup}
    run = run.model_copy(
        update={
            "artifact_sha256": artifact_sha256,
            "raw_events_path": _relative(loaded, prepared.raw_events_path),
            "normalized_events_path": _relative(loaded, prepared.normalized_events_path),
            "tool_calls_path": _relative(loaded, prepared.tool_calls_path),
            "file_access_path": _relative(loaded, prepared.file_access_path),
            "process_events_path": _relative(loaded, prepared.process_events_path),
            "final_raw_path": _relative(loaded, final_raw),
            "observability_grade": observation.grade.value,
            "observation_capabilities": capabilities,
            "purpose": purpose,
            "role": "reference" if purpose == "reference" else "evaluation",
            "execution_condition": execution_condition or {},
            "condition_id": condition_id,
            "condition_source": "explicit",
            "defense_id": defense.id if defense is not None else None,
            "defense_version": defense.version if defense is not None else None,
            "attempt": attempt,
            "planned_repetitions": planned_repetitions,
            "external_file_sha256": external_file_sha256 or {},
            "isolation_enforcement": isolation_metadata.get("enforcement"),
        }
    )
    atomic_write_json(run_dir / "run.json", run)
    meta = _write_meta(
        loaded=loaded,
        run=run,
        prepared=prepared,
        entry=entry,
        manifest=manifest,
        instance=instance,
        raw=raw,
        parse_status=parse_status,
        parse_error=parse_error,
        observation=observation,
        artifact_sha256=artifact_sha256,
        pair_order_seed=pair_order_seed,
        pair_order_index=pair_order_index,
        agent_config_sha256=agent_config_sha256,
        release_root=release_root,
        purpose=purpose,
        observation_capabilities=capabilities,
        execution_condition=execution_condition,
        condition_id=condition_id,
        defense=defense,
        external_file_sha256=external_file_sha256,
        inference=getattr(agent_config, "inference", None),
        isolation_metadata=isolation_metadata,
        planned_repetitions=planned_repetitions,
        attempt_selection_rule=attempt_selection_rule,
        retry_policy=retry_policy,
        container_cleanup=container_cleanup,
    )
    atomic_write_json(run_dir / "meta.json", meta)
    atomic_write_json(run_dir / "run_meta.json", meta)
    manifest_result = build_artifact_manifest(
        run_dir,
        run_id=run.run_id,
        purpose=purpose,
        observation_capabilities=capabilities,
        parse_status=parse_status,
    )
    # Cross-reference the manifest hash from the run meta without including the
    # manifest in its own inputs.
    meta_payload = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
    meta_payload["artifact_manifest_sha256"] = manifest_result["sha256"]
    atomic_write_json(run_dir / "meta.json", meta_payload)
    atomic_write_json(run_dir / "run_meta.json", meta_payload)
    run = run.model_copy(
        update={
            "artifact_manifest_path": _relative(
                loaded, manifest_result["path"]
            )
        }
    )
    atomic_write_json(run_dir / "run.json", run)
    freeze_file(run_dir / "events.raw.jsonl")
    return {
        "run_id": run.run_id,
        "instance_id": run.instance_id,
        "pair_id": instance.pair_id,
        "status": run.status,
        "parse_status": parse_status,
        "exit_code": raw.exit_code,
        "timed_out": raw.timed_out,
        "contaminated": raw.contaminated,
        "duration_seconds": raw.duration_seconds,
        "observability_grade": observation.grade.value,
        "event_count": run.event_count,
        "pair_order_seed": pair_order_seed,
    }


def run_experiment_matrix(
    *,
    loaded: LoadedConfig,
    release_dir: Path,
    agent_config_paths: list[Path],
    defense_ids: list[str],
    repetitions: int | None,
    workers: int | None,
    instance_ids: list[str] | None,
    limit: int | None,
    resume: bool,
    purpose: str = "evaluation",
) -> dict[str, Any]:
    """Run release × agent_config × defense × repetition (P1-1).

    Each cell has its own execution-condition id; C/B/A/T runs for a defense are
    never borrowed from another defense because the condition id differs.
    """
    if not agent_config_paths:
        raise HarnessError("experiment matrix requires at least one agent config")
    if not defense_ids:
        defense_ids = [loaded.config.defense.default]
    cells: list[dict[str, Any]] = []
    for agent_path in agent_config_paths:
        for defense_id in defense_ids:
            result = run_release(
                loaded=loaded,
                release_dir=release_dir,
                agent_config_path=agent_path,
                repetitions=repetitions,
                workers=workers,
                instance_ids=instance_ids,
                limit=limit,
                resume=resume,
                purpose=purpose,
                defense_id=defense_id,
            )
            cells.append(
                {
                    "agent_config": str(agent_path),
                    "defense_id": defense_id,
                    "condition_id": result.get("condition_id"),
                    "run_count": result.get("run_count"),
                    "repetitions": result.get("repetitions"),
                    "failures": len(result.get("failures", [])),
                    "runs_dir": result.get("runs_dir"),
                }
            )
    return {
        "ok": True,
        "release_dir": str(Path(release_dir).resolve()),
        "cell_count": len(cells),
        "repetitions": repetitions or loaded.config.experiment.repetitions,
        "minimum_valid_repetitions": loaded.config.experiment.minimum_valid_repetitions,
        "retry_policy": loaded.config.experiment.retry_policy.model_dump(mode="json"),
        "matrix_kind": "agent_config x defense x repetition",
        "defenses": list(defense_ids),
        "cells": cells,
    }


def select_release_entries(
    manifest: ReleaseManifest,
    *,
    instance_ids: list[str] | None = None,
    limit: int | None = None,
) -> list[ReleaseInstanceEntry]:
    """Select instances and always keep the complete C/B/T closure.

    ``limit`` limits the number of *attack* instances; controls are added
    afterwards, so a limited run never loses its B/T comparison.  Shared clean
    runs appear once.
    """
    by_id = {entry.instance_id: entry for entry in manifest.instances}
    pairs = {pair.pair_id: pair for pair in manifest.pairs}
    group_by_adversarial = {
        group.adversarial_instance_id: group for group in manifest.groups
    }

    def closure(seeds: list[ReleaseInstanceEntry]) -> list[ReleaseInstanceEntry]:
        selected: dict[str, ReleaseInstanceEntry] = {}
        for entry in seeds:
            selected[entry.instance_id] = entry
        for entry in list(seeds):
            if entry.variant_kind != VariantKind.ADVERSARIAL:
                continue
            pair = pairs.get(entry.pair_id)
            if pair is not None and pair.clean_instance_id in by_id:
                selected[pair.clean_instance_id] = by_id[pair.clean_instance_id]
            group = group_by_adversarial.get(entry.instance_id)
            if group is not None:
                for control_id in (
                    group.benign_instance_id,
                    group.truthful_security_instance_id,
                ):
                    if control_id and control_id in by_id:
                        selected[control_id] = by_id[control_id]
        order = {
            entry.instance_id: index for index, entry in enumerate(manifest.instances)
        }
        return sorted(selected.values(), key=lambda item: order.get(item.instance_id, 0))

    if instance_ids:
        wanted = set(instance_ids)
        return closure(
            [entry for entry in manifest.instances if entry.instance_id in wanted]
        )
    if limit is not None:
        adversarial = sorted(
            (
                item
                for item in manifest.instances
                if item.variant_kind == VariantKind.ADVERSARIAL
            ),
            key=lambda item: item.instance_id,
        )
        return closure(adversarial[: max(limit, 0)])
    return closure(list(manifest.instances))


def _pair_order(
    selected_entries: list[ReleaseInstanceEntry],
    *,
    global_seed: int,
    release_id: str,
    repetition: int,
    randomize: bool,
) -> list[tuple[ReleaseInstanceEntry, int]]:
    groups: dict[str, list[ReleaseInstanceEntry]] = {}
    for entry in selected_entries:
        groups.setdefault(entry.pair_id, []).append(entry)
    output: list[tuple[ReleaseInstanceEntry, int]] = []
    for pair_id in sorted(groups):
        seed = derive_seed(global_seed, "pair_order", release_id, pair_id, repetition)
        group = list(groups[pair_id])
        if randomize:
            random.Random(seed).shuffle(group)
        output.extend((entry, seed) for entry in group)
    return output


def _agent_external_file_hashes(agent_loaded) -> dict[str, str]:
    """Content hashes of files the agent YAML *references*.

    Hashing only the YAML misses edits to an OpenCode JSON config or an external
    prompt file (P0-1 #4).
    """
    hashes: dict[str, str] = {}
    config_file = getattr(agent_loaded.config, "config_file", None)
    if config_file:
        path = Path(config_file)
        if not path.is_absolute():
            path = (agent_loaded.base_dir / path).resolve()
        if path.is_file():
            hashes[f"agent_config_file:{path.name}"] = sha256_file(path)
    return hashes


def build_run_execution_condition(
    *,
    loaded: LoadedConfig,
    agent_loaded,
    defense,
    base_prompt_sha256: str,
    external_file_sha256: dict[str, str],
    base_prompt_text: str | None = None,
) -> dict[str, Any]:
    """Canonical condition descriptor shared by run ids and evaluation."""
    from ..evaluation.conditions import build_execution_condition

    agent = agent_loaded.config
    present_credentials = [
        name
        for name in (getattr(agent, "credential_env_allowlist", None) or [])
        if name in os.environ
    ]
    return build_execution_condition(
        model_provider=agent.model_provider,
        model_name=agent.model_name,
        model_version=agent.model_version,
        scaffold=agent.scaffold or agent.adapter,
        scaffold_version=agent.scaffold_version,
        agent_config_sha256=agent_loaded.sha256,
        external_file_sha256=external_file_sha256,
        base_prompt_sha256=base_prompt_sha256,
        defense_instructions_sha256=(
            defense.instructions_sha256 if defense is not None else None
        ),
        effective_prompt_sha256=(
            sha256_text(defense.compose(base_prompt_text))
            if defense is not None and base_prompt_text is not None
            else None
        ),
        # Content identity: renaming a condition with identical instructions
        # does not create a distinct execution condition.
        defense=(
            {
                "instructions_sha256": defense.instructions_sha256,
                "runtime_evidence_gate": bool(
                    defense.spec.implements_runtime_evidence_gate
                ),
            }
            if defense is not None
            else {"instructions_sha256": sha256_text("")}
        ),
        tool_policy={"adapter": agent.adapter, "network_enabled": agent.network_enabled},
        network_enabled=agent.network_enabled,
        token_budget=None,
        time_budget_seconds=agent.timeout_seconds,
        inference=getattr(agent, "inference", None),
        credential_env_names=present_credentials,
        isolation=(
            {
                "enforcement": "container",
                "runtime": getattr(agent, "container_runtime", None),
                "network": getattr(agent, "container_network", "none"),
                "image": getattr(agent, "container_image", None),
            }
            if getattr(agent, "execution_backend", "subprocess") == "container"
            else {
                "enforcement": "subprocess_isolated_repo_copy_best_effort",
                "host_workspace_visible_to_agent": True,
            }
        ),
    )


def run_release(
    *,
    loaded: LoadedConfig,
    release_dir: Path,
    agent_config_path: Path,
    repetitions: int | None,
    workers: int | None,
    instance_ids: list[str] | None,
    limit: int | None,
    resume: bool,
    purpose: str = "evaluation",
    defense_id: str | None = None,
) -> dict[str, Any]:
    loaded.paths.ensure_layout()
    manifest, release_root = load_release(release_dir)
    integrity = validate_release(loaded=loaded, release_dir=release_root)
    if not integrity["ok"]:
        raise HarnessError(
            "release bundle failed integrity validation",
            details={"errors": integrity["errors"][:20]},
        )
    agent_loaded = load_agent_config(agent_config_path)
    agent_config = agent_loaded.config
    if agent_config.network_enabled and not loaded.config.network.agent_enabled:
        raise HarnessError("agent network is disabled by network.agent_enabled")
    # P0-2 #5: a declared credential must reach the agent, or the live run must
    # stop *before* the agent is invoked with an infrastructure error.
    credential_status = ensure_credentials(agent_config, context="run_release")

    from ..defenses import resolve_defense

    defense = resolve_defense(loaded, defense_id)
    # The task template stored in the release is what the agent actually
    # receives; fall back to the configured asset for unusual/older bundles.
    base_prompt_text = None
    if manifest.instances:
        task_candidate = (
            release_root
            / "instances"
            / manifest.instances[0].instance_id
            / "task.md"
        )
        if task_candidate.is_file():
            base_prompt_text = task_candidate.read_text(encoding="utf-8")
    if base_prompt_text is None:
        base_prompt_path = loaded.resolve_asset(loaded.config.audit_task.template)
        base_prompt_text = base_prompt_path.read_text(encoding="utf-8")
    base_prompt_sha256 = sha256_text(base_prompt_text)
    external_file_sha256 = _agent_external_file_hashes(agent_loaded)
    execution_condition = build_run_execution_condition(
        loaded=loaded,
        agent_loaded=agent_loaded,
        defense=defense,
        base_prompt_sha256=base_prompt_sha256,
        external_file_sha256=external_file_sha256,
        base_prompt_text=base_prompt_text,
    )
    from ..evaluation.conditions import condition_id as compute_condition_id

    condition_id = compute_condition_id(execution_condition)
    if condition_id is None:
        raise HarnessError("execution condition identity is empty")
    selected_entries = select_release_entries(
        manifest, instance_ids=instance_ids, limit=limit
    )
    if not selected_entries:
        raise HarnessError("no release instances selected")

    sources: dict[str, Path] = {}
    for entry in selected_entries:
        sources[entry.instance_id] = _ensure_source(loaded, manifest, release_root, entry)
    experiment = loaded.config.experiment
    effective_repetitions = int(repetitions or experiment.repetitions)
    retry_policy = experiment.retry_policy.model_dump(mode="json")
    attempt_rule = experiment.retry_policy.selection_rule
    workers = workers or agent_config.workers or loaded.config.execution.workers
    jobs: list[tuple[ReleaseInstanceEntry, int, int, int]] = []
    for repetition in range(1, effective_repetitions + 1):
        ordered = _pair_order(
            selected_entries,
            global_seed=loaded.config.generation.global_seed,
            release_id=manifest.release_id,
            repetition=repetition,
            randomize=loaded.config.execution.randomize_pair_order,
        )
        for index, (entry, seed) in enumerate(ordered):
            jobs.append((entry, repetition, seed, index))
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    def task(entry, repetition, seed, index) -> dict[str, Any]:
        return _run_one(
            loaded=loaded,
            manifest=manifest,
            release_root=release_root,
            entry=entry,
            source_repo=sources[entry.instance_id],
            agent_config=agent_config,
            agent_config_sha256=agent_loaded.sha256,
            agent_base_dir=agent_loaded.base_dir,
            repetition=repetition,
            resume=resume,
            pair_order_seed=seed,
            pair_order_index=index,
            purpose=purpose,
            defense=defense,
            execution_condition=execution_condition,
            external_file_sha256=external_file_sha256,
            planned_repetitions=effective_repetitions,
            attempt_selection_rule=attempt_rule,
            retry_policy=retry_policy,
        )

    with ThreadPoolExecutor(max_workers=max(workers, 1)) as executor:
        futures = {
            executor.submit(task, entry, repetition, seed, index): (entry, repetition)
            for entry, repetition, seed, index in jobs
        }
        for future in as_completed(futures):
            entry, repetition = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001
                failures.append(
                    {
                        "instance_id": entry.instance_id,
                        "repetition": repetition,
                        "failure_type": "infrastructure_failure",
                        "error": str(exc),
                    }
                )
                continue
            results.append(result)
            if result.get("status") == "infrastructure_failure":
                failures.append(result)
    results.sort(key=lambda item: (item.get("instance_id", ""), item.get("run_id", "")))
    experiment_manifest = {
        "release_id": manifest.release_id,
        "condition_id": condition_id,
        "defense": defense.identity,
        "agent_config_sha256": agent_loaded.sha256,
        "repetitions": effective_repetitions,
        "repetitions_source": (
            "cli_override" if repetitions else "experiment.repetitions"
        ),
        "minimum_valid_repetitions": experiment.minimum_valid_repetitions,
        "retry_policy": retry_policy,
        "attempt_selection_rule": attempt_rule,
        "instance_count": len(selected_entries),
        "planned_run_count": len(jobs),
        "credential_status": credential_status.as_dict(),
        "execution_condition": execution_condition,
    }
    manifest_path = loaded.paths.runs / (
        f"_experiment_manifest_{condition_id[:16]}.json"
    )
    atomic_write_json(manifest_path, experiment_manifest)
    return {
        "ok": True,
        "release_id": manifest.release_id,
        "release_dir": str(release_root.resolve()),
        "agent_config_sha256": agent_loaded.sha256,
        "condition_id": condition_id,
        "execution_condition": execution_condition,
        "external_file_sha256": external_file_sha256,
        "defense": defense.identity,
        "repetitions": effective_repetitions,
        "repetitions_source": experiment_manifest["repetitions_source"],
        "minimum_valid_repetitions": experiment.minimum_valid_repetitions,
        "retry_policy": retry_policy,
        "credential_status": credential_status.as_dict(),
        "experiment_manifest": str(manifest_path.resolve()),
        "workers": workers,
        "run_count": len([item for item in results if item.get("status") != "skipped_existing"]),
        "skipped": [item for item in results if item.get("status") == "skipped_existing"],
        "runs": results,
        "failures": failures,
        "runs_dir": str(loaded.paths.runs.resolve()),
        "pair_order_seeds": sorted({item.get("pair_order_seed") for item in results if item.get("pair_order_seed")}),
    }
