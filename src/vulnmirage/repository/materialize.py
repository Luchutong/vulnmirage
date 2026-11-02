"""Cache + isolated worktree materialization and the M0 clean instance."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from ..config import LoadedConfig
from ..errors import GenerationError, RepositoryError
from ..hashing import atomic_write_json, derive_seed, sha256_file, sha256_text
from ..models import (
    BenchmarkInstance,
    CanonicalVulnerabilityOracle,
    RepositoryRef,
    Stage,
    VariantKind,
)
from ..paths import ensure_within, safe_join
from ..repository.cache import RepositoryCache
from ..repository.git import git_output, status_porcelain, tree_hash, worktree_digest
from ..repository.location_remap import resolve_oracle_locations
from ..repository.worktree import create_worktree, remove_worktree
from ..store import (
    InstanceState,
    InstanceStore,
    HistoryEntry,
    clean_instance_id,
    now_iso,
    pair_id_for,
    render_audit_task,
)


def load_oracle(path: Path) -> CanonicalVulnerabilityOracle:
    path = Path(path)
    if not path.is_file():
        raise GenerationError("oracle file does not exist", details={"path": str(path)})
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GenerationError(
            "invalid oracle JSON", details={"path": str(path), "error": str(exc)}
        ) from exc
    return CanonicalVulnerabilityOracle.model_validate(payload)


def aligned_oracle_path(loaded: LoadedConfig, oracle_id: str) -> Path:
    return loaded.paths.normalized / f"{oracle_id}.aligned.json"


def materialized_pointer_path(loaded: LoadedConfig, oracle_id: str) -> Path:
    return loaded.paths.normalized / f"{oracle_id}.materialized.json"


def read_materialized_pointer(loaded: LoadedConfig, oracle_id: str) -> dict[str, Any] | None:
    path = materialized_pointer_path(loaded, oracle_id)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _write_pointer(loaded: LoadedConfig, payload: dict[str, Any]) -> Path:
    path = materialized_pointer_path(loaded, payload["oracle_id"])
    atomic_write_json(path, payload)
    return path


def _cleanup_instance(
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


def ensure_worktree(
    loaded: LoadedConfig,
    store: InstanceStore,
    cache_path: Path,
    commit: str,
    instance_id: str,
) -> Path:
    destination = store.repo_dir(instance_id)
    if destination.is_dir() and (destination / ".git").exists():
        try:
            if git_output(["rev-parse", "HEAD"], cwd=destination).lower() == commit.lower():
                return destination
        except RepositoryError:
            pass
        remove_worktree(cache_path, destination, worktrees_root=loaded.paths.worktrees)
    return create_worktree(
        cache_path,
        commit,
        destination,
        worktrees_root=loaded.paths.worktrees,
        force=True,
    )


def materialize_oracle_file(
    *,
    loaded: LoadedConfig,
    oracle_path: Path,
    force: bool = False,
    repo_override: str | None = None,
    fetch: bool = False,
) -> dict[str, Any]:
    loaded.paths.ensure_layout()
    store = InstanceStore(loaded.paths)
    oracle = load_oracle(oracle_path)
    if repo_override:
        if repo_override.strip() == oracle.repository.repo_url:
            repo_override = None
        else:
            oracle = oracle.model_copy(
                update={
                    "repository": oracle.repository.model_copy(
                        update={
                            "repo_url": repo_override.strip(),
                            "source_tree_sha256": None,
                        }
                    )
                }
            )
    config_sha = loaded.sha256
    existing_clean = store.find_clean(oracle.oracle_id, config_sha256=config_sha)
    pointer = read_materialized_pointer(loaded, oracle.oracle_id)
    if existing_clean is not None and not force:
        worktree = ensure_worktree(
            loaded,
            store,
            _cache_path_for(loaded, existing_clean.repository.repo_url, fetch=False),
            existing_clean.repository.vulnerable_commit,
            existing_clean.instance_id,
        )
        state = store.load_state(existing_clean.instance_id)
        aligned_path = aligned_oracle_path(loaded, oracle.oracle_id)
        if aligned_path.is_file():
            aligned = CanonicalVulnerabilityOracle.model_validate(
                json.loads(aligned_path.read_text(encoding="utf-8"))
            )
        else:
            aligned = store.load_oracle(existing_clean.instance_id)
            atomic_write_json(aligned_path, aligned)
        if not store.evidence_contract_path(existing_clean.instance_id).is_file():
            from ..generation.evidence_contract import build_evidence_contract

            contract = build_evidence_contract(
                instance_id=existing_clean.instance_id,
                oracle=aligned,
                manipulation=None,
                plan=None,
                decoys=[],
                repo_root=worktree,
                is_clean=True,
            )
            contract_relative, _ = store.write_evidence_contract(
                existing_clean.instance_id, contract
            )
            existing_clean = existing_clean.model_copy(
                update={"evidence_contract_ref": contract_relative}
            )
            store.save_instance(existing_clean)
        if pointer is None:
            pointer = _build_pointer(
                oracle_id=oracle.oracle_id,                oracle_sha256=sha256_text(
                    json.dumps(aligned.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
                ),
                clean_id=existing_clean.instance_id,
                pair_id=existing_clean.pair_id,
                config_sha=config_sha,
                seed=existing_clean.random_seed,
                round_number=state.generation_round,
                repo_url=existing_clean.repository.repo_url,
                commit=existing_clean.repository.vulnerable_commit,
                aligned_path=aligned_path,
            )
            _write_pointer(loaded, pointer)
        return {
            "ok": True,
            "created": False,
            "reason": "clean instance already materialized (use --force for a new version)",
            "instance_id": existing_clean.instance_id,
            "pair_id": existing_clean.pair_id,
            "oracle_id": oracle.oracle_id,
            "oracle_path": str(aligned_path),
            "oracle_sha256": pointer.get("oracle_sha256"),
            "task_file": existing_clean.task_file,
            "task_sha256": state.task_sha256,
            "repository_tree_sha256": existing_clean.repository_tree_sha256,
            "worktree": str(worktree),
            "generation_config_sha256": config_sha,
            "validation_level": aligned.validation_level,
            "vulnerability_count": len(aligned.vulnerabilities),
            "entry_count": len(aligned.source_record_ids),
        }

    network = loaded.config.network
    cache = RepositoryCache(loaded.paths.cache, network)
    repo, cache_path = cache.ensure(oracle.repository.repo_url, fetch=fetch)
    cache.verify_commit(cache_path, oracle.repository.vulnerable_commit)
    refs_snapshot = cache.refs_snapshot(cache_path)

    rounds = 1
    if existing_clean is not None and force:
        try:
            rounds = store.load_state(existing_clean.instance_id).generation_round + 1
        except Exception:
            rounds = 2
    pair_id = pair_id_for(oracle.oracle_id, config_sha, loaded.config.generation.global_seed, rounds)
    instance_id = clean_instance_id(pair_id)
    if store.exists(instance_id):
        raise GenerationError(
            "instance directory already exists but no matching clean instance was found; "
            "re-run with --force to create a new version",
            details={"instance_id": instance_id, "instance_dir": str(store.instance_dir(instance_id))},
        )

    worktree = create_worktree(
        cache_path,
        oracle.repository.vulnerable_commit,
        store.repo_dir(instance_id),
        worktrees_root=loaded.paths.worktrees,
        force=True,
    )
    if status_porcelain(worktree):
        raise RepositoryError(
            "fresh worktree is not clean",
            details={"worktree": str(worktree), "status": status_porcelain(worktree)},
        )
    head_tree = git_output(["rev-parse", "HEAD^{tree}"], cwd=worktree)
    checked_tree = tree_hash(worktree)
    if checked_tree != head_tree:
        raise RepositoryError(
            "materialized worktree tree does not match the commit tree",
            details={"expected": head_tree, "actual": checked_tree},
        )

    aligned, resolve_summary = resolve_oracle_locations(oracle, worktree)
    from ..generation.evidence_contract import (
        build_evidence_contract,
        validate_evidence_contract,
    )

    contract = build_evidence_contract(
        instance_id=instance_id,
        oracle=aligned,
        manipulation=None,
        plan=None,
        decoys=[],
        repo_root=worktree,
        is_clean=True,
    )
    contract_errors = validate_evidence_contract(contract, repo_root=worktree, is_clean=True)
    if contract_errors:
        raise RepositoryError(
            "clean evidence contract is invalid", details={"errors": contract_errors}
        )
    contract_relative, _ = store.write_evidence_contract(instance_id, contract)
    task_text = render_audit_task(loaded)
    task_sha = sha256_text(task_text)
    instance = BenchmarkInstance(
        instance_id=instance_id,
        pair_id=pair_id,
        schema_version="1.0",
        variant_kind=VariantKind.CLEAN,
        oracle_ref=aligned.oracle_id,
        repository=aligned.repository,
        audit_difficulty=aligned.effective_difficulty,
        manipulation_tier="M0",
        manipulation_ref=None,
        evidence_contract_ref=contract_relative,
        task_file=f"instances/{instance_id}/task.md",
        patch_file=None,
        repository_tree_sha256=worktree_digest(worktree),
        generation_config_sha256=config_sha,
        random_seed=derive_seed(
            loaded.config.generation.global_seed, aligned.oracle_id, "M0", rounds
        ),
        release_split=loaded.config.generation.split,
    )

    directory = store.ensure_instance_dir(instance_id)
    store.write_task(instance_id, task_text)
    store.write_oracle(instance_id, aligned)
    store.save_instance(instance)
    aligned_path = aligned_oracle_path(loaded, aligned.oracle_id)
    atomic_write_json(aligned_path, aligned)
    oracle_sha = sha256_file(aligned_path)

    timestamp = now_iso()
    state = InstanceState(
        instance_id=instance_id,
        oracle_id=aligned.oracle_id,
        pair_id=pair_id,
        variant_kind=VariantKind.CLEAN,
        stage=Stage.ORACLE_ALIGNED.value,
        created_at=timestamp,
        updated_at=timestamp,
        generation_config_sha256=config_sha,
        oracle_sha256=oracle_sha,
        task_sha256=task_sha,
        clean_instance_id=instance_id,
        cache_refs_sha256=refs_snapshot,
        base_tree_sha256=head_tree,
        variant_tree_sha256=head_tree,
        random_seed=instance.random_seed,
        operator_names=[],
        payload_ids=[],
        generation_round=rounds,
        history=[
            HistoryEntry(stage=Stage.MATERIALIZED.value, at=timestamp),
            HistoryEntry(
                stage=Stage.ORACLE_ALIGNED.value,
                at=timestamp,
                detail=f"resolved {resolve_summary.get('locations_resolved')} locations",
            ),
        ],
        notes={
            "repo_override": repo_override,
            "original_repo_url": load_oracle(oracle_path).repository.repo_url,
            "aligned_oracle": str(aligned_path),
            "worktree": str(worktree),
            "cache_path": str(cache_path),
            "resolve": resolve_summary,
        },
    )
    store.save_state(state)
    pointer = _build_pointer(
        oracle_id=aligned.oracle_id,
        oracle_sha256=oracle_sha,
        clean_id=instance_id,
        pair_id=pair_id,
        config_sha=config_sha,
        seed=instance.random_seed,
        round_number=rounds,
        repo_url=instance.repository.repo_url,
        commit=instance.repository.vulnerable_commit,
        aligned_path=aligned_path,
    )
    pointer_path = _write_pointer(loaded, pointer)
    return {
        "ok": True,
        "created": True,
        "instance_id": instance.instance_id,
        "pair_id": pair_id,
        "oracle_id": aligned.oracle_id,
        "oracle_path": str(aligned_path),
        "materialized_pointer": str(pointer_path),
        "oracle_sha256": oracle_sha,
        "task_file": instance.task_file,
        "task_sha256": task_sha,
        "repository_tree_sha256": instance.repository_tree_sha256,
        "worktree": str(worktree),
        "cache_path": str(cache_path),
        "cache_refs_sha256": refs_snapshot,
        "generation_config_sha256": config_sha,
        "vulnerability_count": len(aligned.vulnerabilities),
        "entry_count": len(aligned.source_record_ids),
        "locations_resolved": resolve_summary.get("locations_resolved"),
        "validation_level": aligned.validation_level,
        "instance_dir": str(directory),
    }


def _cache_path_for(loaded: LoadedConfig, repo_url: str, *, fetch: bool) -> Path:
    cache = RepositoryCache(loaded.paths.cache, loaded.config.network)
    _, path = cache.ensure(repo_url, fetch=fetch)
    return path


def _build_pointer(
    *,
    oracle_id: str,
    oracle_sha256: str,
    clean_id: str,
    pair_id: str,
    config_sha: str,
    seed: int,
    round_number: int,
    repo_url: str,
    commit: str,
    aligned_path: Path,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "oracle_id": oracle_id,
        "oracle_sha256": oracle_sha256,
        "clean_instance_id": clean_id,
        "pair_id": pair_id,
        "generation_config_sha256": config_sha,
        "seed": seed,
        "generation_round": round_number,
        "repo_url": repo_url,
        "vulnerable_commit": commit,
        "aligned_oracle_file": str(aligned_path),
        "materialized_at": now_iso(),
    }


def load_materialized_oracle(
    loaded: LoadedConfig, oracle_path: Path
) -> tuple[CanonicalVulnerabilityOracle, BenchmarkInstance, dict[str, Any]]:
    """Load the aligned oracle + clean instance for generation."""
    oracle = load_oracle(oracle_path)
    store = InstanceStore(loaded.paths)
    pointer = read_materialized_pointer(loaded, oracle.oracle_id)
    if pointer:
        instance_id = pointer.get("clean_instance_id")
        pointer_config = pointer.get("generation_config_sha256")
        if (
            instance_id
            and pointer_config == loaded.sha256
            and store.exists(instance_id)
        ):
            instance = store.load_instance(instance_id)
            aligned = store.load_oracle(instance_id)
            if instance.variant_kind == VariantKind.CLEAN and instance.oracle_ref == oracle.oracle_id:
                return aligned, instance, pointer
    clean = store.find_clean(oracle.oracle_id, config_sha256=loaded.sha256)
    if clean is None:
        raise GenerationError(
            "oracle has not been materialized for this configuration; run `vulnmirage materialize` first",
            details={"oracle_id": oracle.oracle_id, "oracle_path": str(oracle_path)},
        )
    aligned = store.load_oracle(clean.instance_id)
    return aligned, clean, {"clean_instance_id": clean.instance_id, "pair_id": clean.pair_id}
