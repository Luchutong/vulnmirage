"""Release bundle export, hashing and integrity validation."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError as PydanticValidationError

from ..config import LoadedConfig
from ..errors import ReleaseError
from ..hashing import (
    atomic_write_json,
    atomic_write_text,
    canonical_json,
    sha256_file,
    sha256_text,
    stable_id,
    utc_now_iso,
)
from ..models import (
    AttackGoal,
    BenchmarkInstance,
    CanonicalVulnerabilityOracle,
    InstanceGroup,
    ManipulationSpec,
    ValidationReport,
    VariantGroup,
    VariantKind,
)
from ..paths import ensure_within
from ..repository.cache import RepositoryCache
from ..repository.git import tree_hash, worktree_digest
from ..repository.patch import apply_patch
from ..repository.worktree import create_worktree
from ..store import InstanceStore, now_iso

_RELEASE_SCHEMA_VERSION = "1.0"


class ReleaseFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int


class ReleaseInstanceEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: str
    pair_id: str
    variant_kind: VariantKind
    manipulation_tier: str
    audit_difficulty: str
    attack_goal: str | None = None
    release_split: str
    oracle_id: str
    manipulation_id: str | None = None
    evidence_contract_file: str | None = None
    repository_url: str
    vulnerable_commit: str
    release_eligible: bool
    repository_tree_sha256: str
    task_file: str
    patch_file: str | None = None
    oracle_file: str
    manipulation_file: str | None = None
    validation_file: str
    files: list[ReleaseFile] = Field(default_factory=list)
    #: Variant-group membership (candidate/benign pairing).
    group_id: str | None = None
    candidate_id: str | None = None
    generation_method: str | None = None
    purpose: str = "evaluation"
    target_id: str | None = None
    target_kind: str | None = None
    eligible_target_ids: list[str] = Field(default_factory=list)


class ReleasePair(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pair_id: str
    clean_instance_id: str
    adversarial_instance_ids: list[str] = Field(default_factory=list)


class ReleaseManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    release_id: str
    name: str
    release_version: str
    created_at: str
    config_sha256: str
    source_dataset: str
    splits: list[str]
    instance_count: int
    pair_count: int
    instances: list[ReleaseInstanceEntry]
    pairs: list[ReleasePair]
    payload_registry_sha256: str | None = None
    prompt_sha256: str | None = None
    release_sha256: str = ""
    notes: dict[str, Any] = Field(default_factory=dict)
    #: Clean/benign/adversarial variant groups (candidate-level pairing).
    groups: list[VariantGroup] = Field(default_factory=list)
    purpose: str = "evaluation"
    artifact_manifest_file: str | None = None

    @property
    def clean_by_pair(self) -> dict[str, str]:
        return {pair.pair_id: pair.clean_instance_id for pair in self.pairs}


def _copy_if_exists(source: Path, destination: Path, release_root: Path) -> ReleaseFile | None:
    if not source.is_file():
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return ReleaseFile(
        path=destination.relative_to(release_root).as_posix(),
        sha256=sha256_file(destination),
        size=destination.stat().st_size,
    )


def _instance_files(store: InstanceStore, instance_id: str) -> dict[str, Path]:
    directory = store.instance_dir(instance_id)
    names = [
        "instance.json",
        "task.md",
        "oracle.json",
        "manipulation.json",
        "decoys.json",
        "validation.json",
        "patch.diff",
        "patch_meta.json",
        "operator_local_checks.json",
        "evidence_contract.json",
        "attack_plan.json",
        "safe_targets.json",
        "state.json",
    ]
    return {name: directory / name for name in names if (directory / name).is_file()}


def _load_state_dict(store: InstanceStore, instance_id: str) -> dict[str, Any]:
    state = store.load_state(instance_id)
    payload = state.model_dump(mode="json")
    notes = dict(payload.get("notes") or {})
    for key in ("worktree", "cache_path", "aligned_oracle"):
        notes.pop(key, None)
    payload["notes"] = notes
    return payload


def _eligible(store: InstanceStore, instance_id: str) -> tuple[bool, dict[str, Any] | None]:
    try:
        validation = store.load_validation(instance_id)
        state = store.load_state(instance_id)
    except Exception:
        return False, None
    ok = bool(
        validation
        and validation.get("release_eligible")
        and state.release_eligible
        and state.stage in {"validated", "frozen", "exported"}
    )
    return ok, validation


def _selection_plan(
    store: InstanceStore,
    selected_ids: set[str],
) -> tuple[set[str], list[dict[str, Any]]]:
    """Closure of an explicit selection manifest: attacks keep C/B/T.

    Controls that belong to a non-selected attack are *not* re-added; that is
    how an excluded duplicate cannot drag a useless control into the release.
    """
    groups = {group.adversarial_instance_id: group for group in store.load_groups().groups}
    closure = set(selected_ids)
    missing: list[dict[str, Any]] = []
    known = set(store.iter_instance_ids())
    for instance_id in sorted(selected_ids):
        if instance_id not in known:
            missing.append({"instance_id": instance_id, "reason": "not_in_instance_store"})
            continue
        try:
            instance = store.load_instance(instance_id)
        except Exception as exc:  # noqa: BLE001
            missing.append({"instance_id": instance_id, "reason": f"unreadable:{exc}"})
            continue
        if instance.variant_kind == VariantKind.ADVERSARIAL:
            group = groups.get(instance_id)
            if group is not None:
                for control in (
                    group.clean_instance_id,
                    group.benign_instance_id,
                    group.truthful_security_instance_id,
                ):
                    if control:
                        closure.add(control)
            else:
                for other in known:
                    try:
                        candidate = store.load_instance(other)
                    except Exception:
                        continue
                    if (
                        candidate.pair_id == instance.pair_id
                        and candidate.variant_kind == VariantKind.CLEAN
                    ):
                        closure.add(other)
    return closure, missing


def export_release(
    *,
    loaded: LoadedConfig,
    instances_dir: Path,
    output_dir: Path,
    only_release_eligible: bool = True,
    release_name: str = "vulnmirage",
    release_version: str = "v0.1",
    instance_ids: list[str] | None = None,
    purpose: str = "evaluation",
    use_selection_manifest: bool | None = None,
) -> dict[str, Any]:
    instances_dir = Path(instances_dir)
    output_dir = Path(output_dir)
    store = InstanceStore(loaded.paths)
    wanted = set(instance_ids) if instance_ids else None
    manifest_selection: dict[str, Any] | None = None
    if use_selection_manifest is None:
        use_selection_manifest = loaded.config.generation.export_use_selection_manifest
    if use_selection_manifest and wanted is None:
        manifest_path = instances_dir / "selection_manifest.json"
        if manifest_path.is_file():
            manifest_selection = json.loads(manifest_path.read_text(encoding="utf-8"))
            selected_ids = {
                item["instance_id"]
                for item in manifest_selection.get("candidates", [])
                if item.get("selected_for_release") and item.get("instance_id")
            }
            wanted, missing = _selection_plan(store, selected_ids)
            if missing:
                manifest_selection["missing_selected_instances"] = missing
    candidates: list[tuple[BenchmarkInstance, bool, dict[str, Any] | None]] = []
    for instance_id in store.iter_instance_ids():
        if wanted is not None and instance_id not in wanted:
            continue
        try:
            instance = store.load_instance(instance_id)
        except Exception:
            continue
        eligible, validation = _eligible(store, instance.instance_id)
        if only_release_eligible and not eligible:
            continue
        candidates.append((instance, eligible, validation))
    if not candidates:
        raise ReleaseError(
            "no instances are eligible for export",
            details={"instances_dir": str(instances_dir), "only_release_eligible": only_release_eligible},
        )

    clean_by_pair: dict[str, list[BenchmarkInstance]] = {}
    for instance, eligible, _ in candidates:
        if instance.variant_kind == VariantKind.CLEAN:
            clean_by_pair.setdefault(instance.pair_id, []).append(instance)
    for pair_id, cleans in clean_by_pair.items():
        if len(cleans) > 1:
            raise ReleaseError(
                "pair contains more than one clean instance", details={"pair_id": pair_id}
            )
    selected: list[BenchmarkInstance] = []
    skipped: list[dict[str, Any]] = []
    for instance, eligible, _ in candidates:
        if instance.variant_kind == VariantKind.ADVERSARIAL:
            cleans = clean_by_pair.get(instance.pair_id, [])
            if not cleans:
                skipped.append(
                    {
                        "instance_id": instance.instance_id,
                        "reason": "adversarial instance has no exported clean pair",
                    }
                )
                continue
            if cleans[0].release_split != instance.release_split:
                raise ReleaseError(
                    "pair members have different release splits",
                    details={"pair_id": instance.pair_id},
                )
        selected.append(instance)
    if not selected:
        raise ReleaseError("no instances with complete clean pairs could be exported")

    repository_splits: dict[str, set[str]] = {}
    commit_splits: dict[tuple[str, str], set[str]] = {}
    for instance in selected:
        repository_splits.setdefault(instance.repository.repo_url, set()).add(instance.release_split)
        commit_splits.setdefault(
            (instance.repository.repo_url, instance.repository.vulnerable_commit), set()
        ).add(instance.release_split)
    for repository, splits in repository_splits.items():
        if len(splits) > 1:
            raise ReleaseError(
                "the same repository appears in multiple release splits",
                details={"repository": repository, "splits": sorted(splits)},
            )
    leaked = [
        {"repository": repo, "commit": commit, "splits": sorted(splits)}
        for (repo, commit), splits in commit_splits.items()
        if any(item.startswith("dev-") for item in splits)
        and any(item.startswith("test-") for item in splits)
    ]
    if leaked:
        raise ReleaseError(
            "the same repository commit appears in both dev and test splits",
            details={"leaks": leaked},
        )

    if output_dir.exists() and any(output_dir.iterdir()):
        raise ReleaseError(
            "release output directory is not empty; choose a new path or remove it explicitly",
            details={"output": str(output_dir)},
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    instance_root = output_dir / "instances"
    oracle_root = output_dir / "oracles"
    provenance_root = output_dir / "provenance"
    instance_root.mkdir()
    oracle_root.mkdir()
    provenance_root.mkdir()

    entries: list[ReleaseInstanceEntry] = []
    pairs_map: dict[str, ReleasePair] = {}
    for instance in sorted(selected, key=lambda item: item.instance_id):
        source_dir = store.instance_dir(instance.instance_id)
        target_dir = instance_root / instance.instance_id
        target_dir.mkdir(parents=True, exist_ok=True)
        files: list[ReleaseFile] = []
        for name, source in _instance_files(store, instance.instance_id).items():
            if name == "state.json":
                atomic_write_json(target_dir / name, _load_state_dict(store, instance.instance_id))
                copied = ReleaseFile(
                    path=(target_dir / name).relative_to(output_dir).as_posix(),
                    sha256=sha256_file(target_dir / name),
                    size=(target_dir / name).stat().st_size,
                )
            else:
                copied = _copy_if_exists(source, target_dir / name, output_dir)
            if copied:
                files.append(copied)
        oracle_source = store.oracle_path(instance.instance_id)
        oracle_target = oracle_root / f"{instance.oracle_ref}.json"
        if not oracle_target.exists():
            shutil.copy2(oracle_source, oracle_target)
        manipulation = store.load_manipulation(instance.instance_id)
        validation = store.load_validation(instance.instance_id)
        entry = ReleaseInstanceEntry(
            instance_id=instance.instance_id,
            pair_id=instance.pair_id,
            variant_kind=instance.variant_kind,
            manipulation_tier=instance.manipulation_tier.value,
            audit_difficulty=instance.audit_difficulty.value,
            attack_goal=(
                manipulation.attack_goal.value if manipulation is not None else None
            ),
            release_split=instance.release_split,
            oracle_id=instance.oracle_ref,
            manipulation_id=instance.manipulation_ref,
            evidence_contract_file=(
                f"instances/{instance.instance_id}/evidence_contract.json"
                if (store.instance_dir(instance.instance_id) / "evidence_contract.json").is_file()
                else None
            ),
            repository_url=instance.repository.repo_url,
            vulnerable_commit=instance.repository.vulnerable_commit,
            release_eligible=bool(validation and validation.get("release_eligible")),
            repository_tree_sha256=instance.repository_tree_sha256,
            task_file=instance.task_file,
            patch_file=instance.patch_file,
            oracle_file=f"oracles/{instance.oracle_ref}.json",
            manipulation_file=(
                f"instances/{instance.instance_id}/manipulation.json"
                if manipulation is not None
                else None
            ),
            validation_file=f"instances/{instance.instance_id}/validation.json",
            files=files,
            group_id=instance.group_id,
            candidate_id=instance.candidate_id,
            generation_method=instance.generation_method,
            purpose=purpose,
            target_id=instance.target_id,
            target_kind=instance.target_kind,
            eligible_target_ids=list(instance.eligible_target_ids),
        )
        entries.append(entry)
        pair = pairs_map.setdefault(
            instance.pair_id,
            ReleasePair(pair_id=instance.pair_id, clean_instance_id=""),
        )
        if instance.variant_kind == VariantKind.CLEAN:
            pair.clean_instance_id = instance.instance_id
        else:
            pair.adversarial_instance_ids.append(instance.instance_id)

    pairs = []
    for pair in sorted(pairs_map.values(), key=lambda item: item.pair_id):
        if not pair.clean_instance_id:
            raise ReleaseError("pair has no clean instance", details={"pair_id": pair.pair_id})
        pair.adversarial_instance_ids.sort()
        pairs.append(pair)

    selected_ids = {item.instance_id for item in selected}
    try:
        group_registry = store.load_groups()
        groups = [
            group
            for group in group_registry.groups
            if group.adversarial_instance_id in selected_ids
            or group.clean_instance_id in selected_ids
        ]
    except Exception:  # noqa: BLE001 - a release without groups is still valid
        groups = []

    # Provenance copies.
    for source, relative in (
        (loaded.source, provenance_root / f"config{loaded.source.suffix or '.yaml'}"),
        (
            loaded.resolve_asset(loaded.config.audit_task.template),
            provenance_root / "audit_task.md",
        ),
    ):
        if source.is_file():
            shutil.copy2(source, relative)
    registry_path = loaded.resolve_asset(loaded.config.generation.payload_registry)
    registry_target = provenance_root / "payload_registry.yaml"
    shutil.copy2(registry_path, registry_target)
    templates_source = registry_path.parent / "templates"
    if templates_source.is_dir():
        shutil.copytree(templates_source, provenance_root / "payload_templates")

    materialize_script = output_dir / "materialize.py"
    atomic_write_text(materialize_script, _MATERIALIZE_SCRIPT)
    readme = output_dir / "README.md"
    atomic_write_text(readme, _release_readme())
    prompt_source = loaded.resolve_asset(loaded.config.audit_task.template)

    instance_digests = [
        (entry.instance_id, sha256_text(canonical_json(entry.model_dump(mode="json"))))
        for entry in entries
    ]
    release_id = stable_id(
        "VMR",
        release_name,
        release_version,
        loaded.sha256,
        sorted(instance_digests),
    )
    splits = sorted({instance.release_split for instance in selected})
    manifest = ReleaseManifest(
        schema_version=_RELEASE_SCHEMA_VERSION,
        release_id=release_id,
        name=release_name,
        release_version=release_version,
        created_at=utc_now_iso(),
        config_sha256=loaded.sha256,
        source_dataset=(
            store.load_oracle(entries[0].instance_id).source_dataset if entries else "unknown"
        ),
        splits=splits,
        instance_count=len(entries),
        pair_count=len(pairs),
        instances=entries,
        pairs=pairs,
        payload_registry_sha256=sha256_file(registry_path),
        prompt_sha256=sha256_file(prompt_source),
        release_sha256="",
        groups=groups,
        purpose=purpose,
        notes={
            "only_release_eligible": only_release_eligible,
            "skipped": skipped,
            "full_repositories_not_redistributed": True,
            "purpose": purpose,
            "group_count": len(groups),
            "selection_manifest_used": manifest_selection is not None,
            "selection_manifest": (
                {
                    "schema_version": manifest_selection.get("schema_version"),
                    "selected_count": len(wanted or []),
                    "schedule_policy": manifest_selection.get("schedule_policy"),
                    "missing_selected_instances": manifest_selection.get(
                        "missing_selected_instances", []
                    ),
                }
                if manifest_selection is not None
                else None
            ),
            "duplicates_policy": "selection_manifest_excludes_duplicates",
        },
    )
    manifest = manifest.model_copy(
        update={
            "release_sha256": sha256_text(
                canonical_json(manifest.model_dump(mode="json", exclude={"release_sha256"}))
            )
        }
    )
    atomic_write_json(output_dir / "release.json", manifest)
    manifest_files = _write_manifest_hashes(output_dir)
    return {
        "ok": True,
        "release_id": release_id,
        "release_dir": str(output_dir.resolve()),
        "instance_count": manifest.instance_count,
        "pair_count": manifest.pair_count,
        "splits": manifest.splits,
        "release_sha256": manifest.release_sha256,
        "manifest_files": len(manifest_files),
        "skipped": skipped,
        "release": manifest.model_dump(mode="json"),
    }


def _write_manifest_hashes(output_dir: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for path in sorted(output_dir.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        relative = path.relative_to(output_dir).as_posix()
        if relative == "manifest.sha256":
            continue
        entries[relative] = sha256_file(path)
    lines = [f"{digest}  {relative}" for relative, digest in sorted(entries.items())]
    atomic_write_text(output_dir / "manifest.sha256", "\n".join(lines) + "\n")
    return entries


def load_release(release_dir: Path) -> tuple[ReleaseManifest, Path]:
    release_dir = Path(release_dir)
    path = release_dir / "release.json"
    if not path.is_file():
        raise ReleaseError("release.json is missing", details={"release": str(release_dir)})
    try:
        manifest = ReleaseManifest.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, PydanticValidationError) as exc:
        raise ReleaseError(f"invalid release manifest: {exc}") from exc
    return manifest, release_dir


def _verify_file_manifest(release_dir: Path) -> list[str]:
    manifest_path = release_dir / "manifest.sha256"
    if not manifest_path.is_file():
        return ["manifest.sha256 is missing"]
    errors: list[str] = []
    listed: dict[str, str] = {}
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split("  ", 1)
        if len(parts) != 2:
            errors.append(f"malformed manifest line: {line}")
            continue
        digest, relative = parts
        listed[relative] = digest
        target = release_dir / relative
        if not target.is_file():
            errors.append(f"missing release file: {relative}")
        elif sha256_file(target) != digest:
            errors.append(f"release file hash mismatch: {relative}")
    for path in sorted(release_dir.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        relative = path.relative_to(release_dir).as_posix()
        if relative in {"manifest.sha256"}:
            continue
        if relative not in listed:
            errors.append(f"unlisted release file: {relative}")
    return errors


def validate_release(
    *,
    loaded: LoadedConfig,
    release_dir: Path,
    rebuild: bool = False,
    rebuild_dir: Path | None = None,
) -> dict[str, Any]:
    manifest, root = load_release(release_dir)
    errors: list[str] = _verify_file_manifest(root)
    # Re-hash the *stored* payload, not a model dump: model defaults added by a
    # newer schema must not invalidate historical releases (P1-5).
    raw_manifest = json.loads((root / "release.json").read_text(encoding="utf-8"))
    raw_manifest.pop("release_sha256", None)
    release_sha = sha256_text(canonical_json(raw_manifest))
    if release_sha != manifest.release_sha256:
        errors.append("release_sha256 does not match the manifest content")
    pairs_by_id = {pair.pair_id: pair for pair in manifest.pairs}
    clean_counts: dict[str, int] = {}
    instance_ids = {entry.instance_id for entry in manifest.instances}
    for entry in manifest.instances:
        if entry.variant_kind == VariantKind.CLEAN:
            clean_counts[entry.pair_id] = clean_counts.get(entry.pair_id, 0) + 1
        for relative in [entry.task_file, entry.oracle_file, entry.validation_file]:
            if relative and not (root / relative).is_file():
                errors.append(f"instance artifact missing: {relative}")
        try:
            store_instance = BenchmarkInstance.model_validate(
                json.loads((root / "instances" / entry.instance_id / "instance.json").read_text(encoding="utf-8"))
            )
            oracle = CanonicalVulnerabilityOracle.model_validate(
                json.loads((root / entry.oracle_file).read_text(encoding="utf-8"))
            )
            ValidationReport.model_validate(
                json.loads((root / entry.validation_file).read_text(encoding="utf-8"))
            )
            manipulation_payload = json.loads(
                (root / "instances" / entry.instance_id / "manipulation.json").read_text(encoding="utf-8")
            ) if entry.manipulation_file else None
            if manipulation_payload is not None:
                ManipulationSpec.model_validate(manipulation_payload)
            if entry.evidence_contract_file:
                from ..models import EvidenceContract

                contract = EvidenceContract.model_validate(
                    json.loads((root / entry.evidence_contract_file).read_text(encoding="utf-8"))
                )
                if contract.instance_id != entry.instance_id:
                    errors.append(
                        f"evidence contract instance mismatch: {entry.instance_id}"
                    )
            elif entry.variant_kind.value == "adversarial":
                errors.append(f"adversarial instance has no evidence contract: {entry.instance_id}")
            if store_instance.instance_id != entry.instance_id:
                errors.append(f"instance id mismatch: {entry.instance_id}")
            if oracle.oracle_id != entry.oracle_id:
                errors.append(f"oracle id mismatch: {entry.instance_id}")
        except (OSError, json.JSONDecodeError, PydanticValidationError) as exc:
            errors.append(f"invalid instance bundle {entry.instance_id}: {exc}")
        pair = pairs_by_id.get(entry.pair_id)
        if pair is None:
            errors.append(f"instance references unknown pair: {entry.pair_id}")
        else:
            if entry.variant_kind == VariantKind.CLEAN and pair.clean_instance_id != entry.instance_id:
                errors.append(f"pair clean id mismatch: {entry.pair_id}")
            if entry.variant_kind == VariantKind.ADVERSARIAL and entry.instance_id not in pair.adversarial_instance_ids:
                errors.append(f"adversarial instance missing from pair: {entry.instance_id}")
    for pair in manifest.pairs:
        if pair.clean_instance_id not in instance_ids:
            errors.append(f"pair clean instance not in release: {pair.pair_id}")
        for instance_id in pair.adversarial_instance_ids:
            if instance_id not in instance_ids:
                errors.append(f"pair adversarial instance not in release: {instance_id}")
    for pair_id, count in clean_counts.items():
        if count != 1:
            errors.append(f"pair {pair_id} has {count} clean instances")

    rebuilt: list[dict[str, Any]] = []
    if rebuild:
        destination = Path(rebuild_dir) if rebuild_dir else loaded.paths.runs / "_release_rebuild"
        if destination.exists() and any(destination.iterdir()):
            errors.append(f"rebuild directory is not empty: {destination}")
        else:
            destination.mkdir(parents=True, exist_ok=True)
            for entry in manifest.instances:
                try:
                    source = materialize_release_instance(
                        loaded,
                        manifest,
                        entry,
                        destination / entry.instance_id,
                        release_dir=root,
                    )
                    digest = worktree_digest(source)
                    if digest != entry.repository_tree_sha256:
                        errors.append(
                            f"rebuilt tree digest mismatch for {entry.instance_id}: "
                            f"{digest} != {entry.repository_tree_sha256}"
                        )
                    rebuilt.append({"instance_id": entry.instance_id, "repo": str(source), "ok": True})
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"rebuild failed for {entry.instance_id}: {exc}")
                    rebuilt.append({"instance_id": entry.instance_id, "ok": False, "error": str(exc)})
    return {
        "ok": not errors,
        "release_id": manifest.release_id,
        "release_dir": str(root.resolve()),
        "instance_count": manifest.instance_count,
        "pair_count": manifest.pair_count,
        "release_sha256": manifest.release_sha256,
        "errors": errors,
        "rebuilt": rebuilt,
    }


def materialize_release_instance(
    loaded: LoadedConfig,
    manifest: ReleaseManifest,
    entry: ReleaseInstanceEntry,
    destination: Path,
    *,
    release_dir: Path,
) -> Path:
    """Reconstruct one release instance from URL/commit/patch, verifying its digest."""
    destination = Path(destination)
    release_root = Path(release_dir)
    cache = RepositoryCache(loaded.paths.cache, loaded.config.network)
    _, cache_path = cache.ensure(entry.repository_url, fetch=False)
    cache.verify_commit(cache_path, entry.vulnerable_commit)
    destination.mkdir(parents=True, exist_ok=True)
    from ..repository.worktree import prune_worktrees

    prune_worktrees(cache_path)
    repo = create_worktree(
        cache_path,
        entry.vulnerable_commit,
        destination / "repo",
        worktrees_root=destination,
        force=True,
    )
    if entry.patch_file:
        patch = release_root / "instances" / entry.instance_id / "patch.diff"
        apply_patch(repo, patch)
    return repo


def release_instance_dir(release_dir: Path, instance_id: str) -> Path:
    return ensure_within(Path(release_dir), Path(release_dir) / "instances" / instance_id, must_exist=True)


_MATERIALIZE_SCRIPT = '''#!/usr/bin/env python3
"""Rebuild a VulnMirage release from the published commit + patch.

Usage:
    python materialize.py --release . --output ../materialized [--instance ID]

The script does not redistribute upstream repositories.  It clones each
repository URL at the pinned commit and applies the published patch.  No shell
is used, and no remote write is performed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def run(argv: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True, shell=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", default=".")
    parser.add_argument("--output", required=True)
    parser.add_argument("--instance", action="append", default=None)
    args = parser.parse_args()
    release = Path(args.release).resolve()
    manifest = json.loads((release / "release.json").read_text(encoding="utf-8"))
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    selected = [item for item in manifest["instances"] if not args.instance or item["instance_id"] in args.instance]
    if not selected:
        print("no matching instances", file=sys.stderr)
        return 1
    for entry in selected:
        target = output / entry["instance_id"] / "repo"
        if target.exists() and any(target.iterdir()):
            print(f"{entry['instance_id']}: target already populated, skipping", file=sys.stderr)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "--quiet", entry["repository_url"], str(target)])
        run(["git", "checkout", "--quiet", "--detach", entry["vulnerable_commit"]], cwd=target)
        if entry.get("patch_file"):
            patch = release / "instances" / entry["instance_id"] / "patch.diff"
            run(["git", "apply", "--whitespace=nowarn", str(patch)], cwd=target)
        print(f"materialized {entry['instance_id']} -> {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _release_readme() -> str:
    return """# VulnMirage release bundle

This bundle contains task prompts, hidden oracles, manipulation specs, patches
and validation reports.  It does **not** redistribute upstream repositories.

Rebuild the audited repositories:

```bash
python materialize.py --release . --output ../materialized
```

Then inspect `release.json` for instance IDs, pinned commits, splits and file
hashes.  Verify the bundle with:

```bash
vulnmirage validate-release --release .
```

The `oracles/` directory is ground truth and must never be mounted into an
agent-visible working directory.
"""
