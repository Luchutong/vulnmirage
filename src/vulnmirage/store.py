"""Workspace layout, instance state machine and artifact access."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field

from . import SCHEMA_VERSION
from .config import LoadedConfig
from .errors import GenerationError, ValidationError as VMValidationError
from .hashing import atomic_write_json, sha256_file, sha256_text, stable_id
from .models import (
    BenchmarkInstance,
    CanonicalVulnerabilityOracle,
    DecoyRecord,
    ManipulationSpec,
    Stage,
    VariantKind,
)
from .paths import WorkspacePaths, safe_join


class HistoryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage: str
    at: str
    detail: str | None = None


class InstanceState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    instance_id: str
    oracle_id: str
    pair_id: str
    variant_kind: VariantKind
    stage: str
    created_at: str
    updated_at: str
    generation_config_sha256: str
    oracle_sha256: str
    task_sha256: str
    clean_instance_id: str | None = None
    manipulation_sha256: str | None = None
    patch_sha256: str | None = None
    decoy_sha256: str | None = None
    cache_refs_sha256: str | None = None
    base_tree_sha256: str | None = None
    variant_tree_sha256: str | None = None
    random_seed: int | None = None
    operator_names: list[str] = Field(default_factory=list)
    payload_ids: list[str] = Field(default_factory=list)
    validation_report_sha256: str | None = None
    validation_status: str | None = None
    release_eligible: bool | None = None
    generation_round: int = 1
    history: list[HistoryEntry] = Field(default_factory=list)
    notes: dict[str, Any] = Field(default_factory=dict)


_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    Stage.MATERIALIZED.value: {
        Stage.MATERIALIZED.value,
        Stage.ORACLE_ALIGNED.value,
        Stage.VALIDATING.value,
        Stage.REJECTED.value,
    },
    Stage.ORACLE_ALIGNED.value: {
        Stage.ORACLE_ALIGNED.value,
        Stage.PLANNED.value,
        Stage.VALIDATING.value,
        Stage.REJECTED.value,
    },
    Stage.PLANNED.value: {
        Stage.PLANNED.value,
        Stage.GENERATED.value,
        Stage.REJECTED.value,
    },
    Stage.GENERATED.value: {
        Stage.GENERATED.value,
        Stage.VALIDATING.value,
        Stage.VALIDATED.value,
        Stage.REJECTED.value,
    },
    Stage.VALIDATING.value: {
        Stage.VALIDATING.value,
        Stage.VALIDATED.value,
        Stage.REJECTED.value,
    },
    Stage.VALIDATED.value: {
        Stage.VALIDATED.value,
        Stage.VALIDATING.value,
        Stage.FROZEN.value,
        Stage.REJECTED.value,
    },
    Stage.REJECTED.value: {
        Stage.REJECTED.value,
        Stage.VALIDATING.value,
        Stage.VALIDATED.value,
    },
    Stage.FROZEN.value: {
        Stage.FROZEN.value,
        Stage.VALIDATING.value,
        Stage.REJECTED.value,
        Stage.EXPORTED.value,
    },
    Stage.EXPORTED.value: {Stage.EXPORTED.value},
}


def now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class InstanceStore:
    def __init__(self, paths: WorkspacePaths) -> None:
        self.paths = paths

    # ------------------------------------------------------------------ paths
    def instance_dir(self, instance_id: str) -> Path:
        return safe_join(self.paths.instances, instance_id)

    def repo_dir(self, instance_id: str) -> Path:
        return self.paths.worktrees / instance_id / "repo"

    def instance_manifest_path(self, instance_id: str) -> Path:
        return self.instance_dir(instance_id) / "instance.json"

    def state_path(self, instance_id: str) -> Path:
        return self.instance_dir(instance_id) / "state.json"

    def oracle_path(self, instance_id: str) -> Path:
        return self.instance_dir(instance_id) / "oracle.json"

    def manipulation_path(self, instance_id: str) -> Path:
        return self.instance_dir(instance_id) / "manipulation.json"

    def decoy_path(self, instance_id: str) -> Path:
        return self.instance_dir(instance_id) / "decoys.json"

    def evidence_contract_path(self, instance_id: str) -> Path:
        return self.instance_dir(instance_id) / "evidence_contract.json"

    def validation_path(self, instance_id: str) -> Path:
        return self.instance_dir(instance_id) / "validation.json"

    def patch_path(self, instance_id: str) -> Path:
        return self.instance_dir(instance_id) / "patch.diff"

    def relative(self, path: Path) -> str:
        return Path(path).resolve().relative_to(self.paths.root.resolve()).as_posix()

    def resolve_artifact(self, relative: str) -> Path:
        return safe_join(self.paths.root, relative, allow_git=True)

    # --------------------------------------------------------------- read/write
    def exists(self, instance_id: str) -> bool:
        return self.instance_manifest_path(instance_id).is_file()

    def load_instance(self, instance_id: str) -> BenchmarkInstance:
        path = self.instance_manifest_path(instance_id)
        if not path.is_file():
            raise VMValidationError(
                "benchmark instance does not exist",
                details={"instance_id": instance_id, "expected": str(path)},
            )
        return BenchmarkInstance.model_validate(json.loads(path.read_text(encoding="utf-8")))

    def save_instance(self, instance: BenchmarkInstance) -> None:
        atomic_write_json(self.instance_manifest_path(instance.instance_id), instance)

    def load_state(self, instance_id: str) -> InstanceState:
        path = self.state_path(instance_id)
        if not path.is_file():
            raise VMValidationError(
                "instance state is missing", details={"instance_id": instance_id}
            )
        return InstanceState.model_validate(json.loads(path.read_text(encoding="utf-8")))

    def save_state(self, state: InstanceState, *, allow_transition: bool = True) -> None:
        path = self.state_path(state.instance_id)
        if path.is_file() and allow_transition:
            previous = self.load_state(state.instance_id)
            allowed = _ALLOWED_TRANSITIONS.get(previous.stage)
            if allowed is not None and state.stage not in allowed:
                raise GenerationError(
                    "illegal instance state transition",
                    details={
                        "instance_id": state.instance_id,
                        "from": previous.stage,
                        "to": state.stage,
                    },
                )
        atomic_write_json(path, state)

    def update_stage(
        self, instance_id: str, stage: Stage | str, *, detail: str | None = None
    ) -> InstanceState:
        state = self.load_state(instance_id)
        stage_value = stage.value if isinstance(stage, Stage) else stage
        state = state.model_copy(
            update={
                "stage": stage_value,
                "updated_at": now_iso(),
                "history": [
                    *state.history,
                    HistoryEntry(stage=stage_value, at=now_iso(), detail=detail),
                ],
            }
        )
        self.save_state(state)
        return state

    def load_oracle(self, instance_id: str) -> CanonicalVulnerabilityOracle:
        path = self.oracle_path(instance_id)
        if not path.is_file():
            raise VMValidationError(
                "instance oracle is missing", details={"instance_id": instance_id}
            )
        return CanonicalVulnerabilityOracle.model_validate(
            json.loads(path.read_text(encoding="utf-8"))
        )

    def load_manipulation(self, instance_id: str) -> ManipulationSpec | None:
        path = self.manipulation_path(instance_id)
        if not path.is_file():
            return None
        return ManipulationSpec.model_validate(json.loads(path.read_text(encoding="utf-8")))

    def load_decoys(self, instance_id: str) -> list[DecoyRecord]:
        path = self.decoy_path(instance_id)
        if not path.is_file():
            return []
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload.get("decoys", payload) if isinstance(payload, dict) else payload
        return [DecoyRecord.model_validate(item) for item in items]

    def load_validation(self, instance_id: str) -> dict[str, Any] | None:
        path = self.validation_path(instance_id)
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def iter_instance_ids(self) -> Iterable[str]:
        if not self.paths.instances.is_dir():
            return []
        ids = []
        for path in sorted(self.paths.instances.iterdir()):
            if path.is_dir() and (path / "instance.json").is_file():
                ids.append(path.name)
        return ids

    def iter_instances(self) -> Iterable[BenchmarkInstance]:
        for instance_id in self.iter_instance_ids():
            try:
                yield self.load_instance(instance_id)
            except Exception:
                continue

    def find_clean(self, oracle_id: str, *, config_sha256: str | None = None) -> BenchmarkInstance | None:
        candidates = [
            item
            for item in self.iter_instances()
            if item.variant_kind == VariantKind.CLEAN
            and item.oracle_ref == oracle_id
            and (config_sha256 is None or item.generation_config_sha256 == config_sha256)
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda item: item.instance_id)
        return candidates[-1]

    def pair_instances(self, pair_id: str) -> list[BenchmarkInstance]:
        return sorted(
            [item for item in self.iter_instances() if item.pair_id == pair_id],
            key=lambda item: item.instance_id,
        )

    def instance_sha256(self, instance_id: str) -> str:
        return sha256_file(self.instance_manifest_path(instance_id))

    def write_task(self, instance_id: str, text: str) -> tuple[str, str]:
        path = self.instance_dir(instance_id) / "task.md"
        from .hashing import atomic_write_text

        atomic_write_text(path, text)
        return self.relative(path), sha256_text(text)

    def write_oracle(self, instance_id: str, oracle: CanonicalVulnerabilityOracle) -> str:
        path = self.oracle_path(instance_id)
        atomic_write_json(path, oracle)
        return sha256_file(path)

    def write_manipulation(self, instance_id: str, spec: ManipulationSpec) -> str:
        path = self.manipulation_path(instance_id)
        atomic_write_json(path, spec)
        return sha256_file(path)

    def write_decoys(self, instance_id: str, decoys: list[DecoyRecord]) -> str:
        path = self.decoy_path(instance_id)
        atomic_write_json(path, {"decoys": [decoy.model_dump(mode="json") for decoy in decoys]})
        return sha256_file(path)

    def write_evidence_contract(self, instance_id: str, contract) -> tuple[str, str]:
        path = self.evidence_contract_path(instance_id)
        atomic_write_json(path, contract)
        return self.relative(path), sha256_file(path)

    def load_evidence_contract(self, instance_id: str):
        from .models import EvidenceContract

        path = self.evidence_contract_path(instance_id)
        if not path.is_file():
            return None
        return EvidenceContract.model_validate(json.loads(path.read_text(encoding="utf-8")))

    def ensure_instance_dir(self, instance_id: str) -> Path:
        directory = self.instance_dir(instance_id)
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    # --------------------------------------------------------------- groups
    def groups_path(self) -> Path:
        return self.paths.root / "groups.json"

    def load_groups(self):
        from .models import InstanceGroup

        path = self.groups_path()
        if not path.is_file():
            return InstanceGroup()
        try:
            return InstanceGroup.model_validate(
                json.loads(path.read_text(encoding="utf-8"))
            )
        except Exception:
            return InstanceGroup()

    def add_group(self, group) -> None:
        from .models import InstanceGroup

        registry = self.load_groups()
        groups = [
            item for item in registry.groups if item.group_id != group.group_id
        ]
        groups.append(group)
        atomic_write_json(self.groups_path(), InstanceGroup(groups=groups))


def pair_id_for(oracle_id: str, config_sha256: str, seed: int, generation_round: int = 1) -> str:
    base = stable_id("PAIR", oracle_id, config_sha256, seed)
    return base if generation_round <= 1 else f"{base}-v{generation_round}"


def clean_instance_id(pair_id: str) -> str:
    return stable_id("VM", pair_id, "M0", "clean")


def variant_instance_id(
    pair_id: str,
    tier: str,
    goal: str,
    operator_key: str,
    *,
    target_id: str | None = None,
    target_kind: str | None = None,
) -> str:
    """Stable variant id.

    Target identity is part of the id (P0-2): attacking V1 and V2 with the same
    operator must produce distinct instances, caches and resume keys.  Legacy
    callers that omit the target keep the historical id for already-generated
    data.
    """
    if target_id:
        return stable_id(
            "VM",
            pair_id,
            tier,
            goal,
            operator_key,
            target_kind or "vulnerability",
            target_id,
        )
    return stable_id("VM", pair_id, tier, goal, operator_key)


def render_audit_task(loaded: LoadedConfig) -> str:
    path = loaded.resolve_asset(loaded.config.audit_task.template)
    text = path.read_text(encoding="utf-8")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        raise GenerationError("audit task template is empty", details={"path": str(path)})
    if not text.endswith("\n"):
        text += "\n"
    return text


def deep_copy_instance_dir(source: Path, destination: Path) -> None:
    import shutil

    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
