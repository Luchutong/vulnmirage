"""Native ``dataset-core`` input: manifest + task JSONL + private oracle JSONL.

The published benchmark package is a single release, split into two runtime
views:

* ``tasks/task-*.jsonl`` -- task identity, repository pointer and the *source*
  task prompt.  Visible to the scheduler, never handed to the audit agent;
* ``oracle/target-*.jsonl`` -- ground truth per target.  Private: it is only
  read by the verifier and the mechanism analysis stage.

Nothing here reads a target row into the agent's input.  The exported surface of
this module is a read-only index plus eligibility classification; building the
actual task text is :mod:`vulnmirage.campaign.task_prompt`, which starts from
:meth:`DatasetCore.task` and strips every answer-identifying field.

Layout (from ``manifest.json``)::

    VulnMirage_dataset/
      manifest.json
      tasks/task-261102.jsonl
      oracle/target-261102.jsonl
      schemas/task.schema.json
      schemas/target.schema.json

The export-date suffix (``-261102``) is discovered from the manifest or globbed;
it is never hard-coded, and the loader does not require converting the package to
a second ``dataset.yaml + cases.jsonl`` form.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field

from ..errors import DatasetError
from ..hashing import sha256_file, utc_now_iso

#: Bumped whenever eligibility classification changes meaning.
ELIGIBILITY_RULE_VERSION = "1.0"

#: Ordered, weakest to strongest.  A result may only be counted at or above the
#: level it declares.
ELIGIBILITY_LEVELS: tuple[str, ...] = (
    "unknown",
    "rejected",
    "snapshot_verified",
    "annotation_verified",
    "executable_verified",
)

#: Fields the agent may ever receive.  Everything else in a task row stays behind
#: the exposure boundary (see ``docs/leakage_channels.md``).
AGENT_VISIBLE_FIELDS: frozenset[str] = frozenset(
    {"task_label", "workspace_path", "prompt", "output_contract"}
)


class TargetWeakness(BaseModel):
    model_config = ConfigDict(extra="allow")

    cwe_ids: list[str] = Field(default_factory=list)
    primary_cwe: str | None = None
    family: str | None = None
    category_l1: str | None = None
    category_l2: str | None = None
    label: str | None = None
    title: str | None = None


class TargetLocation(BaseModel):
    model_config = ConfigDict(extra="allow")

    file: str
    function: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    granularity: str | None = None
    language: str | None = None


class TargetAnchor(BaseModel):
    model_config = ConfigDict(extra="allow")

    function_sig: str | None = None
    snippet_sha256: str | None = None
    snippet_lines: int | None = None


class TargetSeverity(BaseModel):
    model_config = ConfigDict(extra="allow")

    convention: str | None = None
    score: float | None = None
    level: str | None = None
    vector: str | None = None
    source: str | None = None
    status: str | None = None
    accepted_interval: list[float] | None = None
    interval_basis: str | None = None


class TaskRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    task_id: str
    repo_id: str
    snapshot_id: str
    commit_sha: str
    task_prompt: str
    repo_url: str | None = None
    repo_full_name: str | None = None
    tag_or_release: str | None = None
    release_date: str | None = None
    primary_language: str | None = None
    file_count: int | None = None
    env_spec: dict[str, Any] = Field(default_factory=dict)
    oracle_coverage: dict[str, Any] = Field(default_factory=dict)

    @property
    def effective_repo_url(self) -> str:
        if self.repo_url and self.repo_url.strip():
            return self.repo_url.strip()
        if self.repo_full_name and self.repo_full_name.strip():
            return f"https://github.com/{self.repo_full_name.strip()}"
        raise DatasetError(
            "task row has neither repo_url nor repo_full_name",
            details={"task_id": self.task_id},
        )


class TargetRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    target_id: str
    task_id: str
    vulnerability_id: str
    snapshot_id: str
    status: str
    weakness: TargetWeakness = Field(default_factory=TargetWeakness)
    location: TargetLocation
    anchor: TargetAnchor = Field(default_factory=TargetAnchor)
    severity: TargetSeverity = Field(default_factory=TargetSeverity)
    entry_point: dict[str, Any] = Field(default_factory=dict)
    critical_operation: dict[str, Any] = Field(default_factory=dict)
    path_edges: list[dict[str, Any]] = Field(default_factory=list)
    prerequisites: list[dict[str, Any]] = Field(default_factory=list)
    verifier_id: str | None = None
    safe_twin_id: str | None = None
    fix: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)

    @property
    def primary_cwe(self) -> str | None:
        return self.weakness.primary_cwe or (
            self.weakness.cwe_ids[0] if self.weakness.cwe_ids else None
        )


def _read_jsonl(path: Path, *, kind: str) -> list[tuple[int, dict[str, Any]]]:
    if not path.is_file():
        raise DatasetError(f"{kind} file does not exist", details={"path": str(path)})
    rows: list[tuple[int, dict[str, Any]]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise DatasetError(
                    f"invalid JSON on {kind} line {number}",
                    details={"path": str(path), "line": number, "error": str(exc)},
                ) from exc
            if not isinstance(payload, dict):
                raise DatasetError(
                    f"{kind} line {number} is not a JSON object",
                    details={"path": str(path), "line": number},
                )
            rows.append((number, payload))
    return rows


def _first_existing(root: Path, candidates: Iterable[str]) -> Path | None:
    for candidate in candidates:
        path = root / candidate
        if path.is_file():
            return path
    return None


def _layer_paths(manifest: dict[str, Any]) -> tuple[list[str], list[str]]:
    layers = manifest.get("layers") or {}
    tasks = [str(item) for item in (layers.get("task") or [])]
    oracle = [str(item) for item in (layers.get("oracle_private") or [])]
    return tasks, oracle


def eligibility_level(target: TargetRecord) -> str:
    """Classify how strongly a target's ground truth is supported.

    ``executable_verified`` is never produced here: the published package records
    ``no_verifier``/``no_poc_commands``, so a dynamic claim would be invented.
    """
    if str(target.status).lower() not in {"confirmed_affected", "affected", "confirmed"}:
        return "rejected"
    has_location = bool(target.location.file) and target.location.line_start is not None
    has_anchor = bool(target.anchor.snippet_sha256)
    has_severity = target.severity.score is not None or bool(target.severity.level)
    has_weakness = bool(target.weakness.cwe_ids) and any(
        token.strip() for token in target.weakness.cwe_ids
    )
    evidence_confirmed = bool(target.evidence.get("root_cause_confirmed"))
    if has_location and has_anchor and has_weakness and has_severity and evidence_confirmed:
        return "annotation_verified"
    if has_location and (has_anchor or has_weakness):
        return "snapshot_verified"
    return "unknown"


def eligibility_rank(level: str) -> int:
    try:
        return ELIGIBILITY_LEVELS.index(level)
    except ValueError:
        return 0


@dataclass(frozen=True)
class DatasetCore:
    """Read-only index over one published dataset package."""

    root: Path
    manifest: dict[str, Any]
    tasks_file: Path
    oracle_file: Path
    tasks: dict[str, TaskRecord]
    targets_by_task: dict[str, tuple[TargetRecord, ...]]
    issues: tuple[str, ...] = ()
    loaded_at: str = field(default_factory=utc_now_iso)

    # ------------------------------------------------------------------ lookup
    def task_ids(self) -> list[str]:
        return sorted(self.tasks)

    def task(self, task_id: str) -> TaskRecord:
        try:
            return self.tasks[task_id]
        except KeyError as exc:
            raise DatasetError(
                "unknown task_id", details={"task_id": task_id, "known": self.task_ids()[:25]}
            ) from exc

    def targets(self, task_id: str) -> tuple[TargetRecord, ...]:
        return self.targets_by_task.get(task_id, ())

    def eligible_targets(
        self, task_id: str, *, minimum: str = "snapshot_verified"
    ) -> list[TargetRecord]:
        floor = eligibility_rank(minimum)
        return [
            target
            for target in self.targets(task_id)
            if eligibility_rank(eligibility_level(target)) >= floor
        ]

    def targets_by_snapshot(self) -> dict[str, tuple[TargetRecord, ...]]:
        grouped: dict[str, list[TargetRecord]] = {}
        for targets in self.targets_by_task.values():
            for target in targets:
                grouped.setdefault(target.snapshot_id, []).append(target)
        return {key: tuple(value) for key, value in grouped.items()}

    # -------------------------------------------------------------- integrity
    def verify_file_hashes(self) -> dict[str, Any]:
        """Compare recorded digests with the bytes on disk.

        A mismatch is reported, never repaired: silently re-baselining the hash
        would erase the evidence that the package changed.
        """
        results: list[dict[str, Any]] = []
        for entry in self.manifest.get("files") or []:
            raw_path = entry.get("path")
            if not raw_path:
                continue
            path = self.root / str(raw_path)
            if not path.is_file():
                results.append({"path": str(raw_path), "status": "missing"})
                continue
            actual_sha = sha256_file(path)
            actual_bytes = path.stat().st_size
            expected_sha = entry.get("sha256")
            expected_bytes = entry.get("bytes")
            ok = (expected_sha in (None, actual_sha)) and (
                expected_bytes in (None, actual_bytes)
            )
            results.append(
                {
                    "path": str(raw_path),
                    "status": "ok" if ok else "mismatch",
                    "expected_sha256": expected_sha,
                    "actual_sha256": actual_sha,
                    "expected_bytes": expected_bytes,
                    "actual_bytes": actual_bytes,
                }
            )
        return {
            "ok": all(item["status"] == "ok" for item in results),
            "files": results,
            "checked_at": utc_now_iso(),
        }

    def summary(self) -> dict[str, Any]:
        declared = (self.manifest.get("counts") or {}).get("targets")
        return {
            "dataset": self.manifest.get("dataset"),
            "version": self.manifest.get("version"),
            "layout": self.manifest.get("layout"),
            "root": self.root.as_posix(),
            "tasks_file": self.tasks_file.name,
            "oracle_file": self.oracle_file.name,
            "task_count": len(self.tasks),
            "target_count": sum(len(item) for item in self.targets_by_task.values()),
            "declared_target_count": declared,
            "issues": list(self.issues),
            "loaded_at": self.loaded_at,
        }


def load_dataset_core(
    root: str | Path,
    *,
    tasks_file: str | Path | None = None,
    oracle_file: str | Path | None = None,
    strict: bool = True,
) -> DatasetCore:
    """Load the published package without converting it to another layout."""
    root_path = Path(root).expanduser()
    if not root_path.is_dir():
        raise DatasetError("dataset root does not exist", details={"path": str(root_path)})
    if not root_path.is_absolute():
        root_path = root_path.resolve()

    manifest_path = root_path / "manifest.json"
    manifest: dict[str, Any] = {}
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            raise DatasetError(
                "invalid manifest.json", details={"path": str(manifest_path), "error": str(exc)}
            ) from exc
        if not isinstance(manifest, dict):
            raise DatasetError("manifest.json root must be an object")

    layer_tasks, layer_oracle = _layer_paths(manifest)
    resolved_tasks = (
        Path(tasks_file).expanduser() if tasks_file else _first_existing(root_path, layer_tasks)
    )
    if resolved_tasks is None:
        resolved_tasks = _first_existing(
            root_path, [f"tasks/{item.name}" for item in sorted((root_path / "tasks").glob("*.jsonl"))]
        )
    if resolved_tasks is None and (root_path / "tasks").is_dir():
        candidates = sorted((root_path / "tasks").glob("*.jsonl"))
        resolved_tasks = candidates[-1] if candidates else None
    if resolved_tasks is None:
        raise DatasetError(
            "no task JSONL found",
            details={"root": str(root_path), "declared": layer_tasks},
        )

    resolved_oracle = (
        Path(oracle_file).expanduser() if oracle_file else _first_existing(root_path, layer_oracle)
    )
    if resolved_oracle is None and (root_path / "oracle").is_dir():
        candidates = sorted((root_path / "oracle").glob("*.jsonl"))
        resolved_oracle = candidates[-1] if candidates else None
    if resolved_oracle is None:
        raise DatasetError(
            "no private oracle JSONL found",
            details={"root": str(root_path), "declared": layer_oracle},
        )
    if not resolved_tasks.is_absolute():
        resolved_tasks = (root_path / resolved_tasks).resolve()
    if not resolved_oracle.is_absolute():
        resolved_oracle = (root_path / resolved_oracle).resolve()

    issues: list[str] = []
    tasks: dict[str, TaskRecord] = {}
    for number, payload in _read_jsonl(resolved_tasks, kind="task"):
        try:
            record = TaskRecord.model_validate(payload)
        except Exception as exc:  # pydantic ValidationError
            raise DatasetError(
                f"task line {number} does not match the task contract",
                details={"line": number, "error": str(exc)},
            ) from exc
        if record.task_id in tasks:
            raise DatasetError(
                "duplicate task_id", details={"task_id": record.task_id, "line": number}
            )
        tasks[record.task_id] = record

    grouped: dict[str, list[TargetRecord]] = {task_id: [] for task_id in tasks}
    for number, payload in _read_jsonl(resolved_oracle, kind="target"):
        try:
            target = TargetRecord.model_validate(payload)
        except Exception as exc:
            raise DatasetError(
                f"target line {number} does not match the target contract",
                details={"line": number, "error": str(exc)},
            ) from exc
        if target.task_id not in grouped:
            issues.append(
                f"target {target.target_id} references unknown task {target.task_id} (line {number})"
            )
            continue
        grouped[target.task_id].append(target)

    for task_id, targets in grouped.items():
        if not targets:
            issues.append(f"task {task_id} has no targets")

    core = DatasetCore(
        root=root_path,
        manifest=manifest,
        tasks_file=resolved_tasks,
        oracle_file=resolved_oracle,
        tasks=tasks,
        targets_by_task={key: tuple(value) for key, value in grouped.items()},
        issues=tuple(issues),
    )
    if strict:
        integrity = core.verify_file_hashes()
        if not integrity["ok"]:
            raise DatasetError(
                "dataset file digests do not match manifest.json",
                details={
                    "mismatched": [
                        item for item in integrity["files"] if item["status"] != "ok"
                    ]
                },
            )
    return core


def task_index_rows(core: DatasetCore) -> list[dict[str, Any]]:
    """Compact per-task index for planning (contains no answer material)."""
    rows: list[dict[str, Any]] = []
    for task_id in core.task_ids():
        task = core.task(task_id)
        targets = core.targets(task_id)
        levels: dict[str, int] = {}
        for target in targets:
            level = eligibility_level(target)
            levels[level] = levels.get(level, 0) + 1
        rows.append(
            {
                "task_id": task.task_id,
                "snapshot_id": task.snapshot_id,
                "repo_id": task.repo_id,
                "primary_language": task.primary_language,
                "commit_sha_present": bool(task.commit_sha),
                "target_count": len(targets),
                "eligibility": dict(sorted(levels.items())),
            }
        )
    return rows


__all__ = [
    "AGENT_VISIBLE_FIELDS",
    "DatasetCore",
    "ELIGIBILITY_LEVELS",
    "ELIGIBILITY_RULE_VERSION",
    "TargetAnchor",
    "TargetLocation",
    "TargetRecord",
    "TargetSeverity",
    "TargetWeakness",
    "TaskRecord",
    "eligibility_level",
    "eligibility_rank",
    "load_dataset_core",
    "task_index_rows",
]
