"""Per-task phase state machine.

The campaign runs one task at a time through fixed phases:

``pending -> downloading -> extracted -> prepared -> variants_frozen -> auditing
-> scoring -> mechanism_analysis -> archived -> cleaned``

Rules:

* a phase may advance by one step or be re-entered (a resumed run continues where
  it stopped); it may not jump backwards or skip forward;
* every transition is persisted before the next step starts, so an interrupted
  campaign resumes instead of repeating side effects;
* ``failed`` records the phase in which it failed and why, and never counts as a
  successful audit;
* resume is refused when the frozen inputs change (plan hash, config hash, archive
  digest), because continuing under a different treatment is not the same run.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..errors import CampaignError
from ..hashing import atomic_write_json, utc_now_iso

STATE_SCHEMA_VERSION = "1.0"

PHASES: tuple[str, ...] = (
    "pending",
    "downloading",
    "extracted",
    "prepared",
    "variants_frozen",
    "auditing",
    "scoring",
    "mechanism_analysis",
    "archived",
    "cleaned",
)

TERMINAL_FAILURE = "failed"


class PhaseRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phase: str
    status: str = "ok"
    at: str = Field(default_factory=utc_now_iso)
    detail: str | None = None


class TaskState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = STATE_SCHEMA_VERSION
    task_id: str
    snapshot_id: str | None = None
    phase: str = "pending"
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    plan_sha256: str | None = None
    config_sha256: str | None = None
    archive_sha256: str | None = None
    source_tree_sha256: str | None = None
    variant_ids: list[str] = Field(default_factory=list)
    run_ids: list[str] = Field(default_factory=list)
    scored_run_ids: list[str] = Field(default_factory=list)
    failed_run_ids: list[str] = Field(default_factory=list)
    #: Runs whose exposure boundary could not be proven.  Kept apart from
    #: ``failed_run_ids`` so a statistics stage can exclude them explicitly instead
    #: of reading an isolation failure as an attack outcome.
    ineligible_run_ids: list[str] = Field(default_factory=list)
    history: list[PhaseRecord] = Field(default_factory=list)
    error: str | None = None
    notes: dict[str, object] = Field(default_factory=dict)


def state_path(archive_root: Path, task_id: str) -> Path:
    return Path(archive_root) / "control" / "state" / f"{task_id}.json"


class TaskStateStore:
    def __init__(self, archive_root: Path) -> None:
        self.root = Path(archive_root)

    def path(self, task_id: str) -> Path:
        return state_path(self.root, task_id)

    def load(self, task_id: str) -> TaskState | None:
        path = self.path(task_id)
        if not path.is_file():
            return None
        import json

        return TaskState.model_validate(json.loads(path.read_text(encoding="utf-8")))

    def save(self, state: TaskState) -> Path:
        state = state.model_copy(update={"updated_at": utc_now_iso()})
        path = self.path(state.task_id)
        atomic_write_json(path, state)
        return path

    def open_or_create(
        self, task_id: str, *, snapshot_id: str | None, plan_sha256: str, config_sha256: str
    ) -> TaskState:
        existing = self.load(task_id)
        if existing is None:
            state = TaskState(
                task_id=task_id,
                snapshot_id=snapshot_id,
                plan_sha256=plan_sha256,
                config_sha256=config_sha256,
                history=[PhaseRecord(phase="pending", detail="campaign opened")],
            )
            self.save(state)
            return state
        if existing.plan_sha256 and plan_sha256 and existing.plan_sha256 != plan_sha256:
            raise CampaignError(
                "resume refused: the plan changed since this task was started",
                details={
                    "task_id": task_id,
                    "stored": existing.plan_sha256,
                    "current": plan_sha256,
                    "hint": "start a new campaign or archive root instead of re-labelling the run",
                },
            )
        if existing.config_sha256 and config_sha256 and existing.config_sha256 != config_sha256:
            raise CampaignError(
                "resume refused: the configuration changed since this task was started",
                details={"task_id": task_id, "stored": existing.config_sha256, "current": config_sha256},
            )
        return existing

    def advance(self, state: TaskState, phase: str, *, detail: str | None = None) -> TaskState:
        if phase not in PHASES and phase != TERMINAL_FAILURE:
            raise CampaignError("unknown campaign phase", details={"phase": phase})
        if phase != TERMINAL_FAILURE:
            current_index = PHASES.index(state.phase) if state.phase in PHASES else -1
            target_index = PHASES.index(phase)
            if target_index < current_index:
                raise CampaignError(
                    "campaign phases cannot move backwards",
                    details={"from": state.phase, "to": phase},
                )
            if target_index > current_index + 1:
                raise CampaignError(
                    "campaign phases cannot skip a step",
                    details={"from": state.phase, "to": phase, "next": PHASES[current_index + 1]},
                )
        elif state.phase == "cleaned":
            raise CampaignError("a cleaned task cannot be marked failed")
        updated = state.model_copy(
            update={
                "phase": phase,
                "history": [*state.history, PhaseRecord(phase=phase, status="ok", detail=detail)],
                "error": None if phase != TERMINAL_FAILURE else (detail or "failed"),
            }
        )
        self.save(updated)
        return updated

    def fail(self, state: TaskState, *, phase: str, error: str) -> TaskState:
        updated = state.model_copy(
            update={
                "phase": TERMINAL_FAILURE,
                "error": f"{phase}: {error}",
                "history": [
                    *state.history,
                    PhaseRecord(phase=phase, status="failed", detail=error),
                ],
            }
        )
        self.save(updated)
        return updated

    def note(self, state: TaskState, **values: object) -> TaskState:
        notes = dict(state.notes)
        notes.update(values)
        updated = state.model_copy(update={"notes": notes})
        self.save(updated)
        return updated


__all__ = [
    "PHASES",
    "STATE_SCHEMA_VERSION",
    "TERMINAL_FAILURE",
    "PhaseRecord",
    "TaskState",
    "TaskStateStore",
    "state_path",
]
