"""Agent adapter interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import AgentConfig, LoadedConfig
from ..hashing import utc_now_iso
from ..models import AgentRun, BenchmarkInstance
from ..store import InstanceStore


@dataclass
class PreparedRun:
    run: AgentRun
    instance: BenchmarkInstance
    run_dir: Path
    repo_dir: Path
    task_path: Path
    output_path: Path
    trace_path: Path
    env: dict[str, str]
    argv: list[str]
    prompt_sha256: str
    timeout_seconds: int
    network_enabled: bool
    agent_argv: list[str] = field(default_factory=list)
    os_trace_path: Path | None = None
    sandbox_notes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    final_raw_path: Path | None = None
    raw_events_path: Path | None = None
    normalized_events_path: Path | None = None
    tool_calls_path: Path | None = None
    file_access_path: Path | None = None
    process_events_path: Path | None = None
    findings_path: Path | None = None
    matches_path: Path | None = None
    trajectory_path: Path | None = None
    verification_path: Path | None = None
    metrics_path: Path | None = None
    meta_path: Path | None = None
    #: Container backend when ``execution_backend=container``; used to force
    #: removal of the run container after a timeout (P1-1 #6).
    container_backend: Any = None


@dataclass
class RawRunResult:
    exit_code: int | None
    timed_out: bool
    started_at: str
    ended_at: str
    duration_seconds: float
    status: str
    stdout_path: Path
    stderr_path: Path
    output_path: Path
    trace_path: Path
    error: str | None = None
    contaminated: bool = False
    changed_files: list[str] = field(default_factory=list)
    digest_before: str | None = None
    digest_after: str | None = None
    started_monotonic_ns: int = 0
    observer_notes: list[str] = field(default_factory=list)


class AgentAdapter(ABC):
    def __init__(
        self,
        *,
        loaded: LoadedConfig,
        agent_config: AgentConfig,
        store: InstanceStore,
        defense=None,
    ) -> None:
        self.loaded = loaded
        self.agent_config = agent_config
        self.store = store
        #: Resolved defense condition; composed in :meth:`prepare`, outside the
        #: audited repository, and hashed into the execution condition.
        self.defense = defense

    @abstractmethod
    def prepare(
        self,
        instance: BenchmarkInstance,
        run: AgentRun,
        *,
        source_repo: Path,
        task_path: Path | None = None,
    ) -> PreparedRun:
        ...

    @abstractmethod
    def execute(self, prepared: PreparedRun) -> RawRunResult:
        ...

    @abstractmethod
    def collect(self, prepared: PreparedRun, raw: RawRunResult) -> AgentRun:
        ...

    def workspace_relative(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.loaded.paths.root.resolve()).as_posix()
        except ValueError:
            return path.as_posix()
