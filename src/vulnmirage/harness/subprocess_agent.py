"""Generic argv-based subprocess agent adapter."""

from __future__ import annotations

import re
import shutil
import time
from pathlib import Path
from typing import Any

from ..config import AgentConfig
from ..credentials import declared_names as declared_credential_names
from ..credentials import inspect_credentials
from ..errors import HarnessError
from ..hashing import sha256_text, utc_now_iso
from ..models import AgentRun, BenchmarkInstance
from ..paths import project_root
from ..repository.git import worktree_digest
from ..store import InstanceStore
from .base import AgentAdapter, PreparedRun, RawRunResult
from .sandbox import (
    build_environment,
    changed_since,
    prepare_sandbox,
    run_agent_process,
    snapshot_tree,
)

_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z0-9_]+)\}")
_ALLOWED_PLACEHOLDERS = {
    "repo",
    "task",
    "output",
    "trace",
    "run_id",
    "instance_id",
    "pair_id",
    "workspace",
    "scratch",
    "prompt",
    "task_file",
}


def expand_argv(argv: list[str], mapping: dict[str, str]) -> list[str]:
    expanded: list[str] = []
    for token in argv:
        for name in _PLACEHOLDER_RE.findall(token):
            if name not in _ALLOWED_PLACEHOLDERS:
                raise HarnessError(
                    "agent argv contains an unknown placeholder",
                    details={"placeholder": name, "allowed": sorted(_ALLOWED_PLACEHOLDERS)},
                )
            if name not in mapping:
                raise HarnessError(
                    "agent argv placeholder has no value", details={"placeholder": name}
                )
        expanded.append(_PLACEHOLDER_RE.sub(lambda match: mapping[match.group(1)], token))
    return expanded


def resolve_script_paths(argv: list[str], base_dirs: list[Path]) -> list[str]:
    """Resolve relative script/tool paths before cwd changes to the repo copy."""
    resolved = [argv[0]] if argv else []
    script_suffixes = {".py", ".sh", ".js", ".mjs", ".cjs", ".ps1", ".bat", ".cmd", ".rb"}
    for token in argv[1:]:
        if token.startswith("-"):
            resolved.append(token)
            continue
        looks_like_script = (
            "/" in token
            or "\\" in token
            or Path(token).suffix.lower() in script_suffixes
        )
        if not looks_like_script:
            resolved.append(token)
            continue
        candidate = Path(token)
        if candidate.is_absolute():
            resolved.append(token)
            continue
        replacement = None
        for base in base_dirs:
            probe = (base / candidate).resolve()
            if probe.is_file():
                replacement = probe
                break
        resolved.append(str(replacement) if replacement else token)
    return resolved


class SubprocessAgentAdapter(AgentAdapter):
    def __init__(
        self,
        *,
        loaded,
        agent_config: AgentConfig,
        store: InstanceStore,
        agent_base_dir: Path | None = None,
        defense=None,
    ) -> None:
        super().__init__(
            loaded=loaded, agent_config=agent_config, store=store, defense=defense
        )
        self.agent_base_dir = Path(agent_base_dir) if agent_base_dir else Path.cwd()

    def build_command(
        self,
        prepared: PreparedRun,
        mapping: dict[str, str],
    ) -> list[str]:
        return expand_argv(self.agent_config.argv, mapping)

    def prepare(
        self,
        instance: BenchmarkInstance,
        run: AgentRun,
        *,
        source_repo: Path,
        task_path: Path | None = None,
    ) -> PreparedRun:
        run_dir = self.loaded.paths.run_dir(run.run_id)
        sandbox = prepare_sandbox(
            source_repo=source_repo,
            instance_task_path=task_path or self.store.resolve_artifact(instance.task_file),
            run_dir=run_dir,
        )
        base_prompt_text = sandbox.task_path.read_text(encoding="utf-8")
        if self.defense is not None:
            prompt_text = self.defense.compose(base_prompt_text)
            # The defense is applied to the run-local copy only; the frozen
            # instance task and the audited repository never change.
            sandbox.task_path.write_text(prompt_text, encoding="utf-8", newline="\n")
        else:
            prompt_text = base_prompt_text
        prompt_sha = sha256_text(prompt_text)
        network_enabled = bool(self.agent_config.network_enabled)
        if network_enabled and not self.loaded.config.network.agent_enabled:
            raise HarnessError(
                "agent network access is requested but disabled by network.agent_enabled",
                details={"agent": self.agent_config.adapter},
            )
        env, notes = build_environment(
            [
                *self.loaded.config.execution.env_allowlist,
                *self.agent_config.env_allowlist,
            ],
            network_enabled=network_enabled,
            # P0-2: declared credentials are read from the parent environment by
            # name.  Values never enter argv, logs or serialised records.
            credential_allowlist=declared_credential_names(self.agent_config),
        )
        if self.agent_config.adapter == "opencode":
            # One isolated session/config/cache state per run: no reuse of an
            # existing chat or a global OpenCode history (P0-4 #6).
            session_root = sandbox.run_dir / "agent_state"
            home = session_root / "home"
            for directory in (
                home,
                session_root / "config",
                session_root / "cache",
                session_root / "data",
                session_root / "state",
            ):
                directory.mkdir(parents=True, exist_ok=True)
            env["HOME"] = str(home)
            env["USERPROFILE"] = str(home)
            env["XDG_CONFIG_HOME"] = str(session_root / "config")
            env["XDG_CACHE_HOME"] = str(session_root / "cache")
            env["XDG_DATA_HOME"] = str(session_root / "data")
            env["XDG_STATE_HOME"] = str(session_root / "state")
            env["OPENCODE_DISABLE_AUTOUPDATE"] = "1"
            notes.append(
                f"per-run OpenCode state isolated under {session_root.as_posix()}"
            )
        config_file = self.agent_config.config_file
        if config_file:
            path = Path(config_file)
            if not path.is_absolute():
                path = (self.agent_base_dir / path).resolve()
            if not path.is_file():
                raise HarnessError(
                    "agent config file does not exist", details={"config_file": str(path)}
                )
            env["OPENCODE_CONFIG"] = str(path)
            notes.append(f"agent config file: {path}")
        credential_status = inspect_credentials(
            self.agent_config,
            forwarded=[name for name in declared_credential_names(self.agent_config) if name in env],
        )
        notes.append(
            "credential names declared/present/forwarded: "
            f"{len(credential_status.declared)}/{len(credential_status.present)}/"
            f"{len(credential_status.forwarded)}"
        )
        container = None
        isolation_metadata: dict[str, Any] = {
            "enforcement": "subprocess_isolated_repo_copy_best_effort",
            "host_workspace_visible_to_agent": True,
            "limit": "process can read absolute host paths; not a security boundary",
        }
        if self.agent_config.execution_backend == "container":
            from .container import build_backend

            from ..hashing import sha256_file as _sha_file

            output_dir = sandbox.run_dir / "container_output"
            output_dir.mkdir(parents=True, exist_ok=True)
            task_copy = output_dir / "task.md"
            task_copy.write_text(prompt_text, encoding="utf-8", newline="\n")
            # P1-1: every run gets its own writable agent state directory that
            # is mounted at /agent-state.  OpenCode's config, HOME and XDG paths
            # all point inside it, so no host path is referenced by the agent.
            agent_state = sandbox.run_dir / "agent_state"
            for relative in ("home", "config", "cache", "data", "state"):
                (agent_state / relative).mkdir(parents=True, exist_ok=True)
            container_env_values = {
                "HOME": "/agent-state/home",
                "USERPROFILE": "/agent-state/home",
                "XDG_CONFIG_HOME": "/agent-state/config",
                "XDG_CACHE_HOME": "/agent-state/cache",
                "XDG_DATA_HOME": "/agent-state/data",
                "XDG_STATE_HOME": "/agent-state/state",
                "OPENCODE_DISABLE_AUTOUPDATE": "1",
            }
            if config_file:
                source_config = Path(config_file)
                if not source_config.is_absolute():
                    source_config = (self.agent_base_dir / source_config).resolve()
                if source_config.is_file():
                    destination = agent_state / "opencode.json"
                    shutil.copy2(source_config, destination)
                    container_env_values["OPENCODE_CONFIG"] = "/agent-state/opencode.json"
                    notes.append(
                        "container OpenCode config copied to /agent-state/opencode.json "
                        f"(sha256={_sha_file(destination)})"
                    )
            env_names = sorted(
                {
                    *self.loaded.config.execution.env_allowlist,
                    *self.agent_config.env_allowlist,
                    *declared_credential_names(self.agent_config),
                }
                & set(env)
            )
            container = build_backend(
                configured_runtime=self.agent_config.container_runtime,
                image=self.agent_config.container_image,
                network=self.agent_config.container_network,
                repo_dir=sandbox.repo_dir,
                scratch_dir=sandbox.scratch_dir,
                output_dir=output_dir,
                env_names=env_names,
                credential_names=declared_credential_names(self.agent_config),
                agent_state_dir=agent_state,
                env_values=container_env_values,
                name=run.run_id,
                agent_executable=self.agent_config.container_agent_executable,
                agent_version=self.agent_config.container_agent_version,
            )
            sandbox.output_path = output_dir / "findings_raw.txt"
            sandbox.trace_path = output_dir / "trace.jsonl"
            sandbox.final_raw_path = output_dir / "final_raw.txt"
            sandbox.stdout_path = output_dir / "stdout.log"
            sandbox.stderr_path = output_dir / "stderr.log"
            isolation_metadata = container.enforcement
            notes.append(
                "container backend: repo mounted read-only; oracle/workspace not "
                "mounted; per-run /agent-state mounted read-write"
            )
        mapping = {
            "repo": "/repo" if container else str(sandbox.repo_dir),
            "task": "/output/task.md" if container else str(sandbox.task_path),
            "task_file": "/output/task.md" if container else str(sandbox.task_path),
            "output": "/output/findings_raw.txt" if container else str(sandbox.output_path),
            "trace": "/output/trace.jsonl" if container else str(sandbox.trace_path),
            "run_id": run.run_id,
            "instance_id": instance.instance_id,
            "pair_id": instance.pair_id,
            "workspace": "/scratch" if container else str(self.loaded.paths.root),
            "scratch": "/scratch" if container else str(sandbox.scratch_dir),
            "prompt": prompt_text,
        }
        argv = self.build_command(
            PreparedRun(
                run=run,
                instance=instance,
                run_dir=sandbox.run_dir,
                repo_dir=sandbox.repo_dir,
                task_path=sandbox.task_path,
                output_path=sandbox.output_path,
                trace_path=sandbox.trace_path,
                env=env,
                argv=[],
                prompt_sha256=prompt_sha,
                timeout_seconds=self.agent_config.timeout_seconds,
                network_enabled=network_enabled,
                sandbox_notes=notes,
            ),
            mapping,
        )
        if container is None:
            argv = resolve_script_paths(
                argv,
                [self.agent_base_dir, project_root(), Path.cwd()],
            )
            agent_argv = list(argv)
        else:
            agent_argv = list(argv)
            argv = container.build_argv(agent_argv, cwd="/repo")
        os_trace_path = None
        observation_probe: dict[str, Any] = {}
        mode = self.loaded.config.observation.os_trace
        if container is not None:
            notes.append(
                "OS trace is not wrapped around the container runtime; "
                "use the agent's native trace for visible content"
            )
            mode = "off"
        if mode != "off":
            from .observation.os_trace import probe_os_trace, wrap_with_strace

            probe = probe_os_trace(mode)
            observation_probe = probe.as_dict()
            if probe.available:
                os_trace_path = sandbox.run_dir / "os_trace.log"
                argv = wrap_with_strace(agent_argv, os_trace_path)
                notes.append(f"OS trace probe: available ({probe.executable})")
            else:
                reason = (
                    f"OS trace unavailable ({probe.status}): {probe.reason or 'unknown'}"
                )
                if mode in {"on", "required"}:
                    # Do not launch the agent when a requested observer could
                    # not be established: the wrapper would fail before the
                    # agent starts and would be misattributed as agent failure.
                    raise HarnessError(
                        reason,
                        details={
                            "failure_type": "observation_setup_failure",
                            "probe": probe.as_dict(),
                            "requested_mode": mode,
                        },
                    )
                notes.append(reason + "; continuing with native/wrapper observation only")
        return PreparedRun(
            run=run.model_copy(update={"prompt_sha256": prompt_sha}),
            instance=instance,
            run_dir=sandbox.run_dir,
            repo_dir=sandbox.repo_dir,
            task_path=sandbox.task_path,
            output_path=sandbox.output_path,
            trace_path=sandbox.trace_path,
            env=env,
            argv=argv,
            prompt_sha256=prompt_sha,
            timeout_seconds=self.agent_config.timeout_seconds,
            network_enabled=network_enabled,
            agent_argv=agent_argv,
            os_trace_path=os_trace_path,
            sandbox_notes=notes,
            metadata={
                "agent_config_sha256": self.agent_config.model_dump_json(),
                "base_prompt_sha256": sha256_text(base_prompt_text),
                "defense_instructions_sha256": (
                    self.defense.instructions_sha256 if self.defense is not None else None
                ),
                "effective_prompt_sha256": prompt_sha,
                "defense": self.defense.identity if self.defense is not None else None,
                "observation_probe": observation_probe,
                "isolation": isolation_metadata,
            },
            final_raw_path=sandbox.final_raw_path,
            raw_events_path=sandbox.raw_events_path,
            normalized_events_path=sandbox.normalized_events_path,
            tool_calls_path=sandbox.tool_calls_path,
            file_access_path=sandbox.file_access_path,
            process_events_path=sandbox.process_events_path,
            findings_path=sandbox.findings_path,
            matches_path=sandbox.matches_path,
            trajectory_path=sandbox.trajectory_path,
            verification_path=sandbox.verification_path,
            metrics_path=sandbox.metrics_path,
            meta_path=sandbox.meta_path,
            container_backend=container,
        )
    def execute(self, prepared: PreparedRun) -> RawRunResult:
        before = snapshot_tree(prepared.repo_dir)
        digest_before = worktree_digest(prepared.repo_dir)
        started_at = utc_now_iso()
        started_monotonic_ns = time.monotonic_ns()
        try:
            exit_code, timed_out, error, duration = run_agent_process(
                prepared.argv,
                cwd=prepared.repo_dir,
                env=prepared.env,
                timeout_seconds=prepared.timeout_seconds,
                stdout_path=prepared.run_dir / "stdout.log",
                stderr_path=prepared.run_dir / "stderr.log",
            )
        finally:
            backend = prepared.container_backend
            if backend is not None:
                # P1-1 #6: a killed client must not leave an orphan container.
                prepared.metadata["container_cleanup"] = backend.cleanup()
        ended_at = utc_now_iso()
        after = snapshot_tree(prepared.repo_dir)
        digest_after = worktree_digest(prepared.repo_dir)
        changed = changed_since(before, after)
        contaminated = bool(changed)
        if timed_out:
            status = "timeout"
        elif exit_code not in (0, None):
            status = "agent_tool_failure"
        elif contaminated:
            status = "contaminated"
        else:
            status = "success"
        return RawRunResult(
            exit_code=exit_code,
            timed_out=timed_out,
            started_at=started_at,
            ended_at=ended_at,
            duration_seconds=duration,
            status=status,
            stdout_path=prepared.run_dir / "stdout.log",
            stderr_path=prepared.run_dir / "stderr.log",
            output_path=prepared.output_path,
            trace_path=prepared.trace_path,
            error=error or None,
            contaminated=contaminated,
            changed_files=changed,
            digest_before=digest_before,
            digest_after=digest_after,
            started_monotonic_ns=started_monotonic_ns,
        )

    def collect(self, prepared: PreparedRun, raw: RawRunResult) -> AgentRun:
        if not prepared.output_path.exists() and prepared.run_dir.joinpath("stdout.log").is_file():
            stdout = prepared.run_dir.joinpath("stdout.log")
            if stdout.stat().st_size > 0:
                shutil.copy2(stdout, prepared.output_path)
        if prepared.output_path.is_file():
            shutil.copy2(prepared.output_path, prepared.final_raw_path or (prepared.run_dir / "final_raw.txt"))
        findings_path = (
            self.workspace_relative(prepared.output_path)
            if prepared.output_path.is_file() and prepared.output_path.stat().st_size > 0
            else None
        )

        def rel(path: Path | None) -> str:
            target = path or (prepared.run_dir / "missing")
            return self.workspace_relative(target)

        return prepared.run.model_copy(
            update={
                "started_at": raw.started_at,
                "ended_at": raw.ended_at,
                "status": raw.status,
                "findings_path": findings_path,
                "stdout_path": self.workspace_relative(raw.stdout_path),
                "stderr_path": self.workspace_relative(raw.stderr_path),
                "raw_events_path": rel(prepared.raw_events_path),
                "normalized_events_path": rel(prepared.normalized_events_path),
                "tool_calls_path": rel(prepared.tool_calls_path),
                "file_access_path": rel(prepared.file_access_path),
                "process_events_path": rel(prepared.process_events_path),
                "final_raw_path": rel(prepared.final_raw_path),
                "observability_grade": "D",
                "tool_policy": {
                    "shell": False,
                    "network_enabled": prepared.network_enabled,
                    "env_allowlist": sorted(prepared.env),
                    "isolated_repo_copy": True,
                    "git_metadata_copied": False,
                    "timeout_seconds": prepared.timeout_seconds,
                    "contaminated": raw.contaminated,
                    "changed_files": raw.changed_files,
                    "sandbox_notes": prepared.sandbox_notes,
                },
            }
        )
