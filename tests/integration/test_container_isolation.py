"""Container isolation integration tests (P1-4 / P1-1).

These tests are skipped when no container runtime is available or when
``VULNMIRAGE_CONTAINER_TEST=1`` is not set.  A skip is reported as such and is
never counted as a pass.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

import pytest

from vulnmirage.harness.container import (
    build_backend,
    container_available,
    container_runtime,
)

pytestmark = pytest.mark.integration

_RUNTIME = container_runtime(os.environ.get("VULNMIRAGE_CONTAINER_RUNTIME"))
_AVAILABLE, _DETAIL = container_available(os.environ.get("VULNMIRAGE_CONTAINER_RUNTIME"))
_IMAGE = os.environ.get("VULNMIRAGE_CONTAINER_IMAGE", "ubuntu:22.04")


def _requires_container() -> None:
    if os.environ.get("VULNMIRAGE_CONTAINER_TEST") != "1":
        pytest.skip("set VULNMIRAGE_CONTAINER_TEST=1 to run container isolation tests")
    if not _AVAILABLE:
        pytest.skip(f"container runtime unavailable: {_DETAIL}")


def _run_in_container(backend, script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        backend.build_argv(["sh", "-c", script]),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _agent_run_record(run_id: str, instance_id: str):
    """Minimal pending run record used by the adapter-level container test."""
    from vulnmirage.models import AgentRun

    return AgentRun(
        run_id=run_id,
        instance_id=instance_id,
        repetition=1,
        model_provider="provider",
        model_name="model",
        scaffold="container-agent",
        prompt_sha256="a" * 64,
        time_budget_seconds=60,
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:00:10Z",
        status="pending",
        raw_events_path="events.raw.jsonl",
        normalized_events_path="events.normalized.jsonl",
        tool_calls_path="tool_calls.jsonl",
        file_access_path="file_access.jsonl",
        process_events_path="process_events.jsonl",
        observability_grade="D",
        stdout_path="stdout.log",
        stderr_path="stderr.log",
        final_raw_path="final_raw.txt",
    )


def test_container_mounts_only_repo_scratch_output(tmp_path: Path) -> None:
    _requires_container()
    repo = tmp_path / "repo"
    scratch = tmp_path / "scratch"
    output = tmp_path / "output"
    oracle = tmp_path / "private" / "oracle.json"
    for directory in (repo, scratch, output):
        directory.mkdir()
    oracle.parent.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    oracle.write_text('{"secret": true}', encoding="utf-8")
    backend = build_backend(
        configured_runtime=_RUNTIME,
        image=_IMAGE,
        network="none",
        repo_dir=repo,
        scratch_dir=scratch,
        output_dir=output,
        env_names=[],
    )
    # Reading the repository works.
    read = _run_in_container(backend, "cat /repo/app.py")
    assert read.returncode == 0
    assert read.stdout.strip() == "x = 1"
    # Host oracle path is not mounted.
    denied = _run_in_container(backend, f"cat {shlex.quote(oracle.as_posix())}")
    assert denied.returncode != 0
    # Repository is read-only.
    write_repo = _run_in_container(backend, "echo x >> /repo/app.py")
    assert write_repo.returncode != 0
    # Scratch is writable.
    write_scratch = _run_in_container(backend, "echo ok > /scratch/ok")
    assert write_scratch.returncode == 0
    assert (scratch / "ok").read_text(encoding="utf-8").strip() == "ok"


def test_two_container_runs_do_not_share_state(tmp_path: Path) -> None:
    _requires_container()
    results = []
    for name in ("run1", "run2"):
        base = tmp_path / name
        repo, scratch, output = base / "repo", base / "scratch", base / "output"
        for directory in (repo, scratch, output):
            directory.mkdir(parents=True)
        backend = build_backend(
            configured_runtime=_RUNTIME,
            image=_IMAGE,
            network="none",
            repo_dir=repo,
            scratch_dir=scratch,
            output_dir=output,
            env_names=[],
        )
        proc = _run_in_container(
            backend,
            "ls -A /scratch",
        )
        assert proc.returncode == 0
        results.append(proc.stdout.strip())
    assert results == ["", ""]  # /scratch is empty in each fresh run


def test_full_adapter_container_run_has_writable_agent_state(tmp_path: Path) -> None:
    """P1-1: the complete adapter path mounts a usable ``/agent-state``.

    Exercised through ``SubprocessAgentAdapter.prepare`` (not a hand-built
    ``docker run``): the OpenCode config must be readable inside the container,
    the per-run state writable, the repository read-only, the host oracle and
    workspace invisible, and the output directory collectable.
    """
    _requires_container()
    from tests.support import make_instance, make_test_config
    from vulnmirage.config import AgentConfig
    from vulnmirage.harness.subprocess_agent import SubprocessAgentAdapter
    from vulnmirage.store import InstanceStore

    base = tmp_path / "adapter"
    repo, task_source = base / "source_repo", base / "task.md"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    task_source.write_text("audit\n", encoding="utf-8")
    config_file = base / "opencode.json"
    config_file.write_text('{"model": "provider/model"}\n', encoding="utf-8")
    oracle_file = base / "private" / "oracle.json"
    oracle_file.parent.mkdir()
    oracle_file.write_text('{"secret": true}', encoding="utf-8")

    project_root = Path(__file__).resolve().parents[2]
    loaded = make_test_config(base, project_root, workspace_name="container-ws")
    store = InstanceStore(loaded.paths)
    agent = AgentConfig(
        adapter="subprocess",
        argv=["sh", "-c", "echo {repo} {output} >/dev/null", "{repo}", "{output}"],
        scaffold="container-agent",
        execution_backend="container",
        container_runtime=_RUNTIME,
        container_image=_IMAGE,
        container_network="none",
        config_file=str(config_file),
    )
    instance = make_instance(instance_id="VM-CONTAINER")
    adapter = SubprocessAgentAdapter(
        loaded=loaded, agent_config=agent, store=store, agent_base_dir=base
    )
    prepared = adapter.prepare(
        instance,
        _agent_run_record("RUN-CONTAINER-1", instance.instance_id),
        source_repo=repo,
        task_path=task_source,
    )
    backend = prepared.container_backend
    assert backend is not None
    state_dir = Path(backend.agent_state_dir)
    assert (state_dir / "opencode.json").is_file()
    assert backend.enforcement["agent_state_mounted"] is True

    def run_script(script: str) -> subprocess.CompletedProcess[str]:
        argv = backend.build_argv(["sh", "-c", script], cwd="/repo")
        return subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)

    # Config readable inside the container.
    config_read = run_script("cat /agent-state/opencode.json")
    assert config_read.returncode == 0
    assert "provider/model" in config_read.stdout

    # State writable and visible on the host.
    state_write = run_script("echo ok > /agent-state/home/state.txt")
    assert state_write.returncode == 0
    assert (state_dir / "home" / "state.txt").is_file()

    # Repository is readable but not writable.
    assert run_script("cat /repo/app.py").returncode == 0
    assert run_script("echo x >> /repo/app.py").returncode != 0

    # Host oracle and the host workspace are not mounted.
    assert run_script(f"cat {shlex.quote(oracle_file.as_posix())}").returncode != 0
    assert run_script(f"test -e {shlex.quote(loaded.paths.root.as_posix())}").returncode != 0

    # Output directory is writable and collectable on the host.
    output_write = run_script("echo reclaimed > /output/findings_raw.txt")
    assert output_write.returncode == 0
    assert prepared.output_path.is_file()
    assert "reclaimed" in prepared.output_path.read_text(encoding="utf-8")

    # Timeout cleanup is idempotent and never leaves a named container behind.
    backend.cleanup()
    leftover = subprocess.run(
        [backend.runtime, "ps", "-a", "-q", "--filter", f"name={backend.name}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert leftover.returncode == 0
    assert leftover.stdout.strip() == ""
