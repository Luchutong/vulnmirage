from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from vulnmirage.config import AgentConfig
from vulnmirage.errors import HarnessError
from vulnmirage.harness.sandbox import (
    build_environment,
    changed_since,
    copy_repository,
    run_agent_process,
    snapshot_tree,
)
from vulnmirage.harness.subprocess_agent import expand_argv, resolve_script_paths


def test_expand_argv_known_placeholders() -> None:
    argv = expand_argv(
        ["python", "agent.py", "--repo", "{repo}", "--out", "{output}"],
        {"repo": "C:/repo", "output": "C:/out.json"},
    )
    assert argv == ["python", "agent.py", "--repo", "C:/repo", "--out", "C:/out.json"]


def test_expand_argv_rejects_unknown_placeholder() -> None:
    with pytest.raises(HarnessError):
        expand_argv(["python", "{secret_key}"], {"repo": "x"})


def test_resolve_script_paths(tmp_path: Path) -> None:
    script = tmp_path / "agent.py"
    script.write_text("print('x')\n", encoding="utf-8")
    argv = resolve_script_paths(["python", "agent.py", "{repo}"], [tmp_path])
    assert argv[0] == "python"
    assert argv[1] == str(script.resolve())


def test_environment_allowlist(monkeypatch) -> None:
    monkeypatch.setenv("VM_SECRET_API_KEY", "super-secret")
    env, notes = build_environment([], network_enabled=False)
    assert "VM_SECRET_API_KEY" not in env
    assert env["HTTP_PROXY"].startswith("http://127.0.0.1")
    assert notes
    env, _ = build_environment(["VM_SECRET_API_KEY"], network_enabled=True)
    assert env["VM_SECRET_API_KEY"] == "super-secret"


def test_copy_repository_excludes_git(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "app").mkdir(parents=True)
    (source / "app" / "x.py").write_text("x = 1\n", encoding="utf-8")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("x", encoding="utf-8")
    destination = tmp_path / "destination"
    copy_repository(source, destination)
    assert (destination / "app" / "x.py").is_file()
    assert not (destination / ".git").exists()


def test_snapshot_detects_changes(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("one", encoding="utf-8")
    before = snapshot_tree(tmp_path)
    (tmp_path / "a.txt").write_text("two", encoding="utf-8")
    (tmp_path / "b.txt").write_text("new", encoding="utf-8")
    after = snapshot_tree(tmp_path)
    assert changed_since(before, after) == ["a.txt", "b.txt"]


def test_timeout_kills_process_tree(tmp_path: Path) -> None:
    marker = tmp_path / "marker.txt"
    code = (
        "import time, pathlib; "
        "time.sleep(8); "
        f"pathlib.Path({str(marker)!r}).write_text('late')"
    )
    exit_code, timed_out, error, duration = run_agent_process(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=build_environment([], network_enabled=False)[0],
        timeout_seconds=1,
        stdout_path=tmp_path / "stdout.log",
        stderr_path=tmp_path / "stderr.log",
    )
    assert timed_out is True
    assert duration < 20
    time.sleep(1.5)
    assert not marker.exists()


def test_opencode_model_provider_split() -> None:
    config = AgentConfig(adapter="opencode", model="dsapi/deepseek-v4-pro")
    assert config.model_provider == "dsapi"
    assert config.model_name == "deepseek-v4-pro"


def test_opencode_command_construction(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from vulnmirage.harness.opencode import OpenCodeAdapter

    config = AgentConfig(
        adapter="opencode",
        model="dsapi/deepseek-v4-pro",
        executable="opencode",
        extra_args=["--agent", "build"],
    )
    adapter = OpenCodeAdapter.__new__(OpenCodeAdapter)
    adapter.agent_config = config
    prepared = SimpleNamespace()
    command = adapter.build_command(prepared, {"prompt": "audit this"})
    assert command[:4] == ["opencode", "run", "--model", "dsapi/deepseek-v4-pro"]
    assert command[-1] == "audit this"
    assert "--agent" in command
