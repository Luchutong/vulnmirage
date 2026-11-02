"""P0-2 credential plumbing and P1-1 container run-time state."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.support import make_instance, make_test_config
from vulnmirage.config import AgentConfig
from vulnmirage.credentials import ensure_credentials, inspect_credentials
from vulnmirage.diagnostics import run_doctor
from vulnmirage.errors import HarnessError
from vulnmirage.harness.base import PreparedRun
from vulnmirage.harness.container import ContainerBackend, build_backend
from vulnmirage.harness.sandbox import build_environment
from vulnmirage.harness.subprocess_agent import SubprocessAgentAdapter
from vulnmirage.models import AgentRun
from vulnmirage.store import InstanceStore

_FAKE_VALUE = "sk-live-FAKE-credential-value-123456"
_FAKE_NAME = "VM_TEST_API_KEY"
_UNDECLARED_NAME = "VM_UNDECLARED_SECRET"


def _agent_run(run_id: str = "RUN-1", instance_id: str = "VM-1") -> AgentRun:
    return AgentRun(
        run_id=run_id,
        instance_id=instance_id,
        repetition=1,
        model_provider="provider",
        model_name="model",
        scaffold="subprocess",
        prompt_sha256="a" * 64,
        time_budget_seconds=30,
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:00:10Z",
        status="pending",
        raw_events_path="e.jsonl",
        normalized_events_path="n.jsonl",
        tool_calls_path="t.jsonl",
        file_access_path="f.jsonl",
        process_events_path="p.jsonl",
        observability_grade="D",
        stdout_path="o.log",
        stderr_path="e.log",
        final_raw_path="r.txt",
    )


def _prepare(tmp_path: Path, project_root: Path, agent: AgentConfig) -> PreparedRun:
    loaded = make_test_config(tmp_path, project_root, workspace_name="cred")
    store = InstanceStore(loaded.paths)
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    task = tmp_path / "task.md"
    task.write_text("audit\n", encoding="utf-8")
    instance = make_instance(instance_id="VM-1")
    adapter = SubprocessAgentAdapter(
        loaded=loaded, agent_config=agent, store=store, agent_base_dir=tmp_path
    )
    return adapter.prepare(
        instance, _agent_run(instance.instance_id), source_repo=repo, task_path=task
    )


def _subprocess_agent(**overrides) -> AgentConfig:
    payload = {
        "adapter": "subprocess",
        "argv": ["python", "-c", "print(1)", "--repo", "{repo}", "--out", "{output}"],
        "scaffold": "subprocess",
        "network_enabled": False,
        "credential_env_allowlist": [_FAKE_NAME],
    }
    payload.update(overrides)
    return AgentConfig(**payload)


# ------------------------------------------------------------- P0-2 env plumbing
def test_declared_credential_reaches_prepared_subprocess(
    monkeypatch, tmp_path: Path, project_root: Path
) -> None:
    monkeypatch.setenv(_FAKE_NAME, _FAKE_VALUE)
    prepared = _prepare(tmp_path, project_root, _subprocess_agent())
    assert prepared.env[_FAKE_NAME] == _FAKE_VALUE
    assert any(
        f"credential variables forwarded by name: {_FAKE_NAME}" in note
        for note in prepared.sandbox_notes
    )


def test_undeclared_variable_is_not_forwarded(
    monkeypatch, tmp_path: Path, project_root: Path
) -> None:
    monkeypatch.setenv(_FAKE_NAME, _FAKE_VALUE)
    monkeypatch.setenv(_UNDECLARED_NAME, "other-secret")
    prepared = _prepare(tmp_path, project_root, _subprocess_agent())
    assert _UNDECLARED_NAME not in prepared.env


def test_credential_value_never_appears_in_serialised_records(
    monkeypatch, tmp_path: Path, project_root: Path
) -> None:
    monkeypatch.setenv(_FAKE_NAME, _FAKE_VALUE)
    prepared = _prepare(tmp_path, project_root, _subprocess_agent())
    payload = json.dumps(
        {
            "notes": prepared.sandbox_notes,
            "metadata": prepared.metadata,
            "argv": prepared.argv,
            "agent_argv": prepared.agent_argv,
        },
        default=str,
    )
    assert _FAKE_VALUE not in payload
    # Only the name may appear.
    assert _FAKE_NAME in payload


def test_missing_required_credential_fails_before_agent(monkeypatch) -> None:
    monkeypatch.delenv(_FAKE_NAME, raising=False)
    agent = _subprocess_agent()
    with pytest.raises(HarnessError) as excinfo:
        ensure_credentials(agent, context="run_release")
    details = excinfo.value.details
    assert details["failure_type"] == "credentials_missing"
    assert details["missing"] == [_FAKE_NAME]
    assert _FAKE_VALUE not in json.dumps(details)


def test_optional_policy_does_not_block(monkeypatch) -> None:
    monkeypatch.delenv(_FAKE_NAME, raising=False)
    agent = _subprocess_agent(credential_policy="optional")
    status = ensure_credentials(agent)
    assert status.satisfied is True
    assert status.missing == [_FAKE_NAME]


def test_build_environment_never_copies_undeclared_values(monkeypatch) -> None:
    monkeypatch.setenv(_FAKE_NAME, _FAKE_VALUE)
    monkeypatch.setenv(_UNDECLARED_NAME, "x")
    env, notes = build_environment(
        ["PATH"], network_enabled=False, credential_allowlist=[_FAKE_NAME]
    )
    assert env[_FAKE_NAME] == _FAKE_VALUE
    assert _UNDECLARED_NAME not in env
    assert all(_FAKE_VALUE not in note for note in notes)


def test_condition_identity_uses_names_not_values(monkeypatch) -> None:
    monkeypatch.setenv(_FAKE_NAME, _FAKE_VALUE)
    agent = _subprocess_agent()
    status = inspect_credentials(agent)
    payload = status.as_dict()
    assert payload["declared"] == [_FAKE_NAME]
    assert payload["present"] == [_FAKE_NAME]
    assert _FAKE_VALUE not in json.dumps(payload)


# --------------------------------------------------------------- doctor report
def _write_agent_yaml(path: Path) -> Path:
    path.write_text(
        "\n".join(
            [
                'schema_version: "1.0"',
                "adapter: subprocess",
                "argv:",
                '  - "python"',
                '  - "-c"',
                '  - "print(1)"',
                '  - "--repo"',
                '  - "{repo}"',
                '  - "--out"',
                '  - "{output}"',
                "scaffold: subprocess",
                "credential_env_allowlist:",
                f"  - {_FAKE_NAME}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_doctor_reports_declared_present_forwarded(
    monkeypatch, tmp_path: Path, project_root: Path
) -> None:
    monkeypatch.delenv(_FAKE_NAME, raising=False)
    loaded = make_test_config(tmp_path, project_root, workspace_name="doctor")
    agent_path = _write_agent_yaml(tmp_path / "agent.yaml")
    absent = run_doctor(loaded, agent_path=str(agent_path))
    check = next(item for item in absent["checks"] if item["name"] == "agent_credentials")
    assert check["declared"] == 1
    assert check["present"] == 0
    assert check["forwarded"] == 0
    assert check["blocks_live_run"] is True
    assert check["variables"] == [
        {"name": _FAKE_NAME, "declared": True, "present": False, "forwarded": False}
    ]

    monkeypatch.setenv(_FAKE_NAME, _FAKE_VALUE)
    present = run_doctor(loaded, agent_path=str(agent_path))
    check = next(item for item in present["checks"] if item["name"] == "agent_credentials")
    assert check["present"] == 1
    assert check["forwarded"] == 1
    assert check["blocks_live_run"] is False
    assert _FAKE_VALUE not in json.dumps(present)


# ------------------------------------------------------- P1-1 container argv/state
def test_container_argv_uses_name_only_for_credentials() -> None:
    backend = ContainerBackend(
        runtime="docker",
        image="vulnmirage/audit-agent:latest",
        network="bridge",
        env_names=["PATH", _FAKE_NAME],
        env_values={
            "HOME": "/agent-state/home",
            "OPENCODE_CONFIG": "/agent-state/opencode.json",
            _FAKE_NAME: "should-be-ignored",
        },
        name="RUN-1",
    )
    argv = backend.build_argv(["opencode", "run"], cwd="/repo")
    assert "-e" in argv
    assert _FAKE_NAME in argv
    assert f"{_FAKE_NAME}={_FAKE_VALUE}" not in argv
    assert f"{_FAKE_NAME}=should-be-ignored" not in argv
    assert "HOME=/agent-state/home" in argv
    assert "OPENCODE_CONFIG=/agent-state/opencode.json" in argv
    assert "--name" in argv and "RUN-1" in argv
    assert backend.enforcement["network_separation"] == (
        "best_effort_same_network_for_model_and_tools"
    )


def test_container_backend_mounts_agent_state(monkeypatch, tmp_path: Path) -> None:
    import vulnmirage.harness.container as container_module

    monkeypatch.setattr(
        container_module, "container_available", lambda runtime: (True, "docker")
    )
    repo = tmp_path / "repo"
    scratch = tmp_path / "scratch"
    output = tmp_path / "output"
    state = tmp_path / "state"
    for directory in (repo, scratch, output, state):
        directory.mkdir()
    backend = build_backend(
        configured_runtime="docker",
        image="img:1",
        network="none",
        repo_dir=repo,
        scratch_dir=scratch,
        output_dir=output,
        env_names=["PATH"],
        credential_names=[_FAKE_NAME],
        agent_state_dir=state,
        env_values={"OPENCODE_CONFIG": "/agent-state/opencode.json"},
        name="RUN-1",
    )
    targets = {mount.target: mount.mode for mount in backend.mounts}
    assert targets["/agent-state"] == "rw"
    assert targets["/repo"] == "ro"
    assert backend.enforcement["agent_state_mounted"] is True
    assert backend.enforcement["open_code_config_path"] == "/agent-state/opencode.json"


def test_container_prepare_copies_opencode_config_and_state(
    monkeypatch, tmp_path: Path, project_root: Path
) -> None:
    import vulnmirage.harness.container as container_module

    captured: dict = {}

    def fake_build_backend(**kwargs):
        captured.update(kwargs)
        return ContainerBackend(
            runtime="docker",
            image=kwargs["image"],
            network=kwargs["network"],
            mounts=[],
            env_names=list(kwargs["env_names"]),
            env_values=dict(kwargs["env_values"]),
            name=kwargs["name"],
            agent_state_dir=kwargs["agent_state_dir"],
        )

    monkeypatch.setattr(container_module, "build_backend", fake_build_backend)
    config = tmp_path / "opencode.json"
    config.write_text('{"model": "provider/model"}\n', encoding="utf-8")
    agent = _subprocess_agent(
        adapter="opencode",
        executable="opencode",
        output_format="json",
        config_file=str(config),
        execution_backend="container",
        container_image="img:1",
        container_network="bridge",
    )
    prepared = _prepare(tmp_path, project_root, agent)
    state_dir = Path(captured["agent_state_dir"])
    assert (state_dir / "opencode.json").is_file()
    for relative in ("home", "config", "cache", "data", "state"):
        assert (state_dir / relative).is_dir()
    assert captured["env_values"]["OPENCODE_CONFIG"] == "/agent-state/opencode.json"
    assert captured["env_values"]["HOME"] == "/agent-state/home"
    assert "OPENCODE_CONFIG" not in captured["env_names"]
    argv = prepared.argv
    assert any(str(mount) for mount in [argv])  # argv built through the backend
    assert "img:1" in argv
    assert prepared.container_backend is not None
    assert "--name" in argv


def test_doctor_container_checks(monkeypatch, tmp_path: Path, project_root: Path) -> None:
    loaded = make_test_config(tmp_path, project_root, workspace_name="doctor-containers")
    agent_path = tmp_path / "container_agent.yaml"
    agent_path.write_text(
        "\n".join(
            [
                'schema_version: "1.0"',
                "adapter: subprocess",
                "argv:",
                '  - "python"',
                '  - "-c"',
                '  - "print(1)"',
                '  - "--repo"',
                '  - "{repo}"',
                '  - "--out"',
                '  - "{output}"',
                "scaffold: container-agent",
                "execution_backend: container",
                "container_image: vulnmirage/audit-agent:latest",
                "container_agent_executable: opencode",
                "",
            ]
        ),
        encoding="utf-8",
    )
    import vulnmirage.harness.container as container_module

    monkeypatch.setattr(
        container_module, "container_available", lambda runtime: (False, "no runtime")
    )
    report = run_doctor(loaded, agent_path=str(agent_path))
    names = {item["name"] for item in report["checks"]}
    assert "container_backend" in names
    backend = next(item for item in report["checks"] if item["name"] == "container_backend")
    assert backend["agent_state_mount"] == "/agent-state"
    assert backend["config_in_container"] == "/agent-state/opencode.json"
