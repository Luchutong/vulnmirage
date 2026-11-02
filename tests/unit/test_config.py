from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnmirage.config import (
    AppConfig,
    config_sha256,
    load_agent_config,
    load_config,
)
from vulnmirage.errors import ConfigError


def test_default_config_loads(default_config) -> None:
    assert default_config.config.workspace_root == "workspace"
    assert default_config.config.generation.tiers[0].value == "M0"
    assert len(default_config.sha256) == 64


def test_config_hash_is_stable(tmp_path: Path, project_root: Path) -> None:
    raw = {
        "schema_version": "1.0",
        "workspace_root": str(tmp_path / "ws"),
        "repo_cache": str(tmp_path / "cache"),
        "matching": {"strict_threshold": 0.7, "relaxed_threshold": 0.5},
    }
    path = tmp_path / "a.yaml"
    path.write_text(json.dumps(raw), encoding="utf-8")
    first = load_config(path)
    second = load_config(path)
    assert first.sha256 == second.sha256
    assert first.sha256 == config_sha256(first.config)
    changed = dict(raw)
    changed["workspace_root"] = str(tmp_path / "other")
    path.write_text(json.dumps(changed), encoding="utf-8")
    assert load_config(path).sha256 != first.sha256


def test_unknown_key_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("schema_version: '1.0'\nunknown_option: true\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_secret_like_key_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("schema_version: '1.0'\napi_key: abc\n", encoding="utf-8")
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "credentials" in str(excinfo.value)


def test_env_substitution(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("VM_TEST_WS", str(tmp_path / "envws"))
    path = tmp_path / "env.yaml"
    path.write_text(
        "schema_version: '1.0'\nworkspace_root: '${VM_TEST_WS}'\n", encoding="utf-8"
    )
    loaded = load_config(path)
    assert loaded.config.workspace_root == str(tmp_path / "envws")


def test_missing_env_rejected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("VM_MISSING_VALUE", raising=False)
    path = tmp_path / "env.yaml"
    path.write_text(
        "schema_version: '1.0'\nworkspace_root: '${VM_MISSING_VALUE}'\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "VM_MISSING_VALUE" in str(excinfo.value)


def test_command_shorthand_and_shell_rejected(tmp_path: Path) -> None:
    path = tmp_path / "commands.yaml"
    path.write_text(
        "schema_version: '1.0'\n"
        "validation:\n"
        "  build_commands:\n"
        "    - ['python', '-c', 'print(1)']\n",
        encoding="utf-8",
    )
    loaded = load_config(path)
    assert loaded.config.validation.build_commands[0].argv == ["python", "-c", "print(1)"]
    path.write_text(
        "schema_version: '1.0'\nvalidation:\n  build_commands:\n    - 'echo hi'\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(path)


def test_agent_config_requires_placeholders(tmp_path: Path, project_root: Path) -> None:
    path = tmp_path / "agent.yaml"
    path.write_text(
        "adapter: subprocess\nargv: ['python', 'agent.py', '{repo}']\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_agent_config(path)
    path.write_text(
        "adapter: subprocess\nargv: ['python', 'agent.py', '{repo}', '{output}']\n",
        encoding="utf-8",
    )
    loaded = load_agent_config(path)
    assert loaded.config.adapter == "subprocess"


def test_matching_weights_must_sum_to_one() -> None:
    with pytest.raises(Exception):
        AppConfig.model_validate(
            {
                "matching": {
                    "type_weight": 0.5,
                    "critical_operation_weight": 0.5,
                    "entry_point_weight": 0.5,
                    "trace_weight": 0.5,
                }
            }
        )


def test_local_repository_flag_present(default_config) -> None:
    assert default_config.config.network.allow_local_repositories is True
