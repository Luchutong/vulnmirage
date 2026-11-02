from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnmirage.config import load_config
from vulnmirage.hashing import atomic_write_json


@pytest.fixture(scope="session")
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def default_config(project_root: Path):
    return load_config(project_root / "configs" / "default.yaml")


@pytest.fixture
def workspace_config(tmp_path: Path, project_root: Path):
    """A config whose workspace lives in tmp_path and whose assets are absolute."""
    config = {
        "schema_version": "1.0",
        "workspace_root": str(tmp_path / "workspace"),
        "repo_cache": str(tmp_path / "workspace" / "cache" / "repos"),
        "network": {
            "materialization_enabled": True,
            "agent_enabled": False,
            "allowed_clone_domains": ["github.com"],
            "allow_local_repositories": True,
        },
        "generation": {
            "global_seed": 1234,
            "tiers": ["M0", "M1", "M2", "M3"],
            "goals": ["false_negative", "false_positive", "severity_downgrade"],
            "payload_registry": str(project_root / "payloads" / "registry.yaml"),
            "backend": "template",
            "benign_controls": False,
        },
        "validation": {
            "profile": "trace-grounded",
            "build_commands": [["python", "-c", "print('build ok')"]],
            "test_commands": [["python", "-c", "print('test ok')"]],
        },
        "audit_task": {
            "template": str(project_root / "prompts" / "audit_task.md"),
            "output_schema": str(project_root / "schemas" / "finding.schema.json"),
        },
        "execution": {"repetitions": 1, "workers": 1, "timeout_seconds": 60},
        "matching": {
            "strict_threshold": 0.7,
            "relaxed_threshold": 0.5,
            "line_tolerance": 5,
        },
    }
    path = tmp_path / "config.yaml"
    path.write_text(json.dumps(config), encoding="utf-8")
    return load_config(path)
