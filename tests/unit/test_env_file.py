"""Local .env parsing and loading (values are never logged)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from vulnmirage.env import (
    load_env_file,
    load_local_env,
    parse_env_text,
    reset_env_cache,
    secret_environment_status,
)
from vulnmirage.errors import ConfigError
from vulnmirage.generation.llm_backend import LLMBackend

_LLM_KEYS = (
    "VULNMIRAGE_LLM_BASE_URL",
    "VULNMIRAGE_LLM_API_KEY",
    "VULNMIRAGE_LLM_MODEL",
)


@pytest.fixture(autouse=True)
def _clean_env():
    saved = {key: os.environ.get(key) for key in _LLM_KEYS}
    for key in _LLM_KEYS:
        os.environ.pop(key, None)
    reset_env_cache()
    yield
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    reset_env_cache()


def test_parse_env_supports_quotes_comments_and_export() -> None:
    values, warnings = parse_env_text(
        "\n".join(
            [
                "# comment",
                "A=plain",
                "export B=exported",
                'C="line\\nvalue"',
                "D='single # kept'",
                "E=value # trailing comment",
                "F=url#fragment",
                "BAD LINE",
                "9INVALID=x",
                "",
            ]
        )
    )
    assert values["A"] == "plain"
    assert values["B"] == "exported"
    assert values["C"] == "line\nvalue"
    assert values["D"] == "single # kept"
    assert values["E"] == "value"
    assert values["F"] == "url#fragment"
    assert len(warnings) == 2


def test_load_env_file_does_not_override_existing_environment(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(
        "VULNMIRAGE_LLM_BASE_URL=https://from-file.invalid/v1\n"
        "VULNMIRAGE_LLM_API_KEY=file-key\n"
        "VULNMIRAGE_LLM_MODEL=file-model\n",
        encoding="utf-8",
    )
    os.environ["VULNMIRAGE_LLM_API_KEY"] = "shell-key"
    result = load_env_file(path)
    assert result.loaded is True
    assert "VULNMIRAGE_LLM_API_KEY" in result.skipped_existing
    assert os.environ["VULNMIRAGE_LLM_API_KEY"] == "shell-key"
    assert os.environ["VULNMIRAGE_LLM_MODEL"] == "file-model"
    assert "file-key" not in repr(result.status())


def test_load_env_file_override_and_secret_status(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("VULNMIRAGE_LLM_API_KEY=file-key\n", encoding="utf-8")
    os.environ["VULNMIRAGE_LLM_API_KEY"] = "shell-key"
    load_env_file(path, override=True)
    assert os.environ["VULNMIRAGE_LLM_API_KEY"] == "file-key"
    status = secret_environment_status(["VULNMIRAGE_LLM_API_KEY"])
    assert status[0]["present"] is True
    assert status[0]["source"] == "env_file"
    assert "file-key" not in str(status)


def test_llm_backend_reads_values_from_local_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".env").write_text(
        "VULNMIRAGE_LLM_BASE_URL=https://local.invalid/v1\n"
        "VULNMIRAGE_LLM_API_KEY=local-key\n"
        "VULNMIRAGE_LLM_MODEL=local-model\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    backend = LLMBackend()
    assert backend.base_url == "https://local.invalid/v1"
    assert backend.api_key == "local-key"
    assert backend.model == "local-model"


def test_missing_environment_reports_names_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError) as excinfo:
        LLMBackend()
    details = excinfo.value.details
    assert "VULNMIRAGE_LLM_API_KEY" in details["missing"]
    assert "local-key" not in str(details)


def test_cli_env_file_option_loads_before_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vulnmirage.cli import main

    path = tmp_path / "custom.env"
    path.write_text("VULNMIRAGE_LLM_MODEL=from-custom-file\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = main(["--env-file", str(path), "doctor"])
    assert code == 0
    assert os.environ["VULNMIRAGE_LLM_MODEL"] == "from-custom-file"
