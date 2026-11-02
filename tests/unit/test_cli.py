from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnmirage.cli import build_parser, main


def test_parser_has_all_commands() -> None:
    parser = build_parser()
    help_text = parser.format_help()
    for command in (
        "doctor",
        "schemas",
        "ingest",
        "materialize",
        "generate",
        "validate",
        "export",
        "run",
        "evaluate",
        "inspect",
        "validate-release",
        "repair-output",
    ):
        assert command in help_text


def test_version(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "vulnmirage" in capsys.readouterr().out


def test_schemas_command(tmp_path: Path, capsys) -> None:
    code = main(["schemas", "--output", str(tmp_path / "schemas")])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert (tmp_path / "schemas" / "finding.schema.json").exists()


def test_missing_config_is_machine_readable(tmp_path: Path, capsys) -> None:
    code = main(["doctor", "--config", str(tmp_path / "missing.yaml")])
    assert code == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.err.strip().splitlines()[-1])
    assert payload["error_code"] == "config_error"


def test_unknown_command_exits_two() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["does-not-exist"])
    assert excinfo.value.code == 2
