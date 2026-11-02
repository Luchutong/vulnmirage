from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.support import make_envelope, make_finding
from vulnmirage.errors import OutputParseError
from vulnmirage.evaluation.parser import parse_agent_output
from vulnmirage.evaluation.repair import repair_output_file


def _envelope_json() -> str:
    return json.dumps(make_envelope().model_dump(mode="json"), indent=2)


def test_parse_plain_json() -> None:
    parsed = parse_agent_output(_envelope_json())
    assert parsed.extraction == "plain_json"
    assert len(parsed.findings) == 1
    assert parsed.raw_sha256


def test_parse_fenced_json_with_prose() -> None:
    text = "Here is the audit result:\n\n```json\n" + _envelope_json() + "\n```\n"
    parsed = parse_agent_output(text)
    assert parsed.extraction == "markdown_fence"
    assert parsed.findings[0].title == "SQL injection"


def test_parse_balanced_json_with_prose() -> None:
    text = "The agent said:\n" + _envelope_json() + "\nEnd of report."
    parsed = parse_agent_output(text)
    assert parsed.extraction == "balanced_object"


def test_multiple_fences_rejected() -> None:
    text = "```json\n" + _envelope_json() + "\n```\n```json\n" + _envelope_json() + "\n```"
    with pytest.raises(OutputParseError):
        parse_agent_output(text)


def test_missing_output_rejected() -> None:
    with pytest.raises(OutputParseError):
        parse_agent_output("")


def test_extra_fields_rejected() -> None:
    payload = json.loads(_envelope_json())
    payload["findings"][0]["surprise"] = True
    with pytest.raises(OutputParseError) as excinfo:
        parse_agent_output(json.dumps(payload))
    assert "schema" in excinfo.value.message


def test_severity_and_cwe_normalized() -> None:
    payload = json.loads(_envelope_json())
    payload["findings"][0]["severity"] = "High"
    payload["findings"][0]["cwe"] = ["89", "CWE-79"]
    parsed = parse_agent_output(json.dumps(payload))
    assert parsed.findings[0].severity.value == "high"
    assert parsed.findings[0].cwe == ["CWE-79", "CWE-89"]


def test_absolute_repo_paths_are_relativized(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    payload = json.loads(_envelope_json())
    payload["findings"][0]["locations"][0]["file"] = str(repo / "app" / "storage.py")
    payload["findings"][0]["critical_operation"]["file"] = str(repo / "app" / "storage.py")
    parsed = parse_agent_output(json.dumps(payload), repo_root=repo)
    assert parsed.findings[0].locations[0].file == "app/storage.py"
    assert parsed.findings[0].critical_operation.file == "app/storage.py"


def test_duplicate_findings_removed() -> None:
    payload = json.loads(_envelope_json())
    payload["findings"].append(payload["findings"][0])
    parsed = parse_agent_output(json.dumps(payload))
    assert len(parsed.findings) == 1
    assert parsed.duplicates_removed == 1


def test_repair_command_writes_diff(tmp_path: Path) -> None:
    raw = tmp_path / "raw.txt"
    raw.write_text("prefix\n```json\n" + _envelope_json() + "\n```\n", encoding="utf-8")
    result = repair_output_file(raw_path=raw, output_path=tmp_path / "fixed.json")
    assert result["ok"] is True
    assert (tmp_path / "fixed.json").is_file()
    assert (tmp_path / "fixed.json.diff").is_file()
    assert result["finding_count"] == 1
