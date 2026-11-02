from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnmirage.errors import DatasetError
from vulnmirage.ingest.base import build_oracle, parse_line_range, parse_location
from vulnmirage.ingest.generic_jsonl import ingest_generic_jsonl
from vulnmirage.ingest.vulngym import ingest_vulngym
from vulnmirage.normalization import normalize_cwe, normalize_cwe_list, normalize_severity


def _report(**overrides):
    report = {
        "report_id": "R1",
        "repo_url": "https://github.com/acme/demo",
        "commit": "a" * 40,
        "title": "SQL injection in search",
        "summary": "Request data reaches a raw query.",
        "cve_id": "CVE-2026-12345",
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "severity": "high",
        "cwe": ["CWE-89"],
        "verify": 1,
    }
    report.update(overrides)
    return report


def _entry(entry_id="E1", file="app/http.py", **overrides):
    entry = {
        "entry_id": entry_id,
        "report_id": "R1",
        "repo_url": "https://github.com/acme/demo",
        "commit": "a" * 40,
        "file": file,
        "line": "10-12",
        "function": "search",
        "cwe": ["CWE-89"],
        "verify": 1,
        "poc_commands": [{"name": "poc", "argv": ["python", "poc.py"]}],
    }
    entry.update(overrides)
    return entry


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (12, (12, 12)),
        ("10-20", (10, 20)),
        ("L10-L20", (10, 20)),
        ("10:20", (10, 20)),
        ("10", (10, 10)),
        ([3, 7], (3, 7)),
        ({"start": 4, "end": 9}, (4, 9)),
        ({"start_line": 2, "end_line": 5}, (2, 5)),
    ],
)
def test_parse_line_range(value, expected) -> None:
    assert parse_line_range(value) == expected


@pytest.mark.parametrize("value", [0, "0", "20-10", "not-a-line", {"end": 2}, True])
def test_parse_line_range_rejects(value) -> None:
    with pytest.raises(DatasetError):
        parse_line_range(value)


def test_parse_location_with_code_extends_range() -> None:
    loc = parse_location(
        {"file": "app/x.py", "line": 5, "code": "one\ntwo\nthree\n"},
    )
    assert loc.start_line == 5
    assert loc.end_line == 7
    assert loc.code_sha256


def test_parse_location_rejects_missing_file() -> None:
    with pytest.raises(DatasetError):
        parse_location({"line": 1})


def test_build_oracle_merges_entries() -> None:
    oracle = build_oracle(
        _report(),
        [
            _entry("E1", "app/http.py"),
            _entry("E2", "app/report.py", function="build_report"),
        ],
    )
    assert len(oracle.vulnerabilities) == 2
    assert oracle.source_record_ids == ["E1", "E2"]
    assert oracle.suggested_difficulty.value == "D4"
    assert oracle.validation_level == "trace_grounded"
    assert oracle.hidden_metadata["cve_ids"] == ["CVE-2026-12345"]
    assert oracle.hidden_metadata["ghsa_ids"] == ["GHSA-aaaa-bbbb-cccc"]
    assert len(oracle.vulnerabilities[0].poc_commands) == 1
    assert oracle.vulnerabilities[0].cwe == ["CWE-89"]
    assert oracle.effective_difficulty.value == "D4"


def test_oracle_ids_are_stable() -> None:
    first = build_oracle(_report(), [_entry()])
    second = build_oracle(_report(), [_entry()])
    assert first.oracle_id == second.oracle_id
    assert first.vulnerabilities[0].vulnerability_id == second.vulnerabilities[0].vulnerability_id


def test_unverified_rejected_unless_allowed() -> None:
    with pytest.raises(DatasetError):
        build_oracle(_report(verify=0), [_entry()])
    oracle = build_oracle(_report(verify=0), [_entry()], allow_unverified=True)
    assert oracle.validation_level == "unverified"


def test_inconsistent_repository_rejected() -> None:
    with pytest.raises(DatasetError):
        build_oracle(_report(), [_entry(repo_url="https://github.com/acme/other")])
    with pytest.raises(DatasetError):
        build_oracle(_report(), [_entry(commit="b" * 40)])


def test_duplicate_entry_rejected() -> None:
    with pytest.raises(DatasetError):
        build_oracle(_report(), [_entry("E1"), _entry("E1", "app/other.py")])


def test_short_commit_rejected() -> None:
    with pytest.raises(DatasetError):
        build_oracle(_report(commit="abc"), [_entry(commit="abc")])


def test_manual_difficulty_override() -> None:
    oracle = build_oracle(_report(difficulty="D3"), [_entry()])
    assert oracle.suggested_difficulty.value == "D3"
    assert oracle.final_difficulty is not None
    assert oracle.difficulty_source == "human"


def test_shell_command_rejected() -> None:
    with pytest.raises(DatasetError):
        build_oracle(_report(), [_entry(poc_commands=["python poc.py"])])


def test_ingest_vulngym_files(tmp_path: Path) -> None:
    reports = tmp_path / "reports.jsonl"
    entries = tmp_path / "entries.jsonl"
    reports.write_text(
        json.dumps(_report()) + "\n" + json.dumps(_report(report_id="R2", repo_url="https://github.com/acme/two", commit="b" * 40)) + "\n",
        encoding="utf-8",
    )
    entries.write_text(
        "\n".join(
            [
                json.dumps(_entry("E1")),
                json.dumps(_entry("E2", "app/report.py")),
                json.dumps(_entry("E3", "app/two.py", report_id="R2", repo_url="https://github.com/acme/two", commit="b" * 40)),
                json.dumps({"entry_id": "ORPHAN", "report_id": "MISSING"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "normalized"
    result = ingest_vulngym(
        reports_path=reports,
        entries_path=entries,
        output_dir=output,
    )
    assert result["imported"] == 2
    assert result["rejected"] == 1
    index = json.loads((output / "index.json").read_text(encoding="utf-8"))
    assert index["reports_sha256"]
    assert len(index["imported"]) == 2
    oracle_files = sorted(
        path for path in output.glob("VMO-*.json") if not path.name.endswith(".meta.json")
    )
    assert len(oracle_files) == 2
    oracle_payloads = [
        json.loads(path.read_text(encoding="utf-8")) for path in oracle_files
    ]
    assert sorted(len(item["vulnerabilities"]) for item in oracle_payloads) == [1, 2]

    # Re-import produces byte-identical oracle files.
    before = {path.name: path.read_bytes() for path in oracle_files}
    ingest_vulngym(reports_path=reports, entries_path=entries, output_dir=output)
    after = {
        path.name: path.read_bytes()
        for path in output.glob("VMO-*.json")
        if not path.name.endswith(".meta.json")
    }
    assert before == after


def test_ingest_generic_oracle_and_report(tmp_path: Path) -> None:
    oracle = build_oracle(_report(), [_entry()]).model_dump(mode="json")
    record = {
        "report": _report(report_id="R3"),
        "entries": [_entry("E9", report_id="R3")],
    }
    input_path = tmp_path / "generic.jsonl"
    input_path.write_text(json.dumps(oracle) + "\n" + json.dumps(record) + "\n", encoding="utf-8")
    output = tmp_path / "out"
    result = ingest_generic_jsonl(input_path=input_path, output_dir=output)
    assert result["imported"] == 2
    assert result["rejected"] == 0


def test_normalization_helpers() -> None:
    assert normalize_cwe("CWE_89") == "CWE-89"
    assert normalize_cwe(79) == "CWE-79"
    assert normalize_cwe_list(["89", "CWE-79", "cwe-89"]) == ["CWE-79", "CWE-89"]
    from vulnmirage.models import SeverityLevel

    assert normalize_severity("Moderate") == SeverityLevel.MEDIUM
    assert normalize_severity("CRITICAL") == SeverityLevel.CRITICAL
    assert normalize_severity("info") == SeverityLevel.INFO
    with pytest.raises(Exception):
        normalize_severity("very bad")
