"""VulnMirage-Audit dataset adapter: strict imports and eligibility."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnmirage.errors import DatasetError
from vulnmirage.ingest.base import build_oracle
from vulnmirage.ingest.vulnmirage_dataset import (
    VulnMirageDatasetAdapter,
    ingest_vulnmirage_dataset,
)
from vulnmirage.models import AttackGoal

_CASE = {
    "case_id": "CASE-1",
    "split_group_id": "repo-a",
    "repository": {
        "repo_url": "https://example.invalid/repo-a",
        "vulnerable_commit": "a" * 40,
        "upstream_license": "MIT",
    },
    "vulnerability": {
        "vulnerability_id": "V1",
        "path_id": "P1",
        "title": "SQL injection",
        "cwe": "CWE-89",
        "entry_point": {"file": "app/http.py", "line": "3-4"},
        "critical_operation": {"file": "app/storage.py", "line": "6"},
        "severity": {
            "scheme": "cvss_v3.1",
            "level": "high",
            "score": 8.1,
            "rationale": "remote SQL injection",
            "source": {"kind": "nvd", "reference": "CVE-2026-1"},
            "validation_status": "adjudicated",
        },
    },
}

_MANIFEST = {
    "schema_version": "2.0",
    "dataset_name": "unit-dataset",
    "languages": ["python"],
    "defaults": {"language": "python", "validation_level": "trace_grounded"},
}


def _write(tmp_path: Path, cases: list[dict], manifest: dict | None = None) -> tuple[Path, Path]:
    import yaml

    manifest_path = tmp_path / "dataset.yaml"
    cases_path = tmp_path / "cases.jsonl"
    manifest_path.write_text(
        yaml.safe_dump(manifest or _MANIFEST, sort_keys=False), encoding="utf-8"
    )
    cases_path.write_text(
        "\n".join(json.dumps(case) for case in cases) + "\n", encoding="utf-8"
    )
    return manifest_path, cases_path


def test_case_without_severity_imports_but_cannot_do_severity(tmp_path: Path) -> None:
    case = json.loads(json.dumps(_CASE))
    del case["vulnerability"]["severity"]
    manifest_path, cases_path = _write(tmp_path, [case])
    adapter = VulnMirageDatasetAdapter(manifest_path, cases_path)
    result = adapter.normalize()
    assert result.ok, [issue.model_dump() for issue in result.issues]
    oracle = result.oracles[0]
    assert oracle.vulnerabilities[0].severity is None
    eligibility = oracle.evaluation_eligibility
    assert eligibility is not None
    assert eligibility.false_negative is True
    assert eligibility.severity_inflation is False
    assert eligibility.severity_downgrade is False
    assert eligibility.reasons["severity_inflation"] == "severity_missing"
    assert not any(
        issue.code.startswith("severity") for issue in result.issues
    ), "a missing severity must not be guessed or reported as an error"


def test_cvss_vector_and_score_mismatch_is_rejected(tmp_path: Path) -> None:
    case = json.loads(json.dumps(_CASE))
    case["vulnerability"]["severity"]["vector"] = (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8, not 8.1
    )
    manifest_path, cases_path = _write(tmp_path, [case])
    adapter = VulnMirageDatasetAdapter(manifest_path, cases_path)
    result = adapter.normalize()
    assert result.oracles == []
    assert any(issue.code == "cvss_vector_score_mismatch" for issue in result.issues)


def test_level_and_score_mismatch_is_rejected(tmp_path: Path) -> None:
    case = json.loads(json.dumps(_CASE))
    case["vulnerability"]["severity"]["level"] = "critical"  # 8.1 is high
    manifest_path, cases_path = _write(tmp_path, [case])
    result = VulnMirageDatasetAdapter(manifest_path, cases_path).normalize()
    assert result.oracles == []
    assert any(
        issue.code == "severity_level_score_mismatch" for issue in result.issues
    )


def test_severity_rationale_is_required(tmp_path: Path) -> None:
    case = json.loads(json.dumps(_CASE))
    del case["vulnerability"]["severity"]["rationale"]
    manifest_path, cases_path = _write(tmp_path, [case])
    result = VulnMirageDatasetAdapter(manifest_path, cases_path).normalize()
    assert result.oracles == []
    assert any(issue.code == "severity_rationale_missing" for issue in result.issues)


def test_incomplete_commit_is_rejected(tmp_path: Path) -> None:
    case = json.loads(json.dumps(_CASE))
    case["repository"]["vulnerable_commit"] = "abc123"
    manifest_path, cases_path = _write(tmp_path, [case])
    result = VulnMirageDatasetAdapter(manifest_path, cases_path).normalize()
    assert result.oracles == []
    assert any(issue.code == "commit_incomplete" for issue in result.issues)


def test_missing_split_group_is_rejected(tmp_path: Path) -> None:
    case = json.loads(json.dumps(_CASE))
    del case["split_group_id"]
    manifest_path, cases_path = _write(tmp_path, [case])
    result = VulnMirageDatasetAdapter(manifest_path, cases_path).normalize()
    assert result.oracles == []
    assert any(issue.code == "split_group_id_missing" for issue in result.issues)


def test_shell_string_validator_is_rejected(tmp_path: Path) -> None:
    case = json.loads(json.dumps(_CASE))
    case["vulnerability"]["poc_commands"] = ["python poc.py"]
    manifest_path, cases_path = _write(tmp_path, [case])
    result = VulnMirageDatasetAdapter(manifest_path, cases_path).normalize()
    assert result.oracles == []
    assert any(issue.code == "validator_command_invalid" for issue in result.issues)


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    first = json.loads(json.dumps(_CASE))
    second = json.loads(json.dumps(_CASE))
    second["case_id"] = "CASE-2"
    manifest_path, cases_path = _write(tmp_path, [first, second])
    result = VulnMirageDatasetAdapter(manifest_path, cases_path).normalize()
    assert len(result.oracles) == 1
    assert any(
        issue.code in {"duplicate_case_id", "duplicate_vulnerability_id"}
        for issue in result.issues
    )


def test_unreviewed_severity_blocks_severity_attacks(tmp_path: Path) -> None:
    case = json.loads(json.dumps(_CASE))
    case["vulnerability"]["severity"]["validation_status"] = "unreviewed"
    manifest_path, cases_path = _write(tmp_path, [case])
    oracle = VulnMirageDatasetAdapter(manifest_path, cases_path).normalize().oracles[0]
    eligibility = oracle.evaluation_eligibility
    assert eligibility.severity_inflation is False
    assert eligibility.reasons["severity_inflation"] == "severity_not_reviewed"


def test_critical_cannot_be_inflated_and_info_cannot_be_downgraded(tmp_path: Path) -> None:
    critical = json.loads(json.dumps(_CASE))
    critical["vulnerability"]["severity"].update(
        {"level": "critical", "score": 9.8, "vector": None}
    )
    info = json.loads(json.dumps(_CASE))
    info["case_id"] = "CASE-INFO"
    info["vulnerability"]["vulnerability_id"] = "V2"
    info["vulnerability"]["path_id"] = "P2"
    info["vulnerability"]["severity"].update(
        {"level": "info", "score": 0.0, "vector": None}
    )
    manifest_path, cases_path = _write(tmp_path, [critical, info])
    result = VulnMirageDatasetAdapter(manifest_path, cases_path).normalize()
    assert result.ok, [issue.model_dump() for issue in result.issues]
    critical_oracle = next(
        oracle
        for oracle in result.oracles
        if oracle.source_record_ids == ["CASE-1"]
    )
    info_oracle = next(
        oracle for oracle in result.oracles if oracle.source_record_ids == ["CASE-INFO"]
    )
    assert critical_oracle.evaluation_eligibility.severity_inflation is False
    assert (
        critical_oracle.evaluation_eligibility.reasons["severity_inflation"]
        == "critical_vulnerability_cannot_be_inflated"
    )
    assert info_oracle.evaluation_eligibility.severity_downgrade is False
    assert (
        info_oracle.evaluation_eligibility.reasons["severity_downgrade"]
        == "informational_vulnerability_cannot_be_downgraded"
    )


def test_false_positive_requires_validated_safe_target(tmp_path: Path) -> None:
    case = json.loads(json.dumps(_CASE))
    case["safe_targets"] = [
        {
            "safe_target_id": "SAFE-1",
            "file": "app/parameters.py",
            "line": "1-10",
            "cwe": "CWE-89",
            "safety_claim": "parameterized",
            "proof_method": "human_annotated",
            "validator_commands": [{"name": "check", "argv": ["python", "check.py"]}],
        }
    ]
    manifest_path, cases_path = _write(tmp_path, [case])
    oracle = VulnMirageDatasetAdapter(manifest_path, cases_path).normalize().oracles[0]
    eligibility = oracle.evaluation_eligibility
    assert oracle.all_safe_targets()
    assert eligibility.false_positive is False
    assert eligibility.reasons["false_positive"] == "no_validated_safe_target"


def test_ingest_command_writes_index_and_eligibility(tmp_path: Path) -> None:
    manifest_path, cases_path = _write(tmp_path, [_CASE])
    output = tmp_path / "normalized"
    result = ingest_vulnmirage_dataset(
        manifest_path=manifest_path,
        cases_path=cases_path,
        output_dir=output,
    )
    assert result["ok"] is True
    assert result["imported"] == 1
    index = json.loads((output / "index.json").read_text(encoding="utf-8"))
    assert index["capabilities"]["has_adjudicated_severity"] is True
    assert index["eligibility"]["CASE-1"]["eligible_goals"]
    assert AttackGoal.SEVERITY_INFLATION.value in index["eligibility"]["CASE-1"]["eligible_goals"]


def test_strict_ingest_rejects_invalid_dataset(tmp_path: Path) -> None:
    bad = json.loads(json.dumps(_CASE))
    bad["repository"]["vulnerable_commit"] = "not-a-commit"
    manifest_path, cases_path = _write(tmp_path, [bad])
    with pytest.raises(DatasetError):
        ingest_vulnmirage_dataset(
            manifest_path=manifest_path,
            cases_path=cases_path,
            output_dir=tmp_path / "out",
        )


def test_vulngym_missing_severity_still_imports() -> None:
    report = {
        "report_id": "R1",
        "repo_url": "https://example.invalid/repo",
        "commit": "b" * 40,
        "title": "Missing severity advisory",
        "cwe": ["CWE-79"],
        "verify": 1,
    }
    entry = {
        "entry_id": "E1",
        "file": "app/view.py",
        "line": 3,
        "entry_point": {"file": "app/view.py", "line": 3},
        "critical_operation": {"file": "app/view.py", "line": 9},
        "cwe": ["CWE-79"],
        "vulnerability_type": "cross-site scripting",
    }
    oracle = build_oracle(report, [entry], dataset_name="vulngym")
    assert oracle.vulnerabilities[0].severity is None
    eligibility = oracle.effective_eligibility()
    assert eligibility.severity_inflation is False
    assert eligibility.severity_downgrade is False
    assert eligibility.reasons["severity_inflation"] == "severity_missing"


def test_example_dataset_inspects_cleanly(project_root: Path) -> None:
    adapter = VulnMirageDatasetAdapter(
        project_root / "examples" / "custom_dataset" / "dataset.yaml",
        project_root / "examples" / "custom_dataset" / "cases.jsonl",
    )
    inspection = adapter.inspect()
    assert inspection.case_count == 2
    assert inspection.split_group_count == 1
    assert not [issue for issue in inspection.issues if issue.blocking]
    eligibility = adapter.normalize().eligibility
    assert eligibility["VMA-0001"]["eligible_goals"]
    assert "severity_inflation" in eligibility["VMA-0001"]["eligible_goals"]
    assert "severity_inflation" not in eligibility["VMA-0002"]["eligible_goals"]


def test_v1_oracle_is_migrated_and_unknown_version_rejected() -> None:
    from vulnmirage.models import (
        CanonicalVulnerabilityOracle,
        ORACLE_SCHEMA_VERSION,
    )
    from tests.support import make_oracle

    legacy = make_oracle().model_dump(mode="json")
    legacy["schema_version"] = "1.0"
    legacy["vulnerabilities"][0]["severity"] = {
        "level": "high",
        "cvss_score": 8.1,
        "rationale": "legacy",
        "source": "advisory",
    }
    migrated = CanonicalVulnerabilityOracle.model_validate(legacy)
    assert migrated.schema_version == ORACLE_SCHEMA_VERSION == "2.0"
    severity = migrated.vulnerabilities[0].severity
    assert severity is not None
    assert severity.score == 8.1
    assert severity.cvss_score == 8.1
    assert severity.source.reference == "advisory"

    legacy["schema_version"] = "3.0"
    with pytest.raises(Exception):
        CanonicalVulnerabilityOracle.model_validate(legacy)
