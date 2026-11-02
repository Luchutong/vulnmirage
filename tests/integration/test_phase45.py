from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fixture_repo import create_fixture_repo
from vulnmirage.code_semantics import executable_semantics_equal, read_text
from vulnmirage.evaluation.matching import match_instance
from vulnmirage.evaluation.report import evaluate_release
from vulnmirage.export.bundle import export_release
from vulnmirage.harness.runner import run_release
from vulnmirage.models import AgentFinding, CodeLocation, SeverityLevel
from vulnmirage.store import InstanceStore
from vulnmirage.validation.pipeline import validate_instance


@pytest.fixture(scope="module")
def phase45_run(phase45_workspace, project_root: Path):
    loaded = phase45_workspace["loaded"]
    release_dir = phase45_workspace["base"] / "release45"
    exported = export_release(
        loaded=loaded,
        instances_dir=loaded.paths.instances,
        output_dir=release_dir,
    )
    runs = run_release(
        loaded=loaded,
        release_dir=release_dir,
        agent_config_path=project_root / "configs" / "dummy_agent.yaml",
        repetitions=1,
        workers=2,
        instance_ids=None,
        limit=None,
        resume=False,
    )
    report = evaluate_release(
        loaded=loaded,
        release_dir=release_dir,
        runs_dir=loaded.paths.runs,
        output_dir=phase45_workspace["base"] / "reports45",
        matching_profile="strict",
    )
    return {
        "release_dir": release_dir,
        "exported": exported,
        "runs": runs,
        "report": report,
        "loaded": loaded,
    }


def test_m4_m5_m6_generated(phase45_workspace) -> None:
    result = phase45_workspace["result"]
    assert len(result["generated"]) == 5
    assert result["rejected"] == []
    tiers = {item["tier"] for item in result["generated"]}
    assert tiers == {"M4", "M5", "M6"}


def test_m4_is_behavior_preserving(phase45_workspace) -> None:
    loaded = phase45_workspace["loaded"]
    store = InstanceStore(loaded.paths)
    clean_id = phase45_workspace["materialized"]["instance_id"]
    clean_repo = store.repo_dir(clean_id)
    for item in phase45_workspace["result"]["generated"]:
        if item["tier"] != "M4":
            continue
        instance = store.load_instance(item["instance_id"])
        variant_repo = store.repo_dir(instance.instance_id)
        meta = json.loads(
            (store.instance_dir(instance.instance_id) / "patch_meta.json").read_text(encoding="utf-8")
        )
        for changed in meta["files_changed"]:
            path = changed["path"]
            if changed["status"] == "M" and path.endswith(".py"):
                assert executable_semantics_equal(
                    path,
                    read_text(clean_repo / path),
                    read_text(variant_repo / path),
                ), f"executable semantics changed in {path} for {instance.instance_id}"
        validation = json.loads(
            (store.instance_dir(instance.instance_id) / "validation.json").read_text(encoding="utf-8")
        )
        checks = {entry["check_name"]: entry["status"] for entry in validation["results"]}
        for name in ("build", "functional_tests", "poc_replay", "semantic_preservation"):
            assert checks[name] == "pass", (instance.instance_id, name, checks[name])
    helper_instances = [
        item for item in phase45_workspace["result"]["generated"]
        if item["operator"] == "AddUnreferencedRepresentationHelper"
    ]
    assert helper_instances
    helper_file = store.repo_dir(helper_instances[0]["instance_id"]) / "app" / "_audit_representation.py"
    assert helper_file.is_file()
    assert "normalize_audit_input" in helper_file.read_text(encoding="utf-8")


def test_m5_decoy_is_verified_safe(phase45_workspace) -> None:
    loaded = phase45_workspace["loaded"]
    store = InstanceStore(loaded.paths)
    m5 = [item for item in phase45_workspace["result"]["generated"] if item["tier"] == "M5"]
    assert len(m5) == 1
    for item in m5:
        instance = store.load_instance(item["instance_id"])
        decoys = store.load_decoys(instance.instance_id)
        assert len(decoys) == 1
        decoy = decoys[0]
        assert decoy.verified_safe is True
        assert decoy.safety_validator_commands
        assert decoy.apparent_critical_operation.file == "legacy_report.py"
        assert decoy.false_bridge.file == "legacy_report.py"
        assert decoy.apparent_critical_operation.start_line != decoy.false_bridge.start_line
        validation = json.loads(
            (store.instance_dir(instance.instance_id) / "validation.json").read_text(encoding="utf-8")
        )
        decoy_check = next(
            entry for entry in validation["results"] if entry["check_name"] == "decoy_safety"
        )
        assert decoy_check["status"] == "pass"
        assert all(
            item.get("verified_safe") is True for item in decoy_check["details"]["decoys"]
        )


def test_m5_decoy_matching_does_not_hit_true_vulnerability(phase45_workspace) -> None:
    loaded = phase45_workspace["loaded"]
    store = InstanceStore(loaded.paths)
    item = next(item for item in phase45_workspace["result"]["generated"] if item["tier"] == "M5")
    oracle = store.load_oracle(item["instance_id"])
    decoy = store.load_decoys(item["instance_id"])[0]
    location = decoy.apparent_critical_operation
    finding = AgentFinding(
        finding_id="F-DECOY-TEST",
        title="SQL injection in legacy report",
        vulnerability_type="SQL injection",
        cwe=["CWE-89"],
        severity=SeverityLevel.HIGH,
        locations=[location],
        entry_point=decoy.apparent_entry_point,
        critical_operation=location,
        trace=decoy.apparent_trace,
        exploitability="Request input reaches a string-built query.",
        evidence=["apparent sink"],
    )
    outcome = match_instance(
        [finding],
        oracle,
        decoys=[decoy],
        config=loaded.config.matching,
    )
    assert outcome.matched_count == 0
    assert outcome.matches[0].matched_decoy is True
    assert outcome.matches[0].decoy_id == decoy.decoy_id


def test_m6_composite_combines_children_and_revalidates(phase45_workspace) -> None:
    loaded = phase45_workspace["loaded"]
    store = InstanceStore(loaded.paths)
    m6 = [item for item in phase45_workspace["result"]["generated"] if item["tier"] == "M6"]
    assert len(m6) == 2
    for item in m6:
        instance = store.load_instance(item["instance_id"])
        manipulation = store.load_manipulation(instance.instance_id)
        assert manipulation is not None
        assert manipulation.operator_names == ["CompositeOperator"]
        assert manipulation.constraints["plan"]["children"]
        assert len(manipulation.constraints["plan"]["children"]) == 2
        assert len(manipulation.files_touched) >= 2
        validation = json.loads(
            (store.instance_dir(instance.instance_id) / "validation.json").read_text(encoding="utf-8")
        )
        checks = {entry["check_name"]: entry["status"] for entry in validation["results"]}
        assert checks["oracle_remap"] == "pass"
        assert checks["build"] == "pass"
        assert checks["functional_tests"] == "pass"
        assert checks["poc_replay"] == "pass"
        assert validation["release_eligible"] is True


def test_decoy_and_diversion_metrics(phase45_run) -> None:
    report = phase45_run["report"]
    assert report["runs"] == 6
    rows = list(
        __import__("csv").DictReader(
            (Path(report["output"]) / "pair_metrics.csv").open(encoding="utf-8")
        )
    )
    m5_rows = [row for row in rows if row["manipulation_tier"] == "M5"]
    assert len(m5_rows) == 1
    assert all(row["decoy_reported"] == "true" for row in m5_rows)
    assert any(int(row["decoy_file_reads"] or 0) > 0 for row in m5_rows)
    overall = report["overall"]
    assert overall["decoy_reporting_rate"] == 1.0
    assert overall["mean_decoy_file_reads"] is not None
    findings = [
        json.loads(line)
        for line in (Path(report["output"]) / "findings.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert any(item["matched_decoy"] is True for item in findings)


def test_m5_safety_validator_failure_rejects_instance(phase45_workspace) -> None:
    loaded = phase45_workspace["loaded"]
    store = InstanceStore(loaded.paths)
    item = next(item for item in phase45_workspace["result"]["generated"] if item["tier"] == "M5")
    instance_id = item["instance_id"]
    decoy_path = store.decoy_path(instance_id)
    payload = json.loads(decoy_path.read_text(encoding="utf-8"))
    payload["decoys"][0]["safety_validator_commands"] = [
        {
            "name": "intentionally-failing-safety-validator",
            "argv": ["python", "-c", "raise SystemExit(1)"],
            "cwd": ".",
            "timeout_seconds": 30,
            "expected_exit_codes": [0],
            "env_allowlist": [],
        }
    ]
    decoy_path.write_text(json.dumps(payload), encoding="utf-8")
    validation = validate_instance(loaded=loaded, instance_id=instance_id)
    assert validation["release_eligible"] is False
    assert validation["ground_truth_preserved"] is False
    decoy_check = next(
        check for check in validation["checks"] if check["name"] == "decoy_safety"
    )
    assert decoy_check["status"] == "fail"
    assert validation["quarantine_path"] is not None
    assert (Path(validation["quarantine_path"]) / "quarantine.json").is_file()
    assert store.load_state(instance_id).stage == "rejected"
