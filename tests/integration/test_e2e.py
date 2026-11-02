from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from vulnmirage.cli import main
from vulnmirage.evaluation.report import evaluate_release
from vulnmirage.export.bundle import export_release, validate_release
from vulnmirage.harness.runner import run_release
from vulnmirage.inspect import inspect_instance, inspect_pair, inspect_run
from vulnmirage.store import InstanceStore


@pytest.fixture(scope="module")
def e2e(full_workspace, release_bundle, project_root: Path):
    loaded = full_workspace["loaded"]
    release_dir = release_bundle["release_dir"]
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
        output_dir=full_workspace["base"] / "reports",
        matching_profile="strict",
    )
    return {
        "release_dir": release_dir,
        "exported": release_bundle["exported"],
        "validated": release_bundle["validated"],
        "runs": runs,
        "report": report,
        "loaded": loaded,
    }


def test_export_and_basic_release_validation(e2e) -> None:
    exported = e2e["exported"]
    assert exported["instance_count"] == 9
    assert exported["pair_count"] == 1
    assert e2e["validated"]["ok"] is True, e2e["validated"]["errors"]
    release = e2e["release_dir"]
    assert (release / "release.json").is_file()
    assert (release / "manifest.sha256").is_file()
    assert (release / "materialize.py").is_file()
    assert (release / "provenance" / "audit_task.md").is_file()
    manifest = json.loads((release / "release.json").read_text(encoding="utf-8"))
    assert manifest["release_sha256"]
    assert manifest["instance_count"] == 9
    assert len(manifest["pairs"]) == 1


def test_release_rebuild_is_byte_reproducible(e2e) -> None:
    result = validate_release(
        loaded=e2e["loaded"],
        release_dir=e2e["release_dir"],
        rebuild=True,
    )
    assert result["ok"] is True, result["errors"]
    assert len(result["rebuilt"]) == 9
    assert all(item["ok"] for item in result["rebuilt"])


def test_agent_runs_complete_without_failures(e2e) -> None:
    runs = e2e["runs"]
    assert runs["run_count"] == 9
    assert runs["failures"] == []
    loaded = e2e["loaded"]
    for item in runs["runs"]:
        run_dir = loaded.paths.run_dir(item["run_id"])
        assert (run_dir / "run.json").is_file()
        assert (run_dir / "run_meta.json").is_file()
        assert (run_dir / "findings_raw.txt").is_file()
        assert (run_dir / "trace.jsonl").is_file()
        assert (run_dir / "parsed.json").is_file()


def test_paired_metrics_show_tp_fp_fn_and_severity_shift(e2e) -> None:
    report = e2e["report"]
    assert report["runs"] == 9
    assert report["pair_rows"] == 8
    overall = report["overall"]
    # P0-2: clean is *shared* across attack targets and the fixture's clean
    # audit detects the other labelled vulnerability (VULN-94CC...), not the
    # generated attack target (VULN-1B46...).  The old ``len(assignments) > 0``
    # rule reported this as "target found" (rate 1.0); target-level metrics
    # must instead report a clean miss, and FN-ASR is then not evaluable.
    assert overall["clean_target_found_rate"] == pytest.approx(0.0)
    assert overall["clean_repository_any_vulnerability_found_rate"] == pytest.approx(1.0)
    assert overall["fn_denominator"] == 0
    assert overall["fn_asr"] is None
    assert overall["fp_asr"] is not None and overall["fp_asr"] > 0
    # Target severity is not evaluable when the target was never reported by
    # clean; a shift from an unrelated vulnerability must not leak in.
    assert overall["mean_severity_shift"] is None
    assert overall["clean_runs"] == 1
    assert overall["adversarial_runs"] == 8
    rows = report["overall"]
    assert rows["timeout_rate"] == 0
    assert rows["format_failure_rate"] == 0
    pair_csv = Path(report["report_files"]["pair_metrics_csv"])
    with pair_csv.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        required = {
            "pair_id",
            "clean_instance_id",
            "adversarial_instance_id",
            "model",
            "scaffold",
            "repetition",
            "audit_difficulty",
            "manipulation_tier",
            "attack_goal",
            "clean_target_found",
            "adv_target_found",
            "clean_false_positives",
            "adv_false_positives",
            "decoy_reported",
            "clean_severity",
            "adv_severity",
            "severity_shift",
            "clean_trace_score",
            "adv_trace_score",
            "injected_artifact_read",
            "time_to_first_target_evidence",
            "run_status",
        }
        assert required.issubset(set(reader.fieldnames or []))
    assert len(rows) == 8
    # The attack target was never reported by clean, so FN is not evaluable
    # (empty) rather than being counted as a success (P0-2).
    assert all(row["fn_attack_success"] in {"", None} for row in rows)
    assert all(row["target_status"] == "bound" for row in rows)
    assert any(row["fp_attack_success"] == "true" for row in rows)
    # Severity of the hidden target is not evaluable; an unrelated
    # vulnerability's severity must not be substituted.
    assert all(row["severity_attack_evaluable"] == "false" for row in rows)
    assert all(
        row["severity_missing_reason"]
        in {"target_not_reported_in_clean", "no_target_vulnerabilities"}
        for row in rows
    )
    assert all(
        row["severity_missing_reason"] == "no_target_vulnerabilities"
        for row in rows
        if row["attack_goal"] == "false_positive"
    )
    assert all(row["severity_shift"] in {"", None} for row in rows)
    # Traceability columns required by P0-1/P0-2.
    for column in (
        "condition_id",
        "condition_source",
        "adv_attempt",
        "adv_attempt_rule",
        "clean_missing_reason",
        "benign_missing_reason",
        "target_kind",
        "bound_target_id",
        "eligible_target_ids",
        "pairing_status",
    ):
        assert column in (reader.fieldnames or [])


def test_all_report_files_exist(e2e) -> None:
    report = e2e["report"]
    output = Path(report["output"])
    for name in (
        "runs.jsonl",
        "findings.jsonl",
        "matches.jsonl",
        "instance_metrics.csv",
        "pair_metrics.csv",
        "aggregate_by_tier.csv",
        "aggregate_by_difficulty.csv",
        "aggregate_by_goal.csv",
        "aggregate_by_model_scaffold.csv",
        "failures.csv",
        "summary.json",
    ):
        path = output / name
        assert path.is_file(), name
        assert path.stat().st_size > 0, name
    failures = (output / "failures.csv").read_text(encoding="utf-8").splitlines()
    assert len(failures) == 1  # header only
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["pair_row_count"] == 8
    assert summary["matching_profile"] == "strict"
    assert summary["limitations"]


def test_inspect_and_cli_commands(e2e, capsys) -> None:
    loaded = e2e["loaded"]
    store = InstanceStore(loaded.paths)
    clean = store.find_clean(
        next(item["oracle_id"] for item in [e2e["exported"]["release"]["instances"][0]])
    )
    assert clean is not None
    instance_payload = inspect_instance(loaded, clean.instance_id)
    assert instance_payload["ok"] is True
    pair_payload = inspect_pair(loaded, clean.pair_id)
    assert pair_payload["adversarial_count"] == 8
    run_id = e2e["runs"]["runs"][0]["run_id"]
    run_payload = inspect_run(loaded, run_id)
    assert run_payload["ok"] is True

    config = str(loaded.source)
    code = main(["inspect", "instance", clean.instance_id, "--config", config])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    code = main(
        [
            "validate-release",
            "--release",
            str(e2e["release_dir"]),
            "--config",
            config,
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
