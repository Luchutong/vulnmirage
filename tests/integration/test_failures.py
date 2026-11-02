from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

from tests.support import make_test_config
from vulnmirage.evaluation.report import evaluate_release
from vulnmirage.harness.runner import run_release

HOSTILE = Path(__file__).resolve().parents[1] / "fixtures" / "hostile_agent.py"


def _adversarial_instance(release_dir: Path) -> str:
    manifest = json.loads((release_dir / "release.json").read_text(encoding="utf-8"))
    return next(
        item["instance_id"] for item in manifest["instances"] if item["variant_kind"] == "adversarial"
    )


def _agent_config(path: Path, mode: str, timeout: int = 30) -> Path:
    payload = {
        "schema_version": "1.0",
        "adapter": "subprocess",
        "argv": [
            sys.executable,
            str(HOSTILE),
            "--mode",
            mode,
            "--repo",
            "{repo}",
            "--output",
            "{output}",
        ],
        "timeout_seconds": timeout,
        "workers": 1,
        "model_provider": "hostile",
        "model_name": mode,
        "scaffold": "hostile-test",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _run_mode(tmp_path: Path, release_bundle, project_root: Path, mode: str, timeout: int = 30):
    loaded = make_test_config(
        tmp_path,
        project_root,
        goals=["false_negative"],
        tiers=["M2"],
        include_build_test=False,
        workspace_name=f"ws-{mode}",
    )
    agent = _agent_config(tmp_path / f"agent-{mode}.json", mode, timeout)
    result = run_release(
        loaded=loaded,
        release_dir=release_bundle["release_dir"],
        agent_config_path=agent,
        repetitions=1,
        workers=1,
        instance_ids=[_adversarial_instance(release_bundle["release_dir"])],
        limit=None,
        resume=False,
    )
    report = evaluate_release(
        loaded=loaded,
        release_dir=release_bundle["release_dir"],
        runs_dir=loaded.paths.runs,
        output_dir=tmp_path / f"report-{mode}",
        matching_profile="strict",
    )
    return loaded, result, report


def test_format_failure_is_separate_from_false_negative(tmp_path: Path, release_bundle, project_root: Path) -> None:
    loaded, result, report = _run_mode(tmp_path, release_bundle, project_root, "format")
    assert result["run_count"] == 2
    statuses = {item["status"] for item in result["runs"]}
    assert statuses == {"format_failure"}
    metas = [
        json.loads((loaded.paths.run_dir(item["run_id"]) / "run_meta.json").read_text(encoding="utf-8"))
        for item in result["runs"]
    ]
    assert {item["parse_status"] for item in metas} == {"format_failure"}
    assert report["overall"]["fn_asr"] is None
    assert report["overall"]["format_failure_rate"] == 1.0
    failures = list(csv.DictReader((Path(report["output"]) / "failures.csv").open(encoding="utf-8")))
    assert {row["failure_type"] for row in failures} == {"format_failure"}
    assert len(failures) == 2


def test_timeout_is_separate_from_false_negative(tmp_path: Path, release_bundle, project_root: Path) -> None:
    loaded, result, report = _run_mode(tmp_path, release_bundle, project_root, "timeout", timeout=1)
    assert result["run_count"] == 2
    statuses = {item["status"] for item in result["runs"]}
    assert statuses == {"timeout"}
    assert report["overall"]["fn_asr"] is None
    assert report["overall"]["timeout_rate"] == 1.0
    assert report["overall"]["format_failure_rate"] == 0
    failures = list(csv.DictReader((Path(report["output"]) / "failures.csv").open(encoding="utf-8")))
    assert {row["failure_type"] for row in failures} == {"timeout"}
    assert len(failures) == 2


def test_repository_contamination_is_reported(tmp_path: Path, release_bundle, project_root: Path) -> None:
    loaded, result, report = _run_mode(tmp_path, release_bundle, project_root, "contaminate")
    assert result["run_count"] == 2
    statuses = {item["status"] for item in result["runs"]}
    assert statuses == {"contaminated"}
    assert report["overall"]["fn_asr"] is None
    assert report["overall"]["contamination_rate"] == 1.0
    failures = list(csv.DictReader((Path(report["output"]) / "failures.csv").open(encoding="utf-8")))
    assert {row["failure_type"] for row in failures} == {"contamination"}
    assert any("evil.txt" in (row["detail"] or "") for row in failures)
    rows = list(
        csv.DictReader((Path(report["output"]) / "pair_metrics.csv").open(encoding="utf-8"))
    )
    assert rows[0]["adv_contaminated"] == "true"
    assert rows[0]["fn_attack_success"] == ""
