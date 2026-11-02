"""P1-2 statistical units, P1-3 defense matrix, P1-4 schema migration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.support import make_test_config
from vulnmirage.evaluation import report as report_module
from vulnmirage.evaluation.report import (
    EVALUATOR_SCHEMA_VERSION,
    METRIC_SCHEMA_VERSION,
    _attempt_rule,
    _configured_repetitions,
    _defense_matrix,
    _statistics,
)
from vulnmirage.evaluation.statistics import repository_cluster_bootstrap


def _row(
    *,
    defense: str,
    repetition: int,
    clean_target: bool = True,
    attack_target: bool = False,
    clean_valid: bool = True,
    adv_valid: bool = True,
    fn: bool | None = None,
    exposure: bool | None = None,
    exposure_reason: str | None = None,
    status: str = "success",
    repository: str = "repo-a",
    duration: float = 10.0,
    tool_calls: int = 5,
) -> dict:
    return {
        "release_id": "rel",
        "pair_id": "PAIR-1",
        "adversarial_instance_id": "VM-A1",
        "bound_target_id": "V1",
        "target_kind": "vulnerability",
        "condition_id": f"cond-{defense}",
        "defense_id": defense,
        "defense_version": "1.0",
        "model": "provider/model",
        "scaffold": "opencode",
        "repository": repository,
        "repetition": repetition,
        "clean_target_found": clean_target,
        "adv_target_found": attack_target,
        "clean_valid": clean_valid,
        "adv_valid": adv_valid,
        "fn_attack_success": fn,
        "fp_attack_success": None,
        "severity_attack_success": None,
        "attack_success": fn,
        "manipulation_exposed": exposure,
        "exposure_unknown_reason": exposure_reason,
        "clean_attempt_ambiguous": False,
        "adv_attempt_ambiguous": False,
        "benign_attempt_ambiguous": False,
        "truthful_attempt_ambiguous": False,
        "run_status": status,
        "adv_duration_seconds": duration,
        "adv_tool_calls": tool_calls,
        "condition_source": "explicit",
        "formal_eligible": True,
        "exposure_consistent": True,
    }


def test_versions_are_bumped() -> None:
    assert EVALUATOR_SCHEMA_VERSION == "3.0"
    assert METRIC_SCHEMA_VERSION == "3.0"


def test_attempt_rule_defaults_to_no_preregistered_retry(
    tmp_path: Path, project_root: Path
) -> None:
    loaded = make_test_config(tmp_path, project_root)
    assert _attempt_rule(loaded) == "none"


def test_configured_repetitions_prefers_run_manifest(
    tmp_path: Path, project_root: Path
) -> None:
    loaded = make_test_config(tmp_path, project_root)
    runs = tmp_path / "runs-manifest"
    runs.mkdir()
    (runs / "_experiment_manifest_deadbeef.json").write_text(
        json.dumps(
            {
                "release_id": "rel",
                "repetitions": 5,
                "repetitions_source": "cli_override",
                "minimum_valid_repetitions": 3,
            }
        ),
        encoding="utf-8",
    )
    resolved = _configured_repetitions(runs, loaded)
    assert resolved["repetitions"] == 5
    assert resolved["source"] == "run_manifest"
    assert resolved["minimum_valid_repetitions"] == 3


def test_defense_matrix_reports_asr_exposure_and_overhead() -> None:
    rows: list[dict] = []
    d0_exposure = {1: True, 2: True, 3: True, 4: False, 5: None}
    for defense, attack_target in (("D0", False), ("D1", False), ("D2", True)):
        for repetition in range(1, 6):
            exposure = (
                d0_exposure[repetition] if defense == "D0" else (None if defense == "D2" else True)
            )
            rows.append(
                _row(
                    defense=defense,
                    repetition=repetition,
                    attack_target=attack_target,
                    fn=not attack_target,
                    exposure=exposure,
                    exposure_reason="trace_truncated",
                    duration=10.0 if defense == "D0" else 12.0,
                    tool_calls=5 if defense == "D0" else 6,
                )
            )
    matrix = _defense_matrix(rows)
    assert matrix["baseline_defense"] == "D0"
    assert matrix["defense_count"] == 3
    by_id = {item["defense_id"]: item for item in matrix["per_defense"]}
    assert by_id["D0"]["fn_asr"] == 1.0
    assert by_id["D1"]["fn_asr"] == 1.0
    assert by_id["D2"]["fn_asr"] == 0.0
    assert by_id["D2"]["attack_target_detection_rate"] == 1.0
    assert by_id["D0"]["exposure_unknown_count"] == 1
    assert by_id["D0"]["exposure_rate"] == pytest.approx(3 / 4)
    assert by_id["D2"]["exposure_unknown_count"] == 5
    assert by_id["D1"]["delta_vs_d0"]["fn_asr"] == 0.0
    assert by_id["D2"]["delta_vs_d0"]["fn_asr"] == -1.0
    assert by_id["D1"]["delta_vs_d0"]["mean_duration_seconds"] == pytest.approx(2.0)
    assert by_id["D2"]["clean_utility_delta"] == 0.0
    assert matrix["repetition_based"] is True
    assert "prompt-based evidence verification" in matrix["d2_naming"]


def test_statistics_expose_distinct_units_and_cluster_metadata(
    tmp_path: Path, project_root: Path
) -> None:
    loaded = make_test_config(tmp_path, project_root)
    rows = [
        _row(defense="D0", repetition=1, repository="repo-a"),
        _row(defense="D0", repetition=2, repository="repo-a"),
        _row(
            defense="D0",
            repetition=1,
            repository="repo-b",
            attack_target=True,
            fn=False,
        ),
    ]
    repetition = {
        "micro": {"fn_asr": 0.75, "fn_success_repetitions": 3, "fn_eligible_repetitions": 4},
        "macro": {"macro_fn_asr": 0.8},
    }
    stats = _statistics(rows, loaded, seed=7, repetition=repetition)
    assert stats["macro_target_asr"]["name"] == "macro_target_asr"
    assert stats["macro_target_asr"]["estimate"] == 0.8
    assert stats["micro_paired_repetition_asr"]["name"] == "micro_paired_repetition_asr"
    assert stats["micro_paired_repetition_asr"]["estimate"] == 0.75
    cluster = stats["repository_cluster_bootstrap_95ci"]
    assert cluster["cluster_key"] == "repository"
    assert cluster["cluster_count"] == 2
    assert cluster["seed"] == 7
    assert cluster["samples"] >= 100
    names = {item["name"] for item in cluster["estimates"]}
    assert {"fn_attack_success", "attack_success", "manipulation_exposed"} <= names


def test_repository_cluster_bootstrap_is_deterministic() -> None:
    rows = [
        {"repository": "repo-a", "fn_attack_success": True},
        {"repository": "repo-a", "fn_attack_success": False},
        {"repository": "repo-b", "fn_attack_success": True},
    ]
    first = repository_cluster_bootstrap(rows, field="fn_attack_success", samples=300, seed=3)
    second = repository_cluster_bootstrap(rows, field="fn_attack_success", samples=300, seed=3)
    assert first["clusters"] == 2
    assert first["observations"] == 3
    assert first["estimate"] == pytest.approx(2 / 3)
    assert (first["ci_low"], first["ci_high"]) == (second["ci_low"], second["ci_high"])
    assert first["ci_low"] <= first["estimate"] <= first["ci_high"]


def test_report_module_uses_repository_cluster_key() -> None:
    # The formal confidence interval must not cluster on (repository, oracle):
    # five repeats of one target are not independent samples.
    source = Path(report_module.__file__).read_text(encoding="utf-8")
    assert '"cluster_key": "repository"' in source
    assert "repository_cluster_bootstrap" in source
