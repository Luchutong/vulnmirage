from __future__ import annotations

import json
from pathlib import Path

from tests.fixture_repo import create_fixture_repo
from tests.support import make_test_config
from vulnmirage.cli import main


def _call(capsys, argv: list[str]) -> dict:
    code = main(argv)
    captured = capsys.readouterr()
    assert code == 0, captured.err
    return json.loads(captured.out)


def test_cli_end_to_end(tmp_path: Path, project_root: Path, capsys) -> None:
    fixture = create_fixture_repo(tmp_path / "fixture")
    loaded = make_test_config(
        tmp_path,
        project_root,
        goals=["false_negative"],
        tiers=["M0", "M1"],
        workspace_name="cli-workspace",
    )
    config = str(loaded.source)
    normalized = tmp_path / "cli-workspace" / "normalized"
    doctor = _call(capsys, ["doctor", "--config", config])
    assert doctor["ok"] is True

    ingested = _call(
        capsys,
        [
            "ingest",
            "vulngym",
            "--reports",
            str(fixture.reports_path),
            "--entries",
            str(fixture.entries_path),
            "--output",
            str(normalized),
        ],
    )
    assert ingested["imported"] == 1
    oracle_path = normalized / ingested["oracles"][0]["file"]

    materialized = _call(
        capsys,
        ["materialize", "--oracle", str(oracle_path), "--config", config],
    )
    assert materialized["created"] is True

    generated = _call(
        capsys,
        [
            "generate",
            "--oracle",
            str(oracle_path),
            "--config",
            config,
            "--tiers",
            "M0,M1",
            "--goals",
            "false_negative",
        ],
    )
    # P0-2: a multi-vulnerability oracle yields one single-target variant per
    # target instead of silently generating only the first target.
    targets = {item["target_id"] for item in generated["generated"]}
    assert len(generated["generated"]) == 2
    assert len(targets) == 2
    instance_id = generated["generated"][0]["instance_id"]

    validated = _call(
        capsys,
        ["validate", "--instance", instance_id, "--config", config],
    )
    assert validated["release_eligible"] is True

    release_dir = tmp_path / "cli-release"
    exported = _call(
        capsys,
        [
            "export",
            "--instances",
            str(loaded.paths.instances),
            "--output",
            str(release_dir),
            "--config",
            config,
        ],
    )
    assert exported["instance_count"] == 3

    runs = _call(
        capsys,
        [
            "run",
            "--release",
            str(release_dir),
            "--agent",
            str(project_root / "configs" / "dummy_agent.yaml"),
            "--config",
            config,
            "--repetitions",
            "1",
            "--workers",
            "1",
        ],
    )
    assert runs["run_count"] == 3

    report = _call(
        capsys,
        [
            "evaluate",
            "--release",
            str(release_dir),
            "--runs",
            str(loaded.paths.runs),
            "--output",
            str(tmp_path / "cli-reports"),
            "--config",
            config,
        ],
    )
    assert report["pair_rows"] == 2
    # P0-2: the clean baseline is shared by two attack targets and detects just
    # one of them.  Repository-level detection is 1.0, but the target-level
    # rate must be strictly between 0 and 1 rather than the old global "any
    # finding" value.
    assert (
        report["overall"]["clean_repository_any_vulnerability_found_rate"] == 1.0
    )
    assert 0.0 < report["overall"]["clean_target_found_rate"] < 1.0

    inspected = _call(
        capsys,
        ["inspect", "instance", instance_id, "--config", config],
    )
    assert inspected["ok"] is True

    run_id = runs["runs"][0]["run_id"]
    trajectory = _call(
        capsys,
        ["inspect", "trajectory", run_id, "--config", config],
    )
    assert trajectory["event_count"] > 0
    verification = _call(
        capsys,
        ["inspect", "verification", run_id, "--config", config],
    )
    assert verification["assessment_count"] >= 0
    validation = _call(
        capsys,
        ["validate-run", "--run", run_id, "--config", config],
    )
    assert validation["ok"] is True
