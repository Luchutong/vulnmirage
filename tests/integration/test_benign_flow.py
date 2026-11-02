"""End-to-end benign structural controls."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from tests.fixture_repo import create_fixture_repo
from tests.support import make_test_config
from vulnmirage.evaluation.report import evaluate_release
from vulnmirage.export.bundle import export_release
from vulnmirage.generation.pipeline import generate_for_oracle
from vulnmirage.harness.runner import run_release
from vulnmirage.ingest.vulngym import ingest_vulngym
from vulnmirage.repository.materialize import materialize_oracle_file
from vulnmirage.store import InstanceStore


def test_benign_control_is_generated_paired_and_reported(
    tmp_path: Path, project_root: Path
) -> None:
    fixture = create_fixture_repo(tmp_path / "fixture")
    loaded = make_test_config(
        tmp_path,
        project_root,
        goals=["false_negative"],
        tiers=["M0", "M1"],
        workspace_name="ws-benign-flow",
    )
    # Enable structural controls explicitly (test baseline configs opt out).
    config_payload = json.loads(loaded.source.read_text(encoding="utf-8"))
    config_payload["generation"]["benign_controls"] = True
    loaded.source.write_text(json.dumps(config_payload), encoding="utf-8")
    from vulnmirage.config import load_config

    loaded = load_config(loaded.source)

    normalized = tmp_path / "normalized"
    ingest_vulngym(
        reports_path=fixture.reports_path,
        entries_path=fixture.entries_path,
        output_dir=normalized,
    )
    index = json.loads((normalized / "index.json").read_text(encoding="utf-8"))
    oracle_path = normalized / index["imported"][0]["file"]
    materialize_oracle_file(loaded=loaded, oracle_path=oracle_path)
    result = generate_for_oracle(
        loaded=loaded, oracle_path=oracle_path, tiers="M0,M1", goals="false_negative"
    )
    assert result["generated"]
    assert result["benign_generated"], result
    benign = result["benign_generated"][0]
    assert benign["release_eligible"] is True
    assert benign["group_id"]
    store = InstanceStore(loaded.paths)
    groups = store.load_groups()
    assert groups.groups
    group = groups.groups[0]
    assert group.benign_instance_id == benign["instance_id"]
    assert group.clean_instance_id
    assert group.adversarial_instance_id

    release = tmp_path / "release"
    exported = export_release(
        loaded=loaded, instances_dir=loaded.paths.instances, output_dir=release
    )
    assert exported["instance_count"] >= 3  # clean + attack + benign
    runs = run_release(
        loaded=loaded,
        release_dir=release,
        agent_config_path=project_root / "configs" / "dummy_agent.yaml",
        repetitions=1,
        workers=1,
        instance_ids=None,
        limit=None,
        resume=False,
    )
    assert runs["run_count"] >= 3
    report = evaluate_release(
        loaded=loaded,
        release_dir=release,
        runs_dir=loaded.paths.runs,
        output_dir=tmp_path / "reports",
    )
    rows = list(
        csv.DictReader((Path(report["output"]) / "pair_metrics.csv").open(encoding="utf-8"))
    )
    assert rows
    row = rows[0]
    assert row["benign_instance_id"]
    assert row["benign_valid"] == "true"
    assert row["clean_to_benign_target_delta"] != ""
    # The benign control (like clean) detects a different labelled
    # vulnerability than the single generated attack target, so target-level
    # detection is false while repository-level detection is true.  The legacy
    # "any vulnerability" rule incorrectly reported 1.0 here (P0-2).
    assert row["benign_repository_any_vulnerability_found"] == "true"
    assert report["overall"]["benign_target_found_rate"] == 0.0
