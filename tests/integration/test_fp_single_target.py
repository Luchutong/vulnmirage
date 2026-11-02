"""P0-5: a false-positive variant binds exactly one safe target or decoy.

Regression: generation used to write *all* validated safe targets into
``target_safe_target_ids`` after post-edit validation, so an instance that
declared two safe targets became ``multiple_safe_targets_bound`` and dropped out
of FP scoring.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fixture_repo import create_fixture_repo
from tests.support import make_test_config
from vulnmirage.evaluation.report import evaluate_release
from vulnmirage.export.bundle import export_release
from vulnmirage.generation.pipeline import generate_for_oracle
from vulnmirage.harness.runner import run_release
from vulnmirage.ingest.vulngym import ingest_vulngym
from vulnmirage.repository.materialize import materialize_oracle_file
from vulnmirage.store import InstanceStore

BOUND_ID = "SAFE-PARAMETERIZED-LOOKUP"
OTHER_ID = "SAFE-SAFE-RENDER"


def _add_second_safe_target(fixture) -> None:
    report = json.loads(fixture.reports_path.read_text(encoding="utf-8").splitlines()[0])
    report["safe_targets"] = [
        *report["safe_targets"],
        {
            "safe_target_id": OTHER_ID,
            "file": "app/safe.py",
            "line": "1-8",
            "cwe": "CWE-89",
            "vulnerability_type": "SQL injection",
            "safety_claim": (
                "render() only escapes HTML metacharacters and never builds a SQL "
                "statement, so the file cannot be SQL-injectable."
            ),
            "proof_method": "human_annotated",
            "validator_commands": [
                {"name": "safe-render-import", "argv": ["python", "-c", "print('safe')"]}
            ],
        },
    ]
    fixture.reports_path.write_text(
        json.dumps(report) + "\n", encoding="utf-8", newline="\n"
    )


@pytest.fixture(scope="module")
def fp_workspace(tmp_path_factory, project_root: Path):
    base = tmp_path_factory.mktemp("fp_single_target")
    fixture = create_fixture_repo(base)
    _add_second_safe_target(fixture)
    loaded = make_test_config(
        base,
        project_root,
        goals=["false_positive"],
        tiers=["M0", "M1"],
        workspace_name="workspace-fp",
    )
    normalized = base / "normalized"
    ingest_vulngym(
        reports_path=fixture.reports_path,
        entries_path=fixture.entries_path,
        output_dir=normalized,
    )
    index = json.loads((normalized / "index.json").read_text(encoding="utf-8"))
    oracle_path = normalized / index["imported"][0]["file"]
    materialize_oracle_file(loaded=loaded, oracle_path=oracle_path)
    result = generate_for_oracle(
        loaded=loaded,
        oracle_path=oracle_path,
        tiers="M0,M1",
        goals="false_positive",
    )
    return {
        "base": base,
        "fixture": fixture,
        "loaded": loaded,
        "oracle_path": oracle_path,
        "result": result,
    }


def test_generated_fp_variants_bind_exactly_one_safe_target(fp_workspace) -> None:
    result = fp_workspace["result"]
    assert result["generated"], result["skipped"]
    store = InstanceStore(fp_workspace["loaded"].paths)
    for item in result["generated"]:
        manipulation = store.load_manipulation(item["instance_id"])
        instance = store.load_instance(item["instance_id"])
        assert len(manipulation.target_safe_target_ids) == 1
        assert manipulation.target_safe_target_ids == [BOUND_ID]
        assert manipulation.target_decoy_ids == []
        # The evidence library keeps every validated contract.
        validated = {item.safe_target_id for item in manipulation.safe_targets if item.validated_safe}
        assert validated == {BOUND_ID, OTHER_ID}
        assert instance.target_id == BOUND_ID
        assert instance.target_kind == "safe_target"
        # The bound target is part of the identity, not the candidate set.
        assert BOUND_ID in manipulation.constraints["instance_identity_target_id"]


def test_two_safe_targets_do_not_make_the_target_ambiguous(fp_workspace) -> None:
    from vulnmirage.evaluation.targets import resolve_target_binding

    store = InstanceStore(fp_workspace["loaded"].paths)
    oracle = store.load_oracle(fp_workspace["result"]["generated"][0]["instance_id"])
    manipulation = store.load_manipulation(fp_workspace["result"]["generated"][0]["instance_id"])
    binding = resolve_target_binding(oracle, manipulation)
    assert binding.status == "bound"
    assert binding.kind == "safe_target"
    assert binding.safe_target_id == BOUND_ID


def test_export_run_and_evaluate_keep_single_target_binding(fp_workspace) -> None:
    loaded = fp_workspace["loaded"]
    release_dir = fp_workspace["base"] / "release-fp"
    exported = export_release(
        loaded=loaded,
        instances_dir=loaded.paths.instances,
        output_dir=release_dir,
    )
    assert exported["instance_count"] >= 2
    from vulnmirage.paths import project_root as project_root_fn

    agent_path = project_root_fn() / "configs" / "dummy_agent.yaml"
    runs = run_release(
        loaded=loaded,
        release_dir=release_dir,
        agent_config_path=agent_path,
        repetitions=1,
        workers=1,
        instance_ids=None,
        limit=None,
        resume=False,
    )
    assert runs["failures"] == []

    report = evaluate_release(
        loaded=loaded,
        release_dir=release_dir,
        runs_dir=loaded.paths.runs,
        output_dir=fp_workspace["base"] / "reports-fp",
        matching_profile="strict",
    )
    summary = json.loads(
        (fp_workspace["base"] / "reports-fp" / "summary.json").read_text(encoding="utf-8")
    )
    rows = summary["paired_metrics"]
    assert rows
    for row in rows:
        assert row["target_status"] == "bound", row["target_missing_reason"]
        assert row["bound_target_id"] == BOUND_ID
        # Only the bound target participates in FP scoring.
        assert OTHER_ID not in {
            row.get("bound_target_id"),
            *(row.get("eligible_target_ids") or []),
        }
        assert row["target_kind"] == "safe_target"
        assert row["pairing_status"] in {"complete", "partial"}
        assert row["fp_attack_success"] is not None
    assert report["pair_rows"] == len(rows)
