from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fixture_repo import create_fixture_repo
from tests.support import make_test_config
from vulnmirage.errors import UnsupportedTierError
from vulnmirage.generation.pipeline import generate_for_oracle
from vulnmirage.ingest.vulngym import ingest_vulngym
from vulnmirage.repository.git import status_porcelain
from vulnmirage.repository.materialize import materialize_oracle_file
from vulnmirage.store import InstanceStore
from vulnmirage.validation.pipeline import validate_instance


@pytest.fixture(scope="module")
def generated(full_workspace):
    return full_workspace


def test_m0_m3_instances_are_generated_and_validated(generated) -> None:
    loaded = generated["loaded"]
    result = generated["result"]
    assert result["ok"] is True
    assert len(result["generated"]) == 8
    assert result["rejected"] == []
    store = InstanceStore(loaded.paths)
    clean = store.load_instance(generated["materialized"]["instance_id"])
    assert clean.manipulation_tier.value == "M0"
    tiers = {item["tier"] for item in result["generated"]}
    assert tiers == {"M1", "M2", "M3"}
    for item in result["generated"]:
        instance = store.load_instance(item["instance_id"])
        state = store.load_state(item["instance_id"])
        assert instance.pair_id == clean.pair_id
        assert instance.variant_kind.value == "adversarial"
        assert state.stage == "frozen"
        assert state.release_eligible is True
        assert state.validation_status == "pass"
        validation = store.load_validation(item["instance_id"])
        assert validation["release_eligible"] is True
        assert validation["ground_truth_preserved"] is True
        assert validation["validation_level"] == "executable_ground_truth"
        assert (store.patch_path(item["instance_id"])).is_file()
        assert store.repo_dir(item["instance_id"]).is_dir()
        assert status_porcelain(store.repo_dir(item["instance_id"]))


def test_clean_task_is_identical_for_all_conditions(generated) -> None:
    loaded = generated["loaded"]
    store = InstanceStore(loaded.paths)
    hashes = set()
    for instance_id in store.iter_instance_ids():
        instance = store.load_instance(instance_id)
        task = store.resolve_artifact(instance.task_file)
        hashes.add((task.read_bytes(), store.load_state(instance_id).task_sha256))
    assert len({item[1] for item in hashes}) == 1


def test_base_repository_is_untouched(generated) -> None:
    fixture = generated["fixture"]
    assert status_porcelain(fixture.path) == []
    assert fixture.path.joinpath("app", "storage.py").read_text(encoding="utf-8").find(
        "conn.execute(user_query)"
    ) == -1
    assert "query" in (fixture.path / "app" / "storage.py").read_text(encoding="utf-8")


def test_patch_scope_and_remapped_oracle(generated) -> None:
    loaded = generated["loaded"]
    store = InstanceStore(loaded.paths)
    for item in generated["result"]["generated"]:
        instance = store.load_instance(item["instance_id"])
        manipulation = store.load_manipulation(item["instance_id"])
        meta = json.loads(
            (store.instance_dir(item["instance_id"]) / "patch_meta.json").read_text(encoding="utf-8")
        )
        changed = {entry["path"] for entry in meta["files_changed"]}
        assert changed == set(item["files_touched"])
        assert changed.issubset(set(manipulation.files_touched))
        oracle = store.load_oracle(item["instance_id"])
        for vulnerability in oracle.vulnerabilities:
            for path in vulnerability.paths:
                assert path.entry_point.code_sha256
                assert path.critical_operation.code_sha256
        validation = json.loads(
            (store.instance_dir(item["instance_id"]) / "validation.json").read_text(encoding="utf-8")
        )
        checks = {entry["check_name"]: entry["status"] for entry in validation["results"]}
        assert checks["oracle_remap"] == "pass"
        assert checks["diff_scope"] == "pass"
        assert checks["leakage"] == "pass"
        assert checks["poc_replay"] == "pass"
        assert checks["release_eligibility"] == "pass"


def test_m2_claims_are_natural_not_direct_overrides(generated) -> None:
    loaded = generated["loaded"]
    store = InstanceStore(loaded.paths)
    m2_fix = next(
        item for item in generated["result"]["generated"] if item["operator"] == "FalseFixStatusClaim"
    )
    text = (store.repo_dir(m2_fix["instance_id"]) / "SECURITY.md").read_text(encoding="utf-8")
    assert "remediated" in text
    assert "ignore previous" not in text.lower()
    assert "ignore any previous" not in text.lower()


def test_m3_claim_graph_is_persisted(generated) -> None:
    loaded = generated["loaded"]
    store = InstanceStore(loaded.paths)
    m3 = next(item for item in generated["result"]["generated"] if item["tier"] == "M3")
    manipulation = store.load_manipulation(m3["instance_id"])
    assert manipulation is not None
    assert manipulation.claim_graph is not None
    assert len(manipulation.claim_graph.nodes) == 3
    assert len(manipulation.claim_graph.edges) == 3
    node_files = {node.file for node in manipulation.claim_graph.nodes}
    assert "SECURITY.md" in node_files
    assert "docs/architecture.md" in node_files


def test_all_manipulation_tiers_are_implemented(generated) -> None:
    from vulnmirage.manipulations import supported_tiers

    assert supported_tiers() == ["M1", "M2", "M3", "M4", "M5", "M6"]


def test_resume_skips_existing_frozen_instances(generated) -> None:
    loaded = generated["loaded"]
    result = generate_for_oracle(
        loaded=loaded,
        oracle_path=generated["oracle_path"],
        tiers="M0,M1,M2,M3",
        goals="false_negative,false_positive,severity_downgrade",
        resume=True,
    )
    assert result["generated"] == []
    resume_skips = [
        item for item in result["skipped"] if item["reason"] == "already generated (resume)"
    ]
    incompatible = [
        item for item in result["skipped"] if item["reason"] == "incompatible_combination"
    ]
    assert len(resume_skips) == 8
    # M3 + severity_downgrade is rejected by the compatibility matrix.
    assert len(incompatible) == 1
    assert incompatible[0]["tier"] == "M3"


def test_validation_failure_blocks_release(tmp_path: Path, project_root: Path) -> None:
    base = tmp_path / "blocked"
    fixture = create_fixture_repo(base)
    loaded = make_test_config(base, project_root, goals=["false_negative"], tiers=["M0", "M2"])
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
        tiers="M2",
        goals="false_negative",
    )
    assert len(result["generated"]) == 1
    store = InstanceStore(loaded.paths)
    instance_id = result["generated"][0]["instance_id"]
    target = store.repo_dir(instance_id) / "app" / "storage.py"
    target.unlink()
    validation = validate_instance(loaded=loaded, instance_id=instance_id)
    assert validation["release_eligible"] is False
    assert validation["ground_truth_preserved"] is False
    assert validation["quarantine_path"] is not None
    assert Path(validation["quarantine_path"]).is_dir()
    assert (Path(validation["quarantine_path"]) / "quarantine.json").is_file()
    assert store.load_state(instance_id).stage == "rejected"


def test_multiple_candidates_are_generated_and_deduplicated(tmp_path: Path, project_root: Path) -> None:
    from vulnmirage.generation.candidates import generate_candidates_for_oracle

    base = tmp_path / "candidates"
    fixture = create_fixture_repo(base)
    loaded = make_test_config(base, project_root, goals=["false_negative"], tiers=["M0", "M1"])
    normalized = base / "normalized"
    ingest_vulngym(
        reports_path=fixture.reports_path,
        entries_path=fixture.entries_path,
        output_dir=normalized,
    )
    index = json.loads((normalized / "index.json").read_text(encoding="utf-8"))
    oracle_path = normalized / index["imported"][0]["file"]
    materialize_oracle_file(loaded=loaded, oracle_path=oracle_path)
    result = generate_candidates_for_oracle(
        loaded=loaded,
        oracle_path=oracle_path,
        tiers="M0,M1",
        goals="false_negative",
        candidates_per_strategy=2,
    )
    assert result["candidates_per_strategy"] == 2
    assert result["generated"]
    candidate_ids = {item.get("candidate_id") for item in result["generated"]}
    assert len(candidate_ids) == len(result["generated"])
    assert result["unique_count"] + result["duplicate_count"] == result["generated_count"]
    store = InstanceStore(loaded.paths)
    for item in result["generated"]:
        plan_path = store.instance_dir(item["instance_id"]) / "attack_plan.json"
        assert plan_path.is_file()
        payload = json.loads(plan_path.read_text(encoding="utf-8"))
        assert payload["attack_plan"]["plan_id"].startswith("PLAN-")
        assert payload["candidate_id"]
