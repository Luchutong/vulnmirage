from __future__ import annotations

import json
from pathlib import Path

from tests.fixture_repo import create_fixture_repo
from vulnmirage.ingest.vulngym import ingest_vulngym
from vulnmirage.repository.cache import RepositoryCache
from vulnmirage.repository.git import status_porcelain
from vulnmirage.repository.materialize import load_materialized_oracle, materialize_oracle_file
from vulnmirage.store import InstanceStore
from vulnmirage.validation.leakage import scan_instance_visible


def _ingest_fixture(fixture, tmp_path: Path) -> Path:
    output = tmp_path / "normalized"
    ingest_vulngym(
        reports_path=fixture.reports_path,
        entries_path=fixture.entries_path,
        output_dir=output,
    )
    index = json.loads((output / "index.json").read_text(encoding="utf-8"))
    fixture_entry = next(item for item in index["imported"] if item["report_id"] == "R-FIXTURE-1")
    return output / fixture_entry["file"]


def test_materialize_m0_clean(tmp_path: Path, workspace_config) -> None:
    fixture = create_fixture_repo(tmp_path / "fixture")
    oracle_path = _ingest_fixture(fixture, tmp_path)
    result = materialize_oracle_file(
        loaded=workspace_config,
        oracle_path=oracle_path,
    )
    assert result["created"] is True
    instance_id = result["instance_id"]
    store = InstanceStore(workspace_config.paths)
    instance = store.load_instance(instance_id)
    state = store.load_state(instance_id)
    oracle = store.load_oracle(instance_id)

    assert instance.variant_kind.value == "clean"
    assert instance.manipulation_tier.value == "M0"
    assert instance.patch_file is None
    assert state.stage == "oracle_aligned"
    assert state.task_sha256 == result["task_sha256"]
    assert instance.repository.source_tree_sha256
    assert len(instance.repository.source_tree_sha256) == 64
    assert oracle.repository.source_tree_sha256 == instance.repository.source_tree_sha256
    assert len(oracle.vulnerabilities) == 2
    for vulnerability in oracle.vulnerabilities:
        for path in vulnerability.paths:
            assert path.entry_point.code
            assert path.critical_operation.code
            assert path.critical_operation.code_sha256

    worktree = store.repo_dir(instance_id)
    assert (worktree / "app" / "storage.py").is_file()
    assert status_porcelain(worktree) == []
    assert (store.instance_dir(instance_id) / "task.md").is_file()
    assert not (worktree / "oracle.json").exists()
    assert not (worktree / "instance.json").exists()

    task_text = (store.instance_dir(instance_id) / "task.md").read_text(encoding="utf-8")
    leakage = scan_instance_visible(
        worktree,
        task_text,
        oracle=oracle,
        scan_advisory_patterns=True,
    )
    assert leakage["passed"] is True, leakage

    cache = RepositoryCache(workspace_config.paths.cache, workspace_config.config.network)
    cache_path = Path(result["cache_path"])
    assert state.cache_refs_sha256 == cache.refs_snapshot(cache_path)

    # Idempotent materialization: identical instance manifest and task.
    manifest_hash = store.instance_sha256(instance_id)
    second = materialize_oracle_file(loaded=workspace_config, oracle_path=oracle_path)
    assert second["created"] is False
    assert second["instance_id"] == instance_id
    assert store.instance_sha256(instance_id) == manifest_hash
    assert second["task_sha256"] == result["task_sha256"]

    aligned, clean, pointer = load_materialized_oracle(workspace_config, oracle_path)
    assert clean.instance_id == instance_id
    assert aligned.oracle_id == oracle.oracle_id
    assert pointer["clean_instance_id"] == instance_id


def test_materialize_force_creates_new_version(tmp_path: Path, workspace_config) -> None:
    fixture = create_fixture_repo(tmp_path / "fixture")
    oracle_path = _ingest_fixture(fixture, tmp_path)
    first = materialize_oracle_file(loaded=workspace_config, oracle_path=oracle_path)
    second = materialize_oracle_file(
        loaded=workspace_config,
        oracle_path=oracle_path,
        force=True,
    )
    assert second["instance_id"] != first["instance_id"]
    assert second["pair_id"] != first["pair_id"]
    assert second["created"] is True
    assert second["task_sha256"] == first["task_sha256"]
    store = InstanceStore(workspace_config.paths)
    assert store.load_state(second["instance_id"]).generation_round == 2
    assert (store.instance_dir(first["instance_id"]) / "instance.json").is_file()


def test_materialize_task_is_condition_independent(tmp_path: Path, workspace_config) -> None:
    fixture = create_fixture_repo(tmp_path / "fixture")
    oracle_path = _ingest_fixture(fixture, tmp_path)
    result = materialize_oracle_file(loaded=workspace_config, oracle_path=oracle_path)
    store = InstanceStore(workspace_config.paths)
    task_text = (store.instance_dir(result["instance_id"]) / "task.md").read_text(encoding="utf-8")
    assert "CVE-" not in task_text
    assert "GHSA-" not in task_text
    assert "oracle" not in task_text.lower()
    assert "reports.jsonl" not in task_text
    assert "repository is in your current working directory" in task_text.lower()
