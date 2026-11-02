from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fixture_repo import create_fixture_repo
from tests.support import make_test_config
from vulnmirage.export.bundle import export_release, validate_release
from vulnmirage.generation.pipeline import generate_for_oracle
from vulnmirage.ingest.vulngym import ingest_vulngym
from vulnmirage.repository.materialize import materialize_oracle_file

GOALS = ["false_negative", "false_positive", "severity_downgrade"]


@pytest.fixture(scope="session")
def full_workspace(tmp_path_factory, project_root: Path):
    base = tmp_path_factory.mktemp("full_workspace")
    fixture = create_fixture_repo(base)
    loaded = make_test_config(base, project_root, goals=GOALS)
    normalized = base / "normalized"
    ingest_vulngym(
        reports_path=fixture.reports_path,
        entries_path=fixture.entries_path,
        output_dir=normalized,
    )
    index = json.loads((normalized / "index.json").read_text(encoding="utf-8"))
    oracle_path = normalized / index["imported"][0]["file"]
    materialized = materialize_oracle_file(loaded=loaded, oracle_path=oracle_path)
    result = generate_for_oracle(
        loaded=loaded,
        oracle_path=oracle_path,
        tiers="M0,M1,M2,M3",
        goals=",".join(GOALS),
    )
    return {
        "base": base,
        "fixture": fixture,
        "loaded": loaded,
        "normalized": normalized,
        "oracle_path": oracle_path,
        "materialized": materialized,
        "result": result,
    }


@pytest.fixture(scope="session")
def release_bundle(full_workspace):
    loaded = full_workspace["loaded"]
    release_dir = full_workspace["base"] / "release"
    exported = export_release(
        loaded=loaded,
        instances_dir=loaded.paths.instances,
        output_dir=release_dir,
    )
    validated = validate_release(loaded=loaded, release_dir=release_dir)
    return {
        "release_dir": release_dir,
        "exported": exported,
        "validated": validated,
        "loaded": loaded,
    }


@pytest.fixture(scope="session")
def phase45_workspace(tmp_path_factory, project_root: Path):
    base = tmp_path_factory.mktemp("phase45_workspace")
    fixture = create_fixture_repo(base)
    loaded = make_test_config(
        base,
        project_root,
        goals=GOALS,
        tiers=["M4", "M5", "M6"],
        workspace_name="workspace45",
    )
    normalized = base / "normalized"
    ingest_vulngym(
        reports_path=fixture.reports_path,
        entries_path=fixture.entries_path,
        output_dir=normalized,
    )
    index = json.loads((normalized / "index.json").read_text(encoding="utf-8"))
    oracle_path = normalized / index["imported"][0]["file"]
    materialized = materialize_oracle_file(loaded=loaded, oracle_path=oracle_path)
    result = generate_for_oracle(
        loaded=loaded,
        oracle_path=oracle_path,
        tiers="M4,M5,M6",
        goals=",".join(GOALS),
    )
    return {
        "base": base,
        "fixture": fixture,
        "loaded": loaded,
        "normalized": normalized,
        "oracle_path": oracle_path,
        "materialized": materialized,
        "result": result,
    }
