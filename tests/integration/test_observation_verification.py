"""Deterministic dummy-agent behaviours and run-artifact integrity."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests.support import make_test_config
from vulnmirage.evaluation.report import evaluate_release
from vulnmirage.export.bundle import load_release
from vulnmirage.harness.runner import run_release
from vulnmirage.inspect import inspect_trajectory, validate_run_artifacts_command


def _documented_adversarial(release_dir: Path) -> str:
    """Pick a documented *false-negative* adversarial instance.

    Verification-depth semantics are defined for claims that suppress a real
    vulnerability; false-positive instances are resolved against a validated
    safe target instead.  Picking the first adversarial in the manifest would
    make this test depend on hash ordering.
    """
    manifest, root = load_release(release_dir)
    fallback: str | None = None
    for entry in manifest.instances:
        if entry.variant_kind.value != "adversarial" or not entry.evidence_contract_file:
            continue
        contract = json.loads((root / entry.evidence_contract_file).read_text(encoding="utf-8"))
        documented = any(
            location["file"].endswith((".md", ".rst", ".txt"))
            for claim in contract.get("claims", [])
            for location in claim.get("presented_locations", [])
        )
        if not documented:
            continue
        goal = None
        if entry.manipulation_file:
            manipulation = json.loads(
                (root / entry.manipulation_file).read_text(encoding="utf-8")
            )
            goal = manipulation.get("attack_goal")
        if goal == "false_negative":
            return entry.instance_id
        fallback = fallback or entry.instance_id
    if fallback:
        return fallback
    raise AssertionError("release has no documented adversarial claim")


def _agent_config(path: Path, project_root: Path, policy: str) -> Path:
    payload = {
        "schema_version": "1.0",
        "adapter": "subprocess",
        "argv": [
            "python",
            str(project_root / "examples" / "dummy_agent.py"),
            "--repo",
            "{repo}",
            "--task",
            "{task}",
            "--output",
            "{output}",
            "--trace",
            "{trace}",
            "--run-id",
            "{run_id}",
            "--policy",
            policy,
        ],
        "timeout_seconds": 120,
        "workers": 1,
        "network_enabled": False,
        "scaffold": f"dummy-{policy}",
        "model_provider": "dummy",
        "model_name": "dummy-auditor",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("policy", "depth"),
    [("no_verify", 1), ("non_decisive", 2), ("decisive", 4)],
)
def test_dummy_verification_depth(
    tmp_path: Path, release_bundle, project_root: Path, policy: str, depth: int
) -> None:
    loaded = make_test_config(
        tmp_path / policy,
        project_root,
        workspace_name="workspace",
    )
    agent = _agent_config(tmp_path / f"agent-{policy}.json", project_root, policy)
    result = run_release(
        loaded=loaded,
        release_dir=release_bundle["release_dir"],
        agent_config_path=agent,
        repetitions=1,
        workers=1,
        instance_ids=[_documented_adversarial(release_bundle["release_dir"])],
        limit=None,
        resume=False,
    )
    assert result["run_count"] == 2
    assessments = []
    for item in result["runs"]:
        path = loaded.paths.run_dir(item["run_id"]) / "verification_assessments.json"
        if path.is_file():
            assessments.extend(json.loads(path.read_text(encoding="utf-8")))
    adversarial = [item for item in assessments if item["depth_score"] == depth]
    assert adversarial, assessments
    assert max(item["depth_score"] for item in assessments) == depth
    if policy == "decisive":
        assert any(item["resolution"] == "correct" for item in assessments)
        assert any(item["state"] == "resolved" for item in assessments)
    if policy == "no_verify":
        assert all(item["depth_score"] <= 1 for item in assessments)
        assert any(item["state"] == "exposed" for item in assessments)


def test_unvisited_citation_increases_uer(tmp_path: Path, release_bundle, project_root: Path) -> None:
    loaded = make_test_config(
        tmp_path / "unvisited",
        project_root,
        workspace_name="workspace",
    )
    agent = _agent_config(
        tmp_path / "agent-unvisited.json", project_root, "unvisited_citation"
    )
    result = run_release(
        loaded=loaded,
        release_dir=release_bundle["release_dir"],
        agent_config_path=agent,
        repetitions=1,
        workers=1,
        instance_ids=[_documented_adversarial(release_bundle["release_dir"])],
        limit=None,
        resume=False,
    )
    report = evaluate_release(
        loaded=loaded,
        release_dir=release_bundle["release_dir"],
        runs_dir=loaded.paths.runs,
        output_dir=tmp_path / "report",
    )
    assert report["ok"] is True
    rows = list(
        __import__("csv").DictReader(
            (Path(report["output"]) / "evidence_metrics.csv").open(encoding="utf-8")
        )
    )
    assert any(float(row["unsupported_evidence_rate"] or 0) > 0 for row in rows)


def test_run_artifacts_validate_and_are_frozen(tmp_path: Path, release_bundle, project_root: Path) -> None:
    loaded = make_test_config(
        tmp_path / "validate",
        project_root,
        workspace_name="workspace",
    )
    agent = _agent_config(tmp_path / "agent.json", project_root, "decisive")
    result = run_release(
        loaded=loaded,
        release_dir=release_bundle["release_dir"],
        agent_config_path=agent,
        repetitions=1,
        workers=1,
        instance_ids=[_documented_adversarial(release_bundle["release_dir"])],
        limit=None,
        resume=False,
    )
    assert result["run_count"] == 2
    for item in result["runs"]:
        run_dir = loaded.paths.run_dir(item["run_id"])
        raw_path = run_dir / "events.raw.jsonl"
        assert raw_path.is_file()
        assert (raw_path.stat().st_mode & 0o222) == 0
        validation = validate_run_artifacts_command(loaded, item["run_id"])
        assert validation["ok"] is True, validation
        trajectory = inspect_trajectory(loaded, item["run_id"])
        assert trajectory["event_count"] > 0
        assert "reporting" in trajectory["stages"]
