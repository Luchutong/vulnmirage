#!/usr/bin/env python3
"""Run the complete VulnMirage demo on a local offline fixture.

Usage:
    python examples/minimal/run_demo.py --workspace workspace/demo
    python examples/minimal/run_demo.py --workspace workspace/demo --all-tiers

This is a controlled example, not a production benchmark run.  It builds a
fixture repository, ingests a VulnGym-shaped advisory, materializes the pinned
commit, generates and validates M0–M3 (or M0–M6), exports a release, runs the
scripted dummy auditor, and writes paired reports.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.fixture_repo import create_fixture_repo  # noqa: E402
from tests.support import make_test_config  # noqa: E402
from vulnmirage.evaluation.report import evaluate_release  # noqa: E402
from vulnmirage.export.bundle import export_release, validate_release  # noqa: E402
from vulnmirage.generation.pipeline import generate_for_oracle  # noqa: E402
from vulnmirage.harness.runner import run_release  # noqa: E402
from vulnmirage.ingest.vulngym import ingest_vulngym  # noqa: E402
from vulnmirage.repository.materialize import materialize_oracle_file  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", default="workspace/demo")
    parser.add_argument("--tiers", default="M0,M1,M2,M3")
    parser.add_argument("--goals", default="false_negative,false_positive,severity_downgrade")
    parser.add_argument("--all-tiers", action="store_true")
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    base = Path(args.workspace).resolve()
    if base.exists() and any(base.iterdir()):
        print(f"workspace is not empty: {base}", file=sys.stderr)
        return 1
    base.mkdir(parents=True, exist_ok=True)
    tiers = "M0,M1,M2,M3,M4,M5,M6" if args.all_tiers else args.tiers
    goals = [item.strip() for item in args.goals.split(",") if item.strip()]

    fixture = create_fixture_repo(base / "fixture")
    loaded = make_test_config(
        base,
        PROJECT_ROOT,
        goals=goals,
        tiers=tiers.split(","),
        include_build_test=True,
        workspace_name="workspace",
    )
    normalized = loaded.paths.normalized
    ingest = ingest_vulngym(
        reports_path=fixture.reports_path,
        entries_path=fixture.entries_path,
        output_dir=normalized,
    )
    oracle_path = normalized / ingest["oracles"][0]["file"]
    materialized = materialize_oracle_file(loaded=loaded, oracle_path=oracle_path)
    generated = generate_for_oracle(
        loaded=loaded,
        oracle_path=oracle_path,
        tiers=tiers,
        goals=args.goals,
    )
    release_dir = loaded.paths.releases / "v0.1"
    exported = export_release(
        loaded=loaded,
        instances_dir=loaded.paths.instances,
        output_dir=release_dir,
    )
    release_validation = validate_release(loaded=loaded, release_dir=release_dir)
    runs = run_release(
        loaded=loaded,
        release_dir=release_dir,
        agent_config_path=PROJECT_ROOT / "configs" / "dummy_agent.yaml",
        repetitions=args.repetitions,
        workers=args.workers,
        instance_ids=None,
        limit=None,
        resume=False,
    )
    report = evaluate_release(
        loaded=loaded,
        release_dir=release_dir,
        runs_dir=loaded.paths.runs,
        output_dir=loaded.paths.reports,
        matching_profile="strict",
    )
    print(
        json.dumps(
            {
                "ok": True,
                "workspace": str(base),
                "oracle": str(oracle_path),
                "clean_instance": materialized["instance_id"],
                "generated": len(generated["generated"]),
                "rejected": len(generated["rejected"]),
                "release": str(release_dir),
                "release_validation": release_validation["ok"],
                "runs": runs["run_count"],
                "reports": report["output"],
                "overall": report["overall"],
            },
            indent=2,
            default=str,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
