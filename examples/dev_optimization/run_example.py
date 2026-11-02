#!/usr/bin/env python3
"""Offline two-round development optimisation example.

The rewriter here is a **scripted, offline** rewriter: it regenerates child
candidates through the normal template pipeline with a new candidate index and
seed, then exports the updated development release.  It is not an LLM rewrite
and the example reports ``template_regeneration`` lineage honestly.

A real run uses the built-in rewriter by setting ``generation.backend: llm`` and
``generation.rewrite_enabled: true``; that path requires user-provided
credentials and is not claimed as executed here.

Usage:
    python examples/dev_optimization/run_example.py --workspace workspace/dev-optimization
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
from vulnmirage.export.bundle import export_release, load_release  # noqa: E402
from vulnmirage.generation.feedback import optimize_payloads  # noqa: E402
from vulnmirage.generation.pipeline import generate_for_oracle  # noqa: E402
from vulnmirage.ingest.vulngym import ingest_vulngym  # noqa: E402
from vulnmirage.repository.materialize import materialize_oracle_file  # noqa: E402
from vulnmirage.store import InstanceStore  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", default="workspace/dev-optimization")
    args = parser.parse_args()
    base = Path(args.workspace).resolve()
    if base.exists() and any(base.iterdir()):
        print(f"workspace is not empty: {base}", file=sys.stderr)
        return 1
    base.mkdir(parents=True, exist_ok=True)
    loaded = make_test_config(
        base,
        PROJECT_ROOT,
        goals=["false_negative", "false_positive"],
        tiers=["M0", "M1", "M2"],
        workspace_name="workspace",
    )
    fixture = create_fixture_repo(base / "fixture")
    ingest = ingest_vulngym(
        reports_path=fixture.reports_path,
        entries_path=fixture.entries_path,
        output_dir=loaded.paths.normalized,
    )
    oracle_path = loaded.paths.normalized / ingest["oracles"][0]["file"]
    materialize_oracle_file(loaded=loaded, oracle_path=oracle_path)
    generate_for_oracle(
        loaded=loaded,
        oracle_path=oracle_path,
        tiers="M1,M2",
        goals="false_negative,false_positive",
    )
    release_dir = loaded.paths.releases / "dev-v0"
    export_release(
        loaded=loaded,
        instances_dir=loaded.paths.instances,
        output_dir=release_dir,
        release_name="vulnmirage-dev-example",
        release_version="dev-v0",
    )
    store = InstanceStore(loaded.paths)
    from vulnmirage.generation.compatibility import load_compatibility_matrix
    from vulnmirage.manipulations import compatible_operator_candidates

    matrix = load_compatibility_matrix(
        loaded.resolve_asset(loaded.config.generation.compatibility_matrix)
    )

    def rewriter(*, generation, candidates, snapshot, budget_remaining, release_dir, budget):
        manifest, _ = load_release(Path(release_dir))
        by_candidate = {
            entry.candidate_id: entry for entry in manifest.instances if entry.candidate_id
        }
        pairs = {pair.pair_id: pair for pair in manifest.pairs}
        outputs = []
        for parent in candidates[:budget_remaining]:
            entry = by_candidate.get(parent)
            if entry is None:
                continue
            manipulation = store.load_manipulation(entry.instance_id)
            if manipulation is None:
                continue
            if not budget.reserve(queries=1, tokens=4000):
                break
            parent_operator = (
                manipulation.operator_names[0] if manipulation.operator_names else ""
            )
            compatible = compatible_operator_candidates(
                manipulation.designed_tier, manipulation.attack_goal, matrix
            )
            alternatives = [item for item in compatible if item != parent_operator]
            operator_override = (
                alternatives[(generation) % len(alternatives)] if alternatives else None
            )
            target_id = (
                manipulation.target_vulnerability_ids[0]
                if manipulation.target_vulnerability_ids
                else None
            )
            if operator_override is None:
                # No compatible alternative strategy: explore another target of
                # the same snapshot so the child still has new content/hash.
                clean_oracle = store.load_oracle(
                    pairs[entry.pair_id].clean_instance_id
                )
                others = [
                    item.vulnerability_id
                    for item in clean_oracle.vulnerabilities
                    if item.vulnerability_id != target_id
                ]
                if others:
                    target_id = others[0]
            result = generate_for_oracle(
                loaded=loaded,
                oracle_path=oracle_path,
                tiers=[manipulation.designed_tier.value],
                goals=[manipulation.attack_goal.value],
                seed=(generation + 1) * 7919,
                force=True,
                max_variants=1,
                candidate_index=generation + 1,
                target_vulnerability_id=target_id,
                parent_candidates=[
                    {"candidate_id": parent, "excerpt": "parent candidate regenerated"}
                ],
                operator_override=operator_override,
            )
            actual = 0
            for item in result.get("generated", []):
                actual += int(item.get("input_tokens") or 0) + int(
                    item.get("output_tokens") or 0
                )
            budget.settle(tokens=actual if actual else None, reserved_tokens=4000)
            for item in result.get("generated", []):
                patch_path = store.patch_path(item["instance_id"])
                parent_patch = store.patch_path(entry.instance_id)
                child_hash = (
                    __import__("hashlib").sha256(patch_path.read_bytes()).hexdigest()
                    if patch_path.is_file()
                    else None
                )
                parent_hash = (
                    __import__("hashlib").sha256(parent_patch.read_bytes()).hexdigest()
                    if parent_patch.is_file()
                    else None
                )
                if child_hash and child_hash == parent_hash:
                    # The renderer had no alternative representation; do not
                    # claim a new candidate.
                    continue
                outputs.append(
                    {
                        "candidate_id": item.get("candidate_id"),
                        "parent_candidate_ids": [parent],
                        "payload_ids": item.get("payload_ids") or [],
                        "note": f"scripted offline child of {parent}",
                        "llm_call_count": 0,
                        "new_instance_id": item.get("instance_id"),
                        "new_patch_sha256": child_hash or item.get("patch_sha256"),
                        "release_path": None,
                    }
                )
        if outputs:
            new_release = Path(release_dir).parent / f"dev-v0-g{generation + 1}"
            if new_release.exists():
                import shutil

                shutil.rmtree(new_release)
            export_release(
                loaded=loaded,
                instances_dir=loaded.paths.instances,
                output_dir=new_release,
                release_name="vulnmirage-dev-example",
                release_version=f"dev-v0-g{generation + 1}",
            )
            for item in outputs:
                item["release_path"] = str(new_release)
        return outputs

    result = optimize_payloads(
        loaded=loaded,
        release_dir=release_dir,
        agent_config_path=PROJECT_ROOT / "configs" / "dummy_agent.yaml",
        generations=2,
        population=2,
        output_path=base / "workspace" / "feedback" / "frozen-strategy.json",
        max_queries=30,
        max_llm_calls=6,
        token_budget=200_000,
        rewrite_enabled=True,
        runner=None,
        evaluator=None,
        rewriter=rewriter,
    )
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
