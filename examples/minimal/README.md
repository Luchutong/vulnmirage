# Minimal offline example

This directory contains two runnable helpers:

* `build_fixture.py` creates a deterministic local git repository with:
  * a real SQL injection reachable through two entry points;
  * a fix commit;
  * an executable PoC (`poc/poc.py`);
  * a regression test (`tests/test_app.py`);
  * a safe function (`app/safe.py`) used as a false-positive target.
* `run_demo.py` executes the full offline pipeline: ingest → materialize →
  generate → validate → export → run (dummy auditor) → evaluate.

```bash
python examples/minimal/build_fixture.py --output workspace/fixture
python examples/minimal/run_demo.py --workspace workspace/demo
# optionally include M4–M6:
python examples/minimal/run_demo.py --workspace workspace/demo-all --all-tiers
```

The fixture repository is created under the requested output directory; the
workspace contains all cache, worktree, instance, run, release and report
artifacts described in the top-level README.

The dummy auditor is intentionally simplistic. It reacts to claims in the
repository text so that the paired clean/adversarial metrics are stable in
tests, and it emits native `UnifiedEvent` JSONL with read line ranges, tool-call
IDs and structured evidence citations. `--policy` provides deterministic
verification behaviours (`no_verify`, `non_decisive`, `decisive`,
`unvisited_citation`); the default policy performs a normal scripted audit. It
is not a security scanner.

Each run writes the frozen `events.raw.jsonl`, normalized events, file/process/
tool views, `trajectory_enriched.jsonl`, `verification_assessments.json`,
`matches.json`, `metrics.json` and `meta.json`; `vulnmirage validate-run`
rechecks their hashes and sequence invariants.
