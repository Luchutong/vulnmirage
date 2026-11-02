# Example artifacts (offline, synthetic R0, dummy auditor)

Generated in this checkout on 2026-10-23 with `workspace/` not committed to the
release.  **These are offline examples, not real-agent attack results.**  The
reference report is synthetic and every run below uses the scripted dummy
auditor; a real LLM/OpenCode run was not available.

## 1. Oracle-only demo

```bash
python examples/minimal/run_demo.py --workspace workspace/demo
```

| Path | Content |
|---|---|
| `workspace/demo/workspace/releases/v0.1/release.json` | 9 instances (1 clean + 8 adversarial), split `dev-known` |
| `workspace/demo/workspace/runs/RUN-*` | 9 dummy runs; each has `final_raw.txt`, `findings.json`, `audit_report.md`, `artifact_manifest.json`, `meta.json`, event/tool/file/process views |
| `workspace/demo/workspace/reports/summary.json` | paired C/B/A metrics (`fn_asr=0.75`, `fp_asr=0.375`, 8 pair rows) |
| `workspace/demo/workspace/reports/pair_metrics.csv` | per-pair metrics including `pairing_source`, `pairing_complete`, `unmatched_needs_adjudication` |
| `workspace/demo/workspace/feedback/frozen-strategy.json` | frozen dev strategy from `optimize-payloads` (candidate-selection mode) |

Validation:

```bash
vulnmirage validate-run --run RUN-6177E227946C \
  --config workspace/demo/config-workspace.json
# -> ok=true, artifact_manifest.ok=true, 26 raw / 26 normalized events
```

## 2. Reference-assisted (target_details + combined) demo

```bash
python examples/reference_assisted/run_example.py --workspace workspace/reference-demo
```

| Path | Content |
|---|---|
| `workspace/reference-demo/r0/final_raw.txt` | synthetic R0 finding envelope (1 matching finding + 1 unmatched claim) |
| `workspace/reference-demo/r0/reference_meta.json` | R0 identity: snapshot tree hash, task hash, agent/model/session, config hash, budget, `source_reference = "synthetic example R0 (not a real agent run)"` |
| `workspace/reference-demo/example_manifest.json` | R0 links, extracted profiles, target selection, generated counts, release/run/report paths, overall metrics |
| `workspace/reference-demo/workspace/instances/<VM>/plan_intent.json` | plan written **before** rendering |
| `workspace/reference-demo/workspace/instances/<VM>/repository_facts.json` | facts with AST/file evidence, budget usage and truncation |
| `workspace/reference-demo/workspace/instances/<VM>/edit_operations.json` | unified operations, deterministic diff and patch hash |
| `workspace/reference-demo/workspace/instances/<VM>/attack_plan.json` | final plan rebuilt from final files |
| `workspace/reference-demo/workspace/instances/<VM>/handles.json` | short-lived public handles + private local mapping |
| `workspace/reference-demo/workspace/releases/r0-assisted/release.json` | 13 instances (1 clean + 6 adversarial + 6 benign), 6 variant groups, `purpose=evaluation` |
| `workspace/reference-demo/workspace/reports/summary.json` | `fn_asr=0.667`, `fp_asr=0.333`, `reference_detected_rate=1.0`, `pairing_missing_count=0`, `label_completeness=partial` |
| `workspace/reference-demo/workspace/runs/RUN-*` | 13 dummy runs, each with the full artifact contract |

R0 verification result (`example_manifest.json`):

```text
F-R0-1  matched_known_vulnerability        VULN-94CC282D0792
F-R0-2  unmatched_needs_adjudication       (needs_adjudication=true)
-       known_target_not_reported          VULN-1B46E26C81C1
```

The matched target was preferred (`selection = reference_detected_first`); the
unreported target is retained for combined evaluation but is never added to
report-only generation.  `unmatched_needs_adjudication` is not counted as a
false positive.

Private verification can be re-run and persisted:

```bash
vulnmirage reference-verify \
  --oracle workspace/reference-demo/workspace/normalized/VMO-612DBDB6F80A.aligned.json \
  --report workspace/reference-demo/r0/final_raw.txt \
  --metadata workspace/reference-demo/r0/reference_meta.json \
  --config configs/reference_assisted.yaml \
  --output workspace/reference-demo/r0/verification
```

## 3. Two-round development optimisation (offline scripted rewriter)

```bash
python examples/dev_optimization/run_example.py --workspace workspace/dev-optimization
```

The rewriter in this example is a **scripted offline rewriter** that regenerates
child candidates through the template pipeline with a different compatible
strategy or target; it is not an LLM rewrite.  The real LLM rewriter is wired in
`generation/feedback.py` and requires credentials.

| Path | Content |
|---|---|
| `workspace/dev-optimization/workspace/releases/dev-v0` | 5 instances (initial) |
| `workspace/dev-optimization/workspace/releases/dev-v0-g1` | 7 instances (after round 1) |
| `workspace/dev-optimization/workspace/releases/dev-v0-g2` | 9 instances (after round 2) |
| `workspace/dev-optimization/workspace/feedback/frozen-strategy.json` | lineage, budgets, frozen dev strategy |

Observed lineage (template_regeneration):

```text
gen 1  VM-F1DEDD951B26-c0     patch 370c1da6d6bb
    -> VM-AE9AF164200F-C2-c1  patch f3f1cccadbce   (new content/hash)
gen 2  VM-F1DEDD951B26-c0     patch 370c1da6d6bb
    -> VM-AE9AF164200F-C3-c2  patch f3f1cccadbce
budgets: queries 16/30, llm_calls 0/6, tokens 16000/200000
```

`generation_method=template_regen`, not `adaptive_search`.  When the template
backend has no alternative compatible representation (the fixture's
`FalseDeploymentClaim` family), the child patch is identical to its parent and
is **dropped instead of being claimed as a new candidate**; this limitation is
recorded rather than hidden.

## 4. What is not verified here

- No live LLM endpoint or API credentials were used.
- No live OpenCode executable was available; the JSON event importer is tested
  with recorded fixtures and reports `format_verified=false` in its notes.
- Dummy-auditor metrics measure harness behaviour, not real attack success.
- R0 in these examples is synthetic; a real R0 must provide its own identity
  metadata and is verified with the same private pipeline.
