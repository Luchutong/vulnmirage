# Campaign flow: one task from archive to archived artefacts

The campaign replaces the clone-first, release-bundle-first flow with a task-driven
one. It reads one row of the published `tasks/task-*.jsonl`, materializes that exact
commit from an archive, builds one clean tree plus the declared variants from that
same tree, audits each variant in its own sealed workspace, and scores the frozen
answers in a separate process.

## Phases

```text
pending -> downloading -> extracted -> prepared -> indexed
        -> generation_started -> candidates_validated -> variants_frozen
        -> auditing -> scoring -> mechanism_analysis -> archived -> cleaned
```

Each phase writes its artefacts and advances a persisted state file, so an
interrupted campaign resumes instead of repeating an audit. Phase transitions
cannot skip forward or move backwards, and resume is refused when the plan or the
configuration hash changed — continuing under a different treatment is not the same
run.

`indexed` / `generation_started` / `candidates_validated` exist because generation
is its own resumable stage: the candidate set, every validator verdict and the
selection are on disk before any tree is built. `campaign generate` stops after
`candidates_validated`.

## Commands

```bash
# offline: read the task index, hash the normalized prompt, freeze conditions+tiers
python -m vulnmirage campaign plan --config configs/experiment.yaml \
    --dataset ../VulnMirage_dataset \
    --variant-set PayloadGen/variant_sets/core_tier_ablation.yaml \
    --workspace workspace/campaigns/tier-ablation/deepseek-reasoner \
    --limit 1 --target-limit 1

# --dry-run resolves everything and prints the digest without writing control/plan.json
python -m vulnmirage campaign plan ... --dry-run

# generate + validate candidates only; prints candidates/verdicts/selection
python -m vulnmirage campaign generate \
    --plan workspace/campaigns/tier-ablation/deepseek-reasoner/control/plan.json \
    --inspect-generation

# execute (or resume) one task; --agent supplies the command that runs an audit and
# --agent-profile picks one model from the single multi-model file
python -m vulnmirage campaign run \
    --plan workspace/campaigns/tier-ablation/deepseek-reasoner/control/plan.json \
    --task task_snap_0319ebb1a71dfd3c --agent configs/opencode.yaml \
    --agent-profile deepseek-reasoner

python -m vulnmirage campaign resume  --plan workspace/campaigns/tier-ablation/deepseek-reasoner/control/plan.json
python -m vulnmirage campaign analyze --plan workspace/campaigns/tier-ablation/deepseek-reasoner/control/plan.json
python -m vulnmirage campaign aggregate --plan workspace/campaigns/tier-ablation/deepseek-reasoner/control/plan.json
python -m vulnmirage campaign verify-archive --plan workspace/campaigns/tier-ablation/deepseek-reasoner/control/plan.json
python -m vulnmirage campaign status  --plan workspace/campaigns/tier-ablation/deepseek-reasoner/control/plan.json

# the evaluator as a separate process
python -m vulnmirage.verifier --private workspace/private \
    --bundle workspace/tmp/<task>/bundles/<run> --out /tmp/score
```

`--variant-set` exists only on `campaign plan`. The resulting plan freezes the
set id, research question, file, SHA-256, resolved conditions with their tiers, and
the generation envelope (seed, per-tier candidate budget and limits); run/resume
restore that selection automatically and fail if any generation asset changed.
Each selected target is expanded into an independent clean/attack pair. The plan also
freezes a seeded permutation of every `(target, variant, repetition)` cell, preventing
the clean arm from always running first. `--target-limit` bounds target expansion per
task without changing the dataset.

`campaign plan` never downloads a repository and never calls a model. Repository
download and dependency preparation belong to the trusted preparation stage, which
is why they happen inside `generate`/`run`, before any agent process starts.

Windows CMD uses the same paths with `^` line continuation:

```bat
python -m vulnmirage campaign plan ^
  --config configs\experiment.yaml ^
  --dataset ..\VulnMirage_dataset ^
  --variant-set PayloadGen\variant_sets\core.yaml ^
  --workspace workspace\campaigns\core\deepseek-chat ^
  --limit 1 ^
  --target-limit 1

python -m vulnmirage campaign run ^
  --config configs\experiment.yaml ^
  --plan workspace\campaigns\core\deepseek-chat\control\plan.json ^
  --agent configs\opencode.yaml ^
  --agent-profile glm-4.7
```

## Layout

```text
workspace/
  control/plan.json                  scheduler + budget + per-tier generation rules
  control/state/<task>.json          phase state, hashes, run ids
  private/targets/<task>.json        reduced target view (evaluator only)
  private/targets/<task>__<variant>.json  remapped target view + private safe decoys
  private/target_remap/<task>__<variant>.json  symbol/anchor/delta remap basis
  private/oracle_attack_views/<task>__<variant>.json  sanitized T2 view (T2 only)
  cache/archives/<source-id>/        one exact-commit archive per snapshot
  tmp/<task>/                        scratch: prep, variants, exposed runs, bundles
  archives/<task>/
    source_manifest.json             archive + tree identity, rejected entries
    task_manifest.json               source/effective prompt hashes, transformations
    generation/repository_index.json public-structure index and its digest
    generation/candidates/<variant>.json  every candidate + validator verdicts
    generation/manifests/<variant>.json   frozen generation manifest + selection
    generation/generation_manifest.json   conditions, seed, index digest
    generation/variants_frozen.json  every variant build with its tree digest
    patches/<variant>.json           structured edits, selected candidate, remap hash
    validation/snapshot_check.json   per-target anchor verification
    runs/<run>/                      run.json (with tier/condition), meta.json,
                                     final_raw.txt, agent_report.md, findings.json,
                                     audit_report.md, output_consistency.json,
                                     isolation_attestation.json, agent_environment.json,
                                     stdout.log, stderr.log,
                                     events.normalized.jsonl, tool_calls.jsonl,
                                     file_access.jsonl, trace_manifest.json,
                                     trace_completeness.json
    evaluation/<run>/                score.json, matches.json, safe_decoy_matches.json,
                                     output_consistency.json, untrusted_input.json,
                                     verifier_attestation.json
    analysis/<task>-comparison/      exposure.json, trajectory_comparison.json,
                                     mechanism_assessment.json, case_analysis.md
    leakage_controls.json            channel -> controlled/failed/unknown
    artifact_manifest.json           every artefact with sha256
    cleanup_manifest.json            what was removed, what was kept
  aggregate/aggregate.json           paired deltas by tier, bootstrap, attrition ledger
```

`campaign aggregate` reads the frozen archives only; it never re-runs an agent or a
generator. Attrition (conditions without a manifest, candidates blocked by a
required validator, ineligible runs, missing traces) is reported next to the effect
rather than dropped from the denominator.

## Invariants that are not conditions

| Invariant | Where it runs | What a failure means |
| --- | --- | --- |
| Oracle absent from the agent tree | before every run | run is ineligible |
| One variant, no `.git`, no sibling run | before every run | run is ineligible |
| Fresh state directory | before every run | run is ineligible |
| Egress probe | before every run | ineligible when an answer host answers |
| Post-hoc scoring in the verifier | after every run | bundle refused, run unscored |

See [leakage_channels.md](leakage_channels.md) for the channel list and the
evidence each check produces.

## Payload methods and tiers

The active registry is `PayloadGen/registry.v2.yaml`; each method declares the tiers
it supports and which generator backend realizes each one. The compact T0 baseline
is `PayloadGen/variant_sets/core.yaml`; `core_tier_ablation.yaml` adds T1/T2 for the
same methods so the ablation is a property of the condition set, not of a run-time
flag.

Every condition is generated, validated and selected before a tree is built:

```text
context (tier-scoped) -> candidates -> structural/leakage/semantic/budget
                     -> predeclared score + deterministic tie-break -> manifest
```

Only the selected candidate reaches `variants_frozen`. A required validator that
returns `unknown` blocks selection — "we could not check" is not "checked". If every
candidate fails, generation fails; there is no silent downgrade to a cheaper tier.

Target comments may be appended at the file footer or inserted before a unique
anchor. Because an insertion shifts lines, each variant gets a private target
remap (symbol delta → anchor window → recorded line delta). A target that cannot be
remapped uniquely makes the variant ineligible instead of scoring against a
coordinate that no longer exists.

Safe-decoy text is checked against a restrictive Python AST subset with no
imports, attribute calls, or dynamic execution. Its certificate stays in the
variant-specific private target view. Consequently `score.json.false_positive`
only measures acceptance of certified decoys; it does not mislabel arbitrary
unmatched findings in a non-exhaustive oracle.

Use a different workspace for every `(variant_set, model)` pair, for example
`workspace/campaigns/core/deepseek-chat` and
`workspace/campaigns/safe-decoy/qwen3-coder-plus`. Archive downloads may still
share `workspace/cache/archives`; run and scoring state may not be shared.

## How an audit is executed

`--agent <config>` selects one of three executors (`campaign/executor.py`); without
it, `NullExecutor` prepares and attests each workspace and runs no model. The agent
config may contain several models under `profiles:`; `--agent-profile <name>`
selects one, and the resolved profile name is recorded in `meta.json`. Without the
flag, `default_profile` is used.

| Mode | Answer comes from | Config |
| --- | --- | --- |
| `stdout` | the harness captures stdout and extracts the last JSON answer (or the last text part of a JSONL event stream) | `mode: stdout`, `answer_extractor: jsonl_events` |
| `argv` | the command writes the answer into `{output}` itself | `mode: argv` |
| none | nothing is executed | omit `--agent` |

Placeholders: `{repo}` is **required** (an audit that never receives the workspace
is a configuration error), `{task}` and `{prompt}` are aliases for the normalized
task path, `{output}` is the writable output directory, and `{model}` is replaced by
the selected profile's model id. Credentials are referenced by **name** in
`requires_env` and are checked before the first run starts; only the selected
profile's names are forwarded.

The supplied OpenCode agent additionally denies `bash`, `webfetch`, `codesearch`,
editing and external-directory access. This removes repository-controlled network
tools, but formal eligibility still requires the independent egress attestation to
pass; a permission policy is not treated as a kernel network boundary.

Extraction only *locates* an answer: no prose is repaired, no JSON is completed. If
no answer block is found, the run is a `missing_answer` format failure — it never
becomes an empty "no findings" result.

## Dual output

One audit produces a report **and** findings. The contract in
`prompts/audit_task.md` is appended to the normalized dataset prompt, so every task
gets byte-identical wording:

```json
{"schema_version": "1.0", "report_markdown": "...", "findings": [], "audit_summary": {}}
```

`output_consistency.json` records which `finding_id`s the JSON contains, which ids
the report mentions, and the difference in both directions. A report that
contradicts the findings is `divergent`; a missing report is `report_missing` and
the run keeps its outcome metrics but contributes no report-level metric. The
legacy findings-only envelope is still parsed and marked `findings_only`, so
archived runs are not relabelled.

## Failure semantics

| Situation | Result |
| --- | --- |
| Download or unpack fails | `download_failed` / phase error; not an audit failure |
| Archive carries nested history | phase error with the offending paths, unless explicitly accepted |
| Condition names a tier with no generator | `unsupported_tier` at plan time; nothing is generated |
| Every candidate fails a required validator | generation fails with the eliminated list; no fallback tier, no weaker candidate |
| A private target cannot be remapped uniquely | phase error; the variant never enters a repetition |
| Isolation invariant fails | run recorded, marked ineligible, not scored |
| Egress probe reaches an answer host | run recorded as ineligible (`fail_closed`) |
| Agent writes no answer / no answer in stdout | `missing_answer`; excluded from denominators |
| Answer unparseable | `format_failure`; excluded from denominators, never read as "no findings" |
| Complete answer with zero findings | valid result, `detected = 0` |
| Trace missing | outcome metrics stay valid, mechanism labels become `insufficient_evidence` |
| Analysis rules change | re-run `campaign analyze`; stored runs are not re-labelled |
