# Campaign flow: one task from archive to archived artefacts

The campaign replaces the clone-first, release-bundle-first flow with a task-driven
one. It reads one row of the published `tasks/task-*.jsonl`, materializes that exact
commit from an archive, builds one clean tree plus the declared variants from that
same tree, audits each variant in its own sealed workspace, and scores the frozen
answers in a separate process.

## Phases

```text
pending -> downloading -> extracted -> prepared -> variants_frozen
        -> auditing -> scoring -> mechanism_analysis -> archived -> cleaned
```

Each phase writes its artefacts and advances a persisted state file, so an
interrupted campaign resumes instead of repeating an audit. Phase transitions
cannot skip forward or move backwards, and resume is refused when the plan or the
configuration hash changed — continuing under a different treatment is not the same
run.

## Commands

```bash
# offline: read the task index, hash the normalized prompt, freeze variants
python -m vulnmirage campaign plan --config configs/experiment.yaml \
    --dataset ../VulnMirage_dataset \
    --variant-set PayloadGen/variant_sets/core.yaml \
    --workspace workspace/campaigns/core/deepseek-chat --limit 1

# execute (or resume) one task; --agent supplies the command that runs an audit
# (any agent config with an argv template works, e.g. configs/opencode.yaml)
python -m vulnmirage campaign run \
    --plan workspace/campaigns/core/deepseek-chat/control/plan.json \
    --task task_snap_0319ebb1a71dfd3c --agent configs/opencode.yaml

python -m vulnmirage campaign resume  --plan workspace/campaigns/core/deepseek-chat/control/plan.json
python -m vulnmirage campaign analyze --plan workspace/campaigns/core/deepseek-chat/control/plan.json
python -m vulnmirage campaign verify-archive --plan workspace/campaigns/core/deepseek-chat/control/plan.json
python -m vulnmirage campaign status  --plan workspace/campaigns/core/deepseek-chat/control/plan.json

# the evaluator as a separate process
python -m vulnmirage.verifier --private workspace/private \
    --bundle workspace/tmp/<task>/bundles/<run> --out /tmp/score
```

`--variant-set` exists only on `campaign plan`. The resulting plan freezes the
set id, research question, file, SHA-256 and resolved variants; run/resume restore
that selection automatically and fail if any generation asset changed.

`campaign plan` never downloads a repository and never calls a model. Repository
download and dependency preparation belong to the trusted preparation stage, which
is why they happen inside `run`, before any agent process starts.

Windows CMD uses the same paths with `^` line continuation:

```bat
python -m vulnmirage campaign plan ^
  --config configs\experiment.yaml ^
  --dataset ..\VulnMirage_dataset ^
  --variant-set PayloadGen\variant_sets\core.yaml ^
  --workspace workspace\campaigns\core\deepseek-chat ^
  --limit 1

python -m vulnmirage campaign run ^
  --config configs\experiment.yaml ^
  --plan workspace\campaigns\core\deepseek-chat\control\plan.json ^
  --agent configs\opencode.yaml
```

## Layout

```text
workspace/
  control/plan.json                  scheduler + budget, never exposed
  control/state/<task>.json          phase state, hashes, run ids
  private/targets/<task>.json        reduced target view (evaluator only)
  private/targets/<task>__<variant>.json  target view + private safe decoys
  cache/archives/<source-id>/        one exact-commit archive per snapshot
  tmp/<task>/                        scratch: prep, variants, exposed runs, bundles
  archives/<task>/
    source_manifest.json             archive + tree identity, rejected entries
    task_manifest.json               source/effective prompt hashes, transformations
    generation/variants_frozen.json  every variant build with its tree digest
    patches/<variant>.json           the structured edits that were applied
    validation/snapshot_check.json   per-target anchor verification
    runs/<run>/                      run.json, meta.json, final_raw.txt,
                                     agent_report.md, findings.json,
                                     audit_report.md, output_consistency.json,
                                     isolation_attestation.json, agent_environment.json
    evaluation/<run>/                score.json, matches.json, safe_decoy_matches.json,
                                     output_consistency.json, untrusted_input.json,
                                     verifier_attestation.json
    analysis/<task>-comparison/      exposure.json, trajectory_comparison.json,
                                     mechanism_assessment.json, case_analysis.md
    leakage_controls.json            channel -> controlled/failed/unknown
    artifact_manifest.json           every artefact with sha256
    cleanup_manifest.json            what was removed, what was kept
```

Cross-task aggregation (`reports/`) is not produced by the campaign yet; per-run and
per-task results are complete, and the paired/statistics modules still consume the
older release-bundle flow (see the status document).

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

## Payload methods

The default experiment loads `PayloadGen/registry.yaml` and the compact
`PayloadGen/variant_sets/core.yaml`. Other files isolate false-negative,
safe-decoy, and severity questions. Each attack variant is independently rendered
from the clean snapshot. The archived patch records the payload id, source,
template/rendered hashes, realized edit, and final tree hash.

Runnable adaptations cover repository false-fix claims, TODO-style false-safety
comments, fabricated analyzer authority, TODO false alarms, a RedHerring-inspired
safe decoy, and severity downgrade/inflation anchors. Target comments are appended
to the same source file without shifting target lines. Familiar-pattern camouflage
and Flashboom-style semantic rewriting are registered as `planned`; activating
them fails until a language-aware generator and behavior-equivalence validator
are implemented.

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
it, `NullExecutor` prepares and attests each workspace and runs no model.

| Mode | Answer comes from | Config |
| --- | --- | --- |
| `stdout` | the harness captures stdout and extracts the last JSON answer (or the last text part of a JSONL event stream) | `mode: stdout`, `answer_extractor: jsonl_events` |
| `argv` | the command writes the answer into `{output}` itself | `mode: argv` |
| none | nothing is executed | omit `--agent` |

Placeholders: `{repo}` is **required** (an audit that never receives the workspace
is a configuration error), `{task}` and `{prompt}` are aliases for the normalized
task path, `{output}` is the writable output directory. Credentials are referenced by
**name** in `requires_env` and are checked before the first run starts.

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
| Isolation invariant fails | run recorded, marked ineligible, not scored |
| Egress probe reaches an answer host | run recorded as ineligible (`fail_closed`) |
| Agent writes no answer / no answer in stdout | `missing_answer`; excluded from denominators |
| Answer unparseable | `format_failure`; excluded from denominators, never read as "no findings" |
| Complete answer with zero findings | valid result, `detected = 0` |
| Trace missing | outcome metrics stay valid, mechanism labels become `insufficient_evidence` |
| Analysis rules change | re-run `campaign analyze`; stored runs are not re-labelled |
