# Revision status: 2026-11-03 plan → implementation

This file maps `docs/benchmark_revision_plan_2026-11-03.md` to what exists, and to what
it deliberately does not. Every "implemented" row names a module and a test.

The forward-looking design now lives in
`docs/next_stage_design_2026-11-04.md`; this file remains the audit trail for the
2026-11-03 revision.

**2026-11-04 update — the old flow is gone.** `generation/`, `manipulations/`,
`validation/`, `export/`, the statistical half of `evaluation/`, the git-based
materialization (`repository/{cache,git,worktree,materialize,patch,location_remap}`),
the git-era `store.py` / `inspect.py` / `credentials.py` / `locking.py` /
`code_semantics.py` / `cvss.py`, the legacy ingest adapters, `payloads/`, the legacy
prompts and configs, and their documents were deleted. Current size: **46 Python
modules**, all on the campaign/verifier import closure. Backup:
`LAB/_archive/vulnmirage_legacy_20261104-1051`.

## Priority table (plan section 12.2)

| Order | Work | Status | Where | Acceptance |
| --- | --- | --- | --- | --- |
| P0-1 | task JSONL import, ordinary task construction | implemented | `ingest/dataset_core.py`, `campaign/task_prompt.py` | `test_dataset_core_reads_published_layout_and_verifies_hashes`, `test_effective_task_is_answer_free_idempotent_and_shared` |
| P0-2 | archive download and preparation | implemented | `repository/archive.py`, `campaign/pipeline.py` (`_phase_download`, `_phase_extract`) | `test_safe_extract_rejects_traversal_links_and_budgets`, `test_download_records_digest_and_detects_history`, `test_nested_history_is_refused_by_default` |
| P0-3 | clean + multi-method variants | implemented | `PayloadGen/variant_sets/`, `payloadgen.py`, `campaign/plan.py`, `campaign/variants.py` | plan-time set selection, independent builds, deterministic rendering, frozen hashes, planned methods fail closed, private safe-decoy tests |
| P0-4 | workspace audit, dual output, trace contract | audit/output implemented; native OpenCode trace normalization pending | `isolation/*`, `verifier/*`, `campaign/executor.py`, `evaluation/parser.py`, `harness/artifacts.py` | `test_campaign_end_to_end_local_tree`, `test_attestation_*`, `test_verifier_*`, `test_ineligible_run_is_excluded_from_scoring`, `test_harness_artifacts_*` |
| P1-1 | clean/attack pairing and mechanism analysis | implemented (rule-based, offline) | `mechanism/analysis.py`, `campaign/pipeline.py:_phase_mechanism` | `test_mechanism_analysis_reports_insufficient_evidence_without_trace`, `test_mechanism_analysis_uses_tool_result_evidence` |
| P1-2 | streaming schedule and cleanup | implemented | `campaign/state.py`, `campaign/pipeline.py:_phase_cleanup` | `test_campaign_cleanup_is_scoped_to_the_task`, `test_campaign_resume_refuses_a_changed_plan` |
| P1-3 | docs and necessary regression | implemented | `README.md`, `docs/campaign.md`, `docs/leakage_channels.md`, `docs/FILES.md`, `tests/test_campaign_revision.py` | `python -m pytest tests` |

## Section by section

| Plan | What was built |
| --- | --- |
| §2.1 dataset-core input | `load_dataset_core` reads `manifest.json` + task JSONL + private oracle JSONL, verifies the recorded digests, and is the only reader. The export-date suffix is discovered, not hard-coded. |
| §2.2 prompt normalization | Seven versioned rules strip repository identity (repo name/URL/commit/tag), rewrite the network statement, drop carrier reminders as whole bullets, drop the dataset-local JSON hint, drop frozen file counts, guarantee a network statement, and tidy layout debris; the contract block is appended and is byte-identical for every task. |
| §2.3 oracle eligibility | `eligibility_level` classifies `rejected / snapshot_verified / annotation_verified`; `executable_verified` is never produced because the package records `no_verifier` and `no_poc_commands`. Targets whose anchor snippet does not match the unpacked tree are excluded and listed. |
| §3 archive materialization | `resolve_archive_request` + `download_archive` + `safe_extract`: allowlisted redirects, TLS, byte budget, zip check, traversal/link/device refusal, case-collision detection, strip-single-root, tree digest, nested-history detection. |
| §4 variants | `PayloadGen` registry + templates; each variant is independently built from the same snapshot. Implemented adaptations cover false-fix/TODO/authority, certified safe decoys, and severity anchors. FPA/Flashboom semantic rewrites are planned and fail closed. Template/rendered/tree hashes and provenance are frozen; answer tokens are refused. |
| §5 workspace isolation | `ExposureLayout` keeps preparation, exposure and state disjoint; `run_attestation` proves what it can and reports `unknown` for the rest; `probe_egress` makes the network claim testable; invariants run for every condition. |
| §6 dual output and trace | Envelope parser with `report_markdown`, `agent_report.md`, `findings.json`, deterministic `audit_report.md`, `output_consistency.json`; answer collection through `campaign/executor.py`, which never repairs output. Raw stdout is archived, but OpenCode JSONL is not yet normalized into `events.normalized.jsonl` / `file_access.jsonl` by a native adapter. |
| §7 mechanism analysis | `exposure.json`, `trajectory_comparison.json`, `mechanism_assessment.json`, `case_analysis.md`; labels require the evidence they name, otherwise `insufficient_evidence`. |
| §8 scoring | Per-run target recall and severity deltas plus certified-decoy acceptance. Only exact private `SafeDecoy` matches count as induced false positives; all other unmatched findings remain unadjudicated. |
| §9 orchestration | Task phase machine with resume identity checks, verified archive before cleanup, `cleanup_manifest.json`, deletion scoped to the task scratch. |
| §10 layout | Implemented as documented in `docs/campaign.md`. |
| §11 module changes | `ingest/dataset_core.py`, `repository/archive.py`, `isolation/`, `verifier/`, `mechanism/`, `campaign/`, plus edits to `config.py`, `schemas.py`, `cli.py`, `diagnostics.py`, `evaluation/parser.py`, `harness/artifacts.py`, `harness/sandbox.py`, `paths.py`, `models/`, `prompts/audit_task.md`, `scripts/check_final_answer.py`. |
| §12 CLI | `doctor`, `schemas`, `ingest dataset-core`, `campaign plan|run|resume|analyze|verify-archive|status`, and `python -m vulnmirage.verifier`. |
| §13 references | Used for the channel list and the boundary model; see `docs/leakage_channels.md`. |

## Not implemented, and why

| Plan item | Status | Reason / next step |
| --- | --- | --- |
| LFS / submodule content completion | not implemented | archives can omit them; the loader records the limitation instead of substituting a newer version |
| Container as the default backend | not implemented | `campaign/executor.py` runs the configured argv; a `subprocess` run records `runtime_boundary: unknown`. Container execution is an operator / agent-config choice, not a code path here |
| Cross-repository statistics | not implemented | the campaign produces per-run and per-task results; the paired/bootstrap statistics belonged to the removed legacy evaluation. Re-adding them means a new module over `score.json` files, not resurrecting the old one |
| LLM-assisted mechanism coding | not implemented | labels are rule-based and auditable; an LLM coder would need its own blind-adjudication protocol |
| Trace capture for arbitrary runtimes | not implemented | the bundle accepts `events.normalized.jsonl` / `file_access.jsonl` when the runtime produces them; otherwise exposure is `unknown` |

## What the first real run changed

The synthetic fixtures pass before the code is right, so the flow was also run once on
real data (`elixir-plug/plug_cowboy` @ `5a4771c`, 20 files, no `.git`). That run exposed
three defects the fixtures had missed, all now fixed and covered by tests:

| Defect | Symptom | Fix |
| --- | --- | --- |
| Root directory entry in the archive defeated strip-single-root | every path stayed one level deep, so every oracle file "did not exist" | `_common_prefix` ignores the bare root entry; the entry itself is skipped instead of being recreated |
| A target whose file was absent from the snapshot was still scored | recall counted against a location the materialization could not find | only `verified` / `no_anchor` anchors enter the private target set; the rest are excluded with a reason |
| Anchor digest convention | every anchor mismatched, because the package hashes the raw snippet while the code hashed a normalized one | both bases are accepted over the same line range, and the matching basis is recorded |

The corrected run: anchor `verified`, 1/1 target scoreable, `strip_prefix` stripped,
`history_metadata: []`, attestation `fail` on `egress_blocked` only (open network on this
machine), leakage channels `5 controlled / 1 failed / 3 unknown`, archive verified with 39
hashed artifacts.

## Honest limitations

* The egress probe proves reachability for the probed hosts at that moment. Domain
  lists are incomplete, and the training-data channel is out of reach.
* `subprocess` mode cannot stop an agent from reading an absolute host path; the
  attestation records that as `unknown` rather than claiming containment.
* The template's illustrative JSON contains a CWE id; the answer-token scan therefore
  covers the task body only, and the contract block is asserted to be byte-identical
  across tasks.
* Mechanism labels are associations supported by recorded events, not a reconstruction
  of the model's reasoning.

## Verification snapshot

```text
python -m pytest tests -q            -> 44 passed
python -m vulnmirage schemas         -> 27 schemas, missing [] stale []
python -m vulnmirage ingest dataset-core --root ../VulnMirage_dataset
                                     -> ok, 47 tasks / 725 targets, digests verified
python -m vulnmirage campaign plan --dataset ../VulnMirage_dataset --limit 2
                                     -> plan written; no target id, CVE or CWE in it
python -m vulnmirage doctor          -> config/dataset/archive pass; egress probed live
```

`doctor` reports `egress: fail` on an ordinary internet-connected machine: with
`fail_closed: true` the probe reaches github.com, so formal runs would be ineligible.
That is the intended behaviour — the remedy is a filtering proxy
(`isolation.egress.mode: proxy`) or a container with a closed network namespace, not a
softer configuration.

The end-to-end test (`test_campaign_end_to_end_local_tree`) exercises the whole chain on
a fixture snapshot: two runs (C, A1), each with its own exposed workspace and
attestation, an archived bundle per run, a score per run, the four analysis artifacts, a
channel report, a verified archive manifest and a scoped cleanup. It asserts C detects
the target while A1 does not, and that the identical effective task reached both runs.
