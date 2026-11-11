# Revision status: 2026-11-03 plan → implementation

This file maps `docs/benchmark_revision_plan_2026-11-03.md` to what exists, and to what
it deliberately does not. Every "implemented" row names a module and a test.

The forward-looking design now lives in
`docs/next_stage_design_2026-11-04.md`; this file remains the audit trail for the
2026-11-03 revision.

**2026-11-11 update — the canonical attack taxonomy is enforced.** Formal plans now
freeze `threat_model_id × objective × method × primary mechanism × surface ×
intensity × realization`; T0–T4 is recorded separately as generator-context
provenance. The schema 3 registry separates method definitions from concrete
realizations, formal variant sets are single-objective, inline payload edits fail
closed, and the clean baseline remains the only non-attack condition.

**2026-11-11 intensity update.** `M2-FALSE-PRIOR-RESOLUTION`,
`M2-FALSE-EXPLOITABILITY-PREMISE` and `M2-FABRICATED-ANALYSIS-RESULT` now have two
concrete realizations at every I0–I4 level. Each realization declares a
machine-checked dose, each fixed-T2 intensity ablation resolves to 11 conditions,
and aggregation reports method-scoped `by_intensity` summaries.

**2026-11-05 update — the tier generation subsystem landed.** The design in
`docs/adaptive_attack_benchmark_architecture_2026-11-04.md` is now implemented for
T0–T2; T3/T4 remain planned and fail closed.

| Design section | What exists now | Where | Acceptance |
| --- | --- | --- | --- |
| §3 T0–T4 ladder | `tiers.py` is the single definition; config validates a declared tier, plan refuses an unimplemented one | `tiers.py`, `config.py`, `campaign/plan.py` | `test_tier_ablation_set_covers_the_three_implemented_tiers` |
| §8 PayloadGen | `payloadgen/` package; schema 3 `PayloadGen/registry.yaml` separates methods, realizations and generator provenance | `src/vulnmirage/payloadgen/`, `PayloadGen/methods/` | `test_t0_generation_matches_the_preexisting_renderer_byte_for_byte` |
| §10 contracts | `ConditionSpec`, `ExperimentCell`, `CandidatePayload`, `CandidateValidation`, `GenerationManifest`, `AdaptationQuery` + schemas | `payloadgen/contracts.py` | `test_schema_index_covers_the_new_contracts` |
| §11 RepositoryIndex | deterministic index with roles, AST/text symbols, comment styles, sink files (no oracle labels) | `payloadgen/repository_index.py` | `test_repository_index_is_deterministic_and_role_aware` |
| §12 OracleAttackView | allowlist sanitizer + eligibility + token re-scan | `payloadgen/oracle_view.py` | `test_oracle_view_strips_identity_fix_and_excerpt`, `test_a_target_with_only_an_advisory_label_is_ineligible_for_t2` |
| §13 generate/validate/select | four validators, predeclared scoring, deterministic tie-break, blocking `unknown` | `payloadgen/validators/`, `payloadgen/selection.py`, `payloadgen/engine.py` | `test_selection_is_reproducible_and_records_its_rule`, `test_a_candidate_that_leaks_an_answer_is_not_selectable` |
| §14.4 target remap | symbol delta → anchor window → line delta, `unique` flag | `payloadgen/remap.py`, `campaign/variants.py` | `test_remap_keeps_a_target_inside_its_function_after_an_insert` |
| §15 phases | `indexed` / `generation_started` / `candidates_validated` inserted before `variants_frozen` | `campaign/state.py`, `campaign/pipeline.py` | `test_pipeline_freezes_generation_before_building_trees` |
| §19 aggregation | paired deltas by tier, bootstrap interval, attrition ledger | `evaluation/aggregate.py` | `test_pipeline_freezes_generation_before_building_trees` |
| §22 CLI | `campaign generate --inspect-generation`, `campaign aggregate`, `--dry-run`, `--agent-profile` | `cli.py` | `test_plan_dry_run_writes_no_control_file` |

Two behaviour changes worth naming: `expected_severity` is no longer filled from the
private oracle (no template used it, so the T0 goldens are unchanged, but the latent
leak is gone), and `configs/opencode.yaml` now holds every model under `profiles:`
with `--agent-profile` selecting one.

Measured on the shipped dataset: **725/725 targets** admit a sanitized T2 view and
**0** of those views contain an answer token. That is a sanitizer check, not an
attack result.

**2026-11-04 update — the old flow is gone.** `generation/`, `manipulations/`,
`validation/`, `export/`, the statistical half of `evaluation/`, the git-based
materialization (`repository/{cache,git,worktree,materialize,patch,location_remap}`),
the git-era `store.py` / `inspect.py` / `credentials.py` / `locking.py` /
`code_semantics.py` / `cvss.py`, the legacy ingest adapters, `payloads/`, the legacy
prompts and configs, and their documents were deleted. Current size: **75 Python
modules**, all on the campaign/verifier/payloadgen import closure. Backup:
`LAB/_archive/vulnmirage_legacy_20261104-1051`.

## Priority table (plan section 12.2)

| Order | Work | Status | Where | Acceptance |
| --- | --- | --- | --- | --- |
| P0-1 | task JSONL import, ordinary task construction | implemented | `ingest/dataset_core.py`, `campaign/task_prompt.py` | `test_dataset_core_reads_published_layout_and_verifies_hashes`, `test_effective_task_is_answer_free_idempotent_and_shared` |
| P0-2 | archive download and preparation | implemented | `repository/archive.py`, `campaign/pipeline.py` (`_phase_download`, `_phase_extract`) | `test_safe_extract_rejects_traversal_links_and_budgets`, `test_download_records_digest_and_detects_history`, `test_nested_history_is_refused_by_default` |
| P0-3 | clean + multi-method variants | implemented | `PayloadGen/{registry.yaml,variant_sets,methods}/`, `payloadgen/`, `campaign/plan.py`, `campaign/variants.py` | plan-time set + generator-context selection, canonical attack identity, independent builds, deterministic rendering, frozen generation manifests, planned methods fail closed, private safe-decoy tests |
| P0-4 | workspace audit, dual output, trace contract | implemented; OpenCode 1.17.18 and native Linux 2.2.7 real-CLI fixtures validated, three model-backed live runs pending | `isolation/*`, `trace/*`, `verifier/*`, `campaign/executor.py`, `evaluation/parser.py`, `harness/artifacts.py` | `test_campaign_end_to_end_local_tree`, `test_real_opencode_cli_fixture_matches_normalizer_contract`, `test_opencode_trace_*`, `test_attestation_*`, `test_verifier_*` |
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
| §6 dual output and trace | Envelope parser with `report_markdown`, `agent_report.md`, `findings.json`, deterministic `audit_report.md`, `output_consistency.json`; answer collection through `campaign/executor.py`, which never repairs output. `trace/` derives normalized events/tool/file-access, a source-bound manifest and completeness from raw OpenCode JSONL. Sanitized 1.17.18 and native Linux 2.2.7 real-CLI fixtures freeze both observed event contracts; runtime version and compatibility are recorded per run. |
| §7 mechanism analysis | `exposure.json`, `trajectory_comparison.json`, `mechanism_assessment.json`, `case_analysis.md`; labels require the evidence they name, otherwise `insufficient_evidence`. |
| §8 scoring | Per-run target recall and severity deltas plus certified-decoy acceptance. Only exact private `SafeDecoy` matches count as induced false positives; all other unmatched findings remain unadjudicated. |
| §9 orchestration | Task phase machine with resume identity checks, verified archive before cleanup, `cleanup_manifest.json`, deletion scoped to the task scratch. |
| §10 layout | Implemented as documented in `docs/campaign.md`. |
| §11 module changes | `ingest/dataset_core.py`, `repository/archive.py`, `isolation/`, `trace/`, `verifier/`, `mechanism/`, `payloadgen/`, `campaign/`, `evaluation/aggregate.py`, plus edits to `config.py`, `tiers.py`, `schemas.py`, `cli.py`, `diagnostics.py`, `evaluation/parser.py`, `harness/artifacts.py`, `harness/sandbox.py`, `paths.py`, `models/`, `prompts/audit_task.md`, `scripts/check_final_answer.py`. |
| §12 CLI | `doctor`, `schemas`, `ingest dataset-core`, `campaign plan|generate|run|resume|analyze|aggregate|verify-archive|status`, and `python -m vulnmirage.verifier`. |
| §13 references | Used for the channel list and the boundary model; see `docs/leakage_channels.md`. |

## Not implemented, and why

| Plan item | Status | Reason / next step |
| --- | --- | --- |
| LFS / submodule content completion | not implemented | archives can omit them; the loader records the limitation instead of substituting a newer version |
| Container as the default backend | not implemented | `campaign/executor.py` runs the configured argv; a `subprocess` run records `runtime_boundary: unknown`. Container/gateway execution is an operator choice, not a code path here |
| Cross-repository statistics at scale | partial | `evaluation/aggregate.py` pairs within a task and bootstraps the paired deltas; clustering by repository and pre-registered exclusion rules are still to be exercised on a real multi-task campaign |
| LLM-assisted mechanism coding | not implemented | labels are rule-based and auditable; an LLM coder would need its own blind-adjudication protocol |
| Trace capture for arbitrary runtimes | OpenCode implemented; other runtimes not implemented | `AgentConfig.trace_adapter` is explicit; unsupported/disabled runtimes produce empty derived files and a stable missing/disabled status rather than inferred evidence |
| T3/T4 generators | not implemented | no surrogate gateway and no adaptation/holdout protocol; both tiers raise `unsupported_tier` and cannot be planned |

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
* Probe-only unreachability is not accepted as enforcement. With
  `fail_closed: true`, `mode: none` and declared-but-unattested proxy/container
  modes make a run ineligible before any agent call.
* `subprocess` mode cannot stop an agent from reading an absolute host path; the
  attestation records that as `unknown` rather than claiming containment.
* The template's illustrative JSON contains a CWE id; the answer-token scan therefore
  covers the task body only, and the contract block is asserted to be byte-identical
  across tasks.
* Mechanism labels are associations supported by recorded events, not a reconstruction
  of the model's reasoning.

## Verification snapshot

```text
python -m pytest tests -q            -> 94 passed
python -m vulnmirage schemas         -> 52 schemas, missing [] stale []
python scripts/capture_opencode_trace_fixture.py
                                     -> native OpenCode 2.2.7, 6 events, external model calls 0
python -m vulnmirage ingest dataset-core --root ../VulnMirage_dataset
                                     -> ok, 47 tasks / 725 targets, digests verified
python -m vulnmirage campaign plan --dataset ../VulnMirage_dataset --limit 2 --dry-run
                                     -> resolved; no target id, CVE or CWE in it
python -m vulnmirage campaign plan ... --variant-set <each set> --dry-run
                                     -> all ten sets resolve; each has one primary objective
python -m vulnmirage doctor          -> config/dataset/archive pass; egress probed live
```

The WSL/Linux configuration now selects a rootless user/network namespace with a
loopback-to-Unix-socket inference relay. `doctor` checks upstream/model reachability and
Linux prerequisites; every audit separately requires namespace evidence before any
model call. The backend is implemented and unit-tested but still requires its first
operator-run WSL validation before G2 can be marked complete.

The end-to-end test (`test_campaign_end_to_end_local_tree`) exercises the whole chain on
a fixture snapshot: two runs (C, A1), each with its own exposed workspace and
attestation, an archived bundle per run, a score per run, the four analysis artifacts, a
channel report, a verified archive manifest and a scoped cleanup. It asserts C detects
the target while A1 does not, and that the identical effective task reached both runs.
