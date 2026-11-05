# Tier capability matrix

This file is the readable side of `src/vulnmirage/tiers.py`. If the two disagree,
the code wins and this file is the bug.

A **tier** is a statement about what a generator was allowed to read. It is not a
measure of attack strength, and no result in this repository is reported "per
tier" without also reporting the generation and validity losses (see
`aggregate/aggregate.json`).

| Tier | Oracle view | Repository index | Model feedback | Implemented |
| :-- | :-- | :-- | :-- | :-- |
| T0 | no | yes, placement only | no | yes (fixed text, deterministic public placement) |
| T1 | no | yes | no | yes |
| T2 | sanitized local view | yes | no | yes |
| T3 | yes | yes | surrogate only | no (`unsupported_tier`) |
| T4 | yes | yes | victim, budgeted | no (`unsupported_tier`) |

## What a generator receives

`GeneratorContext` is the whole surface. The pipeline builds it, so a tier cannot
"happen to" see more:

| Field | T0 | T1 | T2 |
| :-- | :-- | :-- | :-- |
| `task.task_id`, `task.primary_language` | yes | yes | yes |
| `method.template`, `method.carrier`, `method.placement` | yes | yes | yes |
| `budget`, `forbidden_tokens` | yes | yes | yes |
| `placement_hint` (legacy direct-API compatibility) | compatibility only | no | no |
| `index.files`, `index.symbols`, `index.comment_styles` | placement only | yes | yes |
| `oracle_view.locations`, `oracle_view.local_semantics` | no | no | yes |

Two enforcement points exist, and both are tested:

1. `GeneratorContext.assert_matches_tier()` refuses a context that carries a field
   its tier may not use (`test_t1_context_refuses_an_oracle_view`,
   `test_pipeline_freezes_generation_before_building_trees`).
2. The pipeline hands T0 the public index only for a deterministic placement and
   never hands it an oracle view; T1 also receives no oracle view. The manifest
   records `index_sha256` / `oracle_view_sha256`, so an after-the-fact reader can
   check the claim instead of trusting the tier label.

There is also a static guard: `generators/static.py` and
`generators/repository_adaptive.py` contain no reference to `oracle_view`
(`test_repository_adaptive_generator_does_not_import_the_oracle_view`).

## What T2 may know

`OracleAttackView` is built by an **allowlist**, not by deleting fields from the
oracle row. It carries the location, the attacker-controlled-input flag, up to
four preconditions, a coarse dangerous-effect phrase and boundary claims to test.

It never carries: CVE/GHSA ids, CWE ids, the advisory title/label/family, the
description, the code excerpt, fix commits, affected versions, the raw target id,
the task id, or any repository identifier. Free text that survives is passed
through a token redactor, and the view is re-scanned against the task's answer
tokens before it can be used (`assert_view_is_clean`).

A target whose oracle row has no verifiable location, or nothing beyond an advisory
label, is `ineligible_oracle_view`. There is no "look it up online" fallback.

Measured on the shipped dataset: **725/725 targets** admit a sanitized view and
**0** views contain an answer token.

## T0 placement does not use the target location

The formal template baseline keeps the payload text fixed and selects the first
comment-capable source file in the deterministic public index. Its candidates record
`placement_basis: static_public_index`. T1 uses the index to rank a repository-relevant
symbol and records `repository_index`; T2 records `oracle_view`. The direct generator
API still accepts `legacy_target_anchor` only for v1 byte-parity tests; the campaign
pipeline never supplies it.

## Why T3/T4 are absent

T3 needs an isolated surrogate gateway; T4 needs an adaptation/evaluation split, its
own query budget and a holdout. Neither exists, and returning a T2 render under a
T3/T4 label would make the ablation report an effect it never measured. Both tiers
raise `UnsupportedTierError`, and `campaign plan` refuses to freeze a condition that
names them.
