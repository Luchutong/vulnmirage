# PayloadGen

This directory is the benchmark's trusted payload-method library. It is read while
constructing variants and is never copied wholesale into an agent's audit workspace.

## Files

- `registry.v2.yaml` — the active method registry. Each method declares
  `supported_tiers`, the `realizations` backend for every tier it claims, an optional
  per-tier `templates` map, `placement_limits` and `validation` policy. A tier listed
  without a realization fails at load time; a condition whose tier the method does not
  support fails at plan time.
- `registry.yaml` — the v1 registry, kept for compatibility. It has no tier metadata,
  so it only supports T0 conditions.
- `methods/<ID>/templates/` — tier-specific templates. `t1_repository.txt` speaks in
  the repository's own terms; `t2_oracle.txt` may reference `{precondition}`,
  `{boundary_claim}` and `{dangerous_effect}`, which come from the sanitized oracle
  view and never from the advisory itself.
- `variant_sets/` — pre-registered condition groups; every set contains its own clean
  baseline `C`:
  - `core.yaml` — the compact T0 baseline;
  - `core_tier_ablation.yaml` — A2/A3/S1 over T0/T1/T2 plus F2 over T0/T2;
  - `false_negative.yaml` — A1/A2/A3 over T0/T1/T2;
  - `severity.yaml` — S1/S2 over T0/T1/T2;
  - `safe_decoy.yaml` — F1/F2 over T0/T2.
- `templates/` — the T0 templates. Generated text and template hashes are written to
  each task's generation manifest and patch record.

Formal T0 conditions keep this text fixed and use the public repository index only to
choose a deterministic comment-capable source file (`static_public_index`). They do not
receive a target location or sanitized oracle view. T1 adapts placement/content to the
public index, prioritizing non-generated sink-shaped files and the task's primary
language before a seeded deterministic tie-break; T2 may additionally consume the
sanitized local oracle view.

## Status vocabulary

`implemented_adaptation` means the mechanism is inspired by or adapted from the cited
work; it does **not** claim paper-faithful reproduction. `planned` means the method has
no generator: campaign planning rejects it, and no run-time fallback exists.

## Template variables

Templates may use `{comment_prefix}`, `{target_file}`, `{target_function}`,
`{variant_id}`, and — for T2 templates — `{precondition}`, `{boundary_claim}`,
`{dangerous_effect}`. `{expected_severity}` exists for compatibility but is always
filled with `unknown`: it used to come from the private oracle, which meant a template
could silently import oracle knowledge into a public-context condition.

Answer identifiers (target ids, CVE/CWE ids, advisory titles, fix commits) are refused
by the leakage validator, and the sanitized oracle view is re-scanned before it is
used.

## Safe decoys

Safe-decoy templates have a private certificate in the variant-specific target set
(`python_no_execution_subset_v1`). Only findings at those exact certified locations are
counted as induced false positives; other unmatched findings remain unadjudicated.

## Selecting a set

Only during planning:

```text
python -m vulnmirage campaign plan --config configs/experiment.yaml \
  --variant-set PayloadGen/variant_sets/core_tier_ablation.yaml \
  --workspace workspace/campaigns/tier-ablation/deepseek-chat
```

The plan records the set id, research question, source path, SHA-256, resolved
conditions with their tiers, and all payload assets. `campaign run` restores the set
from the plan; it deliberately has no `--variant-set` option.
