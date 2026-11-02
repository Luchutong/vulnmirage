# examples/custom_dataset

A two-case reference dataset for the `VulnMirage-Audit` schema (`schema_version: 2.0`).

| Case | Severity | Eligible experiments |
| --- | --- | --- |
| `VMA-0001` | Adjudicated CVSS v3.1 (high, 8.8) | detection/FN, severity inflation/downgrade, evidence corruption, verification diversion, false positive (after the safe-target validator runs) |
| `VMA-0002` | none (deliberately) | detection/FN, evidence corruption, verification diversion |

`VMA-0002` demonstrates that a missing severity is imported successfully and is
**not** guessed: `false_negative=true`, `severity_inflation=false`,
`severity_downgrade=false` with reason `severity_missing`.

## Run it

Validate without writing anything:

```bash
vulnmirage ingest vulnmirage \
  --manifest examples/custom_dataset/dataset.yaml \
  --cases examples/custom_dataset/cases.jsonl \
  --inspect-only
```

Import the canonical oracles:

```bash
vulnmirage ingest vulnmirage \
  --manifest examples/custom_dataset/dataset.yaml \
  --cases examples/custom_dataset/cases.jsonl \
  --output workspace/normalized/vulnmirage-audit-demo
```

The commit hashes in `cases.jsonl` are illustrative placeholders. Replace them
with real 40-character commit hashes from your repository before running
`vulnmirage materialize`; import validation checks their *form*, not their
existence (existence is checked when the repository is materialized).

## What the importer validates

- repository URL present and commits are full 40-hex hashes;
- locations are repo-relative, line ranges are valid, entry ≠ sink;
- CWE values are canonical (`CWE-<n>`);
- CVSS vector, score and level agree (a real CVSS v3.1 calculator is used);
- every declared severity has a rationale;
- `case_id`, `vulnerability_id` and `path_id` are unique;
- `split_group_id` is present (repository-level dev/test isolation);
- validator commands are argv arrays, never shell strings;
- severity manipulation requires `validation_status: reviewed|adjudicated`;
- a critical vulnerability cannot be inflated and an info vulnerability cannot
  be downgraded;
- false-positive eligibility requires a **validated** `SafeTargetContract`.
