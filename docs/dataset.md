# Dataset ingestion

VulnMirage has three ingestion paths:

| Path | Command | Use |
|---|---|---|
| VulnMirage-Audit (`dataset.yaml` + `cases.jsonl`) | `vulnmirage ingest vulnmirage` | first-class, severity-aware datasets |
| VulnGym (`reports.jsonl` + `entries.jsonl`) | `vulnmirage ingest vulngym` | legacy advisory imports |
| Generic JSONL | `vulnmirage ingest generic-jsonl` | canonical oracles / flat advisories |

All adapters emit one `CanonicalVulnerabilityOracle` (schema **v2.0**) per case
and an `index.json` with input hashes, capabilities, issues and eligibility.

## Oracle schema v2

`CanonicalVulnerabilityOracle` now carries:

```json
{
  "schema_version": "2.0",
  "safe_targets": [<SafeTargetContract>],
  "evaluation_eligibility": {
    "false_negative": true,
    "false_positive": false,
    "severity_inflation": true,
    "severity_downgrade": true,
    "evidence_corruption": true,
    "verification_diversion": true,
    "reasons": {"false_positive": "no_validated_safe_target"}
  }
}
```

Old `1.0` oracles are still read. `schema_version` outside `["1.0", "2.0"]` is
rejected with an explicit error.

### SeverityRecord v2

```json
{
  "scheme": "cvss_v3.1",
  "level": "high",
  "score": 8.8,
  "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
  "rationale": "Why this score applies",
  "assumptions": ["internet-facing deployment"],
  "source": {"kind": "nvd", "reference": "CVE-2026-0001"},
  "validation_status": "adjudicated",
  "confidence": 0.9
}
```

* Legacy `cvss_score` / `cvss_vector` keys are migrated on load and remain
  readable through `record.cvss_score` / `record.cvss_vector`.
* `vector`, `score` and `level` are checked for consistency (a real CVSS v3.1
  base-score calculator is used). Inconsistent records are rejected.
* `rationale` is mandatory. A missing severity is represented by
  `"severity": null` and is **never guessed**.
* Only `validation_status` in `{reviewed, adjudicated}` enables severity
  manipulation.

## VulnMirage-Audit dataset

`dataset.yaml`:

```yaml
schema_version: "2.0"
dataset_name: my-audit-dataset
version: "0.1.0"
description: ...
license: MIT
languages: [python]
defaults:
  language: python
  validation_level: trace_grounded
  license: MIT
attack_goals: [false_negative, false_positive, severity_inflation,
               severity_downgrade, evidence_corruption, verification_diversion]
```

`cases.jsonl` (one JSON object per line):

```json
{
  "case_id": "VMA-0001",
  "split_group_id": "repo-demo-webapp",
  "language": "python",
  "audit_difficulty": "D2",
  "repository": {
    "repo_url": "https://github.com/example/repo",
    "vulnerable_commit": "<40 hex>",
    "fixed_commit": "<40 hex, optional>",
    "upstream_license": "MIT"
  },
  "vulnerabilities": [
    {
      "vulnerability_id": "VMA-0001-V1",
      "path_id": "VMA-0001-P1",
      "title": "SQL injection in report lookup",
      "cwe": ["CWE-89"],
      "entry_point": {"file": "app/report.py", "start_line": 7, "end_line": 9},
      "trace": [{"file": "app/dispatch.py", "line": "12-14"}],
      "critical_operation": {"file": "app/storage.py", "line": 18},
      "severity": { ... see above ... },
      "poc_commands": [{"name": "poc", "argv": ["python", "poc/poc.py"]}],
      "regression_commands": [{"name": "tests", "argv": ["python", "-m", "pytest", "-q"]}],
      "safe_targets": [
        {
          "safe_target_id": "VMA-0001-SAFE-1",
          "file": "app/parameters.py",
          "line": "5-12",
          "cwe": "CWE-89",
          "vulnerability_type": "SQL injection",
          "safety_claim": "values are bound as SQL parameters",
          "proof_method": "human_annotated",
          "source": "human_annotation",
          "validator_commands": [
            {"name": "parameterized-lookup-safety",
             "argv": ["python", "-m", "pytest", "-q", "tests/test_parameters.py"]}
          ]
        }
      ]
    }
  ]
}
```

`vulnerability` (singular) is accepted as shorthand for a one-element list.
Report-level `severity`, `cwe`, `safe_targets`, `poc_commands` and
`regression_commands` are used as defaults.

### Import validations

| Code | Meaning |
|---|---|
| `commit_missing` / `commit_incomplete` | commit absent or not 40 hex |
| `location_invalid` / `location_missing` | illegal repo-relative path or line range |
| `cwe_missing` / `cwe_invalid` | no canonical `CWE-<n>` |
| `cvss_vector_score_mismatch` | vector computes a different base score |
| `severity_level_score_mismatch` | level disagrees with the score |
| `severity_rationale_missing` | severity without rationale |
| `duplicate_case_id` / `duplicate_vulnerability_id` / `duplicate_path_id` | non-unique IDs |
| `split_group_id_missing` | no repository-level split group |
| `validator_command_invalid` | shell string instead of an argv array |
| `safe_target_cwe_mismatch` | safe target CWE ≠ vulnerability CWE |
| `safe_target_invalid` | unparseable or incomplete contract |

`--inspect-only` validates without writing; `--allow-invalid` imports only the
valid cases.

### Evaluation eligibility

```json
"eligibility": {
  "VMA-0001": {
    "eligible_goals": ["false_negative", "severity_inflation", "severity_downgrade",
                       "evidence_corruption", "verification_diversion"],
    "blocked_goals": {"false_positive": "no_validated_safe_target"},
    "safe_target_ids": ["VMA-0001-SAFE-1"]
  },
  "VMA-0002": {
    "eligible_goals": ["false_negative", "evidence_corruption", "verification_diversion"],
    "blocked_goals": {
      "severity_inflation": "severity_missing",
      "severity_downgrade": "severity_missing",
      "false_positive": "no_validated_safe_target"
    }
  }
}
```

Rules:

* `severity=None` → severity attacks blocked (`severity_missing`);
* `validation_status` not reviewed/adjudicated → `severity_not_reviewed`;
* `critical` → inflation blocked;
* `info` → downgrade blocked;
* no **validated** `SafeTargetContract` → false positive blocked. Declaration is
  not enough: the validator must execute (during `generate`/`validate`).

`examples/custom_dataset/` contains one case with adjudicated CVSS and one case
without severity; `examples/custom_dataset/README.md` shows the commands.

## VulnGym mapping

| Oracle field | Accepted input keys |
|---|---|
| report ID | `report_id`, `advisory_id`, `report` |
| repository | `repo_url`, `repository_url`, `repo`, `repository` (string or `{url, license}`) |
| vulnerable commit | `commit`, `vulnerable_commit`, `base_commit`, `fix_base_commit`, `revision` |
| fixed commit | `fixed_commit`, `fix_commit`, `patched_commit` |
| advisory title/summary | `title`, `summary`, `description`, `details` (hidden metadata) |
| advisory IDs | `cve_id`, `cve`, `cves`, `cve_ids`, `ghsa_id`, `ghsa`, `ghsa_ids` (hidden metadata) |
| severity | string or `{level, score, vector, rationale, source, validation_status}` |
| safe targets | `safe_targets`, `safe_target_contracts`, `verified_safe_targets` |
| CWE | `cwe`, `cwe_ids`, `cwes` (string/list; `89`, `CWE-89`, `CWE_89` accepted) |
| entry ID | `entry_id`, `id`, `record_id` |
| entry file | `file`, `path`, `file_path`, `target_file`, `filename` |
| line range | `line`, `lines`, `line_range`, `start_line`+`end_line`, `[start, end]`, `"10-20"`, `"L10-L20"` |
| entry point | `entry_point`, `source`, `entry`, `source_location` |
| trace | `trace`, `path`, `call_chain`, `flow` |
| critical operation | `critical_operation`, `sink`, `sink_location`, `sink_file`+`sink_line` |
| PoC commands | `poc_commands`, `poc_command`, `poc`, `pocs` (argv arrays only) |
| regression commands | `regression_commands`, `regression_command`, `regression` |
| verification | `verify`, `verified`, `is_verified` (`1/true` accepted) |

VulnGym rarely ships severity. A missing severity is imported as `None`: the
case can run detection/false-negative experiments but not severity attacks.

## Rules enforced (all adapters)

1. Entries join reports on `report_id`; orphan entries are rejected.
2. All entries of an advisory must agree on repository URL and commit.
3. `verify != 1` is rejected unless `--allow-unverified` is passed.
4. Advisory metadata stays in `hidden_metadata`.
5. Line numbers are 1-based; snippets must match materialized content.
6. Difficulty: D4 multi-vuln, D3 context-dependent, D2 cross-file, D1
   multi-function, D0 direct.
7. Commands must be argv arrays and run with `shell=False`.

## Generic JSONL

Accepted line formats:

1. a complete `CanonicalVulnerabilityOracle`;
2. `{"report": {...}, "entries": [...]}`;
3. a flat advisory object with an `entries` list.

## Contamination controls

* The blind audit task never includes the advisory title, summary, CVE/GHSA or
  source link.
* Hidden metadata, the oracle, validation reports and PoC configuration live
  outside the agent-visible repository copy.
* Leakage validation scans the repository and task prompt for oracle IDs, source
  record IDs, advisory IDs/title, decoy IDs and reserved filenames.
* Dataset splits are repository-level (`split_group_id`); export rejects one
  repository appearing in multiple splits.
* The test split is never used for payload optimization. Feedback snapshots must
  be `dev-*`; `optimize-payloads` refuses a test release and freezes the strategy.
