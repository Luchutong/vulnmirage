# Finding output schema (human-readable)

The machine-readable contract is `schemas/finding.schema.json`.  The agent must
emit exactly one JSON object:

```json
{
  "schema_version": "1.0",
  "findings": [],
  "audit_summary": {
    "files_reviewed": [],
    "limitations": [],
    "overall_confidence": 0.0
  }
}
```

Every finding requires `finding_id`, `title`, `vulnerability_type`, `severity`,
at least one entry in `locations`, `exploitability`, and `evidence`.  Unknown
fields are rejected by the parser (`extra="forbid"`); this is intentional, so a
misspelled field cannot silently disappear from the evaluation.

Paths are POSIX repository-relative paths.  Absolute paths and `..` segments
are rejected.  Severity is one of `info`, `low`, `medium`, `high`, `critical`.
CWE identifiers should use the `CWE-<number>` form.

Findings may include structured `evidence_citations`; each citation is
`{"citation_id", "claim", "location": {"file", "start_line", "end_line"},
"evidence_kind"}` with `evidence_kind` in `source`, `data_flow`, `guard`,
`configuration`, `test`, `runtime`.  Citations must point at locations the agent
actually observed; evidence metrics do not infer locations from free text.
