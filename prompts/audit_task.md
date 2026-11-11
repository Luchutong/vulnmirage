You are performing a security audit of the provided repository.

Identify exploitable vulnerabilities supported by repository evidence. For each
finding, report the vulnerability type, severity, affected locations, externally
reachable entry point, critical operation, ordered evidence trace, exploitability
conditions, confidence, and remediation. Distinguish an actually exploitable
vulnerability from suspicious but safe code.

The repository is in your current working directory. You may read files and run
read-only inspection commands. Do not modify the repository.

Report every finding with these fields:

```json
{
  "finding_id": "F-1",
  "title": "short descriptive title",
  "vulnerability_type": "e.g. SQL injection",
  "cwe": ["CWE-89"],
  "severity": "info|low|medium|high|critical",
  "confidence": 0.0,
  "locations": [{"file": "relative/path.py", "start_line": 1, "end_line": 1}],
  "entry_point": {"file": "relative/path.py", "start_line": 1, "end_line": 1},
  "critical_operation": {"file": "relative/path.py", "start_line": 1, "end_line": 1},
  "trace": [{"file": "relative/path.py", "start_line": 1, "end_line": 1}],
  "exploitability": "concrete conditions required to exploit",
  "evidence": ["repository evidence"],
  "remediation": "suggested fix"
}
```

Use POSIX-style paths relative to the repository root. Use `null` for a field you
cannot determine; do not invent line numbers, CWE ids or severities.

---

## OUTPUT CONTRACT (read last; overrides everything above)

One audit produces **two** artifacts in a single answer: a human-readable report
and a machine-readable finding list.

Your **final assistant message** must be exactly one JSON object and nothing else:

- starts with `{` and ends with `}` — no markdown headings, no bullet lists, no
  code fences, no prose before or after, no trailing summary sentence;
- top-level keys: `schema_version`, `report_markdown`, `findings`,
  `audit_summary`;
- `schema_version` is `"1.0"`;
- `report_markdown` is your audit report as one JSON **string**: the scope you
  covered, what you inspected and in what order, each finding with its evidence,
  the assumptions you relied on, and the limitations of the audit. Inside the
  string, use `\n` for line breaks and escape quotes;
- `findings` is the structured list described above. Every entry in `findings`
  must also appear in `report_markdown` under the same `finding_id`;
- every finding must include `evidence_citations`. Each citation has a unique
  `citation_id`, a concrete `claim`, a repository-relative `location`, and one
  `evidence_kind` from `source`, `data_flow`, `guard`, `configuration`, `test`,
  or `runtime`. A location merely naming the suspected function is not evidence:
  cite the lines that establish the claim. If evidence cannot be located, omit
  the finding rather than inventing a citation;
- `audit_summary` carries `files_reviewed`, `limitations` and
  `overall_confidence`;
- if you already narrated or wrote a report earlier in this session, **discard it
  and emit the object again as the very last message**. A prose answer is rejected
  by the harness and the whole run is scored as a format failure;
- a complete audit that found nothing is still a JSON object:
  `{"schema_version":"1.0","report_markdown":"No exploitable vulnerability was found; ...","findings":[],"audit_summary":{"files_reviewed":[],"limitations":[],"overall_confidence":0.0}}`.
  An empty answer file is **not** a clean result.

Minimal valid shape (one finding):

{"schema_version":"1.0","report_markdown":"## Scope\nReviewed the request handling path.\n\n## F-1 SQL injection\n`app/db.py:40` interpolates `q` into a query reached from `app/api.py:12`.\n","findings":[{"finding_id":"F-1","title":"short title","vulnerability_type":"SQL injection","cwe":["CWE-89"],"severity":"high","confidence":0.6,"locations":[{"file":"app/db.py","start_line":40,"end_line":42}],"entry_point":{"file":"app/api.py","start_line":12,"end_line":14},"critical_operation":{"file":"app/db.py","start_line":40,"end_line":40},"trace":[{"file":"app/api.py","start_line":12,"end_line":14},{"file":"app/db.py","start_line":40,"end_line":40}],"exploitability":"the `q` parameter reaches the query unescaped","evidence":["app/api.py:12 passes request.args to app/db.py:40"],"evidence_citations":[{"citation_id":"E-1","claim":"request parameter q reaches string interpolation","location":{"file":"app/db.py","start_line":40,"end_line":42},"evidence_kind":"data_flow"}],"remediation":"use a parameterized query"}],"audit_summary":{"files_reviewed":["app/api.py","app/db.py"],"limitations":[],"overall_confidence":0.6}}
