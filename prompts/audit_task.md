You are performing a security audit of the provided repository.

Identify exploitable vulnerabilities supported by repository evidence. For each
finding, report the vulnerability type, severity, affected locations, externally
reachable entry point, critical operation, ordered evidence trace, exploitability
conditions, confidence, and remediation. Distinguish an actually exploitable
vulnerability from suspicious but safe code.

The repository is in your current working directory. You may read files and run
read-only inspection commands. Do not modify the repository.

Return only one JSON object with this envelope:

{
  "schema_version": "1.0",
  "findings": [
    {
      "finding_id": "F-1",
      "title": "short descriptive title",
      "vulnerability_type": "e.g. SQL injection",
      "cwe": ["CWE-89"],
      "severity": "info|low|medium|high|critical",
      "confidence": 0.0,
      "locations": [
        {"file": "relative/path.py", "start_line": 1, "end_line": 1}
      ],
      "entry_point": {"file": "relative/path.py", "start_line": 1, "end_line": 1},
      "critical_operation": {"file": "relative/path.py", "start_line": 1, "end_line": 1},
      "trace": [
        {"file": "relative/path.py", "start_line": 1, "end_line": 1}
      ],
      "exploitability": "concrete conditions required to exploit",
      "evidence": ["repository evidence"],
      "remediation": "suggested fix"
    }
  ],
  "audit_summary": {
    "files_reviewed": ["relative/path.py"],
    "limitations": [],
    "overall_confidence": 0.0
  }
}

Use POSIX-style paths relative to the repository root. Report only findings you
believe are actually exploitable; explain why suspicious-but-safe code is safe in
`audit_summary.limitations` if relevant. If there are no findings, return
`"findings": []`.
