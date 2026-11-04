"""Artifact writers for one audit: findings, the agent's report, and consistency.

Producer boundaries:

* the tested agent produces the raw final answer and the report/findings inside it;
* this module writes the *normalized* copies and a deterministic evaluator view;
* it never rewrites the raw answer and never calls a model to repair output.

A parse failure is rendered as a failure.  It must never look like "the agent found
nothing", because that would silently inflate recall.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..hashing import atomic_write_json, atomic_write_text, sha256_file

ARTIFACT_SCHEMA_VERSION = "1.0"


def _findings_payload(
    parsed, parse_status: str, parse_error: str | None, raw_sha: str | None
) -> dict[str, Any]:
    if parsed is None:
        return {
            "schema_version": ARTIFACT_SCHEMA_VERSION,
            "status": parse_status if parse_status != "ok" else "invalid",
            "failed": True,
            "excluded_from_metrics": True,
            "findings": [],
            "audit_summary": {
                "files_reviewed": [],
                "limitations": [],
                "overall_confidence": 0.0,
            },
            "raw_sha256": raw_sha,
            "parse_method": None,
            "warnings": [],
            "parse_error": parse_error or "no parseable final answer",
            "missing_reason": (
                "final_raw.txt is missing" if raw_sha is None else "output could not be parsed"
            ),
        }
    envelope = parsed.envelope
    return {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "status": "ok",
        "failed": False,
        "excluded_from_metrics": False,
        "raw_sha256": parsed.raw_sha256 or raw_sha,
        "parse_method": parsed.extraction,
        "warnings": list(parsed.warnings),
        "duplicates_removed": parsed.duplicates_removed,
        "output_contract": parsed.output_contract,
        "ignored_keys": list(parsed.ignored_keys),
        "findings": [item.model_dump(mode="json") for item in envelope.findings],
        "audit_summary": envelope.audit_summary.model_dump(mode="json"),
    }


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        key = str(finding.get("severity", "unknown"))
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def render_audit_report_markdown(payload: dict[str, Any]) -> str:
    """Deterministic Markdown rendering of ``findings.json`` (no second LLM)."""
    status = payload.get("status", "invalid")
    lines: list[str] = ["# Security Audit Report", ""]
    if status != "ok":
        lines.extend(
            [
                "## Audit status",
                "",
                f"**{status.upper()}** - the audit did not produce a parseable report.",
                "",
                f"- Reason: {payload.get('parse_error') or payload.get('missing_reason') or 'unknown'}",
                "- The findings below are intentionally empty; this is **not** a clean result.",
                "- This run is excluded from recall/precision denominators.",
                "",
            ]
        )
        return "\n".join(lines) + "\n"
    summary = payload.get("audit_summary") or {}
    findings = payload.get("findings") or []
    counts = _severity_counts(findings)
    lines.extend(
        [
            "## Audit status",
            "",
            "- Status: completed and parsed",
            f"- Findings: {len(findings)}",
            "- Severity counts: "
            + (", ".join(f"{key}={value}" for key, value in counts.items()) or "none"),
            f"- Overall confidence: {summary.get('overall_confidence', 0.0)}",
            "",
            "## Scope",
            "",
        ]
    )
    reviewed = summary.get("files_reviewed") or []
    lines.extend([f"- {item}" for item in reviewed] or ["- not reported by the agent"])
    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("The agent reported no findings.")
        lines.append("")
    for index, finding in enumerate(findings, start=1):
        lines.append(f"### {index}. {finding.get('title', 'untitled')}")
        lines.append("")
        lines.append(f"- Id: {finding.get('finding_id')}")
        lines.append(f"- Type: {finding.get('vulnerability_type')}")
        lines.append(f"- CWE: {', '.join(finding.get('cwe') or []) or 'not stated'}")
        lines.append(f"- Severity: {finding.get('severity')}")
        lines.append(f"- Confidence: {finding.get('confidence')}")
        locations = finding.get("locations") or []
        if locations:
            rendered = ", ".join(
                f"{item.get('file')}:{item.get('start_line')}-{item.get('end_line')}"
                for item in locations
            )
            lines.append(f"- Locations: {rendered}")
        for key, label in (
            ("entry_point", "Entry point"),
            ("critical_operation", "Critical operation"),
        ):
            location = finding.get(key)
            if location:
                lines.append(
                    f"- {label}: {location.get('file')}:"
                    f"{location.get('start_line')}-{location.get('end_line')}"
                )
        lines.append(f"- Exploitability: {finding.get('exploitability')}")
        if finding.get("evidence"):
            lines.append("- Evidence:")
            lines.extend(f"  - {item}" for item in finding["evidence"])
        if finding.get("remediation"):
            lines.append(f"- Remediation: {finding['remediation']}")
        lines.append("")
    limitations = summary.get("limitations") or []
    lines.append("## Limitations")
    lines.append("")
    lines.extend([f"- {item}" for item in limitations] or ["- none reported"])
    warnings = payload.get("warnings") or []
    if warnings:
        lines.extend(["", "## Parse warnings", ""])
        lines.extend(f"- {item}" for item in warnings)
    lines.append("")
    return "\n".join(lines)


def write_agent_report(run_dir: Path, *, parsed, parse_status: str) -> dict[str, Any]:
    """Write the agent's own report verbatim (never repaired by the harness)."""
    run_dir = Path(run_dir)
    path = run_dir / "agent_report.md"
    report = getattr(parsed, "report_markdown", None) if parsed is not None else None
    if parse_status != "ok" or not report or not str(report).strip():
        if path.exists():
            path.unlink()
        return {
            "written": False,
            "path": None,
            "sha256": None,
            "missing_reason": (
                "answer could not be parsed"
                if parse_status != "ok"
                else "the answer carried no report_markdown"
            ),
        }
    atomic_write_text(path, str(report).rstrip() + "\n")
    return {"written": True, "path": path, "sha256": sha256_file(path), "missing_reason": None}


def write_output_consistency(
    run_dir: Path,
    *,
    parsed,
    parse_status: str,
    max_report_chars: int | None = None,
    require_report: bool = True,
) -> dict[str, Any]:
    """Record how the report and the findings correspond for this run."""
    from ..evaluation.parser import output_consistency

    run_dir = Path(run_dir)
    if parse_status != "ok":
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "status": "no_output",
            "consistent": False,
            "report_present": False,
            "notes": [f"parse_status={parse_status}: consistency is not evaluable"],
        }
    else:
        payload = output_consistency(
            parsed, max_report_chars=max_report_chars, require_report=require_report
        ).model_dump(mode="json")
    path = run_dir / "output_consistency.json"
    atomic_write_json(path, payload)
    return {"status": payload.get("status"), "sha256": sha256_file(path), "path": path}


def write_findings_and_report(
    run_dir: Path,
    *,
    parsed,
    parse_status: str,
    parse_error: str | None,
    final_raw_path: Path | None,
    max_report_chars: int | None = None,
    require_report: bool = True,
) -> dict[str, Any]:
    """Write the four per-run answer artifacts and return their digests."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    raw_sha = sha256_file(final_raw_path) if final_raw_path and final_raw_path.is_file() else None
    payload = _findings_payload(parsed, parse_status, parse_error, raw_sha)
    findings_path = run_dir / "findings.json"
    atomic_write_json(findings_path, payload)
    report_path = run_dir / "audit_report.md"
    atomic_write_text(report_path, render_audit_report_markdown(payload))
    agent_report = write_agent_report(run_dir, parsed=parsed, parse_status=parse_status)
    consistency = write_output_consistency(
        run_dir,
        parsed=parsed,
        parse_status=parse_status,
        max_report_chars=max_report_chars,
        require_report=require_report,
    )
    return {
        "findings_sha256": sha256_file(findings_path),
        "report_sha256": sha256_file(report_path),
        "agent_report_sha256": agent_report["sha256"],
        "agent_report_missing_reason": agent_report["missing_reason"],
        "output_consistency_status": consistency["status"],
        "output_consistency_sha256": consistency["sha256"],
        "status": payload["status"],
    }


__all__ = [
    "ARTIFACT_SCHEMA_VERSION",
    "render_audit_report_markdown",
    "write_agent_report",
    "write_findings_and_report",
    "write_output_consistency",
]
