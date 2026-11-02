"""Per-run artifact contract: findings, deterministic report and manifest.

Producer boundaries:

* the tested agent produces the raw final answer and its findings;
* the harness/runtime produces process output, events and file access;
* the evaluator (not the agent) produces matches, metrics and process
  annotations.

This module writes the *normalised* artifacts and a manifest that records path,
kind, producer, status, size, sha256, schema version, input hashes and an explicit
``missing_reason``.  It never rewrites the raw answer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..hashing import atomic_write_json, atomic_write_text, sha256_file, sha256_text
from ..models import ObservabilityGrade

ARTIFACT_SCHEMA_VERSION = "1.0"

_ARTIFACT_KINDS: dict[str, tuple[str, str, str]] = {
    # name: (kind, producer, schema_version)
    "run.json": ("manifest", "harness", "1.0"),
    "meta.json": ("manifest", "harness", "1.0"),
    "stdout.log": ("process_output", "harness", "1.0"),
    "stderr.log": ("process_output", "harness", "1.0"),
    "final_raw.txt": ("raw_answer", "agent", "1.0"),
    "findings.json": ("normalized_findings", "evaluator", "1.0"),
    "audit_report.md": ("human_report", "evaluator", "1.0"),
    "events.raw.jsonl": ("raw_events", "harness", "1.0"),
    "events.normalized.jsonl": ("normalized_events", "harness", "1.0"),
    "tool_calls.jsonl": ("tool_calls", "harness", "1.0"),
    "file_access.jsonl": ("file_access", "harness", "1.0"),
    "process_events.jsonl": ("process_events", "harness", "1.0"),
    "trajectory_enriched.jsonl": ("derived_trajectory", "evaluator", "1.0"),
    "verification_assessments.json": ("verification", "evaluator", "1.0"),
    "matches.json": ("matches", "evaluator", "1.0"),
    "metrics.json": ("metrics", "evaluator", "1.0"),
}

#: Derived artifacts and the immediate input they are computed from.
_DERIVED_FROM = {
    "events.normalized.jsonl": "events.raw.jsonl",
    "tool_calls.jsonl": "events.normalized.jsonl",
    "file_access.jsonl": "events.normalized.jsonl",
    "process_events.jsonl": "events.normalized.jsonl",
    "trajectory_enriched.jsonl": "events.normalized.jsonl",
    "verification_assessments.json": "events.normalized.jsonl",
    "findings.json": "final_raw.txt",
    "audit_report.md": "findings.json",
    "matches.json": "findings.json",
    "metrics.json": "findings.json",
}


def observation_capabilities(
    *,
    events: list[Any],
    file_access: list[Any],
    importer: str | None = None,
    grade: str = "D",
    parse_status: str = "not_attempted",
) -> dict[str, Any]:
    """Per-capability flags derived from the actual artifacts.

    A/B grades are retained for compatibility, but each metric additionally
    checks the specific capability it needs.
    """
    tool_results = [item for item in events if item.event_type.value == "tool_result"]
    commands = [item for item in events if item.event_type.value == "command"]
    timestamps = [item.monotonic_ns for item in events]
    timestamps_reliable = bool(timestamps) and all(
        later >= earlier for earlier, later in zip(timestamps, timestamps[1:])
    )
    return {
        "importer": importer,
        "grade": grade,
        "native_event_count": len([item for item in events if item.source.value == "native_agent"]),
        "can_observe_file_access": bool(file_access),
        "can_prove_content_return": any(
            getattr(item, "content_returned_to_model", False) for item in file_access
        ),
        "can_observe_tool_results": bool(tool_results),
        "can_observe_exit_code": any(item.exit_code is not None for item in commands),
        "can_measure_tokens": any(
            item.input_tokens is not None or item.output_tokens is not None for item in events
        ),
        "can_link_citations": parse_status == "ok",
        "timestamps_reliable": timestamps_reliable,
        "output_parsed": parse_status == "ok",
        "notes": [
            "OS-level file access never proves content returned to the model",
            "missing capabilities make the corresponding metrics not evaluable, not zero",
        ],
    }


def _findings_payload(parsed, parse_status: str, parse_error: str | None, raw_sha: str | None) -> dict[str, Any]:
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
        "findings": [item.model_dump(mode="json") for item in envelope.findings],
        "audit_summary": envelope.audit_summary.model_dump(mode="json"),
    }


def user_raw_sha(parsed_sha: str, raw_sha: str | None) -> str | None:
    return parsed_sha or raw_sha


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
        if finding.get("entry_point"):
            entry = finding["entry_point"]
            lines.append(
                f"- Entry point: {entry.get('file')}:{entry.get('start_line')}-{entry.get('end_line')}"
            )
        if finding.get("critical_operation"):
            sink = finding["critical_operation"]
            lines.append(
                f"- Critical operation: {sink.get('file')}:{sink.get('start_line')}-{sink.get('end_line')}"
            )
        lines.append(f"- Exploitability: {finding.get('exploitability')}")
        if finding.get("evidence"):
            lines.append("- Evidence:")
            lines.extend(f"  - {item}" for item in finding["evidence"])
        citations = finding.get("evidence_citations") or []
        if citations:
            lines.append("- Evidence citations:")
            for citation in citations:
                location = citation.get("location") or {}
                lines.append(
                    f"  - {citation.get('citation_id')} ({citation.get('evidence_kind')}): "
                    f"{citation.get('claim')} "
                    f"[{location.get('file')}:{location.get('start_line')}-{location.get('end_line')}]"
                )
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


def write_findings_and_report(
    run_dir: Path,
    *,
    parsed,
    parse_status: str,
    parse_error: str | None,
    final_raw_path: Path | None,
) -> dict[str, Any]:
    run_dir = Path(run_dir)
    raw_sha = sha256_file(final_raw_path) if final_raw_path and final_raw_path.is_file() else None
    payload = _findings_payload(parsed, parse_status, parse_error, raw_sha)
    findings_path = run_dir / "findings.json"
    atomic_write_json(findings_path, payload)
    report_path = run_dir / "audit_report.md"
    atomic_write_text(report_path, render_audit_report_markdown(payload))
    return {
        "findings_sha256": sha256_file(findings_path),
        "report_sha256": sha256_file(report_path),
        "status": payload["status"],
    }


def build_artifact_manifest(
    run_dir: Path,
    *,
    run_id: str,
    purpose: str,
    observation_capabilities: dict[str, Any],
    parse_status: str,
) -> dict[str, Any]:
    run_dir = Path(run_dir)
    hashes: dict[str, str] = {}
    entries: list[dict[str, Any]] = []
    for name, (kind, producer, schema_version) in _ARTIFACT_KINDS.items():
        if name in {"meta.json", "run.json"}:
            continue
        path = run_dir / name
        input_name = _DERIVED_FROM.get(name)
        input_sha = None
        if input_name and (run_dir / input_name).is_file():
            input_sha = sha256_file(run_dir / input_name)
        if not path.is_file():
            status = "not_produced"
            missing_reason = f"{name} was not produced by this run"
            if name in {"events.raw.jsonl", "events.normalized.jsonl"} and not observation_capabilities.get(
                "native_event_count"
            ):
                status = "unsupported"
                missing_reason = "no verified native trace importer matched this runtime"
            entries.append(
                {
                    "path": name,
                    "kind": kind,
                    "producer": producer,
                    "status": status,
                    "size": None,
                    "sha256": None,
                    "schema_version": schema_version,
                    "inputs_sha256": input_sha,
                    "missing_reason": missing_reason,
                }
            )
            continue
        size = path.stat().st_size
        digest = sha256_file(path)
        hashes[name] = digest
        status = "ok"
        reason = None
        if name == "findings.json" and parse_status != "ok":
            status = "invalid"
            reason = "parse failed; findings are excluded from metrics"
        if size == 0 and name.endswith(".jsonl"):
            status = "supported_empty"
            reason = "the producer was supported but emitted no events"
        if name == "events.raw.jsonl" and not observation_capabilities.get("native_event_count"):
            status = "unsupported"
            reason = "runtime did not provide a verified native event stream"
        entries.append(
            {
                "path": name,
                "kind": kind,
                "producer": producer,
                "status": status,
                "size": size,
                "sha256": digest,
                "schema_version": schema_version,
                "inputs_sha256": input_sha,
                "missing_reason": reason,
            }
        )
    manifest = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "run_id": run_id,
        "purpose": purpose,
        "observability_grade": observation_capabilities.get("grade"),
        "observation_capabilities": observation_capabilities,
        "artifacts": entries,
        "status_counts": _status_counts(entries),
    }
    path = run_dir / "artifact_manifest.json"
    atomic_write_json(path, manifest)
    return {
        "manifest": manifest,
        "path": path,
        "sha256": sha256_file(path),
        "artifact_hashes": hashes,
    }


def _status_counts(entries: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    return counts


def validate_manifest(run_dir: Path) -> dict[str, Any]:
    """Check file presence, hashes, derived inputs and report consistency."""
    run_dir = Path(run_dir)
    errors: list[str] = []
    warnings: list[str] = []
    manifest_path = run_dir / "artifact_manifest.json"
    if not manifest_path.is_file():
        return {
            "ok": False,
            "errors": ["artifact_manifest.json is missing"],
            "warnings": [],
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest.get("artifacts", []):
        name = entry["path"]
        status = entry["status"]
        path = run_dir / name
        if status in {"not_produced", "unsupported"}:
            if path.exists() and not entry.get("missing_reason"):
                errors.append(f"{name}: status {status} without missing_reason")
            continue
        if not path.is_file():
            errors.append(f"{name}: manifest says {status} but the file is missing")
            continue
        digest = sha256_file(path)
        if entry.get("sha256") and digest != entry["sha256"]:
            errors.append(f"{name}: sha256 does not match the manifest")
        if entry.get("size") is not None and path.stat().st_size != entry["size"]:
            errors.append(f"{name}: size does not match the manifest")
        input_name = _DERIVED_FROM.get(name)
        if input_name:
            input_path = run_dir / input_name
            if not input_path.is_file():
                errors.append(f"{name}: derived input {input_name} is missing")
            elif entry.get("inputs_sha256") and sha256_file(input_path) != entry["inputs_sha256"]:
                errors.append(f"{name}: input hash for {input_name} is stale")
    findings_path = run_dir / "findings.json"
    report_path = run_dir / "audit_report.md"
    if findings_path.is_file() and report_path.is_file():
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        report = report_path.read_text(encoding="utf-8")
        if findings.get("status") == "ok":
            count = len(findings.get("findings") or [])
            if f"- Findings: {count}" not in report:
                errors.append("audit_report.md finding count disagrees with findings.json")
            for finding in findings.get("findings") or []:
                if finding.get("title") and finding["title"] not in report:
                    warnings.append(
                        f"finding {finding.get('finding_id')} title missing from audit_report.md"
                    )
        else:
            if "did not produce a parseable report" not in report:
                errors.append("failed findings.json rendered as a successful report")
            if "The agent reported no findings." in report:
                errors.append("format failure rendered as 'no findings'")
    meta_paths = [run_dir / "meta.json", run_dir / "run_meta.json"]
    meta = None
    for path in meta_paths:
        if path.is_file():
            meta = json.loads(path.read_text(encoding="utf-8"))
            if meta.get("artifact_manifest_sha256") and meta["artifact_manifest_sha256"] != sha256_file(
                manifest_path
            ):
                errors.append("meta.json artifact_manifest_sha256 is stale")
            break
    if meta is None:
        warnings.append("meta.json is missing; manifest hash cannot be cross-checked")
    if meta is not None:
        expected_purpose = meta.get("purpose", "evaluation")
        if manifest.get("purpose") != expected_purpose:
            errors.append("artifact_manifest purpose disagrees with run meta")
        if (
            meta.get("observation_capabilities")
            and manifest.get("observation_capabilities")
            and meta["observation_capabilities"] != manifest["observation_capabilities"]
        ):
            warnings.append("observation capabilities differ between meta and manifest")
    return {"ok": not errors, "errors": errors, "warnings": warnings}

