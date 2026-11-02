"""Artifact contract: findings.json, deterministic Markdown, manifest and capabilities."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.support import make_envelope, make_finding
from vulnmirage.evaluation.parser import parse_agent_output
from vulnmirage.harness.artifacts import (
    build_artifact_manifest,
    observation_capabilities,
    render_audit_report_markdown,
    validate_manifest,
    write_findings_and_report,
)
from vulnmirage.harness.opencode import split_json_stream
from vulnmirage.models import EventSource, EventType, FileAccessRecord, UnifiedEvent


def _parsed():
    envelope = make_envelope(make_finding())
    text = json.dumps(envelope.model_dump(mode="json"))
    return parse_agent_output(text)


def _event(event_type: EventType, *, source=EventSource.NATIVE, **kwargs) -> UnifiedEvent:
    return UnifiedEvent(
        event_id=kwargs.pop("event_id", "EV-1"),
        run_id="RUN-1",
        sequence=kwargs.pop("sequence", 0),
        timestamp_utc="2026-01-01T00:00:00Z",
        monotonic_ns=kwargs.pop("monotonic_ns", 1),
        event_type=event_type,
        source=source,
        **kwargs,
    )


def test_findings_and_markdown_report_are_consistent(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    raw = run_dir / "final_raw.txt"
    parsed = _parsed()
    raw.write_text(json.dumps(parsed.envelope.model_dump(mode="json")), encoding="utf-8")
    info = write_findings_and_report(
        run_dir,
        parsed=parsed,
        parse_status="ok",
        parse_error=None,
        final_raw_path=raw,
    )
    assert info["status"] == "ok"
    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    report = (run_dir / "audit_report.md").read_text(encoding="utf-8")
    assert len(findings["findings"]) == 1
    assert "- Findings: 1" in report
    assert "SQL injection" in report
    assert "app/storage.py:1-2" in report


def test_format_failure_is_not_rendered_as_no_vulnerabilities(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "final_raw.txt").write_text("not json", encoding="utf-8")
    info = write_findings_and_report(
        run_dir,
        parsed=None,
        parse_status="format_failure",
        parse_error="no JSON finding envelope could be extracted",
        final_raw_path=run_dir / "final_raw.txt",
    )
    assert info["status"] == "format_failure"
    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    assert findings["failed"] is True
    assert findings["excluded_from_metrics"] is True
    report = (run_dir / "audit_report.md").read_text(encoding="utf-8")
    assert "did not produce a parseable report" in report
    assert "The agent reported no findings." not in report


def test_markdown_rendering_is_deterministic() -> None:
    payload = {
        "status": "ok",
        "audit_summary": {"files_reviewed": ["app/storage.py"], "limitations": [], "overall_confidence": 0.5},
        "findings": [
            {
                "title": "SQL injection",
                "vulnerability_type": "SQL injection",
                "cwe": ["CWE-89"],
                "severity": "high",
                "confidence": 0.9,
                "locations": [{"file": "app/storage.py", "start_line": 1, "end_line": 2}],
                "exploitability": "request parameter reaches the query",
                "evidence": ["app/http.py forwards the parameter"],
                "evidence_citations": [],
                "remediation": "parameterize",
            }
        ],
        "warnings": [],
    }
    assert render_audit_report_markdown(payload) == render_audit_report_markdown(payload)


def test_manifest_records_status_and_detects_tampering(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "final_raw.txt").write_text("{}", encoding="utf-8")
    (run_dir / "findings.json").write_text(
        json.dumps({"status": "ok", "findings": [], "audit_summary": {}}),
        encoding="utf-8",
    )
    (run_dir / "audit_report.md").write_text(
        "# Audit\n\n- Findings: 0\n", encoding="utf-8"
    )
    (run_dir / "events.raw.jsonl").write_text("", encoding="utf-8")
    result = build_artifact_manifest(
        run_dir,
        run_id="RUN-1",
        purpose="evaluation",
        observation_capabilities={"grade": "D", "native_event_count": 0},
        parse_status="ok",
    )
    manifest = json.loads(result["path"].read_text(encoding="utf-8"))
    statuses = {entry["path"]: entry["status"] for entry in manifest["artifacts"]}
    assert statuses["events.raw.jsonl"] == "unsupported"
    assert statuses["events.normalized.jsonl"] == "unsupported"
    assert statuses["findings.json"] == "ok"
    assert statuses["tool_calls.jsonl"] == "not_produced"
    assert validate_manifest(run_dir)["ok"] is True
    (run_dir / "findings.json").write_text(
        json.dumps({"status": "ok", "findings": [], "audit_summary": {}, "tampered": True}),
        encoding="utf-8",
    )
    validation = validate_manifest(run_dir)
    assert validation["ok"] is False
    assert any("sha256" in error or "input hash" in error for error in validation["errors"])


def test_os_access_does_not_prove_content_reached_the_model() -> None:
    events = [
        _event(EventType.FILE_ACCESS, event_id="EV-1"),
        _event(EventType.RUN_START, event_id="EV-2", monotonic_ns=2),
    ]
    access = [
        FileAccessRecord(
            event_id="EV-1",
            run_id="RUN-1",
            sequence=0,
            timestamp_utc="2026-01-01T00:00:00Z",
            monotonic_ns=1,
            path="app/storage.py",
            operation="open",
            access_source=EventSource.OS,
            content_returned_to_model=False,
        )
    ]
    capabilities = observation_capabilities(
        events=events, file_access=access, grade="B", parse_status="ok"
    )
    assert capabilities["can_observe_file_access"] is True
    assert capabilities["can_prove_content_return"] is False
    assert capabilities["can_observe_tool_results"] is False
    assert capabilities["can_observe_exit_code"] is False
    assert capabilities["can_measure_tokens"] is False


def test_session_only_trace_does_not_enable_tool_metrics() -> None:
    events = [
        _event(EventType.RUN_START, event_id="EV-1"),
        _event(EventType.RUN_END, event_id="EV-2", monotonic_ns=2),
    ]
    capabilities = observation_capabilities(
        events=events, file_access=[], grade="C", parse_status="ok"
    )
    assert capabilities["native_event_count"] == 2
    assert capabilities["can_observe_tool_results"] is False
    assert capabilities["can_prove_content_return"] is False


def test_json_stdout_splits_trace_from_final_answer(tmp_path: Path) -> None:
    stdout = tmp_path / "stdout.log"
    trace = tmp_path / "trace.jsonl"
    lines = [
        {"type": "step_start", "sessionID": "ses_1", "part": {}},
        {
            "type": "tool_use",
            "sessionID": "ses_1",
            "part": {
                "tool": "read",
                "callID": "call-1",
                "state": {
                    "status": "completed",
                    "input": {"filePath": "app/storage.py", "offset": 1, "limit": 20},
                    "output": "def execute_query(...): ...",
                },
            },
        },
        {
            "type": "text",
            "sessionID": "ses_1",
            "part": {"text": '{"findings": [], "audit_summary": {}}'},
        },
    ]
    stdout.write_text("\n".join(json.dumps(item) for item in lines) + "\n", encoding="utf-8")
    final = split_json_stream(stdout, trace)
    assert final == '{"findings": [], "audit_summary": {}}'
    assert "tool_use" in trace.read_text(encoding="utf-8")
