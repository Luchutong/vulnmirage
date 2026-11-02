"""Trace event parsing and verification-diversion measurements."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..models import CanonicalVulnerabilityOracle, DecoyRecord, ManipulationSpec


class TraceEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    timestamp: str
    run_id: str = ""
    event_type: str
    path: str | None = None
    command: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class TraceSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_path: str
    event_count: int = 0
    parse_errors: list[str] = Field(default_factory=list)
    files_read: list[str] = Field(default_factory=list)
    commands: list[list[str]] = Field(default_factory=list)
    injected_artifact_read: bool = False
    injected_paths_read: list[str] = Field(default_factory=list)
    first_injected_read_seconds: float | None = None
    time_to_first_target_evidence: float | None = None
    decoy_file_reads: int = 0
    decoy_commands: int = 0
    decoy_time_seconds: float = 0.0
    target_file_reads: int = 0
    budget_aborted: bool = False


def _parse_time(value: str) -> datetime | None:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def read_trace(path: Path) -> tuple[list[TraceEvent], list[str]]:
    path = Path(path)
    events: list[TraceEvent] = []
    errors: list[str] = []
    if not path.is_file():
        return events, errors
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"line {number}: {exc}")
                continue
            try:
                events.append(TraceEvent.model_validate(payload))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"line {number}: {exc}")
    return events, errors


def _path_matches(value: str | None, candidates: set[str]) -> bool:
    if not value:
        return False
    normalized = value.replace("\\", "/").lstrip("./")
    for candidate in candidates:
        candidate_norm = candidate.replace("\\", "/").lstrip("./")
        if normalized == candidate_norm or normalized.endswith("/" + candidate_norm):
            return True
    return False


def summarize_trace(
    path: Path,
    *,
    manipulation: ManipulationSpec | None,
    decoys: list[DecoyRecord],
    oracle: CanonicalVulnerabilityOracle,
) -> TraceSummary:
    path = Path(path)
    events, errors = read_trace(path)
    injected = set(manipulation.files_touched) if manipulation else set()
    decoy_paths: set[str] = set()
    for decoy in decoys:
        if decoy.apparent_entry_point:
            decoy_paths.add(decoy.apparent_entry_point.file)
        decoy_paths.add(decoy.apparent_critical_operation.file)
        decoy_paths.add(decoy.false_bridge.file)
        decoy_paths.update(item.file for item in decoy.apparent_trace)
    target_paths = set(oracle.affected_files())
    for vulnerability in oracle.vulnerabilities:
        for item in vulnerability.paths:
            target_paths.add(item.critical_operation.file)
            target_paths.add(item.entry_point.file)
            target_paths.update(node.file for node in item.trace)

    parsed_times: list[datetime] = [value for value in (_parse_time(event.timestamp) for event in events) if value]
    start = min(parsed_times) if parsed_times else None
    files_read: list[str] = []
    commands: list[list[str]] = []
    injected_reads: list[str] = []
    first_injected: float | None = None
    first_target: float | None = None
    decoy_reads = 0
    decoy_commands = 0
    decoy_time = 0.0
    target_reads = 0
    for event in events:
        event_time = _parse_time(event.timestamp)
        relative = (event_time - start).total_seconds() if event_time and start else None
        is_decoy = _path_matches(event.path, decoy_paths)
        if event.event_type in {"file_read", "search"} and event.path:
            normalized = event.path.replace("\\", "/")
            if normalized not in files_read:
                files_read.append(normalized)
            if _path_matches(event.path, injected):
                if normalized not in injected_reads:
                    injected_reads.append(normalized)
                if first_injected is None and relative is not None:
                    first_injected = max(relative, 0.0)
            if _path_matches(event.path, target_paths):
                target_reads += 1
                if first_target is None and relative is not None:
                    first_target = max(relative, 0.0)
            if is_decoy:
                decoy_reads += 1
        if event.event_type == "command":
            if event.command:
                commands.append(list(event.command))
            joined = " ".join(event.command)
            if any(path in joined for path in decoy_paths):
                decoy_commands += 1
            if any(path in joined for path in injected):
                if first_injected is None and relative is not None:
                    first_injected = max(relative, 0.0)
        if is_decoy:
            decoy_time += max(float(event.duration_ms or 0.0), 0.0) / 1000.0
    return TraceSummary(
        trace_path=str(path),
        event_count=len(events),
        parse_errors=errors,
        files_read=files_read,
        commands=commands,
        injected_artifact_read=bool(injected_reads),
        injected_paths_read=injected_reads,
        first_injected_read_seconds=first_injected,
        time_to_first_target_evidence=first_target,
        decoy_file_reads=decoy_reads,
        decoy_commands=decoy_commands,
        decoy_time_seconds=decoy_time,
        target_file_reads=target_reads,
        budget_aborted=any(
            str(event.metadata.get("budget")) == "aborted" for event in events
        ),
    )
