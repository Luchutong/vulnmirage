"""Native agent trace observer.

The agent/scaffold writes a JSONL trace.  Both the legacy VulnMirage trace
shape (``event_type: file_read``) and the new ``UnifiedEvent`` shape are
accepted.  Each raw line is preserved in an immutable envelope with its own
SHA-256; normalization happens later.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...hashing import stable_id
from ...models import EventSource, EventType, RawEventEnvelope, UnifiedEvent
from .base import SourceResult, event_payload_hash, now_utc

_LEGACY_TYPES = {
    "file_read": (EventType.FILE_ACCESS, "read"),
    "file_access": (EventType.FILE_ACCESS, None),
    "search": (EventType.SEARCH, "search_match"),
    "command": (EventType.COMMAND, None),
    "test": (EventType.TEST, None),
    "poc": (EventType.POC, None),
    "build": (EventType.BUILD, None),
    "finding": (EventType.FINDING, None),
    "error": (EventType.TOOL_ERROR, None),
    "tool_error": (EventType.TOOL_ERROR, None),
    "tool_call": (EventType.TOOL_CALL, None),
    "tool_result": (EventType.TOOL_RESULT, None),
    "process_start": (EventType.PROCESS_START, None),
    "process_end": (EventType.PROCESS_END, None),
    "run_start": (EventType.RUN_START, None),
    "run_end": (EventType.RUN_END, None),
    "timeout": (EventType.TIMEOUT, None),
}


def _relative_path(value: Any, repo_root: Path, scratch_root: Path | None) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.replace("\\", "/").strip()
    if text.startswith("./"):
        text = text[2:]
    candidate = Path(text)
    if candidate.is_absolute() or (len(text) > 1 and text[1] == ":"):
        try:
            resolved = Path(text).resolve()
        except OSError:
            return None
        try:
            return resolved.relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            if scratch_root is not None:
                try:
                    relative = resolved.relative_to(scratch_root.resolve()).as_posix()
                    return f"scratch/{relative}"
                except ValueError:
                    return None
            return None
    try:
        resolved = (repo_root / text).resolve()
    except OSError:
        return None
    try:
        return resolved.relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        if scratch_root is not None:
            try:
                relative = resolved.relative_to(scratch_root.resolve()).as_posix()
                return f"scratch/{relative}"
            except ValueError:
                return None
        return None


def _timestamp(payload: dict[str, Any]) -> str:
    return str(payload.get("timestamp_utc") or payload.get("timestamp") or now_utc())


def parse_native_trace(
    path: Path,
    *,
    run_id: str,
    repo_root: Path,
    scratch_root: Path | None,
    started_monotonic_ns: int,
) -> SourceResult:
    result = SourceResult(source=EventSource.NATIVE.value)
    path = Path(path)
    if not path.is_file():
        result.notes.append("native trace file is missing; observability downgraded")
        return result
    seen = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                result.errors.append(f"line {line_number}: {exc}")
                continue
            if not isinstance(payload, dict):
                result.errors.append(f"line {line_number}: payload is not an object")
                continue
            seen += 1
            source_event_id = payload.get("event_id")
            event_id = stable_id(
                "EV-RAW", run_id, "native", source_event_id or line_number, seen
            )
            monotonic_ns = payload.get("monotonic_ns")
            if not isinstance(monotonic_ns, int):
                monotonic_ns = started_monotonic_ns + seen * 1000
            envelope = RawEventEnvelope(
                event_id=event_id,
                run_id=run_id,
                source=EventSource.NATIVE,
                source_event_id=str(source_event_id) if source_event_id else None,
                timestamp_utc=_timestamp(payload),
                monotonic_ns=max(monotonic_ns, 0),
                raw_payload_sha256=event_payload_hash(payload),
                raw_payload=payload,
                metadata={"line_number": line_number},
            )
            result.raw_events.append(envelope)

            legacy = _LEGACY_TYPES.get(str(payload.get("event_type", "")))
            if legacy is None:
                result.errors.append(
                    f"line {line_number}: unknown native event type {payload.get('event_type')!r}"
                )
                continue
            event_type, default_operation = legacy
            metadata = dict(payload.get("metadata") or {})
            operation = payload.get("operation") or metadata.get("operation") or default_operation
            raw_path = payload.get("path")
            path_value = _relative_path(raw_path, repo_root, scratch_root)
            if raw_path and path_value is None:
                result.errors.append(
                    f"line {line_number}: native event path is outside repo/scratch: {raw_path!r}"
                )
                continue
            cwd_value = _relative_path(payload.get("cwd"), repo_root, scratch_root)
            event = UnifiedEvent(
                event_id=event_id,
                run_id=run_id,
                sequence=0,
                timestamp_utc=envelope.timestamp_utc,
                monotonic_ns=envelope.monotonic_ns,
                event_type=event_type,
                source=EventSource.NATIVE,
                parent_event_id=payload.get("parent_event_id"),
                tool_call_id=payload.get("tool_call_id"),
                tool_name=payload.get("tool_name"),
                argv=payload.get("argv"),
                cwd=cwd_value or ".",
                path=path_value,
                operation=operation if (path_value and operation) else None,
                duration_ms=payload.get("duration_ms"),
                exit_code=payload.get("exit_code"),
                stdout_ref=payload.get("stdout_ref"),
                stderr_ref=payload.get("stderr_ref"),
                input_tokens=payload.get("input_tokens"),
                output_tokens=payload.get("output_tokens"),
                metadata=metadata,
            )
            result.events.append(event)
    if not result.events:
        result.notes.append("native trace contained no parseable events")
    return result
