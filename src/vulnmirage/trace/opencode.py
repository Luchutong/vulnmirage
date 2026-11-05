"""Normalize OpenCode ``run --format json`` output into benchmark contracts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..hashing import sha256_text, stable_id
from .models import FileAccessRecord, NormalizedEvent, ToolCallRecord

KNOWN_EVENT_TYPES = {"step_start", "tool_use", "step_finish", "text", "reasoning", "error"}
_TERMINAL_TOOL_STATES = {"completed", "error"}
_FILE_TOOLS: dict[str, str] = {
    "read": "read",
    "view": "read",
    "grep": "search",
    "glob": "search",
    "search": "search",
    "list": "list",
    "ls": "list",
    "write": "write",
    "edit": "write",
    "patch": "write",
}
_PATH_KEYS = ("filePath", "filepath", "path", "directory", "dir")
_SECRET_VALUE_RE = re.compile(
    r"(?i)(?:sk-[a-z0-9_-]{12,}|authorization\s*[:=]\s*(?:bearer|basic)\s+[^\s,;]+|"
    r"(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+)"
)


@dataclass
class ParseResult:
    events: list[NormalizedEvent] = field(default_factory=list)
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    file_access: list[FileAccessRecord] = field(default_factory=list)
    source_lines: int = 0
    invalid_lines: int = 0
    unknown_events: int = 0
    unknown_event_types: list[str] = field(default_factory=list)


def _redact_text(text: str, secret_values: tuple[str, ...]) -> str:
    value = text
    for secret in secret_values:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return _SECRET_VALUE_RE.sub("[REDACTED]", value)


def _redact(value: Any, secret_values: tuple[str, ...], *, depth: int = 0) -> Any:
    if isinstance(value, str):
        redacted = _redact_text(value, secret_values)
        return redacted if len(redacted) <= 2000 else redacted[:2000] + "...[truncated]"
    if isinstance(value, dict):
        if depth >= 5:
            return {"_summary": "[nested input truncated]"}
        return {
            str(key): _redact(item, secret_values, depth=depth + 1)
            for key, item in list(value.items())[:100]
        }
    if isinstance(value, list):
        if depth >= 5:
            return ["[nested input truncated]"]
        return [_redact(item, secret_values, depth=depth + 1) for item in value[:50]]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return _redact_text(str(value), secret_values)


def _relative_path(value: Any, repo_root: Path) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    candidate = Path(raw)
    try:
        if candidate.is_absolute():
            return candidate.resolve().relative_to(repo_root.resolve()).as_posix()
    except (OSError, ValueError):
        return f"[outside-workspace]/{candidate.name}"
    normalized = raw.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized == ".." or normalized.startswith("../"):
        return f"[outside-workspace]/{Path(normalized).name}"
    return normalized


def _part(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("part")
    return value if isinstance(value, dict) else {}


def _tool_state(part: dict[str, Any]) -> dict[str, Any]:
    value = part.get("state")
    return value if isinstance(value, dict) else {}


def _event_time(event: dict[str, Any], part: dict[str, Any], state: dict[str, Any]) -> Any:
    for container in (event, part, state):
        for key in ("timestamp", "time", "createdAt"):
            if key in container and not isinstance(container[key], dict):
                return container[key]
    time_data = state.get("time")
    if isinstance(time_data, dict):
        return time_data.get("completed") or time_data.get("start")
    return None


def _duration_ms(state: dict[str, Any]) -> float | None:
    time_data = state.get("time")
    if not isinstance(time_data, dict):
        return None
    start = time_data.get("start")
    end = time_data.get("end") or time_data.get("completed")
    if isinstance(start, (int, float)) and isinstance(end, (int, float)) and end >= start:
        return float(end - start)
    return None


def parse_opencode_jsonl(
    source: Path,
    *,
    repo_root: Path,
    secret_values: tuple[str, ...] = (),
) -> ParseResult:
    result = ParseResult()
    if not source.is_file():
        return result
    with source.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            if not raw_line.strip():
                continue
            result.source_lines += 1
            try:
                payload = json.loads(raw_line)
            except json.JSONDecodeError:
                result.invalid_lines += 1
                continue
            if not isinstance(payload, dict):
                result.invalid_lines += 1
                continue
            _append_event(
                result,
                payload=payload,
                raw_line=raw_line,
                source=source,
                repo_root=repo_root,
                secret_values=secret_values,
            )
    result.unknown_event_types = sorted(set(result.unknown_event_types))
    return result


def _append_event(
    result: ParseResult,
    *,
    payload: dict[str, Any],
    raw_line: str,
    source: Path,
    repo_root: Path,
    secret_values: tuple[str, ...],
) -> None:
    source_type = str(payload.get("type") or "unknown")
    if source_type not in KNOWN_EVENT_TYPES:
        result.unknown_events += 1
        result.unknown_event_types.append(source_type)
    part = _part(payload)
    state = _tool_state(part)
    sequence = len(result.events) + 1
    event_id = stable_id("EVT", source.name, sequence, raw_line)
    session_id = payload.get("sessionID") or payload.get("sessionId")
    text_value = part.get("text", payload.get("text"))
    text = _redact_text(text_value, secret_values) if isinstance(text_value, str) else None
    tool_name = part.get("tool") or part.get("toolName")
    tool_name = str(tool_name) if tool_name is not None else None
    tool_call_id = part.get("callID") or part.get("callId") or part.get("id")
    tool_call_id = str(tool_call_id) if tool_call_id is not None else None
    status: str | None = None
    input_data: dict[str, Any] = {}
    output: str | None = None
    if source_type == "tool_use":
        status = str(state.get("status")) if state.get("status") is not None else None
        raw_input = state.get("input")
        if isinstance(raw_input, dict):
            input_data = _redact(raw_input, secret_values)
            for key in _PATH_KEYS:
                if key in input_data:
                    normalized_path = _relative_path(input_data[key], repo_root)
                    if normalized_path is not None:
                        input_data[key] = normalized_path
        raw_output = state.get("output")
        if raw_output is not None:
            output = _redact_text(str(raw_output), secret_values)
    elif source_type == "step_finish":
        reason = part.get("reason") or payload.get("reason")
        status = str(reason) if reason is not None else None
    elif source_type == "error":
        status = "error"
        if text is None:
            error_data = part.get("error", payload.get("error"))
            if error_data is not None:
                text = _redact_text(
                    json.dumps(error_data, sort_keys=True, ensure_ascii=False),
                    secret_values,
                )[:4000]

    terminal = (status or "").lower() in _TERMINAL_TOOL_STATES
    if source_type == "tool_use":
        normalized_type = "tool_result" if terminal else "tool_call"
    else:
        normalized_type = source_type
    event = NormalizedEvent(
        event_id=event_id,
        sequence=sequence,
        event_type=normalized_type,
        source_type=source_type,
        session_id=str(session_id) if session_id is not None else None,
        timestamp=_event_time(payload, part, state),
        tool_call_id=tool_call_id,
        tool_name=tool_name,
        status=status,
        text=text,
        input_summary=input_data,
        output_preview=output[:4000] if output else None,
        output_sha256=sha256_text(output) if output is not None else None,
    )
    result.events.append(event)

    if source_type != "tool_use" or not tool_name:
        return
    content_returned = terminal and bool(output)
    result.tool_calls.append(
        ToolCallRecord(
            event_id=event_id,
            sequence=sequence,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            status=status,
            duration_ms=_duration_ms(state),
            input_summary=input_data,
            output_sha256=sha256_text(output) if output is not None else None,
            content_returned_to_model=content_returned,
        )
    )
    access_type = _FILE_TOOLS.get(tool_name.lower())
    if not access_type:
        return
    paths: list[str] = []
    for key in _PATH_KEYS:
        path = _relative_path(input_data.get(key), repo_root)
        if path and path not in paths:
            paths.append(path)
    for path in paths:
        result.file_access.append(
            FileAccessRecord(
                event_id=event_id,
                sequence=sequence,
                path=path,
                tool_call_id=tool_call_id,
                tool_name=tool_name,
                access_type=access_type,
                content_returned_to_model=(
                    content_returned and access_type in {"read", "search", "list"}
                ),
            )
        )


__all__ = ["KNOWN_EVENT_TYPES", "ParseResult", "parse_opencode_jsonl"]
