"""Native agent trace importers.

OS-level tracing can prove that a process opened a file; it can never prove
that the file content reached the model context.  Only a native trace produced
by the agent runtime can do that, so native traces are imported explicitly and
an unknown format stays *unsupported* instead of being guessed.

The OpenCode CLI's JSON event schema is version-dependent and this build has no
licence to assume one.  :class:`OpenCodeNativeImporter` therefore only accepts
payloads that carry the documented VulnMirage envelope marker
``"vulnmirage_opencode_event": true`` and otherwise reports ``unsupported``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ...hashing import stable_id
from ...models import EventSource, EventType, RawEventEnvelope, UnifiedEvent
from .base import SourceResult, event_payload_hash, now_utc
from .native import parse_native_trace

MARKER = "vulnmirage_opencode_event"

#: Documented event types accepted by the OpenCode importer.  This is the shape
#: the ``vulnmirage-opencode-adapter`` emits; it is *not* a guess about any
#: OpenCode internal format.
OPENCODE_EVENT_TYPES = {
    "session_start": EventType.RUN_START,
    "session_end": EventType.RUN_END,
    "tool_call": EventType.TOOL_CALL,
    "tool_result": EventType.TOOL_RESULT,
    "file_read": EventType.FILE_ACCESS,
    "file_open": EventType.FILE_ACCESS,
    "search": EventType.SEARCH,
    "shell": EventType.COMMAND,
    "command": EventType.COMMAND,
    "message": EventType.TOOL_RESULT,
    "error": EventType.TOOL_ERROR,
}

_TOOL_KIND = {
    "read": ("file_access", "read"),
    "view": ("file_access", "read"),
    "grep": ("search", "search_match"),
    "glob": ("search", "search_match"),
    "bash": ("command", None),
    "shell": ("command", None),
    "edit": ("tool_call", None),
    "write": ("tool_call", None),
}


@dataclass
class TraceCapability:
    name: str
    supported: bool
    expected_format: dict[str, Any]
    notes: list[str] = field(default_factory=list)

    def describe(self) -> dict[str, Any]:
        return {
            "importer": self.name,
            "supported": self.supported,
            "expected_format": self.expected_format,
            "notes": self.notes,
        }


class NativeTraceImporter(Protocol):
    name: str

    def capability(self) -> TraceCapability: ...

    def detect(self, path: Path) -> bool: ...

    def import_trace(
        self,
        path: Path,
        *,
        run_id: str,
        repo_root: Path,
        scratch_root: Path | None,
        started_monotonic_ns: int,
    ) -> SourceResult: ...


class VulnMirageNativeImporter:
    """The native JSONL format emitted by the built-in scaffolds."""

    name = "vulnmirage_native_jsonl"

    def capability(self) -> TraceCapability:
        return TraceCapability(
            name=self.name,
            supported=True,
            expected_format={
                "format": "jsonl",
                "required_fields": ["event_type"],
                "optional_fields": [
                    "event_id",
                    "path",
                    "operation",
                    "argv",
                    "exit_code",
                    "tool_call_id",
                    "tool_name",
                    "metadata.start_line",
                    "metadata.end_line",
                    "metadata.content_sha256",
                ],
                "event_types": sorted(
                    {
                        "file_read",
                        "file_access",
                        "search",
                        "command",
                        "test",
                        "poc",
                        "build",
                        "tool_call",
                        "tool_result",
                        "process_start",
                        "process_end",
                        "run_start",
                        "run_end",
                        "timeout",
                        "finding",
                        "error",
                    }
                ),
            },
        )

    def detect(self, path: Path) -> bool:
        if not Path(path).is_file():
            return False
        with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= 5:
                    break
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    return False
                if not isinstance(payload, dict):
                    return False
                if payload.get(MARKER) is True:
                    return False
                if payload.get("event_type") in {
                    "file_read",
                    "file_access",
                    "search",
                    "tool_call",
                    "tool_result",
                    "process_start",
                    "run_start",
                }:
                    return True
                return False
        return False

    def import_trace(self, path: Path, **kwargs) -> SourceResult:
        return parse_native_trace(path, **kwargs)


class OpenCodeNativeImporter:
    name = "opencode_native"

    def capability(self) -> TraceCapability:
        return TraceCapability(
            name=self.name,
            supported=True,
            expected_format={
                "format": "jsonl",
                "marker": MARKER,
                "required_fields": [MARKER, "event_type"],
                "event_types": sorted(OPENCODE_EVENT_TYPES),
                "example": {
                    MARKER: True,
                    "event_type": "tool_result",
                    "tool_name": "read",
                    "tool_call_id": "call-1",
                    "path": "app/storage.py",
                    "metadata": {
                        "start_line": 1,
                        "end_line": 20,
                        "returned_to_model": True,
                        "truncated": False,
                    },
                },
            },
            notes=[
                "The OpenCode CLI's JSON schema is not stable across versions.",
                "This importer accepts only the documented VulnMirage adapter "
                "envelope; without it the trace is reported as unsupported and "
                "the observability grade is not raised.",
                "OS-level file access never counts as content returned to the model.",
            ],
        )

    def detect(self, path: Path) -> bool:
        if not Path(path).is_file():
            return False
        with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= 5:
                    break
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    return False
                return bool(isinstance(payload, dict) and payload.get(MARKER) is True)
        return False

    def import_trace(
        self,
        path: Path,
        *,
        run_id: str,
        repo_root: Path,
        scratch_root: Path | None,
        started_monotonic_ns: int,
    ) -> SourceResult:
        from .native import _relative_path, _timestamp

        result = SourceResult(source=EventSource.NATIVE.value)
        path = Path(path)
        if not path.is_file():
            result.notes.append("opencode trace file is missing")
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
                if not isinstance(payload, dict) or payload.get(MARKER) is not True:
                    result.errors.append(
                        f"line {line_number}: unsupported OpenCode payload "
                        f"(missing {MARKER}=true)"
                    )
                    continue
                seen += 1
                raw_type = str(payload.get("event_type", ""))
                tool_kind = str(payload.get("tool_name") or payload.get("tool") or "")
                if raw_type == "tool_call" and tool_kind in _TOOL_KIND:
                    mapped_type, default_operation = _TOOL_KIND[tool_kind]
                else:
                    event_type = OPENCODE_EVENT_TYPES.get(raw_type)
                    if event_type is None:
                        result.errors.append(
                            f"line {line_number}: unknown OpenCode event type {raw_type!r}"
                        )
                        continue
                    mapped_type, default_operation = event_type.value, None
                event_id = stable_id(
                    "EV-RAW", run_id, "opencode", payload.get("event_id") or line_number, seen
                )
                metadata = dict(payload.get("metadata") or {})
                raw_path = payload.get("path")
                path_value = _relative_path(raw_path, repo_root, scratch_root)
                if raw_path and path_value is None:
                    result.errors.append(
                        f"line {line_number}: path outside repo/scratch: {raw_path!r}"
                    )
                    continue
                operation = default_operation or payload.get("operation")
                if tool_kind in _TOOL_KIND:
                    operation = _TOOL_KIND[tool_kind][1] or operation
                monotonic_ns = payload.get("monotonic_ns")
                if not isinstance(monotonic_ns, int):
                    monotonic_ns = started_monotonic_ns + seen * 1000
                envelope = RawEventEnvelope(
                    event_id=event_id,
                    run_id=run_id,
                    source=EventSource.NATIVE,
                    source_event_id=str(payload.get("event_id") or line_number),
                    timestamp_utc=_timestamp(payload),
                    monotonic_ns=max(monotonic_ns, 0),
                    raw_payload_sha256=event_payload_hash(payload),
                    raw_payload=payload,
                    metadata={"line_number": line_number, "importer": self.name},
                )
                result.raw_events.append(envelope)
                result.events.append(
                    UnifiedEvent(
                        event_id=event_id,
                        run_id=run_id,
                        sequence=0,
                        timestamp_utc=envelope.timestamp_utc,
                        monotonic_ns=envelope.monotonic_ns,
                        event_type=EventType(mapped_type),
                        source=EventSource.NATIVE,
                        parent_event_id=payload.get("parent_event_id"),
                        tool_call_id=payload.get("tool_call_id"),
                        tool_name=tool_kind or payload.get("tool_name"),
                        argv=payload.get("argv"),
                        cwd=_relative_path(payload.get("cwd"), repo_root, scratch_root) or ".",
                        path=path_value,
                        operation=operation if (path_value and operation) else None,
                        duration_ms=payload.get("duration_ms"),
                        exit_code=payload.get("exit_code"),
                        input_tokens=payload.get("input_tokens"),
                        output_tokens=payload.get("output_tokens"),
                        metadata={
                            **metadata,
                            "returned_to_model": bool(
                                metadata.get(
                                    "returned_to_model",
                                    mapped_type in {"tool_result", "file_access", "search"},
                                )
                            ),
                            "truncated": bool(metadata.get("truncated", False)),
                        },
                    )
                )
        if not result.events:
            result.notes.append("opencode trace contained no importable events")
        return result


class OpenCodeJsonImporter:
    """Known ``opencode run --format json`` event stream (version-dependent).

    The CLI emits one JSON object per line with a ``type`` plus a ``part``
    payload and a ``sessionID``.  This importer is explicit about what it can
    prove: ``tool_use`` parts with a completed ``state`` provide tool result
    content; ``text`` parts are model-visible message text.  Unknown ``type``
    values are reported as errors, not guessed.

    No live OpenCode executable was available in this environment; this adapter
    is exercised with recorded/fixture event streams and reports
    ``format_verified=false`` in its capability metadata.
    """

    name = "opencode_json_events"

    def capability(self) -> TraceCapability:
        return TraceCapability(
            name=self.name,
            supported=True,
            expected_format={
                "format": "jsonl",
                "required_fields": ["type", "sessionID"],
                "recorded_shape": {
                    "type": "text|tool_use|step_start|step_finish|error",
                    "sessionID": "ses_...",
                    "part": {
                        "text": "final or intermediate text",
                        "tool": "read|grep|bash|...",
                        "callID": "call_...",
                        "state": {
                            "input": {"filePath": "app/storage.py", "offset": 1, "limit": 80},
                            "output": "content returned to the model",
                            "status": "completed",
                        },
                    },
                },
            },
            notes=[
                "Known OpenCode JSON event shape; version-dependent.",
                "The --format json stream is parsed separately from the final answer.",
                "A live OpenCode executable was not available here, so the real "
                "binary path is not claimed as verified.",
            ],
        )

    def detect(self, path: Path) -> bool:
        if not Path(path).is_file():
            return False
        with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= 5:
                    break
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    return False
                if not isinstance(payload, dict):
                    return False
                if payload.get(MARKER) is True:
                    return False
                if payload.get("type") in {
                    "text",
                    "tool_use",
                    "step_start",
                    "step_finish",
                    "error",
                } and ("sessionID" in payload or "part" in payload):
                    return True
                return False
        return False

    def import_trace(
        self,
        path: Path,
        *,
        run_id: str,
        repo_root: Path,
        scratch_root: Path | None,
        started_monotonic_ns: int,
    ) -> SourceResult:
        from .native import _relative_path, _timestamp

        result = SourceResult(source=EventSource.NATIVE.value)
        path = Path(path)
        if not path.is_file():
            result.notes.append("opencode json stream is missing")
            return result
        seen = 0
        step = 0
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
                    result.errors.append(f"line {line_number}: not a JSON object")
                    continue
                raw_type = str(payload.get("type", ""))
                part = payload.get("part") if isinstance(payload.get("part"), dict) else {}
                metadata: dict[str, Any] = {"line_number": line_number, "importer": self.name}
                mapped_type: str
                operation: str | None = None
                raw_path = None
                tool_name = None
                tool_call_id = None
                exit_code = None
                if raw_type == "step_start":
                    step += 1
                    mapped_type = EventType.RUN_START.value if seen == 0 else EventType.TOOL_CALL.value
                elif raw_type == "step_finish":
                    mapped_type = EventType.RUN_END.value
                    tokens = part.get("tokens") if isinstance(part.get("tokens"), dict) else {}
                    if tokens.get("input") is not None:
                        metadata["input_tokens"] = tokens.get("input")
                    if tokens.get("output") is not None:
                        metadata["output_tokens"] = tokens.get("output")
                elif raw_type == "text":
                    mapped_type = EventType.TOOL_RESULT.value
                    metadata["message_text"] = str(part.get("text") or "")[:20000]
                    metadata["returned_to_model"] = True
                elif raw_type == "error":
                    mapped_type = EventType.TOOL_ERROR.value
                    metadata["error"] = str(payload.get("error") or "")[:2000]
                elif raw_type == "tool_use":
                    tool_name = str(part.get("tool") or "")
                    tool_call_id = part.get("callID")
                    state = part.get("state") if isinstance(part.get("state"), dict) else {}
                    tool_input = state.get("input") if isinstance(state.get("input"), dict) else {}
                    if state.get("status") and state.get("status") != "completed":
                        mapped_type = EventType.TOOL_CALL.value
                    else:
                        mapped_type = EventType.TOOL_RESULT.value
                    if tool_name in {"read", "view"}:
                        operation = "read"
                        raw_path = tool_input.get("filePath") or tool_input.get("path")
                        if tool_input.get("offset") is not None:
                            metadata["start_line"] = tool_input.get("offset")
                        if tool_input.get("limit") is not None and tool_input.get("offset"):
                            metadata["end_line"] = (
                                int(tool_input["offset"]) + int(tool_input["limit"]) - 1
                            )
                    elif tool_name in {"grep", "glob"}:
                        operation = "search_match"
                        metadata["search_term"] = tool_input.get("pattern")
                    elif tool_name in {"bash", "shell"}:
                        operation = None
                        metadata["argv"] = tool_input.get("command")
                        exit_code = state.get("exitCode") or state.get("exit_code")
                    else:
                        operation = None
                    output = state.get("output")
                    if output is not None:
                        text = str(output)
                        metadata["content_sha256"] = __import__("hashlib").sha256(
                            text.encode("utf-8")
                        ).hexdigest()
                        metadata["returned_to_model"] = True
                        metadata["truncated"] = bool(state.get("truncated", False))
                else:
                    result.errors.append(
                        f"line {line_number}: unknown OpenCode event type {raw_type!r}"
                    )
                    continue
                if seen >= 1 and mapped_type == EventType.RUN_START.value:
                    mapped_type = EventType.TOOL_CALL.value
                path_value = _relative_path(raw_path, repo_root, scratch_root)
                if raw_path and path_value is None:
                    result.errors.append(
                        f"line {line_number}: path outside repo/scratch: {raw_path!r}"
                    )
                    continue
                event_id = stable_id(
                    "EV-RAW", run_id, "opencode_json", payload.get("sessionID"), line_number, seen
                )
                seen += 1
                monotonic_ns = payload.get("time")
                if not isinstance(monotonic_ns, int):
                    monotonic_ns = started_monotonic_ns + seen * 1000
                envelope = RawEventEnvelope(
                    event_id=event_id,
                    run_id=run_id,
                    source=EventSource.NATIVE,
                    source_event_id=str(payload.get("sessionID") or line_number),
                    timestamp_utc=_timestamp(payload),
                    monotonic_ns=max(monotonic_ns, 0),
                    raw_payload_sha256=event_payload_hash(payload),
                    raw_payload=payload,
                    metadata={"line_number": line_number, "importer": self.name},
                )
                result.raw_events.append(envelope)
                result.events.append(
                    UnifiedEvent(
                        event_id=event_id,
                        run_id=run_id,
                        sequence=0,
                        timestamp_utc=envelope.timestamp_utc,
                        monotonic_ns=envelope.monotonic_ns,
                        event_type=EventType(mapped_type),
                        source=EventSource.NATIVE,
                        tool_call_id=tool_call_id,
                        tool_name=tool_name,
                        path=path_value,
                        operation=operation if (path_value and operation) else None,
                        exit_code=exit_code,
                        input_tokens=metadata.get("input_tokens"),
                        output_tokens=metadata.get("output_tokens"),
                        metadata=metadata,
                    )
                )
        if not result.events:
            result.notes.append("opencode json stream contained no importable events")
        elif all(event.event_type.value in {"run_start", "run_end"} for event in result.events):
            result.notes.append(
                "opencode stream only contained session/session-end events; "
                "tool-result-dependent metrics remain ineligible"
            )
        return result


class UnsupportedTraceImporter:
    name = "unsupported"

    def capability(self) -> TraceCapability:
        return TraceCapability(
            name=self.name,
            supported=False,
            expected_format={
                "format": "jsonl",
                "note": "no verified native importer matched the trace",
            },
            notes=[
                "A native trace was supplied but no importer recognised it.",
                "Observability is downgraded; OS strace is not a substitute.",
            ],
        )

    def detect(self, path: Path) -> bool:
        return False

    def import_trace(self, path: Path, **kwargs) -> SourceResult:
        result = SourceResult(source=EventSource.NATIVE.value)
        result.notes.append(self.capability().notes[0])
        return result


IMPORTERS: list[NativeTraceImporter] = [
    VulnMirageNativeImporter(),
    OpenCodeNativeImporter(),
    OpenCodeJsonImporter(),
]


def importer_capabilities() -> list[dict[str, Any]]:
    return [importer.capability().describe() for importer in IMPORTERS]


def select_importer(path: Path) -> NativeTraceImporter:
    for importer in IMPORTERS:
        if importer.capability().supported and importer.detect(Path(path)):
            return importer
    return UnsupportedTraceImporter()


def import_native_trace(
    path: Path,
    *,
    run_id: str,
    repo_root: Path,
    scratch_root: Path | None,
    started_monotonic_ns: int,
) -> SourceResult:
    importer = select_importer(path)
    return importer.import_trace(
        Path(path),
        run_id=run_id,
        repo_root=repo_root,
        scratch_root=scratch_root,
        started_monotonic_ns=started_monotonic_ns,
    )
