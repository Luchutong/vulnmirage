"""Command-wrapper observer for the top-level agent invocation.

The process supervisor is authoritative for start/end/exit status.  Internal
tool commands are observed only if the agent emits them natively; a generic
subprocess cannot see another process's syscalls without OS tracing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ...hashing import stable_id
from ...logging import redact
from ...models import EventSource, EventType, RawEventEnvelope, UnifiedEvent
from .base import SourceResult, event_payload_hash

_CMD_TOOL_ID = "agent-process"


def build_wrapper_events(
    *,
    run_id: str,
    argv: list[str],
    started_at: str,
    ended_at: str,
    started_monotonic_ns: int,
    exit_code: int | None,
    timed_out: bool,
    stdout_ref: str,
    stderr_ref: str,
    duration_seconds: float,
) -> SourceResult:
    result = SourceResult(source=EventSource.WRAPPER.value)
    command_payload: dict[str, Any] = {
        "event_type": "process_start",
        "argv": list(argv),
        "cwd": ".",
        "tool_call_id": _CMD_TOOL_ID,
        "tool_name": "agent_subprocess",
        "metadata": {"observer": "command_wrapper"},
    }
    raw_start = RawEventEnvelope(
        event_id=stable_id("EV-RAW", run_id, "wrapper", "start"),
        run_id=run_id,
        source=EventSource.WRAPPER,
        timestamp_utc=started_at,
        monotonic_ns=started_monotonic_ns,
        raw_payload_sha256=event_payload_hash(command_payload),
        raw_payload=command_payload,
    )
    start_event = UnifiedEvent(
        event_id=raw_start.event_id,
        run_id=run_id,
        sequence=0,
        timestamp_utc=started_at,
        monotonic_ns=started_monotonic_ns,
        event_type=EventType.PROCESS_START,
        source=EventSource.WRAPPER,
        tool_call_id=_CMD_TOOL_ID,
        tool_name="agent_subprocess",
        argv=redact(list(argv)),
        cwd=".",
        stdout_ref=stdout_ref,
        stderr_ref=stderr_ref,
        metadata={"observer": "command_wrapper"},
    )
    end_payload: dict[str, Any] = {
        "event_type": "process_end",
        "tool_call_id": _CMD_TOOL_ID,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": int(duration_seconds * 1000),
        "stdout_ref": stdout_ref,
        "stderr_ref": stderr_ref,
        "metadata": {"observer": "command_wrapper"},
    }
    raw_end = RawEventEnvelope(
        event_id=stable_id("EV-RAW", run_id, "wrapper", "end"),
        run_id=run_id,
        source=EventSource.WRAPPER,
        timestamp_utc=ended_at,
        monotonic_ns=started_monotonic_ns + int(duration_seconds * 1_000_000_000),
        raw_payload_sha256=event_payload_hash(end_payload),
        raw_payload=end_payload,
    )
    end_event = UnifiedEvent(
        event_id=raw_end.event_id,
        run_id=run_id,
        sequence=0,
        timestamp_utc=ended_at,
        monotonic_ns=raw_end.monotonic_ns,
        event_type=EventType.PROCESS_END,
        source=EventSource.WRAPPER,
        parent_event_id=start_event.event_id,
        tool_call_id=_CMD_TOOL_ID,
        tool_name="agent_subprocess",
        duration_ms=int(duration_seconds * 1000),
        exit_code=exit_code,
        stdout_ref=stdout_ref,
        stderr_ref=stderr_ref,
        metadata={"observer": "command_wrapper", "timed_out": timed_out},
    )
    result.raw_events.extend([raw_start, raw_end])
    result.events.extend([start_event, end_event])
    return result


def wrapper_available(enabled: bool) -> bool:
    return bool(enabled)
