"""Deterministic normalization of multi-source observation events."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...config import ObservationConfig
from ...logging import redact
from ...models import EventSource, EventType, FileAccessRecord, UnifiedEvent

_SOURCE_PRIORITY = {
    EventSource.NATIVE: 0,
    EventSource.WRAPPER: 1,
    EventSource.SUPERVISOR: 1,
    EventSource.OS: 2,
    EventSource.EVALUATOR: 3,
}
_OPERATION_BY_TYPE = {
    EventType.SEARCH: "search_match",
    EventType.FILE_ACCESS: "read",
    EventType.TOOL_RESULT: "tool_context",
}
_PROCESS_TYPES = {
    EventType.PROCESS_START,
    EventType.PROCESS_END,
    EventType.COMMAND,
    EventType.BUILD,
    EventType.TEST,
    EventType.POC,
    EventType.TIMEOUT,
}


@dataclass
class NormalizedObservation:
    events: list[UnifiedEvent] = field(default_factory=list)
    file_access: list[FileAccessRecord] = field(default_factory=list)
    tool_calls: list[UnifiedEvent] = field(default_factory=list)
    process_events: list[UnifiedEvent] = field(default_factory=list)
    duplicates: int = 0
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def primary_events(self) -> list[UnifiedEvent]:
        return [event for event in self.events if not event.metadata.get("duplicate_of")]


def _line_value(metadata: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, int) and value >= 1:
            return value
    return None


def _access_key(event: UnifiedEvent) -> tuple[str, str, str | None] | None:
    if not event.path:
        return None
    operation = event.operation or _OPERATION_BY_TYPE.get(event.event_type)
    if not operation:
        return None
    return (event.path, operation, event.tool_call_id)


def _priority(event: UnifiedEvent) -> int:
    return _SOURCE_PRIORITY.get(event.source, 9)


def _deduplicate_access(
    events: list[UnifiedEvent], window_ms: int
) -> tuple[list[UnifiedEvent], list[UnifiedEvent]]:
    primary: list[UnifiedEvent] = []
    duplicates: list[UnifiedEvent] = []
    window_ns = max(window_ms, 0) * 1_000_000
    for event in sorted(events, key=lambda item: (item.monotonic_ns, _priority(item))):
        key = _access_key(event)
        duplicate_index = None
        for index, kept in enumerate(primary):
            if _access_key(kept) != key:
                continue
            if abs(kept.monotonic_ns - event.monotonic_ns) <= window_ns:
                duplicate_index = index
                break
        if duplicate_index is None:
            primary.append(event)
            continue
        kept = primary[duplicate_index]
        if _priority(event) < _priority(kept):
            primary[duplicate_index] = event
            duplicates.append(
                kept.model_copy(
                    update={
                        "metadata": {
                            **kept.metadata,
                            "duplicate_of": event.event_id,
                            "duplicate_reason": "higher_priority_source",
                        }
                    }
                )
            )
        else:
            duplicates.append(
                event.model_copy(
                    update={
                        "metadata": {
                            **event.metadata,
                            "duplicate_of": kept.event_id,
                            "duplicate_reason": (
                                "lower_priority_source"
                                if _priority(event) > _priority(kept)
                                else "same_priority"
                            ),
                        }
                    }
                )
            )
    return primary, duplicates


def _merge_processes(events: list[UnifiedEvent]) -> tuple[list[UnifiedEvent], list[UnifiedEvent]]:
    groups: dict[str, list[UnifiedEvent]] = {}
    remaining: list[UnifiedEvent] = []
    for event in events:
        if event.event_type in {EventType.PROCESS_START, EventType.PROCESS_END} and event.tool_call_id:
            groups.setdefault(event.tool_call_id, []).append(event)
        else:
            remaining.append(event)
    merged: list[UnifiedEvent] = []
    duplicates: list[UnifiedEvent] = []
    for group in groups.values():
        starts = [item for item in group if item.event_type == EventType.PROCESS_START]
        ends = [item for item in group if item.event_type == EventType.PROCESS_END]
        if starts and ends:
            start, end = starts[0], ends[-1]
            merged.append(
                start.model_copy(
                    update={
                        "duration_ms": end.duration_ms if end.duration_ms is not None else start.duration_ms,
                        "exit_code": end.exit_code,
                        "stdout_ref": end.stdout_ref or start.stdout_ref,
                        "stderr_ref": end.stderr_ref or start.stderr_ref,
                        "metadata": {
                            **start.metadata,
                            **end.metadata,
                            "merged_end_event_id": end.event_id,
                            "merged": True,
                        },
                    }
                )
            )
            duplicates.append(
                end.model_copy(
                    update={
                        "metadata": {
                            **end.metadata,
                            "duplicate_of": start.event_id,
                            "duplicate_reason": "merged_process_end",
                        }
                    }
                )
            )
        else:
            remaining.extend(group)
    return remaining + merged, duplicates


def normalize_events(
    events: list[UnifiedEvent],
    *,
    config: ObservationConfig,
    capture_file_lines: bool = True,
    capture_content_hashes: bool = True,
) -> NormalizedObservation:
    observation = NormalizedObservation()
    access_events = [event for event in events if _access_key(event) is not None]
    other_events = [event for event in events if _access_key(event) is None]
    primary_access, duplicate_access = _deduplicate_access(access_events, config.dedup_window_ms)
    primary_process, duplicate_process = _merge_processes(other_events)
    primary = primary_access + primary_process
    duplicates = duplicate_access + duplicate_process
    observation.duplicates = len(duplicates)
    all_events = primary + duplicates
    source_order = {event.event_id: index for index, event in enumerate(events)}
    all_events.sort(
        key=lambda item: (
            item.monotonic_ns,
            _priority(item),
            source_order.get(item.event_id, 0),
        )
    )
    ids = {event.event_id for event in all_events}
    normalized: list[UnifiedEvent] = []
    seen: set[str] = set()
    for sequence, event in enumerate(all_events, start=1):
        event = event.model_copy(
            update={
                "sequence": sequence,
                "parent_event_id": (
                    event.parent_event_id if event.parent_event_id in ids else None
                ),
                "argv": redact(event.argv) if event.argv else None,
                "metadata": redact(event.metadata) if config.redact else event.metadata,
            }
        )
        if event.event_id in seen:
            observation.errors.append(f"duplicate normalized event id: {event.event_id}")
            continue
        seen.add(event.event_id)
        normalized.append(event)
    observation.events = normalized
    primary_events = [event for event in normalized if not event.metadata.get("duplicate_of")]

    file_access: list[FileAccessRecord] = []
    seen_paths: set[str] = set()
    for event in primary_events:
        if _access_key(event) is None or event.path is None:
            continue
        if event.path in {".", "/", ""}:
            # Repository-root directory access is not a file access.
            continue
        operation = event.operation or _OPERATION_BY_TYPE.get(event.event_type) or "read"
        if operation not in {
            "open",
            "read",
            "stat",
            "list",
            "search_match",
            "tool_context",
            "bulk_runtime_read",
        }:
            operation = "read"
        metadata = event.metadata
        requested_start = _line_value(
            metadata, "requested_start_line", "start_line", "line_start", "line"
        )
        requested_end = _line_value(metadata, "requested_end_line", "end_line", "line_end")
        observed_start = _line_value(
            metadata, "observed_start_line", "start_line", "line_start", "line"
        )
        observed_end = _line_value(metadata, "observed_end_line", "end_line", "line_end")
        if not capture_file_lines:
            requested_start = requested_end = observed_start = observed_end = None
        content_sha = metadata.get("content_sha256") if capture_content_hashes else None
        # Content reaches the model only when the native/wrapper source says so;
        # OS tracing proves access, never model exposure.  Keep the *basis* so a
        # later observer can distinguish proof from inference (P1-2).
        if "returned_to_model" in metadata:
            returned_to_model = bool(metadata["returned_to_model"])
            returned_source = "explicit"
        elif event.source in {
            EventSource.NATIVE,
            EventSource.WRAPPER,
            EventSource.SUPERVISOR,
        } and operation in {"read", "search_match", "tool_context"}:
            returned_to_model = True
            returned_source = "inferred_from_source_and_operation"
        else:
            returned_to_model = False
            returned_source = (
                "os_only_no_content_evidence"
                if event.source == EventSource.OS
                else "unknown"
            )
        file_access.append(
            FileAccessRecord(
                event_id=event.event_id,
                run_id=event.run_id,
                sequence=event.sequence,
                timestamp_utc=event.timestamp_utc,
                monotonic_ns=event.monotonic_ns,
                path=event.path,
                operation=operation,
                access_source=event.source,
                tool_call_id=event.tool_call_id,
                requested_start_line=requested_start,
                requested_end_line=requested_end,
                observed_start_line=observed_start,
                observed_end_line=observed_end,
                bytes_observed=metadata.get("bytes_observed"),
                content_sha256=content_sha if isinstance(content_sha, str) else None,
                first_access=event.path not in seen_paths,
                content_returned_to_model=returned_to_model,
                content_truncated=bool(metadata.get("truncated") or metadata.get("content_truncated")),
                file_access_observed=True,
                returned_to_model_source=returned_source,
            )
        )
        seen_paths.add(event.path)

    observation.file_access = file_access
    observation.tool_calls = [
        event
        for event in primary_events
        if event.event_type in {EventType.TOOL_CALL, EventType.TOOL_RESULT}
        or event.metadata.get("tool_call")
    ]
    observation.process_events = [
        event for event in primary_events if event.event_type in _PROCESS_TYPES
    ]
    return observation


def validate_normalized(observation: NormalizedObservation) -> list[str]:
    errors: list[str] = []
    sequences = [event.sequence for event in observation.events]
    if sequences != list(range(1, len(sequences) + 1)):
        errors.append("normalized event sequences are not strictly increasing from 1")
    ids = {event.event_id for event in observation.events}
    for event in observation.events:
        if event.parent_event_id and event.parent_event_id not in ids:
            errors.append(f"parent event missing: {event.parent_event_id}")
    return errors

