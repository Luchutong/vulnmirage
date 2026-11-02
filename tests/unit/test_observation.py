"""Observation normalization and frozen raw-event invariants."""

from __future__ import annotations

from pathlib import Path

from vulnmirage.config import ObservationConfig
from vulnmirage.harness.observation.base import event_payload_hash
from vulnmirage.harness.observation.manager import _grade
from vulnmirage.harness.observation.normalize import normalize_events, validate_normalized
from vulnmirage.models import EventSource, EventType, ObservabilityGrade, UnifiedEvent


def _event(
    sequence: int,
    *,
    source: EventSource,
    event_type: EventType = EventType.FILE_ACCESS,
    path: str = "app/storage.py",
    start: int = 1,
    end: int = 2,
    tool_call_id: str = "t1",
    operation: str = "read",
) -> UnifiedEvent:
    return UnifiedEvent(
        event_id=f"EV-{sequence}",
        run_id="RUN-1",
        sequence=sequence,
        timestamp_utc="2026-01-01T00:00:00Z",
        monotonic_ns=sequence * 10_000_000,
        event_type=event_type,
        source=source,
        path=path,
        operation=operation,
        tool_call_id=tool_call_id,
        metadata={
            "observed_start_line": start,
            "observed_end_line": end,
            "requested_start_line": start,
            "requested_end_line": end,
        },
    )


def test_normalization_deduplicates_cross_source_access() -> None:
    events = [
        _event(1, source=EventSource.NATIVE),
        _event(2, source=EventSource.OS),
        _event(3, source=EventSource.NATIVE, path="app/other.py", tool_call_id="t2"),
    ]
    result = normalize_events(events, config=ObservationConfig())
    assert result.duplicates == 1
    assert len(result.file_access) == 2
    assert len(result.primary_events) == 2
    assert [event.sequence for event in result.events] == [1, 2, 3]
    duplicate = [event for event in result.events if event.metadata.get("duplicate_of")]
    assert duplicate and duplicate[0].source == EventSource.OS
    assert validate_normalized(result) == []


def test_normalization_merges_process_start_and_end() -> None:
    events = [
        UnifiedEvent(
            event_id="EV-P1",
            run_id="RUN-1",
            sequence=1,
            timestamp_utc="2026-01-01T00:00:00Z",
            monotonic_ns=10,
            event_type=EventType.PROCESS_START,
            source=EventSource.WRAPPER,
            tool_call_id="agent",
            argv=["python", "agent.py"],
        ),
        UnifiedEvent(
            event_id="EV-P2",
            run_id="RUN-1",
            sequence=2,
            timestamp_utc="2026-01-01T00:00:01Z",
            monotonic_ns=1_000_000_010,
            event_type=EventType.PROCESS_END,
            source=EventSource.WRAPPER,
            tool_call_id="agent",
            exit_code=0,
            duration_ms=1000,
        ),
    ]
    result = normalize_events(events, config=ObservationConfig())
    assert len(result.process_events) == 1
    assert result.process_events[0].exit_code == 0
    assert result.duplicates == 1


def test_raw_payload_hash_is_deterministic() -> None:
    payload = {"event": "read", "path": "app/storage.py", "lines": [1, 2]}
    assert event_payload_hash(payload) == event_payload_hash(dict(payload))
    assert event_payload_hash(payload) != event_payload_hash({**payload, "lines": [1, 3]})


def test_observability_grade_requires_native_events() -> None:
    # Without native events, OS tracing and the command wrapper can never raise
    # the grade above D (or A/B without native is impossible).
    assert _grade(native=0, wrapper=1, os_count=0) == ObservabilityGrade.D
    assert _grade(native=0, wrapper=1, os_count=5) == ObservabilityGrade.D
    assert _grade(native=0, wrapper=0, os_count=5) == ObservabilityGrade.D
    assert _grade(native=1, wrapper=0, os_count=0) == ObservabilityGrade.C
    assert _grade(native=1, wrapper=1, os_count=0) == ObservabilityGrade.B
