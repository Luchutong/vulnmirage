"""Observation orchestration: collect, normalize, freeze and grade."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ...config import LoadedConfig
from ...models import (
    EventSource,
    ObservabilityGrade,
    UnifiedEvent,
)
from ..base import PreparedRun, RawRunResult
from .base import SourceResult, freeze_file, sha256_file, write_jsonl
from .command_wrapper import build_wrapper_events
from .importers import importer_capabilities, select_importer
from .native import parse_native_trace
from .normalize import NormalizedObservation, normalize_events, validate_normalized
from .os_trace import os_trace_available, parse_strace, wrap_with_strace

__all__ = [
    "ObservationBundle",
    "observe_run",
    "os_trace_available",
    "wrap_with_strace",
]


@dataclass
class ObservationBundle:
    normalized: NormalizedObservation
    grade: ObservabilityGrade
    native_count: int
    wrapper_count: int
    os_count: int
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    artifact_sha256: dict[str, str] = field(default_factory=dict)
    raw_events_path: Path | None = None
    normalized_events_path: Path | None = None
    tool_calls_path: Path | None = None
    file_access_path: Path | None = None
    process_events_path: Path | None = None
    process_metrics_eligible: bool = False
    importer: str | None = None

    @property
    def primary_events(self) -> list[UnifiedEvent]:
        return self.normalized.primary_events


def _grade(native: int, wrapper: int, os_count: int) -> ObservabilityGrade:
    if native > 0 and wrapper > 0 and os_count > 0:
        return ObservabilityGrade.A
    if native > 0 and wrapper > 0:
        return ObservabilityGrade.B
    if native > 0:
        return ObservabilityGrade.C
    return ObservabilityGrade.D


def observe_run(
    *,
    loaded: LoadedConfig,
    prepared: PreparedRun,
    raw: RawRunResult,
    native_trace_path: Path,
    os_trace_path: Path | None = None,
) -> ObservationBundle:
    config = loaded.config.observation
    repo_root = prepared.repo_dir
    scratch_root = prepared.run_dir / "scratch"
    sources: list[SourceResult] = []
    notes: list[str] = []
    errors: list[str] = []
    importer_name: str | None = None

    if config.native_trace:
        importer = select_importer(native_trace_path)
        capability = importer.capability()
        importer_name = capability.name
        notes.append(
            f"native trace importer: {capability.name} "
            f"(supported={capability.supported})"
        )
        notes.extend(capability.notes)
        native = importer.import_trace(
            native_trace_path,
            run_id=prepared.run.run_id,
            repo_root=repo_root,
            scratch_root=scratch_root,
            started_monotonic_ns=raw.started_monotonic_ns,
        )
        sources.append(native)
        notes.extend(native.notes)
        errors.extend(native.errors)
    else:
        notes.append("native trace disabled by configuration")

    if config.command_wrapper:
        wrapper = build_wrapper_events(
            run_id=prepared.run.run_id,
            argv=prepared.argv,
            started_at=raw.started_at,
            ended_at=raw.ended_at,
            started_monotonic_ns=raw.started_monotonic_ns,
            exit_code=raw.exit_code,
            timed_out=raw.timed_out,
            stdout_ref=(prepared.run_dir / "stdout.log").relative_to(prepared.run_dir).as_posix(),
            stderr_ref=(prepared.run_dir / "stderr.log").relative_to(prepared.run_dir).as_posix(),
            duration_seconds=raw.duration_seconds,
        )
        sources.append(wrapper)
        notes.extend(wrapper.notes)
        errors.extend(wrapper.errors)
    else:
        notes.append("command wrapper disabled by configuration")

    os_source: SourceResult | None = None
    if os_trace_path is not None and os_trace_path.is_file():
        os_source = parse_strace(
            os_trace_path,
            run_id=prepared.run.run_id,
            repo_root=repo_root,
            scratch_root=scratch_root,
            started_monotonic_ns=raw.started_monotonic_ns,
        )
        sources.append(os_source)
        notes.extend(os_source.notes)
        errors.extend(os_source.errors)
    else:
        available, os_notes = os_trace_available(config.os_trace)
        notes.extend(os_notes)
        if config.os_trace == "on" and not available:
            errors.append("OS trace was requested but is unavailable on this platform")
    wrapper_count = sum(
        len([event for event in source.events if event.source == EventSource.WRAPPER])
        for source in sources
    )
    native_count = sum(
        len([event for event in source.events if event.source == EventSource.NATIVE])
        for source in sources
    )
    os_count = sum(
        len([event for event in source.events if event.source == EventSource.OS])
        for source in sources
    )
    grade = _grade(native_count, wrapper_count, os_count)
    normalized = normalize_events(
        [event for source in sources for event in source.events],
        config=config,
        capture_file_lines=config.capture_file_lines,
        capture_content_hashes=config.capture_content_hashes,
    )
    errors.extend(validate_normalized(normalized))
    notes.extend(normalized.notes)

    raw_events = [envelope for source in sources for envelope in source.raw_events]
    raw_events.sort(key=lambda item: (item.monotonic_ns, item.event_id))
    raw_path = prepared.raw_events_path or (prepared.run_dir / "events.raw.jsonl")
    normalized_path = prepared.normalized_events_path or (
        prepared.run_dir / "events.normalized.jsonl"
    )
    tool_path = prepared.tool_calls_path or (prepared.run_dir / "tool_calls.jsonl")
    access_path = prepared.file_access_path or (prepared.run_dir / "file_access.jsonl")
    process_path = prepared.process_events_path or (prepared.run_dir / "process_events.jsonl")
    digest_raw = write_jsonl(raw_path, raw_events)
    digest_normalized = write_jsonl(normalized_path, normalized.events)
    digest_tools = write_jsonl(tool_path, normalized.tool_calls)
    digest_access = write_jsonl(access_path, normalized.file_access)
    digest_process = write_jsonl(process_path, normalized.process_events)
    if config.retain_raw_events:
        freeze_file(raw_path)

    minimum = loaded.config.observation.minimum_grade_for_process_metrics
    eligible = (grade == ObservabilityGrade.A and minimum in {"A", "B"}) or (
        grade == ObservabilityGrade.B and minimum == "B"
    )
    return ObservationBundle(
        normalized=normalized,
        grade=grade,
        native_count=native_count,
        wrapper_count=wrapper_count,
        os_count=os_count,
        notes=notes,
        errors=errors,
        artifact_sha256={
            "events.raw.jsonl": digest_raw,
            "events.normalized.jsonl": digest_normalized,
            "tool_calls.jsonl": digest_tools,
            "file_access.jsonl": digest_access,
            "process_events.jsonl": digest_process,
        },
        raw_events_path=raw_path,
        normalized_events_path=normalized_path,
        tool_calls_path=tool_path,
        file_access_path=access_path,
        process_events_path=process_path,
        process_metrics_eligible=eligible,
        importer=importer_name,
    )
