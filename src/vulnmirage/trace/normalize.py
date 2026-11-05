"""Write normalized trace artefacts beside every archived run."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from ..hashing import atomic_write_json, atomic_write_text, sha256_file
from .completeness import assess_completeness
from .models import OPENCODE_ADAPTER_VERSION, TraceManifest
from .opencode import ParseResult, parse_opencode_jsonl

TRACE_OUTPUTS = (
    "events.normalized.jsonl",
    "tool_calls.jsonl",
    "file_access.jsonl",
)


def _write_jsonl(path: Path, rows: Iterable[Any]) -> None:
    lines = []
    for row in rows:
        payload = row.model_dump(mode="json") if hasattr(row, "model_dump") else row
        lines.append(json.dumps(payload, sort_keys=True, ensure_ascii=False))
    atomic_write_text(path, "".join(line + "\n" for line in lines))


def normalize_trace(
    source_path: str | Path | None,
    output_dir: str | Path,
    *,
    adapter: str,
    repo_root: str | Path,
    secret_values: Iterable[str] = (),
) -> dict[str, Any]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    source = Path(source_path) if source_path else None
    adapter_version: str | None = None
    result = ParseResult()
    limitations: list[str] = []

    if adapter == "none":
        status = "disabled"
        unavailable = "disabled"
    elif source is None or not source.is_file():
        status = "missing"
        unavailable = "missing"
    elif source.stat().st_size == 0:
        status = "empty"
        unavailable = "empty"
    elif adapter == "opencode_jsonl":
        adapter_version = OPENCODE_ADAPTER_VERSION
        result = parse_opencode_jsonl(
            source,
            repo_root=Path(repo_root),
            secret_values=tuple(value for value in secret_values if value),
        )
        if not result.events:
            status = "unsupported"
            unavailable = "unsupported"
        else:
            unavailable = None
            status = "partial" if result.invalid_lines else "ok"
    else:
        status = "unsupported"
        unavailable = "unsupported"
        limitations.append(f"unknown trace adapter: {adapter}")

    completeness = assess_completeness(
        result.events,
        result.tool_calls,
        file_access_count=len(result.file_access),
        invalid_line_count=result.invalid_lines,
        unknown_event_count=result.unknown_events,
        unavailable_status=unavailable,
    )
    if status == "ok" and completeness.status == "partial":
        status = "partial"
    limitations.extend(completeness.limitations)

    _write_jsonl(out / TRACE_OUTPUTS[0], result.events)
    _write_jsonl(out / TRACE_OUTPUTS[1], result.tool_calls)
    _write_jsonl(out / TRACE_OUTPUTS[2], result.file_access)
    atomic_write_json(out / "trace_completeness.json", completeness)
    output_hashes = {
        name: sha256_file(out / name)
        for name in (*TRACE_OUTPUTS, "trace_completeness.json")
    }
    manifest = TraceManifest(
        adapter=adapter,
        adapter_version=adapter_version,
        status=status,
        source_file=source.name if source is not None else None,
        source_sha256=sha256_file(source) if source is not None and source.is_file() else None,
        source_lines=result.source_lines,
        parsed_events=len(result.events),
        invalid_lines=result.invalid_lines,
        unknown_event_types=result.unknown_event_types,
        output_sha256=output_hashes,
        limitations=limitations,
    )
    atomic_write_json(out / "trace_manifest.json", manifest)
    return {
        "status": status,
        "completeness": completeness.status,
        "events": len(result.events),
        "tool_calls": len(result.tool_calls),
        "file_accesses": len(result.file_access),
        "manifest": manifest,
    }


__all__ = ["TRACE_OUTPUTS", "normalize_trace"]
