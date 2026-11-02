"""Integrity checks for a completed run's observation artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...hashing import sha256_file
from .base import event_payload_hash


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def validate_run_artifacts(
    run_dir: Path,
    *,
    check_event_order: bool = True,
    check_artifact_hashes: bool = True,
    check_parent_links: bool = True,
) -> dict[str, Any]:
    run_dir = Path(run_dir)
    errors: list[str] = []
    notes: list[str] = []
    raw_path = run_dir / "events.raw.jsonl"
    normalized_path = run_dir / "events.normalized.jsonl"
    raw = _read_jsonl(raw_path)
    normalized = _read_jsonl(normalized_path)
    if not raw_path.is_file():
        errors.append("events.raw.jsonl is missing")
    if not normalized_path.is_file():
        errors.append("events.normalized.jsonl is missing")
    for index, row in enumerate(raw, start=1):
        payload = row.get("raw_payload")
        expected = row.get("raw_payload_sha256")
        if not isinstance(payload, dict) or not expected:
            errors.append(f"raw event {index} lacks payload/hash")
            continue
        if event_payload_hash(payload) != expected:
            errors.append(f"raw event {index} payload hash mismatch")
    if check_event_order:
        sequences = [row.get("sequence") for row in normalized]
        if sequences != list(range(1, len(sequences) + 1)):
            errors.append("normalized event sequences are not strictly increasing from 1")
        monotonic = [row.get("monotonic_ns") for row in normalized]
        if monotonic != sorted(monotonic):
            errors.append("normalized monotonic_ns values are not sorted")
    if check_parent_links:
        ids = {row.get("event_id") for row in normalized}
        for row in normalized:
            parent = row.get("parent_event_id")
            if parent and parent not in ids:
                errors.append(f"normalized parent event missing: {parent}")
    meta_path = run_dir / "meta.json"
    if check_artifact_hashes:
        if not meta_path.is_file():
            errors.append("meta.json is missing")
        else:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            for relative, expected in (meta.get("artifact_sha256") or {}).items():
                target = run_dir / relative
                if not target.is_file():
                    errors.append(f"artifact missing: {relative}")
                elif sha256_file(target) != expected:
                    errors.append(f"artifact hash mismatch: {relative}")
            raw_frozen = meta.get("raw_events_frozen")
            if raw_frozen is None:
                notes.append("meta.json has no raw_events_frozen flag")
    return {
        "ok": not errors,
        "run_dir": str(run_dir),
        "raw_event_count": len(raw),
        "normalized_event_count": len(normalized),
        "errors": errors,
        "notes": notes,
    }
