"""Observation source interfaces and shared artifact helpers."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...hashing import atomic_write_text, canonical_json, sha256_text, utc_now_iso


@dataclass
class SourceResult:
    source: str
    raw_events: list[Any] = field(default_factory=list)
    events: list[Any] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def write_jsonl(path: Path, rows: list[Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = ""
    for row in rows:
        payload = row.model_dump(mode="json") if hasattr(row, "model_dump") else row
        text += json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n"
    atomic_write_text(path, text)
    payload = path.read_bytes()
    import hashlib

    return hashlib.sha256(payload).hexdigest()


def freeze_file(path: Path) -> None:
    """Mark the raw event stream read-only after the run."""
    if not path.exists():
        return
    try:
        os.chmod(path, stat.S_IREAD)
    except OSError:
        pass


def sha256_file(path: Path) -> str | None:
    import hashlib

    if not Path(path).is_file():
        return None
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def now_utc() -> str:
    return utc_now_iso()


def event_payload_hash(payload: dict[str, Any]) -> str:
    return sha256_text(canonical_json(payload))
