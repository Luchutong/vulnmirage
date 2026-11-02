"""Deterministic hashing, identifiers and seeds.

Python's built-in ``hash()`` is randomized per process and MUST NOT be used for
persisted identifiers.  Everything here uses SHA-256 over canonical bytes.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9_-]+")


def sha256_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    """Stable JSON representation used for hashing and signatures."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )


def _json_default(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, (set, frozenset, tuple)):
        return sorted(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def stable_digest(*parts: Any) -> str:
    return sha256_text("\x1f".join(_stringify(part) for part in parts))


def _stringify(part: Any) -> str:
    if isinstance(part, str):
        return part
    if isinstance(part, (int, float, bool)) or part is None:
        return str(part)
    return canonical_json(part)


def stable_id(prefix: str, *parts: Any, length: int = 12) -> str:
    """Deterministic, path-safe identifier such as ``VMO-1A2B3C4D5E6F``."""
    cleaned = _SAFE_ID_RE.sub("-", prefix).strip("-")
    digest = stable_digest(*parts).upper()
    return f"{cleaned}-{digest[:length]}"


def derive_seed(global_seed: int, *parts: Any) -> int:
    """Derive a 63-bit seed from a global seed and stable context strings."""
    digest = stable_digest("seed", global_seed, *parts)
    return int(digest[:16], 16) & 0x7FFF_FFFF_FFFF_FFFF


def normalize_code(code: str) -> str:
    """Normalize a code snippet before hashing/comparison.

    - CRLF/CR become LF
    - trailing spaces and tabs on each line are removed
    - leading/trailing blank lines are removed
    - exactly one trailing newline is kept
    """
    normalized = code.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip(" \t") for line in normalized.split("\n")]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines) + "\n" if lines else ""


def code_sha256(code: str) -> str:
    return sha256_text(normalize_code(code))


def safe_slug(value: str, *, max_length: int = 48) -> str:
    slug = _SAFE_ID_RE.sub("-", value).strip("-").lower()
    slug = re.sub(r"-{2,}", "-", slug)
    return (slug or "item")[:max_length].strip("-") or "item"


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write text atomically (same-directory temp file + os.replace)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = text.encode(encoding)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def atomic_write_json(path: Path, value: Any, *, indent: int = 2, sort_keys: bool = True) -> None:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    text = json.dumps(value, indent=indent, sort_keys=sort_keys, ensure_ascii=False) + "\n"
    atomic_write_text(path, text)


def read_json(path: Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def random_token(nbytes: int = 8) -> str:
    return secrets.token_hex(nbytes)


def split_lines(text: str) -> list[str]:
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def joined_lines(lines: Iterable[str]) -> str:
    return "\n".join(lines)
