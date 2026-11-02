"""Structured JSON logging with secret redaction."""

from __future__ import annotations

import json
import logging as _stdlib_logging
import re
import sys
from datetime import datetime, timezone
from typing import Any, TextIO

_SECRET_KEY_RE = re.compile(
    r"(^|[._-])(api[_-]?key|token|secret|password|passwd|authorization|pat)$", re.I
)
_SECRET_VALUE_RE = re.compile(
    r"((?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})"
)
_REDACTED = "[REDACTED]"


def redact(value: Any, _depth: int = 0) -> Any:
    """Recursively redact likely credentials without touching normal content."""
    if _depth > 8:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if _SECRET_KEY_RE.search(str(key)):
                out[str(key)] = _REDACTED
            else:
                out[str(key)] = redact(item, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(item, _depth + 1) for item in value]
    if isinstance(value, str):
        return _SECRET_VALUE_RE.sub(_REDACTED, value)
    return value


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class JsonFormatter(_stdlib_logging.Formatter):
    def format(self, record: _stdlib_logging.LogRecord) -> str:
        base: dict[str, Any] = {
            "timestamp": utc_now_iso(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": redact(record.getMessage()),
        }
        extra = getattr(record, "context", None)
        if isinstance(extra, dict):
            base.update(redact(extra))
        if record.exc_info:
            base["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(base, ensure_ascii=False, sort_keys=True, default=str)


def configure_logging(level: str = "INFO", stream: TextIO | None = None) -> None:
    handler = _stdlib_logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = _stdlib_logging.getLogger("vulnmirage")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(_stdlib_logging, level.upper(), _stdlib_logging.INFO))
    root.propagate = False


def get_logger(stage: str, **context: Any) -> _stdlib_logging.LoggerAdapter:
    logger = _stdlib_logging.getLogger(f"vulnmirage.{stage}")
    merged = {"stage": stage}
    merged.update(context)
    return _stdlib_logging.LoggerAdapter(logger, {"context": merged})


def log_event(stage: str, event: str, level: str = "info", **fields: Any) -> None:
    get_logger(stage).log(getattr(_stdlib_logging, level.upper()), event, extra={"context": fields})
