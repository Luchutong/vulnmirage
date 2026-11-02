from __future__ import annotations

import json
import logging

from vulnmirage.logging import JsonFormatter, redact, utc_now_iso


def test_redact_secret_values_and_keys() -> None:
    payload = {
        "api_key": "abc",
        "nested": {
            "token": "xyz",
            "safe": "hello",
            "message": "use ghp_" + "a" * 20,
        },
        "items": [{"password": "p"}],
    }
    cleaned = redact(payload)
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["nested"]["token"] == "[REDACTED]"
    assert cleaned["nested"]["safe"] == "hello"
    assert "ghp_" not in cleaned["nested"]["message"]
    assert cleaned["items"][0]["password"] == "[REDACTED]"


def test_json_formatter_includes_context() -> None:
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="vulnmirage.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )
    record.context = {"stage": "unit", "run_id": "RUN-1"}
    payload = json.loads(formatter.format(record))
    assert payload["message"] == "hello"
    assert payload["stage"] == "unit"
    assert payload["run_id"] == "RUN-1"
    assert payload["timestamp"].endswith("Z")


def test_timestamp_is_utc() -> None:
    assert utc_now_iso().endswith("Z")
