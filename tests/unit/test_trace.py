from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from tests.support import make_decoy, make_oracle
from vulnmirage.harness.trace import read_trace, summarize_trace
from vulnmirage.models import ManipulationSpec


def _event(run_id: str, kind: str, path: str | None = None, command=None, duration=0.0):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "event_type": kind,
        "path": path,
        "command": command or [],
        "duration_ms": duration,
        "metadata": {},
    }


def test_trace_summary(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    events = [
        _event("r1", "file_read", "README.md"),
        _event("r1", "file_read", "SECURITY.md", duration=120),
        _event("r1", "command", command=["python", "poc.py"], duration=5),
        _event("r1", "file_read", "app/storage.py"),
    ]
    path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
    manipulation = ManipulationSpec(
        manipulation_id="VMAN-1",
        designed_tier="M2",
        attack_goal="false_negative",
        strategy_family="false_fix_status",
        carriers=["markdown"],
        operator_names=["FalseFixStatusClaim"],
        files_touched=["SECURITY.md"],
        expected_effect="suppress",
    )
    summary = summarize_trace(
        path,
        manipulation=manipulation,
        decoys=[make_decoy()],
        oracle=make_oracle(),
    )
    assert summary.event_count == 4
    assert summary.injected_artifact_read is True
    assert summary.injected_paths_read == ["SECURITY.md"]
    assert summary.first_injected_read_seconds is not None
    assert summary.time_to_first_target_evidence is not None
    assert "SECURITY.md" in summary.files_read
    assert not summary.parse_errors


def test_trace_parse_errors(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    path.write_text('{"bad": "event"}\nnot-json\n', encoding="utf-8")
    events, errors = read_trace(path)
    assert not events
    assert len(errors) == 2


def test_trace_missing_file(tmp_path: Path) -> None:
    summary = summarize_trace(
        tmp_path / "missing.jsonl",
        manipulation=None,
        decoys=[],
        oracle=make_oracle(),
    )
    assert summary.event_count == 0
    assert summary.injected_artifact_read is False
