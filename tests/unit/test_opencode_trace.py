"""Native trace importers: observable tool events vs OS-level access."""

from __future__ import annotations

import json
from pathlib import Path

from vulnmirage.harness.observation.importers import (
    MARKER,
    OpenCodeNativeImporter,
    UnsupportedTraceImporter,
    importer_capabilities,
    select_importer,
)
from vulnmirage.harness.observation.normalize import normalize_events
from vulnmirage.harness.observation.os_trace import parse_strace
from vulnmirage.config import ObservationConfig


def _write(tmp_path: Path, rows: list[dict]) -> Path:
    path = tmp_path / "trace.jsonl"
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    return path


def test_importer_capabilities_document_expected_format() -> None:
    capabilities = {item["importer"]: item for item in importer_capabilities()}
    assert capabilities["vulnmirage_native_jsonl"]["supported"] is True
    opencode = capabilities["opencode_native"]
    assert opencode["supported"] is True
    assert opencode["expected_format"]["marker"] == MARKER
    assert "OS-level file access never counts" in " ".join(opencode["notes"])


def test_opencode_marker_trace_is_imported(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "storage.py").write_text("x = 1\n", encoding="utf-8")
    trace = _write(
        tmp_path,
        [
            {
                MARKER: True,
                "event_type": "tool_call",
                "event_id": "e1",
                "tool_name": "read",
                "path": "app/storage.py",
                "metadata": {"start_line": 1, "end_line": 1},
            },
            {
                MARKER: True,
                "event_type": "tool_result",
                "event_id": "e2",
                "tool_name": "read",
                "path": "app/storage.py",
                "metadata": {
                    "start_line": 1,
                    "end_line": 1,
                    "returned_to_model": True,
                    "truncated": False,
                },
            },
            {
                MARKER: True,
                "event_type": "shell",
                "event_id": "e3",
                "argv": ["python", "-m", "pytest"],
                "exit_code": 0,
            },
        ],
    )
    assert isinstance(select_importer(trace), OpenCodeNativeImporter)
    result = select_importer(trace).import_trace(
        trace, run_id="RUN-1", repo_root=repo, scratch_root=None, started_monotonic_ns=0
    )
    assert len(result.events) == 3
    normalized = normalize_events(result.events, config=ObservationConfig())
    reads = [record for record in normalized.file_access if record.path == "app/storage.py"]
    assert reads
    assert reads[0].content_returned_to_model is True
    assert reads[0].content_truncated is False
    command = next(event for event in result.events if event.argv)
    assert command.exit_code == 0


def test_unmarked_trace_is_unsupported(tmp_path: Path) -> None:
    trace = _write(
        tmp_path,
        [{"type": "message", "content": "hello"}, {"event_type": "tool_call"}],
    )
    importer = select_importer(trace)
    assert isinstance(importer, UnsupportedTraceImporter)
    result = importer.import_trace(
        trace, run_id="RUN-1", repo_root=tmp_path, scratch_root=None, started_monotonic_ns=0
    )
    assert result.events == []
    assert result.notes


def test_os_trace_never_claims_model_exposure(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    strace = tmp_path / "strace.log"
    strace.write_text(
        f'1234 openat(AT_FDCWD, "{repo / "app.py"}", O_RDONLY) = 3\n',
        encoding="utf-8",
    )
    result = parse_strace(
        strace, run_id="RUN-1", repo_root=repo, scratch_root=None, started_monotonic_ns=0
    )
    assert result.events
    normalized = normalize_events(result.events, config=ObservationConfig())
    assert normalized.file_access
    assert all(
        record.content_returned_to_model is False for record in normalized.file_access
    )
