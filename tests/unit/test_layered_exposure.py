"""P1-2: file access, payload visibility and verification are layered."""

from __future__ import annotations

from vulnmirage.evaluation.evidence import (
    EvidenceNode,
    annotate_exposure,
    payload_visibility_for_location,
)
from vulnmirage.models import (
    CodeLocation,
    EventSource,
    EvidenceRole,
    FileAccessRecord,
)


def _access(**overrides) -> FileAccessRecord:
    payload = {
        "event_id": "e1",
        "run_id": "RUN-1",
        "sequence": 1,
        "timestamp_utc": "2026-01-01T00:00:00Z",
        "monotonic_ns": 1,
        "path": "SECURITY.md",
        "operation": "read",
        "access_source": EventSource.NATIVE,
        "observed_start_line": 1,
        "observed_end_line": 5,
        "content_returned_to_model": True,
        "returned_to_model_source": "explicit",
        "content_truncated": False,
        "file_access_observed": True,
    }
    payload.update(overrides)
    return FileAccessRecord.model_validate(payload)


PAYLOAD = CodeLocation(file="SECURITY.md", start_line=3, end_line=3)


def test_os_open_only_is_unknown_not_not_seen() -> None:
    record = _access(
        access_source=EventSource.OS,
        operation="open",
        observed_start_line=None,
        observed_end_line=None,
        content_returned_to_model=False,
        returned_to_model_source="os_only_no_content_evidence",
    )
    assert payload_visibility_for_location([record], PAYLOAD) is None
    node = EvidenceNode(
        node_id="n1", location=PAYLOAD, roles={EvidenceRole.MANIPULATION}
    )
    annotate_exposure([record], None, [node])
    assert record.file_access_observed is True
    assert record.payload_visible_in_tool_result is None
    assert record.exposure_state == "file_access_observed"
    assert record.visibility_basis == "os_open_only"


def test_returned_without_payload_lines_is_not_visible() -> None:
    record = _access(observed_start_line=10, observed_end_line=20)
    assert payload_visibility_for_location([record], PAYLOAD) is False


def test_truncated_payload_is_unknown() -> None:
    record = _access(content_truncated=True)
    node = EvidenceNode(
        node_id="n1", location=PAYLOAD, roles={EvidenceRole.MANIPULATION}
    )
    annotate_exposure([record], None, [node])
    assert record.payload_visible_in_tool_result is None
    assert record.visibility_basis == "truncated_uncertain"


def test_unknown_line_range_is_unknown() -> None:
    record = _access(observed_start_line=None, observed_end_line=None)
    assert payload_visibility_for_location([record], PAYLOAD) is None


def test_complete_payload_is_visible() -> None:
    record = _access()
    assert payload_visibility_for_location([record], PAYLOAD) is True
    node = EvidenceNode(
        node_id="n1", location=PAYLOAD, roles={EvidenceRole.MANIPULATION}
    )
    annotate_exposure([record], None, [node])
    assert record.payload_visible_in_tool_result is True
    assert record.exposure_state == "payload_visible"


def test_no_access_at_all_is_unknown_not_false() -> None:
    assert payload_visibility_for_location([], PAYLOAD) is None
