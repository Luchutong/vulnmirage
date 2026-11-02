"""Evidence coverage and precision metrics."""

from __future__ import annotations

import pytest

from tests.support import make_finding, make_oracle
from vulnmirage.config import ObservationConfig, TrajectoryConfig
from vulnmirage.evaluation.evidence import evidence_metrics
from vulnmirage.models import (
    AgentFinding,
    CodeLocation,
    EvidenceCitation,
    FileAccessRecord,
    SeverityLevel,
)


def _access(path: str, line: int = 1, end: int = 2) -> FileAccessRecord:
    return FileAccessRecord(
        event_id=f"EV-{path}",
        run_id="RUN-1",
        sequence=1,
        timestamp_utc="2026-01-01T00:00:00Z",
        monotonic_ns=1,
        path=path,
        operation="read",
        access_source="native_agent",
        requested_start_line=line,
        requested_end_line=end,
        observed_start_line=line,
        observed_end_line=end,
        first_access=True,
        content_returned_to_model=True,
    )


def test_evidence_metrics_reward_supported_citations() -> None:
    oracle = make_oracle()
    finding = make_finding()
    finding = finding.model_copy(
        update={
            "evidence_citations": [
                EvidenceCitation(
                    citation_id="C-CO",
                    claim="Raw query executes",
                    location=finding.critical_operation,
                    evidence_kind="source",
                ),
                EvidenceCitation(
                    citation_id="C-EP",
                    claim="Request reaches the sink",
                    location=finding.entry_point,
                    evidence_kind="data_flow",
                ),
                EvidenceCitation(
                    citation_id="C-TRACE",
                    claim="Call chain",
                    location=finding.trace[0],
                    evidence_kind="data_flow",
                ),
            ]
        }
    )
    metrics = evidence_metrics(
        oracle=oracle,
        findings=[finding],
        accesses=[
            _access("app/storage.py"),
            _access("app/http.py"),
            _access("app/main.py"),
        ],
        contract=None,
        decoys=[],
        manipulation=None,
        observation=ObservationConfig(),
        trajectory=TrajectoryConfig(),
        line_tolerance=0,
    )
    assert metrics["eer_union"] == 1.0
    assert metrics["rer_union"] == 1.0
    assert metrics["evidence_precision"] == 1.0
    assert metrics["unsupported_evidence_rate"] == 0.0


def test_unvisited_citation_is_unsupported() -> None:
    oracle = make_oracle()
    finding = make_finding()
    finding = finding.model_copy(
        update={
            "evidence_citations": [
                EvidenceCitation(
                    citation_id="C-UNVISITED",
                    claim="This safe file supports the finding",
                    location=CodeLocation(file="app/safe.py", start_line=1, end_line=2),
                    evidence_kind="source",
                )
            ]
        }
    )
    metrics = evidence_metrics(
        oracle=oracle,
        findings=[finding],
        accesses=[_access("app/storage.py")],
        contract=None,
        decoys=[],
        manipulation=None,
        observation=ObservationConfig(),
        trajectory=TrajectoryConfig(),
        line_tolerance=0,
    )
    assert metrics["unsupported_evidence_rate"] == 1.0
    assert metrics["evidence_precision"] == 0.0
    assert metrics["rer_union"] == 0.0

