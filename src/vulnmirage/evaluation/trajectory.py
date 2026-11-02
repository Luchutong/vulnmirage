"""Trajectory-level metrics derived only from observable events."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..models import (
    AuditStage,
    EnrichedTrajectoryEvent,
    EvidenceRole,
    VerificationAssessment,
)

_SUSPICIOUS = {
    EvidenceRole.MANIPULATION.value,
    EvidenceRole.DECOY.value,
    EvidenceRole.FALSE_BRIDGE.value,
}
_TRUE = {
    EvidenceRole.ENTRY_POINT.value,
    EvidenceRole.TRUE_TRACE.value,
    EvidenceRole.CRITICAL_OPERATION.value,
    EvidenceRole.DECISIVE_COUNTEREVIDENCE.value,
}


def _first_time(
    enriched: list[EnrichedTrajectoryEvent],
    start_ns: int,
    predicate,
) -> float | None:
    for item in enriched:
        if predicate(item):
            return max((item.event.monotonic_ns - start_ns) / 1_000_000_000.0, 0.0)
    return None


def _first_tool_calls(
    enriched: list[EnrichedTrajectoryEvent], predicate
) -> int | None:
    count = 0
    for item in enriched:
        if item.event.event_type.value in {"tool_call", "command"}:
            count += 1
        if predicate(item):
            return count
    return None


def trajectory_metrics(
    *,
    enriched: list[EnrichedTrajectoryEvent],
    start_monotonic_ns: int,
    assessments: list[VerificationAssessment],
    end_monotonic_ns: int | None = None,
) -> dict[str, Any]:
    ordered = [item for item in enriched if not item.metadata.get("derived")]
    first_repo = _first_time(ordered, start_monotonic_ns, lambda item: bool(item.event.path))
    first_exposure = _first_time(
        ordered, start_monotonic_ns, lambda item: bool(set(item.roles) & _SUSPICIOUS)
    )
    first_true = _first_time(
        ordered, start_monotonic_ns, lambda item: bool(set(item.roles) & _TRUE)
    )
    first_ep = _first_time(
        ordered, start_monotonic_ns, lambda item: EvidenceRole.ENTRY_POINT.value in item.roles
    )
    first_trace = _first_time(
        ordered, start_monotonic_ns, lambda item: EvidenceRole.TRUE_TRACE.value in item.roles
    )
    first_co = _first_time(
        ordered, start_monotonic_ns, lambda item: EvidenceRole.CRITICAL_OPERATION.value in item.roles
    )
    decisive_ids = {
        event_id
        for assessment in assessments
        for event_id in assessment.decisive_event_ids
    }
    first_decisive = _first_time(
        ordered, start_monotonic_ns, lambda item: item.event.event_id in decisive_ids
    )
    stage_times: dict[str, float] = defaultdict(float)
    stage_counts: dict[str, int] = defaultdict(int)
    transitions = 0
    previous_stage = None
    for index, item in enumerate(ordered):
        stage_counts[item.stage] += 1
        if previous_stage is not None and item.stage != previous_stage:
            transitions += 1
        previous_stage = item.stage
        if index + 1 < len(ordered):
            dwell = max(
                (ordered[index + 1].event.monotonic_ns - item.event.monotonic_ns) / 1e9, 0.0
            )
        else:
            end_ns = end_monotonic_ns or item.event.monotonic_ns
            dwell = max((end_ns - item.event.monotonic_ns) / 1e9, 0.0)
        stage_times[item.stage] += dwell
    backtracking = 0
    previous_roles: set[str] = set()
    for item in ordered:
        roles = set(item.roles)
        if previous_roles & _SUSPICIOUS and roles & _TRUE:
            backtracking += 1
        previous_roles = roles
    return {
        "time_to_first_repository_evidence": first_repo,
        "time_to_first_manipulation_exposure": first_exposure,
        "time_to_first_true_evidence": first_true,
        "time_to_first_entry_point": first_ep,
        "time_to_first_true_trace": first_trace,
        "time_to_first_critical_operation": first_co,
        "time_to_first_decisive_verification": first_decisive,
        "tool_calls_to_first_repository_evidence": _first_tool_calls(
            ordered, lambda item: bool(item.event.path)
        ),
        "tool_calls_to_first_manipulation_exposure": _first_tool_calls(
            ordered, lambda item: bool(set(item.roles) & _SUSPICIOUS)
        ),
        "tool_calls_to_first_true_evidence": _first_tool_calls(
            ordered, lambda item: bool(set(item.roles) & _TRUE)
        ),
        "stage_dwell_seconds": dict(stage_times),
        "stage_counts": dict(stage_counts),
        "stage_transitions": transitions,
        "backtracking_count": backtracking,
        "final_stage": ordered[-1].stage if ordered else AuditStage.EXPLORE.value,
        "observed_event_count": len(ordered),
    }


def role_sequence(enriched: list[EnrichedTrajectoryEvent]) -> list[str]:
    sequence: list[str] = []
    for item in enriched:
        if item.roles:
            sequence.append("+".join(sorted(item.roles)))
        else:
            sequence.append(item.stage)
    return sequence


def sequence_distance(left: list[str], right: list[str]) -> float | None:
    if not left and not right:
        return 0.0
    if not left or not right:
        return None
    # Normalized Levenshtein distance.
    previous = list(range(len(right) + 1))
    for i, left_item in enumerate(left, start=1):
        current = [i]
        for j, right_item in enumerate(right, start=1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (0 if left_item == right_item else 1),
                )
            )
        previous = current
    return previous[-1] / max(len(left), len(right))
