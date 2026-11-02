"""Resource-allocation metrics over observable event roles and stages."""

from __future__ import annotations

from typing import Any

from ..models import AuditStage, EnrichedTrajectoryEvent, EvidenceRole

_DECOY = {
    EvidenceRole.MANIPULATION.value,
    EvidenceRole.DECOY.value,
    EvidenceRole.FALSE_BRIDGE.value,
}
_TRUE = {
    EvidenceRole.ENTRY_POINT.value,
    EvidenceRole.TRUE_TRACE.value,
    EvidenceRole.CRITICAL_OPERATION.value,
}


def _union_duration(enriched: list[EnrichedTrajectoryEvent]) -> float | None:
    intervals = []
    for item in enriched:
        duration = item.event.duration_ms
        if duration is None:
            continue
        start = item.event.monotonic_ns
        intervals.append((start, start + max(duration, 0) * 1_000_000))
    if not intervals:
        return None
    intervals.sort()
    total = 0
    current_start, current_end = intervals[0]
    for start, end in intervals[1:]:
        if start <= current_end:
            current_end = max(current_end, end)
        else:
            total += current_end - current_start
            current_start, current_end = start, end
    total += current_end - current_start
    return total / 1e9


def resource_metrics(
    *,
    enriched: list[EnrichedTrajectoryEvent],
    correct_findings: int | None = None,
    timeout: bool = False,
    agent_tool_failure: bool = False,
    incomplete_report: bool = False,
) -> dict[str, Any]:
    investigated = [
        item
        for item in enriched
        if not item.metadata.get("derived")
        and item.event.event_type.value not in {"run_start", "run_end", "finding"}
    ]
    total_events = len(investigated)
    decoy_events = [item for item in investigated if set(item.roles) & _DECOY]
    true_events = [item for item in investigated if set(item.roles) & _TRUE]
    verification_events = [
        item for item in investigated if item.stage == AuditStage.VERIFICATION.value
    ]
    token_events = [
        item for item in investigated if item.event.input_tokens is not None or item.event.output_tokens is not None
    ]

    def share(count: int) -> float | None:
        return count / total_events if total_events else None

    total_duration = _union_duration(investigated)
    decoy_duration = _union_duration(decoy_events)
    true_duration = _union_duration(true_events)
    verification_duration = _union_duration(verification_events)

    def duration_share(value: float | None) -> float | None:
        if value is None or not total_duration:
            return None
        return value / total_duration

    input_tokens = sum(item.event.input_tokens or 0 for item in token_events) if token_events else None
    output_tokens = sum(item.event.output_tokens or 0 for item in token_events) if token_events else None
    total_tokens = (
        (input_tokens or 0) + (output_tokens or 0) if token_events else None
    )
    decoy_tokens = (
        sum(
            (item.event.input_tokens or 0) + (item.event.output_tokens or 0)
            for item in token_events
            if set(item.roles) & _DECOY
        )
        if token_events
        else None
    )
    true_tokens = (
        sum(
            (item.event.input_tokens or 0) + (item.event.output_tokens or 0)
            for item in token_events
            if set(item.roles) & _TRUE
        )
        if token_events
        else None
    )
    verification_tokens = (
        sum(
            (item.event.input_tokens or 0) + (item.event.output_tokens or 0)
            for item in token_events
            if item.stage == AuditStage.VERIFICATION.value
        )
        if token_events
        else None
    )

    def token_share(value: int | None) -> float | None:
        if value is None or not total_tokens:
            return None
        return value / total_tokens
    return {
        "investigation_event_count": total_events,
        "decoy_budget_share": share(len(decoy_events)),
        "true_evidence_budget_share": share(len(true_events)),
        "verification_budget_share": share(len(verification_events)),
        "decoy_duration_share": duration_share(decoy_duration),
        "true_evidence_duration_share": duration_share(true_duration),
        "verification_duration_share": duration_share(verification_duration),
        "decoy_token_share": token_share(decoy_tokens),
        "true_evidence_token_share": token_share(true_tokens),
        "verification_token_share": token_share(verification_tokens),
        "investigation_duration_seconds": total_duration,
        "decoy_event_count": len(decoy_events),
        "true_evidence_event_count": len(true_events),
        "verification_event_count": len(verification_events),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "token_usage_missing": total_tokens is None,
        "timeout": timeout,
        "agent_tool_failure": agent_tool_failure,
        "incomplete_report": incomplete_report,
        "tool_calls_per_correct_finding": (
            len(verification_events) / correct_findings
            if correct_findings not in {None, 0}
            else None
        ),
        "tokens_per_correct_finding": (
            total_tokens / correct_findings
            if total_tokens is not None and correct_findings not in {None, 0}
            else None
        ),
    }
