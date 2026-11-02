"""Versioned audit-stage classification and enriched trajectory construction."""

from __future__ import annotations

from ..config import TrajectoryConfig
from ..hashing import stable_id
from ..models import (
    AgentFinding,
    AuditStage,
    CodeLocation,
    EnrichedTrajectoryEvent,
    EventSource,
    EventType,
    EvidenceContract,
    EvidenceRole,
    UnifiedEvent,
)
from .evidence import EvidenceNode, _overlap, event_roles

STAGE_RULE_VERSION = "1.0"

_TRUE_ROLES = {
    EvidenceRole.ENTRY_POINT.value,
    EvidenceRole.TRUE_TRACE.value,
    EvidenceRole.CRITICAL_OPERATION.value,
    EvidenceRole.DECISIVE_COUNTEREVIDENCE.value,
}
_SUSPICIOUS_ROLES = {
    EvidenceRole.MANIPULATION.value,
    EvidenceRole.DECOY.value,
    EvidenceRole.FALSE_BRIDGE.value,
}
_VERIFICATION_TYPES = {
    EventType.BUILD.value,
    EventType.TEST.value,
    EventType.POC.value,
}


def _claim_ids_for_event(
    event: UnifiedEvent, nodes: list[EvidenceNode], contract: EvidenceContract | None
) -> list[str]:
    if contract is None or not event.path:
        return []
    start = event.metadata.get("observed_start_line") or event.metadata.get("start_line")
    end = event.metadata.get("observed_end_line") or event.metadata.get("end_line") or start
    if start is None:
        return []
    location_file = event.path
    result: set[str] = set()
    for node in nodes:
        if node.location.file != location_file:
            continue
        if _overlap(
            CodeLocation(file=location_file, start_line=start, end_line=end),
            node.location,
        ):
            result.update(node.claim_ids)
    return sorted(result)


def enrich_trajectory(
    *,
    run_id: str,
    events: list[UnifiedEvent],
    nodes: list[EvidenceNode],
    contract: EvidenceContract | None,
    findings: list[AgentFinding] | None,
    config: TrajectoryConfig,
) -> list[EnrichedTrajectoryEvent]:
    enriched: list[EnrichedTrajectoryEvent] = []
    stage = AuditStage.EXPLORE
    saw_suspicious = False
    for event in events:
        roles = [role.value for role in event_roles(event, nodes)]
        role_set = set(roles)
        if role_set & _SUSPICIOUS_ROLES:
            saw_suspicious = True
        if role_set & _TRUE_ROLES:
            if stage == AuditStage.EXPLORE or (
                stage == AuditStage.HYPOTHESIZE and EvidenceRole.TRUE_TRACE.value in role_set
            ):
                stage = AuditStage.HYPOTHESIZE if stage == AuditStage.EXPLORE else AuditStage.EVIDENCE_COLLECTION
        if saw_suspicious and stage == AuditStage.EXPLORE:
            stage = AuditStage.HYPOTHESIZE
        if stage in {AuditStage.HYPOTHESIZE, AuditStage.EVIDENCE_COLLECTION} and (
            role_set & _TRUE_ROLES or role_set & _SUSPICIOUS_ROLES
        ):
            if stage == AuditStage.HYPOTHESIZE and EvidenceRole.TRUE_TRACE.value in role_set:
                stage = AuditStage.EVIDENCE_COLLECTION
        if event.event_type.value in _VERIFICATION_TYPES or (
            event.event_type.value == EventType.COMMAND.value
            and any(token in (event.argv or []) for token in ("test", "pytest", "poc", "build"))
        ):
            stage = AuditStage.VERIFICATION
        if event.event_type.value == EventType.FINDING.value:
            stage = AuditStage.REPORTING
        enriched.append(
            EnrichedTrajectoryEvent(
                event=event,
                roles=sorted(role_set),
                stage=stage.value,
                claim_ids=_claim_ids_for_event(event, nodes, contract),
                node_ids=[
                    node.node_id
                    for node in nodes
                    if event.path
                    and node.location.file == event.path
                    and (
                        event.metadata.get("observed_start_line") is None
                        or _overlap(
                            CodeLocation(
                                file=event.path,
                                start_line=int(
                                    event.metadata.get("observed_start_line")
                                    or event.metadata.get("start_line")
                                ),
                                end_line=int(
                                    event.metadata.get("observed_end_line")
                                    or event.metadata.get("end_line")
                                    or event.metadata.get("observed_start_line")
                                    or event.metadata.get("start_line")
                                ),
                            ),
                            node.location,
                        )
                    )
                ],
                derived_from=[event.event_id],
            )
        )
    if findings:
        last = enriched[-1].event if enriched else None
        order = (last.sequence if last else 0) + 1
        for index, finding in enumerate(findings, start=1):
            event = UnifiedEvent(
                event_id=stable_id("EV-REPORT", run_id, finding.finding_id, index),
                run_id=run_id,
                sequence=order,
                timestamp_utc=(last.timestamp_utc if last else "1970-01-01T00:00:00Z"),
                monotonic_ns=(last.monotonic_ns + index if last else index),
                event_type=EventType.FINDING,
                source=EventSource.EVALUATOR,
                metadata={"finding_id": finding.finding_id, "derived": True},
            )
            enriched.append(
                EnrichedTrajectoryEvent(
                    event=event,
                    roles=[],
                    stage=AuditStage.REPORTING.value,
                    derived_from=[finding.finding_id],
                    metadata={"derived": True},
                )
            )
    return enriched
