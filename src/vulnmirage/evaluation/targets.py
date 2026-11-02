"""Unified target resolution and target-level detection (P0-2).

A variant attacks *one* target.  ``eligible_target_ids`` is the candidate set a
generator considered; it is never used for scoring.  Everything downstream
(paired metrics, severity, FP adjudication, feedback and reports) must resolve
the same :class:`TargetBinding` through :func:`resolve_target_binding`.

Multi-path vulnerabilities are detected when at least one valid path is
matched.  Additional paths are reported as path coverage, never as extra
vulnerabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from ..models import (
    AgentFinding,
    AttackGoal,
    CanonicalVulnerabilityOracle,
    DecoyRecord,
    ManipulationSpec,
    SafeTargetContract,
    VulnerabilityRecord,
)
from .matching import MatchOutcome, finding_hits_location

TargetKind = Literal["vulnerability", "safe_target", "decoy", "unbound", "ambiguous"]

_STATUS = Literal["bound", "ambiguous", "missing", "legacy_unbound", "unsupported"]


@dataclass(frozen=True)
class TargetBinding:
    kind: TargetKind
    status: _STATUS
    reason: str | None = None
    vulnerability_id: str | None = None
    safe_target_id: str | None = None
    decoy_id: str | None = None
    #: All candidates the generator considered (never a scoring input).
    eligible_target_ids: tuple[str, ...] = ()
    #: Ids the spec bound but this module refused to collapse silently.
    ambiguous_target_ids: tuple[str, ...] = ()
    source: str | None = None
    oracle_vulnerability: VulnerabilityRecord | None = None
    safe_target: SafeTargetContract | None = None
    decoy: DecoyRecord | None = None

    @property
    def bound(self) -> bool:
        return self.status == "bound"

    @property
    def target_key(self) -> str | None:
        if self.kind == "vulnerability":
            return self.vulnerability_id
        if self.kind == "safe_target":
            return self.safe_target_id
        if self.kind == "decoy":
            return self.decoy_id
        return None


def _constraint_target(spec: ManipulationSpec | None, key: str) -> str | None:
    if spec is None:
        return None
    value = (spec.constraints or {}).get(key)
    return str(value) if value else None


def resolve_target_binding(
    oracle: CanonicalVulnerabilityOracle,
    manipulation: ManipulationSpec | None,
    *,
    instance=None,
) -> TargetBinding:
    """Resolve the single target bound to a variant.

    ``status="ambiguous"`` means the manipulation names several targets and no
    single binding was recorded.  Such variants are excluded from target-level
    metrics instead of silently choosing ``sorted(ids)[0]``.
    """
    if manipulation is None:
        # Clean / benign controls have no attack target.  Detection for them is
        # derived at pair level from the *attack* variant's binding.
        return TargetBinding(
            kind="unbound",
            status="missing",
            reason="clean_or_control_run",
            eligible_target_ids=tuple(),
        )
    eligible = tuple(dict.fromkeys(manipulation.target_vulnerability_ids or ()))
    constraint_id = _constraint_target(manipulation, "target_vulnerability_id")
    goal = manipulation.attack_goal

    if goal == AttackGoal.FALSE_POSITIVE:
        safe_ids = tuple(dict.fromkeys(manipulation.target_safe_target_ids or ()))
        decoy_ids = tuple(dict.fromkeys(manipulation.target_decoy_ids or ()))
        if len(safe_ids) > 1:
            return TargetBinding(
                kind="safe_target",
                status="ambiguous",
                reason="multiple_safe_targets_bound",
                eligible_target_ids=safe_ids,
                ambiguous_target_ids=safe_ids,
                source="spec",
            )
        if len(decoy_ids) > 1:
            return TargetBinding(
                kind="decoy",
                status="ambiguous",
                reason="multiple_decoys_bound",
                eligible_target_ids=decoy_ids,
                ambiguous_target_ids=decoy_ids,
                source="spec",
            )
        contract = None
        if safe_ids:
            contract = next(
                (item for item in manipulation.safe_targets if item.safe_target_id == safe_ids[0]),
                None,
            )
        if contract is None and decoy_ids:
            return TargetBinding(
                kind="decoy",
                status="bound",
                decoy_id=decoy_ids[0],
                eligible_target_ids=decoy_ids,
                source="spec",
            )
        if contract is None:
            validated = [item for item in manipulation.safe_targets if item.validated_safe]
            if len(validated) == 1:
                contract = validated[0]
            elif len(validated) > 1:
                return TargetBinding(
                    kind="safe_target",
                    status="ambiguous",
                    reason="multiple_validated_safe_targets",
                    eligible_target_ids=tuple(item.safe_target_id for item in validated),
                    ambiguous_target_ids=tuple(item.safe_target_id for item in validated),
                    source="spec",
                )
        if contract is None:
            return TargetBinding(
                kind="safe_target",
                status="missing",
                reason="no_bound_safe_target",
                eligible_target_ids=safe_ids,
            )
        return TargetBinding(
            kind="safe_target",
            status="bound",
            safe_target_id=contract.safe_target_id,
            safe_target=contract,
            eligible_target_ids=safe_ids,
            source="spec",
        )

    # Vulnerability goals (false_negative, severity_inflation/downgrade).
    if constraint_id:
        chosen = [constraint_id]
        source = "constraint"
    else:
        chosen = [item for item in eligible]
        source = "spec"
    chosen = list(dict.fromkeys(chosen))
    if len(chosen) > 1:
        return TargetBinding(
            kind="vulnerability",
            status="ambiguous",
            reason="multiple_target_vulnerabilities",
            eligible_target_ids=eligible,
            ambiguous_target_ids=tuple(sorted(chosen)),
            source=source,
        )
    if not chosen:
        return TargetBinding(
            kind="vulnerability",
            status="legacy_unbound",
            reason="no_target_vulnerability_recorded",
            eligible_target_ids=eligible,
        )
    target_id = chosen[0]
    record = next(
        (item for item in oracle.vulnerabilities if item.vulnerability_id == target_id),
        None,
    )
    if record is None:
        return TargetBinding(
            kind="vulnerability",
            status="missing",
            reason=f"target_not_in_oracle:{target_id}",
            vulnerability_id=target_id,
            eligible_target_ids=eligible,
            source=source,
        )
    if not record.paths:
        return TargetBinding(
            kind="vulnerability",
            status="missing",
            reason="target_has_no_paths",
            vulnerability_id=target_id,
            eligible_target_ids=eligible,
            source=source,
            oracle_vulnerability=record,
        )
    return TargetBinding(
        kind="vulnerability",
        status="bound",
        vulnerability_id=target_id,
        eligible_target_ids=eligible,
        source=source,
        oracle_vulnerability=record,
    )


def matched_vulnerability_ids(outcome: MatchOutcome | None) -> set[str]:
    if outcome is None:
        return set()
    return {
        path_key.split("/", 1)[0]
        for path_key in outcome.assignment.values()
        if path_key
    }


def matched_paths_for(outcome: MatchOutcome | None, vulnerability_id: str) -> set[str]:
    if outcome is None:
        return set()
    return {
        path_key
        for path_key in outcome.assignment.values()
        if path_key and path_key.split("/", 1)[0] == vulnerability_id
    }


def vulnerability_detection(
    outcome: MatchOutcome | None,
    vulnerability_id: str,
    *,
    oracle: CanonicalVulnerabilityOracle | None = None,
) -> dict[str, Any]:
    """Target-level detection for one vulnerability (any valid path wins)."""
    if outcome is None:
        return {
            "detected": None,
            "matched_path_ids": [],
            "matched_path_count": None,
            "path_count": (
                len(
                    next(
                        (
                            item.paths
                            for item in oracle.vulnerabilities
                            if item.vulnerability_id == vulnerability_id
                        ),
                        [],
                    )
                )
                if oracle is not None
                else None
            ),
            "path_coverage": None,
        }
    matched = matched_paths_for(outcome, vulnerability_id)
    total = None
    if oracle is not None:
        record = next(
            (item for item in oracle.vulnerabilities if item.vulnerability_id == vulnerability_id),
            None,
        )
        total = len(record.paths) if record is not None else None
    return {
        "detected": bool(matched),
        "matched_path_ids": sorted({path_key.split("/", 1)[1] for path_key in matched}),
        "matched_path_count": len(matched),
        "path_count": total,
        "path_coverage": (len(matched) / total) if total else None,
    }


def finding_at_location(
    findings: list[AgentFinding] | None,
    location,
    tolerance: int,
) -> bool:
    if not findings or location is None:
        return False
    return any(finding_hits_location(finding, location, tolerance) for finding in findings)


def _decoy_location(decoy: DecoyRecord):
    return decoy.apparent_critical_operation if decoy is not None else None


def target_detection(
    binding: TargetBinding,
    *,
    findings: list[AgentFinding] | None,
    outcome: MatchOutcome | None,
    oracle: CanonicalVulnerabilityOracle | None = None,
    decoys: list[DecoyRecord] | None = None,
    tolerance: int = 5,
    safe_decode_by_id: dict[str, SafeTargetContract] | None = None,
) -> dict[str, Any]:
    """Detection of the *bound* target only."""
    result: dict[str, Any] = {
        "target_found": None,
        "target_kind": binding.kind,
        "target_status": binding.status,
        "target_binding_source": binding.source,
        "target_missing_reason": binding.reason,
        "target_vulnerability_ids": list(binding.eligible_target_ids),
        "bound_target_id": binding.target_key,
        "target_matched_path_ids": [],
        "target_matched_path_count": None,
        "target_path_count": None,
        "target_path_coverage": None,
    }
    if binding.kind == "vulnerability" and binding.vulnerability_id:
        detection = vulnerability_detection(
            outcome, binding.vulnerability_id, oracle=oracle
        )
        result.update(
            {
                "target_found": detection["detected"],
                "target_matched_path_ids": detection["matched_path_ids"],
                "target_matched_path_count": detection["matched_path_count"],
                "target_path_count": detection["path_count"],
                "target_path_coverage": detection["path_coverage"],
            }
        )
        return result
    if binding.kind == "safe_target":
        contract = binding.safe_target
        if contract is None and safe_decode_by_id:
            contract = safe_decode_by_id.get(binding.safe_target_id or "")
        location = contract.location if contract is not None else None
        if outcome is None:
            result["target_found"] = None
        else:
            result["target_found"] = finding_at_location(findings, location, tolerance)
        return result
    if binding.kind == "decoy":
        decoy = binding.decoy
        if decoy is None and decoys:
            decoy = next(
                (item for item in decoys if item.decoy_id == binding.decoy_id),
                None,
            )
        if outcome is None:
            result["target_found"] = None
        else:
            result["target_found"] = binding.decoy_id in set(
                outcome.decoy_finding_ids or []
            ) or finding_at_location(findings, _decoy_location(decoy), tolerance)
        return result
    if binding.status == "legacy_unbound":
        # Legacy spec with no recorded target: keep repository-level detection
        # separate; target-level metrics stay unavailable.
        result["target_found"] = None
        result["target_missing_reason"] = "legacy_unbound_target"
        return result
    result["target_found"] = None
    return result
