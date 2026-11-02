"""Explicit target resolution shared by planning, operators and generation.

No code path may fall back to ``oracle.vulnerabilities[0]``: a target is either
named by the request (``target_vulnerability_ids`` / ``target_safe_target_ids``),
declared by the generation config, or selected by a documented, recorded policy.
"""

from __future__ import annotations

from typing import Iterable

from ..hashing import sha256_text
from ..models import (
    AgentFinding,
    CanonicalVulnerabilityOracle,
    SafeTargetContract,
    VulnerabilityPath,
    VulnerabilityRecord,
)


def resolve_target_vulnerability(
    oracle: CanonicalVulnerabilityOracle,
    *,
    target_vulnerability_id: str | None = None,
    target_vulnerability_ids: Iterable[str] | None = None,
) -> VulnerabilityRecord:
    """Resolve exactly one target vulnerability, or raise."""
    requested: list[str] = []
    if target_vulnerability_id:
        requested.append(target_vulnerability_id)
    for item in target_vulnerability_ids or []:
        if item and item not in requested:
            requested.append(item)
    by_id = {item.vulnerability_id: item for item in oracle.vulnerabilities}
    # Dataset identifiers (CVE/GHSA) are user-facing aliases; resolve them to
    # the canonical internal vulnerability_id before binding.
    alias_to_id: dict[str, str] = {}
    for item in oracle.vulnerabilities:
        for alias in item.aliases:
            alias_to_id.setdefault(str(alias), item.vulnerability_id)
        alias_to_id.setdefault(item.vulnerability_id, item.vulnerability_id)
    if requested:
        resolved: list[str] = []
        unknown: list[str] = []
        for item in requested:
            canonical = alias_to_id.get(item)
            if canonical is None:
                unknown.append(item)
            elif canonical not in resolved:
                resolved.append(canonical)
        if unknown:
            raise ValueError(f"unknown target vulnerability id(s): {sorted(unknown)}")
        if len(resolved) > 1:
            raise ValueError(
                "a single variant must bind exactly one target vulnerability; "
                f"got {sorted(resolved)}"
            )
        return by_id[resolved[0]]
    return sorted(oracle.vulnerabilities, key=lambda item: item.vulnerability_id)[0]


def resolve_target_path(
    vulnerability: VulnerabilityRecord, *, path_id: str | None = None
) -> VulnerabilityPath:
    if path_id:
        for path in vulnerability.paths:
            if path.path_id == path_id:
                return path
        raise ValueError(
            f"unknown path_id {path_id!r} for vulnerability {vulnerability.vulnerability_id}"
        )
    return sorted(
        vulnerability.paths,
        key=lambda item: (item.critical_operation.file, item.path_id),
    )[0]


def select_target_from_spec(
    oracle: CanonicalVulnerabilityOracle, spec
) -> tuple[VulnerabilityRecord, VulnerabilityPath]:
    """Target bound by a manipulation spec (never the oracle's first record)."""
    constraints = getattr(spec, "constraints", {}) or {}
    vulnerability_id = constraints.get("target_vulnerability_id")
    path_id = constraints.get("target_path_id")
    declared = list(spec.target_vulnerability_ids)
    if not vulnerability_id and declared:
        # A spec may carry the oracle's full id set (legacy); a single variant
        # still needs one target.  Prefer an explicitly single id, otherwise use
        # the documented ``first_by_id`` selection policy -- never oracle order.
        vulnerability_id = declared[0] if len(declared) == 1 else sorted(declared)[0]
    vulnerability = resolve_target_vulnerability(
        oracle, target_vulnerability_id=vulnerability_id
    )
    return vulnerability, resolve_target_path(vulnerability, path_id=path_id)


def select_safe_target_from_spec(spec) -> SafeTargetContract | None:
    """The one validated safe target bound by the spec (P0-5).

    A spec never selects among several validated targets: either it names the
    target it manipulates or the candidate is not a false-positive candidate.
    """
    requested = set(spec.target_safe_target_ids or [])
    for contract in sorted(spec.safe_targets, key=lambda item: item.safe_target_id):
        if not contract.validated_safe:
            continue
        if not requested or contract.safe_target_id in requested:
            return contract
    return None


def target_handle(*parts: str) -> str:
    """Short-lived public handle; the local mapping stays private."""
    digest = sha256_text("|".join(parts))
    return f"TH-{digest[:16].upper()}"


def claim_handle(plan_handle: str, claim_index: int) -> str:
    digest = sha256_text(f"{plan_handle}|claim|{claim_index}")
    return f"CH-{digest[:16].upper()}"


def finding_targets_validated_safe(
    finding: AgentFinding,
    safe_targets: list[SafeTargetContract],
    *,
    tolerance: int,
) -> list[SafeTargetContract]:
    """Findings that point at a validated-safe location (evaluation-side)."""

    hits: list[SafeTargetContract] = []
    for contract in safe_targets:
        if not contract.validated_safe:
            continue
        location = contract.location
        for candidate in [finding.critical_operation, *finding.locations]:
            if candidate is None or candidate.file != location.file:
                continue
            if (
                candidate.start_line <= location.end_line + tolerance
                and location.start_line - tolerance <= candidate.end_line
            ):
                hits.append(contract)
                break
    return hits
