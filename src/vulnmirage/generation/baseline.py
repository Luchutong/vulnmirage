"""Reference audit (R0) acquisition, extraction and private verification.

This module reuses the existing harness, parser and :class:`AgentFinding` model;
it does not implement a second auditing agent.

Three acquisition paths are supported:

``none``
    No reference audit.  The baseline is oracle-only.
``import``
    An existing local report.  Identity metadata is mandatory unless explicitly
    waived; a metadata-free report is never cached or treated as trusted.
``run``
    A reference-only clean release executed by the existing runner with a
    separate role/session, into a separate artifact directory.  The resulting
    runs are never selected as a formal clean/control run.

Every extraction keeps the original quote/event reference.  Report statements
remain ``report_claim``; verification verdicts live only in
:class:`ReferenceFindingLink` and stay evaluation-side.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from ..config import LoadedConfig
from ..errors import ConfigError, GenerationError
from ..hashing import atomic_write_json, sha256_file, sha256_text, stable_id, utc_now_iso
from ..models import (
    AgentFinding,
    BaselineAuditContext,
    CanonicalVulnerabilityOracle,
    ReferenceAudit,
    ReferenceBudget,
    ReferenceFindingLink,
    ReferenceFindingLinkStatus,
    ReferenceFindingProfile,
    ReferenceSource,
    ReferenceStatus,
    ReferenceTraceObservation,
    SeverityLevel,
)
from ..paths import ensure_within, safe_join
from .targets import finding_targets_validated_safe

_UNCERTAIN = ("likely", "possibly", "may ", "might", "cannot confirm", "unclear", "assume")
_VERIFICATION = ("verify", "check", "confirm", "reproduce", "test", "validate", "audit")


def _safe_relative(root: Path | None, value: str | None) -> str | None:
    if not value:
        return value
    text = str(value).replace("\\", "/")
    if root is not None and text.startswith("/"):
        try:
            return Path(text).resolve().relative_to(Path(root).resolve()).as_posix()
        except ValueError:
            pass
    return text.lstrip("./")


def reference_audit_cache_key(
    *,
    repository_tree_sha256: str,
    task_sha256: str,
    agent: str,
    model: str,
    config_sha256: str,
    repetition: int,
    seed: int | None,
    environment: str,
    budget: dict[str, Any],
) -> str:
    """Identity of one acquisition; repository name alone is never enough."""
    payload = {
        "repository_tree_sha256": repository_tree_sha256,
        "task_sha256": task_sha256,
        "agent": agent,
        "model": model,
        "config_sha256": config_sha256,
        "repetition": repetition,
        "seed": seed,
        "environment": environment,
        "budget": {key: budget.get(key) for key in sorted(budget)},
    }
    return sha256_text(json.dumps(payload, sort_keys=True))


def _require_metadata(metadata: dict[str, Any], *, allow_missing: bool) -> list[str]:
    required = (
        "repository_tree_sha256",
        "task_sha256",
        "agent",
        "model",
        "session_id",
        "config_sha256",
    )
    missing = [key for key in required if not metadata.get(key)]
    if missing and not allow_missing:
        raise GenerationError(
            "reference report identity metadata is incomplete; provide a sidecar descriptor "
            "(repository_tree_sha256, task_sha256, agent, model, session_id, config_sha256) "
            "or set allow_missing_metadata=true to mark it explicitly untrusted",
            details={"missing": missing},
        )
    return missing


def load_reference_audit(
    path: Path,
    *,
    metadata_path: Path | None = None,
    allow_missing_metadata: bool = False,
    repo_root: Path | None = None,
) -> ReferenceAudit:
    """Load a persisted :class:`ReferenceAudit` (or a bare finding envelope)."""
    path = Path(path)
    if not path.is_file():
        raise GenerationError(
            "reference audit file does not exist", details={"path": str(path)}
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GenerationError(
            "reference audit is not valid JSON", details={"path": str(path)}
        ) from exc
    metadata: dict[str, Any] = {}
    if metadata_path is not None:
        metadata = json.loads(Path(metadata_path).read_text(encoding="utf-8"))
    if isinstance(payload, dict) and "reference_audit" in payload:
        payload = payload["reference_audit"]
    if isinstance(payload, dict) and "raw_report" in payload:
        raw_text = str(payload["raw_report"])
        metadata = {**metadata, **dict(payload.get("metadata") or {})}
        payload = {
            "findings": payload.get("findings") or [],
            **{key: value for key, value in payload.items() if key not in {"raw_report", "findings", "metadata"}},
        }
    else:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
    missing = _require_metadata(metadata, allow_missing=allow_missing_metadata)
    findings_payload = payload.get("findings") if isinstance(payload, dict) else None
    findings: list[AgentFinding] = []
    parse_status = ReferenceStatus.OK
    parse_error: str | None = None
    if isinstance(findings_payload, list) and findings_payload:
        try:
            findings = [AgentFinding.model_validate(item) for item in findings_payload]
        except Exception as exc:  # noqa: BLE001
            parse_status = ReferenceStatus.INVALID
            parse_error = str(exc)
    else:
        from ..evaluation.parser import parse_agent_output

        try:
            parsed = parse_agent_output(raw_text, repo_root=repo_root)
            findings = parsed.findings
        except Exception as exc:  # noqa: BLE001
            parse_status = ReferenceStatus.FORMAT_FAILURE
            parse_error = str(exc)
    if isinstance(payload, dict) and payload.get("status"):
        try:
            parse_status = ReferenceStatus(payload["status"])
        except ValueError:
            pass
    audit_id = str(
        metadata.get("reference_audit_id")
        or payload.get("reference_audit_id")
        or stable_id("REF", sha256_file(path), metadata.get("session_id", "import"))
    )
    warnings: list[str] = []
    if missing:
        warnings.append(
            "identity metadata incomplete: " + ", ".join(sorted(missing))
        )
    actions = {
        "session_start", "session_end", "tool_call", "tool_result", "file_read",
        "file_open", "search", "shell", "command", "message", "error",
    }
    trace = ReferenceTraceObservation(
        available=False,
        importer=None,
        observability_level="none",
        notes=["no verified R0 trace was imported"],
    )
    trace_payload = payload.get("trace") if isinstance(payload, dict) else None
    if isinstance(trace_payload, dict) and trace_payload:
        trace = ReferenceTraceObservation.model_validate(trace_payload)
        if trace.available and not trace.event_ids:
            warnings.append("trace declared available but carries no event ids")
    audit = ReferenceAudit(
        reference_audit_id=audit_id,
        source=ReferenceSource.IMPORT,
        status=parse_status,
        snapshot_id=metadata.get("snapshot_id"),
        repository_tree_sha256=metadata.get("repository_tree_sha256"),
        task_sha256=metadata.get("task_sha256"),
        agent=str(metadata.get("agent") or "unknown"),
        provider=metadata.get("provider"),
        model=metadata.get("model"),
        model_version=metadata.get("model_version"),
        config_sha256=metadata.get("config_sha256"),
        repetition=int(metadata.get("repetition") or 1),
        seed=metadata.get("seed"),
        session_id=str(metadata.get("session_id") or f"import-{audit_id}"),
        budget=ReferenceBudget.model_validate(metadata.get("budget") or {}),
        report_access=str(metadata.get("report_access") or "target"),
        trace_access=str(metadata.get("trace_access") or ("observable" if trace.available else "none")),
        raw_report_path=str(path),
        raw_report_sha256=sha256_file(path),
        findings_path=str(path),
        findings=findings,
        trace=trace,
        cache_key=metadata.get("cache_key"),
        imported_at=utc_now_iso(),
        source_reference=metadata.get("source_reference") or str(path),
        metadata={
            **dict(metadata),
            "metadata_complete": not missing,
            "cacheable": not missing,
            "parse_error": parse_error,
            "extraction_actions": sorted(actions) if trace.available else [],
        },
        warnings=warnings,
    )
    return audit


def store_reference_audit(audit: ReferenceAudit, *, directory: Path) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{audit.reference_audit_id}.json"
    atomic_write_json(path, {"reference_audit": audit.model_dump(mode="json")})
    return path


def _extract_uncertainty(text: str) -> str | None:
    lowered = text.lower()
    hits = [word for word in _UNCERTAIN if word in lowered]
    return f"report uses uncertainty markers: {', '.join(sorted(set(hits)))}" if hits else None


def _extract_verification_items(text: str) -> list[str]:
    items: list[str] = []
    for sentence in re_split_sentences(text):
        lowered = sentence.lower()
        if any(word in lowered for word in _VERIFICATION):
            items.append(sentence.strip()[:300])
    return items[:5]


def re_split_sentences(text: str) -> list[str]:
    import re

    return [item for item in re.split(r"(?<=[.!?])\s+", text) if item.strip()]


def extract_reference_profiles(audit: ReferenceAudit) -> list[ReferenceFindingProfile]:
    profiles: list[ReferenceFindingProfile] = []
    for index, finding in enumerate(audit.findings, start=1):
        excerpt = " ".join(
            [finding.title, finding.vulnerability_type, *finding.evidence]
        ).strip()
        uncertain = _extract_uncertainty(excerpt)
        verification = _extract_verification_items(excerpt)
        profiles.append(
            ReferenceFindingProfile(
                profile_id=f"RFP-{sha256_text(audit.reference_audit_id + finding.finding_id)[:12].upper()}",
                reference_audit_id=audit.reference_audit_id,
                finding_id=finding.finding_id,
                reported_type=finding.vulnerability_type,
                reported_cwe=list(finding.cwe),
                reported_severity=finding.severity,
                severity_rationale=(
                    finding.evidence[0][:300] if finding.evidence else None
                ),
                reported_locations=list(finding.locations),
                reported_entry_point=finding.entry_point,
                reported_critical_operation=finding.critical_operation,
                reported_trace=list(finding.trace),
                safe_judgment=(
                    excerpt[:300]
                    if "not vulnerable" in excerpt.lower() or "is safe" in excerpt.lower()
                    else None
                ),
                uncertainty=uncertain,
                verification_items=verification,
                source_excerpt=excerpt[:1000],
                extraction_method="finding_envelope",
                extraction_confidence="high" if finding.evidence_citations else "medium",
                trace_backed=bool(audit.trace.available and finding.trace),
                evidence_kind="report_claim",
            )
        )
    return profiles


def _severity_agrees(
    reported: SeverityLevel | None, oracle: SeverityLevel | None
) -> bool | None:
    if reported is None or oracle is None:
        return None
    return reported == oracle


def verify_reference_findings(
    audit: ReferenceAudit,
    profiles: list[ReferenceFindingProfile],
    oracle: CanonicalVulnerabilityOracle,
    *,
    matching_config,
    tolerance: int = 5,
) -> list[ReferenceFindingLink]:
    """Private verification of report claims against snapshot ground truth.

    Unmatched findings are ``unmatched_needs_adjudication`` -- *not* false
    positives.  The only confirmed false positives are findings on validated
    safe targets (or on validated decoys that this module does not see).
    """
    from ..evaluation.matching import match_instance

    links: list[ReferenceFindingLink] = []
    strict = match_instance(
        audit.findings, oracle, config=matching_config, profile="strict"
    )
    relaxed = match_instance(
        audit.findings, oracle, config=matching_config, profile="relaxed"
    )
    profile_by_id = {item.finding_id: item for item in profiles}
    safe_targets = oracle.validated_safe_targets()
    matched_vulnerability_ids: set[str] = set()
    for finding in audit.findings:
        profile = profile_by_id.get(finding.finding_id)
        strict_path = strict.assignment.get(finding.finding_id)
        relaxed_path = relaxed.assignment.get(finding.finding_id)
        record = next(
            (item for item in strict.matches if item.finding_id == finding.finding_id),
            None,
        )
        vulnerability = None
        path_id = None
        match_profile = None
        match_score = None
        if strict_path:
            vulnerability_id, path_id = strict_path.split("/", 1)
            vulnerability = next(
                (
                    item
                    for item in oracle.vulnerabilities
                    if item.vulnerability_id == vulnerability_id
                ),
                None,
            )
            match_profile = "strict"
            match_score = record.score if record else None
        elif relaxed_path:
            vulnerability_id, path_id = relaxed_path.split("/", 1)
            vulnerability = next(
                (
                    item
                    for item in oracle.vulnerabilities
                    if item.vulnerability_id == vulnerability_id
                ),
                None,
            )
            match_profile = "relaxed"
            match_score = next(
                (
                    item.score
                    for item in relaxed.matches
                    if item.finding_id == finding.finding_id
                ),
                None,
            )
        safe_hits = finding_targets_validated_safe(finding, safe_targets, tolerance=tolerance)
        if vulnerability is not None and match_profile == "relaxed":
            links.append(
                ReferenceFindingLink(
                    link_id=f"RFL-{sha256_text(audit.reference_audit_id + finding.finding_id + 'amb')[0:16].upper()}",
                    reference_audit_id=audit.reference_audit_id,
                    finding_id=finding.finding_id,
                    status=ReferenceFindingLinkStatus.AMBIGUOUS_MATCH,
                    vulnerability_id=vulnerability.vulnerability_id,
                    matched_path_id=path_id,
                    match_profile=match_profile,
                    match_score=match_score,
                    needs_adjudication=True,
                    reasons=[
                        "only a relaxed match was found; a different CWE at the same "
                        "location is not the same target",
                    ],
                )
            )
            continue
        if vulnerability is not None:
            matched_vulnerability_ids.add(vulnerability.vulnerability_id)
            oracle_level = (
                vulnerability.severity.level if vulnerability.severity is not None else None
            )
            agrees = _severity_agrees(profile.reported_severity if profile else None, oracle_level)
            status = (
                ReferenceFindingLinkStatus.SEVERITY_DISAGREEMENT
                if agrees is False
                else ReferenceFindingLinkStatus.MATCHED_KNOWN_VULNERABILITY
            )
            links.append(
                ReferenceFindingLink(
                    link_id=f"RFL-{sha256_text(audit.reference_audit_id + finding.finding_id)[0:16].upper()}",
                    reference_audit_id=audit.reference_audit_id,
                    finding_id=finding.finding_id,
                    status=status,
                    vulnerability_id=vulnerability.vulnerability_id,
                    matched_path_id=path_id,
                    match_profile=match_profile,
                    match_score=match_score,
                    reported_severity=profile.reported_severity if profile else None,
                    oracle_severity=oracle_level,
                    severity_agrees=agrees,
                    reasons=(
                        ["reported severity differs from the reviewed oracle severity"]
                        if agrees is False
                        else []
                    ),
                )
            )
            if oracle_level is None and profile and profile.reported_severity is not None:
                links.append(
                    ReferenceFindingLink(
                        link_id=f"RFL-{sha256_text(audit.reference_audit_id + finding.finding_id + 'sev')[0:16].upper()}",
                        reference_audit_id=audit.reference_audit_id,
                        finding_id=finding.finding_id,
                        status=ReferenceFindingLinkStatus.INSUFFICIENT_EVIDENCE,
                        vulnerability_id=vulnerability.vulnerability_id,
                        reported_severity=profile.reported_severity,
                        oracle_severity=None,
                        severity_agrees=None,
                        reasons=["oracle severity is missing; cannot adjudicate severity"],
                        needs_adjudication=True,
                    )
                )
            continue
        if safe_hits:
            links.append(
                ReferenceFindingLink(
                    link_id=f"RFL-{sha256_text(audit.reference_audit_id + finding.finding_id + 'fp')[0:16].upper()}",
                    reference_audit_id=audit.reference_audit_id,
                    finding_id=finding.finding_id,
                    status=ReferenceFindingLinkStatus.CONFIRMED_FALSE_POSITIVE,
                    safe_target_id=safe_hits[0].safe_target_id,
                    reported_severity=profile.reported_severity if profile else None,
                    reasons=[
                        "finding points at a validated-safe target; the report claim is "
                        "an already-known false positive and is not a real vulnerability",
                    ],
                    verification_evidence=[
                        f"SafeTargetContract {safe_hits[0].safe_target_id} "
                        f"({safe_hits[0].proof_method.value})"
                    ],
                    needs_adjudication=False,
                )
            )
            continue
        links.append(
            ReferenceFindingLink(
                link_id=f"RFL-{sha256_text(audit.reference_audit_id + finding.finding_id + 'unk')[0:16].upper()}",
                reference_audit_id=audit.reference_audit_id,
                finding_id=finding.finding_id,
                status=ReferenceFindingLinkStatus.UNMATCHED_NEEDS_ADJUDICATION,
                reported_severity=profile.reported_severity if profile else None,
                needs_adjudication=True,
                reasons=[
                    "finding does not match the known (partial) oracle or any validated "
                    "safe target; it is unknown, not a false positive",
                ],
            )
        )
    for vulnerability in oracle.vulnerabilities:
        if vulnerability.vulnerability_id in matched_vulnerability_ids:
            continue
        links.append(
            ReferenceFindingLink(
                link_id=f"RFL-{sha256_text(audit.reference_audit_id + vulnerability.vulnerability_id)[0:16].upper()}",
                reference_audit_id=audit.reference_audit_id,
                status=ReferenceFindingLinkStatus.KNOWN_TARGET_NOT_REPORTED,
                vulnerability_id=vulnerability.vulnerability_id,
                reasons=[
                    "known vulnerability was not reported by R0; it is retained for "
                    "oracle/combined generation but cannot be added to report-only generation",
                ],
                needs_adjudication=False,
            )
        )
    return links


def build_baseline_context(
    audit: ReferenceAudit | None,
    oracle: CanonicalVulnerabilityOracle,
    *,
    matching_config,
    target_source: str = "combined",
    report_access: str = "target",
    trace_access: str = "none",
    oracle_access: str = "target_details",
    tolerance: int = 5,
) -> BaselineAuditContext:
    if audit is None:
        return BaselineAuditContext(
            target_source=target_source,  # type: ignore[arg-type]
            report_access=report_access,  # type: ignore[arg-type]
            trace_access=trace_access,  # type: ignore[arg-type]
            oracle_access=oracle_access,  # type: ignore[arg-type]
            available=False,
            missing_reason="reference_audit.source=none",
        )
    profiles = extract_reference_profiles(audit)
    links = verify_reference_findings(
        audit, profiles, oracle, matching_config=matching_config, tolerance=tolerance
    )
    matched = [
        link.vulnerability_id
        for link in links
        if link.status
        in {
            ReferenceFindingLinkStatus.MATCHED_KNOWN_VULNERABILITY,
            ReferenceFindingLinkStatus.SEVERITY_DISAGREEMENT,
        }
        and link.vulnerability_id
    ]
    unreported = [
        link.vulnerability_id
        for link in links
        if link.status == ReferenceFindingLinkStatus.KNOWN_TARGET_NOT_REPORTED
        and link.vulnerability_id
    ]
    false_positive = [
        link.safe_target_id
        for link in links
        if link.status == ReferenceFindingLinkStatus.CONFIRMED_FALSE_POSITIVE
        and link.safe_target_id
    ]
    adjudication = [
        link.finding_id
        for link in links
        if link.status == ReferenceFindingLinkStatus.UNMATCHED_NEEDS_ADJUDICATION
        and link.finding_id
    ]
    severity = [
        link.vulnerability_id
        for link in links
        if link.status == ReferenceFindingLinkStatus.SEVERITY_DISAGREEMENT
        and link.vulnerability_id
    ]
    insufficient = [
        link.vulnerability_id
        for link in links
        if link.status == ReferenceFindingLinkStatus.INSUFFICIENT_EVIDENCE
        and link.vulnerability_id
    ]
    available = audit.status == ReferenceStatus.OK
    return BaselineAuditContext(
        audit=audit,
        profiles=profiles,
        links=links,
        target_source=target_source,  # type: ignore[arg-type]
        report_access=report_access,  # type: ignore[arg-type]
        trace_access=trace_access,  # type: ignore[arg-type]
        oracle_access=oracle_access,  # type: ignore[arg-type]
        available=available,
        missing_reason=None if available else f"reference audit status={audit.status.value}",
        reference_detected_target_ids=sorted({item for item in matched if item}),
        unreported_known_target_ids=sorted({item for item in unreported if item}),
        confirmed_false_positive_target_ids=sorted({item for item in false_positive if item}),
        adjudication_target_ids=sorted({item for item in adjudication if item}),
        severity_disagreement_ids=sorted({item for item in severity if item}),
        insufficient_evidence_target_ids=sorted({item for item in insufficient if item}),
        extraction_notes=[
            f"extracted {len(profiles)} report claims from {len(audit.findings)} findings",
            "extracted statements remain report_claim and are not repository facts",
        ],
    )


# --------------------------------------------------------------------- acquisition
def _reference_environment(loaded: LoadedConfig) -> str:
    import platform
    import sys

    return (
        f"python={sys.version_info.major}.{sys.version_info.minor};"
        f"platform={platform.system().lower()};"
        f"mode={loaded.config.generation.backend}"
    )


def verify_reference_report(
    *,
    loaded: LoadedConfig,
    oracle_path: Path,
    report_path: Path,
    metadata_path: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    """Import a report, verify its findings privately and persist the result.

    The output is evaluation-side only; ``GeneratorRequest`` never sees the
    links or the unreported-target list unless the knowledge permission allows
    it (oracle/combined).
    """
    oracle = CanonicalVulnerabilityOracle.model_validate(
        json.loads(Path(oracle_path).read_text(encoding="utf-8"))
    )
    audit = load_reference_audit(
        Path(report_path),
        metadata_path=Path(metadata_path) if metadata_path else None,
        allow_missing_metadata=loaded.config.generation.reference_audit.allow_missing_metadata,
        repo_root=None,
    )
    context = build_baseline_context(
        audit,
        oracle,
        matching_config=loaded.config.matching,
        target_source=loaded.config.generation.target_source,
        report_access=loaded.config.generation.report_access,
        trace_access=loaded.config.generation.trace_access,
        oracle_access=loaded.config.generation.oracle_access,
    )
    output = Path(output_dir) if output_dir else (
        loaded.paths.root / "references" / "verification" / audit.reference_audit_id
    )
    output.mkdir(parents=True, exist_ok=True)
    atomic_write_json(
        output / "reference_audit.json",
        {
            "reference_audit": audit.model_dump(mode="json"),
            "baseline_context": context.model_dump(mode="json"),
        },
    )
    return {
        "ok": context.available,
        "reference_audit_id": audit.reference_audit_id,
        "status": audit.status.value,
        "output": str(output.resolve()),
        "findings": len(audit.findings),
        "profiles": len(context.profiles),
        "links": [
            {
                "finding_id": link.finding_id,
                "vulnerability_id": link.vulnerability_id,
                "safe_target_id": link.safe_target_id,
                "status": link.status.value,
                "needs_adjudication": link.needs_adjudication,
            }
            for link in context.links
        ],
        "reference_detected_target_ids": context.reference_detected_target_ids,
        "unreported_known_target_ids": context.unreported_known_target_ids,
        "confirmed_false_positive_ids": context.confirmed_false_positive_target_ids,
        "adjudication_finding_ids": context.adjudication_target_ids,
        "severity_disagreement_ids": context.severity_disagreement_ids,
        "insufficient_evidence_ids": context.insufficient_evidence_target_ids,
        "report_only_eligible_target_ids": context.generation_eligible_vulnerability_ids(),
        "warnings": audit.warnings,
        "formal_pairing": False,
        "purpose": "reference",
    }


def acquire_reference_audit(
    *,
    loaded: LoadedConfig,
    oracle: CanonicalVulnerabilityOracle,
    clean_instance_id: str,
    repo_root: Path,
    task_sha256: str,
    repository_tree_sha256: str,
    agent_config_path: Path | None = None,
    runner: Callable[..., dict[str, Any]] | None = None,
) -> tuple[ReferenceAudit | None, BaselineAuditContext]:
    """Acquire R0 according to ``generation.reference_audit`` and verify it."""
    settings = loaded.config.generation.reference_audit
    target_source = loaded.config.generation.target_source
    report_access = loaded.config.generation.report_access
    trace_access = loaded.config.generation.trace_access
    oracle_access = loaded.config.generation.oracle_access
    if settings.source == "none":
        return None, build_baseline_context(
            None,
            oracle,
            matching_config=loaded.config.matching,
            target_source=target_source,
            report_access=report_access,
            trace_access=trace_access,
            oracle_access=oracle_access,
        )
    if report_access == "none":
        raise GenerationError(
            "generation.reference_audit.source is set but report_access=none",
            details={"source": settings.source},
        )
    cache_dir = loaded.paths.root / settings.cache_dir
    if settings.source == "import":
        if not settings.report_path:
            raise ConfigError(
                "reference_audit.source=import requires reference_audit.report_path"
            )
        audit = load_reference_audit(
            loaded.resolve_asset(settings.report_path),
            metadata_path=(
                loaded.resolve_asset(settings.metadata_path) if settings.metadata_path else None
            ),
            allow_missing_metadata=settings.allow_missing_metadata,
            repo_root=repo_root,
        )
        if not audit.metadata.get("metadata_complete", False):
            audit = audit.model_copy(
                update={"cache_key": None, "cache_hit": False}
            )
        else:
            key = reference_audit_cache_key(
                repository_tree_sha256=repository_tree_sha256,
                task_sha256=task_sha256,
                agent=audit.agent,
                model=audit.model or "unknown",
                config_sha256=audit.config_sha256 or loaded.sha256,
                repetition=audit.repetition,
                seed=audit.seed,
                environment=_reference_environment(loaded),
                budget=audit.budget.as_dict(),
            )
            if audit.repository_tree_sha256 != repository_tree_sha256:
                raise GenerationError(
                    "imported reference report belongs to a different repository snapshot",
                    details={
                        "report_tree": audit.repository_tree_sha256,
                        "snapshot_tree": repository_tree_sha256,
                    },
                )
            if audit.task_sha256 and audit.task_sha256 != task_sha256:
                raise GenerationError(
                    "imported reference report was produced by a different audit task",
                    details={"report_task": audit.task_sha256, "task": task_sha256},
                )
            audit = audit.model_copy(update={"cache_key": key})
        context = build_baseline_context(
            audit,
            oracle,
            matching_config=loaded.config.matching,
            target_source=target_source,
            report_access=report_access,
            trace_access=trace_access,
            oracle_access=oracle_access,
        )
        store_reference_audit(audit, directory=cache_dir)
        return audit, context

    # source == "run"
    if runner is None:
        runner = _default_reference_runner
    audit = runner(
        loaded=loaded,
        oracle=oracle,
        clean_instance_id=clean_instance_id,
        repo_root=repo_root,
        task_sha256=task_sha256,
        repository_tree_sha256=repository_tree_sha256,
        agent_config_path=agent_config_path,
        cache_dir=cache_dir,
        report_access=report_access,
        trace_access=trace_access,
        settings=settings,
    )
    context = build_baseline_context(
        audit,
        oracle,
        matching_config=loaded.config.matching,
        target_source=target_source,
        report_access=report_access,
        trace_access=trace_access,
        oracle_access=oracle_access,
    )
    if audit.status == ReferenceStatus.OK:
        store_reference_audit(audit, directory=cache_dir)
    return audit, context


def _default_reference_runner(
    *,
    loaded: LoadedConfig,
    oracle: CanonicalVulnerabilityOracle,
    clean_instance_id: str,
    repo_root: Path,
    task_sha256: str,
    repository_tree_sha256: str,
    agent_config_path: Path | None,
    cache_dir: Path,
    report_access: str,
    trace_access: str,
    settings,
) -> ReferenceAudit:
    """Execute a reference-only clean release in a separate session/role."""
    from ..export.bundle import export_release
    from ..harness.runner import run_release

    if agent_config_path is None:
        raise ConfigError(
            "reference_audit.source=run requires reference_audit.agent_config"
        )
    agent_config_path = loaded.resolve_asset(str(agent_config_path))
    environment = _reference_environment(loaded)
    key = reference_audit_cache_key(
        repository_tree_sha256=repository_tree_sha256,
        task_sha256=task_sha256,
        agent=agent_config_path.name,
        model=loaded.config.generation.llm_model or "configured-agent",
        config_sha256=loaded.sha256,
        repetition=settings.repetitions,
        seed=settings.seed,
        environment=environment,
        budget={
            "max_queries": settings.max_queries,
            "max_tokens": settings.max_tokens,
        },
    )
    cache_dir = Path(cache_dir)
    cache_file = cache_dir / "cache" / key / "reference_audit.json"
    if cache_file.is_file():
        cached = load_reference_audit(
            cache_file,
            allow_missing_metadata=False,
            repo_root=repo_root,
        )
        if (
            cached.repository_tree_sha256 == repository_tree_sha256
            and cached.task_sha256 == task_sha256
            and cached.cache_key == key
        ):
            return cached.model_copy(update={"cache_hit": True})
    if settings.max_queries < 1:
        raise GenerationError(
            "reference_audit.max_queries=0 leaves no budget for a reference run",
            details={"source": "run"},
        )
    release_dir = cache_dir / "releases" / key
    if release_dir.exists():
        import shutil

        shutil.rmtree(release_dir)
    export_release(
        loaded=loaded,
        instances_dir=loaded.paths.instances,
        output_dir=release_dir,
        only_release_eligible=True,
        release_name="vulnmirage-reference",
        release_version="r0",
        instance_ids=[clean_instance_id],
        purpose="reference",
    )
    # A separate workspace root gives R0 its own runs/worktrees/session and
    # keeps reference artifacts out of `workspace/runs`.
    import dataclasses

    reference_root = Path(cache_dir) / "workspace"
    reference_loaded = dataclasses.replace(
        loaded,
        config=loaded.config.model_copy(
            update={"workspace_root": str(reference_root)}
        ),
    )
    reference_loaded.paths.ensure_layout()
    result = run_release(
        loaded=reference_loaded,
        release_dir=release_dir,
        agent_config_path=agent_config_path,
        repetitions=settings.repetitions,
        workers=1,
        instance_ids=[clean_instance_id],
        limit=None,
        resume=False,
        purpose="reference",
    )
    runs = [item for item in result.get("runs", []) if item.get("status") != "skipped_existing"]
    if not runs:
        raise GenerationError(
            "reference run produced no run directory",
            details={"release": str(release_dir)},
        )
    run_id = runs[0]["run_id"]
    run_dir = reference_loaded.paths.run_dir(run_id)
    findings_path = run_dir / "findings.json"
    final_raw_path = run_dir / "final_raw.txt"
    meta = {}
    if (run_dir / "meta.json").is_file():
        meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
    raw_text = (
        findings_path.read_text(encoding="utf-8")
        if findings_path.is_file()
        else final_raw_path.read_text(encoding="utf-8", errors="replace")
        if final_raw_path.is_file()
        else ""
    )
    findings: list[AgentFinding] = []
    status = ReferenceStatus.FAILED
    warnings: list[str] = []
    if raw_text:
        try:
            payload = json.loads(raw_text)
            if isinstance(payload, dict) and "findings" in payload:
                findings = [AgentFinding.model_validate(item) for item in payload["findings"]]
            status = ReferenceStatus.OK
        except Exception as exc:  # noqa: BLE001
            status = ReferenceStatus.FORMAT_FAILURE
            warnings.append(f"reference findings did not parse: {exc}")
    else:
        warnings.append("reference run produced no final report")
    trace = ReferenceTraceObservation(
        available=False,
        importer=meta.get("metadata", {}).get("importer"),
        observability_level=str(meta.get("observability_grade") or "none"),
        notes=["R0 trace is imported only when the runtime emitted native events"],
    )
    if trace_access == "observable":
        access_path = run_dir / "file_access.jsonl"
        if access_path.is_file():
            visited: list[str] = []
            event_ids: list[str] = []
            for line in access_path.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("path"):
                    visited.append(record["path"])
                if record.get("event_id"):
                    event_ids.append(record["event_id"])
            if event_ids:
                trace = trace.model_copy(
                    update={
                        "available": True,
                        "visited_files": sorted(set(visited)),
                        "event_ids": event_ids,
                    }
                )
    audit_id = stable_id("REF", key)
    audit = ReferenceAudit(
        reference_audit_id=audit_id,
        source=ReferenceSource.RUN,
        status=status,
        snapshot_id=oracle.repository.vulnerable_commit,
        repository_tree_sha256=repository_tree_sha256,
        task_sha256=task_sha256,
        agent="opencode" if "opencode" in agent_config_path.name else agent_config_path.stem,
        model=meta.get("metadata", {}).get("model") or settings.agent_config,
        config_sha256=loaded.sha256,
        repetition=settings.repetitions,
        seed=settings.seed,
        session_id=run_id,
        budget=ReferenceBudget(
            max_queries=settings.max_queries,
            queries_used=len(runs),
            max_tokens=settings.max_tokens,
            tokens_used=meta.get("input_tokens") or None,
            cost_known=False,
        ),
        report_access=report_access,
        trace_access=trace_access,
        raw_report_path=str(final_raw_path) if final_raw_path.is_file() else None,
        raw_report_sha256=sha256_file(final_raw_path) if final_raw_path.is_file() else None,
        findings_path=str(findings_path) if findings_path.is_file() else None,
        findings=findings,
        trace=trace,
        cache_key=key,
        created_at=utc_now_iso(),
        source_reference=str(release_dir),
        metadata={
            "metadata_complete": True,
            "cacheable": True,
            "run_id": run_id,
            "release_id": result.get("release_id"),
            "role": "reference",
            "purpose": "reference",
            "observability_grade": meta.get("observability_grade"),
        },
        warnings=warnings,
    )
    atomic_write_json(cache_file, {"reference_audit": audit.model_dump(mode="json")})
    return audit
