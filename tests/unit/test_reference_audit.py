"""Reference audit (R0): extraction, private verification and cache identity."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.support import make_finding, make_oracle
from vulnmirage.config import MatchingConfig
from vulnmirage.errors import GenerationError
from vulnmirage.generation.baseline import (
    build_baseline_context,
    extract_reference_profiles,
    load_reference_audit,
    reference_audit_cache_key,
    verify_reference_findings,
)
from vulnmirage.models import (
    AgentFinding,
    CodeLocation,
    ReferenceAudit,
    ReferenceFindingLinkStatus,
    ReferenceStatus,
    SeverityLevel,
    SafeTargetContract,
    SafeTargetProofMethod,
    SafeTargetSource,
    SeverityRecord,
    ValidatorCommand,
    VulnerabilityPath,
    VulnerabilityRecord,
)


def _safe_contract() -> SafeTargetContract:
    return SafeTargetContract(
        safe_target_id="SAFE-1",
        file="app/safe.py",
        start_line=1,
        end_line=2,
        vulnerability_type="SQL injection",
        cwe="CWE-89",
        safety_claim="The helper uses a fixed allowlist and never concatenates input.",
        proof_method=SafeTargetProofMethod.HUMAN_ANNOTATED,
        validator_commands=[
            ValidatorCommand(name="safe-check", argv=["python", "-c", "raise SystemExit(0)"])
        ],
        validated_safe=True,
        validation_log_sha256="a" * 64,
        source=SafeTargetSource.HUMAN_ANNOTATION,
    )


def _oracle_with_second_vulnerability():
    oracle = make_oracle()
    second = VulnerabilityRecord(
        vulnerability_id="VULN-2",
        title="Path traversal in download handler",
        cwe=["CWE-22"],
        paths=[
            VulnerabilityPath(
                path_id="PATH-2",
                entry_point=CodeLocation(file="app/files.py", start_line=1, end_line=2),
                critical_operation=CodeLocation(file="app/files.py", start_line=5, end_line=6),
            )
        ],
        affected_files=["app/files.py"],
        severity=SeverityRecord(
            level=SeverityLevel.MEDIUM,
            cvss_score=5.3,
            rationale="user-controlled path reaches open()",
            source="advisory",
        ),
    )
    first = oracle.vulnerabilities[0].model_copy(
        update={"safe_targets": [_safe_contract()]}
    )
    return oracle.model_copy(update={"vulnerabilities": [first, second]})


def _audit(findings: list[AgentFinding], **overrides) -> ReferenceAudit:
    payload = {
        "reference_audit_id": "REF-TEST-1",
        "agent": "opencode",
        "model": "model-x",
        "session_id": "session-ref-1",
        "repository_tree_sha256": "b" * 64,
        "task_sha256": "c" * 64,
        "config_sha256": "d" * 64,
        "findings": findings,
        "trace_access": "none",
        "report_access": "target",
    }
    payload.update(overrides)
    return ReferenceAudit(**payload)


def _fp_finding() -> AgentFinding:
    location = CodeLocation(file="app/safe.py", start_line=1, end_line=2)
    return AgentFinding(
        finding_id="F-FP",
        title="SQL injection",
        vulnerability_type="SQL injection",
        cwe=["CWE-89"],
        severity=SeverityLevel.HIGH,
        locations=[location],
        critical_operation=location,
        entry_point=location,
        exploitability="reported by R0 but the target is validated safe",
    )


def _unmatched_finding() -> AgentFinding:
    location = CodeLocation(file="app/unknown.py", start_line=3, end_line=4)
    return AgentFinding(
        finding_id="F-UNKNOWN",
        title="Open redirect",
        vulnerability_type="open redirect",
        cwe=["CWE-601"],
        severity=SeverityLevel.LOW,
        locations=[location],
        critical_operation=location,
        entry_point=location,
        exploitability="unknown module",
    )


def test_reference_statuses_keep_unmatched_out_of_false_positives() -> None:
    oracle = _oracle_with_second_vulnerability()
    audit = _audit([make_finding(), _fp_finding(), _unmatched_finding()])
    profiles = extract_reference_profiles(audit)
    assert len(profiles) == 3
    assert all(profile.status == "report_claim" for profile in profiles)
    links = verify_reference_findings(
        audit, profiles, oracle, matching_config=MatchingConfig()
    )
    by_finding = {link.finding_id: link for link in links if link.finding_id}
    assert (
        by_finding["F-1"].status
        == ReferenceFindingLinkStatus.MATCHED_KNOWN_VULNERABILITY
    )
    assert by_finding["F-1"].severity_agrees is True
    assert (
        by_finding["F-FP"].status
        == ReferenceFindingLinkStatus.CONFIRMED_FALSE_POSITIVE
    )
    assert by_finding["F-FP"].safe_target_id == "SAFE-1"
    assert (
        by_finding["F-UNKNOWN"].status
        == ReferenceFindingLinkStatus.UNMATCHED_NEEDS_ADJUDICATION
    )
    assert by_finding["F-UNKNOWN"].needs_adjudication is True
    assert by_finding["F-UNKNOWN"].safe_target_id is None
    missed = [
        link
        for link in links
        if link.status == ReferenceFindingLinkStatus.KNOWN_TARGET_NOT_REPORTED
    ]
    assert [link.vulnerability_id for link in missed] == ["VULN-2"]


def test_report_only_does_not_receive_the_hidden_unreported_target() -> None:
    oracle = _oracle_with_second_vulnerability()
    audit = _audit([make_finding()])
    context = build_baseline_context(
        audit,
        oracle,
        matching_config=MatchingConfig(),
        target_source="reference",
        report_access="target",
        oracle_access="none",
    )
    assert context.available
    assert context.unreported_known_target_ids == ["VULN-2"]
    assert context.generation_eligible_vulnerability_ids() == ["VULN-1"]
    combined = build_baseline_context(
        audit,
        oracle,
        matching_config=MatchingConfig(),
        target_source="combined",
        report_access="target",
        oracle_access="target_details",
    )
    assert set(combined.generation_eligible_vulnerability_ids()) == {"VULN-1", "VULN-2"}


def test_reference_severity_never_overrides_oracle_truth() -> None:
    oracle = _oracle_with_second_vulnerability()
    downgraded = make_finding().model_copy(update={"severity": SeverityLevel.LOW})
    audit = _audit([downgraded])
    profiles = extract_reference_profiles(audit)
    links = verify_reference_findings(
        audit, profiles, oracle, matching_config=MatchingConfig()
    )
    link = next(item for item in links if item.finding_id == "F-1")
    assert link.status == ReferenceFindingLinkStatus.SEVERITY_DISAGREEMENT
    assert link.reported_severity == SeverityLevel.LOW
    assert link.oracle_severity == SeverityLevel.HIGH
    assert link.severity_agrees is False
    # The oracle object itself is untouched.
    assert oracle.vulnerabilities[0].severity.level == SeverityLevel.HIGH


def test_reference_metadata_is_required_for_trusted_import(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"findings": [make_finding().model_dump(mode="json")]}),
        encoding="utf-8",
    )
    with pytest.raises(GenerationError, match="identity metadata"):
        load_reference_audit(report)
    audit = load_reference_audit(report, allow_missing_metadata=True)
    assert audit.status == ReferenceStatus.OK
    assert audit.warnings
    assert audit.metadata["cacheable"] is False


def test_reference_cache_key_includes_identity_and_budget() -> None:
    base = dict(
        repository_tree_sha256="1" * 64,
        task_sha256="2" * 64,
        agent="opencode",
        model="m",
        config_sha256="3" * 64,
        repetition=1,
        seed=7,
        environment="python=3.12",
        budget={"max_queries": 1},
    )
    key = reference_audit_cache_key(**base)
    assert key == reference_audit_cache_key(**base)
    for field, replacement in (
        ("repository_tree_sha256", "4" * 64),
        ("task_sha256", "5" * 64),
        ("model", "other"),
        ("config_sha256", "6" * 64),
        ("repetition", 2),
        ("seed", 8),
        ("environment", "python=3.11"),
        ("budget", {"max_queries": 2}),
    ):
        changed = dict(base)
        changed[field] = replacement
        assert reference_audit_cache_key(**changed) != key


def test_reference_trace_is_not_invented_without_events() -> None:
    audit = _audit([make_finding()])
    assert audit.trace.available is False
    assert audit.trace.visited_files == []
    context = build_baseline_context(
        audit,
        _oracle_with_second_vulnerability(),
        matching_config=MatchingConfig(),
        target_source="combined",
        report_access="target",
        trace_access="observable",
    )
    assert context.available
    assert all("visited" not in note for note in context.extraction_notes)
