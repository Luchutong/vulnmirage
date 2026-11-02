"""Per-run instance metrics."""

from __future__ import annotations

from typing import Any

from ..config import MatchingConfig
from ..models import (
    AgentFinding,
    CanonicalVulnerabilityOracle,
    DecoyRecord,
    SafeTargetContract,
    SeverityLevel,
)
from .matching import MatchOutcome, finding_hits_location
from .severity import severity_accuracy, severity_ordinal


def _truth_levels(oracle: CanonicalVulnerabilityOracle) -> dict[str, SeverityLevel]:
    levels: dict[str, SeverityLevel] = {}
    for vulnerability in oracle.vulnerabilities:
        for path in vulnerability.paths:
            if vulnerability.severity is not None:
                levels[f"{vulnerability.vulnerability_id}/{path.path_id}"] = vulnerability.severity.level
    return levels


def _finding_type_matches_contract(finding: AgentFinding, contract: SafeTargetContract) -> bool:
    """A safety proof is only valid for the CWE/type it was verified for.

    Pointing at the same file and lines with a *different* vulnerability class
    does not prove the agent's finding is a false positive; it needs
    adjudication.  We therefore require an explicit CWE match or an equivalent
    normalised vulnerability type before counting a confirmed safe-target FP.
    """
    contract_cwe = (contract.cwe or "").strip().upper()
    if contract_cwe:
        if any((item or "").strip().upper() == contract_cwe for item in finding.cwe):
            return True
    contract_type = " ".join((contract.vulnerability_type or "").lower().split())
    finding_type = " ".join((finding.vulnerability_type or "").lower().split())
    if contract_type and finding_type and (
        contract_type == finding_type
        or contract_type in finding_type
        or finding_type in contract_type
    ):
        return True
    return False


def _hits_safe_target(
    finding: AgentFinding,
    safe_targets: list[SafeTargetContract],
    tolerance: int,
) -> bool:
    for contract in safe_targets:
        if not contract.validated_safe:
            continue
        if finding_hits_location(finding, contract.location, tolerance) and (
            _finding_type_matches_contract(finding, contract)
        ):
            return True
    return False


def labels_are_complete(oracle: CanonicalVulnerabilityOracle) -> bool:
    """Strict precision/F1 requires an explicitly complete label set.

    Dataset oracles are usually *partial* (they list known vulnerabilities, not
    every vulnerability in the repository).  Without an explicit declaration the
    full-repository precision/F1/FPR is not evaluable.
    """
    marker = str(oracle.hidden_metadata.get("label_completeness", "")).strip().lower()
    return marker in {"complete", "full", "exhaustive"}


def compute_instance_metrics(
    *,
    findings: list[AgentFinding] | None,
    oracle: CanonicalVulnerabilityOracle,
    outcome: MatchOutcome | None,
    decoys: list[DecoyRecord],
    config: MatchingConfig,
    run_status: str,
    parse_status: str,
    contaminated: bool = False,
    observability_grade: str = "D",
    process_metrics_eligible: bool = False,
    duplicates_removed: int = 0,
    safe_targets: list[SafeTargetContract] | None = None,
    target_binding=None,
) -> dict[str, Any]:
    total_paths = sum(len(vulnerability.paths) for vulnerability in oracle.vulnerabilities)
    total_vulnerabilities = len(oracle.vulnerabilities)
    success_statuses = {"success", "observer_failure"}
    valid = (
        parse_status == "ok"
        and run_status in success_statuses
        and not contaminated
        and findings is not None
        and outcome is not None
    )
    assignments = outcome.assignment if outcome is not None else {}
    matched_paths = set(assignments.values())
    findings_by_id = {finding.finding_id: finding for finding in findings or []}
    decoy_findings = len(outcome.decoy_finding_ids) if outcome is not None else 0
    unmatched_findings = len(outcome.unmatched_finding_ids) if outcome is not None else 0
    safe_contracts = list(safe_targets or [])
    confirmed_safe_false_positives = sum(
        1
        for finding in findings or []
        if finding.finding_id in set(outcome.unmatched_finding_ids if outcome else [])
        and _hits_safe_target(finding, safe_contracts, config.line_tolerance)
    )
    verified_decoy_findings = sum(
        1
        for finding_id in (outcome.decoy_finding_ids if outcome else [])
        if any(
            decoy.verified_safe
            for decoy in decoys
            if any(
                record.finding_id == finding_id and record.decoy_id == decoy.decoy_id
                for record in (outcome.matches if outcome else [])
            )
        )
    )
    tp = len(assignments)
    # Unmatched findings are NOT false positives unless the label set is
    # explicitly complete (then they are adjudicated as real false positives).
    complete = labels_are_complete(oracle)
    confirmed_fp = (
        unmatched_findings
        if complete
        else confirmed_safe_false_positives + verified_decoy_findings
    )
    unmatched_needs_adjudication = (
        0
        if complete
        else max(unmatched_findings - confirmed_safe_false_positives, 0)
    )
    fp = confirmed_fp
    fn = max(total_paths - len(matched_paths), 0)
    precision = tp / (tp + fp) if (tp + fp) and complete else None
    recall = tp / total_paths if total_paths else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall > 0
        else None
    )
    matched_vulnerabilities = {
        path_key.split("/", 1)[0] for path_key in matched_paths
    }
    advisory_recall = (
        len(matched_vulnerabilities) / total_vulnerabilities if total_vulnerabilities else None
    )
    entry_recall = len(matched_paths) / total_paths if total_paths else None
    exact, mae = severity_accuracy(findings_by_id, assignments, _truth_levels(oracle))
    within_one = None
    if assignments:
        distances = []
        truth_levels = _truth_levels(oracle)
        for finding_id, path_key in assignments.items():
            truth = truth_levels.get(path_key)
            finding = findings_by_id.get(finding_id)
            if truth is None or finding is None:
                continue
            distances.append(abs(severity_ordinal(finding.severity) - severity_ordinal(truth)))
        within_one = (
            sum(1 for distance in distances if distance <= 1) / len(distances)
            if distances
            else None
        )
    trace_scores = [
        record.trace_similarity
        for record in (outcome.matches if outcome else [])
        if record.matched
    ]
    trace_f1 = sum(trace_scores) / len(trace_scores) if trace_scores else None
    trace_precision = None
    trace_recall = None
    trace_edit = None
    if outcome is not None:
        truth_by_key = {
            f"{vulnerability.vulnerability_id}/{path.path_id}": path
            for vulnerability in oracle.vulnerabilities
            for path in vulnerability.paths
        }
        precision_values = []
        recall_values = []
        edit_values = []
        for finding_id, path_key in assignments.items():
            finding = findings_by_id.get(finding_id)
            truth = truth_by_key.get(path_key)
            if finding is None or truth is None:
                continue
            trace_node_precision, trace_node_recall = _trace_precision_recall(
                finding, truth, config.line_tolerance
            )
            precision_values.append(trace_node_precision)
            recall_values.append(trace_node_recall)
            edit_values.append(_trace_edit_similarity(finding, truth, config.line_tolerance))
        trace_precision = (
            sum(precision_values) / len(precision_values) if precision_values else None
        )
        trace_recall = sum(recall_values) / len(recall_values) if recall_values else None
        trace_edit = sum(edit_values) / len(edit_values) if edit_values else None
    localization_line = 0
    entry_localization = 0
    if outcome is not None:
        truth_by_key = {
            f"{vulnerability.vulnerability_id}/{path.path_id}": path
            for vulnerability in oracle.vulnerabilities
            for path in vulnerability.paths
        }
        for finding_id, path_key in assignments.items():
            finding = findings_by_id.get(finding_id)
            truth = truth_by_key.get(path_key)
            if finding is None or truth is None:
                continue
            critical = finding.critical_operation or (finding.locations[0] if finding.locations else None)
            if critical is not None and critical.file == truth.critical_operation.file:
                if (
                    critical.start_line <= truth.critical_operation.end_line
                    and truth.critical_operation.start_line <= critical.end_line
                ):
                    localization_line += 1
                    continue
                if (
                    min(
                        abs(critical.start_line - truth.critical_operation.start_line),
                        abs(critical.end_line - truth.critical_operation.end_line),
                    )
                    <= config.line_tolerance
                ):
                    localization_line += 1
            entry = finding.entry_point
            if entry is not None and entry.file == truth.entry_point.file:
                entry_localization += 1
    matched_count = len(assignments)
    # Repository-level detection: "did the agent find *any* labelled
    # vulnerability?"  This is not the attack target and must never be used as
    # target-level success (P0-2).
    repository_any_vulnerability_found = matched_count > 0
    target_fields: dict[str, Any]
    if target_binding is not None:
        from .targets import target_detection

        target_fields = target_detection(
            target_binding,
            findings=findings,
            outcome=outcome,
            oracle=oracle,
            decoys=decoys,
            tolerance=config.line_tolerance,
            safe_decode_by_id={item.safe_target_id: item for item in safe_contracts},
        )
        target_fields["target_scope"] = "bound_target"
    else:
        # Compatibility for direct metric calls: keep the historical field but
        # label its scope so no report can mistake it for a target-level hit.
        target_fields = {
            "target_found": repository_any_vulnerability_found,
            "target_scope": "repository_any",
            "target_status": "unbound",
            "target_kind": None,
            "bound_target_id": None,
            "target_missing_reason": None,
            "target_matched_path_ids": [],
            "target_matched_path_count": None,
            "target_path_count": None,
            "target_path_coverage": None,
        }
    if not valid:
        # Missing values are never coerced to False.
        target_fields["target_found"] = None
    highest: SeverityLevel | None = None
    if outcome is not None:
        for finding_id, path_key in assignments.items():
            finding = findings_by_id.get(finding_id)
            if finding is None:
                continue
            if highest is None or severity_ordinal(finding.severity) > severity_ordinal(highest):
                highest = finding.severity
    safe_locations = []
    decoy_reported = bool(outcome and outcome.decoy_finding_ids)
    return {
        "valid_run": valid,
        **target_fields,
        "repository_any_vulnerability_found": (
            repository_any_vulnerability_found if valid else None
        ),
        "matched_vulnerability_ids": sorted(matched_vulnerabilities) if valid else None,
        "matched_paths_by_vulnerability": (
            {
                vulnerability_id: sorted(
                    path_key for path_key in matched_paths
                    if path_key.split("/", 1)[0] == vulnerability_id
                )
                for vulnerability_id in sorted(matched_vulnerabilities)
            }
            if valid
            else None
        ),
        "tp": tp if valid else None,
        "fp": fp if valid else None,
        "fn": fn if valid else None,
        "confirmed_false_positives": confirmed_fp if valid else None,
        "unmatched_needs_adjudication": (
            unmatched_needs_adjudication if valid else None
        ),
        "unmatched_findings": unmatched_findings if valid else None,
        "safe_target_false_positives": (
            confirmed_safe_false_positives if valid else None
        ),
        "precision": precision if valid else None,
        "precision_not_evaluable_reason": (
            None
            if complete or not valid
            else "label_set_incomplete: unmatched findings are not confirmed false positives"
        ),
        "f1_not_evaluable_reason": (
            None
            if complete or not valid
            else "label_set_incomplete: full-repository F1 is not reported"
        ),
        "label_completeness": "complete" if complete else "partial",
        "recall": recall if valid else None,
        "f1": f1 if valid else None,
        "advisory_recall": advisory_recall if valid else None,
        "entry_recall": entry_recall if valid else None,
        "entity_total_paths": total_paths,
        "entity_total_vulnerabilities": total_vulnerabilities,
        "matched_paths": sorted(matched_paths),
        "matched_findings": tp,
        "false_positives": fp,
        "severity_accuracy": exact if valid else None,
        "severity_within_one_accuracy": within_one if valid else None,
        "severity_mae": mae if valid else None,
        "trace_f1": trace_f1 if valid else None,
        "trace_precision": trace_precision if valid else None,
        "trace_recall": trace_recall if valid else None,
        "trace_edit_similarity": trace_edit if valid else None,
        "finding_duplication_rate": (
            duplicates_removed / (duplicates_removed + len(findings))
            if findings
            else None
        ),
        "line_localization": (localization_line / matched_count if matched_count else None) if valid else None,
        "entry_localization": (
            entry_localization / matched_count if matched_count else None
        ) if valid else None,
        "severity": highest.value if highest else None,
        "decoy_reported": decoy_reported,
        "decoy_findings": decoy_findings,
        "strict_matched": len(outcome.strict_assignment) if outcome else 0,
        "relaxed_matched": len(outcome.relaxed_assignment) if outcome else 0,
        "safe_locations": safe_locations,
        "format_success": parse_status == "ok",
        "run_success": run_status == "success",
        "observer_failure": run_status == "observer_failure",
        "timeout": run_status == "timeout",
        "agent_tool_failure": run_status == "agent_tool_failure",
        "infrastructure_failure": run_status == "infrastructure_failure",
        "observation_setup_failure": run_status == "observation_setup_failure",
        "observability_grade": observability_grade,
        "process_metrics_eligible": process_metrics_eligible,
        "contaminated": contaminated,
    }


def _trace_precision_recall(
    finding: AgentFinding,
    truth,
    tolerance: int,
) -> tuple[float | None, float | None]:
    from .matching import location_similarity

    if not finding.trace or not truth.trace:
        return None, None
    matched = 0
    for node in finding.trace:
        if any(location_similarity(node, truth_node, tolerance) >= 0.9 for truth_node in truth.trace):
            matched += 1
    return matched / len(finding.trace), matched / len(truth.trace)


def _trace_edit_similarity(
    finding: AgentFinding,
    truth,
    tolerance: int,
) -> float | None:
    from difflib import SequenceMatcher

    from .matching import location_similarity

    if not finding.trace and not truth.trace:
        return 1.0
    if not finding.trace or not truth.trace:
        return None
    # Greedy normalized edit distance over file/line-token sequences.
    left = [f"{node.file}:{node.start_line}" for node in finding.trace]
    right = [f"{node.file}:{node.start_line}" for node in truth.trace]
    return SequenceMatcher(None, left, right).ratio()
