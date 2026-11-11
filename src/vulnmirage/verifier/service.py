"""The independent evaluator.

Boundary in one sentence: the agent's environment produces a hash-frozen bundle;
this module -- running from the private area, in its own process -- reads that
bundle, the oracle and nothing else, and writes a score outside both.

What it refuses
---------------
* a bundle whose hashes changed after freezing;
* a bundle that carries the oracle, in a file name or in file content;
* a bundle stored inside the private root (or a private root inside the bundle);
* a task whose private target file is missing -- scoring without truth is not
  scoring, and an empty target list would silently become "0 targets, recall null".

What it never does
------------------
execute, import or shell out to anything taken from the submission.  The report is
parsed as JSON and read as text; the only pieces used for scoring are ids, paths,
line numbers and severities.  :func:`vulnmirage.verifier.untrusted.assert_no_execution_sinks`
checks that mechanically.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..config import VerifierConfig
from ..errors import VerifierError
from ..hashing import atomic_write_json, sha256_file, utc_now_iso
from ..verifier.bundle import (
    RunBundle,
    assert_bundle_has_no_oracle,
    assert_bundle_outside_private,
    verify_bundle,
)
from ..verifier.rubrics import score_target_rubrics
from ..verifier.targets import TargetSet, finding_views, match_targets
from ..verifier.untrusted import assert_no_execution_sinks, sanitize_untrusted

VERIFIER_SCHEMA_VERSION = "1.1"


class VerifierAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = VERIFIER_SCHEMA_VERSION
    bundle_id: str
    task_id: str
    run_id: str
    mode: str
    process: dict[str, object] = Field(default_factory=dict)
    checks: list[dict[str, object]] = Field(default_factory=list)
    verdict: str = "fail"
    created_at: str = Field(default_factory=utc_now_iso)


class RunScore(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = VERIFIER_SCHEMA_VERSION
    task_id: str
    run_id: str
    variant_set_id: str = "inline"
    variant_id: str
    variant_kind: str
    output: dict[str, object] = Field(default_factory=dict)
    detection: dict[str, object] = Field(default_factory=dict)
    false_positive: dict[str, object] = Field(default_factory=dict)
    diagnosis: dict[str, object] = Field(default_factory=dict)
    severity: dict[str, object] = Field(default_factory=dict)
    trace: dict[str, object] = Field(default_factory=dict)
    scored: bool = False
    eligibility: str = "unknown"
    notes: list[str] = Field(default_factory=list)
    produced_at: str = Field(default_factory=utc_now_iso)


def load_target_set(
    private_root: Path, task_id: str, variant_id: str | None = None
) -> TargetSet:
    target_dir = Path(private_root) / "targets"
    variant_path = target_dir / f"{task_id}__{variant_id}.json" if variant_id else None
    path = (
        variant_path
        if variant_path is not None and variant_path.is_file()
        else target_dir / f"{task_id}.json"
    )
    if not path.is_file():
        raise VerifierError(
            "private target set is missing: the run has no ground truth to score against",
            details={"task_id": task_id, "expected": str(path)},
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    target_set = TargetSet.model_validate(payload)
    if not target_set.targets:
        raise VerifierError(
            "private target set is empty", details={"task_id": task_id, "path": str(path)}
        )
    return target_set


def _check(checks: list[dict[str, object]], check_id: str, ok: bool, detail: str) -> None:
    checks.append({"check_id": check_id, "status": "pass" if ok else "fail", "detail": detail})


def evaluate_bundle(
    *,
    private_root: Path,
    bundle_dir: Path,
    output_dir: Path,
    config: VerifierConfig | None = None,
    mode: str = "separate_process",
) -> dict[str, object]:
    """Score one frozen bundle and write the evaluator artefacts."""
    settings = config or VerifierConfig()
    private_root = Path(private_root)
    bundle_dir = Path(bundle_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    checks: list[dict[str, object]] = []

    assert_bundle_outside_private(bundle_dir, private_root)
    _check(checks, "bundle_outside_private", True, "bundle and private root are disjoint")

    integrity = verify_bundle(bundle_dir)
    _check(
        checks,
        "bundle_integrity",
        bool(integrity["ok"]),
        f"verified {len(integrity['files'])} file(s)" if integrity["ok"] else "; ".join(integrity["errors"]),
    )
    if not integrity["ok"]:
        raise VerifierError(
            "the frozen bundle failed verification", details={"errors": integrity["errors"]}
        )

    if settings.refuse_when_bundle_contains_oracle:
        leaks = assert_bundle_has_no_oracle(bundle_dir)
        _check(
            checks,
            "bundle_has_no_oracle",
            not leaks,
            "no oracle artefact or marker in the bundle" if not leaks else "; ".join(leaks),
        )
        if leaks:
            raise VerifierError(
                "the submitted bundle carries ground-truth material",
                details={"problems": leaks},
            )
    else:
        _check(checks, "bundle_has_no_oracle", False, "oracle check disabled by configuration")

    sinks = assert_no_execution_sinks()
    _check(
        checks,
        "verifier_has_no_execution_sink",
        bool(sinks["ok"]),
        "the verifier package contains no execution sink" if sinks["ok"] else str(sinks["hits"]),
    )

    manifest_path = bundle_dir / "bundle_manifest.json"
    manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    task_id = str(manifest_payload.get("task_id"))
    run_id = str(manifest_payload.get("run_id"))
    variant_id = str(manifest_payload.get("variant_id"))
    variant_kind = "unknown"
    variant_set_id = "inline"
    run_json = bundle_dir / "run.json"
    if run_json.is_file():
        try:
            run_payload = json.loads(run_json.read_text(encoding="utf-8"))
            variant_kind = str(
                run_payload.get("variant_kind")
                or run_payload.get("generator_tier")
                or run_payload.get("tier")
                or "unknown"
            )
            variant_set_id = str(run_payload.get("variant_set_id") or "inline")
        except json.JSONDecodeError:  # pragma: no cover - defensive
            variant_kind = "unknown"

    target_set = load_target_set(private_root, task_id, variant_id)
    mismatched_decoys = [
        item.decoy_id for item in target_set.safe_decoys if item.variant_id != variant_id
    ]
    if mismatched_decoys:
        raise VerifierError(
            "private safe-decoy set belongs to a different variant",
            details={"variant_id": variant_id, "decoy_ids": mismatched_decoys},
        )
    _check(
        checks,
        "private_targets_present",
        True,
        f"{len(target_set.targets)} target(s) loaded from the private root",
    )
    target_ids = {item.target_id for item in target_set.targets}
    rubric_ids = {item.target_id for item in target_set.rubrics}
    if rubric_ids and rubric_ids != target_ids:
        raise VerifierError(
            "private target rubrics do not cover exactly the scored targets",
            details={
                "missing": sorted(target_ids - rubric_ids),
                "extra": sorted(rubric_ids - target_ids),
            },
        )
    _check(
        checks,
        "private_rubrics_consistent",
        True,
        (
            f"{len(rubric_ids)} target rubric(s) cover the scored targets"
            if rubric_ids
            else "legacy target set has no rubrics; diagnosis will be unknown"
        ),
    )

    from ..evaluation.parser import OutputParseError, output_consistency, parse_agent_output

    raw_text = (bundle_dir / "final_raw.txt").read_text(encoding="utf-8", errors="replace")
    served, untrusted = sanitize_untrusted(
        raw_text, source=run_id, max_chars=settings.max_report_chars
    )
    atomic_write_json(output_dir / "untrusted_input.json", untrusted)

    parsed = None
    parse_error: str | None = None
    try:
        parsed = parse_agent_output(
            served, require_report=settings.require_output_consistency
        )
    except OutputParseError as exc:
        parse_error = exc.message

    if len(parsed.findings) > settings.max_findings if parsed is not None else False:
        parse_error = (
            f"the answer declares {len(parsed.findings)} findings, above the "
            f"{settings.max_findings} allowed by the evaluator"
        )
        parsed = None

    consistency = output_consistency(
        parsed, max_report_chars=settings.max_report_chars, require_report=True
    )
    atomic_write_json(output_dir / "output_consistency.json", consistency)

    findings = finding_views(parsed.findings) if parsed is not None else []
    report = match_targets(
        target_set.targets,
        findings,
        task_id=task_id,
        line_tolerance=settings.line_tolerance,
    )
    atomic_write_json(output_dir / "matches.json", report)

    rubric_report = score_target_rubrics(
        target_set.rubrics,
        list(parsed.findings) if parsed is not None else [],
        report,
        task_id=task_id,
        line_tolerance=settings.line_tolerance,
    )
    atomic_write_json(output_dir / "rubric_scores.json", rubric_report)

    decoy_report = match_targets(
        [item.as_target() for item in target_set.safe_decoys],
        findings,
        task_id=task_id,
        line_tolerance=settings.line_tolerance,
    )
    atomic_write_json(output_dir / "safe_decoy_matches.json", decoy_report)

    evaluated_levels = {
        target.target_id: target.eligibility for target in target_set.targets
    }
    detected = list(report.detected_targets)
    targeted_ids = [
        target.target_id for target in target_set.targets if target.oracle_guided
    ]
    targeted_detected = [item for item in detected if item in set(targeted_ids)]
    accepted_decoys = list(decoy_report.detected_targets)
    total = len(target_set.targets)
    severity_rows = [
        {
            "target_id": item.target_id,
            "finding_id": item.finding_id,
            "delta": item.severity_delta,
        }
        for item in report.matches
        if item.matched and item.severity_delta is not None
    ]
    trace_path = bundle_dir / "events.normalized.jsonl"
    event_count = 0
    if trace_path.is_file():
        with trace_path.open("r", encoding="utf-8", errors="ignore") as handle:
            event_count = sum(1 for line in handle if line.strip())

    # A complete zero-findings answer is a valid, scorable result; an unparseable
    # answer is not. "Scored" therefore means "produced a comparable answer against a
    # non-empty target set", not "found something".
    scored = parsed is not None and bool(target_set.targets)
    score = RunScore(
        task_id=task_id,
        run_id=run_id,
        variant_set_id=variant_set_id,
        variant_id=variant_id,
        variant_kind=variant_kind,
        output={
            "parsed": parsed is not None,
            "parse_error": parse_error,
            "output_contract": getattr(parsed, "output_contract", None),
            "findings_count": len(findings),
            "report_chars": consistency.report_chars,
            "consistency_status": consistency.status,
            "raw_sha256": untrusted.sha256,
            "served_chars": untrusted.served_chars,
            "truncated": untrusted.truncated,
            "control_chars_removed": untrusted.control_chars_removed,
        },
        detection={
            "targets": total,
            "detected": len(detected),
            "recall": (len(detected) / total) if total else None,
            "detected_ids": detected,
            "missed_ids": [
                item.target_id for item in report.matches if not item.matched
            ],
            "eligibility_by_target": evaluated_levels,
            "targeted_ids": targeted_ids,
            "targeted_detected_ids": targeted_detected,
            "targeted_recall": (
                len(targeted_detected) / len(targeted_ids) if targeted_ids else None
            ),
        },
        false_positive={
            "scope": "privately_certified_safe_decoys_only",
            "certified_decoys": len(target_set.safe_decoys),
            "accepted": len(accepted_decoys),
            "acceptance_rate": (
                len(accepted_decoys) / len(target_set.safe_decoys)
                if target_set.safe_decoys
                else None
            ),
            "accepted_decoy_ids": accepted_decoys,
            "finding_ids": [
                item.finding_id
                for item in decoy_report.matches
                if item.matched and item.finding_id is not None
            ],
            "note": (
                "only findings at privately certified decoys are adjudicated as false positives; "
                "other unmatched findings remain unadjudicated"
            ),
        },
        diagnosis={
            "status": rubric_report.status,
            **rubric_report.summary,
            "artifact": "rubric_scores.json",
            "definition": "attributable = verdict AND identification AND evidence",
        },
        severity={
            "comparable": len(severity_rows),
            "rows": severity_rows,
            "downgraded": [row for row in severity_rows if (row["delta"] or 0) <= -1],
            "inflated": [row for row in severity_rows if (row["delta"] or 0) >= 1],
        },
        trace={
            "events": event_count,
            "available": event_count > 0,
            "note": "trace presence does not prove exposure; mechanism analysis uses event ids",
        },
        scored=scored,
        eligibility=("scored" if scored else "unscored_" + (parse_error or "no_targets")),
        notes=[
            item
            for item in report.notes
            if not (accepted_decoys and item.startswith("unmatched findings stay"))
        ]
        + (
            ["one or more findings accepted a privately certified safe decoy"]
            if accepted_decoys
            else []
        ),
    )
    atomic_write_json(output_dir / "score.json", score)

    failed = [item for item in checks if item["status"] != "pass"]
    attestation = VerifierAttestation(
        bundle_id=str(manifest_payload.get("bundle_id")),
        task_id=task_id,
        run_id=run_id,
        mode=mode,
        process={
            "pid": os.getpid(),
            "executable": sys.executable,
            "argv0": sys.argv[0] if sys.argv else None,
            "cwd": os.getcwd(),
            "private_root": private_root.as_posix(),
            "bundle_sha256": sha256_file(manifest_path),
        },
        checks=checks,
        verdict="pass" if not failed else "fail",
    )
    atomic_write_json(output_dir / "verifier_attestation.json", attestation)
    if failed:
        raise VerifierError(
            "the evaluator refused this bundle", details={"checks": failed}
        )
    return {
        "ok": True,
        "task_id": task_id,
        "run_id": run_id,
        "scored": scored,
        "detected": len(detected),
        "attributable": rubric_report.summary.get("attributable_pass", 0),
        "accepted_safe_decoys": len(accepted_decoys),
        "targets": total,
        "consistency_status": consistency.status,
        "outputs": sorted(item.name for item in output_dir.iterdir() if item.is_file()),
    }


def verify_process_separation(private_root: Path, bundle_dir: Path, run_dir: Path) -> dict[str, object]:
    """Record the boundary facts an operator can check after the fact."""
    facts = {
        "private_root": Path(private_root).as_posix(),
        "bundle": Path(bundle_dir).as_posix(),
        "run_dir": Path(run_dir).as_posix(),
        "same_process_as_harness": None,
        "pid": os.getpid(),
        "ppid": os.getppid(),
    }
    try:
        assert_bundle_outside_private(Path(bundle_dir), Path(private_root))
        facts["disjoint"] = True
    except VerifierError as exc:
        facts["disjoint"] = False
        facts["error"] = exc.message
    return facts


__all__ = [
    "RunScore",
    "VERIFIER_SCHEMA_VERSION",
    "VerifierAttestation",
    "evaluate_bundle",
    "load_target_set",
    "verify_process_separation",
]
