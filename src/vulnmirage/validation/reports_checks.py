"""Leakage and new-vulnerability-scanner checks."""

from __future__ import annotations

import time

from ..models import CheckStatus
from .command_support import outcome_details, run_commands_in_copy
from .context import ValidationContext, new_started, result
from .leakage import scan_instance_visible


def check_leakage(ctx: ValidationContext):
    started = new_started()
    began = time.monotonic()
    task_path = ctx.store.resolve_artifact(ctx.instance.task_file)
    task_text = task_path.read_text(encoding="utf-8") if task_path.is_file() else ""
    report = scan_instance_visible(
        ctx.repo,
        task_text,
        oracle=ctx.oracle,
        manipulation=ctx.manipulation,
        decoys=ctx.decoys,
        evidence_contract=ctx.store.load_evidence_contract(ctx.instance.instance_id),
        scan_advisory_patterns=ctx.config.validation.leakage_scan_advisory_ids,
    )
    return result(
        "leakage",
        CheckStatus.PASS if report["passed"] else CheckStatus.FAIL,
        started,
        time.monotonic() - began,
        details=report,
    )


def check_new_vulnerability_scanner(ctx: ValidationContext):
    started = new_started()
    began = time.monotonic()
    spec = ctx.config.validation.new_vulnerability_scanner
    if spec is None:
        return result(
            "new_vulnerability_scanner",
            CheckStatus.SKIP,
            started,
            time.monotonic() - began,
            details={
                "reason": "no new-vulnerability scanner configured",
                "limitation": "absence of new vulnerabilities is not proven by a scanner",
            },
        )
    outcomes, _ = run_commands_in_copy(
        ctx.loaded,
        ctx.repo,
        [spec],
        label=f"{ctx.instance.instance_id}-new-vuln",
        log_dir=ctx.log_dir / "new-vulnerability",
    )
    errors = [
        f"scanner command failed: {outcome.argv} exit {outcome.exit_code}"
        for outcome in outcomes
        if not outcome.passed
    ]
    return result(
        "new_vulnerability_scanner",
        CheckStatus.PASS if not errors else CheckStatus.FAIL,
        started,
        time.monotonic() - began,
        details={"errors": errors, "commands": [outcome_details(item) for item in outcomes]},
    )
