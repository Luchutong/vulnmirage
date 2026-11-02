"""Original PoC replay and regression checks on clean and adversarial variants."""

from __future__ import annotations

import time
from pathlib import Path

from ..models import CheckStatus, ValidatorCommand
from .command_support import outcome_details, run_commands_in_copy
from .context import ValidationContext, new_started, result
from .exec import dedupe_commands, normalize_command_output


def _collect_commands(ctx: ValidationContext, kind: str) -> list[ValidatorCommand]:
    commands: list[ValidatorCommand] = []
    for vulnerability in ctx.oracle.vulnerabilities:
        commands.extend(
            vulnerability.poc_commands if kind == "poc" else vulnerability.regression_commands
        )
    if kind == "poc":
        extra = ctx.config.validation.extra_poc_commands
        return dedupe_commands(commands, extra)
    return dedupe_commands(commands)


def _replay(ctx: ValidationContext, kind: str):
    check_name = "poc_replay" if kind == "poc" else "regression"
    started = new_started()
    began = time.monotonic()
    commands = _collect_commands(ctx, kind)
    if not commands:
        return result(
            check_name,
            CheckStatus.SKIP,
            started,
            time.monotonic() - began,
            details={"reason": f"no {kind} commands defined", "executed": False},
        )
    clean_outcomes, clean_repo = run_commands_in_copy(
        ctx.loaded,
        ctx.clean_repo,
        commands,
        label=f"{ctx.instance.instance_id}-{kind}-clean",
        log_dir=ctx.log_dir / f"{kind}-clean",
    )
    variant_outcomes, variant_repo = run_commands_in_copy(
        ctx.loaded,
        ctx.repo,
        commands,
        label=f"{ctx.instance.instance_id}-{kind}-variant",
        log_dir=ctx.log_dir / f"{kind}-variant",
    )
    errors: list[str] = []
    for clean, variant in zip(clean_outcomes, variant_outcomes, strict=True):
        if clean.timed_out:
            errors.append(f"clean {kind} timed out: {clean.argv}")
        if variant.timed_out:
            errors.append(f"variant {kind} timed out: {variant.argv}")
        if not clean.passed:
            errors.append(
                f"clean {kind} did not produce the expected result: "
                f"{clean.argv} exit {clean.exit_code}"
            )
        if not variant.passed:
            errors.append(
                f"variant {kind} did not produce the expected result: "
                f"{variant.argv} exit {variant.exit_code}"
            )
        if clean.exit_code != variant.exit_code:
            errors.append(
                f"{kind} exit code changed: clean {clean.exit_code} vs variant {variant.exit_code}"
            )
        clean_stdout = normalize_command_output(clean.stdout_text, Path(clean.repo_root))
        variant_stdout = normalize_command_output(variant.stdout_text, Path(variant.repo_root))
        if clean_stdout != variant_stdout:
            errors.append(f"{kind} stdout changed between clean and variant: {clean.argv}")
    details = {
        "errors": errors,
        "executed": True,
        "commands": [list(command.argv) for command in commands],
        "clean": [outcome_details(item) for item in clean_outcomes],
        "variant": [outcome_details(item) for item in variant_outcomes],
    }
    return result(
        check_name,
        CheckStatus.PASS if not errors else CheckStatus.FAIL,
        started,
        time.monotonic() - began,
        details=details,
    )


def check_poc_replay(ctx: ValidationContext):
    return _replay(ctx, "poc")


def check_regression(ctx: ValidationContext):
    return _replay(ctx, "regression")
