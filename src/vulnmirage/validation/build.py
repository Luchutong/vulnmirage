"""Build and functional-test checks with clean/variant parity."""

from __future__ import annotations

import time

from ..models import CheckStatus
from .command_support import outcome_details, run_commands_in_copy
from .context import ValidationContext, new_started, result


def _pair_check(ctx: ValidationContext, kind: str):
    started = new_started()
    began = time.monotonic()
    specs = (
        ctx.config.validation.build_commands
        if kind == "build"
        else ctx.config.validation.test_commands
    )
    check_name = "build" if kind == "build" else "functional_tests"
    if not specs:
        return result(
            check_name,
            CheckStatus.SKIP,
            started,
            time.monotonic() - began,
            details={"reason": f"no {kind} commands configured"},
        )
    clean_outcomes, _ = run_commands_in_copy(
        ctx.loaded,
        ctx.clean_repo,
        specs,
        label=f"{ctx.instance.instance_id}-{kind}-clean",
        log_dir=ctx.log_dir / f"{kind}-clean",
    )
    variant_outcomes, _ = run_commands_in_copy(
        ctx.loaded,
        ctx.repo,
        specs,
        label=f"{ctx.instance.instance_id}-{kind}-variant",
        log_dir=ctx.log_dir / f"{kind}-variant",
    )
    errors: list[str] = []
    for clean, variant in zip(clean_outcomes, variant_outcomes, strict=True):
        if not clean.passed:
            errors.append(f"clean {kind} command failed: {clean.argv} (exit {clean.exit_code})")
        if not variant.passed:
            errors.append(
                f"variant {kind} command failed: {variant.argv} (exit {variant.exit_code})"
            )
        if clean.exit_code != variant.exit_code:
            errors.append(
                f"{kind} exit code differs between clean and variant: "
                f"{clean.exit_code} vs {variant.exit_code}"
            )
    details = {
        "errors": errors,
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


def check_build(ctx: ValidationContext):
    return _pair_check(ctx, "build")


def check_functional_tests(ctx: ValidationContext):
    return _pair_check(ctx, "tests")
