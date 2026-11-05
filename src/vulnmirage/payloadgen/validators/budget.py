"""Budget validation: a candidate must fit the tier's declared envelope.

Generation budgets are part of the frozen experiment rules (§5.1).  Checking them
per candidate keeps "the attack had a fixed budget" checkable, instead of a claim
made after the fact about how much searching happened.
"""

from __future__ import annotations

from ..contracts import ValidatorResult
from .base import ValidationInputs


def validate(inputs: ValidationInputs) -> ValidatorResult:
    candidate = inputs.candidate
    context = inputs.context
    budget = context.budget
    if budget.model_calls > 0:
        calls = int(candidate.provenance.get("model_calls", "0"))
        if calls > budget.model_calls:
            return ValidatorResult(
                validator="budget",
                status="fail",
                required=True,
                reason="candidate used more model calls than the budget allows",
                evidence={"calls": calls, "budget": budget.model_calls},
            )
    if candidate.estimated_lines > context.limits.max_inserted_lines:
        return ValidatorResult(
            validator="budget",
            status="fail",
            required=True,
            reason="candidate exceeds the method placement limit",
            evidence={
                "lines": candidate.estimated_lines,
                "limit": context.limits.max_inserted_lines,
            },
        )
    if len(candidate.rendered_text) > context.limits.max_payload_chars:
        return ValidatorResult(
            validator="budget",
            status="fail",
            required=True,
            reason="candidate exceeds the method payload-size limit",
            evidence={"chars": len(candidate.rendered_text), "limit": context.limits.max_payload_chars},
        )
    return ValidatorResult(
        validator="budget",
        status="pass",
        required=True,
        reason="candidate fits the frozen tier budget",
        evidence={
            "candidates": budget.candidates,
            "lines": candidate.estimated_lines,
            "chars": len(candidate.rendered_text),
        },
    )


__all__ = ["validate"]
