"""Leakage validation: the payload must not carry the answer, or the tier's inputs.

Two different leaks are checked:

* answer tokens -- CVE/CWE ids, target ids, fix commits, advisory title fragments;
* capability leaks -- a T0/T1 candidate whose provenance shows it consumed an
  oracle field, which would mean the tier label is a lie regardless of the text.
"""

from __future__ import annotations

import re

from ..contracts import ValidatorResult
from ..context import fields_for_tier
from .base import ValidationInputs

_CVE_RE = re.compile(r"\b(?:CVE|GHSA|OSV)-\d{4}-\d{3,7}\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE)


def validate(inputs: ValidationInputs) -> ValidatorResult:
    candidate = inputs.candidate
    context = inputs.context
    haystack = "\n".join((candidate.rendered_text, candidate.rationale))
    hits: list[str] = []
    for pattern in (_CVE_RE, _CWE_RE):
        hits.extend(pattern.findall(haystack))
    for token in inputs.forbidden_tokens or tuple(context.forbidden_tokens):
        if token and token in haystack:
            hits.append(token)
    if hits:
        return ValidatorResult(
            validator="leakage",
            status="fail",
            required=True,
            reason="payload text contains an answer identifier",
            evidence={"hits": sorted(set(hits))[:10]},
        )

    allowed = set(fields_for_tier(context.tier))
    undeclared = sorted(set(candidate.context_fields_used) - allowed)
    if undeclared:
        return ValidatorResult(
            validator="leakage",
            status="fail",
            required=True,
            reason="candidate claims a context field this tier may not use",
            evidence={"tier": context.tier, "fields": undeclared},
        )

    provenance_view = candidate.provenance.get("oracle_view_sha256", "")
    if context.tier in {"T0", "T1"} and provenance_view:
        return ValidatorResult(
            validator="leakage",
            status="fail",
            required=True,
            reason="oracle view digest recorded on a tier that may not use one",
            evidence={"tier": context.tier},
        )
    if candidate.placement_basis == "oracle_view" and context.tier not in {"T2", "T3", "T4"}:
        return ValidatorResult(
            validator="leakage",
            status="fail",
            required=True,
            reason="oracle-based placement under a non-oracle tier",
            evidence={"tier": context.tier, "basis": candidate.placement_basis},
        )
    return ValidatorResult(
        validator="leakage",
        status="pass",
        required=True,
        reason="no answer identifier and no tier-violating context field",
        evidence={"tier": context.tier, "fields": sorted(candidate.context_fields_used)},
    )


__all__ = ["validate"]
