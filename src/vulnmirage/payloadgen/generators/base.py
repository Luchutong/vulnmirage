"""Shared helper for the tier generators."""

from __future__ import annotations

from dataclasses import dataclass

from ...errors import GenerationError
from ...hashing import sha256_text, stable_id
from ..context import GeneratorContext
from ..contracts import CandidatePayload
from ..render import comment_prefix_for, render_template


@dataclass(frozen=True)
class Placement:
    target_file: str | None
    symbol: str | None
    edit_op: str
    anchor: str | None
    basis: str


def render_values(
    context: GeneratorContext,
    *,
    prefix: str,
    target_file: str | None,
    symbol: str | None,
) -> dict[str, str]:
    semantics = context.oracle_view.local_semantics if context.oracle_view else None
    preconditions = list(semantics.required_preconditions) if semantics else []
    claims = list(semantics.boundary_claims_to_test) if semantics else []
    effect = (semantics.dangerous_effect if semantics else None) or (
        "resource growth before a limit is enforced"
    )
    return {
        "comment_prefix": prefix,
        "target_file": target_file or "",
        "target_function": symbol or "the affected routine",
        # Never the oracle severity: see payloadgen.legacy module docstring.
        "expected_severity": "unknown",
        "variant_id": context.variant_id,
        "precondition": preconditions[0]
        if preconditions
        else "untrusted input reaches the parsed structure",
        "boundary_claim": claims[0]
        if claims
        else "the shipped defaults already cover this case",
        "dangerous_effect": effect,
    }


def candidate(
    context: GeneratorContext,
    *,
    placement: Placement,
    rendered: str,
    rationale: str,
    fields_used: list[str],
    generator: str,
    ordinal: int = 0,
) -> CandidatePayload:
    payload = CandidatePayload(
        candidate_id=stable_id(
            "CAND",
            context.variant_id,
            context.method_id,
            context.tier,
            context.seed,
            ordinal,
            rendered,
        ),
        variant_id=context.variant_id,
        method_id=context.method_id,
        tier=context.tier,
        seed=context.seed,
        generator=generator,
        carrier=context.carrier,
        target_file=placement.target_file,
        edit_op=placement.edit_op,  # type: ignore[arg-type]
        anchor=placement.anchor,
        rendered_text=rendered,
        rationale=rationale,
        context_fields_used=sorted(set(fields_used)),
        placement_basis=placement.basis,
        estimated_files=1,
        provenance={
            "tier": context.tier,
            "method": context.method_id,
            "template_sha256": sha256_text(context.template_text()),
            "index_sha256": context.index.index_sha256 if context.index else "",
            "oracle_view_sha256": context.oracle_view.source_sha256 if context.oracle_view else "",
        },
    )
    return payload.finalized()


def anchor_line(context: GeneratorContext, path: str, symbol: str) -> str | None:
    """Return the single source line that declares ``symbol``, if unambiguous."""
    if context.repo_root is None:
        return None
    from ...paths import safe_join

    try:
        target = safe_join(context.repo_root, path)
    except Exception:
        return None
    if not target.is_file():
        return None
    hits = [
        line for line in target.read_text(encoding="utf-8", errors="replace").splitlines()
        if symbol in line and "(" in line
    ]
    if len(hits) != 1:
        return None
    return hits[0].strip()


def footer_placement(context: GeneratorContext, *, path: str, symbol: str | None, basis: str) -> Placement:
    try:
        prefix = comment_prefix_for(path)
    except Exception as exc:  # noqa: BLE001 - surfaced with context below
        raise GenerationError(
            "target file has no comment syntax this method can use",
            details={"path": path, "method_id": context.method_id},
        ) from exc
    return Placement(
        target_file=path,
        symbol=symbol,
        edit_op="append",
        anchor=None,
        basis=basis,
    )


def insert_placement(context: GeneratorContext, *, path: str, symbol: str, basis: str) -> Placement | None:
    anchor = anchor_line(context, path, symbol)
    if anchor is None:
        return None
    try:
        comment_prefix_for(path)
    except Exception:  # noqa: BLE001
        return None
    return Placement(target_file=path, symbol=symbol, edit_op="insert_before", anchor=anchor, basis=basis)


def create_placement(
    context: GeneratorContext, *, basis: str, symbol: str | None = None
) -> Placement:
    if not context.output_path:
        raise GenerationError(
            "file payload is missing output_path",
            details={"method_id": context.method_id},
        )
    return Placement(
        target_file=context.output_path,
        symbol=symbol,
        edit_op="create",
        anchor=None,
        basis=basis,
    )


def render(context: GeneratorContext, *, placement: Placement, tier_template: str | None = None) -> str:
    template = context.template_text(tier_template)
    prefix = "#"
    if placement.target_file and placement.edit_op != "create":
        prefix = comment_prefix_for(placement.target_file)
    elif placement.target_file and placement.edit_op == "create":
        prefix = "#"
    values = render_values(
        context,
        prefix=prefix,
        target_file=placement.target_file,
        symbol=placement.symbol,
    )
    return render_template(template, values, payload_id=context.method_id)


__all__ = [
    "Placement",
    "anchor_line",
    "candidate",
    "create_placement",
    "footer_placement",
    "insert_placement",
    "render",
    "render_values",
]
