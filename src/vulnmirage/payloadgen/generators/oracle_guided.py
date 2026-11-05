"""T2: oracle-guided placement and wording.

The generator receives a sanitized :class:`OracleAttackView`: a location and the
local semantics that make the path reachable.  It does not receive the advisory,
the weakness id, the fix or the code excerpt, so the payload can talk about the
*dangerous effect* and the *preconditions* without quoting the answer.
"""

from __future__ import annotations

from ..context import GeneratorContext
from ..contracts import CandidatePayload
from ...errors import GenerationError
from ..oracle_view import assert_view_is_clean
from . import base


def generate(context: GeneratorContext) -> list[CandidatePayload]:
    context.assert_matches_tier()
    view = context.oracle_view
    if view is None:
        raise GenerationError(
            "T2 generation requires a sanitized oracle view",
            details={"method_id": context.method_id},
        )
    assert_view_is_clean(view, context.forbidden_tokens)
    location = view.locations[0]

    candidates: list[CandidatePayload] = []
    seen: set[tuple[str, str | None, str]] = set()
    for ordinal in range(context.budget.candidates):
        placement = None
        if context.placement in {"create_file", "safe_decoy_file"}:
            placement = base.create_placement(
                context, basis="oracle_view", symbol=location.symbol
            )
        elif ordinal % 2 == 1 and location.symbol:
            placement = base.insert_placement(
                context, path=location.file, symbol=location.symbol, basis="oracle_view"
            )
        if placement is None:
            placement = base.footer_placement(
                context, path=location.file, symbol=location.symbol, basis="oracle_view"
            )
        rendered = base.render(context, placement=placement)
        key = (rendered, placement.target_file, placement.anchor)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            base.candidate(
                context,
                placement=placement,
                rendered=rendered,
                rationale=(
                    "placement and wording come from the sanitized local semantics "
                    f"({view.target_ref}); advisory identity, fix and excerpt were removed"
                ),
                fields_used=[
                    "task.task_id",
                    "method.template",
                    "oracle_view.locations",
                    "oracle_view.local_semantics",
                ],
                generator="oracle_guided",
                ordinal=ordinal,
            )
        )
    if not candidates:
        raise GenerationError(
            "T2 generator produced no distinct candidate",
            details={"method_id": context.method_id},
        )
    return candidates


__all__ = ["generate"]
