"""T0: fixed text with deterministic, oracle-free placement.

Formal campaigns use only the public repository index to choose the first
comment-capable source file.  The template itself does not adapt to repository
content.  A legacy placement hint remains accepted only by the direct API so the
v1 rendering regression can be checked; the campaign never supplies that hint.
"""

from __future__ import annotations

from ..context import GeneratorContext
from ..contracts import CandidatePayload
from ...errors import GenerationError
from . import base


def generate(context: GeneratorContext) -> list[CandidatePayload]:
    context.assert_matches_tier()
    placement_kind = context.placement
    if placement_kind == "target_file_footer":
        if context.index is not None:
            from ..render import comment_prefix_for

            candidates = []
            for item in context.index.files:
                if item.role != "source":
                    continue
                try:
                    comment_prefix_for(item.path)
                except Exception:  # noqa: BLE001
                    continue
                candidates.append(item.path)
            if not candidates:
                raise GenerationError(
                    "the public index has no source file suitable for a static comment",
                    details={"method_id": context.method_id, "tier": context.tier},
                )
            path = sorted(candidates)[0]
            symbols = context.index.symbols_in(path)
            placement = base.footer_placement(
                context,
                path=path,
                symbol=(symbols[0].name if symbols else None),
                basis="static_public_index",
            )
        else:
            # Compatibility path for v1 callers and the byte-parity regression.
            # The formal campaign always supplies the public index.
            hint = context.placement_hint
            if hint is None or not hint.target_file:
                raise GenerationError(
                    "a target-file payload needs a public index",
                    details={"method_id": context.method_id, "tier": context.tier},
                )
            placement = base.footer_placement(
                context,
                path=hint.target_file,
                symbol=hint.target_function,
                basis=hint.basis,
            )
    else:
        placement = base.create_placement(context, basis="template")
    rendered = base.render(context, placement=placement)
    return [
        base.candidate(
            context,
            placement=placement,
            rendered=rendered,
            rationale="static template rendered with fixed placeholders",
            fields_used=[
                "task.task_id",
                "method.template",
                *(
                    ["index.files"]
                    if context.index is not None and placement_kind == "target_file_footer"
                    else []
                ),
                *(["placement_hint"] if context.placement_hint is not None else []),
            ],
            generator="static",
        )
    ]


__all__ = ["generate"]
