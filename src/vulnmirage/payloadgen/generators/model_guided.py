"""T3/T4: optimization loops over surrogate or victim feedback.

Not implemented in this build, and deliberately not stubbed with a template: the
design makes T3/T4 a separate protocol with its own budget, query log, freeze and
holdout (§17).  A generator that returned a T2 render under a T3 label would make
the ablation report an effect it never measured.
"""

from __future__ import annotations

from ..context import GeneratorContext
from ..contracts import CandidatePayload
from ...errors import UnsupportedTierError


def generate(context: GeneratorContext) -> list[CandidatePayload]:
    raise UnsupportedTierError(
        "surrogate/victim-adaptive generation is not implemented in this build",
        details={"tier": context.tier, "method_id": context.method_id},
    )


__all__ = ["generate"]
