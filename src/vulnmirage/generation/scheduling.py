"""Deterministic operator/candidate scheduling (P0-3).

``select_operator`` alone returns the first compatible operator when no
feedback exists, so generating N candidates for one strategy could never cover
a second operator.  Scheduling is now explicit:

* ``exhaustive`` — every compatible operator is used before repeating;
* ``balanced`` — deterministic round-robin across operators;
* ``feedback`` — rank by a dev feedback snapshot (falls back to round-robin).

The schedule is recorded in the selection manifest together with the
compatibility-matrix version it was computed against.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..errors import GenerationError
from .feedback import FeedbackSnapshot, select_operator


@dataclass(frozen=True)
class OperatorAssignment:
    index: int
    operator: str
    policy: str
    candidate_set: list[str]
    position: int

    @property
    def record(self) -> dict[str, object]:
        return {
            "candidate_index": self.index,
            "operator": self.operator,
            "schedule_policy": self.policy,
            "compatible_operators": list(self.candidate_set),
            "position": self.position,
        }


def assign_operator(
    *,
    index: int,
    tier: str,
    goal: str,
    compatible: list[str],
    policy: str,
    feedback: FeedbackSnapshot | None = None,
) -> OperatorAssignment:
    if index < 0:
        raise GenerationError("candidate index must be non-negative")
    operators = list(dict.fromkeys(compatible))
    if not operators:
        raise GenerationError(f"no compatible operator for {tier}/{goal}")
    if policy == "feedback":
        if feedback is None:
            # Declared fallback, recorded in the manifest.
            names = _round_robin(operators, index)
        else:
            names = [select_operator(tier, goal, operators, feedback)]
    elif policy in {"exhaustive", "balanced"}:
        names = _round_robin(operators, index)
    else:
        raise GenerationError(f"unknown candidate schedule policy {policy!r}")
    chosen = names[0]
    return OperatorAssignment(
        index=index,
        operator=chosen,
        policy=policy,
        candidate_set=operators,
        position=operators.index(chosen),
    )


def _round_robin(operators: list[str], index: int) -> list[str]:
    offset = index % len(operators)
    return operators[offset:] + operators[:offset]
