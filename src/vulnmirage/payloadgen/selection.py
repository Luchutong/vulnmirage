"""Deterministic selection over validated candidates (design §13).

The policy is fixed before generation and recorded with its scores.  There is no
step in which a candidate is preferred because a victim model reacted better to
it: T3/T4 may optimize inside their own budget, but that budget and its stop
condition are frozen in the plan, and the selection here never looks at a run.
"""

from __future__ import annotations

from ..errors import GenerationError
from ..hashing import sha256_text
from .contracts import CandidatePayload, CandidateValidation, SelectionRecord

SELECTION_POLICIES = ("semantic_fit_then_deterministic_tiebreak",)

#: Which placement bases fit an Objective. Used as a coarse fit signal,
#: never as evidence that an attack worked.
_FIT_BY_OBJECTIVE = {
    "O-FN": {"append", "insert_before", "create"},
    "O-FP": {"create"},
    "O-SEV-D": {"append", "insert_before"},
    "O-SEV-I": {"append", "insert_before"},
    "O-EV": {"append", "insert_before", "create"},
    "O-SCOPE": {"create"},
    "O-AVAIL": {"create", "append", "insert_before"},
    "none": {"create", "append", "insert_before"},
}


def score_candidate(
    candidate: CandidatePayload, validation: CandidateValidation
) -> dict[str, float]:
    """Return the named components plus a total; the components are kept for audit."""
    components: dict[str, float] = {}
    components["validated"] = 1.0 if validation.selectable else 0.0
    components["placement_fit"] = (
        1.0
        if candidate.edit_op
        in _FIT_BY_OBJECTIVE.get(
            candidate.provenance.get("objective", ""),
            {"create", "append", "insert_before"},
        )
        else 0.5
    )
    components["visibility"] = (
        1.0
        if candidate.target_file
        and candidate.target_file.endswith(
            (".py", ".c", ".h", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs", ".rs")
        )
        else 0.75
    )
    components["compact"] = 1.0 / (1.0 + max(0, candidate.estimated_lines - 1))
    components["tier_evidence"] = 1.0 if candidate.context_fields_used else 0.0
    components["total"] = round(
        0.35 * components["validated"]
        + 0.25 * components["placement_fit"]
        + 0.15 * components["visibility"]
        + 0.15 * components["compact"]
        + 0.10 * components["tier_evidence"],
        6,
    )
    return components


def select(
    candidates: list[CandidatePayload],
    validations: dict[str, CandidateValidation],
    *,
    policy: str,
    objective: str = "none",
) -> SelectionRecord:
    if policy not in SELECTION_POLICIES:
        raise GenerationError("unknown selection policy", details={"policy": policy})
    if not candidates:
        raise GenerationError("no candidate was generated")

    eliminated: dict[str, str] = {}
    scores: dict[str, float] = {}
    eligible: list[CandidatePayload] = []
    for candidate in candidates:
        validation = validations.get(candidate.candidate_id)
        if validation is None:
            eliminated[candidate.candidate_id] = "no validation record"
            scores[candidate.candidate_id] = 0.0
            continue
        annotated = candidate.model_copy(
            update={"provenance": {**candidate.provenance, "objective": objective}}
        )
        components = score_candidate(annotated, validation)
        scores[candidate.candidate_id] = components["total"]
        if not validation.selectable:
            blocked = ", ".join(item.validator for item in validation.blocking())
            eliminated[candidate.candidate_id] = f"required validation not passed: {blocked}"
            continue
        eligible.append(candidate)

    if not eligible:
        raise GenerationError(
            "every candidate failed a required validator; refusing to select one",
            details={"eliminated": eliminated},
        )

    ranked = sorted(
        eligible,
        key=lambda item: (-scores.get(item.candidate_id, 0.0), item.candidate_id),
    )
    selected = ranked[0]
    for loser in ranked[1:]:
        if scores.get(loser.candidate_id) == scores.get(selected.candidate_id):
            eliminated[loser.candidate_id] = "tie broken by candidate id"
        else:
            eliminated[loser.candidate_id] = "lower predeclared score"
    record = SelectionRecord(
        policy=policy,
        scores=dict(sorted(scores.items())),
        ranked=[item.candidate_id for item in ranked],
        selected_id=selected.candidate_id,
        eliminated=dict(sorted(eliminated.items())),
        tie_break=f"sha256(policy+candidate_id)={sha256_text(policy + selected.candidate_id)[:12]}",
        notes=[
            "selection was computed before any victim run",
            "objective/placement fit is a heuristic component, not evidence of effect",
        ],
    )
    return record


__all__ = ["SELECTION_POLICIES", "score_candidate", "select"]
