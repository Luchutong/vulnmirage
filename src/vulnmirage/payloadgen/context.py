"""The generator's capability object (design §10.1, §10.1 note on paths).

A generator never receives a filesystem root it can walk.  It receives this
object, whose fields are the *whole* of what that tier may know.  ``fields_for_tier``
is the allowlist; ``assert_matches_tier`` refuses a context that carries oracle
material into T0/T1, which is what stops a "T1" run from quietly being a T2 run.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..errors import GenerationError
from ..tiers import INDEXED_TIERS, ORACLE_VIEW_TIERS, TIER_INDEX, Tier
from .catalog import MethodPlacementLimits, MethodValidationPolicy
from .oracle_view import OracleAttackView
from .repository_index import RepositoryIndex

_PUBLIC_FIELDS = (
    "task.task_id",
    "task.primary_language",
    "method.template",
    "method.carrier",
    "method.placement",
    "budget",
    "forbidden_tokens",
)
_INDEX_FIELDS = (
    "index.files",
    "index.symbols",
    "index.comment_styles",
    "index.sink_files",
    "index.todo_lines",
    "index.source_files",
    "index.test_files",
    "index.doc_files",
)
_ORACLE_FIELDS = (
    "oracle_view.locations",
    "oracle_view.local_semantics",
)

ALLOWED_FIELDS_BY_TIER: dict[str, tuple[str, ...]] = {
    "T0": (*_PUBLIC_FIELDS, *_INDEX_FIELDS, "placement_hint"),
    "T1": (*_PUBLIC_FIELDS, *_INDEX_FIELDS),
    "T2": (*_PUBLIC_FIELDS, *_INDEX_FIELDS, *_ORACLE_FIELDS),
    "T3": (*_PUBLIC_FIELDS, *_INDEX_FIELDS, *_ORACLE_FIELDS, "surrogate.feedback"),
    "T4": (*_PUBLIC_FIELDS, *_INDEX_FIELDS, *_ORACLE_FIELDS, "victim.feedback"),
}


def fields_for_tier(tier: str) -> tuple[str, ...]:
    return ALLOWED_FIELDS_BY_TIER.get(tier, _PUBLIC_FIELDS)


class PublicTaskView(BaseModel):
    """What the dataset says about the task, minus anything answer-shaped."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    primary_language: str | None = None
    #: Target count is deliberately absent: "how many bugs are here" is oracle
    #: information a public-context attacker would not have.


class TierBudget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidates: int = Field(default=1, ge=1, le=64)
    max_files_changed: int = Field(default=1, ge=1, le=16)
    max_inserted_lines: int = Field(default=8, ge=1, le=400)
    max_payload_chars: int = Field(default=4000, ge=1, le=200_000)
    model_calls: int = Field(default=0, ge=0, le=1000)


class PlacementHint(BaseModel):
    """Compatibility-only placement for direct v1 rendering calls.

    Formal campaigns do not supply this field to T0; they use deterministic
    placement from the public repository index.
    """

    model_config = ConfigDict(extra="forbid")

    target_file: str | None = None
    target_function: str | None = None
    comment_prefix: str | None = None
    basis: str = "template"


class GeneratorContext(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    variant_id: str
    condition_id: str
    method_id: str
    method_family: str
    objective: str
    carrier: str
    placement: str
    tier: Tier
    goal: str = "none"
    seed: int = 0

    task: PublicTaskView
    templates: dict[str, str] = Field(default_factory=dict)
    template_source: str = ""

    index: RepositoryIndex | None = None
    oracle_view: OracleAttackView | None = None
    placement_hint: PlacementHint | None = None

    budget: TierBudget = Field(default_factory=TierBudget)
    limits: MethodPlacementLimits = Field(default_factory=MethodPlacementLimits)
    validation: MethodValidationPolicy = Field(default_factory=MethodValidationPolicy)
    output_path: str | None = None
    forbidden_tokens: list[str] = Field(default_factory=list)

    #: The only directory a generator may read.  It is the clean, public tree.
    repo_root: Path | None = None

    def fields_used(self) -> list[str]:
        used = ["task.task_id", "method.template"]
        if self.placement_hint is not None:
            used.append("placement_hint")
        if self.index is not None:
            used.extend(["index.files", "index.symbols", "index.comment_styles"])
        if self.oracle_view is not None:
            used.extend(["oracle_view.locations", "oracle_view.local_semantics"])
        return used

    def assert_matches_tier(self) -> None:
        allowed = set(fields_for_tier(self.tier))
        if self.oracle_view is not None and "oracle_view.locations" not in allowed:
            raise GenerationError(
                "this tier may not receive an oracle view",
                details={"tier": self.tier},
            )
        if self.index is not None and "index.files" not in allowed:
            raise GenerationError(
                "this tier may not receive a repository index",
                details={"tier": self.tier},
            )
        if self.placement_hint is not None and "placement_hint" not in allowed:
            raise GenerationError(
                "this tier may not receive a legacy placement hint",
                details={"tier": self.tier},
            )
        if self.index is not None and self.tier not in INDEXED_TIERS:
            raise GenerationError("index present on a non-indexed tier", details={"tier": self.tier})
        if self.oracle_view is not None and self.tier not in ORACLE_VIEW_TIERS:
            raise GenerationError("oracle view present below T2", details={"tier": self.tier})

    def template_text(self, tier: str | None = None) -> str:
        key = tier or self.tier
        text = self.templates.get(key)
        if text is None:
            text = self.templates.get("T0")
        if text is None:
            raise GenerationError(
                "no template is available for this method",
                details={"method_id": self.method_id, "tier": key},
            )
        return text


def tier_rank(tier: str) -> int:
    return TIER_INDEX.get(tier, -1)


__all__ = [
    "ALLOWED_FIELDS_BY_TIER",
    "GeneratorContext",
    "PlacementHint",
    "PublicTaskView",
    "TierBudget",
    "fields_for_tier",
    "tier_rank",
]
