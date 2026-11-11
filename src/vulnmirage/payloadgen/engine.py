"""The generation engine: context -> candidates -> validation -> selection -> freeze.

This is the only entry point a campaign uses to decide what a condition contains.
It deliberately has no "give me one payload" mode: the pre-package behaviour of
rendering a single template allowed a choice to be made after a result was seen,
because there was nothing to choose between and nothing recorded.  Here the
candidate set, every validator verdict and the selection rule are written down
before the audit runs.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from ..errors import CampaignError, UnsupportedTierError
from ..tiers import Tier, is_implemented
from ..verifier.targets import SafeDecoy
from .catalog import MethodPlacementLimits, MethodValidationPolicy, PayloadMethod
from .context import GeneratorContext, PlacementHint, PublicTaskView, TierBudget
from .contracts import (
    CandidatePayload,
    CandidateValidation,
    GenerationManifest,
)
from .generators import GENERATOR_BY_NAME, GENERATOR_BY_TIER
from .oracle_view import OracleAttackView
from .remap import TargetRemap
from .repository_index import RepositoryIndex
from .selection import select
from .validators import VALIDATOR_ORDER, VALIDATORS, ValidationInputs

GENERATOR_VERSION = "2026-11-05.1"


class GenerationRequest(BaseModel):
    """Everything a generator is allowed to see, assembled by the campaign."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    task_id: str
    snapshot_id: str
    variant_id: str
    condition_id: str
    method_id: str
    method_family: str = ""
    taxonomy_version: str | None = None
    threat_model_id: str | None = None
    realization_id: str | None = None
    objective: str = Field(default="none", validation_alias=AliasChoices("objective", "goal"))
    primary_mechanism: str | None = None
    surface: dict[str, str] | None = None
    intensity: str | None = None
    dose: dict[str, object] | None = None
    generator_tier: Tier = Field(
        default="T0", validation_alias=AliasChoices("generator_tier", "tier")
    )
    seed: int = 0
    carrier: str = "unknown"
    placement: str = "create_file"
    output_path: str | None = None
    selection_policy: str = "semantic_fit_then_deterministic_tiebreak"

    task: PublicTaskView
    templates: dict[str, str] = Field(default_factory=dict)
    template_source: str = ""
    budget: TierBudget = Field(default_factory=TierBudget)
    limits: MethodPlacementLimits = Field(default_factory=MethodPlacementLimits)
    validation: MethodValidationPolicy = Field(default_factory=MethodValidationPolicy)

    index: RepositoryIndex | None = None
    oracle_view: OracleAttackView | None = None
    placement_hint: PlacementHint | None = None

    forbidden_tokens: list[str] = Field(default_factory=list)
    clean_tree_sha256: str = ""
    input_hashes: dict[str, str] = Field(default_factory=dict)
    repo_root: Path | None = None

    @property
    def tier(self) -> Tier:
        return self.generator_tier

    @property
    def goal(self) -> str:
        return self.objective


def build_context(request: GenerationRequest) -> GeneratorContext:
    if not is_implemented(request.tier):
        raise UnsupportedTierError(
            "this build implements T0-T2 only",
            details={"tier": request.tier, "method_id": request.method_id},
        )
    context = GeneratorContext(
        variant_id=request.variant_id,
        condition_id=request.condition_id,
        method_id=request.method_id,
        method_family=request.method_family,
        objective=request.objective,
        carrier=request.carrier,
        placement=request.placement,
        tier=request.tier,
        seed=request.seed,
        task=request.task,
        templates=request.templates,
        template_source=request.template_source,
        index=request.index,
        oracle_view=request.oracle_view,
        placement_hint=request.placement_hint,
        budget=request.budget,
        limits=request.limits,
        validation=request.validation,
        output_path=request.output_path,
        forbidden_tokens=list(request.forbidden_tokens),
        repo_root=request.repo_root,
    )
    context.assert_matches_tier()
    return context


def _generator_for(request: GenerationRequest, method: PayloadMethod | None):
    realization = method.realization_for(request.tier) if method else None
    if realization:
        module = GENERATOR_BY_NAME.get(realization)
        if module is None:
            raise UnsupportedTierError(
                "no generator implements this realization",
                details={"realization": realization, "tier": request.tier},
            )
        return module
    module = GENERATOR_BY_TIER.get(request.tier)
    if module is None:  # pragma: no cover - guarded by is_implemented
        raise UnsupportedTierError("no generator for this tier", details={"tier": request.tier})
    return module


def validate_candidate(
    candidate: CandidatePayload,
    *,
    context: GeneratorContext,
    repo_root: Path | None,
    forbidden_tokens: list[str],
) -> CandidateValidation:
    inputs = ValidationInputs(
        candidate=candidate,
        context=context,
        repo_root=repo_root,
        clean_root=repo_root,
        forbidden_tokens=tuple(forbidden_tokens),
    )
    results = [VALIDATORS[name](inputs) for name in VALIDATOR_ORDER]
    return CandidateValidation(candidate_id=candidate.candidate_id, results=results)


def _dedupe(candidates: list[CandidatePayload]) -> list[CandidatePayload]:
    seen: set[tuple[str, str | None, str | None]] = set()
    unique: list[CandidatePayload] = []
    for candidate in candidates:
        key = (candidate.rendered_text, candidate.target_file, candidate.anchor)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def generate_manifest(
    request: GenerationRequest,
    *,
    method: PayloadMethod | None = None,
    decoys: list[SafeDecoy] | None = None,
) -> GenerationManifest:
    context = build_context(request)
    module = _generator_for(request, method)
    generated = module.generate(context)
    candidates = [
        item.model_copy(
            update={
                "realization_id": request.realization_id,
                "objective": request.objective,
                "primary_mechanism": request.primary_mechanism,
                "surface": request.surface,
                "intensity": request.intensity,
                "dose": request.dose,
            }
        )
        for item in generated
    ]
    candidates = _dedupe(candidates)[: request.budget.candidates]
    if not candidates:
        raise CampaignError(
            "the generator produced no candidate",
            details={"variant_id": request.variant_id, "tier": request.tier},
        )
    validations = [
        validate_candidate(
            candidate,
            context=context,
            repo_root=request.repo_root,
            forbidden_tokens=request.forbidden_tokens,
        )
        for candidate in candidates
    ]
    by_id = {item.candidate_id: item for item in validations}
    selection = select(
        candidates,
        by_id,
        policy=request.selection_policy,
        objective=request.objective,
    )
    manifest = GenerationManifest(
        task_id=request.task_id,
        snapshot_id=request.snapshot_id,
        variant_id=request.variant_id,
        condition_id=request.condition_id,
        taxonomy_version=request.taxonomy_version,
        threat_model_id=request.threat_model_id,
        objective=request.objective,
        method_id=request.method_id,
        primary_mechanism=request.primary_mechanism,
        surface=request.surface,
        intensity=request.intensity,
        dose=request.dose,
        realization_id=request.realization_id,
        generator_tier=request.generator_tier,
        seed=request.seed,
        generator_version=GENERATOR_VERSION,
        clean_tree_sha256=request.clean_tree_sha256,
        index_sha256=(request.index.index_sha256 if request.index else None),
        oracle_view_sha256=(request.oracle_view.source_sha256 if request.oracle_view else None),
        input_hashes=dict(sorted(request.input_hashes.items())),
        candidate_budget=request.budget.candidates,
        candidates=candidates,
        validations=validations,
        selection=selection,
        notes=[
            "candidates were generated before any victim run existed",
            "a required validator that returns unknown blocks selection, it is not a pass",
            "the selected candidate is the only one that reaches the exposed tree",
        ],
    )
    return manifest


def selected_candidate(manifest: GenerationManifest) -> CandidatePayload:
    selected_id = manifest.selection.selected_id
    for candidate in manifest.candidates:
        if candidate.candidate_id == selected_id:
            return candidate
    raise CampaignError(
        "the frozen selection names a candidate that is not in the manifest",
        details={"variant_id": manifest.variant_id, "selected_id": selected_id},
    )


def candidate_to_edit(candidate: CandidatePayload):
    """Convert the selected candidate into the structured edit the builder applies."""
    from ..config import VariantEditConfig

    if not candidate.target_file:
        raise CampaignError(
            "the selected candidate has no target file",
            details={"candidate_id": candidate.candidate_id},
        )
    if candidate.edit_op == "create":
        return VariantEditConfig(
            op="create", path=candidate.target_file, text=candidate.rendered_text
        )
    if candidate.edit_op == "append":
        return VariantEditConfig(
            op="append", path=candidate.target_file, text=candidate.rendered_text
        )
    if candidate.edit_op == "insert_before":
        if not candidate.anchor:
            raise CampaignError(
                "insert_before candidate has no anchor",
                details={"candidate_id": candidate.candidate_id},
            )
        return VariantEditConfig(
            op="insert_before",
            path=candidate.target_file,
            text=candidate.rendered_text,
            find=candidate.anchor,
        )
    raise CampaignError("unsupported candidate edit", details={"op": candidate.edit_op})


def attach_remap(
    manifest: GenerationManifest, remap: TargetRemap, *, variant_tree_sha256: str
) -> GenerationManifest:
    """Bind the frozen remap to the manifest so both are covered by one hash."""
    return manifest.model_copy(
        update={
            "remap_sha256": remap.remap_sha256,
            "variant_tree_sha256": variant_tree_sha256,
        }
    )


__all__ = [
    "GENERATOR_VERSION",
    "GenerationRequest",
    "attach_remap",
    "build_context",
    "candidate_to_edit",
    "generate_manifest",
    "selected_candidate",
    "validate_candidate",
]
