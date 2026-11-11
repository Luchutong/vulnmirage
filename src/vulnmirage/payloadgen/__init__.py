"""Repository-injection payload generation.

The package is split so the static, checkable parts stay static and the adaptive
parts stay explicit:

``taxonomy``           objective × mechanism × surface × intensity contracts
``catalog``            canonical methods plus concrete realizations
``render``             deterministic template rendering and the decoy certificate
``legacy``             the pre-package render path, kept for byte-level parity
``repository_index``   deterministic public-structure index consumed by T1+
``oracle_view``        allowlist sanitizer for T2+ local semantics
``context``            the capability object every generator receives
``generators``         one module per tier; T3/T4 fail closed
``validators``         structural / leakage / semantic / budget
``selection``          predeclared scoring with a deterministic tie-break
``remap``              target relocation after an edit shifts lines
``engine``             the single generate-validate-select-freeze entry point
"""

from __future__ import annotations

from .catalog import (
    PAYLOAD_CATALOG_VERSION,
    MethodPlacementLimits,
    MethodValidationPolicy,
    PayloadCatalog,
    PayloadMethod,
    PayloadRealizationDefinition,
    load_payload_catalog,
    load_threat_models,
)
from .context import (
    GeneratorContext,
    PlacementHint,
    PublicTaskView,
    TierBudget,
    fields_for_tier,
)
from .contracts import (
    AdaptationQuery,
    CandidatePayload,
    CandidateValidation,
    ConditionSpec,
    ExperimentCell,
    GenerationManifest,
    SelectionRecord,
    ValidatorResult,
)
from .engine import (
    GENERATOR_VERSION,
    GenerationRequest,
    attach_remap,
    build_context,
    candidate_to_edit,
    generate_manifest,
    selected_candidate,
    validate_candidate,
)
from .legacy import (
    PayloadRealization,
    payload_asset_hashes,
    realize_payload,
    validate_payload_references,
)
from .oracle_view import OracleAttackView, assert_view_is_clean, build_oracle_attack_view
from .remap import RemapRecord, TargetRemap, remap_targets
from .repository_index import IndexLimits, RepositoryIndex, build_repository_index
from .taxonomy import (
    TAXONOMY_VERSION,
    AttackConditionIdentity,
    AttackMethod,
    AttackSurface,
    RealizationDose,
    ThreatModel,
)

__all__ = [
    "AdaptationQuery",
    "AttackConditionIdentity",
    "AttackMethod",
    "AttackSurface",
    "CandidatePayload",
    "CandidateValidation",
    "ConditionSpec",
    "ExperimentCell",
    "GENERATOR_VERSION",
    "GenerationManifest",
    "GenerationRequest",
    "GeneratorContext",
    "IndexLimits",
    "MethodPlacementLimits",
    "MethodValidationPolicy",
    "OracleAttackView",
    "PAYLOAD_CATALOG_VERSION",
    "PayloadCatalog",
    "PayloadMethod",
    "PayloadRealizationDefinition",
    "PayloadRealization",
    "PlacementHint",
    "PublicTaskView",
    "RemapRecord",
    "RepositoryIndex",
    "RealizationDose",
    "SelectionRecord",
    "TargetRemap",
    "TAXONOMY_VERSION",
    "ThreatModel",
    "TierBudget",
    "ValidatorResult",
    "assert_view_is_clean",
    "attach_remap",
    "build_context",
    "build_oracle_attack_view",
    "build_repository_index",
    "candidate_to_edit",
    "fields_for_tier",
    "generate_manifest",
    "load_payload_catalog",
    "load_threat_models",
    "payload_asset_hashes",
    "realize_payload",
    "remap_targets",
    "selected_candidate",
    "validate_candidate",
    "validate_payload_references",
]
