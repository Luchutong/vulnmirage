"""Canonical payload method and realization registry.

Methods define causal mechanisms. Realizations define one concrete expression,
surface and intensity. Generator tiers remain generation provenance and are not
part of the attack taxonomy.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..errors import CampaignError
from ..tiers import Tier
from .taxonomy import (
    TAXONOMY_VERSION,
    AttackMethod,
    AttackSurface,
    Intensity,
    Objective,
    RealizationDose,
    ThreatModel,
)

PAYLOAD_CATALOG_VERSION = "3.0"
SUPPORTED_CATALOG_VERSIONS = (PAYLOAD_CATALOG_VERSION,)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MethodPlacementLimits(_Strict):
    max_files_changed: int = Field(default=1, ge=1, le=16)
    max_inserted_lines: int = Field(default=8, ge=1, le=400)
    max_payload_chars: int = Field(default=4000, ge=1, le=200_000)


class MethodValidationPolicy(_Strict):
    parse_required: bool = True
    build_equivalence: Literal["required", "when_profile_available", "not_applicable"] = (
        "when_profile_available"
    )
    target_remap_required: bool = True
    answer_token_scan: bool = True


class PayloadRealizationDefinition(_Strict):
    """One concrete expression of a method at one surface and intensity."""

    realization_id: str
    method_id: str
    objective: Objective
    surface: AttackSurface
    intensity: Intensity
    dose: RealizationDose
    language: str = "repository_native"
    reproduction_status: Literal["implemented_adaptation", "planned"]
    carrier: str
    placement: Literal["create_file", "target_file_footer", "safe_decoy_file"]
    template: str
    templates: dict[str, str] = Field(default_factory=dict)
    supported_generator_tiers: list[Tier] = Field(default_factory=lambda: ["T0"])
    generator_backends: dict[str, str] = Field(default_factory=dict)
    allowed_threat_models: list[str] = Field(default_factory=list)
    output_path: str | None = None
    description: str = ""
    source_url: str | None = None
    safe_decoy_cwe_ids: list[str] = Field(default_factory=list)
    private_safety_basis: str | None = None
    placement_limits: MethodPlacementLimits = Field(default_factory=MethodPlacementLimits)
    validation: MethodValidationPolicy = Field(default_factory=MethodValidationPolicy)
    inspiration_scope: str | None = None
    known_deviations: list[str] = Field(default_factory=list)

    @field_validator("supported_generator_tiers")
    @classmethod
    def _tiers_unique(cls, value: list[str]) -> list[str]:
        result = list(dict.fromkeys(value))
        if not result:
            raise ValueError("a realization must declare at least one generator tier")
        return result


class PayloadMethod(_Strict):
    """Resolved method + realization used by the generation pipeline."""

    payload_id: str
    realization_id: str
    method_id: str
    method_family: str
    objective: Objective
    primary_mechanism: str
    mechanism_class: str
    surface: AttackSurface
    intensity: Intensity
    dose: RealizationDose
    carrier: str
    placement: Literal["create_file", "target_file_footer", "safe_decoy_file"]
    reproduction_status: Literal["implemented_adaptation", "planned"]
    template: str
    templates: dict[str, str] = Field(default_factory=dict)
    supported_tiers: list[Tier] = Field(default_factory=lambda: ["T0"])
    generator_backends: dict[str, str] = Field(default_factory=dict)
    allowed_threat_models: list[str] = Field(default_factory=list)
    output_path: str | None = None
    description: str = ""
    source_url: str | None = None
    safe_decoy_cwe_ids: list[str] = Field(default_factory=list)
    private_safety_basis: str | None = None
    placement_limits: MethodPlacementLimits = Field(default_factory=MethodPlacementLimits)
    validation: MethodValidationPolicy = Field(default_factory=MethodValidationPolicy)
    inspiration_scope: str | None = None
    known_deviations: list[str] = Field(default_factory=list)

    def template_for(self, tier: str) -> str:
        return self.templates.get(tier) or self.template

    def supports(self, tier: str) -> bool:
        return tier in self.supported_tiers

    def realization_for(self, tier: str) -> str | None:
        return self.generator_backends.get(tier)

    def referenced_templates(self) -> list[str]:
        return sorted({self.template, *self.templates.values()})


class PayloadCatalog(_Strict):
    schema_version: str = PAYLOAD_CATALOG_VERSION
    taxonomy_version: str = TAXONOMY_VERSION
    threat_model_files: list[str] = Field(min_length=1)
    method_definitions: list[AttackMethod] = Field(min_length=1)
    realizations: list[PayloadRealizationDefinition] = Field(min_length=1)

    @field_validator("schema_version")
    @classmethod
    def _known_version(cls, value: str) -> str:
        if value not in SUPPORTED_CATALOG_VERSIONS:
            raise ValueError(f"unsupported payload catalog schema_version {value!r}")
        return value

    @field_validator("taxonomy_version")
    @classmethod
    def _taxonomy_version(cls, value: str) -> str:
        if value != TAXONOMY_VERSION:
            raise ValueError(f"unsupported taxonomy_version {value!r}")
        return value

    def method_map(self) -> dict[str, AttackMethod]:
        result: dict[str, AttackMethod] = {}
        for method in self.method_definitions:
            if method.method_id in result:
                raise CampaignError(
                    "duplicate method id in catalog", details={"method_id": method.method_id}
                )
            result[method.method_id] = method
        return result

    def realization_map(self) -> dict[str, PayloadRealizationDefinition]:
        result: dict[str, PayloadRealizationDefinition] = {}
        for realization in self.realizations:
            if realization.realization_id in result:
                raise CampaignError(
                    "duplicate realization id in catalog",
                    details={"realization_id": realization.realization_id},
                )
            result[realization.realization_id] = realization
        return result

    def resolve(self, realization: PayloadRealizationDefinition) -> PayloadMethod:
        method = self.method_map().get(realization.method_id)
        if method is None:
            raise CampaignError(
                "realization references an unknown method",
                details={
                    "realization_id": realization.realization_id,
                    "method_id": realization.method_id,
                },
            )
        return PayloadMethod(
            payload_id=realization.realization_id,
            realization_id=realization.realization_id,
            method_id=method.method_id,
            method_family=method.name,
            objective=realization.objective,
            primary_mechanism=method.mechanism.primary,
            mechanism_class=method.mechanism.class_id,
            surface=realization.surface,
            intensity=realization.intensity,
            dose=realization.dose,
            carrier=realization.carrier,
            placement=realization.placement,
            reproduction_status=realization.reproduction_status,
            template=realization.template,
            templates=realization.templates,
            supported_tiers=realization.supported_generator_tiers,
            generator_backends=realization.generator_backends,
            allowed_threat_models=realization.allowed_threat_models,
            output_path=realization.output_path,
            description=realization.description,
            source_url=realization.source_url,
            safe_decoy_cwe_ids=realization.safe_decoy_cwe_ids,
            private_safety_basis=realization.private_safety_basis,
            placement_limits=realization.placement_limits,
            validation=realization.validation,
            inspiration_scope=realization.inspiration_scope,
            known_deviations=realization.known_deviations,
        )

    @property
    def methods(self) -> list[PayloadMethod]:
        return [self.resolve(item) for item in self.realizations]

    def by_id(self) -> dict[str, PayloadMethod]:
        return {item.realization_id: self.resolve(item) for item in self.realizations}


def _load_yaml(path: Path, *, kind: str) -> object:
    if not path.is_file():
        raise CampaignError(f"{kind} is missing", details={"path": str(path)})
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise CampaignError(
            f"invalid {kind}", details={"path": str(path), "error": str(exc)}
        ) from exc


def _parse_catalog(source: Path) -> PayloadCatalog:
    try:
        return PayloadCatalog.model_validate(_load_yaml(source, kind="payload catalog"))
    except Exception as exc:
        if isinstance(exc, CampaignError):
            raise
        raise CampaignError(
            "invalid payload catalog", details={"path": str(source), "error": str(exc)}
        ) from exc


def load_threat_models(catalog_path: str | Path) -> dict[str, ThreatModel]:
    source = Path(catalog_path).resolve()
    catalog = _parse_catalog(source)
    result: dict[str, ThreatModel] = {}
    for relative in catalog.threat_model_files:
        path = (source.parent / relative).resolve()
        try:
            model = ThreatModel.model_validate(_load_yaml(path, kind="threat model"))
        except Exception as exc:
            if isinstance(exc, CampaignError):
                raise
            raise CampaignError(
                "invalid threat model", details={"path": str(path), "error": str(exc)}
            ) from exc
        if model.threat_model_id in result:
            raise CampaignError(
                "duplicate threat model id",
                details={"threat_model_id": model.threat_model_id},
            )
        result[model.threat_model_id] = model
    return result


def _validate_catalog(catalog: PayloadCatalog, threat_models: dict[str, ThreatModel]) -> None:
    methods = catalog.method_map()
    catalog.realization_map()
    for realization in catalog.realizations:
        method = methods.get(realization.method_id)
        if method is None:
            raise CampaignError(
                "realization references an unknown method",
                details={"realization_id": realization.realization_id},
            )
        if realization.objective not in method.supported_objectives:
            raise CampaignError(
                "realization objective is not supported by its method",
                details={"realization_id": realization.realization_id},
            )
        if realization.surface not in method.supported_surfaces:
            raise CampaignError(
                "realization surface is not supported by its method",
                details={"realization_id": realization.realization_id},
            )
        if realization.intensity not in method.intensity_profiles:
            raise CampaignError(
                "realization intensity has no method-specific profile",
                details={"realization_id": realization.realization_id},
            )
        profile = method.intensity_profiles[realization.intensity]
        dose = realization.dose
        if dose.claim_count > profile.max_claims:
            raise CampaignError(
                "realization claim dose exceeds its intensity profile",
                details={"realization_id": realization.realization_id},
            )
        if dose.supporting_evidence_count > profile.max_supporting_evidence:
            raise CampaignError(
                "realization evidence dose exceeds its intensity profile",
                details={"realization_id": realization.realization_id},
            )
        intensity_requirements = {
            "I0": ("implicit", 0, 0, 1),
            "I1": ("explicit", 0, 0, 1),
            "I2": ("explicit", 1, 0, 1),
            "I3": ("explicit", 2, 0, 1),
            "I4": ("explicit", 2, 1, 2),
        }
        directness, min_evidence, min_reinforcement, min_claims = intensity_requirements[
            realization.intensity
        ]
        if (
            dose.directness != directness
            or dose.supporting_evidence_count < min_evidence
            or dose.reinforcement_count < min_reinforcement
            or dose.claim_count < min_claims
        ):
            raise CampaignError(
                "realization dose does not satisfy its declared intensity",
                details={
                    "realization_id": realization.realization_id,
                    "intensity": realization.intensity,
                    "dose": dose.model_dump(mode="json"),
                },
            )
        if f"__{realization.intensity}__" not in realization.realization_id:
            raise CampaignError(
                "realization id does not encode its declared intensity",
                details={"realization_id": realization.realization_id},
            )
        unknown_models = set(realization.allowed_threat_models) - set(threat_models)
        if unknown_models:
            raise CampaignError(
                "realization references an unknown threat model",
                details={
                    "realization_id": realization.realization_id,
                    "unknown": sorted(unknown_models),
                },
            )
        for model_id in realization.allowed_threat_models:
            maximum = threat_models[model_id].mutation_constraints.max_files_changed
            if realization.placement_limits.max_files_changed > maximum:
                raise CampaignError(
                    "realization mutation budget exceeds its threat model",
                    details={"realization_id": realization.realization_id},
                )
        if realization.reproduction_status == "implemented_adaptation":
            for tier in realization.supported_generator_tiers:
                if tier not in realization.generator_backends:
                    raise CampaignError(
                        "realization declares a generator tier without a backend",
                        details={"realization_id": realization.realization_id, "tier": tier},
                    )
        if method.mechanism.class_id == "M5" and (
            realization.validation.build_equivalence == "not_applicable"
        ):
            raise CampaignError(
                "M5 realization must require behavior-equivalence validation",
                details={"realization_id": realization.realization_id},
            )


def load_payload_catalog(path: str | Path) -> PayloadCatalog:
    source = Path(path).resolve()
    catalog = _parse_catalog(source)
    _validate_catalog(catalog, load_threat_models(source))
    return catalog


__all__ = [
    "MethodPlacementLimits",
    "MethodValidationPolicy",
    "PAYLOAD_CATALOG_VERSION",
    "PayloadCatalog",
    "PayloadMethod",
    "PayloadRealizationDefinition",
    "SUPPORTED_CATALOG_VERSIONS",
    "load_payload_catalog",
    "load_threat_models",
]
