"""Payload method registry (v1 and v2 shapes).

The registry describes **capabilities and constraints**, never results (design §9).
A method declares which tiers it can be realized at and which realization backend
each tier uses; the campaign refuses a condition whose tier the method does not
support instead of falling back to a cheaper realization at run time.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..errors import CampaignError
from ..tiers import Tier

PAYLOAD_CATALOG_VERSION = "2.0"
SUPPORTED_CATALOG_VERSIONS = ("1.0", "2.0")


class MethodPlacementLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_files_changed: int = Field(default=1, ge=1, le=16)
    max_inserted_lines: int = Field(default=8, ge=1, le=400)
    max_payload_chars: int = Field(default=4000, ge=1, le=200_000)


class MethodValidationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parse_required: bool = True
    build_equivalence: Literal["required", "when_profile_available", "not_applicable"] = (
        "when_profile_available"
    )
    target_remap_required: bool = True
    answer_token_scan: bool = True


class PayloadMethod(BaseModel):
    """One registered method.

    ``templates`` maps a tier to a template path.  When a tier has no dedicated
    template the method falls back to ``template`` (the v1 field), and that
    fallback is visible in the generation manifest rather than implied.
    """

    model_config = ConfigDict(extra="forbid")

    payload_id: str
    method_id: str | None = None
    method_family: str
    objective: Literal[
        "false_negative",
        "false_positive",
        "severity_downgrade",
        "severity_inflation",
        "verification_diversion",
    ]
    carrier: str
    placement: Literal["create_file", "target_file_footer", "safe_decoy_file"]
    reproduction_status: Literal["implemented_adaptation", "planned"]
    template: str
    output_path: str | None = None
    description: str = ""
    source_url: str | None = None
    safe_decoy_cwe_ids: list[str] = Field(default_factory=list)
    private_safety_basis: str | None = None
    # --- v2 capability fields ------------------------------------------------
    supported_tiers: list[Tier] = Field(default_factory=lambda: ["T0"])
    realizations: dict[str, str] = Field(default_factory=dict)
    templates: dict[str, str] = Field(default_factory=dict)
    placement_limits: MethodPlacementLimits = Field(default_factory=MethodPlacementLimits)
    validation: MethodValidationPolicy = Field(default_factory=MethodValidationPolicy)
    inspiration_scope: str | None = None
    known_deviations: list[str] = Field(default_factory=list)

    @field_validator("supported_tiers")
    @classmethod
    def _tiers_unique(cls, value: list[str]) -> list[str]:
        seen: list[str] = []
        for item in value:
            if item not in seen:
                seen.append(item)
        if not seen:
            raise ValueError("a method must support at least one tier")
        return seen

    def template_for(self, tier: str) -> str:
        return self.templates.get(tier) or self.template

    def supports(self, tier: str) -> bool:
        return tier in self.supported_tiers

    def realization_for(self, tier: str) -> str | None:
        return self.realizations.get(tier)

    def referenced_templates(self) -> list[str]:
        paths = {self.template, *self.templates.values()}
        return sorted(paths)


class PayloadCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = PAYLOAD_CATALOG_VERSION
    methods: list[PayloadMethod]

    @field_validator("schema_version")
    @classmethod
    def _known_version(cls, value: str) -> str:
        if value not in SUPPORTED_CATALOG_VERSIONS:
            raise ValueError(f"unsupported payload catalog schema_version {value!r}")
        return value

    def by_id(self) -> dict[str, PayloadMethod]:
        result: dict[str, PayloadMethod] = {}
        for method in self.methods:
            if method.payload_id in result:
                raise CampaignError(
                    "duplicate payload id in catalog",
                    details={"payload_id": method.payload_id},
                )
            result[method.payload_id] = method
        return result


def load_payload_catalog(path: str | Path) -> PayloadCatalog:
    source = Path(path)
    if not source.is_file():
        raise CampaignError("payload catalog is missing", details={"path": str(source)})
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        catalog = PayloadCatalog.model_validate(raw)
    except Exception as exc:
        raise CampaignError(
            "invalid payload catalog", details={"path": str(source), "error": str(exc)}
        ) from exc
    catalog.by_id()
    for method in catalog.methods:
        # A method that claims a tier it has no realization for would fail at
        # generation time with an unclear error; refuse it at load time instead.
        if not method.realizations:
            continue
        for tier in method.supported_tiers:
            if tier in method.realizations:
                continue
            raise CampaignError(
                "method declares a tier without a realization",
                details={"payload_id": method.payload_id, "tier": tier},
            )
    return catalog


__all__ = [
    "MethodPlacementLimits",
    "MethodValidationPolicy",
    "PAYLOAD_CATALOG_VERSION",
    "PayloadCatalog",
    "PayloadMethod",
    "SUPPORTED_CATALOG_VERSIONS",
    "load_payload_catalog",
]
