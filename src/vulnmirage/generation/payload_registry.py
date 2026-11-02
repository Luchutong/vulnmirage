"""Payload registry with provenance, compatibility, licence and split metadata."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..errors import ConfigError, GenerationError
from ..hashing import sha256_file, sha256_text
from ..models import (
    AdaptationRecord,
    AttackGoal,
    Carrier,
    GenerationMethod,
    LiteratureSource,
    Mechanism,
    PayloadOrigin,
    PayloadProvenance,
    Presentation,
)
from ..paths import is_safe_relpath, safe_join
from .context import GenerationContext
from .template_backend import TemplateBackend

_VALID_SPLITS = {"public_known", "heldout_strategy", "generated_variant"}


class PayloadDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload_id: str
    origin: PayloadOrigin
    source_title: str | None = None
    source_url: str | None = None
    source_license: str | None = None
    strategy_family: str
    #: Orthogonal taxonomy used by the compatibility matrix.
    mechanism: Mechanism
    presentation: Presentation
    supported_languages: list[str] = Field(default_factory=lambda: ["*"])
    generation_method: GenerationMethod = GenerationMethod.TEMPLATE
    compatible_goals: list[AttackGoal]
    compatible_carriers: list[str]
    template_file: str
    strategy_split: str = "public_known"
    required_context: list[str] = Field(default_factory=list)
    required_oracle_fields: list[str] = Field(default_factory=list)
    required_safe_target: bool = False
    required_validators: bool = False
    literature_sources: list[LiteratureSource] = Field(default_factory=list)
    adaptation: AdaptationRecord | None = None
    notes: str | None = None

    @field_validator("payload_id", "strategy_family")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("compatible_carriers")
    @classmethod
    def _carriers(cls, value: list[str]) -> list[str]:
        cleaned = sorted({item.strip() for item in value if item.strip()})
        if not cleaned:
            raise ValueError("payload must support at least one carrier")
        allowed = {item.value for item in Carrier}
        for item in cleaned:
            if item not in allowed:
                raise ValueError(f"unknown carrier {item!r}; allowed: {sorted(allowed)}")
        return cleaned

    @field_validator("compatible_goals")
    @classmethod
    def _goals(cls, value: list[AttackGoal]) -> list[AttackGoal]:
        if not value:
            raise ValueError("payload must support at least one attack goal")
        return list(dict.fromkeys(value))

    @field_validator("supported_languages")
    @classmethod
    def _languages(cls, value: list[str]) -> list[str]:
        cleaned = sorted({item.strip().lower() for item in value if item.strip()})
        return cleaned or ["*"]

    @field_validator("template_file")
    @classmethod
    def _template(cls, value: str) -> str:
        if not is_safe_relpath(value):
            raise ValueError("template_file must be a safe repository-relative path")
        return value

    @field_validator("strategy_split")
    @classmethod
    def _split(cls, value: str) -> str:
        if value not in _VALID_SPLITS:
            raise ValueError(f"strategy_split must be one of {sorted(_VALID_SPLITS)}")
        return value

    @model_validator(mode="after")
    def _license(self) -> "PayloadDefinition":
        if self.origin == PayloadOrigin.PUBLISHED_VERBATIM:
            if not self.source_url or not self.source_license:
                raise ValueError(
                    "published_verbatim payloads require source_url and source_license"
                )
            if not self.literature_sources:
                raise ValueError(
                    "published_verbatim payloads must cite their literature source"
                )
        if self.required_safe_target and AttackGoal.FALSE_POSITIVE not in self.compatible_goals:
            raise ValueError("required_safe_target only applies to false_positive payloads")
        return self


class PayloadRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    registry_version: str
    matrix_version: str | None = None
    compatibility_matrix: str | None = None
    payloads: list[PayloadDefinition]
    source_path: str | None = None
    registry_sha256: str | None = None

    @model_validator(mode="after")
    def _unique(self) -> "PayloadRegistry":
        if self.schema_version != "1.0":
            raise ValueError("payload registry schema_version must be 1.0")
        ids = [item.payload_id for item in self.payloads]
        if len(ids) != len(set(ids)):
            raise ValueError("payload_id values must be unique")
        if not self.payloads:
            raise ValueError("registry contains no payloads")
        return self

    # ---------------------------------------------------------- compatibility
    def validate_against(self, matrix) -> None:
        """Reject payloads whose declared surface exceeds the matrix."""
        for payload in self.payloads:
            entry = matrix.entry(payload.mechanism, payload.strategy_family)
            if entry is None:
                raise ConfigError(
                    "payload has no compatibility matrix entry",
                    details={
                        "payload_id": payload.payload_id,
                        "mechanism": payload.mechanism.value,
                        "strategy_family": payload.strategy_family,
                    },
                )
            extra_goals = set(payload.compatible_goals) - set(entry.supported_goals)
            if extra_goals:
                raise ConfigError(
                    "payload declares attack goals the matrix forbids",
                    details={
                        "payload_id": payload.payload_id,
                        "forbidden": sorted(goal.value for goal in extra_goals),
                        "allowed": [goal.value for goal in entry.supported_goals],
                    },
                )
            extra_carriers = set(payload.compatible_carriers) - {
                item.value for item in entry.carriers
            }
            if extra_carriers:
                raise ConfigError(
                    "payload declares carriers the matrix forbids",
                    details={
                        "payload_id": payload.payload_id,
                        "forbidden": sorted(extra_carriers),
                    },
                )
            if "*" not in entry.supported_languages:
                extra_languages = {
                    item for item in payload.supported_languages if item not in {"*"}
                } - set(entry.supported_languages)
                if extra_languages:
                    raise ConfigError(
                        "payload declares languages the matrix forbids",
                        details={
                            "payload_id": payload.payload_id,
                            "forbidden": sorted(extra_languages),
                        },
                    )
            if payload.required_safe_target and not entry.required_safe_target:
                raise ConfigError(
                    "payload requires a safe target but the matrix entry does not",
                    details={"payload_id": payload.payload_id},
                )
            if payload.required_validators and not entry.required_validators:
                raise ConfigError(
                    "payload requires validators but the matrix entry does not",
                    details={"payload_id": payload.payload_id},
                )

    # ------------------------------------------------------------------ select
    def select(
        self,
        *,
        strategy_family: str,
        goal: AttackGoal,
        carrier: str,
        mechanism: Mechanism | None = None,
        language: str | None = None,
    ) -> list[PayloadDefinition]:
        candidates = [
            payload
            for payload in self.payloads
            if payload.strategy_family == strategy_family
            and goal in payload.compatible_goals
            and carrier in payload.compatible_carriers
            and (mechanism is None or payload.mechanism == mechanism)
            and (
                language is None
                or "*" in payload.supported_languages
                or language.lower() in payload.supported_languages
            )
        ]
        return sorted(candidates, key=lambda item: item.payload_id)

    def filter_for_split(self, split: str) -> "PayloadRegistry":
        """Apply strategy-split visibility rules.

        Public payloads are always available.  Held-out strategies are only
        available to the held-out test split, never during development.
        """
        allowed = {"public_known"}
        if split == "test-heldout-strategy":
            allowed.add("heldout_strategy")
        if split.startswith("test-"):
            allowed.add("generated_variant")
        filtered = [item for item in self.payloads if item.strategy_split in allowed]
        if not filtered:
            raise ConfigError(
                "no payloads are visible for the requested split",
                details={"split": split, "allowed_splits": sorted(allowed)},
            )
        return self.model_copy(update={"payloads": filtered})

    def filter_for_mechanism(self, mechanism: Mechanism) -> "PayloadRegistry":
        filtered = [item for item in self.payloads if item.mechanism == mechanism]
        if not filtered:
            raise GenerationError(
                "no payloads are visible for the requested mechanism",
                details={"mechanism": mechanism.value},
            )
        return self.model_copy(update={"payloads": filtered})

    def select_one(
        self,
        *,
        strategy_family: str,
        goal: AttackGoal,
        carrier: str,
        mechanism: Mechanism | None = None,
        language: str | None = None,
    ) -> PayloadDefinition:
        candidates = self.select(
            strategy_family=strategy_family,
            goal=goal,
            carrier=carrier,
            mechanism=mechanism,
            language=language,
        )
        if not candidates:
            raise GenerationError(
                "no payload matches the requested strategy/goal/carrier",
                details={
                    "strategy_family": strategy_family,
                    "goal": goal.value,
                    "carrier": carrier,
                    "mechanism": mechanism.value if mechanism else None,
                    "language": language,
                    "available": [
                        {
                            "payload_id": item.payload_id,
                            "strategy_family": item.strategy_family,
                            "carriers": item.compatible_carriers,
                            "goals": [goal.value for goal in item.compatible_goals],
                        }
                        for item in self.payloads
                    ],
                },
            )
        return candidates[0]

    def render(
        self,
        payload: PayloadDefinition,
        context: GenerationContext,
        *,
        base_dir: Path,
        seed: int | None = None,
    ) -> tuple[str, PayloadProvenance]:
        backend = TemplateBackend(base_dir)
        try:
            text = backend.render(payload.template_file, context.model_dump(mode="json"))
        except Exception as exc:
            raise GenerationError(
                f"failed to render payload template {payload.template_file}: {exc}",
                details={"payload_id": payload.payload_id},
            ) from exc
        provenance = PayloadProvenance(
            payload_id=payload.payload_id,
            origin=payload.origin,
            source_title=payload.source_title,
            source_url=payload.source_url,
            source_license=payload.source_license,
            generator_name="vulnmirage.template_backend",
            generator_version=self.registry_version,
            prompt_sha256=sha256_text(payload.template_file),
            response_sha256=sha256_text(text),
            random_seed=seed,
            literature_sources=list(payload.literature_sources),
            adaptation=payload.adaptation,
        )
        return text, provenance


def load_payload_registry(
    path: Path, *, matrix_path: Path | None = None
) -> tuple[PayloadRegistry, Path]:
    path = Path(path)
    if not path.is_file():
        raise ConfigError("payload registry not found", details={"path": str(path)})
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid payload registry YAML: {exc}", details={"path": str(path)}) from exc
    if not isinstance(raw, dict):
        raise ConfigError("payload registry root must be a mapping")
    try:
        registry = PayloadRegistry.model_validate(raw)
    except Exception as exc:
        raise ConfigError(
            f"invalid payload registry: {exc}", details={"path": str(path)}
        ) from exc
    base_dir = path.parent
    for payload in registry.payloads:
        template = safe_join(base_dir, payload.template_file)
        if not template.is_file():
            raise ConfigError(
                "payload template file is missing",
                details={"payload_id": payload.payload_id, "template": str(template)},
            )
    if registry.compatibility_matrix:
        from .compatibility import load_compatibility_matrix

        matrix_file = (
            Path(matrix_path)
            if matrix_path is not None
            else safe_join(base_dir, registry.compatibility_matrix)
        )
        matrix = load_compatibility_matrix(matrix_file)
        if registry.matrix_version and registry.matrix_version != matrix.matrix_version:
            raise ConfigError(
                "payload registry and compatibility matrix versions disagree",
                details={
                    "registry_matrix_version": registry.matrix_version,
                    "matrix_version": matrix.matrix_version,
                },
            )
        registry.validate_against(matrix)
    registry = registry.model_copy(
        update={
            "source_path": str(path),
            "registry_sha256": sha256_file(path),
        }
    )
    return registry, base_dir


def registry_summary(registry: PayloadRegistry) -> dict[str, Any]:
    return {
        "schema_version": registry.schema_version,
        "registry_version": registry.registry_version,
        "matrix_version": registry.matrix_version,
        "registry_sha256": registry.registry_sha256,
        "payload_count": len(registry.payloads),
        "splits": sorted({item.strategy_split for item in registry.payloads}),
        "strategy_families": sorted({item.strategy_family for item in registry.payloads}),
        "mechanisms": sorted({item.mechanism.value for item in registry.payloads}),
        "presentations": sorted({item.presentation.value for item in registry.payloads}),
        "origins": sorted({item.origin.value for item in registry.payloads}),
    }
