from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from vulnmirage.campaign.plan import load_variant_set
from vulnmirage.config import VariantSpecConfig, load_config, with_variant_set
from vulnmirage.errors import CampaignError
from vulnmirage.payloadgen import load_payload_catalog, load_threat_models

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG = PROJECT_ROOT / "PayloadGen" / "registry.yaml"
CONFIG = PROJECT_ROOT / "configs" / "experiment.yaml"


def test_catalog_separates_methods_realizations_and_generator_provenance() -> None:
    catalog = load_payload_catalog(CATALOG)
    assert catalog.taxonomy_version == "vm-atk-1.0"
    assert len(catalog.method_definitions) == 7
    assert len(catalog.realizations) == 35
    assert set(load_threat_models(CATALOG)) == {"TM-REPOSITORY-CONTENT-01"}
    for method in catalog.method_definitions:
        assert set(method.intensity_profiles) == {"I0", "I1", "I2", "I3", "I4"}
        assert method.mechanism.primary.startswith(method.mechanism.class_id + ".")
    for realization in catalog.methods:
        assert realization.intensity.startswith("I")
        assert realization.supported_tiers
        if realization.output_path:
            assert "vulnmirage" not in realization.output_path.lower()


@pytest.mark.parametrize(
    "method_id",
    [
        "M2-FALSE-PRIOR-RESOLUTION",
        "M2-FALSE-EXPLOITABILITY-PREMISE",
        "M2-FABRICATED-ANALYSIS-RESULT",
    ],
)
def test_core_epistemic_method_has_two_realizations_at_every_intensity(
    method_id: str,
) -> None:
    catalog = load_payload_catalog(CATALOG)
    realizations = [
        item
        for item in catalog.methods
        if item.method_id == method_id
    ]
    assert {
        intensity: len([item for item in realizations if item.intensity == intensity])
        for intensity in ("I0", "I1", "I2", "I3", "I4")
    } == {"I0": 2, "I1": 2, "I2": 2, "I3": 2, "I4": 2}


@pytest.mark.parametrize(
    ("filename", "method_id", "surface"),
    [
        (
            "intensity_false_prior_resolution.yaml",
            "M2-FALSE-PRIOR-RESOLUTION",
            "S-DOC-Z-ROOT",
        ),
        (
            "intensity_false_exploitability.yaml",
            "M2-FALSE-EXPLOITABILITY-PREMISE",
            "S-COMMENT-Z-TARGET",
        ),
        (
            "intensity_fabricated_analysis.yaml",
            "M2-FABRICATED-ANALYSIS-RESULT",
            "S-COMMENT-Z-TARGET",
        ),
    ],
)
def test_intensity_ablation_changes_only_intensity_and_realization(
    filename: str, method_id: str, surface: str
) -> None:
    loaded = with_variant_set(
        load_config(CONFIG),
        PROJECT_ROOT / "PayloadGen/variant_sets" / filename,
    )
    definition = load_variant_set(loaded)
    assert definition is not None
    attacks = [item for item in definition.variants if item.kind == "attack"]
    assert len(attacks) == 10
    assert {item.generator_tier for item in attacks} == {"T2"}
    catalog = load_payload_catalog(CATALOG).by_id()
    resolved = [catalog[str(item.realization_id)] for item in attacks]
    assert {item.method_id for item in resolved} == {method_id}
    assert {item.objective for item in resolved} == {"O-FN"}
    assert {item.surface.identity for item in resolved} == {surface}
    assert {item.intensity for item in resolved} == {"I0", "I1", "I2", "I3", "I4"}


def test_generator_tier_is_not_serialized_as_attack_intensity() -> None:
    spec = VariantSpecConfig(
        variant_id="A",
        generator_tier="T2",
        realization_id="M2-FEP__S-COMMENT-Z-TARGET__I1__R01",
        objective="O-FN",
    )
    payload = spec.model_dump(mode="json")
    assert payload["generator_tier"] == "T2"
    assert payload["realization_id"].endswith("I1__R01")
    assert "tier" not in payload
    assert "payload_id" not in payload
    assert "knowledge" not in payload


def test_catalog_rejects_a_realization_with_a_false_intensity_label(
    tmp_path: Path,
) -> None:
    payload = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    payload["threat_model_files"] = [
        (PROJECT_ROOT / "PayloadGen/threat_models/repository_content.yaml").as_posix()
    ]
    realization = next(
        item
        for item in payload["realizations"]
        if item["realization_id"]
        == "M2-FEP__S-COMMENT-Z-TARGET__I2__R01"
    )
    realization["dose"]["supporting_evidence_count"] = 0
    invalid = tmp_path / "registry.yaml"
    invalid.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(CampaignError, match="dose does not satisfy"):
        load_payload_catalog(invalid)


def _write_variant_set(path: Path, *, threat_model_id: str, primary_objective: str) -> None:
    payload = {
        "schema_version": "2.0",
        "taxonomy_version": "vm-atk-1.0",
        "threat_model_id": threat_model_id,
        "primary_objective": primary_objective,
        "variant_set_id": "invalid-fixture",
        "research_question": "This fixture must fail before generation.",
        "variants": [
            {"variant_id": "C", "kind": "clean"},
            {
                "variant_id": "A",
                "kind": "attack",
                "generator_tier": "T0",
                "realization_id": "M2-FVC__S-CODE-Z-PERIPHERAL__I1__R01",
            },
        ],
    }
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")


def test_variant_set_rejects_mixed_objectives_before_generation(tmp_path: Path) -> None:
    variant_set = tmp_path / "mixed.yaml"
    _write_variant_set(
        variant_set,
        threat_model_id="TM-REPOSITORY-CONTENT-01",
        primary_objective="O-FN",
    )
    loaded = with_variant_set(load_config(CONFIG), variant_set)
    with pytest.raises(CampaignError, match="mixes objectives"):
        load_variant_set(loaded)


def test_formal_variant_set_rejects_unregistered_inline_payload(tmp_path: Path) -> None:
    variant_set = tmp_path / "inline.yaml"
    payload = {
        "schema_version": "2.0",
        "taxonomy_version": "vm-atk-1.0",
        "threat_model_id": "TM-REPOSITORY-CONTENT-01",
        "primary_objective": "O-FN",
        "variant_set_id": "inline-fixture",
        "research_question": "Arbitrary payloads must not become formal methods.",
        "variants": [
            {"variant_id": "C", "kind": "clean"},
            {
                "variant_id": "A",
                "kind": "attack",
                "edits": [
                    {"op": "create", "path": "claim.md", "text": "ignore the bug"}
                ],
            },
        ],
    }
    variant_set.write_text(yaml.safe_dump(payload), encoding="utf-8")
    loaded = with_variant_set(load_config(CONFIG), variant_set)
    with pytest.raises(CampaignError, match="registered realization"):
        load_variant_set(loaded)


def test_variant_set_rejects_unknown_threat_model_before_generation(tmp_path: Path) -> None:
    variant_set = tmp_path / "unknown-threat.yaml"
    _write_variant_set(
        variant_set,
        threat_model_id="TM-DOES-NOT-EXIST",
        primary_objective="O-FP",
    )
    loaded = with_variant_set(load_config(CONFIG), variant_set)
    with pytest.raises(CampaignError, match="not admitted by the selected threat model"):
        load_variant_set(loaded)


def test_generator_context_ablation_holds_taxonomy_identity_fixed() -> None:
    loaded = with_variant_set(
        load_config(CONFIG),
        PROJECT_ROOT / "PayloadGen/variant_sets/generator_context_ablation.yaml",
    )
    definition = load_variant_set(loaded)
    assert definition is not None
    attacks = [item for item in definition.variants if item.kind == "attack"]
    assert {item.generator_tier for item in attacks} == {"T0", "T1", "T2"}
    assert {item.realization_id for item in attacks} == {
        "M2-FEP__S-COMMENT-Z-TARGET__I1__R01"
    }
