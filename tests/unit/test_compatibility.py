"""Compatibility matrix: incompatible payload/goal combinations are rejected."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnmirage.errors import GenerationError
from vulnmirage.generation.compatibility import (
    CompatibilityError,
    load_compatibility_matrix,
)
from vulnmirage.generation.payload_registry import load_payload_registry
from vulnmirage.models import AttackGoal, Carrier, Mechanism


@pytest.fixture(scope="module")
def matrix(project_root: Path):
    return load_compatibility_matrix(project_root / "payloads" / "compatibility.yaml")


def test_safe_decoy_is_not_a_false_negative_attack(matrix) -> None:
    assert (
        matrix.supports(
            mechanism=Mechanism.SAFE_DECOY,
            strategy_family="safe_decoy",
            carrier=Carrier.STRING_LITERAL,
            goal=AttackGoal.FALSE_NEGATIVE,
        )
        is False
    )
    with pytest.raises(CompatibilityError):
        matrix.require(
            mechanism=Mechanism.SAFE_DECOY,
            strategy_family="safe_decoy",
            carrier=Carrier.STRING_LITERAL,
            goal=AttackGoal.FALSE_NEGATIVE,
        )


def test_representation_helper_cannot_claim_false_positive_or_severity(matrix) -> None:
    for goal in (
        AttackGoal.FALSE_POSITIVE,
        AttackGoal.SEVERITY_INFLATION,
        AttackGoal.SEVERITY_DOWNGRADE,
    ):
        assert not matrix.supports(
            mechanism=Mechanism.REPRESENTATION_CONFUSION,
            strategy_family="representation_helper",
            carrier=Carrier.STRING_LITERAL,
            goal=goal,
        )


def test_false_positive_requires_a_validated_safe_target(matrix) -> None:
    with pytest.raises(CompatibilityError) as excinfo:
        matrix.check_binding(
            mechanism=Mechanism.DIRECT_INSTRUCTION,
            strategy_family="direct_string",
            goal=AttackGoal.FALSE_POSITIVE,
            has_validated_safe_target=False,
            has_safe_decoy=False,
            has_severity=True,
            has_validators=False,
            carrier=Carrier.STRING_LITERAL,
            language="python",
        )
    assert excinfo.value.details.get("reason") == "no_validated_safe_target"
    matrix.check_binding(
        mechanism=Mechanism.DIRECT_INSTRUCTION,
        strategy_family="direct_string",
        goal=AttackGoal.FALSE_POSITIVE,
        has_validated_safe_target=True,
        has_safe_decoy=False,
        has_severity=True,
        has_validators=True,
        carrier=Carrier.STRING_LITERAL,
        language="python",
    )


def test_severity_goals_require_oracle_severity(matrix) -> None:
    with pytest.raises(CompatibilityError) as excinfo:
        matrix.check_binding(
            mechanism=Mechanism.SEMANTIC_MISINFORMATION,
            strategy_family="severity_anchor",
            goal=AttackGoal.SEVERITY_INFLATION,
            has_validated_safe_target=False,
            has_safe_decoy=False,
            has_severity=False,
            has_validators=False,
            carrier=Carrier.MARKDOWN,
            language="python",
        )
    assert excinfo.value.details.get("reason") == "severity_missing"


def test_language_restrictions_are_enforced(matrix) -> None:
    assert not matrix.supports(
        mechanism=Mechanism.REPRESENTATION_CONFUSION,
        strategy_family="representation_helper",
        carrier=Carrier.STRING_LITERAL,
        goal=AttackGoal.FALSE_NEGATIVE,
        language="javascript",
    )


def test_registry_has_direction_specific_severity_payloads(project_root: Path) -> None:
    registry, _ = load_payload_registry(project_root / "payloads" / "registry.yaml")
    inflation = registry.select(
        strategy_family="severity_anchor",
        goal=AttackGoal.SEVERITY_INFLATION,
        carrier=Carrier.MARKDOWN.value,
    )
    downgrade = registry.select(
        strategy_family="severity_anchor",
        goal=AttackGoal.SEVERITY_DOWNGRADE,
        carrier=Carrier.MARKDOWN.value,
    )
    assert {item.payload_id for item in inflation} != {item.payload_id for item in downgrade}
    assert all(
        item.compatible_goals == [AttackGoal.SEVERITY_INFLATION] for item in inflation
    )
    assert all(
        item.compatible_goals == [AttackGoal.SEVERITY_DOWNGRADE] for item in downgrade
    )


def test_registry_rejects_matrix_violation(project_root: Path, tmp_path: Path) -> None:
    source = (project_root / "payloads" / "registry.yaml").read_text(encoding="utf-8")
    # Claim that the representation helper also creates false positives.
    tampered = source.replace(
        "    compatible_goals: [false_negative, evidence_corruption, verification_diversion]\n"
        "    compatible_carriers: [string_literal]",
        "    compatible_goals: [false_negative, false_positive, evidence_corruption, verification_diversion]\n"
        "    compatible_carriers: [string_literal]",
        1,
    )
    assert tampered != source
    path = tmp_path / "registry.yaml"
    path.write_text(tampered, encoding="utf-8")
    import shutil

    shutil.copytree(project_root / "payloads" / "templates", tmp_path / "templates")
    shutil.copy2(
        project_root / "payloads" / "compatibility.yaml",
        tmp_path / "compatibility.yaml",
    )
    with pytest.raises(Exception) as excinfo:
        load_payload_registry(path)
    assert "compatibility" in str(excinfo.value).lower() or "forbid" in str(excinfo.value).lower()


def test_generation_error_type_is_shared() -> None:
    assert issubclass(CompatibilityError, GenerationError)
