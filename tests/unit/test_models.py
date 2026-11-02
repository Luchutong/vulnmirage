from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from tests.support import make_decoy, make_envelope, make_finding, make_instance, make_manipulation, make_oracle
from vulnmirage.models import (
    AgentFinding,
    BenchmarkInstance,
    CanonicalVulnerabilityOracle,
    ClaimGraph,
    ClaimNode,
    CodeLocation,
    ManipulationSpec,
    PayloadOrigin,
    PayloadProvenance,
    ValidationReport,
    ValidationResult,
    VariantKind,
)


def test_code_location_autohash_and_validation() -> None:
    loc = CodeLocation(file="./app/x.py", start_line=1, end_line=2, code="a = 1\n")
    assert loc.file == "app/x.py"
    assert loc.code_sha256 is not None
    with pytest.raises(ValidationError):
        CodeLocation(file="app/x.py", start_line=2, end_line=1)
    with pytest.raises(ValidationError):
        CodeLocation(file="/abs/x.py", start_line=1, end_line=1)
    with pytest.raises(ValidationError):
        CodeLocation(
            file="app/x.py",
            start_line=1,
            end_line=1,
            code="a = 1\n",
            code_sha256="0" * 64,
        )


def test_oracle_round_trip() -> None:
    oracle = make_oracle()
    payload = oracle.model_dump(mode="json")
    restored = CanonicalVulnerabilityOracle.model_validate(payload)
    assert restored == oracle
    assert restored.effective_difficulty.value == "D2"
    assert restored.affected_files() == ["app/http.py", "app/main.py", "app/storage.py"]


def test_oracle_rejects_duplicate_ids() -> None:
    oracle = make_oracle()
    payload = oracle.model_dump(mode="json")
    payload["vulnerabilities"].append(payload["vulnerabilities"][0])
    with pytest.raises(ValidationError):
        CanonicalVulnerabilityOracle.model_validate(payload)


def test_oracle_final_difficulty_requires_human_source() -> None:
    payload = make_oracle().model_dump(mode="json")
    payload["final_difficulty"] = "D3"
    payload["difficulty_source"] = "automatic"
    with pytest.raises(ValidationError):
        CanonicalVulnerabilityOracle.model_validate(payload)
    payload["difficulty_source"] = "human"
    assert CanonicalVulnerabilityOracle.model_validate(payload).effective_difficulty.value == "D3"


def test_extra_fields_forbidden() -> None:
    payload = make_finding().model_dump(mode="json")
    payload["unexpected"] = 1
    with pytest.raises(ValidationError):
        AgentFinding.model_validate(payload)


def test_finding_requires_locations() -> None:
    payload = make_finding().model_dump(mode="json")
    payload["locations"] = []
    with pytest.raises(ValidationError):
        AgentFinding.model_validate(payload)


def test_instance_clean_and_adversarial_constraints() -> None:
    clean = make_instance()
    assert clean.variant_kind == VariantKind.CLEAN
    payload = clean.model_dump(mode="json")
    payload["patch_file"] = "instances/VM-1/patch.diff"
    with pytest.raises(ValidationError):
        BenchmarkInstance.model_validate(payload)

    adversarial = make_instance(instance_id="VM-2", kind=VariantKind.ADVERSARIAL)
    assert adversarial.manipulation_tier.value == "M2"
    bad = adversarial.model_dump(mode="json")
    bad["patch_file"] = None
    with pytest.raises(ValidationError):
        BenchmarkInstance.model_validate(bad)
    bad = adversarial.model_dump(mode="json")
    bad["release_split"] = "production"
    with pytest.raises(ValidationError):
        BenchmarkInstance.model_validate(bad)


def test_manipulation_clean_spec_has_no_operators() -> None:
    spec = make_manipulation()
    payload = spec.model_dump(mode="json")
    payload["designed_tier"] = "M0"
    payload["operator_names"] = []
    payload["files_touched"] = []
    clean = ManipulationSpec.model_validate(payload)
    assert clean.designed_tier.value == "M0"
    payload["operator_names"] = ["X"]
    with pytest.raises(ValidationError):
        ManipulationSpec.model_validate(payload)


def test_published_payload_requires_license() -> None:
    with pytest.raises(ValidationError):
        PayloadProvenance(
            payload_id="p",
            origin=PayloadOrigin.PUBLISHED_VERBATIM,
            source_url="https://example.com",
        )
    provenance = PayloadProvenance(
        payload_id="p",
        origin=PayloadOrigin.PUBLISHED_VERBATIM,
        source_url="https://example.com",
        source_license="CC-BY-4.0",
    )
    assert provenance.source_license == "CC-BY-4.0"


def test_claim_graph_validates_edges() -> None:
    node = ClaimNode(node_id="n1", file="SECURITY.md", line=1, claim="fixed", carrier="markdown")
    second = ClaimNode(
        node_id="n2", file="docs/arch.md", line=3, claim="guard", carrier="markdown"
    )
    graph = ClaimGraph(
        nodes=[node, second],
        edges=[{"source": "n1", "target": "n2", "relation": "supports"}],
    )
    assert len(graph.nodes) == 2
    with pytest.raises(ValidationError):
        ClaimGraph(
            nodes=[node, second],
            edges=[{"source": "n1", "target": "missing"}],
        )
    with pytest.raises(ValidationError):
        ClaimGraph(nodes=[node, second])


def test_decoy_requires_validator() -> None:
    decoy = make_decoy()
    assert decoy.verified_safe is True
    payload = decoy.model_dump(mode="json")
    payload["safety_validator_commands"] = []
    with pytest.raises(ValidationError):
        from vulnmirage.models import DecoyRecord

        DecoyRecord.model_validate(payload)


def test_validation_report_digest() -> None:
    report = ValidationReport(
        instance_id="VM-1",
        results=[
            ValidationResult(
                check_name="schema",
                status="pass",
                started_at="2026-01-01T00:00:00Z",
                duration_seconds=0.1,
            )
        ],
        ground_truth_preserved=True,
        release_eligible=True,
        validation_level="trace_grounded",
    )
    digest = report.compute_sha256()
    stamped = report.with_digest()
    assert len(digest) == 64
    assert stamped.report_sha256 == digest
    assert stamped.compute_sha256() == digest


def test_envelope_round_trip() -> None:
    envelope = make_envelope()
    data = envelope.model_dump(mode="json")
    assert json.loads(json.dumps(data))["schema_version"] == "1.0"
    assert envelope.findings[0].severity.value == "high"
