"""Export and validate publishable JSON Schemas for all data contracts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .hashing import atomic_write_json
from .models import (
    AgentFinding,
    AgentRun,
    AttackPlan,
    BaselineAuditContext,
    BenchmarkInstance,
    CandidateFile,
    CandidateSelfCheck,
    CanonicalVulnerabilityOracle,
    DecoyRecord,
    EditApplication,
    EvaluationEligibility,
    EvidenceContract,
    EvidenceExpression,
    EvidencePredicate,
    FindingEnvelope,
    GeneratedCandidate,
    InstanceGroup,
    ManipulationSpec,
    PatchOperation,
    PredicateResult,
    ReferenceAudit,
    RepositoryContext,
    RepositoryFacts,
    SafeTargetContract,
    SeverityRecord,
    SeveritySource,
    UnifiedEvent,
    ValidationReport,
    VariantGroup,
    VerificationAssessment,
)

SCHEMA_FILES: dict[str, Any] = {
    "oracle.schema.json": CanonicalVulnerabilityOracle,
    "manipulation.schema.json": ManipulationSpec,
    "decoy.schema.json": DecoyRecord,
    "validation.schema.json": ValidationReport,
    "finding.schema.json": FindingEnvelope,
    "agent_finding.schema.json": AgentFinding,
    "run.schema.json": AgentRun,
    "instance.schema.json": BenchmarkInstance,
    "instance_group.schema.json": InstanceGroup,
    "variant_group.schema.json": VariantGroup,
    "event.schema.json": UnifiedEvent,
    "evidence_contract.schema.json": EvidenceContract,
    "evidence_expression.schema.json": EvidenceExpression,
    "evidence_predicate.schema.json": EvidencePredicate,
    "predicate_result.schema.json": PredicateResult,
    "verification_assessment.schema.json": VerificationAssessment,
    "safe_target.schema.json": SafeTargetContract,
    "evaluation_eligibility.schema.json": EvaluationEligibility,
    "severity.schema.json": SeverityRecord,
    "severity_source.schema.json": SeveritySource,
    "attack_plan.schema.json": AttackPlan,
    "repository_context.schema.json": RepositoryContext,
    "generated_candidate.schema.json": GeneratedCandidate,
    "candidate_file.schema.json": CandidateFile,
    "candidate_self_check.schema.json": CandidateSelfCheck,
    "repository_facts.schema.json": RepositoryFacts,
    "reference_audit.schema.json": ReferenceAudit,
    "baseline_audit_context.schema.json": BaselineAuditContext,
    "patch_operation.schema.json": PatchOperation,
    "edit_application.schema.json": EditApplication,
}


def dataset_schema_files() -> dict[str, Any]:
    """Dataset adapter models are imported lazily to avoid import cycles."""
    from .ingest.adapter import (
        DatasetCapabilities,
        DatasetInspection,
        DatasetIssue,
        NormalizationResult,
    )
    from .ingest.vulnmirage_dataset import DatasetManifest

    return {
        "dataset_manifest.schema.json": DatasetManifest,
        "dataset_capabilities.schema.json": DatasetCapabilities,
        "dataset_issues.schema.json": DatasetIssue,
        "dataset_inspection.schema.json": DatasetInspection,
        "dataset_normalization.schema.json": NormalizationResult,
    }


def build_schema(model: Any, *, title: str | None = None) -> dict[str, Any]:
    schema = model.model_json_schema(ref_template="#/$defs/{model}")
    schema.setdefault("$schema", "https://json-schema.org/draft/2020-12/schema")
    schema["title"] = title or model.__name__
    return schema


def generate_schemas(output_dir: str | Path) -> dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    digests: dict[str, str] = {}
    import hashlib

    files = {**SCHEMA_FILES, **dataset_schema_files()}
    for filename, model in files.items():
        schema = build_schema(model)
        path = out / filename
        atomic_write_json(path, schema)
        digests[filename] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


def schema_index(output_dir: str | Path) -> dict[str, Any]:
    out = Path(output_dir)
    entries = {}
    files = {**SCHEMA_FILES, **dataset_schema_files()}
    for filename in files:
        path = out / filename
        entries[filename] = {
            "exists": path.exists(),
            "sha256": __import__("hashlib").sha256(path.read_bytes()).hexdigest() if path.exists() else None,
        }
    return {"schema_version": "2.0", "directory": str(out), "schemas": entries}


def load_schema(name: str, directory: str | Path = "schemas") -> dict[str, Any]:
    path = Path(directory) / name
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))
