"""Export the JSON Schemas of every data contract this build still produces.

Two groups:

* **answer contract** -- what an agent may return, and what the harness/verifier
  write about it (``finding``, ``audit_output``, ``agent_finding``, ``code_location``,
  ``output_consistency``, ``verifier_*``);
* **campaign contract** -- plan, per-task state, manifests, variants, isolation
  attestation, leakage controls and the mechanism artifacts.

Schemas are generated from the pydantic models, never hand-edited; ``vulnmirage
schemas`` rewrites them and reports the digest of each file.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .hashing import atomic_write_json
from .models import AgentFinding, AuditReportEnvelope, CodeLocation, FindingEnvelope

SCHEMA_FILES: dict[str, Any] = {
    "finding.schema.json": FindingEnvelope,
    "audit_output.schema.json": AuditReportEnvelope,
    "agent_finding.schema.json": AgentFinding,
    "code_location.schema.json": CodeLocation,
}


def benchmark_schema_files() -> dict[str, Any]:
    """Campaign-side contracts are imported lazily to keep CLI start-up cheap."""
    from .campaign.pipeline import (
        ArtifactEntry,
        RunRecord,
        SourceManifest,
        TaskManifest,
        VariantFreeze,
    )
    from .campaign.plan import (
        PlanDoc,
        PlanGeneration,
        PlanTask,
        PlanVariant,
        VariantSetDefinition,
    )
    from .campaign.state import TaskState
    from .campaign.variants import VariantBuild
    from .evaluation.aggregate import AggregateResult, PairedComparison
    from .evaluation.parser import OutputConsistency
    from .isolation.attestation import IsolationAttestation
    from .isolation.channels import LeakageControlReport
    from .isolation.network import EgressProbeResult
    from .mechanism.analysis import ComparisonReport, ExposureReport, MechanismReport
    from .payloadgen import (
        CandidatePayload,
        CandidateValidation,
        ConditionSpec,
        ExperimentCell,
        GenerationManifest,
        OracleAttackView,
        RepositoryIndex,
        TargetRemap,
    )
    from .payloadgen.catalog import PayloadCatalog, PayloadRealizationDefinition
    from .payloadgen.contracts import AdaptationQuery
    from .payloadgen.taxonomy import (
        AttackConditionIdentity,
        AttackMethod,
        RealizationDose,
        ThreatModel,
    )
    from .trace.models import (
        FileAccessRecord,
        NormalizedEvent,
        ToolCallRecord,
        TraceCompleteness,
        TraceManifest,
    )
    from .verifier.bundle import BundleManifest
    from .verifier.rubrics import RubricScoreReport, TargetRubric
    from .verifier.service import RunScore, VerifierAttestation
    from .verifier.targets import TargetSet
    from .verifier.untrusted import UntrustedInput

    return {
        "campaign_plan.schema.json": PlanDoc,
        "campaign_plan_task.schema.json": PlanTask,
        "campaign_plan_variant.schema.json": PlanVariant,
        "campaign_plan_generation.schema.json": PlanGeneration,
        "campaign_variant_set.schema.json": VariantSetDefinition,
        "campaign_state.schema.json": TaskState,
        "campaign_source_manifest.schema.json": SourceManifest,
        "campaign_task_manifest.schema.json": TaskManifest,
        "campaign_variant.schema.json": VariantBuild,
        "campaign_variants_frozen.schema.json": VariantFreeze,
        "campaign_run_record.schema.json": RunRecord,
        "campaign_artifact_entry.schema.json": ArtifactEntry,
        "condition_spec.schema.json": ConditionSpec,
        "experiment_cell.schema.json": ExperimentCell,
        "repository_index.schema.json": RepositoryIndex,
        "oracle_attack_view.schema.json": OracleAttackView,
        "candidate_payload.schema.json": CandidatePayload,
        "candidate_validation.schema.json": CandidateValidation,
        "generation_manifest.schema.json": GenerationManifest,
        "target_remap.schema.json": TargetRemap,
        "adaptation_query.schema.json": AdaptationQuery,
        "payload_catalog.schema.json": PayloadCatalog,
        "payload_attack_method.schema.json": AttackMethod,
        "payload_realization.schema.json": PayloadRealizationDefinition,
        "payload_realization_dose.schema.json": RealizationDose,
        "payload_threat_model.schema.json": ThreatModel,
        "attack_condition_identity.schema.json": AttackConditionIdentity,
        "aggregate_result.schema.json": AggregateResult,
        "paired_comparison.schema.json": PairedComparison,
        "isolation_attestation.schema.json": IsolationAttestation,
        "isolation_egress_probe.schema.json": EgressProbeResult,
        "leakage_controls.schema.json": LeakageControlReport,
        "verifier_bundle.schema.json": BundleManifest,
        "verifier_targets.schema.json": TargetSet,
        "verifier_target_rubric.schema.json": TargetRubric,
        "verifier_rubric_scores.schema.json": RubricScoreReport,
        "verifier_score.schema.json": RunScore,
        "verifier_attestation.schema.json": VerifierAttestation,
        "verifier_untrusted_input.schema.json": UntrustedInput,
        "output_consistency.schema.json": OutputConsistency,
        "exposure_report.schema.json": ExposureReport,
        "trajectory_comparison.schema.json": ComparisonReport,
        "mechanism_assessment.schema.json": MechanismReport,
        "trace_event.schema.json": NormalizedEvent,
        "trace_tool_call.schema.json": ToolCallRecord,
        "trace_file_access.schema.json": FileAccessRecord,
        "trace_manifest.schema.json": TraceManifest,
        "trace_completeness.schema.json": TraceCompleteness,
    }


def all_schema_files() -> dict[str, Any]:
    return {**SCHEMA_FILES, **benchmark_schema_files()}


def build_schema(model: Any, *, title: str | None = None) -> dict[str, Any]:
    schema = model.model_json_schema(ref_template="#/$defs/{model}")
    schema.setdefault("$schema", "https://json-schema.org/draft/2020-12/schema")
    schema["title"] = title or model.__name__
    return schema


def generate_schemas(output_dir: str | Path) -> dict[str, str]:
    """Write every schema and return ``filename -> sha256``."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    digests: dict[str, str] = {}
    for filename, model in all_schema_files().items():
        path = out / filename
        atomic_write_json(path, build_schema(model))
        digests[filename] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


def schema_index(output_dir: str | Path) -> dict[str, Any]:
    """Report which declared schemas exist and whether they are current."""
    out = Path(output_dir)
    files = all_schema_files()
    entries: dict[str, Any] = {}
    stale: list[str] = []
    missing: list[str] = []
    for filename, model in files.items():
        path = out / filename
        if not path.is_file():
            entries[filename] = {"exists": False, "sha256": None, "current": False}
            missing.append(filename)
            continue
        serialized = (
            json.dumps(build_schema(model), indent=2, sort_keys=True, ensure_ascii=False)
            + "\n"
        )
        expected = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        entries[filename] = {
            "exists": True,
            "sha256": actual,
            "current": actual == expected,
        }
        if actual != expected:
            stale.append(filename)
    return {
        "schema_version": "3.0",
        "directory": out.as_posix(),
        "count": len(files),
        "missing": missing,
        "stale": stale,
        "schemas": entries,
    }


def load_schema(name: str, directory: str | Path = "schemas") -> dict[str, Any]:
    path = Path(directory) / name
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


__all__ = [
    "SCHEMA_FILES",
    "all_schema_files",
    "benchmark_schema_files",
    "build_schema",
    "generate_schemas",
    "load_schema",
    "schema_index",
]
