"""``vulnmirage inspect`` implementations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import LoadedConfig
from .errors import ValidationError as VMValidationError
from .hashing import sha256_file
from .models import (
    BenchmarkInstance,
    CanonicalVulnerabilityOracle,
    EnrichedTrajectoryEvent,
    ManipulationSpec,
    VerificationAssessment,
)
from .store import InstanceState, InstanceStore


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _instance_summary(store: InstanceStore, instance_id: str, directory: Path) -> dict[str, Any]:
    instance = BenchmarkInstance.model_validate(_read_json(directory / "instance.json"))
    state = InstanceState.model_validate(_read_json(directory / "state.json"))
    oracle = CanonicalVulnerabilityOracle.model_validate(_read_json(directory / "oracle.json"))
    manipulation = (
        ManipulationSpec.model_validate(_read_json(directory / "manipulation.json"))
        if (directory / "manipulation.json").is_file()
        else None
    )
    validation = (
        _read_json(directory / "validation.json")
        if (directory / "validation.json").is_file()
        else None
    )
    contract = (
        _read_json(directory / "evidence_contract.json")
        if (directory / "evidence_contract.json").is_file()
        else None
    )
    return {
        "instance": instance.model_dump(mode="json"),
        "state": state.model_dump(mode="json"),
        "oracle": {
            "oracle_id": oracle.oracle_id,
            "vulnerability_count": len(oracle.vulnerabilities),
            "suggested_difficulty": oracle.suggested_difficulty.value,
            "validation_level": oracle.validation_level,
            "source_dataset": oracle.source_dataset,
            "hidden_metadata_keys": sorted(oracle.hidden_metadata),
        },
        "manipulation": manipulation.model_dump(mode="json") if manipulation else None,
        "evidence_contract": {
            "claim_count": len(contract.get("claims", [])) if contract else 0,
            "contract_sha256": contract.get("contract_sha256") if contract else None,
        },
        "validation": (
            {
                "release_eligible": validation.get("release_eligible"),
                "ground_truth_preserved": validation.get("ground_truth_preserved"),
                "validation_level": validation.get("validation_level"),
                "report_sha256": validation.get("report_sha256"),
                "checks": {
                    item["check_name"]: item["status"]
                    for item in validation.get("results", [])
                },
            }
            if validation
            else None
        ),
        "files": {
            path.name: {"size": path.stat().st_size, "sha256": sha256_file(path)}
            for path in sorted(directory.iterdir())
            if path.is_file()
        },
        "repo": str(store.repo_dir(instance_id)),
    }


def inspect_generation(loaded: LoadedConfig, instance_id: str) -> dict[str, Any]:
    """Inspect the plan → facts → request → edits → diff chain of one instance."""
    store = InstanceStore(loaded.paths)
    directory = store.instance_dir(instance_id)
    if not directory.is_dir():
        raise VMValidationError(
            "instance not found", details={"instance_id": instance_id}
        )
    payload: dict[str, Any] = {"ok": True, "kind": "generation", "instance_id": instance_id}
    for name, key in (
        ("plan_intent.json", "plan_intent"),
        ("attack_plan.json", "attack_plan"),
        ("repository_facts.json", "repository_facts"),
        ("generator_request.json", "generator_request"),
        ("edit_operations.json", "edit_operations"),
        ("handles.json", "handles"),
        ("safe_targets.json", "safe_targets"),
        ("patch_meta.json", "patch_meta"),
        ("operator_local_checks.json", "operator_local_checks"),
        ("validation.json", "validation"),
    ):
        path = directory / name
        if path.is_file():
            payload[key] = _read_json(path)
            payload.setdefault("artifact_hashes", {})[name] = sha256_file(path)
        else:
            payload.setdefault("missing", []).append(name)
    patch = store.patch_path(instance_id)
    if patch.is_file():
        payload["patch_sha256"] = sha256_file(patch)
        payload["patch_preview"] = patch.read_text(encoding="utf-8", errors="replace")[:4000]
    return payload


def inspect_instance(loaded: LoadedConfig, instance_id: str) -> dict[str, Any]:
    store = InstanceStore(loaded.paths)
    if store.exists(instance_id):
        return {
            "ok": True,
            "kind": "instance",
            **_instance_summary(store, instance_id, store.instance_dir(instance_id)),
        }
    quarantine = loaded.paths.quarantine / instance_id
    if quarantine.is_dir() and (quarantine / "instance.json").is_file():
        summary = _instance_summary(store, instance_id, quarantine)
        return {"ok": True, "kind": "quarantined_instance", **summary}
    raise VMValidationError("instance not found", details={"instance_id": instance_id})


def inspect_pair(loaded: LoadedConfig, pair_id: str) -> dict[str, Any]:
    store = InstanceStore(loaded.paths)
    instances = store.pair_instances(pair_id)
    if not instances:
        raise VMValidationError("pair not found", details={"pair_id": pair_id})
    clean = next((item for item in instances if item.variant_kind.value == "clean"), None)
    if clean is None:
        raise VMValidationError("pair has no clean instance", details={"pair_id": pair_id})
    variants = []
    for item in instances:
        if item.instance_id == clean.instance_id:
            continue
        state = store.load_state(item.instance_id)
        manipulation = store.load_manipulation(item.instance_id)
        variants.append(
            {
                "instance": item.model_dump(mode="json"),
                "stage": state.stage,
                "release_eligible": state.release_eligible,
                "attack_goal": manipulation.attack_goal.value if manipulation else None,
                "operator_names": manipulation.operator_names if manipulation else [],
                "files_touched": manipulation.files_touched if manipulation else [],
            }
        )
    return {
        "ok": True,
        "kind": "pair",
        "pair_id": pair_id,
        "clean": clean.model_dump(mode="json"),
        "adversarial": variants,
        "adversarial_count": len(variants),
    }


def _run_dir(loaded: LoadedConfig, run_id: str) -> Path:
    run_dir = loaded.paths.run_dir(run_id)
    if not run_dir.is_dir():
        raise VMValidationError("run not found", details={"run_id": run_id, "run_dir": str(run_dir)})
    return run_dir


def inspect_run(loaded: LoadedConfig, run_id: str) -> dict[str, Any]:
    run_dir = _run_dir(loaded, run_id)
    payload: dict[str, Any] = {"ok": True, "kind": "run", "run_id": run_id, "run_dir": str(run_dir)}
    for name in (
        "run.json",
        "meta.json",
        "run_meta.json",
        "parsed.json",
        "trace_summary.json",
        "parse_error.json",
        "run_error.json",
        "metrics.json",
        "matches.json",
    ):
        path = run_dir / name
        if path.is_file():
            payload[name.removesuffix(".json")] = _read_json(path)
    for name in (
        "stdout.log",
        "stderr.log",
        "final_raw.txt",
        "findings_raw.txt",
        "trace.jsonl",
        "events.raw.jsonl",
        "events.normalized.jsonl",
        "tool_calls.jsonl",
        "file_access.jsonl",
        "process_events.jsonl",
        "trajectory_enriched.jsonl",
        "verification_assessments.json",
    ):
        path = run_dir / name
        if path.is_file():
            payload.setdefault("logs", {})[name] = {
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
    return payload


def inspect_trajectory(loaded: LoadedConfig, run_id: str) -> dict[str, Any]:
    run_dir = _run_dir(loaded, run_id)
    path = run_dir / "trajectory_enriched.jsonl"
    if not path.is_file():
        raise VMValidationError("trajectory_enriched.jsonl is missing", details={"run_id": run_id})
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            events.append(EnrichedTrajectoryEvent.model_validate(json.loads(line)).model_dump(mode="json"))
        except Exception:
            continue
    return {
        "ok": True,
        "kind": "trajectory",
        "run_id": run_id,
        "event_count": len(events),
        "stages": sorted({item["stage"] for item in events}),
        "events": events,
    }


def inspect_verification(loaded: LoadedConfig, run_id: str) -> dict[str, Any]:
    run_dir = _run_dir(loaded, run_id)
    path = run_dir / "verification_assessments.json"
    if not path.is_file():
        raise VMValidationError(
            "verification_assessments.json is missing", details={"run_id": run_id}
        )
    payload = _read_json(path)
    assessments = [VerificationAssessment.model_validate(item) for item in payload]
    return {
        "ok": True,
        "kind": "verification",
        "run_id": run_id,
        "assessment_count": len(assessments),
        "assessments": [item.model_dump(mode="json") for item in assessments],
    }


def validate_run_artifacts_command(
    loaded: LoadedConfig,
    run_id: str,
    *,
    check_event_order: bool = True,
    check_artifact_hashes: bool = True,
    check_parent_links: bool = True,
) -> dict[str, Any]:
    from .harness.artifacts import validate_manifest
    from .harness.observation.validate import validate_run_artifacts

    run_dir = _run_dir(loaded, run_id)
    result = validate_run_artifacts(
        run_dir,
        check_event_order=check_event_order,
        check_artifact_hashes=check_artifact_hashes,
        check_parent_links=check_parent_links,
    )
    manifest = validate_manifest(run_dir)
    errors = [*result.get("errors", []), *manifest.get("errors", [])]
    warnings = [*result.get("notes", []), *manifest.get("warnings", [])]
    result.update(
        {
            "ok": bool(result.get("ok")) and bool(manifest.get("ok")),
            "errors": errors,
            "notes": warnings,
            "artifact_manifest": manifest,
        }
    )
    result["run_id"] = run_id
    result["kind"] = "run_validation"
    return result
