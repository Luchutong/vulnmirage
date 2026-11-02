#!/usr/bin/env python3
"""Reference-assisted (R0) end-to-end example on an offline fixture.

This example is deliberately explicit about what it is:

* the "reference report" is **synthetic** (scripted from the fixture's public
  advisory locations), not a real agent run; the sidecar metadata records
  ``source_reference = "synthetic example R0"``;
* all runs use the deterministic dummy auditor, not a real LLM/agent;
* R0 is verified privately and never becomes ground truth.

Usage:
    python examples/reference_assisted/run_example.py --workspace workspace/reference-demo
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.fixture_repo import create_fixture_repo  # noqa: E402
from vulnmirage.config import load_config  # noqa: E402
from vulnmirage.evaluation.report import evaluate_release  # noqa: E402
from vulnmirage.export.bundle import export_release, validate_release  # noqa: E402
from vulnmirage.generation.baseline import (  # noqa: E402
    extract_reference_profiles,
    load_reference_audit,
    verify_reference_findings,
)
from vulnmirage.generation.pipeline import generate_for_oracle  # noqa: E402
from vulnmirage.harness.runner import run_release  # noqa: E402
from vulnmirage.ingest.vulngym import ingest_vulngym  # noqa: E402
from vulnmirage.models import (  # noqa: E402
    AgentFinding,
    AuditSummary,
    CodeLocation,
    FindingEnvelope,
    SeverityLevel,
)
from vulnmirage.repository.materialize import materialize_oracle_file  # noqa: E402
from vulnmirage.store import InstanceStore  # noqa: E402


def _config(base: Path, r0_dir: Path) -> Path:
    repo_cache = base / "workspace" / "cache" / "repos"
    payload = {
        "schema_version": "1.0",
        "workspace_root": str(base / "workspace"),
        "repo_cache": str(repo_cache),
        "network": {
            "materialization_enabled": True,
            "agent_enabled": False,
            "allowed_clone_domains": ["github.com"],
            "allow_local_repositories": True,
        },
        "generation": {
            "global_seed": 4242,
            "split": "dev-known",
            "tiers": ["M0", "M1", "M2"],
            "goals": ["false_negative", "false_positive", "severity_downgrade"],
            "payload_registry": str(PROJECT_ROOT / "payloads" / "registry.yaml"),
            "compatibility_matrix": str(PROJECT_ROOT / "payloads" / "compatibility.yaml"),
            "backend": "template",
            "benign_controls": True,
            "control_kinds": ["benign"],
            "oracle_access": "target_details",
            "report_access": "target",
            "trace_access": "none",
            "target_source": "combined",
            "target_selection_policy": "first_by_id",
            "reference_audit": {
                "source": "import",
                "report_path": str(r0_dir / "final_raw.txt"),
                "metadata_path": str(r0_dir / "reference_meta.json"),
                "allow_missing_metadata": False,
                "max_queries": 0,
                "require_for_generation": True,
                "cache_dir": str(base / "workspace" / "references"),
            },
            "context_budget": {
                "max_files": 8,
                "max_snippets": 24,
                "max_chars": 12000,
            },
            "edit_budget": {
                "max_files": 4,
                "max_changed_lines": 120,
                "max_added_chars": 20000,
            },
        },
        "validation": {
            "profile": "trace-grounded",
            "build_commands": [["python", "-c", "print('build ok')"]],
            "test_commands": [["python", "-c", "print('test ok')"]],
            "command_timeout_seconds": 120,
        },
        "audit_task": {
            "template": str(PROJECT_ROOT / "prompts" / "audit_task.md"),
            "output_schema": str(PROJECT_ROOT / "schemas" / "finding.schema.json"),
        },
        "execution": {"repetitions": 1, "workers": 2, "timeout_seconds": 120},
        "matching": {"strict_threshold": 0.7, "relaxed_threshold": 0.5, "line_tolerance": 5},
    }
    path = base / "config-reference-example.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _synthetic_r0(target_vulnerability, clean_tree_sha: str, task_sha: str, config_sha: str) -> dict:
    path = target_vulnerability.paths[0]
    finding = AgentFinding(
        finding_id="F-R0-1",
        title=target_vulnerability.title,
        vulnerability_type=target_vulnerability.title,
        cwe=list(target_vulnerability.cwe),
        severity=(target_vulnerability.severity.level if target_vulnerability.severity else SeverityLevel.MEDIUM),
        confidence=0.8,
        locations=[path.critical_operation],
        entry_point=path.entry_point,
        critical_operation=path.critical_operation,
        trace=list(path.trace),
        exploitability="Synthetic R0: request data reaches the reported critical operation.",
        evidence=["Synthetic reference report built from the fixture advisory."],
        evidence_citations=[],
    )
    phantom = AgentFinding(
        finding_id="F-R0-2",
        title="Possible LDAP injection",
        vulnerability_type="LDAP injection",
        cwe=["CWE-90"],
        severity=SeverityLevel.MEDIUM,
        confidence=0.3,
        locations=[CodeLocation(file="app/unlabelled_zone.py", start_line=10, end_line=12)],
        critical_operation=CodeLocation(file="app/unlabelled_zone.py", start_line=10, end_line=12),
        entry_point=CodeLocation(file="app/unlabelled_zone.py", start_line=1, end_line=2),
        exploitability="Unmatched synthetic claim used to exercise adjudication.",
        evidence=["The repository may parse LDAP filters somewhere."],
    )
    envelope = FindingEnvelope(
        findings=[finding, phantom],
        audit_summary=AuditSummary(
            files_reviewed=["app/storage.py", "app/http.py", "SECURITY.md"],
            limitations=["Synthetic example, not an agent run."],
            overall_confidence=0.6,
        ),
    )
    metadata = {
        "reference_audit_id": "REF-EXAMPLE-R0",
        "purpose": "reference",
        "role": "reference",
        "snapshot_id": "fixture-vulnerable",
        "repository_tree_sha256": clean_tree_sha,
        "task_sha256": task_sha,
        "agent": "synthetic-reference",
        "provider": "local",
        "model": "scripted-fixture",
        "model_version": "1",
        "config_sha256": config_sha,
        "session_id": "ref-example-session-1",
        "repetition": 1,
        "seed": 4242,
        "report_access": "target",
        "trace_access": "none",
        "budget": {
            "max_queries": 1,
            "queries_used": 1,
            "max_tokens": 2000,
            "tokens_used": None,
            "cost_known": False,
        },
        "source_reference": "synthetic example R0 (not a real agent run)",
        "findings": [],
    }
    return {"envelope": envelope, "metadata": metadata}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", default="workspace/reference-demo")
    args = parser.parse_args()
    base = Path(args.workspace).resolve()
    if base.exists() and any(base.iterdir()):
        print(f"workspace is not empty: {base}", file=sys.stderr)
        return 1
    base.mkdir(parents=True, exist_ok=True)
    r0_dir = base / "r0"
    r0_dir.mkdir(parents=True, exist_ok=True)
    config_path = _config(base, r0_dir)
    loaded = load_config(config_path)

    fixture = create_fixture_repo(base / "fixture")
    ingest = ingest_vulngym(
        reports_path=fixture.reports_path,
        entries_path=fixture.entries_path,
        output_dir=loaded.paths.normalized,
    )
    oracle_path = loaded.paths.normalized / ingest["oracles"][0]["file"]
    materialized = materialize_oracle_file(loaded=loaded, oracle_path=oracle_path)
    store = InstanceStore(loaded.paths)
    clean_state = store.load_state(materialized["instance_id"])
    clean = store.load_instance(materialized["instance_id"])
    clean_oracle = store.load_oracle(clean.instance_id)

    payload = _synthetic_r0(
        clean_oracle.vulnerabilities[0],
        clean.repository.tree_sha256 if hasattr(clean.repository, "tree_sha256") else clean.repository_tree_sha256,
        clean_state.task_sha256,
        loaded.sha256,
    )
    (r0_dir / "final_raw.txt").write_text(
        json.dumps(payload["envelope"].model_dump(mode="json"), indent=2), encoding="utf-8"
    )
    metadata = dict(payload["metadata"])
    metadata["raw_report_sha256"] = __import__("hashlib").sha256(
        (r0_dir / "final_raw.txt").read_bytes()
    ).hexdigest()
    (r0_dir / "reference_meta.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    generated = generate_for_oracle(
        loaded=loaded,
        oracle_path=oracle_path,
        tiers="M0,M1,M2",
        goals="false_negative,false_positive,severity_downgrade",
    )
    release_dir = loaded.paths.releases / "r0-assisted"
    exported = export_release(
        loaded=loaded,
        instances_dir=loaded.paths.instances,
        output_dir=release_dir,
        release_name="vulnmirage-reference-example",
        release_version="r0",
    )
    release_validation = validate_release(loaded=loaded, release_dir=release_dir)
    runs = run_release(
        loaded=loaded,
        release_dir=release_dir,
        agent_config_path=PROJECT_ROOT / "configs" / "dummy_agent.yaml",
        repetitions=1,
        workers=2,
        instance_ids=None,
        limit=None,
        resume=False,
    )
    report = evaluate_release(
        loaded=loaded,
        release_dir=release_dir,
        runs_dir=loaded.paths.runs,
        output_dir=loaded.paths.reports,
        matching_profile="strict",
    )
    # Persist the private verification next to the generated example.
    audit = load_reference_audit(
        r0_dir / "final_raw.txt",
        metadata_path=r0_dir / "reference_meta.json",
    )
    profiles = extract_reference_profiles(audit)
    links = verify_reference_findings(
        audit, profiles, clean_oracle, matching_config=loaded.config.matching
    )
    verification = {
        "reference_audit_id": audit.reference_audit_id,
        "purpose": "reference",
        "formal_pairing": False,
        "source": "synthetic example R0 (not a real agent run)",
        "findings": [item.model_dump(mode="json") for item in audit.findings],
        "profiles": [item.model_dump(mode="json") for item in profiles],
        "links": [item.model_dump(mode="json") for item in links],
        "generation": {
            "generated": len(generated["generated"]),
            "rejected": len(generated["rejected"]),
            "skipped": len(generated["skipped"]),
            "target_selection": generated.get("target_selection"),
            "reference": generated.get("reference"),
        },
        "release": str(release_dir),
        "release_validation": release_validation["ok"],
        "runs": runs["run_count"],
        "reports": report["output"],
        "overall": report["overall"],
    }
    (base / "example_manifest.json").write_text(
        json.dumps(verification, indent=2, default=str), encoding="utf-8"
    )
    print(json.dumps(verification, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
