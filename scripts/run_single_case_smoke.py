#!/usr/bin/env python3
"""Single-case smoke test for VulnMirage (P1-3).

Two explicit modes:

``offline``
    Evaluate an existing release + runs directory (local fixture / dummy agent)
    and emit a machine-readable summary.  This proves the plumbing, *not* a real
    attack effect.

``live``
    Run ONE adversarial case (with its C/B/A/T controls) through a configured
    real agent, then evaluate it.  Requires user-provided credentials and an
    installed OpenCode/agent executable.  This is the only mode that can produce
    live agent evidence; it is never part of the default pytest run.

No secret is read or written by this script.  Credentials reach the agent only
through the environment variables allowlisted in the agent YAML.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

SMOKE_SUMMARY_SCHEMA = "1.0"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_csv(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _truth(value: Any) -> bool | None:
    if value in {"true", "True", True}:
        return True
    if value in {"false", "False", False}:
        return False
    return None


def select_case(
    rows: list[dict[str, Any]], preferred_instance: str | None = None
) -> dict[str, Any]:
    """Pick one attack case deterministically (first by id, not by success)."""
    if not rows:
        raise SystemExit("no paired rows found; nothing to summarise")
    ordered = sorted(
        rows, key=lambda row: (row.get("adversarial_instance_id") or "", row.get("repetition") or "")
    )
    if preferred_instance:
        for row in ordered:
            if row.get("adversarial_instance_id") == preferred_instance:
                return row
        raise SystemExit(f"instance {preferred_instance!r} is not in the paired rows")
    return ordered[0]


def _find_instance_entry(release: dict[str, Any], instance_id: str | None) -> dict[str, Any] | None:
    for entry in release.get("instances", []):
        if entry.get("instance_id") == instance_id:
            return entry
    return None


def _find_run_row(runs: list[dict[str, Any]], run_id: str | None) -> dict[str, Any] | None:
    for run in runs:
        if run.get("run_id") == run_id:
            return run
    return None


def _effective_identity(run: dict[str, Any]) -> dict[str, Any]:
    condition = run.get("execution_condition") or {}
    model = condition.get("model") or {}
    scaffold = condition.get("scaffold") or {}
    prompt = condition.get("prompt") or {}
    return {
        "prompt_sha256": run.get("prompt_sha256"),
        "base_prompt_sha256": prompt.get("base_sha256"),
        "defense_instructions_sha256": prompt.get("defense_sha256"),
        "effective_prompt_sha256": prompt.get("effective_sha256"),
        "agent_config_sha256": condition.get("agent_config_sha256"),
        "external_file_sha256": condition.get("external_file_sha256"),
        "model_provider": run.get("model_provider") or model.get("provider"),
        "model_name": run.get("model_name") or model.get("name"),
        "model_version": run.get("model_version") or model.get("version"),
        "scaffold": run.get("scaffold") or scaffold.get("name"),
        "scaffold_version": run.get("scaffold_version") or scaffold.get("version"),
        "defense_id": run.get("defense_id"),
        "defense_version": run.get("defense_version"),
        "condition_id": run.get("condition_id"),
        "condition_source": run.get("condition_source"),
        "execution_condition": condition,
    }


def build_summary(
    *,
    mode: str,
    loaded_config,
    release_dir: Path,
    runs_dir: Path,
    evaluation_dir: Path,
    preferred_instance: str | None = None,
    live_requests: list[dict[str, Any]] | None = None,
    required_repetitions: int = 1,
) -> dict[str, Any]:
    from vulnmirage.evaluation.live_verification import assess_live_verification

    release = _read_json(release_dir / "release.json")
    rows = _read_csv(evaluation_dir / "pair_metrics.csv")
    row = select_case(rows, preferred_instance)
    runs = [
        json.loads(line)
        for line in (evaluation_dir / "runs.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    findings = _read_csv(evaluation_dir / "instance_metrics.csv")
    failures = _read_csv(evaluation_dir / "failures.csv")
    summary_path = evaluation_dir / "summary.json"
    evaluation_summary = _read_json(summary_path) if summary_path.is_file() else {}
    case_rows = [
        item
        for item in rows
        if item.get("adversarial_instance_id") == row.get("adversarial_instance_id")
    ]
    verification = assess_live_verification(
        requested_mode=mode,
        runs=runs,
        instance_rows=findings,
        pair_rows=case_rows,
        required_repetitions=required_repetitions,
        case_instance_id=row.get("adversarial_instance_id"),
    )
    instance_ids = {
        "clean": row.get("clean_instance_id") or None,
        "adversarial": row.get("adversarial_instance_id") or None,
        "benign": row.get("benign_instance_id") or None,
        "truthful_security": row.get("truthful_security_instance_id") or None,
    }
    run_ids = {
        "clean": row.get("clean_run_id") or None,
        "adversarial": row.get("adv_run_id") or None,
        "benign": row.get("benign_run_id") or None,
        "truthful_security": row.get("truthful_run_id") or None,
    }
    entries = {
        kind: _find_instance_entry(release, instance_id)
        for kind, instance_id in instance_ids.items()
    }
    adv_run = _find_run_row(runs, run_ids["adversarial"])
    clean_run = _find_run_row(runs, run_ids["clean"])
    def _json_value(value: Any) -> Any:
        if isinstance(value, str) and value[:1] in {"[", "{"}:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return value

    target_metrics = {
        key: _json_value(row.get(key))
        for key in (
            "target_kind",
            "target_status",
            "bound_target_id",
            "eligible_target_ids",
            "adv_target_found",
            "target_path_count",
            "target_path_coverage",
            "fn_attack_success",
            "fp_attack_success",
            "severity_attack_success",
            "severity_attack_evaluable",
            "severity_missing_reason",
        )
    }
    pair_identity = {
        key: row.get(key)
        for key in (
            "release_id",
            "condition_id",
            "condition_source",
            "condition_complete",
            "clean_condition_id",
            "benign_condition_id",
            "truthful_condition_id",
            "model",
            "model_version",
            "scaffold",
            "scaffold_version",
            "defense_id",
            "defense_version",
            "repetition",
            "adv_attempt",
            "adv_attempt_rule",
            "clean_attempt",
            "clean_attempt_rule",
            "adv_attempt_ambiguous",
            "clean_attempt_ambiguous",
            "benign_attempt_ambiguous",
            "truthful_attempt_ambiguous",
            "pairing_status",
            "pairing_source",
            "clean_pair_status",
            "benign_pair_status",
            "truthful_pair_status",
            "formal_eligible",
        )
    }
    not_evaluable = {
        "clean_missing_reason": row.get("clean_missing_reason") or None,
        "benign_missing_reason": row.get("benign_missing_reason") or None,
        "truthful_missing_reason": row.get("truthful_missing_reason") or None,
        "target_missing_reason": row.get("target_missing_reason") or None,
        "adv_target_missing_reason": row.get("adv_target_missing_reason") or None,
        "precision_not_evaluable_reason": row.get("precision_not_evaluable_reason") or None,
        "observability_coverage": _json_value(row.get("observability_coverage")) or None,
        "exposure_unknown_reason": row.get("exposure_unknown_reason") or None,
        "pairing_status": row.get("pairing_status") or None,
    }
    repetition = evaluation_summary.get("repetition_statistics") or {}
    exposure = evaluation_summary.get("exposure") or {}
    summary = {
        "schema_version": SMOKE_SUMMARY_SCHEMA,
        "mode": mode,
        "live_verified": verification.live_verified,
        "dummy_or_fixture_only": not verification.live_verified,
        "live_verification": verification.as_dict(),
        "warning": (
            None
            if verification.live_verified
            else "Offline/dummy/fixture result. This is NOT a real attack-effect measurement."
        ),
        "release_dir": str(release_dir.resolve()),
        "runs_dir": str(runs_dir.resolve()),
        "evaluation_dir": str(evaluation_dir.resolve()),
        "config": {
            "source": str(loaded_config.source),
            "sha256": loaded_config.sha256,
            "defense_default": loaded_config.config.defense.default,
            "configured_repetitions": loaded_config.config.experiment.repetitions,
            "minimum_valid_repetitions": loaded_config.config.experiment.minimum_valid_repetitions,
            "retry_policy": loaded_config.config.experiment.retry_policy.model_dump(mode="json"),
            "required_repetitions": required_repetitions,
        },
        "case": {
            "pair_id": row.get("pair_id"),
            "instance_ids": instance_ids,
            "run_ids": run_ids,
            "target_binding": target_metrics,
            "pair_identity": pair_identity,
            "repetitions_in_case": len(case_rows),
            "patch_files": {
                kind: (entry or {}).get("patch_file") for kind, entry in entries.items()
            },
            "validation_level": {
                kind: ((entry or {}).get("validation_file")) for kind, entry in entries.items()
            },
        },
        "effective": _effective_identity(adv_run or {}),
        "artifacts": {
            "raw_adversarial_output": (adv_run or {}).get("final_raw_path"),
            "raw_events": (adv_run or {}).get("raw_events_path"),
            "normalized_events": (adv_run or {}).get("normalized_events_path"),
            "tool_calls": (adv_run or {}).get("tool_calls_path"),
            "file_access": (adv_run or {}).get("file_access_path"),
            "clean_raw_output": (clean_run or {}).get("final_raw_path"),
            "report_pair_metrics": str((evaluation_dir / "pair_metrics.csv").resolve()),
            "report_instance_metrics": str((evaluation_dir / "instance_metrics.csv").resolve()),
            "report_summary": str(summary_path.resolve()),
            "repetition_metrics": str((evaluation_dir / "repetition_metrics.csv").resolve()),
            "defense_matrix": str((evaluation_dir / "defense_matrix.csv").resolve()),
        },
        "target_matching": target_metrics,
        "metrics": {
            "clean_target_found": _truth(row.get("clean_target_found")),
            "adv_target_found": _truth(row.get("adv_target_found")),
            "fn_attack_success": _truth(row.get("fn_attack_success")),
            "fp_attack_success": _truth(row.get("fp_attack_success")),
            "attack_success": _truth(row.get("attack_success")),
            "manipulation_exposed": _truth(row.get("manipulation_exposed")),
            "observability_grade": row.get("adv_observability_grade"),
        },
        "attempt_selection": {
            "adversarial": {
                "attempt": row.get("adv_attempt"),
                "rule": row.get("adv_attempt_rule"),
                "ambiguous": _truth(row.get("adv_attempt_ambiguous")),
                "count": row.get("adv_attempt_count"),
            },
            "clean": {
                "attempt": row.get("clean_attempt"),
                "rule": row.get("clean_attempt_rule"),
                "ambiguous": _truth(row.get("clean_attempt_ambiguous")),
            },
            "benign": {
                "attempt": row.get("benign_attempt"),
                "ambiguous": _truth(row.get("benign_attempt_ambiguous")),
            },
            "truthful": {
                "attempt": row.get("truthful_attempt"),
                "ambiguous": _truth(row.get("truthful_attempt_ambiguous")),
            },
        },
        "repetition_probabilities": {
            "configured_repetitions": repetition.get("configured_repetitions"),
            "observed_repetitions": (repetition.get("per_target") or [{}])[0].get(
                "observed_repetitions"
            )
            if repetition.get("per_target")
            else None,
            "stability_status": repetition.get("stability_status"),
            "micro": repetition.get("micro"),
            "macro": repetition.get("macro"),
            "per_target": repetition.get("per_target"),
        },
        "exposure": exposure,
        "not_evaluable": not_evaluable,
        "failures": failures,
        "run_status": {
            "clean": (clean_run or {}).get("status"),
            "adversarial": (adv_run or {}).get("status"),
        },
        "live_requests": live_requests or [],
    }
    return summary


def _write_summary(path: Path, summary: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def run_offline(args: argparse.Namespace) -> dict[str, Any]:
    from vulnmirage.config import load_config
    from vulnmirage.evaluation.report import evaluate_release

    loaded = load_config(args.config)
    release_dir = Path(args.release)
    runs_dir = Path(args.runs)
    evaluation_dir = Path(args.output) / "evaluation"
    evaluate_release(
        loaded=loaded,
        release_dir=release_dir,
        runs_dir=runs_dir,
        output_dir=evaluation_dir,
        matching_profile=args.matching_profile,
    )
    summary = build_summary(
        mode="offline",
        loaded_config=loaded,
        release_dir=release_dir,
        runs_dir=runs_dir,
        evaluation_dir=evaluation_dir,
        preferred_instance=args.instance,
        required_repetitions=_expected_repetitions(args, loaded),
    )
    path = _write_summary(Path(args.output) / "smoke_summary.json", summary)
    summary["smoke_summary"] = str(path)
    return summary


def _expected_repetitions(args: argparse.Namespace, loaded) -> int:
    return int(
        getattr(args, "repetition", None)
        or getattr(args, "repetitions", None)
        or loaded.config.experiment.repetitions
    )


def _resolve_release(args: argparse.Namespace) -> Path:
    if args.release:
        return Path(args.release)
    ingest_index = Path(args.ingest_dir) / "index.json"
    if not ingest_index.is_file():
        raise SystemExit(
            "live mode needs --release (prebuilt single-target release) or "
            "--ingest-dir with index.json"
        )
    index = _read_json(ingest_index)
    if not index.get("imported"):
        raise SystemExit("ingest index contains no imported oracle")
    oracle_file = index["imported"][0]["file"]
    print(f"resolved oracle from ingest index: {oracle_file}", file=sys.stderr)
    raise SystemExit(
        "materialize/generate/export is intentionally explicit; pass the exported "
        "--release path after running those commands (see README)"
    )


def _isolated_config(args: argparse.Namespace, output: Path):
    """Derive a config whose workspace lives under the smoke output."""
    import yaml

    from vulnmirage.config import load_config

    raw = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    raw = dict(raw or {})
    raw["workspace_root"] = str((output / "workspace").resolve())
    raw["repo_cache"] = str((output / "workspace" / "cache" / "repos").resolve())
    path = output / "smoke_config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=True), encoding="utf-8")
    return load_config(path)


def run_live(args: argparse.Namespace) -> dict[str, Any]:
    from vulnmirage.evaluation.report import evaluate_release
    from vulnmirage.harness.runner import run_release

    release_dir = _resolve_release(args)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    loaded = _isolated_config(args, output)
    # run_release writes to the configured workspace runs dir; use a dedicated
    # workspace copy so a smoke test does not pollute a formal experiment.
    instance_ids = [args.instance] if args.instance else None
    repetitions = int(
        getattr(args, "repetition", None)
        or getattr(args, "repetitions", None)
        or loaded.config.experiment.repetitions
    )
    run_result = run_release(
        loaded=loaded,
        release_dir=release_dir,
        agent_config_path=Path(args.agent),
        repetitions=repetitions,
        workers=1,
        instance_ids=instance_ids,
        limit=1 if instance_ids is None else None,
        resume=args.resume,
        defense_id=args.defense,
    )
    evaluation_dir = output / "evaluation"
    evaluate_release(
        loaded=loaded,
        release_dir=release_dir,
        runs_dir=loaded.paths.runs,
        output_dir=evaluation_dir,
        matching_profile=args.matching_profile,
    )
    summary = build_summary(
        mode="live",
        loaded_config=loaded,
        release_dir=release_dir,
        runs_dir=loaded.paths.runs,
        evaluation_dir=evaluation_dir,
        preferred_instance=args.instance,
        required_repetitions=_expected_repetitions(args, loaded),
        live_requests=[
            {
                "release_id": run_result.get("release_id"),
                "condition_id": run_result.get("condition_id"),
                "defense": run_result.get("defense"),
                "run_count": run_result.get("run_count"),
                "repetitions": run_result.get("repetitions"),
                "repetitions_source": run_result.get("repetitions_source"),
                "credential_status": run_result.get("credential_status"),
                "failures": run_result.get("failures"),
                "runs_dir": str(loaded.paths.runs),
                "experiment_manifest": run_result.get("experiment_manifest"),
                "isolated_output": str(output),
            }
        ],
    )
    path = _write_summary(output / "smoke_summary.json", summary)
    summary["smoke_summary"] = str(path)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    def common(item: argparse.ArgumentParser) -> None:
        item.add_argument("--config", required=True, help="application config YAML")
        item.add_argument("--release", default=None, help="exported release directory")
        item.add_argument("--output", required=True, help="smoke output directory")
        item.add_argument("--instance", default=None, help="adversarial instance id")
        item.add_argument(
            "--matching-profile", choices=["strict", "relaxed"], default="strict"
        )
        item.add_argument(
            "--repetitions",
            type=int,
            default=None,
            help="expected repetitions of the cell (default: experiment.repetitions)",
        )

    offline = sub.add_parser("offline", help="evaluate existing fixture/dummy runs")
    common(offline)
    offline.add_argument(
        "--runs", required=True, help="existing runs directory (fixture/dummy output)"
    )
    offline.set_defaults(func=run_offline)

    live = sub.add_parser("live", help="run one real agent case (explicit, not default pytest)")
    common(live)
    live.add_argument("--agent", required=True, help="agent config YAML")
    live.add_argument("--defense", default=None, help="defense condition id (default config)")
    live.add_argument("--repetition", type=int, default=None)
    live.add_argument("--resume", action="store_true")
    live.add_argument(
        "--ingest-dir",
        default=None,
        help="ingest output directory (used to resolve the exact oracle id)",
    )
    live.set_defaults(func=run_live)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = args.func(args)
    verification = summary.get("live_verification") or {}
    print(
        json.dumps(
            {
                "mode": summary["mode"],
                "live_verified": summary["live_verified"],
                "real_agent_invoked": verification.get("real_agent_invoked"),
                "outputs_parseable": verification.get("outputs_parseable"),
                "pairing_evaluable": verification.get("pairing_evaluable"),
                "completed_repetitions": verification.get("completed_repetitions"),
                "failed_repetitions": verification.get("failed_repetitions"),
                "attack_success_rate": verification.get("attack_success_rate"),
                "smoke_summary": summary["smoke_summary"],
            },
            indent=2,
        )
    )
    if summary["mode"] == "live" and not summary["live_verified"]:
        # A live request that does not meet the pre-declared evidence bar is a
        # failed run, not a "completed" smoke test.
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
