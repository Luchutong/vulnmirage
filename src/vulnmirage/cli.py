"""VulnMirage command-line interface.

All commands return machine-readable JSON on stdout and use a non-zero exit
code on failure.  Human-readable diagnostics are emitted as structured JSON
logs on stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import Any

from . import __version__
from .config import LoadedConfig, load_config
from .errors import VulnMirageError
from .logging import configure_logging, get_logger, redact as redact_json
from .paths import project_root

_LOG = get_logger("cli")


def default_config_path() -> Path:
    local = Path.cwd() / "configs" / "default.yaml"
    if local.exists():
        return local
    return project_root() / "configs" / "default.yaml"


def _emit(payload: Any) -> None:
    print(json.dumps(redact_json(payload), indent=2, ensure_ascii=False, default=str))


def _load_config(path: str | None) -> LoadedConfig:
    source = Path(path) if path else default_config_path()
    return load_config(source)


def cmd_doctor(args: argparse.Namespace) -> dict[str, Any]:
    from .diagnostics import run_doctor

    loaded = _load_config(args.config)
    return run_doctor(loaded, agent_path=args.agent)


def cmd_schemas(args: argparse.Namespace) -> dict[str, Any]:
    from .schemas import generate_schemas, schema_index

    output = Path(args.output)
    if not output.is_absolute():
        output = (Path.cwd() / output).resolve()
    digests = generate_schemas(output)
    return {"ok": True, "output": str(output), "schemas": digests, **schema_index(output)}


def cmd_ingest_vulngym(args: argparse.Namespace) -> dict[str, Any]:
    from .ingest.vulngym import ingest_vulngym

    return ingest_vulngym(
        reports_path=Path(args.reports),
        entries_path=Path(args.entries),
        output_dir=Path(args.output),
        allow_unverified=args.allow_unverified,
        limit=args.limit,
        dataset_name=args.dataset_name,
    )


def cmd_ingest_generic(args: argparse.Namespace) -> dict[str, Any]:
    from .ingest.generic_jsonl import ingest_generic_jsonl

    return ingest_generic_jsonl(
        input_path=Path(args.input),
        output_dir=Path(args.output),
        source_dataset=args.dataset_name,
        allow_unverified=args.allow_unverified,
        limit=args.limit,
    )


def cmd_ingest_repovuln(args: argparse.Namespace) -> dict[str, Any]:
    from .ingest.repovuln import ingest_repovuln_xlsx

    return ingest_repovuln_xlsx(
        workbook_path=Path(args.workbook),
        output_dir=Path(args.output),
        sheet=args.sheet,
        data_scope=args.data_scope,
        limit_groups=args.limit_groups,
        dataset_name=args.dataset_name,
    )


def cmd_ingest_vulnmirage(args: argparse.Namespace) -> dict[str, Any]:
    from .ingest.vulnmirage_dataset import (
        VulnMirageDatasetAdapter,
        ingest_vulnmirage_dataset,
    )

    if args.inspect_only:
        adapter = VulnMirageDatasetAdapter(
            Path(args.manifest), Path(args.cases), dataset_name=args.dataset_name
        )
        inspection = adapter.inspect()
        return {
            "ok": not any(issue.blocking for issue in inspection.issues),
            "inspect_only": True,
            **inspection.model_dump(mode="json"),
        }
    if not args.output:
        from .errors import ConfigError

        raise ConfigError("ingest vulnmirage requires --output unless --inspect-only is used")
    return ingest_vulnmirage_dataset(
        manifest_path=Path(args.manifest),
        cases_path=Path(args.cases),
        output_dir=Path(args.output),
        dataset_name=args.dataset_name,
        limit=args.limit,
        strict=not args.allow_invalid,
    )


def cmd_optimize_payloads(args: argparse.Namespace) -> dict[str, Any]:
    from .generation.feedback import optimize_payloads

    loaded = _load_config(args.config)
    return optimize_payloads(
        loaded=loaded,
        release_dir=Path(args.release),
        agent_config_path=Path(args.agent),
        generations=args.generations,
        population=args.population,
        output_path=Path(args.output),
        seed=args.seed,
        max_queries=args.max_queries,
        max_llm_calls=args.max_llm_calls,
        token_budget=args.token_budget,
        rewrite_enabled=args.rewrite,
    )


def cmd_reference_verify(args: argparse.Namespace) -> dict[str, Any]:
    from .generation.baseline import verify_reference_report

    loaded = _load_config(args.config)
    return verify_reference_report(
        loaded=loaded,
        oracle_path=Path(args.oracle),
        report_path=Path(args.report),
        metadata_path=Path(args.metadata) if args.metadata else None,
        output_dir=Path(args.output) if args.output else None,
    )


def cmd_materialize(args: argparse.Namespace) -> dict[str, Any]:
    from .repository.materialize import materialize_oracle_file

    loaded = _load_config(args.config)
    return materialize_oracle_file(
        loaded=loaded,
        oracle_path=Path(args.oracle),
        force=args.force,
        repo_override=args.repo_url,
        fetch=args.fetch,
    )


def cmd_generate(args: argparse.Namespace) -> dict[str, Any]:
    from .generation.candidates import generate_candidates_for_oracle
    from .generation.pipeline import generate_for_oracle

    loaded = _load_config(args.config)
    candidates = args.candidates
    if candidates is None:
        candidates = loaded.config.generation.candidates_per_strategy
    # Multi-target oracles are never collapsed to one silently: the candidate
    # driver iterates single-target variants unless the caller names a target.
    if not args.target_vulnerability_id:
        return generate_candidates_for_oracle(
            loaded=loaded,
            oracle_path=Path(args.oracle),
            tiers=args.tiers,
            goals=args.goals,
            seed=args.seed,
            force=args.force,
            resume=args.resume,
            split=args.split,
            max_variants=args.max_variants,
            candidates_per_strategy=max(1, candidates or 1),
            deduplication_threshold=args.dedup_threshold,
            target_vulnerability_ids=args.target_vulnerability_ids,
        )
    if candidates and candidates > 1:
        return generate_candidates_for_oracle(
            loaded=loaded,
            oracle_path=Path(args.oracle),
            tiers=args.tiers,
            goals=args.goals,
            seed=args.seed,
            force=args.force,
            resume=args.resume,
            split=args.split,
            max_variants=args.max_variants,
            candidates_per_strategy=candidates,
            deduplication_threshold=args.dedup_threshold,
            target_vulnerability_id=args.target_vulnerability_id,
        )
    return generate_for_oracle(
        loaded=loaded,
        oracle_path=Path(args.oracle),
        tiers=args.tiers,
        goals=args.goals,
        seed=args.seed,
        force=args.force,
        resume=args.resume,
        split=args.split,
        max_variants=args.max_variants,
        candidate_index=0,
        target_vulnerability_id=args.target_vulnerability_id,
    )


def cmd_validate(args: argparse.Namespace) -> dict[str, Any]:
    from .validation.pipeline import validate_instance

    loaded = _load_config(args.config)
    return validate_instance(
        loaded=loaded,
        instance_id=args.instance,
        profile=args.profile,
        clean_instance_id=args.clean_instance,
    )


def cmd_export(args: argparse.Namespace) -> dict[str, Any]:
    from .export.bundle import export_release

    loaded = _load_config(args.config)
    instances = Path(args.instances) if args.instances else loaded.paths.instances
    output = Path(args.output) if args.output else loaded.paths.releases / "v0.1"
    return export_release(
        loaded=loaded,
        instances_dir=instances,
        output_dir=output,
        only_release_eligible=not args.include_rejected,
        release_name=args.name,
        release_version=args.release_version,
        use_selection_manifest=not args.all_instances,
    )


def cmd_run(args: argparse.Namespace) -> dict[str, Any]:
    from .harness.runner import run_release

    loaded = _load_config(args.config)
    return run_release(
        loaded=loaded,
        release_dir=Path(args.release),
        agent_config_path=Path(args.agent),
        repetitions=args.repetitions,
        workers=args.workers,
        instance_ids=args.instance,
        limit=args.limit,
        resume=args.resume,
        defense_id=getattr(args, "defense", None),
    )


def cmd_run_matrix(args: argparse.Namespace) -> dict[str, Any]:
    from .harness.runner import run_experiment_matrix

    loaded = _load_config(args.config)
    return run_experiment_matrix(
        loaded=loaded,
        release_dir=Path(args.release),
        agent_config_paths=[Path(item) for item in args.agent],
        defense_ids=args.defense,
        repetitions=args.repetitions,
        workers=args.workers,
        instance_ids=args.instance,
        limit=args.limit,
        resume=args.resume,
    )


def cmd_evaluate(args: argparse.Namespace) -> dict[str, Any]:
    from .evaluation.report import evaluate_release

    loaded = _load_config(args.config)
    return evaluate_release(
        loaded=loaded,
        release_dir=Path(args.release),
        runs_dir=Path(args.runs),
        output_dir=Path(args.output),
        matching_profile=args.matching_profile,
    )


def cmd_inspect(args: argparse.Namespace) -> dict[str, Any]:
    from .inspect import (
        inspect_instance,
        inspect_pair,
        inspect_run,
        inspect_trajectory,
        inspect_verification,
    )

    loaded = _load_config(args.config)
    if args.kind == "instance":
        return inspect_instance(loaded, args.identifier)
    if args.kind == "pair":
        return inspect_pair(loaded, args.identifier)
    if args.kind == "generation":
        from .inspect import inspect_generation

        return inspect_generation(loaded, args.identifier)
    if args.kind == "trajectory":
        return inspect_trajectory(loaded, args.identifier)
    if args.kind == "verification":
        return inspect_verification(loaded, args.identifier)
    return inspect_run(loaded, args.identifier)


def cmd_validate_run(args: argparse.Namespace) -> dict[str, Any]:
    from .inspect import validate_run_artifacts_command

    loaded = _load_config(args.config)
    return validate_run_artifacts_command(
        loaded,
        args.run,
        check_event_order=not args.skip_event_order,
        check_artifact_hashes=not args.skip_artifact_hashes,
        check_parent_links=not args.skip_parent_links,
    )


def cmd_validate_release(args: argparse.Namespace) -> dict[str, Any]:
    from .export.bundle import validate_release

    loaded = _load_config(args.config)
    return validate_release(
        loaded=loaded,
        release_dir=Path(args.release),
        rebuild=args.rebuild,
        rebuild_dir=Path(args.rebuild_dir) if args.rebuild_dir else None,
    )


def cmd_repair_output(args: argparse.Namespace) -> dict[str, Any]:
    from .evaluation.repair import repair_output_file

    return repair_output_file(
        raw_path=Path(args.raw),
        output_path=Path(args.output),
        repo_root=Path(args.repo_root) if args.repo_root else None,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnmirage",
        description="VulnMirage adversarial repository-manipulation benchmark",
    )
    parser.add_argument("--version", action="version", version=f"vulnmirage {__version__}")
    parser.add_argument(
        "--env-file",
        default=None,
        help=(
            "load local credentials from this .env file (default: ./.env or the "
            "project .env; existing environment variables win)"
        ),
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="errors only")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="check the local environment")
    doctor.add_argument("--config", help="application config YAML")
    doctor.add_argument("--agent", help="optional agent config YAML")
    doctor.set_defaults(func=cmd_doctor)

    schemas = sub.add_parser("schemas", help="regenerate JSON Schemas")
    schemas.add_argument("--output", default="schemas")
    schemas.set_defaults(func=cmd_schemas)

    ingest = sub.add_parser("ingest", help="import dataset records")
    ingest_sub = ingest.add_subparsers(dest="ingest_kind", required=True)
    vg = ingest_sub.add_parser("vulngym", help="import VulnGym reports.jsonl + entries.jsonl")
    vg.add_argument("--reports", required=True)
    vg.add_argument("--entries", required=True)
    vg.add_argument("--output", required=True)
    vg.add_argument("--allow-unverified", action="store_true")
    vg.add_argument("--limit", type=int, default=None)
    vg.add_argument("--dataset-name", default="vulngym")
    vg.set_defaults(func=cmd_ingest_vulngym)

    generic = ingest_sub.add_parser("generic-jsonl", help="import a normalized generic JSONL file")
    generic.add_argument("--input", required=True)
    generic.add_argument("--output", required=True)
    generic.add_argument("--allow-unverified", action="store_true")
    generic.add_argument("--limit", type=int, default=None)
    generic.add_argument("--dataset-name", default="generic")
    generic.set_defaults(func=cmd_ingest_generic)

    rv = ingest_sub.add_parser(
        "repovuln",
        help="import a RepoVuln-50 xlsx workbook (one oracle per repository snapshot)",
    )
    rv.add_argument("--workbook", required=True)
    rv.add_argument("--output", required=True)
    rv.add_argument(
        "--sheet",
        default=None,
        help="worksheet name; default: the sheet whose header looks like RepoVuln-50",
    )
    rv.add_argument(
        "--data-scope",
        default=None,
        help="comma list (live,historical); default: all rows",
    )
    rv.add_argument("--limit-groups", type=int, default=None)
    rv.add_argument("--dataset-name", default="repovuln-50")
    rv.set_defaults(func=cmd_ingest_repovuln)

    vm = ingest_sub.add_parser(
        "vulnmirage",
        help="import a VulnMirage-Audit dataset.yaml + cases.jsonl",
    )
    vm.add_argument("--manifest", required=True)
    vm.add_argument("--cases", required=True)
    vm.add_argument("--output", default=None)
    vm.add_argument("--dataset-name", default=None)
    vm.add_argument("--limit", type=int, default=None)
    vm.add_argument(
        "--allow-invalid",
        action="store_true",
        help="normalize valid cases even when other cases have errors",
    )
    vm.add_argument(
        "--inspect-only",
        action="store_true",
        help="validate the dataset and report capabilities without writing oracles",
    )
    vm.set_defaults(func=cmd_ingest_vulnmirage)

    materialize = sub.add_parser("materialize", help="cache the repository and build the M0 clean instance")
    materialize.add_argument("--oracle", required=True)
    materialize.add_argument("--config")
    materialize.add_argument("--repo-url", help="override the repository URL (for local fixtures)")
    materialize.add_argument("--fetch", action="store_true", help="explicitly fetch the cache remote")
    materialize.add_argument("--force", action="store_true")
    materialize.set_defaults(func=cmd_materialize)

    generate = sub.add_parser("generate", help="generate M0-M6 benchmark instances")
    generate.add_argument("--oracle", required=True)
    generate.add_argument("--config")
    generate.add_argument("--tiers", default=None, help="comma list, e.g. M0,M1,M2,M3")
    generate.add_argument("--goals", default=None, help="comma list of attack goals")
    generate.add_argument("--seed", type=int, default=None)
    generate.add_argument("--split", default=None)
    generate.add_argument("--max-variants", type=int, default=None)
    generate.add_argument(
        "--target-vulnerability-id",
        default=None,
        help="explicit single target vulnerability; omit to iterate every eligible target",
    )
    generate.add_argument(
        "--target-vulnerability-ids",
        action="append",
        default=None,
        help="restrict generation to these target ids (each produces its own single-target variant)",
    )
    generate.add_argument(
        "--candidates",
        type=int,
        default=None,
        help="candidates per (oracle, goal, mechanism): >1 enables candidate generation",
    )
    generate.add_argument("--dedup-threshold", type=float, default=None)
    generate.add_argument("--force", action="store_true")
    generate.add_argument("--resume", action="store_true")
    generate.set_defaults(func=cmd_generate)

    validate = sub.add_parser("validate", help="run the validation pipeline on one instance")
    validate.add_argument("--instance", required=True)
    validate.add_argument("--config")
    validate.add_argument("--profile", default=None)
    validate.add_argument("--clean-instance", default=None)
    validate.set_defaults(func=cmd_validate)

    export = sub.add_parser("export", help="export release-eligible instances")
    export.add_argument("--instances", default=None)
    export.add_argument("--output", default=None)
    export.add_argument("--config")
    export.add_argument("--only-release-eligible", action="store_true", default=True)
    export.add_argument("--include-rejected", action="store_true")
    export.add_argument("--name", default="vulnmirage")
    export.add_argument("--release-version", default="v0.1")
    export.add_argument(
        "--all-instances",
        action="store_true",
        help="ignore the selection manifest and export every eligible instance (duplicates included)",
    )
    export.set_defaults(func=cmd_export)

    run = sub.add_parser("run", help="run a code agent over a release")
    run.add_argument("--release", required=True)
    run.add_argument("--agent", required=True)
    run.add_argument("--config")
    run.add_argument("--repetitions", type=int, default=None)
    run.add_argument("--workers", type=int, default=None)
    run.add_argument("--instance", action="append", default=None)
    run.add_argument("--limit", type=int, default=None)
    run.add_argument("--resume", action="store_true")
    run.add_argument(
        "--defense",
        default=None,
        help="defense condition id (default: defense.default in the config, normally D0)",
    )
    run.set_defaults(func=cmd_run)

    matrix = sub.add_parser(
        "run-matrix",
        help="run release × agent_config × defense × repetition experiment cells",
    )
    matrix.add_argument("--release", required=True)
    matrix.add_argument(
        "--agent", action="append", required=True, help="agent config YAML (repeatable)"
    )
    matrix.add_argument(
        "--defense",
        action="append",
        default=None,
        help="defense condition id (repeatable; default: defense.default)",
    )
    matrix.add_argument("--config")
    matrix.add_argument("--repetitions", type=int, default=None)
    matrix.add_argument("--workers", type=int, default=None)
    matrix.add_argument("--instance", action="append", default=None)
    matrix.add_argument("--limit", type=int, default=None)
    matrix.add_argument("--resume", action="store_true")
    matrix.set_defaults(func=cmd_run_matrix)

    evaluate = sub.add_parser("evaluate", help="parse outputs and compute paired metrics")
    evaluate.add_argument("--release", required=True)
    evaluate.add_argument("--runs", required=True)
    evaluate.add_argument("--output", required=True)
    evaluate.add_argument("--config")
    evaluate.add_argument(
        "--matching-profile",
        choices=["strict", "relaxed"],
        default="strict",
    )
    evaluate.set_defaults(func=cmd_evaluate)

    inspect = sub.add_parser("inspect", help="inspect an instance, pair, run or trajectory")
    inspect_sub = inspect.add_subparsers(dest="kind", required=True)
    for kind in ("instance", "pair", "run", "trajectory", "verification", "generation"):
        item = inspect_sub.add_parser(kind)
        item.add_argument("identifier")
        item.add_argument("--config")
        item.set_defaults(func=cmd_inspect)

    validate_run = sub.add_parser("validate-run", help="validate raw/normalized event artifacts")
    validate_run.add_argument("--run", required=True)
    validate_run.add_argument("--config")
    validate_run.add_argument("--skip-event-order", action="store_true")
    validate_run.add_argument("--skip-artifact-hashes", action="store_true")
    validate_run.add_argument("--skip-parent-links", action="store_true")
    validate_run.set_defaults(func=cmd_validate_run)

    validate_release = sub.add_parser("validate-release", help="verify release bundle integrity")
    validate_release.add_argument("--release", required=True)
    validate_release.add_argument("--config")
    validate_release.add_argument("--rebuild", action="store_true")
    validate_release.add_argument("--rebuild-dir", default=None)
    validate_release.set_defaults(func=cmd_validate_release)

    repair = sub.add_parser("repair-output", help="extract one JSON object from raw agent output")
    repair.add_argument("--raw", required=True)
    repair.add_argument("--output", required=True)
    repair.add_argument("--repo-root", default=None)
    repair.set_defaults(func=cmd_repair_output)

    optimize = sub.add_parser(
        "optimize-payloads",
        help="candidate-level development-set payload optimization (dev splits only)",
    )
    optimize.add_argument("--release", required=True)
    optimize.add_argument("--agent", required=True)
    optimize.add_argument("--config")
    optimize.add_argument("--generations", type=int, default=3)
    optimize.add_argument("--population", type=int, default=5)
    optimize.add_argument("--output", required=True)
    optimize.add_argument("--seed", type=int, default=None)
    optimize.add_argument("--max-queries", type=int, default=None)
    optimize.add_argument("--max-llm-calls", type=int, default=None)
    optimize.add_argument("--token-budget", type=int, default=None)
    optimize.add_argument(
        "--rewrite",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable the real rewriter (default: generation.rewrite_enabled)",
    )
    optimize.set_defaults(func=cmd_optimize_payloads)

    reference = sub.add_parser(
        "reference-verify",
        help="import a reference audit and verify its findings privately",
    )
    reference.add_argument("--oracle", required=True)
    reference.add_argument("--report", required=True)
    reference.add_argument("--metadata", default=None)
    reference.add_argument("--output", default=None)
    reference.add_argument("--config")
    reference.set_defaults(func=cmd_reference_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    from .env import load_local_env

    load_local_env(getattr(args, "env_file", None))
    level = "ERROR" if args.quiet else ("DEBUG" if args.verbose else "INFO")
    configure_logging(level)
    try:
        result = args.func(args)
    except VulnMirageError as exc:
        _LOG.error(
            exc.message,
            extra={"context": {"error_code": exc.error_code, **exc.details}},
        )
        print(json.dumps(redact_json(exc.to_dict()), ensure_ascii=False), file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover - interactive
        print(json.dumps({"ok": False, "error_code": "interrupted"}), file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - top-level guard
        payload = {
            "ok": False,
            "error": True,
            "error_code": "internal_error",
            "exception": type(exc).__name__,
            "message": str(exc),
        }
        if args.verbose:
            payload["traceback"] = traceback.format_exc()
        _LOG.exception("unexpected failure")
        print(json.dumps(redact_json(payload), ensure_ascii=False), file=sys.stderr)
        return 1
    _emit(result)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
