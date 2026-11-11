"""VulnMirage command-line interface.

Every command prints machine-readable JSON on stdout and returns a non-zero exit
code on failure; diagnostics go to stderr as structured JSON.

The command surface is the campaign flow only::

    doctor                      check configuration, dataset, egress and executor
    schemas                     regenerate the JSON Schemas of every contract
    ingest dataset-core         read the published package and verify its digests
    campaign plan               freeze the plan (offline, no download, no model call)
    campaign run|resume         execute one task / continue a plan
    campaign analyze            recompute mechanism artifacts from stored runs
    campaign verify-archive     recompute every archived artifact hash
    campaign status             show per-task phase state

The evaluator has its own entry point, so the oracle is never loaded by the process
that ran the agent: ``python -m vulnmirage.verifier``.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import Any

from . import __version__
from .config import LoadedConfig, load_config, with_variant_set
from .errors import ConfigError, VulnMirageError
from .logging import configure_logging, get_logger, redact as redact_json
from .paths import project_root

_LOG = get_logger("cli")


def default_config_path() -> Path:
    local = Path.cwd() / "configs" / "experiment.yaml"
    if local.exists():
        return local
    return project_root() / "configs" / "experiment.yaml"


def _emit(payload: Any) -> None:
    print(json.dumps(redact_json(payload), indent=2, ensure_ascii=False, default=str))


def _load_config(path: str | None) -> LoadedConfig:
    source = Path(path) if path else default_config_path()
    return load_config(source)


# ------------------------------------------------------------------------ doctor
def cmd_doctor(args: argparse.Namespace) -> dict[str, Any]:
    from .diagnostics import run_doctor

    loaded = _load_config(args.config)
    return run_doctor(
        loaded,
        agent_path=Path(args.agent) if args.agent else None,
        agent_profile=getattr(args, "agent_profile", None),
    )


# ----------------------------------------------------------------------- schemas
def cmd_schemas(args: argparse.Namespace) -> dict[str, Any]:
    from .schemas import generate_schemas, schema_index

    output = Path(args.output)
    if not output.is_absolute():
        output = (Path.cwd() / output).resolve()
    digests = generate_schemas(output)
    return {"ok": True, "output": output.as_posix(), "schemas": digests, **schema_index(output)}


# ------------------------------------------------------------------------ ingest
def cmd_ingest_dataset_core(args: argparse.Namespace) -> dict[str, Any]:
    from .ingest.dataset_core import load_dataset_core, task_index_rows

    core = load_dataset_core(
        Path(args.root),
        tasks_file=args.tasks,
        oracle_file=args.oracle,
        strict=not args.skip_integrity,
    )
    integrity = core.verify_file_hashes()
    return {
        "ok": integrity["ok"],
        "summary": core.summary(),
        "integrity": integrity,
        "tasks": task_index_rows(core) if args.with_tasks else None,
    }


# ---------------------------------------------------------------------- campaign
def _runner(args: argparse.Namespace):
    import os

    from .campaign.executor import (
        NullExecutor,
        build_executor,
        detect_framework_version,
    )
    from .campaign.pipeline import CampaignRunner
    from .campaign.plan import load_plan

    loaded = _load_config(args.config)
    plan = load_plan(Path(args.plan)) if getattr(args, "plan", None) else None
    if plan is not None and plan.variant_set_file:
        loaded = with_variant_set(loaded, plan.variant_set_file)
    dataset_root = (
        Path(args.dataset)
        if getattr(args, "dataset", None)
        else (Path(plan.dataset_root) if plan else None)
    )
    archive_root = (
        Path(args.workspace)
        if getattr(args, "workspace", None)
        else (Path(plan.archive_root) if plan else None)
    )

    executor = NullExecutor()
    model_label = getattr(args, "model_label", None)
    agent_env_names: tuple[str, ...] = ()
    agent_env_allowlist: tuple[str, ...] = ()
    trace_adapter = "none"
    agent_profile: str | None = None
    agent_env_overrides: dict[str, str] = {}
    agent_config_sha256: str | None = None
    agent_external_file_sha256: dict[str, str] = {}
    framework_version: str | None = None
    agent_path = getattr(args, "agent", None)
    if agent_path:
        from .config import load_agent_config

        agent = load_agent_config(
            Path(agent_path), profile=getattr(args, "agent_profile", None)
        )
        missing = agent.config.missing_env()
        if missing:
            raise ConfigError(
                "the agent declares credentials that are not set in this environment",
                details={"missing": sorted(missing), "path": str(agent_path)},
            )
        executor = build_executor(
            agent.config,
            egress_config=loaded.config.isolation.egress,
        )
        model_label = model_label or agent.config.model_label
        agent_env_names = tuple(agent.config.requires_env)
        agent_env_allowlist = tuple(agent.config.env_allowlist)
        trace_adapter = agent.config.trace_adapter
        agent_profile = agent.profile
        agent_env_overrides = dict(agent.child_env)
        agent_config_sha256 = agent.sha256
        agent_external_file_sha256 = dict(agent.external_file_sha256)
        version_env = {
            name: os.environ[name]
            for name in agent.config.env_allowlist
            if name in os.environ
        }
        version_env.update(agent.child_env)
        framework_version = detect_framework_version(
            agent.config.framework_version_command,
            env=version_env,
        )

    runner = CampaignRunner(
        loaded,
        dataset_root=dataset_root,
        archive_root=archive_root,
        executor=executor,
        model_label=model_label,
        agent_env_names=agent_env_names,
        agent_env_allowlist=agent_env_allowlist,
        trace_adapter=trace_adapter,
        agent_profile=agent_profile,
        agent_env_overrides=agent_env_overrides,
        agent_config_sha256=agent_config_sha256,
        agent_external_file_sha256=agent_external_file_sha256,
        framework_version=framework_version,
    )
    if plan is not None:
        runner.use_plan(plan)
    return runner, plan


def cmd_campaign_plan(args: argparse.Namespace) -> dict[str, Any]:
    from .campaign.pipeline import CampaignRunner

    loaded = _load_config(args.config)
    if args.variant_set:
        loaded = with_variant_set(loaded, args.variant_set)
    runner = CampaignRunner(
        loaded,
        dataset_root=Path(args.dataset) if args.dataset else None,
        archive_root=Path(args.workspace) if args.workspace else None,
    )
    return runner.write_plan(
        dry_run=bool(getattr(args, "dry_run", False)),
        task_ids=args.task or None,
        limit=args.limit,
        target_limit=args.target_limit,
    )


def cmd_campaign_generate(args: argparse.Namespace) -> dict[str, Any]:
    """Generate and validate candidates only; no agent, no audit budget."""
    runner, plan = _runner(args)
    if plan is None:
        raise ConfigError("campaign generate requires --plan")
    task_ids = args.task or [item.task_id for item in plan.tasks]
    results = [runner.generate_only(task_id) for task_id in task_ids]
    return {
        "ok": all(item.get("ok") for item in results),
        "variant_set_id": plan.variant_set_id,
        "results": results,
    }


def cmd_campaign_aggregate(args: argparse.Namespace) -> dict[str, Any]:
    runner, plan = _runner(args)
    if plan is None:
        raise ConfigError("campaign aggregate requires --plan")
    task_ids = args.task or None
    return runner.aggregate(tasks=task_ids)


def cmd_campaign_run(args: argparse.Namespace) -> dict[str, Any]:
    runner, plan = _runner(args)
    if plan is None:
        raise ConfigError("campaign run requires --plan")
    task_ids = args.task or [item.task_id for item in plan.tasks]
    results = [runner.run_task(task_id, resume=not args.no_resume) for task_id in task_ids]
    return {
        "ok": all(item.get("ok") for item in results),
        "variant_set_id": plan.variant_set_id,
        "results": results,
    }


def cmd_campaign_analyze(args: argparse.Namespace) -> dict[str, Any]:
    runner, plan = _runner(args)
    if plan is None:
        raise ConfigError("campaign analyze requires --plan")
    task_ids = args.task or [item.task_id for item in plan.tasks]
    return {"ok": True, "results": [runner.analyze(task_id) for task_id in task_ids]}


def cmd_campaign_verify_archive(args: argparse.Namespace) -> dict[str, Any]:
    runner, plan = _runner(args)
    if plan is None:
        raise ConfigError("campaign verify-archive requires --plan")
    task_ids = args.task or [item.task_id for item in plan.tasks]
    results = [runner.verify_archive(task_id) for task_id in task_ids]
    return {"ok": all(item["ok"] for item in results), "results": results}


def cmd_campaign_status(args: argparse.Namespace) -> dict[str, Any]:
    from .campaign.plan import load_plan
    from .campaign.state import TaskStateStore

    loaded = _load_config(args.config)
    plan = load_plan(Path(args.plan)) if args.plan else None
    workspace = args.workspace or (
        plan.archive_root if plan else loaded.config.campaign.archive_root
    )
    store = TaskStateStore(Path(workspace))
    tasks: list[dict[str, Any]] = []
    if plan is not None:
        for item in plan.tasks:
            state = store.load(item.task_id)
            tasks.append(
                {
                    "task_id": item.task_id,
                    "phase": state.phase if state else "pending",
                    "runs": len(state.run_ids) if state else 0,
                    "scored": len(state.scored_run_ids) if state else 0,
                    "ineligible": len(state.ineligible_run_ids) if state else 0,
                    "error": state.error if state else None,
                }
            )
    return {
        "ok": True,
        "workspace": store.root.as_posix(),
        "variant_set_id": plan.variant_set_id if plan else None,
        "tasks": tasks,
    }


# ------------------------------------------------------------------------ parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnmirage",
        description="VulnMirage: adversarial repository-manipulation benchmark for code agents",
    )
    parser.add_argument("--version", action="version", version=f"vulnmirage {__version__}")
    parser.add_argument(
        "--env-file",
        default=None,
        help=(
            "load local credentials from this .env file (default: ./.env or the project "
            ".env; existing environment variables win)"
        ),
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="errors only")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="check configuration, dataset, egress and executor")
    doctor.add_argument("--config", help="application config YAML")
    doctor.add_argument("--agent", help="optional agent config YAML")
    doctor.add_argument(
        "--agent-profile",
        default=None,
        help="profile inside a multi-model agent config (default: its default_profile)",
    )
    doctor.set_defaults(func=cmd_doctor)

    schemas = sub.add_parser("schemas", help="regenerate the JSON Schemas")
    schemas.add_argument("--output", default="schemas")
    schemas.set_defaults(func=cmd_schemas)

    ingest = sub.add_parser("ingest", help="read a dataset package")
    ingest_sub = ingest.add_subparsers(dest="ingest_kind", required=True)
    core = ingest_sub.add_parser(
        "dataset-core", help="read manifest + task JSONL + private oracle JSONL"
    )
    core.add_argument("--root", required=True, help="dataset package root")
    core.add_argument("--tasks", default=None, help="explicit task JSONL path")
    core.add_argument("--oracle", default=None, help="explicit private oracle JSONL path")
    core.add_argument("--skip-integrity", action="store_true")
    core.add_argument("--with-tasks", action="store_true", help="include the per-task index")
    core.set_defaults(func=cmd_ingest_dataset_core)

    campaign = sub.add_parser("campaign", help="run one task from archive to archived artifacts")
    campaign_sub = campaign.add_subparsers(dest="campaign_command", required=True)

    def add_common(item: argparse.ArgumentParser, *, plan_required: bool) -> None:
        if plan_required:
            item.add_argument("--plan", required=True)
        else:
            item.add_argument("--plan", default=None)
        item.add_argument("--config", default=None)
        item.add_argument("--dataset", default=None, help="dataset package root")
        item.add_argument("--workspace", default=None, help="campaign archive root")
        item.add_argument("--task", action="append", default=None, help="repeatable task id")

    plan_cmd = campaign_sub.add_parser("plan", help="freeze the campaign plan (offline)")
    add_common(plan_cmd, plan_required=False)
    plan_cmd.add_argument("--limit", type=int, default=None)
    plan_cmd.add_argument(
        "--target-limit",
        type=int,
        default=None,
        help="maximum eligible targets expanded per task (default: campaign config)",
    )
    plan_cmd.add_argument(
        "--variant-set",
        default=None,
        help="variant-set YAML selected and frozen into this plan",
    )
    plan_cmd.add_argument(
        "--dry-run",
        action="store_true",
        help="resolve every input and print the plan digest without writing it",
    )
    plan_cmd.set_defaults(func=cmd_campaign_plan)

    generate_cmd = campaign_sub.add_parser(
        "generate",
        help="generate and validate attack candidates only (no agent, no audit)",
    )
    add_common(generate_cmd, plan_required=True)
    generate_cmd.add_argument(
        "--inspect-generation",
        action="store_true",
        help="print candidates, validator verdicts and the recorded selection",
    )
    generate_cmd.set_defaults(func=cmd_campaign_generate)

    aggregate_cmd = campaign_sub.add_parser(
        "aggregate",
        help="pair clean/attacked runs and write aggregate/aggregate.json",
    )
    add_common(aggregate_cmd, plan_required=True)
    aggregate_cmd.set_defaults(func=cmd_campaign_aggregate)

    for name, func, help_text in (
        ("run", cmd_campaign_run, "execute (or resume) one task"),
        ("resume", cmd_campaign_run, "continue every task of a plan"),
    ):
        item = campaign_sub.add_parser(name, help=help_text)
        add_common(item, plan_required=True)
        item.add_argument("--agent", default=None, help="agent config with an argv template")
        item.add_argument(
            "--agent-profile",
            default=None,
            help="profile inside a multi-model agent config (e.g. glm-4.7)",
        )
        item.add_argument("--model-label", default=None)
        item.add_argument("--no-resume", action="store_true")
        item.set_defaults(func=func)

    analyze = campaign_sub.add_parser(
        "analyze", help="recompute mechanism artifacts from stored runs"
    )
    add_common(analyze, plan_required=True)
    analyze.set_defaults(func=cmd_campaign_analyze)

    verify_archive = campaign_sub.add_parser(
        "verify-archive", help="recompute every archived artifact hash"
    )
    add_common(verify_archive, plan_required=True)
    verify_archive.set_defaults(func=cmd_campaign_verify_archive)

    status = campaign_sub.add_parser("status", help="show per-task phase state")
    add_common(status, plan_required=False)
    status.set_defaults(func=cmd_campaign_status)

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
