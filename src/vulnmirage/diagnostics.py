"""Environment diagnostics for ``vulnmirage doctor``."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from .config import LoadedConfig, load_agent_config
from .env import last_loaded_path, secret_environment_status
from .paths import project_root


def _writable(directory: Path) -> tuple[bool, str | None]:
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".vulnmirage-write-", dir=directory, delete=True):
            pass
        return True, None
    except OSError as exc:
        return False, str(exc)


def _check_credentials(add, loaded: LoadedConfig | None, agent) -> None:
    """P0-2 #4: declared / present / forwarded, names only."""
    from .credentials import inspect_credentials
    from .harness.sandbox import build_environment

    env_allow = [
        *(loaded.config.execution.env_allowlist if loaded else []),
        *(getattr(agent, "env_allowlist", None) or []),
    ]
    credential_status = inspect_credentials(agent)
    if credential_status.declared:
        prepared_env, _ = build_environment(
            env_allow,
            network_enabled=bool(getattr(agent, "network_enabled", False)),
            credential_allowlist=credential_status.declared,
        )
        forwarded = [name for name in credential_status.declared if name in prepared_env]
        credential_status = inspect_credentials(agent, forwarded=forwarded)
    add(
        "agent_credentials",
        "ok" if credential_status.satisfied else "warn",
        policy=credential_status.policy,
        variables=credential_status.forwarded_status(),
        declared=len(credential_status.declared),
        present=len(credential_status.present),
        forwarded=len(credential_status.forwarded),
        missing=credential_status.missing,
        blocks_live_run=not credential_status.satisfied,
        note=(
            "names only (declared/present/forwarded); values are never logged "
            "and are never written to run records"
        ),
    )


def _check_container(add, agent) -> None:
    """P1-1: image/runtime/agent-version checks for the container backend."""
    if getattr(agent, "execution_backend", "subprocess") != "container":
        return
    from .harness.container import container_agent_version, container_available

    available, detail = container_available(getattr(agent, "container_runtime", None))
    image = getattr(agent, "container_image", "")
    executable = getattr(agent, "container_agent_executable", "opencode")
    add(
        "container_backend",
        "ok" if available else "fail",
        runtime=detail,
        image=image,
        network=getattr(agent, "container_network", "none"),
        network_policy=(
            "tools_and_model_both_blocked"
            if getattr(agent, "container_network", "none") == "none"
            else "best_effort_same_network_for_model_and_tools"
        ),
        agent_state_mount="/agent-state",
        config_in_container="/agent-state/opencode.json",
    )
    if available:
        version = container_agent_version(
            getattr(agent, "container_runtime", None), image, executable
        )
        configured = getattr(agent, "container_agent_version", None)
        add(
            "container_agent_executable",
            "ok" if version.get("status") == "ok" else "warn",
            executable=executable,
            image=image,
            configured_version=configured,
            detected_version=version.get("version"),
            detail=version,
        )


def run_doctor(loaded: LoadedConfig | None, agent_path: str | None = None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, status: str, **details: Any) -> None:
        checks.append({"name": name, "status": status, **details})

    version_ok = sys.version_info >= (3, 11)
    add(
        "python",
        "ok" if version_ok else "fail",
        version=sys.version.split()[0],
        executable=sys.executable,
        requirement=">=3.11",
    )

    git = shutil.which("git")
    if git:
        import subprocess

        proc = subprocess.run(
            [git, "--version"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        add("git", "ok" if proc.returncode == 0 else "warn", executable=git, version=proc.stdout.strip())
    else:
        add("git", "fail", message="git executable not found on PATH")

    if loaded is not None:
        add(
            "config",
            "ok",
            path=str(loaded.source),
            sha256=loaded.sha256,
            workspace_root=str(loaded.paths.root),
        )
        ok, error = _writable(loaded.paths.root)
        add("workspace_writable", "ok" if ok else "fail", path=str(loaded.paths.root), error=error)
        ok, error = _writable(loaded.paths.cache)
        add("repo_cache_writable", "ok" if ok else "fail", path=str(loaded.paths.cache), error=error)
        for label, value in (
            ("audit_task_template", loaded.config.audit_task.template),
            ("payload_registry", loaded.config.generation.payload_registry),
        ):
            try:
                path = loaded.resolve_asset(value)
                add(label, "ok", path=str(path))
            except Exception as exc:
                add(label, "fail", path=value, error=str(exc))
        try:
            schema = loaded.resolve_asset(loaded.config.audit_task.output_schema)
            add("finding_schema", "ok", path=str(schema))
        except Exception as exc:
            add("finding_schema", "warn", path=loaded.config.audit_task.output_schema, error=str(exc))
        for name in ("build_commands", "test_commands"):
            commands = getattr(loaded.config.validation, name)
            add(name, "ok", count=len(commands))
    else:
        add("config", "fail", message="configuration was not loaded")

    if agent_path:
        try:
            loaded_agent = load_agent_config(agent_path)
            agent = loaded_agent.config
            add("agent_config", "ok", path=str(loaded_agent.source), adapter=getattr(agent, "adapter", None))
            if getattr(agent, "adapter", None) == "opencode":
                exe = shutil.which(getattr(agent, "executable", "opencode"))
                add(
                    "agent_executable",
                    "ok" if exe else "warn",
                    executable=getattr(agent, "executable", "opencode"),
                    resolved=exe,
                )
                actual_version = None
                if exe:
                    import subprocess

                    try:
                        proc = subprocess.run(
                            [exe, "--version"],
                            capture_output=True,
                            text=True,
                            timeout=20,
                            check=False,
                        )
                        actual_version = (proc.stdout or proc.stderr).strip() or None
                    except Exception as exc:  # noqa: BLE001
                        actual_version = f"unavailable: {exc}"
                configured_version = getattr(agent, "opencode_version", None)
                add(
                    "opencode_version",
                    "ok" if actual_version else "warn",
                    configured=configured_version,
                    detected=actual_version,
                    note="recorded in every run; no model request is made",
                )
                config_file = getattr(agent, "config_file", None)
                if config_file:
                    # Resolve exactly once, relative to the agent YAML directory.
                    path = Path(config_file)
                    if not path.is_absolute():
                        path = (loaded_agent.base_dir / path).resolve()
                    add(
                        "opencode_config",
                        "ok" if path.is_file() else "fail",
                        path=str(path),
                        resolution="relative_to_agent_yaml",
                    )
                else:
                    add("opencode_config", "warn", message="config_file is not set")
                output_format = getattr(agent, "output_format", "text")
                event_format = getattr(agent, "opencode_event_format", None)
                add(
                    "opencode_trace_capability",
                    "ok" if output_format == "json" else "warn",
                    output_format=output_format,
                    event_format=event_format,
                    message=(
                        "native JSONL events enabled"
                        if output_format == "json"
                        else "text output cannot provide a native trace"
                    ),
                )
                # P0-2 #4: report declared / present / forwarded separately and
                # only ever print the variable *names*.
                _check_credentials(add, loaded, agent)
                backend = getattr(agent, "execution_backend", "subprocess")
                if backend == "container":
                    _check_container(add, agent)
                ok, error = _writable(loaded.paths.runs)
                add(
                    "run_output_writable",
                    "ok" if ok else "fail",
                    path=str(loaded.paths.runs),
                    error=error,
                )
            else:
                _check_credentials(add, loaded, agent)
                _check_container(add, agent)
                argv = getattr(agent, "argv", [])
                if argv:
                    exe = shutil.which(argv[0]) or (argv[0] if Path(argv[0]).exists() else None)
                    add(
                        "agent_executable",
                        "ok" if exe else "warn",
                        executable=argv[0],
                        resolved=exe,
                    )
        except Exception as exc:
            add("agent_config", "fail", path=agent_path, error=str(exc))

    add(
        "project_assets",
        "ok" if (project_root() / "prompts").exists() else "warn",
        root=str(project_root()),
    )

    env_path = last_loaded_path()
    add(
        "env_file",
        "ok" if env_path is not None else "warn",
        path=str(env_path) if env_path else None,
        message=(
            "local .env loaded; existing environment variables win"
            if env_path
            else "no local .env loaded (use --env-file or create .env)"
        ),
        values_are_never_logged=True,
    )
    llm_variables = secret_environment_status(
        [
            "VULNMIRAGE_LLM_BASE_URL",
            "VULNMIRAGE_LLM_API_KEY",
            "VULNMIRAGE_LLM_MODEL",
        ]
    )
    add(
        "llm_environment",
        "ok" if all(item["present"] for item in llm_variables) else "warn",
        variables=llm_variables,
        note="presence and source only; values are never logged",
    )

    failed = [item for item in checks if item["status"] == "fail"]
    warned = [item for item in checks if item["status"] == "warn"]
    return {
        "ok": not failed,
        "critical_failures": len(failed),
        "warnings": len(warned),
        "checks": checks,
        "environment": {
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "cwd": os.getcwd(),
        },
    }
