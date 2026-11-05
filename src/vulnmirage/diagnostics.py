"""``vulnmirage doctor``: is this machine able to run a campaign?

Checks are ordered by what would waste the most work if it were wrong:

1. configuration loads and resolves its assets (task template, contract section);
2. the dataset package is readable and its recorded digests match;
3. the archive provider is usable and the workspace is writable;
4. the egress probe reproduces the intended tool boundary (the probe, not the
   config value, is the answer);
5. the agent command is startable and its declared credential names are present.

Nothing here downloads a repository or calls a model.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .config import LoadedConfig, load_agent_config

CheckStatus = str  # "pass" | "warn" | "fail" | "skip"


def _writable(directory: Path) -> tuple[bool, str | None]:
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".vulnmirage-write-", dir=directory, delete=True):
            pass
        return True, None
    except OSError as exc:
        return False, str(exc)


def _check_config(loaded: LoadedConfig) -> dict[str, Any]:
    campaign = loaded.config.campaign
    try:
        template = loaded.resolve_asset(campaign.audit_task_template)
    except Exception as exc:  # noqa: BLE001
        return {"status": "fail", "detail": f"task template not found: {exc}"}
    from .campaign.task_prompt import OUTPUT_CONTRACT_MARKER, output_contract_section

    try:
        contract = output_contract_section(template)
    except Exception as exc:  # noqa: BLE001
        return {"status": "fail", "detail": f"task template has no {OUTPUT_CONTRACT_MARKER} section: {exc}"}
    from .campaign.plan import _variant_specs

    try:
        variants = _variant_specs(loaded)
    except Exception as exc:  # noqa: BLE001
        return {"status": "fail", "detail": f"variant set could not be loaded: {exc}"}
    if not variants:
        return {"status": "fail", "detail": "no variants declared"}
    kinds = {item.kind for item in variants}
    if "clean" not in kinds:
        return {"status": "fail", "detail": "variants declare no clean baseline"}
    return {
        "status": "pass",
        "detail": f"{len(variants)} variant(s) declared, contract section present",
        "contract_chars": len(contract),
        "config_sha256": loaded.sha256,
    }


def _check_dataset(loaded: LoadedConfig) -> dict[str, Any]:
    from .ingest.dataset_core import load_dataset_core

    root = Path(loaded.config.campaign.dataset_root)
    if not root.is_absolute():
        root = (Path.cwd() / root).resolve()
    if not root.is_dir():
        return {"status": "fail", "detail": f"dataset root does not exist: {root}"}
    try:
        core = load_dataset_core(
            root,
            tasks_file=loaded.config.campaign.tasks_file,
            oracle_file=loaded.config.campaign.oracle_file,
            strict=True,
        )
    except Exception as exc:  # noqa: BLE001
        return {"status": "fail", "detail": f"dataset package rejected: {exc}"}
    integrity = core.verify_file_hashes()
    summary = core.summary()
    if not integrity["ok"]:
        return {"status": "fail", "detail": "dataset digests do not match manifest.json", "integrity": integrity}
    return {
        "status": "pass",
        "detail": (
            f"{summary['task_count']} task(s), {summary['target_count']} target(s), "
            f"digests verified"
        ),
        "root": summary["root"],
        "issues": summary["issues"],
    }


def _check_archive(loaded: LoadedConfig) -> dict[str, Any]:
    provider = loaded.config.archive.provider
    campaign_root = Path(loaded.config.campaign.archive_root)
    if not campaign_root.is_absolute():
        campaign_root = (Path.cwd() / campaign_root).resolve()
    ok, error = _writable(campaign_root)
    if not ok:
        return {"status": "fail", "detail": f"campaign root is not writable: {error}"}
    notes: list[str] = [f"provider={provider.name}", f"root={campaign_root.as_posix()}"]
    if provider.name in {"local_zip", "local_tree"}:
        notes.append("local provider: no network download will occur")
    else:
        notes.append("hosts=" + ",".join(provider.allowed_hosts))
        notes.append("downloads happen in the preparation phase only, never during an audit")
    return {"status": "pass", "detail": "; ".join(notes)}


def _check_egress(loaded: LoadedConfig) -> dict[str, Any]:
    from .isolation.network import probe_egress

    config = loaded.config.isolation.egress
    result = probe_egress(config)
    payload = {
        "mode": result.mode,
        "verdict": result.verdict,
        "reachable_answer_hosts": result.reachable_answer_hosts,
        "gateway_reachable": result.gateway_reachable,
        "notes": result.notes,
    }
    if result.reachable_answer_hosts:
        return {
            "status": "fail" if config.fail_closed else "warn",
            "detail": (
                "an answer-serving host is reachable from this machine. With fail_closed=true "
                "every run would be marked ineligible; to run the formal experiment, point "
                "tools at a filtering proxy (isolation.egress.mode=proxy) or run the audit in a "
                "container with the network namespace closed, then re-check"
            ),
            "probe": payload,
        }
    if config.mode == "none":
        return {
            "status": "warn",
            "detail": "egress mode is 'none': nothing is enforced, only probed",
            "probe": payload,
        }
    return {"status": "pass", "detail": f"no answer host answered (mode={config.mode})", "probe": payload}


def _check_agent(
    loaded: LoadedConfig, agent_path: Path | None, agent_profile: str | None = None
) -> dict[str, Any]:
    if agent_path is None:
        return {
            "status": "skip",
            "detail": "no --agent given: campaign run will prepare and attest workspaces only",
        }
    agent = load_agent_config(agent_path, profile=agent_profile)
    missing = agent.config.missing_env()
    executable = agent.config.argv[0] if agent.config.argv else ""
    resolved = shutil.which(executable) or (
        executable if Path(executable).is_file() else None
    )
    payload = {
        "path": agent_path.as_posix(),
        "profile": agent.profile,
        "profiles": list(agent.profiles),
        "mode": agent.config.mode,
        "argv_head": agent.config.argv[:3],
        "requires_env": agent.config.requires_env,
        "fixed_child_env_names": sorted(agent.child_env),
        "external_file_sha256": agent.external_file_sha256,
        "effective_agent_config_sha256": agent.sha256,
    }
    if missing:
        return {"status": "fail", "detail": "missing credentials: " + ", ".join(missing), **payload}
    if not resolved:
        return {"status": "fail", "detail": f"executable not found: {executable}", **payload}
    return {"status": "pass", "detail": f"executable resolved, {len(agent.config.argv)} argv item(s)", **payload}


def run_doctor(
    loaded: LoadedConfig,
    *,
    agent_path: Path | None = None,
    agent_profile: str | None = None,
) -> dict[str, Any]:
    checks = {
        "config": _check_config(loaded),
        "dataset": _check_dataset(loaded),
        "archive": _check_archive(loaded),
        "egress": _check_egress(loaded),
        "agent": _check_agent(loaded, agent_path, agent_profile),
    }
    failures = [name for name, item in checks.items() if item["status"] == "fail"]
    warnings = [name for name, item in checks.items() if item["status"] == "warn"]
    return {
        "ok": not failures,
        "config_source": loaded.source.as_posix(),
        "config_sha256": loaded.sha256,
        "campaign_root": loaded.config.campaign.archive_root,
        "checks": checks,
        "failures": failures,
        "warnings": warnings,
        "environment": {
            "cwd": os.getcwd(),
            "python": os.sys.version.split()[0],
        },
    }


__all__ = ["run_doctor"]
