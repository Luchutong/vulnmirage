"""Tool egress: the audit agent may call the model, nothing else.

A prompt that says "do not use the network" is not a control.  Two things are
recorded here instead:

* the environment handed to the agent process, which removes proxy variables,
  package-index configuration and search-tool credentials, and
* a **live probe** that actually tries to reach the inference gateway and the
  answer-serving hosts.  The probe result, not the configuration, decides
  eligibility: ``mode: none`` is honest about not enforcing anything, and a probe
  that reaches ``github.com`` marks the run ineligible rather than being explained
  away.

Nothing in this module claims kernel-level enforcement.  ``container`` means the
operator runs the agent inside a container whose network namespace was configured;
that claim still has to pass :func:`probe_egress`.
"""

from __future__ import annotations

import os
import socket
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field

from ..config import EgressConfig
from ..hashing import utc_now_iso

#: Variables that let a process reach the network or fetch packages.  They are
#: removed from the agent environment unless they are the inference gateway's.
_PROXY_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "GIT_PROXY_COMMAND",
    "RESTRICTED_NETWORK",
)

#: Offline hints: they do not block anything, they make accidental fetches fail
#: fast and visibly instead of quietly succeeding.
_OFFLINE_HINTS = {
    "PIP_NO_INDEX": "1",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "npm_config_offline": "true",
    "npm_config_registry": "http://127.0.0.1:1/",
    "YARN_ENABLE_NETWORK": "0",
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ALLOW_PROTOCOL": "file",
    "CARGO_NET_OFFLINE": "true",
    "GOFLAGS": "-mod=mod",
    "VULNMIRAGE_EGRESS": "tools_offline",
}


class ProbeTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str
    port: int = 443
    resolved: bool = False
    connected: bool = False
    error: str | None = None
    addresses: list[str] = Field(default_factory=list)


class EgressProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    mode: str
    enforcement: str
    probe_timeout_seconds: float
    blocked_targets: list[ProbeTarget] = Field(default_factory=list)
    gateway_targets: list[ProbeTarget] = Field(default_factory=list)
    reachable_answer_hosts: list[str] = Field(default_factory=list)
    gateway_reachable: bool | None = None
    verdict: str = "unknown"
    notes: list[str] = Field(default_factory=list)
    probed_at: str = Field(default_factory=utc_now_iso)


def _probe(host: str, *, port: int, timeout: float) -> ProbeTarget:
    target = ProbeTarget(host=host, port=port)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        target.error = f"resolve: {exc}"
        return target
    target.resolved = True
    # Truncate to keep the record small and stable.
    target.addresses = sorted({info[4][0] for info in infos})[:4]
    try:
        with socket.create_connection((host, port), timeout=timeout):
            target.connected = True
    except OSError as exc:
        target.error = f"connect: {exc}"
    return target


def probe_egress(
    config: EgressConfig,
    *,
    blocked_hosts: Iterable[str] | None = None,
    gateway_hosts: Iterable[str] | None = None,
    port: int = 443,
) -> EgressProbeResult:
    """Attempt real connections and report what happened."""
    blocked = list(blocked_hosts if blocked_hosts is not None else config.probe_blocked_hosts)
    gateway = list(
        gateway_hosts if gateway_hosts is not None else config.inference_gateway_hosts
    )
    timeout = float(config.probe_timeout_seconds)
    blocked_targets = [_probe(host, port=port, timeout=timeout) for host in blocked]
    gateway_targets = [_probe(host, port=port, timeout=timeout) for host in gateway]
    reachable = [item.host for item in blocked_targets if item.connected]
    gateway_reachable = (
        any(item.connected for item in gateway_targets) if gateway_targets else None
    )
    notes: list[str] = []
    if config.mode == "none":
        notes.append(
            "egress mode is 'none': no enforcement is claimed, only the probe result"
        )
    if reachable:
        notes.append(
            "an answer-serving host is reachable from this environment: online answer "
            "lookup cannot be excluded for this run"
        )
    if gateway_targets and not gateway_reachable:
        notes.append("no configured inference gateway answered the probe")
    verdict = "blocked" if not reachable else "open"
    return EgressProbeResult(
        mode=config.mode,
        enforcement="probe_only" if config.mode == "none" else f"{config.mode}_plus_probe",
        probe_timeout_seconds=timeout,
        blocked_targets=blocked_targets,
        gateway_targets=gateway_targets,
        reachable_answer_hosts=reachable,
        gateway_reachable=gateway_reachable,
        verdict=verdict,
        notes=notes,
    )


def build_agent_environment(
    config: EgressConfig,
    *,
    base_env: dict[str, str] | None = None,
    keep: Iterable[str] = (),
    inference_env: dict[str, str] | None = None,
) -> tuple[dict[str, str], dict[str, object]]:
    """Return the environment for the agent process plus an audit record.

    ``inference_env`` carries model credentials/endpoint variables only; they are
    the single permitted network capability and are recorded by *name*, never by
    value.
    """
    source = dict(os.environ if base_env is None else base_env)
    kept = set(keep)
    dropped: list[str] = []
    for name in _PROXY_VARS:
        if name in source and name not in kept:
            source.pop(name, None)
            dropped.append(name)
    applied_hints: dict[str, str] = {}
    for name, value in _OFFLINE_HINTS.items():
        if name not in kept:
            source.setdefault(name, value)
            applied_hints[name] = value
    credential_names: list[str] = []
    for name, value in (inference_env or {}).items():
        source[name] = value
        credential_names.append(name)
    record = {
        "mode": config.mode,
        "enforcement": "environment_hints" if config.mode == "none" else config.mode,
        "dropped_variables": dropped,
        "offline_hints": applied_hints,
        "inference_env_names": credential_names,
        "notes": [
            "environment variables are hints, not a boundary; the live probe decides eligibility"
        ],
    }
    return source, record


__all__ = [
    "EgressProbeResult",
    "ProbeTarget",
    "build_agent_environment",
    "probe_egress",
]
