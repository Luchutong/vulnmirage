"""Credential *name* plumbing for agent subprocesses (P0-2).

Only variable **names** ever leave this module.  Values are read from the parent
process environment at the moment the child environment is built and are never
written into argv, logs, run JSON, condition identity, error details or reports.

The three facts a doctor run must report are kept apart:

* ``declared``  – the name appears in ``credential_env_allowlist``;
* ``present``   – the parent process environment has a non-empty value;
* ``forwarded`` – the prepared child environment will contain the variable.

A live run refuses to start when a declared credential is missing and the
agent declares ``credential_policy: required``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Iterable

from .errors import HarnessError


def normalize_names(names: Iterable[str] | None) -> list[str]:
    """Return declared credential names in a stable order (never values)."""
    cleaned = []
    for name in names or []:
        text = str(name).strip()
        if text and text not in cleaned:
            cleaned.append(text)
    return cleaned


def declared_names(agent_config: Any) -> list[str]:
    return normalize_names(getattr(agent_config, "credential_env_allowlist", None))


def present_names(names: Iterable[str]) -> list[str]:
    return [name for name in normalize_names(names) if os.environ.get(name)]


def missing_names(names: Iterable[str]) -> list[str]:
    return [name for name in normalize_names(names) if not os.environ.get(name)]


def credential_policy(agent_config: Any) -> str:
    policy = getattr(agent_config, "credential_policy", "required") or "required"
    return policy if policy in {"required", "optional"} else "required"


@dataclass
class CredentialStatus:
    """Name-only credential report (safe to log and serialise)."""

    declared: list[str] = field(default_factory=list)
    present: list[str] = field(default_factory=list)
    forwarded: list[str] = field(default_factory=list)
    policy: str = "required"

    @property
    def missing(self) -> list[str]:
        return [name for name in self.declared if name not in self.present]

    @property
    def satisfied(self) -> bool:
        return not self.missing or self.policy == "optional"

    def as_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "declared": list(self.declared),
            "present": list(self.present),
            "missing": self.missing,
            "forwarded": list(self.forwarded),
            "values_are_never_logged": True,
            "note": (
                "names only: declared by the agent YAML, present in the parent "
                "environment, and forwarded to the child process"
            ),
        }

    def forwarded_status(self) -> list[dict[str, object]]:
        """Per-variable triple used by ``vulnmirage doctor``."""
        return [
            {
                "name": name,
                "declared": name in self.declared,
                "present": name in self.present,
                "forwarded": name in self.forwarded,
            }
            for name in self.declared
        ]


def inspect_credentials(
    agent_config: Any, *, forwarded: Iterable[str] | None = None
) -> CredentialStatus:
    declared = declared_names(agent_config)
    present = present_names(declared)
    return CredentialStatus(
        declared=declared,
        present=present,
        forwarded=normalize_names(forwarded if forwarded is not None else present),
        policy=credential_policy(agent_config),
    )


def ensure_credentials(agent_config: Any, *, context: str = "live run") -> CredentialStatus:
    """Fail before the agent starts when a required credential is missing.

    The raised error is an infrastructure failure and lists *names* only.
    """
    status = inspect_credentials(agent_config)
    if not status.satisfied:
        raise HarnessError(
            f"{context}: required credential environment variables are not set",
            details={
                "failure_type": "credentials_missing",
                "missing": status.missing,
                "declared": status.declared,
                "policy": status.policy,
                "values_are_never_logged": True,
            },
        )
    return status
