"""Execution-condition identity for exact clean/attack pairing (P0-1).

A benchmark comparison is only meaningful when the adversarial run and its
control run were produced by the *same* execution condition: same model,
scaffold, effective agent configuration, audit prompt, defense, tool/network
policy and inference budget.  Pairing on ``instance_id`` alone silently mixes
different models, configurations or defenses whenever they share a run
directory.

This module defines one serialisable identity:

``(release_id, instance_id, condition_id, repetition)``

``condition_id`` is the SHA-256 of a canonical, credential-free descriptor.
Only the *names* of credential environment variables are recorded, never their
values.  External files referenced by the agent configuration (an OpenCode JSON
config or an external prompt) are represented by content hashes so that editing
them changes identity even when the agent YAML is unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from ..hashing import canonical_json, sha256_text

CONDITION_SCHEMA_VERSION = "1"

#: Bumped whenever the descriptor layout changes; written into every run.
_LATEST = CONDITION_SCHEMA_VERSION

_ATTEMPT_RE = re.compile(r"-b(?P<attempt>\d+)$")


def _clean(value: Any) -> Any:
    """Recursively normalise a descriptor for hashing.

    ``None`` and empty containers are dropped so that an unspecified optional
    field does not create a spurious condition.  Values are never interpreted as
    credentials here; callers must not put secrets in the descriptor.
    """
    if isinstance(value, dict):
        output = {}
        for key in sorted(value):
            item = _clean(value[key])
            if item is None or item == "" or item == [] or item == {}:
                continue
            output[str(key)] = item
        return output
    if isinstance(value, (list, tuple, set)):
        items = [_clean(item) for item in value]
        return [item for item in items if item is not None and item != ""]
    return value


def build_execution_condition(
    *,
    model_provider: str,
    model_name: str,
    model_version: str | None,
    scaffold: str,
    scaffold_version: str | None,
    agent_config_sha256: str | None = None,
    agent_config_semantic_sha256: str | None = None,
    external_file_sha256: dict[str, str] | None = None,
    task_prompt_sha256: str | None = None,
    base_prompt_sha256: str | None = None,
    defense_instructions_sha256: str | None = None,
    effective_prompt_sha256: str | None = None,
    defense: dict[str, Any] | None = None,
    tool_policy: dict[str, Any] | None = None,
    network_enabled: bool | None = None,
    token_budget: int | None = None,
    time_budget_seconds: int | None = None,
    inference: dict[str, Any] | None = None,
    credential_env_names: list[str] | None = None,
    isolation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical, public execution-condition descriptor."""
    return _clean(
        {
            "schema_version": _LATEST,
            "model": {
                "provider": model_provider,
                "name": model_name,
                "version": model_version,
            },
            "scaffold": {"name": scaffold, "version": scaffold_version},
            "agent_config_sha256": agent_config_sha256,
            "agent_config_semantic_sha256": agent_config_semantic_sha256,
            "external_file_sha256": dict(sorted((external_file_sha256 or {}).items())),
            "prompt": {
                "task_sha256": task_prompt_sha256,
                "base_sha256": base_prompt_sha256,
                "defense_sha256": defense_instructions_sha256,
                "effective_sha256": effective_prompt_sha256,
            },
            "defense": defense,
            "tool_policy": tool_policy,
            "network_enabled": network_enabled,
            "budgets": {
                "token_budget": token_budget,
                "time_budget_seconds": time_budget_seconds,
            },
            "inference": inference,
            # Presence of a credential is part of the execution environment, but
            # its value must never enter public records.
            "credential_env_names": sorted(set(credential_env_names or [])),
            "isolation": isolation,
        }
    )


def condition_id(descriptor: dict[str, Any] | None) -> str | None:
    if not descriptor:
        return None
    normalized = _clean(descriptor)
    if not normalized:
        return None
    return sha256_text(canonical_json(normalized))


def legacy_condition(
    *,
    model_provider: str,
    model_name: str,
    model_version: str | None,
    scaffold: str,
    scaffold_version: str | None,
    agent_config_sha256: str | None,
    prompt_sha256: str | None,
    network_enabled: bool,
    time_budget_seconds: int,
    token_budget: int | None,
) -> dict[str, Any]:
    """Reduced identity for runs recorded before condition metadata existed.

    The reduced descriptor deliberately excludes everything that was never
    persisted (external config hashes, defense, inference parameters).  Runs
    resolved this way are marked ``condition_source="legacy_reduced"`` and
    ``condition_complete=False``; they are only paired with other legacy runs
    whose reduced fields match.  A report must surface that limitation.
    """
    return _clean(
        {
            "schema_version": f"{_LATEST}-legacy-reduced",
            "legacy_reduced": True,
            "model": {
                "provider": model_provider,
                "name": model_name,
                "version": model_version,
            },
            "scaffold": {"name": scaffold, "version": scaffold_version},
            "agent_config_sha256": agent_config_sha256,
            "prompt_sha256": prompt_sha256,
            "network_enabled": network_enabled,
            "budgets": {
                "time_budget_seconds": time_budget_seconds,
                "token_budget": token_budget,
            },
        }
    )


ConditionSource = Literal["explicit", "run_meta", "legacy_reduced", "missing"]


@dataclass(frozen=True)
class ResolvedCondition:
    condition_id: str | None
    source: ConditionSource
    descriptor: dict[str, Any] = field(default_factory=dict)
    complete: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def pairable(self) -> bool:
        return self.condition_id is not None


def resolve_condition(run, meta=None) -> ResolvedCondition:
    """Resolve a run's execution condition, preferring explicit metadata.

    * ``run.execution_condition`` (written by the current harness) wins;
    * ``meta.execution_condition`` is the next authority;
    * otherwise a *declared* reduced identity is derived from required run
      fields.  If even that is unavailable the run is not pairable.
    """
    notes: list[str] = []
    explicit = getattr(run, "execution_condition", None) or {}
    if explicit:
        cid = getattr(run, "condition_id", None)
        computed = condition_id(explicit)
        if cid and computed and cid != computed:
            return ResolvedCondition(
                condition_id=None,
                source="explicit",
                descriptor=explicit,
                complete=False,
                notes=[
                    "stored condition_id does not match its descriptor; refusing to pair"
                ],
            )
        return ResolvedCondition(
            condition_id=cid or computed,
            source="explicit",
            descriptor=explicit,
            complete=True,
        )
    meta_descriptor = getattr(meta, "execution_condition", None) or {}
    if meta_descriptor:
        cid = getattr(meta, "condition_id", None) or condition_id(meta_descriptor)
        computed = condition_id(meta_descriptor)
        if cid and computed and cid != computed:
            return ResolvedCondition(
                condition_id=None,
                source="run_meta",
                descriptor=meta_descriptor,
                complete=False,
                notes=[
                    "run metadata condition_id does not match its descriptor; refusing to pair"
                ],
            )
        return ResolvedCondition(
            condition_id=cid or computed,
            source="run_meta",
            descriptor=meta_descriptor,
            complete=True,
        )
    agent_sha = getattr(meta, "agent_config_sha256", None) if meta is not None else None
    descriptor = legacy_condition(
        model_provider=run.model_provider,
        model_name=run.model_name,
        model_version=run.model_version,
        scaffold=run.scaffold,
        scaffold_version=run.scaffold_version,
        agent_config_sha256=agent_sha,
        prompt_sha256=run.prompt_sha256,
        network_enabled=run.network_enabled,
        time_budget_seconds=run.time_budget_seconds,
        token_budget=run.token_budget,
    )
    if not agent_sha:
        notes.append(
            "legacy run has no agent_config_sha256; effective agent configuration "
            "cannot be proven identical"
        )
    return ResolvedCondition(
        condition_id=condition_id(descriptor),
        source="legacy_reduced",
        descriptor=descriptor,
        complete=False,
        notes=notes,
    )


def attempt_number(run_id: str) -> int:
    """Attempt index encoded by the harness (``RUN-...`` is attempt 1)."""
    match = _ATTEMPT_RE.search(run_id or "")
    return int(match.group("attempt")) if match else 1


@dataclass
class AttemptChoice:
    run: Any
    attempt: int
    excluded: list[dict[str, Any]] = field(default_factory=list)
    rule: str = ""
    ambiguous: bool = False
    reason: str | None = None


_ATTEMPT_RULES = {"none", "first_attempt", "last_attempt", "first_evaluable"}


def _is_evaluable_run(item) -> bool:
    """Infrastructure-level evaluability, never audit outcome quality.

    A broken attempt (parse/transport/infrastructure failure) is not
    preferentially selected over a completed one, because its findings are not
    comparable.  This inspects *run status*, not whether the target was found.
    """
    run = getattr(item, "run", item)
    status = getattr(run, "status", "")
    parse_status = getattr(item, "parse_status", None)
    if status in {
        "timeout",
        "agent_tool_failure",
        "infrastructure_failure",
        "observer_failure",
        "contaminated",
        "pending",
    }:
        return False
    if parse_status is not None and parse_status != "ok":
        return False
    return True


def select_attempt(
    candidates: list,
    *,
    rule: str = "first_evaluable",
) -> AttemptChoice | None:
    """Deterministically choose one attempt for a logical run.

    Rules are infrastructure-only and declared in the experiment protocol.
    Duplicate attempt numbers are treated as ambiguous rather than resolved by
    directory iteration order.
    """
    if not candidates:
        return None
    if rule not in _ATTEMPT_RULES:
        raise ValueError(f"unknown attempt selection rule {rule!r}")
    numbered = []
    seen: dict[int, list] = {}
    for item in candidates:
        run = getattr(item, "run", item)
        number = attempt_number(getattr(run, "run_id", ""))
        numbered.append((number, item))
        seen.setdefault(number, []).append(item)
    duplicates = {number: items for number, items in seen.items() if len(items) > 1}
    if duplicates:

        def _run_id(item) -> str:
            return getattr(getattr(item, "run", item), "run_id", "")

        # Two distinct runs claim the same attempt index: no deterministic
        # choice can be justified, so the logical run is not evaluable.
        first = min(candidates, key=_run_id)
        excluded = [
            {
                "run_id": _run_id(item),
                "attempt": attempt_number(_run_id(item)),
                "reason": "duplicate_attempt_index",
            }
            for item in candidates
            if item is not first
        ]
        return AttemptChoice(
            run=first,
            attempt=attempt_number(_run_id(first)),
            excluded=excluded,
            rule=rule,
            ambiguous=True,
            reason="duplicate_attempt_index",
        )
    numbered.sort(key=lambda pair: (pair[0], getattr(getattr(pair[1], "run", pair[1]), "run_id", "")))
    if rule == "none":
        # No pre-registered retry rule: more than one attempt cannot be resolved
        # without looking at outcomes, so the logical run is not evaluable.
        if len(numbered) > 1:
            def _id(item) -> str:
                return getattr(getattr(item, "run", item), "run_id", "")

            first = min(candidates, key=_id)
            return AttemptChoice(
                run=first,
                attempt=attempt_number(_id(first)),
                excluded=[
                    {
                        "run_id": _id(item),
                        "attempt": attempt_number(_id(item)),
                        "reason": "attempt_selection_not_preregistered",
                    }
                    for item in candidates
                    if item is not first
                ],
                rule=rule,
                ambiguous=True,
                reason="attempt_selection_not_preregistered",
            )
        chosen = numbered[0]
    elif rule == "first_attempt":
        chosen = numbered[0]
    elif rule == "last_attempt":
        chosen = numbered[-1]
    else:  # first_evaluable
        evaluable = [pair for pair in numbered if _is_evaluable_run(pair[1])]
        chosen = evaluable[0] if evaluable else numbered[0]
    excluded = [
        {
            "run_id": getattr(getattr(item, "run", item), "run_id", None),
            "attempt": number,
            "reason": "attempt_not_selected",
        }
        for number, item in numbered
        if item is not chosen[1]
    ]
    return AttemptChoice(
        run=chosen[1],
        attempt=chosen[0],
        excluded=excluded,
        rule=rule,
    )
