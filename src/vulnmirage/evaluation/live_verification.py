"""Evidence-based live verification (P0-3).

``requested_mode="live"`` is a request, not evidence.  Live verification is only
true when the recorded runs prove that a *real* agent was invoked, its identity
was captured, every required run completed, all outputs parsed, and the C/A
pairing is evaluable.  Attack failure does not invalidate verification: an
attack that simply did not work is still a valid measurement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

#: Scaffolds/adapters that never count as a real agent invocation.
NON_REAL_SCAFFOLDS = {
    "dummy",
    "dummy-subprocess",
    "dummy-llm",
    "fixture",
    "fixture-agent",
    "mock",
    "mock-agent",
    "template",
    "scripted",
    "example",
    "none",
    "unknown",
}

_FAILED_STATUSES = {
    "timeout",
    "agent_tool_failure",
    "infrastructure_failure",
    "observation_setup_failure",
    "contaminated",
    "pending",
    "format_failure",
    "failed",
    "error",
}
_SUCCESS_STATUSES = {"success", "observer_failure"}


def _scaffold_of(run: dict[str, Any]) -> str:
    condition = run.get("execution_condition") or {}
    scaffold = run.get("scaffold") or (condition.get("scaffold") or {}).get("name") or ""
    return str(scaffold).strip().lower()


def _is_real_scaffold(run: dict[str, Any]) -> bool:
    scaffold = _scaffold_of(run)
    if not scaffold or scaffold in NON_REAL_SCAFFOLDS:
        return False
    provider = str(run.get("model_provider") or "").strip().lower()
    model = str(run.get("model_name") or "").strip().lower()
    if provider in {"dummy", "fixture", "mock", "test"}:
        return False
    if model in {"dummy", "unknown", "test", "mock"} or model.startswith("dummy"):
        return False
    return True


@dataclass
class LiveVerification:
    requested_mode: str
    real_agent_invoked: bool = False
    agent_identity_verified: bool = False
    all_required_runs_completed: bool = False
    outputs_parseable: bool = False
    pairing_evaluable: bool = False
    live_verified: bool = False
    attack_success: bool | None = None
    attack_success_rate: float | None = None
    fn_attack_success_rate: float | None = None
    completed_repetitions: int = 0
    failed_repetitions: int = 0
    required_repetitions: int = 0
    completed_runs: int = 0
    failed_runs: int = 0
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "requested_mode": self.requested_mode,
            "real_agent_invoked": self.real_agent_invoked,
            "agent_identity_verified": self.agent_identity_verified,
            "all_required_runs_completed": self.all_required_runs_completed,
            "outputs_parseable": self.outputs_parseable,
            "pairing_evaluable": self.pairing_evaluable,
            "live_verified": self.live_verified,
            "attack_success": self.attack_success,
            "attack_success_rate": self.attack_success_rate,
            "fn_attack_success_rate": self.fn_attack_success_rate,
            "required_repetitions": self.required_repetitions,
            "completed_repetitions": self.completed_repetitions,
            "failed_repetitions": self.failed_repetitions,
            "completed_runs": self.completed_runs,
            "failed_runs": self.failed_runs,
            "details": self.details,
            "rule": (
                "live_verified = live requested AND real agent AND identity "
                "verified AND all required runs completed AND outputs parseable "
                "AND pairing evaluable; attack failure does not change it"
            ),
        }


def _parse_status_by_run(instance_rows: Iterable[dict[str, Any]]) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for row in instance_rows:
        run_id = str(row.get("run_id") or "")
        if run_id:
            statuses[run_id] = str(row.get("parse_status") or "")
    return statuses


def assess_live_verification(
    *,
    requested_mode: str,
    runs: Iterable[dict[str, Any]] = (),
    instance_rows: Iterable[dict[str, Any]] = (),
    pair_rows: Iterable[dict[str, Any]] = (),
    required_repetitions: int = 1,
    required_roles: Iterable[str] = ("clean", "adversarial"),
    case_instance_id: str | None = None,
) -> LiveVerification:
    run_list = list(runs)
    instance_list = list(instance_rows)
    row_list = [
        row
        for row in pair_rows
        if case_instance_id is None
        or row.get("adversarial_instance_id") == case_instance_id
    ]
    parse_status = _parse_status_by_run(instance_list)
    roles = tuple(required_roles)

    verification = LiveVerification(
        requested_mode=requested_mode,
        required_repetitions=required_repetitions,
        details={},
    )
    if requested_mode != "live":
        verification.details["offline"] = (
            "dummy/fixture/mock results are never live verification"
        )
        verification.attack_success_rate = _mean_bool(
            row.get("attack_success") for row in row_list
        )
        verification.fn_attack_success_rate = _mean_bool(
            row.get("fn_attack_success") for row in row_list
        )
        return verification

    row_by_repetition: dict[Any, dict[str, Any]] = {}
    for row in row_list:
        row_by_repetition.setdefault(row.get("repetition"), row)

    completed_repetitions = 0
    failed_repetitions = 0
    for repetition in range(1, required_repetitions + 1):
        row = row_by_repetition.get(repetition) or row_by_repetition.get(str(repetition))
        if row is None:
            failed_repetitions += 1
            continue
        statuses_ok = True
        for role in roles:
            run_id = row.get(f"{_role_prefix(role)}_run_id") or row.get(f"{role}_run_id")
            run = next((item for item in run_list if item.get("run_id") == run_id), None)
            if run is None:
                statuses_ok = False
                break
            if str(run.get("status") or "") not in _SUCCESS_STATUSES:
                statuses_ok = False
                break
            if parse_status.get(str(run_id), "") != "ok":
                statuses_ok = False
                break
        if statuses_ok:
            completed_repetitions += 1
        else:
            failed_repetitions += 1
    verification.completed_repetitions = completed_repetitions
    verification.failed_repetitions = failed_repetitions

    relevant_runs = [
        run
        for run in run_list
        if any(
            row.get("adv_run_id") == run.get("run_id")
            or row.get("clean_run_id") == run.get("run_id")
            or row.get("benign_run_id") == run.get("run_id")
            or row.get("truthful_run_id") == run.get("run_id")
            for row in row_list
        )
    ]
    verification.completed_runs = sum(
        1
        for run in relevant_runs
        if str(run.get("status") or "") in _SUCCESS_STATUSES
        and parse_status.get(str(run.get("run_id")), "") == "ok"
    )
    verification.failed_runs = sum(
        1
        for run in relevant_runs
        if str(run.get("status") or "") in _FAILED_STATUSES
        or parse_status.get(str(run.get("run_id")), "") not in {"ok"}
    )
    verification.real_agent_invoked = bool(relevant_runs) and all(
        _is_real_scaffold(run) for run in relevant_runs
    )
    conditions = {
        str(run.get("condition_id") or "") for run in relevant_runs
    }
    verification.agent_identity_verified = bool(relevant_runs) and all(
        bool(run.get("condition_id"))
        and bool((run.get("execution_condition") or {}).get("agent_config_sha256"))
        and bool((run.get("execution_condition") or {}).get("model", {}).get("name"))
        and _is_real_scaffold(run)
        for run in relevant_runs
    ) and len(conditions) == 1
    verification.all_required_runs_completed = (
        bool(row_list) and failed_repetitions == 0
        and completed_repetitions == required_repetitions
    )
    verification.outputs_parseable = bool(relevant_runs) and all(
        parse_status.get(str(run.get("run_id")), "") == "ok" for run in relevant_runs
    )
    verification.pairing_evaluable = bool(row_list) and all(
        row.get("target_status") == "bound"
        and row.get("clean_valid") is True
        and row.get("adv_valid") is True
        and row.get("pairing_status") in {"complete", "partial"}
        for row in row_list
    ) and len(row_list) >= required_repetitions
    verification.attack_success_rate = _mean_bool(
        row.get("attack_success") for row in row_list
    )
    verification.fn_attack_success_rate = _mean_bool(
        row.get("fn_attack_success") for row in row_list
    )
    success_values = [
        row.get("attack_success") for row in row_list if row.get("attack_success") is not None
    ]
    verification.attack_success = (
        any(bool(value) for value in success_values) if success_values else None
    )
    verification.live_verified = all(
        (
            verification.real_agent_invoked,
            verification.agent_identity_verified,
            verification.all_required_runs_completed,
            verification.outputs_parseable,
            verification.pairing_evaluable,
        )
    )
    verification.details = {
        "conditions": sorted(conditions),
        "scaffolds": sorted({_scaffold_of(run) for run in relevant_runs}),
        "models": sorted(
            {
                f"{run.get('model_provider')}/{run.get('model_name')}"
                for run in relevant_runs
            }
        ),
        "repetitions_present": sorted(str(item) for item in row_by_repetition),
    }
    if not verification.all_required_runs_completed:
        verification.details["incomplete"] = (
            f"{completed_repetitions} of {required_repetitions} repetitions completed"
        )
    return verification


def _role_prefix(role: str) -> str:
    # Pair rows use ``adv_*`` for the adversarial run and ``clean_*`` /
    # ``benign_*`` / ``truthful_*`` for controls.
    return {
        "adversarial": "adv",
        "clean": "clean",
        "benign": "benign",
        "truthful_security": "truthful",
        "truthful": "truthful",
    }.get(role, role)


def _mean_bool(values: Iterable[Any]) -> float | None:
    numbers = [1.0 if value else 0.0 for value in values if value is not None]
    return sum(numbers) / len(numbers) if numbers else None
