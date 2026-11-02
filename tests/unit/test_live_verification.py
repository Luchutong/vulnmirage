"""P0-3: live verification is computed from evidence, never from mode=live."""

from __future__ import annotations

from vulnmirage.evaluation.live_verification import assess_live_verification

_HEX = "a" * 64


def _run(
    run_id: str,
    *,
    scaffold: str = "opencode",
    provider: str = "custom",
    model: str = "deepseek-v4-pro",
    status: str = "success",
    condition_id: str = _HEX,
    agent_config_sha256: str = _HEX,
) -> dict:
    return {
        "run_id": run_id,
        "scaffold": scaffold,
        "model_provider": provider,
        "model_name": model,
        "status": status,
        "condition_id": condition_id,
        "execution_condition": {
            "agent_config_sha256": agent_config_sha256,
            "model": {"provider": provider, "name": model},
            "scaffold": {"name": scaffold},
        },
    }


def _instance_row(run_id: str, parse_status: str = "ok") -> dict:
    return {"run_id": run_id, "parse_status": parse_status, "valid_run": True}


def _pair(
    repetition: int,
    *,
    attack_success: bool,
    fn: bool | None,
    pairing_status: str = "complete",
    target_status: str = "bound",
) -> dict:
    return {
        "repetition": repetition,
        "adversarial_instance_id": "VM-A1",
        "clean_run_id": f"RUN-C-{repetition}",
        "adv_run_id": f"RUN-A-{repetition}",
        "benign_run_id": None,
        "truthful_run_id": None,
        "target_status": target_status,
        "pairing_status": pairing_status,
        "clean_valid": True,
        "adv_valid": True,
        "attack_success": attack_success,
        "fn_attack_success": fn,
        "clean_target_found": True,
        "adv_target_found": not attack_success,
    }


def test_live_mode_with_dummy_scaffold_and_failure_is_not_verified() -> None:
    runs = [
        _run("RUN-C-1", scaffold="dummy", provider="dummy", model="dummy-auditor", status="agent_tool_failure"),
        _run("RUN-A-1", scaffold="dummy", provider="dummy", model="dummy-auditor", status="agent_tool_failure"),
    ]
    instance_rows = [_instance_row("RUN-C-1", "not_attempted"), _instance_row("RUN-A-1", "not_attempted")]
    pairs = [_pair(1, attack_success=False, fn=None)]
    result = assess_live_verification(
        requested_mode="live",
        runs=runs,
        instance_rows=instance_rows,
        pair_rows=pairs,
        required_repetitions=1,
    ).as_dict()
    assert result["requested_mode"] == "live"
    assert result["real_agent_invoked"] is False
    assert result["outputs_parseable"] is False
    assert result["live_verified"] is False


def test_real_identity_but_unparseable_output_is_not_verified() -> None:
    runs = [_run("RUN-C-1"), _run("RUN-A-1")]
    instance_rows = [
        _instance_row("RUN-C-1", "ok"),
        _instance_row("RUN-A-1", "format_failure"),
    ]
    pairs = [_pair(1, attack_success=False, fn=True)]
    result = assess_live_verification(
        requested_mode="live",
        runs=runs,
        instance_rows=instance_rows,
        pair_rows=pairs,
        required_repetitions=1,
    ).as_dict()
    assert result["real_agent_invoked"] is True
    assert result["agent_identity_verified"] is True
    assert result["outputs_parseable"] is False
    assert result["live_verified"] is False


def test_five_successful_runs_with_failed_attacks_are_verified() -> None:
    runs: list[dict] = []
    instance_rows: list[dict] = []
    pairs: list[dict] = []
    for repetition in range(1, 6):
        runs.append(_run(f"RUN-C-{repetition}"))
        runs.append(_run(f"RUN-A-{repetition}"))
        instance_rows.extend(
            [_instance_row(f"RUN-C-{repetition}"), _instance_row(f"RUN-A-{repetition}")]
        )
        pairs.append(_pair(repetition, attack_success=False, fn=True))
    result = assess_live_verification(
        requested_mode="live",
        runs=runs,
        instance_rows=instance_rows,
        pair_rows=pairs,
        required_repetitions=5,
    ).as_dict()
    assert result["completed_repetitions"] == 5
    assert result["failed_repetitions"] == 0
    assert result["real_agent_invoked"] is True
    assert result["agent_identity_verified"] is True
    assert result["all_required_runs_completed"] is True
    assert result["outputs_parseable"] is True
    assert result["pairing_evaluable"] is True
    assert result["live_verified"] is True
    assert result["attack_success_rate"] == 0.0
    assert result["attack_success"] is False


def test_partial_repetitions_are_reported_not_verified() -> None:
    runs = []
    instance_rows = []
    pairs = []
    for repetition in (1, 2, 3):
        runs.append(_run(f"RUN-C-{repetition}"))
        runs.append(_run(f"RUN-A-{repetition}"))
        instance_rows.extend(
            [_instance_row(f"RUN-C-{repetition}"), _instance_row(f"RUN-A-{repetition}")]
        )
        pairs.append(_pair(repetition, attack_success=False, fn=True))
    result = assess_live_verification(
        requested_mode="live",
        runs=runs,
        instance_rows=instance_rows,
        pair_rows=pairs,
        required_repetitions=5,
    ).as_dict()
    assert result["completed_repetitions"] == 3
    assert result["failed_repetitions"] == 2
    assert result["all_required_runs_completed"] is False
    assert result["live_verified"] is False


def test_offline_results_are_never_live_verified() -> None:
    runs = [_run("RUN-C-1"), _run("RUN-A-1")]
    instance_rows = [_instance_row("RUN-C-1"), _instance_row("RUN-A-1")]
    pairs = [_pair(1, attack_success=True, fn=False)]
    result = assess_live_verification(
        requested_mode="offline",
        runs=runs,
        instance_rows=instance_rows,
        pair_rows=pairs,
        required_repetitions=1,
    ).as_dict()
    assert result["live_verified"] is False
    assert result["attack_success_rate"] == 1.0


def test_ambiguous_pairing_is_not_evaluable() -> None:
    runs = [_run("RUN-C-1"), _run("RUN-A-1")]
    instance_rows = [_instance_row("RUN-C-1"), _instance_row("RUN-A-1")]
    pairs = [_pair(1, attack_success=False, fn=None, pairing_status="not_evaluable")]
    result = assess_live_verification(
        requested_mode="live",
        runs=runs,
        instance_rows=instance_rows,
        pair_rows=pairs,
        required_repetitions=1,
    ).as_dict()
    assert result["pairing_evaluable"] is False
    assert result["live_verified"] is False
