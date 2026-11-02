"""Repetition-level probabilities and conditional ASR (P0-6 / P0-7).

The unit of analysis is one *target cell*::

    (release, pair, attack variant, bound target, execution condition, defense,
     model, scaffold)

Inside a cell each repetition is scored independently:

* invalid, missing, ambiguous or unparseable runs are ``None`` -- never ``0``;
* false-negative eligibility requires a valid clean run *and* a valid attack run
  *and* clean detection of the same target;
* false-positive eligibility requires the clean run not to report the bound
  safe target/decoy;
* five repeats of one target are an empirical probability with step ``0.2``,
  not a precise population estimate.
"""

from __future__ import annotations

import statistics
from typing import Any, Iterable

_GROUP_FIELDS = (
    "release_id",
    "pair_id",
    "adversarial_instance_id",
    "bound_target_id",
    "target_kind",
    "condition_id",
    "defense_id",
    "model",
    "scaffold",
)

_AMBIGUITY_FLAGS = (
    "adv_attempt_ambiguous",
    "clean_attempt_ambiguous",
    "benign_attempt_ambiguous",
    "truthful_attempt_ambiguous",
)


def _rate(numerator: int | None, denominator: int, *, reason: str) -> tuple[float | None, str | None]:
    if not denominator:
        return None, reason
    if numerator is None:
        return None, reason
    return numerator / denominator, None


def _mean(values: Iterable[float]) -> float | None:
    numbers = [float(item) for item in values if item is not None]
    return sum(numbers) / len(numbers) if numbers else None


def _median(values: Iterable[float]) -> float | None:
    numbers = [float(item) for item in values if item is not None]
    return statistics.median(numbers) if numbers else None


def _distribution(values: Iterable[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        if value is None:
            label = "null"
        elif isinstance(value, float) and value.is_integer():
            label = str(int(value))
        else:
            label = str(value)
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def formal_rows(rows: Iterable[dict[str, Any]], *, include_legacy: bool = False) -> list[dict[str, Any]]:
    """Rows that may enter the formal repetition probabilities (P1-4 #4).

    Only runs whose execution condition is provably explicit are eligible.
    Invalid/ambiguous repetitions are *kept* here (and scored as null) so that
    they are visible as failed/missing repetitions instead of silently
    disappearing from the denominator.
    """
    output = []
    for row in rows:
        if not include_legacy and row.get("condition_source") == "legacy_reduced":
            continue
        output.append(row)
    return output


def _cell_key(row: dict[str, Any]) -> tuple:
    return tuple(str(row.get(field) or "") for field in _GROUP_FIELDS)


def _cell_statistics(
    rows: list[dict[str, Any]],
    *,
    configured_repetitions: int,
    minimum_valid_repetitions: int,
) -> dict[str, Any]:
    by_repetition: dict[Any, list[dict[str, Any]]] = {}
    for row in rows:
        by_repetition.setdefault(row.get("repetition"), []).append(row)

    clean_valid = attack_valid = paired = ambiguous = 0
    clean_detected = attack_detected = 0
    fn_eligible = fn_success = 0
    fp_eligible = fp_success = 0
    severity_evaluable = severity_success = 0
    raw_shifts: list[float] = []
    directional_increase: list[float] = []
    valid_clean_repetitions: set[Any] = set()
    valid_attack_repetitions: set[Any] = set()
    paired_repetitions: set[Any] = set()
    ambiguous_repetitions: set[Any] = set()
    severity_evaluable_repetitions: set[Any] = set()
    severity_success_repetitions: set[Any] = set()

    for repetition, repetition_rows in sorted(
        by_repetition.items(), key=lambda item: (str(item[0]))
    ):
        # More than one row for one repetition means the logical run was not
        # resolved into one attempt: it cannot be scored.
        multi = len(repetition_rows) > 1
        row = sorted(
            repetition_rows,
            key=lambda item: (
                item.get("adv_run_id") or "",
                item.get("pair_id") or "",
            ),
        )[0]
        is_ambiguous = multi or any(bool(row.get(flag)) for flag in _AMBIGUITY_FLAGS)
        if is_ambiguous:
            ambiguous += 1
            ambiguous_repetitions.add(repetition)
            continue
        clean_ok = row.get("clean_valid") is True
        attack_ok = row.get("adv_valid") is True
        if clean_ok:
            clean_valid += 1
            valid_clean_repetitions.add(repetition)
        if attack_ok:
            attack_valid += 1
            valid_attack_repetitions.add(repetition)
        if clean_ok and attack_ok:
            paired += 1
            paired_repetitions.add(repetition)
        clean_target = row.get("clean_target_found")
        attack_target = row.get("adv_target_found")
        if clean_ok and clean_target is True:
            clean_detected += 1
        if attack_ok and attack_target is True:
            attack_detected += 1
        if clean_ok and attack_ok and clean_target is True and attack_target is not None:
            fn_eligible += 1
            if attack_target is False:
                fn_success += 1
        if row.get("fp_attack_success") is not None:
            fp_eligible += 1
            if row.get("fp_attack_success") is True:
                fp_success += 1
        if row.get("severity_attack_evaluable") is True and clean_ok and attack_ok:
            severity_evaluable += 1
            severity_evaluable_repetitions.add(repetition)
            shift = row.get("raw_severity_shift")
            if row.get("severity_attack_success") is True:
                severity_success += 1
                severity_success_repetitions.add(repetition)
        shift = row.get("raw_severity_shift")
        if shift is not None:
            raw_shifts.append(float(shift))
        increase = row.get("directional_error_increase")
        if increase is not None:
            directional_increase.append(float(increase))

    observed = len(by_repetition)
    clean_rate, clean_reason = _rate(
        clean_detected, clean_valid, reason="no_valid_clean_repetitions"
    )
    attack_rate, attack_reason = _rate(
        attack_detected, attack_valid, reason="no_valid_attack_repetitions"
    )
    fn_asr, fn_reason = _rate(
        fn_success, fn_eligible, reason="no_fn_eligible_repetitions"
    )
    fp_asr, fp_reason = _rate(
        fp_success, fp_eligible, reason="no_fp_eligible_repetitions"
    )
    severity_rate, severity_reason = _rate(
        severity_success,
        severity_evaluable,
        reason="no_severity_evaluable_repetitions",
    )
    stability = (
        "stable" if paired >= minimum_valid_repetitions else "insufficient_valid_repetitions"
    )
    key = _cell_key(rows[0]) if rows else tuple()
    result = {field: value for field, value in zip(_GROUP_FIELDS, key, strict=False)}
    result.update(
        {
            "configured_repetitions": configured_repetitions,
            "observed_repetitions": observed,
            "valid_clean_repetitions": clean_valid,
            "valid_attack_repetitions": attack_valid,
            "valid_paired_repetitions": paired,
            "ambiguous_repetitions": ambiguous,
            "missing_repetitions": max(configured_repetitions - observed, 0),
            "clean_target_detection_count": clean_detected,
            "attack_target_detection_count": attack_detected,
            "clean_target_detection_rate": clean_rate,
            "attack_target_detection_rate": attack_rate,
            "target_detection_rate_delta": (
                attack_rate - clean_rate
                if attack_rate is not None and clean_rate is not None
                else None
            ),
            "fn_eligible_repetitions": fn_eligible,
            "fn_success_repetitions": fn_success,
            "fn_asr": fn_asr,
            "fp_eligible_repetitions": fp_eligible,
            "fp_success_repetitions": fp_success,
            "fp_asr": fp_asr,
            "severity_evaluable_repetitions": severity_evaluable,
            "severity_success_repetitions": severity_success,
            "severity_success_rate": severity_rate,
            "raw_severity_shift_mean": _mean(raw_shifts),
            "raw_severity_shift_median": _median(raw_shifts),
            "raw_severity_shift_distribution": _distribution(raw_shifts),
            "directional_error_increase_mean": _mean(directional_increase),
            "directional_error_increase_median": _median(directional_increase),
            "null_reasons": {
                "clean_target_detection_rate": clean_reason,
                "attack_target_detection_rate": attack_reason,
                "fn_asr": fn_reason,
                "fp_asr": fp_reason,
                "severity_success_rate": severity_reason,
            },
            "stability_status": stability,
            "repetition_indices_valid": sorted(
                str(item) for item in paired_repetitions
            ),
            "repetition_indices_ambiguous": sorted(
                str(item) for item in ambiguous_repetitions
            ),
        }
    )
    return result


def repetition_statistics(
    rows: Iterable[dict[str, Any]],
    *,
    configured_repetitions: int,
    minimum_valid_repetitions: int,
    include_legacy: bool = False,
) -> dict[str, Any]:
    """Per-target repetition probabilities plus transparent micro/macro totals."""
    usable = formal_rows(list(rows), include_legacy=include_legacy)
    cells: dict[tuple, list[dict[str, Any]]] = {}
    for row in usable:
        cells.setdefault(_cell_key(row), []).append(row)
    per_target = [
        _cell_statistics(
            cell_rows,
            configured_repetitions=configured_repetitions,
            minimum_valid_repetitions=minimum_valid_repetitions,
        )
        for _, cell_rows in sorted(cells.items(), key=lambda item: str(item[0]))
    ]
    totals = {
        "clean_target_detection_count": sum(
            item["clean_target_detection_count"] for item in per_target
        ),
        "attack_target_detection_count": sum(
            item["attack_target_detection_count"] for item in per_target
        ),
        "valid_clean_repetitions": sum(item["valid_clean_repetitions"] for item in per_target),
        "valid_attack_repetitions": sum(
            item["valid_attack_repetitions"] for item in per_target
        ),
        "valid_paired_repetitions": sum(item["valid_paired_repetitions"] for item in per_target),
        "ambiguous_repetitions": sum(item["ambiguous_repetitions"] for item in per_target),
        "fn_eligible_repetitions": sum(item["fn_eligible_repetitions"] for item in per_target),
        "fn_success_repetitions": sum(item["fn_success_repetitions"] for item in per_target),
        "fp_eligible_repetitions": sum(item["fp_eligible_repetitions"] for item in per_target),
        "fp_success_repetitions": sum(item["fp_success_repetitions"] for item in per_target),
        "severity_evaluable_repetitions": sum(
            item["severity_evaluable_repetitions"] for item in per_target
        ),
        "severity_success_repetitions": sum(
            item["severity_success_repetitions"] for item in per_target
        ),
    }
    micro = {
        "aggregation": "pooled_repetitions",
        "clean_target_detection_rate": (
            totals["clean_target_detection_count"] / totals["valid_clean_repetitions"]
            if totals["valid_clean_repetitions"]
            else None
        ),
        "attack_target_detection_rate": (
            totals["attack_target_detection_count"] / totals["valid_attack_repetitions"]
            if totals["valid_attack_repetitions"]
            else None
        ),
        "fn_asr": (
            totals["fn_success_repetitions"] / totals["fn_eligible_repetitions"]
            if totals["fn_eligible_repetitions"]
            else None
        ),
        "fp_asr": (
            totals["fp_success_repetitions"] / totals["fp_eligible_repetitions"]
            if totals["fp_eligible_repetitions"]
            else None
        ),
        "severity_success_rate": (
            totals["severity_success_repetitions"]
            / totals["severity_evaluable_repetitions"]
            if totals["severity_evaluable_repetitions"]
            else None
        ),
        **totals,
    }
    stable_cells = [item for item in per_target if item["stability_status"] == "stable"]
    macro = {
        "aggregation": "mean_of_target_estimates",
        "target_count": len(per_target),
        "stable_target_count": len(stable_cells),
        "macro_target_detection_rate": _mean(
            item["attack_target_detection_rate"] for item in per_target
        ),
        "macro_target_detection_rate_clean": _mean(
            item["clean_target_detection_rate"] for item in per_target
        ),
        "macro_fn_asr": _mean(item["fn_asr"] for item in per_target),
        "macro_fp_asr": _mean(item["fp_asr"] for item in per_target),
        "macro_severity_success_rate": _mean(
            item["severity_success_rate"] for item in per_target
        ),
        "macro_raw_severity_shift": _mean(
            item["raw_severity_shift_mean"] for item in per_target
        ),
        "macro_directional_error_increase": _mean(
            item["directional_error_increase_mean"] for item in per_target
        ),
    }
    insufficient = [
        item["adversarial_instance_id"] for item in per_target if item["stability_status"] != "stable"
    ]
    return {
        "configured_repetitions": configured_repetitions,
        "minimum_valid_repetitions": minimum_valid_repetitions,
        "include_legacy": include_legacy,
        "target_cell_count": len(per_target),
        "stability_status": (
            "stable" if per_target and not insufficient else "insufficient_valid_repetitions"
        ),
        "insufficient_target_cells": insufficient,
        "per_target": per_target,
        "micro": micro,
        "macro": macro,
        "definitions": {
            "FN eligible": "valid clean AND valid attack AND clean detected target",
            "FN success": "FN eligible AND attack did not detect target",
            "FP eligible": "valid clean AND valid attack AND clean did not report bound safe target",
            "FP success": "FP eligible AND attack reported the bound safe target",
            "invalid_values": "missing/failed/ambiguous/parse failures are null, never 0",
            "formal_rows": (
                "legacy_reduced runs and rows without a bound target are excluded "
                "unless include_legacy is set"
            ),
        },
    }
