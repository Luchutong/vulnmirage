"""Paired aggregation over stored runs (design §19).

Nothing here re-runs an agent or a generator.  The function reads the frozen
artefacts of a campaign and reports:

* per-condition detection/decoy outcomes;
* paired clean-vs-attacked deltas, with the repository kept as the clustering unit;
* a bootstrap interval over the paired deltas, so a two-task pilot cannot be read
  as an effect;
* an explicit **attrition ledger** -- planned conditions that never got a manifest,
  runs that were ineligible, runs without a trace.  A method's generation-failure
  rate is part of its usability, so it is reported next to its effect instead of
  being dropped from the denominator.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..hashing import utc_now_iso

AGGREGATE_SCHEMA_VERSION = "1.0"


class ConditionOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str
    condition_id: str
    variant_id: str
    target_ref: str | None = None
    tier: str = "T0"
    kind: str = "attack"
    runs: int = 0
    scored_runs: int = 0
    detected: int = 0
    targets: int = 0
    recall: float | None = None
    recall_by_repetition: dict[str, float] = Field(default_factory=dict)
    missed_ids: list[str] = Field(default_factory=list)
    missed_ids_by_repetition: dict[str, list[str]] = Field(default_factory=dict)
    certified_decoys: int = 0
    accepted_decoys: int = 0
    accepted_decoys_by_repetition: dict[str, int] = Field(default_factory=dict)
    severity_deltas: list[int] = Field(default_factory=list)
    trace_status: list[str] = Field(default_factory=list)


class PairedComparison(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str
    clean_variant_id: str
    attacked_variant_id: str
    target_ref: str | None = None
    tier: str
    clean_recall: float | None = None
    attacked_recall: float | None = None
    recall_delta: float | None = None
    recall_deltas: list[float] = Field(default_factory=list)
    paired_repetitions: list[int] = Field(default_factory=list)
    hidden_target_ids: list[str] = Field(default_factory=list)
    induced_decoy_ids: list[str] = Field(default_factory=list)
    severity_shift: float | None = None
    interpretation: str = ""


class LossLedger(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conditions_planned: int = 0
    conditions_generated: int = 0
    generation_failures: list[str] = Field(default_factory=list)
    candidates_total: int = 0
    candidates_blocked: int = 0
    runs: int = 0
    invalid_runs: list[str] = Field(default_factory=list)
    ineligible_runs: list[str] = Field(default_factory=list)
    missing_trace_runs: list[str] = Field(default_factory=list)


class AggregateResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = AGGREGATE_SCHEMA_VERSION
    campaign: str
    created_at: str = Field(default_factory=utc_now_iso)
    tasks: list[str] = Field(default_factory=list)
    conditions: list[ConditionOutcome] = Field(default_factory=list)
    pairs: list[PairedComparison] = Field(default_factory=list)
    by_tier: dict[str, dict[str, float]] = Field(default_factory=dict)
    losses: LossLedger = Field(default_factory=LossLedger)
    bootstrap: dict[str, dict[str, float]] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


def _read_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:  # pragma: no cover - corrupt artefact
        return {}


def bootstrap_ci(
    values: list[float], *, iterations: int = 1000, seed: int = 0
) -> dict[str, float]:
    """Percentile bootstrap over paired deltas.  Empty input stays empty."""
    if not values:
        return {}
    rng = random.Random(seed)
    n = len(values)
    means: list[float] = []
    for _ in range(max(1, iterations)):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()
    low = means[int(0.025 * (len(means) - 1))]
    high = means[int(0.975 * (len(means) - 1))]
    return {
        "n": float(n),
        "mean": round(sum(values) / n, 6),
        "ci_low": round(low, 6),
        "ci_high": round(high, 6),
    }


def _runs_of(archive: Path) -> list[dict]:
    runs: list[dict] = []
    run_root = archive / "runs"
    if not run_root.is_dir():
        return runs
    for run_dir in sorted(p for p in run_root.iterdir() if p.is_dir()):
        record = _read_json(run_dir / "run.json")
        if record:
            runs.append(record)
    return runs


def _condition_outcomes(
    archive: Path, task_id: str, plan_variants: list[dict]
) -> list[ConditionOutcome]:
    from ..campaign.plan import PlanVariant  # noqa: F401

    runs = _runs_of(archive)
    outcomes: list[ConditionOutcome] = []
    for variant in plan_variants:
        variant_id = str(variant.get("variant_id"))
        relevant = [item for item in runs if str(item.get("variant_id")) == variant_id]
        detected = 0
        targets = 0
        recall: float | None = None
        recalls: dict[str, float] = {}
        missed: set[str] = set()
        missed_by_repetition: dict[str, list[str]] = {}
        decoys = 0
        accepted = 0
        accepted_by_repetition: dict[str, int] = {}
        severity_deltas: list[int] = []
        trace_status: list[str] = []
        scored_runs = 0
        for record in relevant:
            run_id = str(record.get("run_id"))
            trace_status.append(str(record.get("trace_completeness") or "missing"))
            score = _read_json(archive / "evaluation" / run_id / "score.json")
            if not score or score.get("scored") is not True:
                continue
            scored_runs += 1
            repetition = str(int(record.get("repetition") or 1))
            detection = score.get("detection") or {}
            targets += int(detection.get("targets") or 0)
            detected += int(detection.get("detected") or 0)
            if detection.get("recall") is not None:
                recalls[repetition] = float(detection["recall"])
            run_missed = sorted(str(item) for item in detection.get("missed_ids") or [])
            missed_by_repetition[repetition] = run_missed
            missed.update(run_missed)
            fp = score.get("false_positive") or {}
            decoys += int(fp.get("certified_decoys") or 0)
            run_accepted = int(fp.get("accepted") or 0)
            accepted += run_accepted
            accepted_by_repetition[repetition] = run_accepted
            severity_deltas.extend(
                int(item["delta"])
                for item in (score.get("severity") or {}).get("deltas") or []
                if isinstance(item, dict) and item.get("delta") is not None
            )
        if recalls:
            recall = sum(recalls.values()) / len(recalls)
        outcomes.append(
            ConditionOutcome(
                task_id=task_id,
                condition_id=str(variant.get("condition_id") or variant_id),
                variant_id=variant_id,
                target_ref=variant.get("target_ref"),
                tier=str(variant.get("tier") or "T0"),
                kind=str(variant.get("kind") or "attack"),
                runs=len(relevant),
                scored_runs=scored_runs,
                detected=detected,
                targets=targets,
                recall=recall,
                recall_by_repetition=dict(sorted(recalls.items(), key=lambda item: int(item[0]))),
                missed_ids=sorted(missed),
                missed_ids_by_repetition=dict(
                    sorted(missed_by_repetition.items(), key=lambda item: int(item[0]))
                ),
                certified_decoys=decoys,
                accepted_decoys=accepted,
                accepted_decoys_by_repetition=dict(
                    sorted(accepted_by_repetition.items(), key=lambda item: int(item[0]))
                ),
                severity_deltas=sorted(severity_deltas),
                trace_status=sorted(set(trace_status)),
            )
        )
    return outcomes


def _pairs(outcomes: list[ConditionOutcome]) -> list[PairedComparison]:
    clean_by_target = {
        item.target_ref: item for item in outcomes if item.kind == "clean"
    }
    pairs: list[PairedComparison] = []
    if not clean_by_target:
        return pairs
    for attacked in outcomes:
        if attacked.kind == "clean":
            continue
        clean = clean_by_target.get(attacked.target_ref)
        if clean is None:
            continue
        common_repetitions = sorted(
            set(clean.recall_by_repetition) & set(attacked.recall_by_repetition),
            key=int,
        )
        deltas = [
            round(
                clean.recall_by_repetition[item]
                - attacked.recall_by_repetition[item],
                6,
            )
            for item in common_repetitions
        ]
        delta = round(sum(deltas) / len(deltas), 6) if deltas else None
        hidden_set: set[str] = set()
        for repetition in common_repetitions:
            hidden_set.update(
                set(attacked.missed_ids_by_repetition.get(repetition, []))
                - set(clean.missed_ids_by_repetition.get(repetition, []))
            )
        hidden = sorted(hidden_set)
        shift = None
        if attacked.severity_deltas and clean.severity_deltas:
            shift = round(
                sum(attacked.severity_deltas) / len(attacked.severity_deltas)
                - sum(clean.severity_deltas) / len(clean.severity_deltas),
                3,
            )
        pairs.append(
            PairedComparison(
                task_id=attacked.task_id,
                clean_variant_id=clean.variant_id,
                attacked_variant_id=attacked.variant_id,
                target_ref=attacked.target_ref,
                tier=attacked.tier,
                clean_recall=clean.recall,
                attacked_recall=attacked.recall,
                recall_delta=delta,
                recall_deltas=deltas,
                paired_repetitions=[int(item) for item in common_repetitions],
                hidden_target_ids=hidden,
                induced_decoy_ids=(
                    []
                    if not any(
                        attacked.accepted_decoys_by_repetition.get(item, 0)
                        > clean.accepted_decoys_by_repetition.get(item, 0)
                        for item in common_repetitions
                    )
                    else [attacked.variant_id]
                ),
                severity_shift=shift,
                interpretation=(
                    "paired within one task; a difference here is not an effect until the "
                    "isolation and trace checks for both runs passed"
                ),
            )
        )
    return pairs


def _losses(archive: Path, outcomes: list[ConditionOutcome]) -> LossLedger:
    generation = _read_json(archive / "generation" / "generation_manifest.json")
    conditions = generation.get("conditions") or []
    manifests = sorted((archive / "generation" / "manifests").glob("*.json"))
    blocked = 0
    total = 0
    for manifest_path in manifests:
        manifest = _read_json(manifest_path)
        total += len(manifest.get("candidates") or [])
        for validation in manifest.get("validations") or []:
            if any(
                item.get("required") and item.get("status") != "pass"
                for item in validation.get("results") or []
            ):
                blocked += 1
    runs = _runs_of(archive)
    invalid: list[str] = []
    for item in runs:
        run_id = str(item.get("run_id"))
        status = str(item.get("execution_status") or "not_run")
        score = _read_json(archive / "evaluation" / run_id / "score.json")
        if status != "success" or score.get("scored") is not True:
            invalid.append(run_id)
    ineligible = [
        str(item.get("run_id"))
        for item in runs
        if not str(item.get("isolation_eligibility") or "").startswith("eligible")
    ]
    missing_trace = [
        str(item.get("run_id"))
        for item in runs
        if str(item.get("trace_completeness")) in {"missing", "unknown", "disabled"}
    ]
    planned = len(conditions)
    return LossLedger(
        conditions_planned=planned,
        conditions_generated=len(manifests),
        generation_failures=[
            str(item.get("variant_id"))
            for item in conditions
            if item.get("generation") not in {"not_generated", None}
            and not item.get("selected_candidate")
        ],
        candidates_total=total,
        candidates_blocked=blocked,
        runs=len(runs),
        invalid_runs=sorted(set(invalid)),
        ineligible_runs=sorted(set(ineligible)),
        missing_trace_runs=sorted(set(missing_trace)),
    )


def aggregate_campaign(
    workspace: str | Path,
    *,
    tasks: list[str] | None = None,
    iterations: int = 1000,
    seed: int = 0,
) -> AggregateResult:
    """Aggregate one campaign root. Never mutates the archived artefacts."""
    root = Path(workspace)
    plan = _read_json(root / "control" / "plan.json")
    planned_tasks = plan.get("tasks") or []
    selected = {item for item in tasks} if tasks else None
    conditions: list[ConditionOutcome] = []
    pairs: list[PairedComparison] = []
    losses = LossLedger()
    seen_tasks: list[str] = []
    for task in planned_tasks:
        task_id = str(task.get("task_id"))
        if selected is not None and task_id not in selected:
            continue
        archive = root / "archives" / task_id
        outcomes = _condition_outcomes(archive, task_id, task.get("variants") or [])
        conditions.extend(outcomes)
        pairs.extend(_pairs(outcomes))
        task_losses = _losses(archive, outcomes)
        losses.conditions_planned += task_losses.conditions_planned
        losses.conditions_generated += task_losses.conditions_generated
        losses.candidates_total += task_losses.candidates_total
        losses.candidates_blocked += task_losses.candidates_blocked
        losses.runs += task_losses.runs
        losses.generation_failures.extend(task_losses.generation_failures)
        losses.invalid_runs.extend(task_losses.invalid_runs)
        losses.ineligible_runs.extend(task_losses.ineligible_runs)
        losses.missing_trace_runs.extend(task_losses.missing_trace_runs)
        seen_tasks.append(task_id)

    by_tier: dict[str, dict[str, float]] = {}
    bootstrap: dict[str, dict[str, float]] = {}
    for tier in sorted({pair.tier for pair in pairs}):
        tier_pairs = [pair for pair in pairs if pair.tier == tier]
        deltas = [pair.recall_delta for pair in tier_pairs if pair.recall_delta is not None]
        task_deltas: dict[str, list[float]] = {}
        for pair in tier_pairs:
            if pair.recall_delta is not None:
                task_deltas.setdefault(pair.task_id, []).append(pair.recall_delta)
        clustered = [sum(items) / len(items) for items in task_deltas.values()]
        hidden = [float(len(pair.hidden_target_ids)) for pair in tier_pairs]
        by_tier[tier] = {
            "pairs": float(len(tier_pairs)),
            "mean_recall_delta": round(sum(deltas) / len(deltas), 6) if deltas else 0.0,
            "mean_hidden_targets": round(sum(hidden) / len(hidden), 3) if hidden else 0.0,
        }
        bootstrap[tier] = bootstrap_ci(clustered, iterations=iterations, seed=seed)

    return AggregateResult(
        campaign=root.as_posix(),
        tasks=seen_tasks,
        conditions=conditions,
        pairs=pairs,
        by_tier=by_tier,
        losses=losses,
        bootstrap=bootstrap,
        notes=[
            "pairing is within one task; the repository is the clustering unit",
            "a generation failure counts against the method, it is not dropped from the denominator",
            "the bootstrap interval describes this sample of tasks, not the population of repositories",
        ],
    )


__all__ = [
    "AGGREGATE_SCHEMA_VERSION",
    "AggregateResult",
    "ConditionOutcome",
    "LossLedger",
    "PairedComparison",
    "aggregate_campaign",
    "bootstrap_ci",
]
