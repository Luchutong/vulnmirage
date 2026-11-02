"""Small-sample statistics and paired bootstrap confidence intervals."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from pydantic import BaseModel, ConfigDict, Field


class MetricEstimate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    numerator: float | int | None = None
    denominator: float | int | None = None
    estimate: float | None = None
    ci_low: float | None = None
    ci_high: float | None = None
    method: str = "wilson"
    notes: list[str] = Field(default_factory=list)


def _z(level: float) -> float:
    # Normal quantile approximation sufficient for the common 0.90/0.95/0.99.
    table = {0.90: 1.6448536269514722, 0.95: 1.959963984540054, 0.99: 2.5758293035489004}
    return table.get(round(level, 2), 1.959963984540054)


def wilson_interval(successes: int, total: int, *, level: float = 0.95) -> tuple[float | None, float | None]:
    if total <= 0:
        return None, None
    z = _z(level)
    phat = successes / total
    denominator = 1 + z * z / total
    centre = (phat + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * total)) / total) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def proportion_estimate(
    name: str,
    successes: int,
    total: int,
    *,
    level: float = 0.95,
    notes: list[str] | None = None,
) -> MetricEstimate:
    low, high = wilson_interval(successes, total, level=level)
    return MetricEstimate(
        name=name,
        numerator=successes,
        denominator=total,
        estimate=successes / total if total else None,
        ci_low=low,
        ci_high=high,
        method="wilson",
        notes=notes or [],
    )


def bootstrap_ci(
    values: Sequence[float],
    *,
    samples: int = 1000,
    level: float = 0.95,
    seed: int = 0,
    statistic: Callable[[Sequence[float]], float | None] | None = None,
) -> tuple[float | None, float | None]:
    if not values:
        return None, None
    rng = random.Random(seed)
    stat = statistic or (lambda sample: sum(sample) / len(sample) if sample else None)
    estimates: list[float] = []
    n = len(values)
    for _ in range(max(samples, 100)):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        value = stat(sample)
        if value is not None and math.isfinite(value):
            estimates.append(value)
    if not estimates:
        return None, None
    estimates.sort()
    alpha = (1 - level) / 2
    low_index = min(len(estimates) - 1, max(0, int(alpha * len(estimates))))
    high_index = min(len(estimates) - 1, max(0, int((1 - alpha) * len(estimates)) - 1))
    return estimates[low_index], estimates[high_index]


def paired_bootstrap_ci(
    pairs: Sequence[tuple[float, float]],
    *,
    samples: int = 1000,
    level: float = 0.95,
    seed: int = 0,
    statistic: Callable[[Sequence[tuple[float, float]]], float | None] | None = None,
) -> tuple[float | None, float | None]:
    if not pairs:
        return None, None

    def default(sample: Sequence[tuple[float, float]]) -> float | None:
        values = [left - right for left, right in sample]
        return sum(values) / len(values) if values else None

    stat = statistic or default
    rng = random.Random(seed)
    estimates: list[float] = []
    n = len(pairs)
    for _ in range(max(samples, 100)):
        sample = [pairs[rng.randrange(n)] for _ in range(n)]
        value = stat(sample)
        if value is not None and math.isfinite(value):
            estimates.append(value)
    if not estimates:
        return None, None
    estimates.sort()
    alpha = (1 - level) / 2
    return (
        estimates[min(len(estimates) - 1, max(0, int(alpha * len(estimates))))],
        estimates[min(len(estimates) - 1, max(0, int((1 - alpha) * len(estimates)) - 1))],
    )


def cluster_bootstrap_ci(
    clusters: dict[str, Sequence[float]],
    *,
    samples: int = 1000,
    level: float = 0.95,
    seed: int = 0,
    statistic: Callable[[Sequence[float]], float | None] | None = None,
) -> tuple[float | None, float | None]:
    """Bootstrap over *clusters* (repository/oracle), not individual runs.

    Multiple payloads or repeated runs of the same oracle are not independent
    samples; resampling clusters preserves that dependence.
    """
    usable = {key: list(values) for key, values in clusters.items() if values}
    if not usable:
        return None, None
    keys = sorted(usable)
    rng = random.Random(seed)
    stat = statistic or (lambda sample: sum(sample) / len(sample) if sample else None)
    estimates: list[float] = []
    for _ in range(max(samples, 100)):
        sampled_keys = [keys[rng.randrange(len(keys))] for _ in keys]
        values = [value for key in sampled_keys for value in usable[key]]
        value = stat(values)
        if value is not None and math.isfinite(value):
            estimates.append(value)
    if not estimates:
        return None, None
    estimates.sort()
    alpha = (1 - level) / 2
    low = estimates[min(len(estimates) - 1, max(0, int(alpha * len(estimates))))]
    high = estimates[
        min(len(estimates) - 1, max(0, int((1 - alpha) * len(estimates)) - 1))
    ]
    return low, high


def cluster_key(row: dict[str, Any]) -> str:
    repository = row.get("repository") or row.get("repo_url") or "unknown"
    oracle = row.get("oracle_id") or row.get("pair_id") or "unknown"
    return f"{repository}|{oracle}"


def repository_cluster_key(row: dict[str, Any]) -> str:
    """Cluster by repository only (P1-2).

    Targets, variants and repetitions of one repository stay together: five
    repeats of one target are not five independent benchmark samples.
    """
    return str(row.get("repository") or row.get("repo_url") or "unknown")


def repository_cluster_bootstrap(
    rows: Sequence[dict[str, Any]],
    *,
    field: str,
    samples: int = 1000,
    level: float = 0.95,
    seed: int = 0,
) -> dict[str, Any]:
    """Repository-cluster bootstrap interval for a 0/1 row field."""
    clusters: dict[str, list[float]] = {}
    for row in rows:
        value = row.get(field)
        if value is None:
            continue
        clusters.setdefault(repository_cluster_key(row), []).append(
            1.0 if value else 0.0
        )
    low, high = cluster_bootstrap_ci(
        clusters, samples=samples, level=level, seed=seed
    )
    usable = {key: values for key, values in clusters.items() if values}
    total = sum(len(values) for values in usable.values())
    estimate = (
        sum(sum(values) for values in usable.values()) / total if total else None
    )
    return {
        "name": field,
        "cluster_key": "repository",
        "clusters": len(usable),
        "observations": total,
        "samples": max(samples, 100),
        "seed": seed,
        "confidence_level": level,
        "estimate": estimate,
        "ci_low": low,
        "ci_high": high,
        "method": "repository_cluster_bootstrap",
    }


def _binom_two_sided(k: int, n: int) -> float:
    if n == 0:
        return 1.0
    p = 0.5
    probabilities = [math.comb(n, i) * (p**i) * ((1 - p) ** (n - i)) for i in range(n + 1)]
    observed = probabilities[k]
    return min(1.0, sum(value for value in probabilities if value <= observed + 1e-12))


def mcnemar_test(before: Sequence[bool], after: Sequence[bool]) -> dict[str, Any]:
    if len(before) != len(after):
        raise ValueError("paired sequences must have equal length")
    b = sum(1 for left, right in zip(before, after) if left and not right)
    c = sum(1 for left, right in zip(before, after) if not left and right)
    n = b + c
    p_value = _binom_two_sided(b, n) if n else 1.0
    risk_difference = (b - c) / len(before) if before else None
    odds_ratio = (b / c) if c else None
    return {
        "discordant_b": b,
        "discordant_c": c,
        "n": len(before),
        "p_value": p_value,
        "risk_difference": risk_difference,
        "odds_ratio": odds_ratio,
        "method": "exact_binomial_mcnemar",
    }


def wilcoxon_signed_rank(differences: Sequence[float]) -> dict[str, Any]:
    nonzero = [value for value in differences if value != 0]
    if not nonzero:
        return {"n": 0, "statistic": None, "p_value": None, "median_difference": 0.0, "method": "wilcoxon_normal_approx"}
    absolute = sorted((abs(value), index) for index, value in enumerate(nonzero))
    ranks = [0.0] * len(nonzero)
    ties: dict[float, int] = {}
    for rank, (value, index) in enumerate(absolute, start=1):
        ranks[index] = rank
        ties[value] = ties.get(value, 0) + 1
    positive = sum(ranks[index] for index, value in enumerate(nonzero) if value > 0)
    negative = sum(ranks[index] for index, value in enumerate(nonzero) if value < 0)
    n = len(nonzero)
    mean = n * (n + 1) / 4
    tie_correction = sum(count**3 - count for count in ties.values())
    variance = n * (n + 1) * (2 * n + 1) / 24 - tie_correction / 48
    if variance <= 0:
        p_value = 1.0
    else:
        z_value = (positive - mean) / math.sqrt(variance)
        p_value = math.erfc(abs(z_value) / math.sqrt(2))
    ordered = sorted(nonzero)
    median = ordered[len(ordered) // 2] if len(ordered) % 2 else (
        ordered[len(ordered) // 2 - 1] + ordered[len(ordered) // 2]
    ) / 2
    return {
        "n": n,
        "statistic": min(positive, negative),
        "p_value": min(1.0, p_value),
        "median_difference": median,
        "method": "wilcoxon_normal_approx_tie_corrected",
    }


def holm_correction(p_values: Sequence[float]) -> list[float]:
    count = len(p_values)
    order = sorted(range(count), key=lambda index: p_values[index])
    adjusted = [1.0] * count
    running = 0.0
    for rank, index in enumerate(order):
        value = min(1.0, (count - rank) * p_values[index])
        running = max(running, value)
        adjusted[index] = running
    return adjusted


def benjamini_hochberg(p_values: Sequence[float]) -> list[float]:
    count = len(p_values)
    order = sorted(range(count), key=lambda index: p_values[index])
    adjusted = [1.0] * count
    running = 1.0
    for rank in range(count - 1, -1, -1):
        index = order[rank]
        value = min(running, p_values[index] * count / (rank + 1))
        running = value
        adjusted[index] = value
    return adjusted


def adjust_p_values(p_values: Sequence[float], method: str) -> list[float]:
    if method == "holm":
        return holm_correction(p_values)
    if method in {"bh", "benjamini-hochberg"}:
        return benjamini_hochberg(p_values)
    return list(p_values)
