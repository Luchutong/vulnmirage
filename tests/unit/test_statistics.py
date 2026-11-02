"""Statistics primitives used by the four-layer report."""

from __future__ import annotations

import pytest

from vulnmirage.evaluation.statistics import (
    bootstrap_ci,
    cluster_bootstrap_ci,
    cluster_key,
    holm_correction,
    mcnemar_test,
    proportion_estimate,
    wilcoxon_signed_rank,
)


def test_wilson_interval_is_bounded() -> None:
    estimate = proportion_estimate("asr", 3, 10)
    assert estimate.estimate == pytest.approx(0.3)
    assert 0.0 <= estimate.ci_low < estimate.estimate < estimate.ci_high <= 1.0


def test_mcnemar_counts_discordant_pairs() -> None:
    result = mcnemar_test([True, True, False, False], [False, True, True, False])
    assert result["discordant_b"] == 1
    assert result["discordant_c"] == 1
    assert 0 <= result["p_value"] <= 1


def test_holm_correction_is_monotone() -> None:
    adjusted = holm_correction([0.01, 0.02, 0.5])
    assert adjusted[0] == pytest.approx(0.03)
    assert adjusted[1] == pytest.approx(0.04)
    assert adjusted[2] == pytest.approx(0.5)


def test_wilcoxon_and_bootstrap_are_deterministic() -> None:
    first = wilcoxon_signed_rank([1, 1, 1, -1])
    second = wilcoxon_signed_rank([1, 1, 1, -1])
    assert first["p_value"] == second["p_value"]
    low, high = bootstrap_ci([0.0, 1.0, 2.0], samples=300, seed=7)
    low_again, high_again = bootstrap_ci([0.0, 1.0, 2.0], samples=300, seed=7)
    assert (low, high) == (low_again, high_again)
    assert low <= high


def test_cluster_bootstrap_resamples_repositories_not_runs() -> None:
    # Three oracles; oracle A has many correlated runs (same repository).
    clusters = {
        "repo-a|A": [1.0, 1.0, 1.0, 1.0, 1.0],
        "repo-a|B": [1.0],
        "repo-b|C": [0.0],
    }
    low, high = cluster_bootstrap_ci(clusters, samples=500, seed=3)
    assert low is not None and high is not None
    assert low <= high
    # Resampling runs (not clusters) would understate the variance of this
    # design; the cluster interval must include the all-A sample mean 1.0.
    assert high == pytest.approx(1.0)
    assert low <= 0.6


def test_cluster_key_uses_repository_and_oracle() -> None:
    assert cluster_key({"repository": "r", "oracle_id": "o"}) == "r|o"
    assert cluster_key({"repo_url": "r", "pair_id": "p"}) == "r|p"

