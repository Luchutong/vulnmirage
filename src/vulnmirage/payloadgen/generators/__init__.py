"""Tier generators.  Each module is a function of a :class:`GeneratorContext`."""

from __future__ import annotations

from . import model_guided, oracle_guided, repository_adaptive, static

GENERATOR_BY_TIER = {
    "T0": static,
    "T1": repository_adaptive,
    "T2": oracle_guided,
    "T3": model_guided,
    "T4": model_guided,
}

GENERATOR_BY_NAME = {
    "static_template": static,
    "repository_adaptive": repository_adaptive,
    "oracle_guided": oracle_guided,
    "surrogate_optimized": model_guided,
    "victim_blackbox": model_guided,
}

__all__ = [
    "GENERATOR_BY_NAME",
    "GENERATOR_BY_TIER",
    "model_guided",
    "oracle_guided",
    "repository_adaptive",
    "static",
]
