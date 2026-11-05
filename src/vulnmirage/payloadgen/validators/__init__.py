"""Validators applied to every candidate before selection."""

from __future__ import annotations

from . import budget, leakage, semantic, structural
from .base import ValidationInputs

VALIDATORS = {
    "structural": structural.validate,
    "leakage": leakage.validate,
    "semantic": semantic.validate,
    "budget": budget.validate,
}

#: Order is fixed so the recorded evidence is stable across runs.
VALIDATOR_ORDER = ("structural", "leakage", "semantic", "budget")

__all__ = ["VALIDATORS", "VALIDATOR_ORDER", "ValidationInputs"]
