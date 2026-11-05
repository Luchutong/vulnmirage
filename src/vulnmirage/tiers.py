"""The T0-T4 capability ladder, as a single shared definition.

Tiers describe **what information and feedback a generator may use**, not how
strong an attack is (design §3).  Keeping the definition in one module matters:
``config`` validates a declared tier, ``payloadgen`` refuses to realize a tier it
has no generator for, and the campaign records the tier with every run.  If those
three drifted apart, a plan could claim T2 while the pipeline quietly rendered a
T0 template -- exactly the silent downgrade the design forbids.
"""

from __future__ import annotations

from typing import Literal

TIERS: tuple[str, ...] = ("T0", "T1", "T2", "T3", "T4")

#: Ordinal position; used for "this tier or above" checks, never for scoring.
TIER_INDEX: dict[str, int] = {name: index for index, name in enumerate(TIERS)}

Tier = Literal["T0", "T1", "T2", "T3", "T4"]

#: Tiers that may see a sanitized ``OracleAttackView``.
ORACLE_VIEW_TIERS: frozenset[str] = frozenset({"T2", "T3", "T4"})

#: Tiers that may receive the public repository index.  T0 uses it only for a
#: deterministic, non-targeted carrier location; T1+ may adapt to structure.
INDEXED_TIERS: frozenset[str] = frozenset({"T0", "T1", "T2", "T3", "T4"})

#: Tiers implemented in this build.  Everything else fails closed.
IMPLEMENTED_TIERS: frozenset[str] = frozenset({"T0", "T1", "T2"})

#: Tiers that may not be used for formal repetitions yet (no generator + protocol).
PLANNED_TIERS: frozenset[str] = frozenset({"T3", "T4"})


def tier_at_least(tier: str, floor: str) -> bool:
    return TIER_INDEX.get(tier, -1) >= TIER_INDEX.get(floor, 99)


def is_implemented(tier: str) -> bool:
    return tier in IMPLEMENTED_TIERS


__all__ = [
    "IMPLEMENTED_TIERS",
    "INDEXED_TIERS",
    "ORACLE_VIEW_TIERS",
    "PLANNED_TIERS",
    "TIERS",
    "TIER_INDEX",
    "Tier",
    "is_implemented",
    "tier_at_least",
]
