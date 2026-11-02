from __future__ import annotations

import random
from pathlib import Path

import pytest

from vulnmirage.errors import GenerationError
from vulnmirage.manipulations.base import ChangePlan, ManipulationOperator, OperatorTools, PlannedFile
from vulnmirage.manipulations.m6_hybrid import CompositeOperator
from vulnmirage.models import AttackGoal, ManipulationTier


class _FixedFileOperator(ManipulationOperator):
    name = "FixedFileOperator"
    tier = ManipulationTier.M2_SEMANTIC_CLAIM
    strategy_family = "fixed"
    carriers = ("markdown",)

    def __init__(self, tools, path: str):
        super().__init__(tools)
        self.path = path

    def supports(self, context) -> bool:
        return True

    def plan(self, repo_root, oracle, spec, rng):
        return ChangePlan(
            operator_name=self.name,
            tier=self.tier,
            files=[
                PlannedFile(
                    path=self.path,
                    mode="create",
                    content="# claim\n",
                    carrier="markdown",
                )
            ],
            allowed_paths=[self.path],
        )


class _FixedFileOperator2(_FixedFileOperator):
    name = "FixedFileOperator2"


def test_composite_rejects_conflicting_write_sets(tmp_path: Path) -> None:
    tools = OperatorTools(registry=None, payload_dir=tmp_path)  # type: ignore[arg-type]
    children = [
        _FixedFileOperator(tools, "SECURITY.md"),
        _FixedFileOperator2(tools, "SECURITY.md"),
    ]
    composite = CompositeOperator(tools, children)
    with pytest.raises(GenerationError) as excinfo:
        composite.plan(tmp_path, None, None, random.Random(1))
    assert "conflicting" in excinfo.value.message


def test_composite_requires_two_distinct_children(tmp_path: Path) -> None:
    tools = OperatorTools(registry=None, payload_dir=tmp_path)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        CompositeOperator(tools, [_FixedFileOperator(tools, "a.md")])
    with pytest.raises(ValueError):
        CompositeOperator(
            tools,
            [_FixedFileOperator(tools, "a.md"), _FixedFileOperator(tools, "b.md")],
        )
