"""Structural benign controls mirror the attack without misleading content."""

from __future__ import annotations

import random
import re
import shutil
from pathlib import Path

import pytest

from tests.fixture_repo import create_fixture_repo
from tests.support import make_test_config
from vulnmirage.code_semantics import compare_semantics
from vulnmirage.generation.benign import benign_plan, neutral_text
from vulnmirage.generation.payload_registry import load_payload_registry
from vulnmirage.ingest.base import build_oracle, read_jsonl
from vulnmirage.manipulations.base import OperatorTools
from vulnmirage.manipulations.m1_direct import AddDirectAuditInstruction, InsertDirectComment
from vulnmirage.models import AttackGoal, ManipulationSpec

_FORBIDDEN = re.compile(
    r"\b(audit|vulnerab\w*|security|exploit\w*|saniti\w*|remediat\w*|"
    r"cve-\d+|ignore\w*|out of scope|report\w*|finding\w*)\b",
    re.I,
)


@pytest.fixture(scope="module")
def fixture(tmp_path_factory):
    return create_fixture_repo(tmp_path_factory.mktemp("benign"))


@pytest.fixture(scope="module")
def oracle(fixture):
    reports = read_jsonl(fixture.reports_path)
    entries = [record for _, record in read_jsonl(fixture.entries_path)]
    return build_oracle(reports[0][1], entries, dataset_name="fixture")


@pytest.fixture(scope="module")
def tools(project_root: Path):
    registry, base_dir = load_payload_registry(project_root / "payloads" / "registry.yaml")
    return OperatorTools(registry=registry, payload_dir=base_dir)


@pytest.fixture(scope="module")
def loaded(tmp_path_factory, project_root: Path):
    return make_test_config(
        tmp_path_factory.mktemp("benign-config"), project_root, workspace_name="ws-benign"
    )


def _spec(operator, oracle, goal):
    return ManipulationSpec(
        manipulation_id="VMAN-BENIGN",
        designed_tier=operator.tier,
        attack_goal=goal,
        strategy_family=operator.strategy_family,
        mechanism=operator.mechanism,
        carriers=list(operator.carriers),
        operator_names=[operator.name],
        target_vulnerability_ids=[v.vulnerability_id for v in oracle.vulnerabilities],
        expected_effect=operator.expected_effect,
    )


def test_neutral_text_contains_no_security_claims() -> None:
    text = neutral_text(240, seed=1)
    assert text
    assert not _FORBIDDEN.search(text)


@pytest.mark.parametrize(
    "operator_cls",
    [InsertDirectComment, AddDirectAuditInstruction],
)
def test_benign_control_mirrors_structure(
    operator_cls, oracle, fixture, tools, tmp_path: Path, loaded
) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(fixture.path, repo)
    operator = operator_cls(tools)
    spec = _spec(operator, oracle, AttackGoal.FALSE_NEGATIVE)
    plan = operator.plan(repo, oracle, spec, random.Random(5))
    benign = benign_plan(
        plan,
        payload_texts=operator.payload_texts(),
        repo_root=repo,
        seed=11,
    )
    assert benign.benign_files
    assert [item.path for item in benign.benign_files] == [item.path for item in plan.files]
    for attack, control in zip(plan.files, benign.benign_files):
        assert attack.mode == control.mode
        assert control.content != attack.content
        assert not _FORBIDDEN.search(control.content)
        ratio = len(control.content) / max(len(attack.content), 1)
        assert 0.4 <= ratio <= 1.8, (ratio, len(control.content), len(attack.content))
        if attack.mode == "replace" and attack.original_content:
            verdict = compare_semantics(
                control.path,
                attack.original_content,
                control.content,
            )
            assert verdict.preserved, (control.path, verdict.status, verdict.reason)
    # No adversarial payload may survive in the control.
    for payload in operator.payload_texts():
        for control in benign.benign_files:
            assert payload.strip() not in control.content
