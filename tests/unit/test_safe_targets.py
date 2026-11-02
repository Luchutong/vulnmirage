"""Regression tests: only explicitly validated targets may be used as safe truth."""

from __future__ import annotations

import random
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.fixture_repo import create_fixture_repo
from tests.support import make_test_config
from vulnmirage.generation.compatibility import load_compatibility_matrix
from vulnmirage.generation.payload_registry import load_payload_registry
from vulnmirage.generation.safe_targets import (
    prepare_safe_targets,
    select_safe_targets,
    execute_safe_target_validation,
)
from vulnmirage.ingest.base import build_oracle, read_jsonl
from vulnmirage.manipulations.base import OperatorTools
from vulnmirage.manipulations.m1_direct import InsertNonExecutableString
from vulnmirage.models import (
    AttackGoal,
    ManipulationSpec,
    SafeTargetContract,
    SafeTargetProofMethod,
    SafeTargetSource,
    ValidatorCommand,
)


@pytest.fixture(scope="module")
def fixture(tmp_path_factory):
    return create_fixture_repo(tmp_path_factory.mktemp("safe-targets"))


@pytest.fixture(scope="module")
def oracle(fixture):
    reports = read_jsonl(fixture.reports_path)
    entries = [record for _, record in read_jsonl(fixture.entries_path)]
    return build_oracle(reports[0][1], entries, dataset_name="fixture")


@pytest.fixture(scope="module")
def loaded(tmp_path_factory, project_root: Path):
    return make_test_config(
        tmp_path_factory.mktemp("safe-config"), project_root, workspace_name="ws-safe"
    )


def test_unannotated_file_is_not_selected(oracle, fixture) -> None:
    """A file merely absent from the oracle is not safe ground truth."""
    resolution = prepare_safe_targets(oracle, fixture.path)
    assert [item.safe_target_id for item in resolution.accepted] == [
        "SAFE-PARAMETERIZED-LOOKUP"
    ]
    assert any(
        item["reason"] == "safe_target_cwe_not_in_oracle" for item in resolution.rejected
    )
    assert select_safe_targets(resolution.accepted) == []
    assert not oracle.validated_safe_targets()


def test_only_validated_contracts_are_selectable() -> None:
    contract = SafeTargetContract(
        safe_target_id="SAFE-1",
        file="app/parameters.py",
        start_line=1,
        end_line=5,
        vulnerability_type="SQL injection",
        cwe="CWE-89",
        safety_claim="parameterized",
        proof_method=SafeTargetProofMethod.HUMAN_ANNOTATED,
        validator_commands=[
            ValidatorCommand(name="ok", argv=["python", "-c", "raise SystemExit(1)"])
        ],
        validated_safe=False,
        source=SafeTargetSource.HUMAN_ANNOTATION,
    )
    assert select_safe_targets([contract]) == []
    with pytest.raises(Exception):
        SafeTargetContract.model_validate(
            {**contract.model_dump(mode="json"), "validated_safe": True}
        )


def test_validator_failure_keeps_target_unvalidated(
    loaded, oracle, fixture, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(fixture.path, repo)
    contract = SafeTargetContract(
        safe_target_id="SAFE-FAIL",
        file="app/parameters.py",
        start_line=1,
        end_line=13,
        vulnerability_type="SQL injection",
        cwe="CWE-89",
        safety_claim="declared but unproven",
        proof_method=SafeTargetProofMethod.HUMAN_ANNOTATED,
        validator_commands=[
            ValidatorCommand(name="fail", argv=["python", "-c", "raise SystemExit(1)"])
        ],
        source=SafeTargetSource.HUMAN_ANNOTATION,
    )
    executed = execute_safe_target_validation(
        [contract],
        loaded=loaded,
        repo_root=repo,
        log_dir=tmp_path / "logs",
        instance_id="VM-SAFE-TEST",
    )
    assert executed.validated == []
    assert executed.rejected[0].validated_safe is False
    assert executed.log_sha256


def test_fixed_commit_contract_is_validated_against_git(
    loaded, oracle, fixture, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(fixture.path, repo)
    fixed = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()
    critical = oracle.vulnerabilities[0].paths[0].critical_operation
    contract = SafeTargetContract(
        safe_target_id="SAFE-FIXED-PATH",
        file=critical.file,
        start_line=critical.start_line,
        end_line=critical.end_line,
        vulnerability_type="SQL injection",
        cwe="CWE-89",
        safety_claim="the fix commit changed the vulnerable region",
        proof_method=SafeTargetProofMethod.FIX_COMMIT_PATH,
        validator_commands=[],
        source=SafeTargetSource.FIX_COMMIT,
    )
    fixed_oracle = oracle.model_copy(
        update={
            "repository": oracle.repository.model_copy(update={"fixed_commit": fixed}),
            "safe_targets": [contract],
        }
    )
    resolution = prepare_safe_targets(fixed_oracle, repo)
    assert resolution.accepted, resolution.rejected
    executed = execute_safe_target_validation(
        resolution.accepted,
        loaded=loaded,
        repo_root=repo,
        log_dir=tmp_path / "logs-fixed",
        instance_id="VM-FIXED",
    )
    assert executed.validated, executed.details

    # The same validator must fail when the declared span is not changed by the
    # fix commit (fail-closed provenance).
    unchanged = contract.model_copy(update={"start_line": 1, "end_line": 1})
    unchanged_oracle = fixed_oracle.model_copy(update={"safe_targets": [unchanged]})
    resolution = prepare_safe_targets(unchanged_oracle, repo)
    executed = execute_safe_target_validation(
        resolution.accepted,
        loaded=loaded,
        repo_root=repo,
        log_dir=tmp_path / "logs-fixed-bad",
        instance_id="VM-FIXED-BAD",
    )
    assert executed.validated == []


def test_false_positive_operator_refuses_without_validated_target(
    oracle, fixture, tmp_path: Path, project_root: Path
) -> None:
    registry, base_dir = load_payload_registry(project_root / "payloads" / "registry.yaml")
    tools = OperatorTools(registry=registry, payload_dir=base_dir)
    operator = InsertNonExecutableString(tools)
    repo = tmp_path / "repo"
    shutil.copytree(fixture.path, repo)
    spec = ManipulationSpec(
        manipulation_id="VMAN-SAFE-TEST",
        designed_tier="M1",
        attack_goal=AttackGoal.FALSE_POSITIVE,
        strategy_family=operator.strategy_family,
        mechanism=operator.mechanism,
        carriers=["string"],
        operator_names=[operator.name],
        target_vulnerability_ids=[v.vulnerability_id for v in oracle.vulnerabilities],
        expected_effect=operator.expected_effect,
    )
    with pytest.raises(ValueError, match="no_validated_safe_target"):
        operator.plan(repo, oracle, spec, random.Random(0))


def test_matrix_records_safe_target_requirements(project_root: Path) -> None:
    matrix = load_compatibility_matrix(project_root / "payloads" / "compatibility.yaml")
    entry = matrix.requirements(
        mechanism="semantic_misinformation",
        strategy_family="false_deployment",
        goal=AttackGoal.FALSE_POSITIVE,
    )
    assert entry.required_safe_target is True
    assert entry.required_validators is True
