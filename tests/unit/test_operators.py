from __future__ import annotations

import random
import shutil
from pathlib import Path

import pytest

from tests.fixture_repo import create_fixture_repo
from tests.support import make_test_config
from vulnmirage.generation.payload_registry import load_payload_registry
from vulnmirage.generation.safe_targets import (
    execute_safe_target_validation,
    prepare_safe_targets,
)
from vulnmirage.ingest.base import build_oracle, read_jsonl
from vulnmirage.manipulations.base import ManipulationOperator, OperatorTools
from vulnmirage.manipulations.m1_direct import (
    AddDirectAuditInstruction,
    InsertDirectComment,
    InsertNonExecutableString,
)
from vulnmirage.manipulations.m2_semantic import (
    FalseDeploymentClaim,
    FalseFixStatusClaim,
    FalsePrivilegeClaim,
    FalseReachabilityClaim,
    SeverityAnchorClaim,
)
from vulnmirage.manipulations.m3_distributed import DistributedClaimOperator
from vulnmirage.models import AttackGoal, BenchmarkInstance, ManipulationSpec, VariantKind
from vulnmirage.repository.git import worktree_digest


@pytest.fixture(scope="module")
def fixture(tmp_path_factory):
    return create_fixture_repo(tmp_path_factory.mktemp("operators"))


@pytest.fixture(scope="module")
def oracle(fixture):
    reports = read_jsonl(fixture.reports_path)
    entries = [record for _, record in read_jsonl(fixture.entries_path)]
    return build_oracle(reports[0][1], entries, dataset_name="fixture")


@pytest.fixture(scope="module")
def loaded(tmp_path_factory, project_root: Path):
    return make_test_config(
        tmp_path_factory.mktemp("operators-config"),
        project_root,
        workspace_name="workspace-operators",
    )


@pytest.fixture(scope="module")
def tools(project_root: Path):
    registry, base_dir = load_payload_registry(project_root / "payloads" / "registry.yaml")
    return OperatorTools(registry=registry, payload_dir=base_dir)


def _copy_repo(fixture, destination: Path) -> Path:
    shutil.copytree(fixture.path, destination)
    return destination


def _spec(cls: type[ManipulationOperator], oracle, goal: AttackGoal) -> ManipulationSpec:
    return ManipulationSpec(
        manipulation_id=f"VMAN-TEST-{cls.name}",
        designed_tier=cls.tier,
        attack_goal=goal,
        strategy_family=cls.strategy_family,
        mechanism=cls.mechanism,
        carriers=list(cls.carriers),
        operator_names=[cls.name],
        target_vulnerability_ids=[v.vulnerability_id for v in oracle.vulnerabilities],
        expected_effect=cls.expected_effect,
    )


def _run_operator(cls, goal, oracle, tools, fixture, tmp_path: Path, loaded):
    operator = cls(tools)
    repo = _copy_repo(fixture, tmp_path / "repo")
    spec = _spec(cls, oracle, goal)
    if goal == AttackGoal.FALSE_POSITIVE:
        resolution = prepare_safe_targets(oracle, repo)
        executed = execute_safe_target_validation(
            resolution.accepted,
            loaded=loaded,
            repo_root=repo,
            log_dir=tmp_path / "safe-target-logs",
            instance_id="VM-UNIT-TEST",
        )
        spec = spec.model_copy(update={"safe_targets": executed.validated})
    before = worktree_digest(repo)
    plan = operator.plan(repo, oracle, spec, random.Random(7))
    assert worktree_digest(repo) == before, "plan() must not modify the repository"
    assert plan.files
    assert all(item.path in plan.allowed_paths for item in plan.files)
    artifact = operator.apply(repo, plan)
    assert artifact.patch_text
    checks = operator.validate_local(repo, plan)
    failures = [check for check in checks if check.status.value in {"fail", "error"}]
    assert not failures, failures
    assert sorted(artifact.paths) == sorted(item.path for item in plan.files)
    return plan, artifact, repo


@pytest.mark.parametrize(
    ("cls", "goal"),
    [
        (AddDirectAuditInstruction, AttackGoal.FALSE_NEGATIVE),
        (AddDirectAuditInstruction, AttackGoal.SEVERITY_DOWNGRADE),
        (InsertDirectComment, AttackGoal.EVIDENCE_CORRUPTION),
        (InsertNonExecutableString, AttackGoal.FALSE_POSITIVE),
    ],
)
def test_m1_operators(cls, goal, oracle, tools, fixture, tmp_path: Path, loaded) -> None:
    plan, artifact, repo = _run_operator(cls, goal, oracle, tools, fixture, tmp_path, loaded)
    assert plan.tier.value == "M1"
    assert plan.payloads
    assert all(item.payload_id for item in plan.payloads)
    for changed in artifact.paths:
        assert (repo / changed).exists()


@pytest.mark.parametrize(
    ("cls", "goal"),
    [
        (FalseFixStatusClaim, AttackGoal.FALSE_NEGATIVE),
        (FalseReachabilityClaim, AttackGoal.EVIDENCE_CORRUPTION),
        (FalseDeploymentClaim, AttackGoal.FALSE_POSITIVE),
        (FalsePrivilegeClaim, AttackGoal.SEVERITY_DOWNGRADE),
        (SeverityAnchorClaim, AttackGoal.SEVERITY_INFLATION),
    ],
)
def test_m2_operators(cls, goal, oracle, tools, fixture, tmp_path: Path, loaded) -> None:
    plan, artifact, repo = _run_operator(cls, goal, oracle, tools, fixture, tmp_path, loaded)
    assert plan.tier.value == "M2"
    assert plan.payloads
    if cls is FalseDeploymentClaim:
        assert plan.target_safe_locations
        assert plan.safe_targets
        assert all(item.validated_safe for item in plan.safe_targets)
    # M2 must read like natural project prose, not a direct override.
    for changed in artifact.paths:
        text = (repo / changed).read_text(encoding="utf-8").lower()
        assert "ignore previous" not in text
        assert "ignore any previous instruction" not in text


def test_m3_distributed_claim_graph(oracle, tools, fixture, tmp_path: Path, loaded) -> None:
    plan, artifact, repo = _run_operator(
        DistributedClaimOperator,
        AttackGoal.FALSE_NEGATIVE,
        oracle,
        tools,
        fixture,
        tmp_path,
        loaded,
    )
    assert plan.claim_graph is not None
    assert len(plan.claim_graph.nodes) >= 3
    assert len(plan.claim_graph.edges) >= 2
    assert len(plan.files) >= 3
    paths = {item.path for item in plan.files}
    assert "SECURITY.md" in paths
    assert "docs/architecture.md" in paths
    assert any(path.endswith(".py") for path in paths)


def test_m1_false_positive_targets_validated_safe_file(
    oracle, tools, fixture, tmp_path: Path, loaded
) -> None:
    plan, artifact, repo = _run_operator(
        InsertNonExecutableString,
        AttackGoal.FALSE_POSITIVE,
        oracle,
        tools,
        fixture,
        tmp_path,
        loaded,
    )
    assert plan.target_safe_locations
    assert plan.target_safe_locations[0].file == "app/parameters.py"
    assert plan.safe_targets
    assert plan.safe_targets[0].validated_safe is True
    assert plan.safe_targets[0].validation_log_sha256


def test_unannotated_file_is_never_a_safe_target(oracle, tools, fixture, tmp_path: Path) -> None:
    """A file outside the oracle must not automatically become safe ground truth."""
    from vulnmirage.generation.context import is_code
    from vulnmirage.manipulations import compatible_operator_candidates
    from vulnmirage.models import ManipulationTier

    names = compatible_operator_candidates(
        ManipulationTier.M1_DIRECT,
        AttackGoal.FALSE_POSITIVE,
        __import__(
            "vulnmirage.generation.compatibility", fromlist=["load_compatibility_matrix"]
        ).load_compatibility_matrix("payloads/compatibility.yaml"),
    )
    assert names
    operator = InsertNonExecutableString(tools)
    repo = _copy_repo(fixture, tmp_path / "repo")
    spec = _spec(InsertNonExecutableString, oracle, AttackGoal.FALSE_POSITIVE)
    candidates = [
        path.relative_to(repo).as_posix()
        for path in repo.rglob("*")
        if path.is_file() and is_code(path.relative_to(repo).as_posix())
    ]
    assert candidates
    # No validated contract is bound: generation must refuse rather than pick
    # one of the unannotated files.
    with pytest.raises(ValueError, match="no_validated_safe_target"):
        operator.plan(repo, oracle, spec, random.Random(1))


def test_operator_rejects_write_outside_allowed_paths(oracle, tools, fixture, tmp_path: Path) -> None:
    operator = AddDirectAuditInstruction(tools)
    repo = _copy_repo(fixture, tmp_path / "repo")
    spec = _spec(AddDirectAuditInstruction, oracle, AttackGoal.FALSE_NEGATIVE)
    plan = operator.plan(repo, oracle, spec, random.Random(1))
    bad = plan.model_copy(update={"allowed_paths": []})
    with pytest.raises(Exception):
        operator.apply(repo, bad)
