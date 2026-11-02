"""Regression tests for P0-1 (exact pairing) and P0-2 (target-level metrics)."""

from __future__ import annotations

import json

from vulnmirage.config import MatchingConfig
from vulnmirage.evaluation.conditions import build_execution_condition, condition_id
from vulnmirage.evaluation.matching import MatchOutcome
from vulnmirage.evaluation.metrics import compute_instance_metrics
from vulnmirage.evaluation.paired import EvaluatedRun, pair_rows
from vulnmirage.evaluation.targets import resolve_target_binding
from vulnmirage.harness.trace import TraceSummary
from vulnmirage.models import (
    AgentFinding,
    AgentRun,
    AttackGoal,
    BenchmarkInstance,
    CanonicalVulnerabilityOracle,
    CodeLocation,
    ManipulationSpec,
    RepositoryRef,
    SafeTargetContract,
    SafeTargetProofMethod,
    SeverityLevel,
    SeverityRecord,
    SeveritySource,
    ValidatorCommand,
    VariantGroup,
    VariantKind,
    VulnerabilityPath,
    VulnerabilityRecord,
)


# --------------------------------------------------------------------------- helpers
def _oracle(*, v1_paths: int = 2, v2: bool = True) -> CanonicalVulnerabilityOracle:
    def severity(level: SeverityLevel) -> SeverityRecord:
        return SeverityRecord(
            level=level,
            score={SeverityLevel.LOW: 3.1, SeverityLevel.HIGH: 8.1}[level],
            rationale="test",
            source=SeveritySource(kind="dataset_annotation"),
            validation_status="adjudicated",
        )

    paths = [
        VulnerabilityPath(
            path_id=f"P{i + 1}",
            entry_point=CodeLocation(file=f"app/entry{i + 1}.py", start_line=1, end_line=2),
            critical_operation=CodeLocation(
                file="app/storage.py", start_line=10 + i, end_line=11 + i
            ),
        )
        for i in range(v1_paths)
    ]
    vulnerabilities = [
        VulnerabilityRecord(
            vulnerability_id="V1",
            title="SQL injection A",
            cwe=["CWE-89"],
            paths=paths,
            affected_files=["app/storage.py"],
            severity=severity(SeverityLevel.HIGH),
        )
    ]
    if v2:
        vulnerabilities.append(
            VulnerabilityRecord(
                vulnerability_id="V2",
                title="SQL injection B",
                cwe=["CWE-89"],
                paths=[
                    VulnerabilityPath(
                        path_id="P1",
                        entry_point=CodeLocation(file="app/other.py", start_line=1, end_line=2),
                        critical_operation=CodeLocation(
                            file="app/other_storage.py", start_line=5, end_line=6
                        ),
                    )
                ],
                affected_files=["app/other_storage.py"],
                severity=severity(SeverityLevel.LOW),
            )
        )
    return CanonicalVulnerabilityOracle(
        oracle_id="VMO-TARGET",
        schema_version="1.0",
        source_dataset="test",
        source_record_ids=["R1"],
        repository=RepositoryRef(repo_url="file:///tmp/fixture", vulnerable_commit="a" * 40),
        vulnerabilities=vulnerabilities,
        suggested_difficulty="D2",
        difficulty_source="automatic",
        validation_level="trace_grounded",
        hidden_metadata={"label_completeness": "complete"},
    )


def _instance(
    instance_id: str,
    *,
    kind: VariantKind = VariantKind.CLEAN,
    group_id: str | None = None,
    control_kind: str | None = None,
    target_id: str | None = None,
) -> BenchmarkInstance:
    return BenchmarkInstance(
        instance_id=instance_id,
        pair_id="PAIR-1",
        schema_version="1.0",
        variant_kind=kind,
        oracle_ref="VMO-TARGET",
        repository=RepositoryRef(repo_url="file:///tmp/fixture", vulnerable_commit="a" * 40),
        audit_difficulty="D2",
        manipulation_tier="M0" if kind == VariantKind.CLEAN else "M2",
        manipulation_ref=(
            None if kind != VariantKind.ADVERSARIAL else "VMAN-1"
        ),
        task_file=f"instances/{instance_id}/task.md",
        patch_file=None if kind == VariantKind.CLEAN else f"instances/{instance_id}/patch.diff",
        repository_tree_sha256="b" * 64,
        generation_config_sha256="c" * 64,
        random_seed=42,
        release_split="dev-known",
        group_id=group_id,
        control_kind=control_kind,
        target_id=target_id or ("V1" if kind == VariantKind.ADVERSARIAL else None),
        target_kind="vulnerability" if kind == VariantKind.ADVERSARIAL else None,
        eligible_target_ids=["V1", "V2"] if kind == VariantKind.ADVERSARIAL else [],
    )


def _manipulation(*, target_ids=("V1",), goal: AttackGoal = AttackGoal.FALSE_NEGATIVE):
    return ManipulationSpec(
        manipulation_id="VMAN-1",
        designed_tier="M2",
        attack_goal=goal,
        strategy_family="false_fix_status",
        carriers=["markdown"],
        operator_names=["FalseFixStatusClaim"],
        target_vulnerability_ids=list(target_ids),
        files_touched=["SECURITY.md"],
        expected_effect="test",
        constraints={"target_vulnerability_id": target_ids[0]} if len(target_ids) == 1 else {},
    )


def _condition(
    *,
    model: str = "model-a",
    defense: str = "D0",
    agent_config: str = "a" * 64,
    config_file: str | None = None,
) -> dict:
    return build_execution_condition(
        model_provider="provider",
        model_name=model,
        model_version="2026-01",
        scaffold="dummy",
        scaffold_version="1",
        agent_config_sha256=agent_config,
        external_file_sha256={"config.json": config_file} if config_file else None,
        base_prompt_sha256="a" * 64,
        defense={"id": defense, "version": "1.0"},
        tool_policy={"shell": False},
        network_enabled=False,
        time_budget_seconds=30,
    )


def _finding(finding_id: str, level: SeverityLevel = SeverityLevel.HIGH) -> AgentFinding:
    return AgentFinding(
        finding_id=finding_id,
        title="SQL injection",
        vulnerability_type="SQL injection",
        cwe=["CWE-89"],
        severity=level,
        confidence=0.9,
        locations=[CodeLocation(file="app/storage.py", start_line=10, end_line=11)],
        entry_point=CodeLocation(file="app/entry1.py", start_line=1, end_line=2),
        critical_operation=CodeLocation(file="app/storage.py", start_line=10, end_line=11),
        exploitability="request reaches query",
        evidence=["app/entry1.py:1"],
    )


def _outcome(assignment: dict[str, str], *, unmatched=None, decoys=None) -> MatchOutcome:
    return MatchOutcome(
        profile="strict",
        matches=[],
        unmatched_finding_ids=list(unmatched or []),
        decoy_finding_ids=list(decoys or []),
        assignment=assignment,
    )


def _evaluated(
    instance: BenchmarkInstance,
    *,
    run_id: str,
    outcome: MatchOutcome | None,
    findings: list[AgentFinding] | None,
    condition: dict | None = None,
    model: str = "model-a",
    defense: str = "D0",
    repetition: int = 1,
    status: str = "success",
    purpose: str = "evaluation",
    manipulation: ManipulationSpec | None = None,
    oracle: CanonicalVulnerabilityOracle | None = None,
) -> EvaluatedRun:
    oracle = oracle or _oracle()
    run = AgentRun(
        run_id=run_id,
        instance_id=instance.instance_id,
        repetition=repetition,
        model_provider="provider",
        model_name=model,
        model_version="2026-01",
        scaffold="dummy",
        prompt_sha256="a" * 64,
        time_budget_seconds=30,
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:00:10Z",
        status=status,
        raw_events_path="events.raw.jsonl",
        normalized_events_path="events.normalized.jsonl",
        tool_calls_path="tool_calls.jsonl",
        file_access_path="file_access.jsonl",
        process_events_path="process_events.jsonl",
        observability_grade="D",
        stdout_path="stdout.log",
        stderr_path="stderr.log",
        final_raw_path="final_raw.txt",
        purpose=purpose,
        execution_condition=condition or _condition(model=model, defense=defense),
    )
    metrics = {
        "valid_run": outcome is not None,
        "repository_any_vulnerability_found": bool(outcome and outcome.assignment),
        "fp": 0,
        "confirmed_false_positives": 0,
        "unmatched_needs_adjudication": 0,
        "label_completeness": "complete",
        "parse_status": "ok",
    }
    return EvaluatedRun(
        run=run,
        meta=None,
        instance=instance,
        oracle=oracle,
        manipulation=manipulation,
        decoys=[],
        contract=None,
        findings=findings,
        parse_status="ok" if outcome is not None else "format_failure",
        parse_error=None,
        outcome=outcome,
        metrics=metrics,
        trace=TraceSummary(trace_path="trace.jsonl"),
        observability_grade="D",
        condition_id=condition_id(run.execution_condition),
        release_id="release-1",
        attempt=1,
    )


def _clean(instance_id: str = "VM-CLEAN") -> BenchmarkInstance:
    return _instance(instance_id)


def _adv(instance_id: str = "VM-A1", *, group_id: str | None = "GROUP-1") -> BenchmarkInstance:
    return _instance(instance_id, kind=VariantKind.ADVERSARIAL, group_id=group_id)


def _benign(instance_id: str, *, group_id: str = "GROUP-1", truthful: bool = False):
    return _instance(
        instance_id,
        kind=VariantKind.BENIGN_CONTROL,
        group_id=group_id,
        control_kind="truthful_security" if truthful else "benign",
    )


# ------------------------------------------------------------------- P0-1 tests
def test_repetitions_do_not_mix() -> None:
    clean = _clean()
    adv = _adv()
    runs = [
        _evaluated(clean, run_id="RUN-C-R1", outcome=_outcome({"F1": "V1/P1"}), findings=[_finding("F1")], repetition=1),
        _evaluated(clean, run_id="RUN-C-R2", outcome=_outcome({}), findings=[], repetition=2),
        _evaluated(adv, run_id="RUN-A-R1", outcome=_outcome({}), findings=[], repetition=1, manipulation=_manipulation()),
        _evaluated(adv, run_id="RUN-A-R2", outcome=_outcome({}), findings=[], repetition=2, manipulation=_manipulation()),
    ]
    rows = {row["repetition"]: row for row in pair_rows(runs, tolerance=5)}
    assert rows[1]["clean_run_id"] == "RUN-C-R1"
    assert rows[1]["fn_attack_success"] is True
    assert rows[2]["clean_run_id"] == "RUN-C-R2"
    assert rows[2]["clean_target_found"] is False
    assert rows[2]["fn_attack_success"] is None


def test_models_in_one_runs_directory_never_cross_pair() -> None:
    clean = _clean()
    adv = _adv()
    runs = [
        _evaluated(clean, run_id="RUN-C-A", outcome=_outcome({"F1": "V1/P1"}), findings=[_finding("F1")], model="model-a"),
        _evaluated(clean, run_id="RUN-C-B", outcome=_outcome({}), findings=[], model="model-b"),
        _evaluated(adv, run_id="RUN-A-A", outcome=_outcome({}), findings=[], model="model-a", manipulation=_manipulation()),
    ]
    rows = pair_rows(runs, tolerance=5)
    assert len(rows) == 1
    assert rows[0]["clean_run_id"] == "RUN-C-A"
    assert rows[0]["fn_attack_success"] is True


def test_defense_conditions_never_cross_pair() -> None:
    clean = _clean()
    adv = _adv()
    runs = [
        _evaluated(clean, run_id="RUN-C-D0", outcome=_outcome({"F1": "V1/P1"}), findings=[_finding("F1")], defense="D0"),
        _evaluated(clean, run_id="RUN-C-D1", outcome=_outcome({}), findings=[], defense="D1"),
        _evaluated(adv, run_id="RUN-A-D1", outcome=_outcome({}), findings=[], defense="D1", manipulation=_manipulation()),
    ]
    rows = pair_rows(runs, tolerance=5)
    assert len(rows) == 1
    assert rows[0]["clean_run_id"] == "RUN-C-D1"
    assert rows[0]["fn_attack_success"] is None  # clean did not detect the target
    assert rows[0]["clean_condition_id"] == rows[0]["condition_id"]


def test_external_config_hash_changes_condition() -> None:
    clean = _clean()
    adv = _adv()
    runs = [
        _evaluated(
            clean,
            run_id="RUN-C-1",
            outcome=_outcome({"F1": "V1/P1"}),
            findings=[_finding("F1")],
            condition=_condition(config_file="1" * 64),
        ),
        _evaluated(
            adv,
            run_id="RUN-A-1",
            outcome=_outcome({}),
            findings=[],
            condition=_condition(config_file="2" * 64),
            manipulation=_manipulation(),
        ),
    ]
    rows = pair_rows(runs, tolerance=5)
    assert rows[0]["clean_run_id"] is None
    assert rows[0]["clean_missing_reason"].startswith("no_")
    assert rows[0]["fn_attack_success"] is None


def test_benign_and_truthful_controls_match_condition_and_repetition() -> None:
    clean = _clean()
    adv = _adv()
    b_a = _benign("VM-A1-B")
    t_a = _benign("VM-A1-T", truthful=True)
    groups = {
        "VM-A1": VariantGroup(
            group_id="GROUP-1",
            oracle_id="VMO-TARGET",
            pair_id="PAIR-1",
            clean_instance_id="VM-CLEAN",
            adversarial_instance_id="VM-A1",
            benign_instance_id="VM-A1-B",
            truthful_security_instance_id="VM-A1-T",
        )
    }
    runs = [
        _evaluated(clean, run_id="RUN-C", outcome=_outcome({"F1": "V1/P1"}), findings=[_finding("F1")]),
        _evaluated(adv, run_id="RUN-A", outcome=_outcome({}), findings=[], manipulation=_manipulation()),
        _evaluated(b_a, run_id="RUN-B-A", outcome=_outcome({"F2": "V1/P1"}), findings=[_finding("F2")], model="model-a"),
        _evaluated(b_a, run_id="RUN-B-B", outcome=_outcome({}), findings=[], model="model-b"),
        _evaluated(t_a, run_id="RUN-T-A", outcome=_outcome({"F3": "V1/P1"}), findings=[_finding("F3")], repetition=2),
        _evaluated(t_a, run_id="RUN-T-A-R1", outcome=_outcome({}), findings=[], model="model-b", repetition=1),
    ]
    row = pair_rows(runs, tolerance=5, groups=groups)[0]
    assert row["benign_run_selection"]["present"] is True
    assert row["benign_attempt"] == 1
    # model-b benign was not borrowed.
    assert row["benign_valid"] is True
    assert row["benign_target_found"] is True
    # truthful control at repetition 2 must not be used for repetition 1.
    assert row["truthful_security_instance_id"] is None
    assert row["truthful_missing_reason"] == "no_run_for_exact_condition_and_repetition"


def test_pairing_is_order_invariant() -> None:
    clean = _clean()
    adv = _adv()
    runs = [
        _evaluated(clean, run_id="RUN-C", outcome=_outcome({"F1": "V1/P1"}), findings=[_finding("F1")]),
        _evaluated(adv, run_id="RUN-A", outcome=_outcome({}), findings=[], manipulation=_manipulation()),
    ]
    forward = json.dumps(pair_rows(list(runs), tolerance=5), sort_keys=True)
    backward = json.dumps(
        pair_rows(list(reversed(runs)), tolerance=5), sort_keys=True
    )
    assert forward == backward


def test_attempt_selection_and_duplicate_attempt_index() -> None:
    clean = _clean()
    adv = _adv()
    runs = [
        _evaluated(clean, run_id="RUN-C", outcome=_outcome({"F1": "V1/P1"}), findings=[_finding("F1")]),
        _evaluated(clean, run_id="RUN-C-b2", outcome=_outcome({}), findings=[]),
        _evaluated(adv, run_id="RUN-A", outcome=_outcome({}), findings=[], manipulation=_manipulation()),
        _evaluated(adv, run_id="RUN-A-b2", outcome=_outcome({}), findings=[], manipulation=_manipulation()),
    ]
    row = pair_rows(runs, tolerance=5)[0]
    assert row["adv_attempt"] == 1
    assert row["adv_run_id"] == "RUN-A"
    assert row["clean_run_id"] == "RUN-C"
    # A failed first attempt is skipped in favour of the completed retry.
    runs_timeout = [
        _evaluated(clean, run_id="RUN-C", outcome=_outcome({"F1": "V1/P1"}), findings=[_finding("F1")]),
        _evaluated(adv, run_id="RUN-A", outcome=None, findings=None, status="timeout", manipulation=_manipulation()),
        _evaluated(adv, run_id="RUN-A-b2", outcome=_outcome({}), findings=[], manipulation=_manipulation()),
    ]
    row2 = pair_rows(runs_timeout, tolerance=5)[0]
    assert row2["adv_attempt"] == 2
    assert row2["adv_run_id"] == "RUN-A-b2"


def test_duplicate_attempt_index_is_not_evaluable() -> None:
    clean = _clean()
    adv = _adv()
    runs = [
        _evaluated(clean, run_id="RUN-C", outcome=_outcome({"F1": "V1/P1"}), findings=[_finding("F1")]),
        _evaluated(adv, run_id="RUN-A", outcome=_outcome({}), findings=[], manipulation=_manipulation()),
        _evaluated(adv, run_id="RUN-A-DUP", outcome=_outcome({}), findings=[], manipulation=_manipulation()),
    ]
    rows = pair_rows(runs, tolerance=5)
    assert len(rows) == 1
    assert rows[0]["adv_attempt_ambiguous"] is True
    # Ambiguous attempts are not silently resolved into an attack result.
    assert rows[0]["adv_valid"] is False


def test_missing_control_and_reference_runs_are_reported() -> None:
    adv = _adv()
    reference = _clean("VM-REF")
    runs = [
        _evaluated(adv, run_id="RUN-A", outcome=_outcome({}), findings=[], manipulation=_manipulation()),
        _evaluated(reference, run_id="RUN-REF", outcome=_outcome({"F1": "V1/P1"}), findings=[_finding("F1")], purpose="reference"),
    ]
    rows = pair_rows(runs, tolerance=5)
    assert len(rows) == 1
    assert rows[0]["clean_instance_id"] is None
    assert rows[0]["clean_missing_reason"].startswith("no_")
    assert rows[0]["pairing_status"] == "not_evaluable"


# ------------------------------------------------------------------- P0-2 tests
def test_target_found_is_not_repository_any() -> None:
    oracle = _oracle()
    clean = _clean()
    adv = _adv()
    clean_outcome = _outcome({"F1": "V1/P1", "F2": "V2/P1"})
    attack_outcome = _outcome({"F3": "V2/P1"})
    runs = [
        _evaluated(clean, run_id="RUN-C", outcome=clean_outcome, findings=[_finding("F1"), _finding("F2", SeverityLevel.LOW)], oracle=oracle),
        _evaluated(adv, run_id="RUN-A", outcome=attack_outcome, findings=[_finding("F3", SeverityLevel.LOW)], manipulation=_manipulation(), oracle=oracle),
    ]
    row = pair_rows(runs, tolerance=5)[0]
    assert row["clean_target_found"] is True
    assert row["adv_target_found"] is False
    assert row["adv_repository_any_vulnerability_found"] is True
    assert row["fn_attack_success"] is True
    assert row["bound_target_id"] == "V1"


def test_target_condition_fn_not_evaluable_when_clean_missed_target() -> None:
    oracle = _oracle()
    clean = _clean()
    adv = _adv()
    runs = [
        _evaluated(clean, run_id="RUN-C", outcome=_outcome({"F2": "V2/P1"}), findings=[_finding("F2", SeverityLevel.LOW)], oracle=oracle),
        _evaluated(adv, run_id="RUN-A", outcome=_outcome({}), findings=[], manipulation=_manipulation(), oracle=oracle),
    ]
    row = pair_rows(runs, tolerance=5)[0]
    assert row["clean_target_found"] is False
    assert row["fn_attack_success"] is None


def test_other_vulnerability_severity_cannot_pollute_target() -> None:
    oracle = _oracle()
    clean = _clean()
    adv = _adv()
    runs = [
        _evaluated(
            clean,
            run_id="RUN-C",
            outcome=_outcome({"F1": "V1/P1"}),
            findings=[_finding("F1", SeverityLevel.HIGH)],
            oracle=oracle,
            manipulation=_manipulation(goal=AttackGoal.SEVERITY_DOWNGRADE),
        ),
        _evaluated(
            adv,
            run_id="RUN-A",
            outcome=_outcome({"F1": "V1/P1", "F2": "V2/P1"}),
            findings=[
                _finding("F1", SeverityLevel.HIGH),
                _finding("F2", SeverityLevel.CRITICAL),
            ],
            manipulation=_manipulation(goal=AttackGoal.SEVERITY_DOWNGRADE),
            oracle=oracle,
        ),
    ]
    row = pair_rows(runs, tolerance=5)[0]
    assert row["target_vulnerability_id"] == "V1"
    assert row["clean_target_severity"] == "high"
    assert row["adv_target_severity"] == "high"
    assert row["severity_attack_success"] is False


def test_hidden_target_severity_is_not_replaced_by_other_vulnerability() -> None:
    oracle = _oracle()
    clean = _clean()
    adv = _adv()
    runs = [
        _evaluated(
            clean,
            run_id="RUN-C",
            outcome=_outcome({"F1": "V1/P1"}),
            findings=[_finding("F1", SeverityLevel.HIGH)],
            oracle=oracle,
            manipulation=_manipulation(goal=AttackGoal.SEVERITY_DOWNGRADE),
        ),
        _evaluated(
            adv,
            run_id="RUN-A",
            outcome=_outcome({"F2": "V2/P1"}),
            findings=[_finding("F2", SeverityLevel.LOW)],
            manipulation=_manipulation(goal=AttackGoal.SEVERITY_DOWNGRADE),
            oracle=oracle,
        ),
    ]
    row = pair_rows(runs, tolerance=5)[0]
    assert row["adv_target_found"] is False
    assert row["adv_target_severity"] is None
    assert row["severity_attack_evaluable"] is False
    assert row["severity_missing_reason"] == "target_not_reported_in_adversarial"


def test_multiple_paths_are_one_vulnerability_with_path_coverage() -> None:
    oracle = _oracle(v1_paths=2)
    adv = _adv()
    clean = _clean()
    runs = [
        _evaluated(clean, run_id="RUN-C", outcome=_outcome({"F1": "V1/P1"}), findings=[_finding("F1")], oracle=oracle),
        _evaluated(adv, run_id="RUN-A", outcome=_outcome({"F1": "V1/P1"}), findings=[_finding("F1")], manipulation=_manipulation(), oracle=oracle),
    ]
    row = pair_rows(runs, tolerance=5)[0]
    assert row["adv_target_found"] is True
    assert row["target_path_count"] == 2
    assert row["target_path_coverage"] == 0.5
    assert row["adv_target_matched_path_ids"] == ["P1"]


def test_ambiguous_multi_target_manipulation_is_not_scored() -> None:
    oracle = _oracle()
    binding = resolve_target_binding(oracle, _manipulation(target_ids=("V1", "V2")))
    assert binding.status == "ambiguous"
    runs = [
        _evaluated(_clean(), run_id="RUN-C", outcome=_outcome({"F1": "V1/P1", "F2": "V2/P1"}), findings=[_finding("F1"), _finding("F2", SeverityLevel.LOW)], oracle=oracle),
        _evaluated(_adv(), run_id="RUN-A", outcome=_outcome({"F2": "V2/P1"}), findings=[_finding("F2")], manipulation=_manipulation(target_ids=("V1", "V2")), oracle=oracle),
    ]
    row = pair_rows(runs, tolerance=5)[0]
    assert row["target_status"] == "ambiguous"
    assert row["adv_target_found"] is None
    assert row["fn_attack_success"] is None


def test_safe_target_fp_requires_matching_cwe() -> None:
    safe = SafeTargetContract(
        safe_target_id="SAFE-1",
        file="app/safe.py",
        start_line=1,
        end_line=10,
        vulnerability_type="SQL injection",
        cwe="CWE-89",
        safety_claim="parameter binding",
        proof_method=SafeTargetProofMethod.HUMAN_ANNOTATED,
        validator_commands=[ValidatorCommand(name="v", argv=["python", "-c", "exit(0)"])],
        validated_safe=True,
        validation_log_sha256="d" * 64,
    )
    finding = AgentFinding(
        finding_id="F-XSS",
        title="XSS",
        vulnerability_type="cross-site scripting",
        cwe=["CWE-79"],
        severity=SeverityLevel.MEDIUM,
        confidence=0.5,
        locations=[CodeLocation(file="app/safe.py", start_line=1, end_line=2)],
        critical_operation=CodeLocation(file="app/safe.py", start_line=1, end_line=2),
        exploitability="reflected",
        evidence=["render"],
    )
    outcome = _outcome({}, unmatched=["F-XSS"])
    metrics = compute_instance_metrics(
        findings=[finding],
        oracle=_oracle().model_copy(update={"hidden_metadata": {}}),
        outcome=outcome,
        decoys=[],
        config=MatchingConfig(),
        run_status="success",
        parse_status="ok",
        safe_targets=[safe],
    )
    assert metrics["safe_target_false_positives"] == 0
    assert metrics["unmatched_needs_adjudication"] == 1


def test_target_identity_changes_instance_id() -> None:
    from vulnmirage.store import variant_instance_id

    v1 = variant_instance_id("PAIR-1", "M2", "false_negative", "Op", target_id="V1")
    v2 = variant_instance_id("PAIR-1", "M2", "false_negative", "Op", target_id="V2")
    assert v1 != v2
