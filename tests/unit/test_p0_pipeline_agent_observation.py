"""Regression tests for P0-3 (scheduling/release), P0-4 (agent) and P0-5 (probes)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tests.support import make_instance, make_test_config
from vulnmirage.config import AgentConfig, load_agent_config
from vulnmirage.errors import HarnessError
from vulnmirage.export.bundle import ReleaseInstanceEntry, ReleaseManifest, ReleasePair
from vulnmirage.generation.candidates import (
    _coverage_summary,
    _write_selection_manifest,
    deduplicate_instances,
)
from vulnmirage.generation.scheduling import assign_operator
from vulnmirage.harness.observation.os_trace import probe_os_trace
from vulnmirage.harness.opencode import split_json_stream_result
from vulnmirage.harness.runner import select_release_entries
from vulnmirage.harness.subprocess_agent import SubprocessAgentAdapter
from vulnmirage.models import AgentRun, BenchmarkInstance, RepositoryRef, VariantGroup, VariantKind
from vulnmirage.paths import WorkspacePaths
from vulnmirage.store import InstanceStore


# ------------------------------------------------------------------ P0-3
def test_exhaustive_schedule_covers_every_operator() -> None:
    operators = ["OpA", "OpB"]
    chosen = {
        assign_operator(
            index=i, tier="M2", goal="false_negative", compatible=operators, policy="exhaustive"
        ).operator
        for i in range(4)
    }
    assert operators[0] in chosen and operators[1] in chosen
    balanced = [
        assign_operator(
            index=i, tier="M2", goal="false_negative", compatible=operators, policy="balanced"
        ).operator
        for i in range(3)
    ]
    assert balanced[:2] == ["OpA", "OpB"]


def test_schedule_coverage_summary_lists_operators() -> None:
    summary = _coverage_summary(
        [
            {"tier": "M2", "goal": "false_negative", "operator": "OpA"},
            {"tier": "M2", "goal": "false_negative", "operator": "OpB"},
        ]
    )
    assert summary["distinct_operators"] == ["OpA", "OpB"]


def _write_instance(store: InstanceStore, instance_id: str, *, target: str, text: str) -> None:
    directory = store.instance_dir(instance_id)
    directory.mkdir(parents=True, exist_ok=True)
    instance = make_instance(instance_id=instance_id, kind=VariantKind.ADVERSARIAL).model_copy(
        update={"target_id": target, "target_kind": "vulnerability"}
    )
    (directory / "instance.json").write_text(
        instance.model_dump_json(indent=2), encoding="utf-8"
    )
    (directory / "patch.diff").write_text(
        f"--- a/SECURITY.md\n+++ b/SECURITY.md\n@@ -0,0 +1 @@\n+{text}\n",
        encoding="utf-8",
    )


def test_dedup_never_merges_different_targets(tmp_path: Path) -> None:
    paths = WorkspacePaths(
        root=tmp_path,
        cache=tmp_path / "cache",
        normalized=tmp_path / "normalized",
        worktrees=tmp_path / "worktrees",
        instances=tmp_path / "instances",
        runs=tmp_path / "runs",
        reports=tmp_path / "reports",
        logs=tmp_path / "logs",
        releases=tmp_path / "releases",
        quarantine=tmp_path / "quarantine",
    )
    store = InstanceStore(paths)
    _write_instance(store, "VM-A1", target="V1", text="identical payload")
    _write_instance(store, "VM-A2", target="V2", text="identical payload")
    _write_instance(store, "VM-A3", target="V1", text="identical payload")
    kept, dropped = deduplicate_instances(store, ["VM-A1", "VM-A2", "VM-A3"], threshold=0.9)
    assert "VM-A1" in kept and "VM-A2" in kept
    assert "VM-A3" not in kept
    assert dropped and dropped[0]["duplicate_of"] == "VM-A1"


def test_selection_manifest_records_dedup_and_selection(tmp_path: Path) -> None:
    paths = WorkspacePaths(
        root=tmp_path,
        cache=tmp_path / "cache",
        normalized=tmp_path / "normalized",
        worktrees=tmp_path / "worktrees",
        instances=tmp_path / "instances",
        runs=tmp_path / "runs",
        reports=tmp_path / "reports",
        logs=tmp_path / "logs",
        releases=tmp_path / "releases",
        quarantine=tmp_path / "quarantine",
    )
    store = InstanceStore(paths)
    generated = [
        {
            "instance_id": "VM-A1",
            "candidate_id": "VM-A1-c0",
            "target_id": "V1",
            "target_kind": "vulnerability",
            "release_eligible": True,
            "operator": "OpA",
            "tier": "M2",
            "goal": "false_negative",
            "candidate_index": 0,
        },
        {
            "instance_id": "VM-A2",
            "candidate_id": "VM-A2-c0",
            "target_id": "V1",
            "target_kind": "vulnerability",
            "release_eligible": True,
            "operator": "OpA",
            "tier": "M2",
            "goal": "false_negative",
            "candidate_index": 1,
        },
    ]
    payload, path = _write_selection_manifest(
        store=store,
        generated=generated,
        dropped=[
            {
                "instance_id": "VM-A2",
                "candidate_id": "VM-A2-c0",
                "duplicate_of": "VM-A1",
                "reason": "identical_patch_hash",
            }
        ],
        rejected=[],
        kept=["VM-A1"],
        policy="exhaustive",
        slots=2,
        threshold=0.9,
        matrix_version="1.0",
        budget={"unit": "attempted_job", "attempted": 2},
        schedule=[],
        target_count=1,
    )
    assert path.is_file()
    entries = {item["instance_id"]: item for item in payload["candidates"]}
    assert entries["VM-A1"]["selected_for_release"] is True
    assert entries["VM-A2"]["selected_for_release"] is False
    assert entries["VM-A2"]["duplicate_of"] == "VM-A1"


def _entry(instance_id: str, kind: VariantKind, *, pair_id="PAIR-1", group_id=None):
    return ReleaseInstanceEntry(
        instance_id=instance_id,
        pair_id=pair_id,
        variant_kind=kind,
        manipulation_tier="M0" if kind == VariantKind.CLEAN else "M2",
        audit_difficulty="D2",
        release_split="dev-known",
        oracle_id="VMO-1",
        repository_url="file:///tmp/fixture",
        vulnerable_commit="a" * 40,
        release_eligible=True,
        repository_tree_sha256="b" * 64,
        task_file=f"instances/{instance_id}/task.md",
        oracle_file=f"oracles/VMO-1.json",
        validation_file=f"instances/{instance_id}/validation.json",
        group_id=group_id,
    )


def _manifest(entries) -> ReleaseManifest:
    return ReleaseManifest(
        schema_version="1.0",
        release_id="REL-1",
        name="test",
        release_version="v0",
        created_at="2026-01-01T00:00:00Z",
        config_sha256="c" * 64,
        source_dataset="test",
        splits=["dev-known"],
        instance_count=len(entries),
        pair_count=1,
        instances=entries,
        pairs=[ReleasePair(pair_id="PAIR-1", clean_instance_id="VM-CLEAN")],
        groups=[
            VariantGroup(
                group_id="GROUP-1",
                oracle_id="VMO-1",
                pair_id="PAIR-1",
                clean_instance_id="VM-CLEAN",
                adversarial_instance_id="VM-A1",
                benign_instance_id="VM-A1-B",
                truthful_security_instance_id="VM-A1-T",
            )
        ],
    )


def test_limit_keeps_controls_for_selected_attack() -> None:
    manifest = _manifest(
        [
            _entry("VM-CLEAN", VariantKind.CLEAN),
            _entry("VM-A1", VariantKind.ADVERSARIAL, group_id="GROUP-1"),
            _entry("VM-A1-B", VariantKind.BENIGN_CONTROL, group_id="GROUP-1"),
            _entry("VM-A1-T", VariantKind.BENIGN_CONTROL, group_id="GROUP-1"),
            _entry("VM-A2", VariantKind.ADVERSARIAL, group_id="GROUP-2"),
            _entry("VM-A2-B", VariantKind.BENIGN_CONTROL, group_id="GROUP-2"),
        ]
    )
    selected = {entry.instance_id for entry in select_release_entries(manifest, limit=1)}
    assert selected == {"VM-A1", "VM-A1-B", "VM-A1-T", "VM-CLEAN"}


# ------------------------------------------------------------------ P0-4
def _stdout(tmp_path: Path, events: list[dict]) -> Path:
    path = tmp_path / "stdout.log"
    path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
    return path


def test_opencode_final_answer_ignores_tool_results(tmp_path: Path) -> None:
    envelope = {"schema_version": "1.0", "findings": [{"finding_id": "F-1"}]}
    stdout = _stdout(
        tmp_path,
        [
            {"type": "text", "part": {"type": "text", "text": "I will inspect the repo."}},
            {
                "type": "tool_result",
                "part": {
                    "type": "tool_result",
                    "text": json.dumps({"schema_version": "1.0", "findings": [{"finding_id": "DECOY"}]}),
                },
            },
            {"type": "text", "part": {"type": "text", "text": json.dumps(envelope)}},
        ],
    )
    trace = tmp_path / "trace.jsonl"
    result = split_json_stream_result(stdout, trace)
    assert result.status == "ok"
    assert "DECOY" not in (result.final_text or "")
    assert "F-1" in (result.final_text or "")
    assert trace.is_file()


def test_opencode_ambiguous_and_unknown_formats_degrade(tmp_path: Path) -> None:
    stdout = _stdout(
        tmp_path,
        [
            {"type": "text", "part": {"type": "text", "text": '{"findings": [{"finding_id": "F-1"}]}'}},
            {"type": "text", "part": {"type": "text", "text": '{"findings": [{"finding_id": "F-2"}]}'}},
        ],
    )
    trace = tmp_path / "trace.jsonl"
    result = split_json_stream_result(stdout, trace)
    assert result.status == "ambiguous"
    assert trace.is_file()

    unsupported = split_json_stream_result(
        stdout, trace, event_format="some-future-format"
    )
    assert unsupported.status == "unsupported"


def test_relative_agent_config_resolves_once(tmp_path: Path, project_root: Path) -> None:
    loaded = load_agent_config(project_root / "configs" / "opencode.yaml")
    assert loaded.config.config_file == "opencode.json"
    resolved = (loaded.base_dir / loaded.config.config_file).resolve()
    assert resolved == (project_root / "configs" / "opencode.json").resolve()
    assert loaded.config.output_format == "json"
    assert "OPENCODE_API_KEY" in loaded.config.credential_env_allowlist


def _agent_run(run_id: str, instance_id: str) -> AgentRun:
    return AgentRun(
        run_id=run_id,
        instance_id=instance_id,
        repetition=1,
        model_provider="p",
        model_name="m",
        scaffold="opencode",
        prompt_sha256="a" * 64,
        time_budget_seconds=30,
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:00:10Z",
        status="pending",
        raw_events_path="e.jsonl",
        normalized_events_path="n.jsonl",
        tool_calls_path="t.jsonl",
        file_access_path="f.jsonl",
        process_events_path="p.jsonl",
        observability_grade="D",
        stdout_path="o.log",
        stderr_path="e.log",
        final_raw_path="r.txt",
    )


def test_each_opencode_run_gets_isolated_state(tmp_path: Path, project_root: Path) -> None:
    loaded = make_test_config(tmp_path, project_root, workspace_name="ws")
    store = InstanceStore(loaded.paths)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    instance: BenchmarkInstance = make_instance(instance_id="VM-1")
    task = tmp_path / "task.md"
    task.write_text("audit\n", encoding="utf-8")
    agent = AgentConfig(
        adapter="opencode",
        executable="opencode",
        output_format="json",
        scaffold="opencode",
    )
    prepared = []
    for run_id in ("RUN-1", "RUN-2"):
        adapter = SubprocessAgentAdapter(
            loaded=loaded, agent_config=agent, store=store, agent_base_dir=tmp_path
        )
        prepared.append(
            adapter.prepare(
                instance,
                _agent_run(run_id, instance.instance_id),
                source_repo=repo,
                task_path=task,
            )
        )
    assert prepared[0].env["HOME"] != prepared[1].env["HOME"]
    assert prepared[0].env["XDG_CONFIG_HOME"] != prepared[1].env["XDG_CONFIG_HOME"]


# ------------------------------------------------------------------ P0-5
def test_trace_probe_classifies_environment() -> None:
    ok = probe_os_trace(
        "auto",
        platform_name="posix",
        which=lambda _: "/usr/bin/strace",
        runner=lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "", ""),
        cache=False,
    )
    assert ok.available and ok.status == "available"

    missing = probe_os_trace(
        "auto", platform_name="posix", which=lambda _: None, cache=False
    )
    assert missing.status == "strace_missing"

    denied = probe_os_trace(
        "auto",
        platform_name="posix",
        which=lambda _: "/usr/bin/strace",
        runner=lambda *a, **k: subprocess.CompletedProcess(
            a[0], 1, "", "strace: ptrace(PTRACE_TRACEME): Operation not permitted"
        ),
        cache=False,
    )
    assert denied.status == "ptrace_denied"

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 1)

    timed = probe_os_trace(
        "auto",
        platform_name="posix",
        which=lambda _: "/usr/bin/strace",
        runner=timeout,
        cache=False,
    )
    assert timed.status == "probe_timeout"


def test_trace_probe_is_cached() -> None:
    calls = {"n": 0}

    def runner(*args, **kwargs):
        calls["n"] += 1
        return subprocess.CompletedProcess(args[0], 0, "", "")

    first = probe_os_trace(
        "auto",
        platform_name="posix",
        which=lambda _: "/cache-test/strace",
        runner=runner,
    )
    second = probe_os_trace(
        "auto",
        platform_name="posix",
        which=lambda _: "/cache-test/strace",
        runner=runner,
    )
    assert first.available and second.available
    assert calls["n"] == 1
    assert second.cached is True


def test_required_trace_failure_aborts_before_agent(
    tmp_path: Path, project_root: Path, monkeypatch
) -> None:
    from vulnmirage.harness.observation import os_trace as os_trace_module
    from vulnmirage.harness.observation.os_trace import TraceProbe

    def fake_probe(mode):
        return TraceProbe(False, "ptrace_denied", reason="ptrace denied")

    monkeypatch.setattr(os_trace_module, "probe_os_trace", fake_probe)
    loaded = make_test_config(tmp_path, project_root, workspace_name="ws")
    loaded.config.observation.os_trace = "required"
    store = InstanceStore(loaded.paths)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    task = tmp_path / "task.md"
    task.write_text("audit\n", encoding="utf-8")
    adapter = SubprocessAgentAdapter(
        loaded=loaded,
        agent_config=AgentConfig(adapter="subprocess", argv=["python", "{task}", "{output}", "{repo}"]),
        store=store,
        agent_base_dir=tmp_path,
    )
    with pytest.raises(HarnessError) as excinfo:
        adapter.prepare(
            make_instance(instance_id="VM-1"),
            _agent_run("RUN-1", "VM-1"),
            source_repo=repo,
            task_path=task,
        )
    assert excinfo.value.details.get("failure_type") == "observation_setup_failure"
