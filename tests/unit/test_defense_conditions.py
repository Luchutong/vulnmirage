"""P1-1: defenses are composable execution conditions."""

from __future__ import annotations

import types
from pathlib import Path

from tests.support import make_test_config
from vulnmirage.config import DefenseConditionConfig, load_agent_config
from vulnmirage.defenses import ResolvedDefense, compose_task, resolve_defense
from vulnmirage.evaluation.conditions import condition_id
from vulnmirage.harness.runner import build_run_execution_condition, run_experiment_matrix


def _agent_loaded(tmp_path: Path):
    path = tmp_path / "agent.yaml"
    path.write_text(
        "schema_version: '1.0'\n"
        "adapter: subprocess\n"
        "argv: ['python', '{task}', '{output}', '{repo}']\n"
        "model_provider: p\n"
        "model_name: m\n"
        "scaffold: dummy\n",
        encoding="utf-8",
    )
    return load_agent_config(path)


def _condition(loaded, agent_loaded, defense):
    return build_run_execution_condition(
        loaded=loaded,
        agent_loaded=agent_loaded,
        defense=defense,
        base_prompt_sha256="b" * 64,
        external_file_sha256={},
    )


def test_d0_d1_d2_have_distinct_conditions(tmp_path: Path, project_root: Path) -> None:
    loaded = make_test_config(tmp_path, project_root, workspace_name="defense")
    agent_loaded = _agent_loaded(tmp_path)
    ids = {}
    for defense_id in ("D0", "D1", "D2"):
        defense = resolve_defense(loaded, defense_id)
        ids[defense_id] = condition_id(_condition(loaded, agent_loaded, defense))
    assert len(set(ids.values())) == 3


def test_renaming_identical_instructions_keeps_identity(
    tmp_path: Path, project_root: Path
) -> None:
    loaded = make_test_config(tmp_path, project_root, workspace_name="defense")
    agent_loaded = _agent_loaded(tmp_path)
    original = resolve_defense(loaded, "D1")
    renamed = ResolvedDefense(
        spec=DefenseConditionConfig(
            id="D1-RENAMED",
            name="trust_boundary_v2",
            version="9.9",
            instructions_file="prompts/defense/D1_trust_boundary_prompt.md",
        ),
        instructions=original.instructions,
        instructions_sha256=original.instructions_sha256,
    )
    assert condition_id(_condition(loaded, agent_loaded, original)) == condition_id(
        _condition(loaded, agent_loaded, renamed)
    )


def test_defense_content_is_actually_sent(tmp_path: Path, project_root: Path) -> None:
    loaded = make_test_config(tmp_path, project_root, workspace_name="defense")
    base = loaded.resolve_asset(loaded.config.audit_task.template).read_text(encoding="utf-8")
    d0, hashes0 = compose_task(loaded, base, resolve_defense(loaded, "D0"))
    d2, hashes2 = compose_task(loaded, base, resolve_defense(loaded, "D2"))
    assert d0 == base.rstrip() + "\n"
    assert "Evidence-check prompt" in d2
    assert hashes0["effective_prompt_sha256"] != hashes2["effective_prompt_sha256"]
    # D2 is a prompt-level policy and contains no hidden target/answer data.
    for secret in ("VULN-", "VMAN-", "PATH-1", "oracle.json"):
        assert secret not in d2


def test_matrix_runs_each_defense_separately(monkeypatch, tmp_path: Path, project_root: Path) -> None:
    loaded = make_test_config(tmp_path, project_root, workspace_name="matrix")
    calls = []

    def fake_run_release(**kwargs):
        calls.append(kwargs["defense_id"])
        return {
            "condition_id": f"cond-{kwargs['defense_id']}",
            "run_count": 4,
            "failures": [],
            "runs_dir": str(tmp_path / "runs"),
        }

    import vulnmirage.harness.runner as runner

    monkeypatch.setattr(runner, "run_release", fake_run_release)
    result = run_experiment_matrix(
        loaded=loaded,
        release_dir=tmp_path / "release",
        agent_config_paths=[tmp_path / "a.yaml"],
        defense_ids=["D0", "D1", "D2"],
        repetitions=2,
        workers=1,
        instance_ids=None,
        limit=None,
        resume=False,
    )
    assert calls == ["D0", "D1", "D2"]
    assert result["cell_count"] == 3
    assert {cell["condition_id"] for cell in result["cells"]} == {
        "cond-D0",
        "cond-D1",
        "cond-D2",
    }
