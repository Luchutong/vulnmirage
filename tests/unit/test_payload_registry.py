from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnmirage.config import ConfigError
from vulnmirage.generation.context import GenerationContext
from vulnmirage.generation.payload_registry import load_payload_registry, registry_summary


@pytest.fixture(scope="module")
def registry(project_root: Path):
    return load_payload_registry(project_root / "payloads" / "registry.yaml")


def test_registry_loads_and_hashes(registry) -> None:
    reg, base_dir = registry
    assert len(reg.payloads) >= 13
    assert reg.registry_sha256
    assert base_dir.name == "payloads"
    summary = registry_summary(reg)
    assert summary["payload_count"] == len(reg.payloads)
    assert "public_known" in summary["splits"]


def test_all_templates_exist_and_strategy_selection(registry) -> None:
    reg, base_dir = registry
    for payload in reg.payloads:
        assert (base_dir / payload.template_file).is_file()
        for goal in payload.compatible_goals:
            for carrier in payload.compatible_carriers:
                selected = reg.select(
                    strategy_family=payload.strategy_family,
                    goal=goal,
                    carrier=carrier,
                )
                assert selected


def test_render_context_has_no_undefined(project_root: Path, registry) -> None:
    reg, base_dir = registry
    context = GenerationContext(
        project_name="demo",
        language="python",
        vulnerability_type="SQL injection",
        cwe=["CWE-89"],
        target_component="storage",
        visible_function_names=["execute_query"],
        attack_goal="false_negative",
        carrier="markdown",
    )
    for payload in reg.payloads:
        carrier = payload.compatible_carriers[0]
        goal = payload.compatible_goals[0]
        bound = context.model_copy(update={"attack_goal": goal, "carrier": carrier})
        text, provenance = reg.render(payload, bound, base_dir=base_dir, seed=7)
        assert text.strip()
        assert provenance.payload_id == payload.payload_id
        assert provenance.prompt_sha256
        assert len(provenance.prompt_sha256) == 64


def test_registry_rejects_missing_template(tmp_path: Path, project_root: Path) -> None:
    source = (project_root / "payloads" / "registry.yaml").read_text(encoding="utf-8")
    source = source.replace("templates/m2_false_fix_status.md.j2", "templates/missing.j2")
    path = tmp_path / "registry.yaml"
    path.write_text(source, encoding="utf-8")
    (tmp_path / "templates").mkdir()
    with pytest.raises(ConfigError):
        load_payload_registry(path)


def test_registry_rejects_duplicate_ids(tmp_path: Path, project_root: Path) -> None:
    import yaml

    raw = yaml.safe_load((project_root / "payloads" / "registry.yaml").read_text(encoding="utf-8"))
    raw["payloads"].append(raw["payloads"][0])
    path = tmp_path / "registry.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    import shutil

    shutil.copytree(project_root / "payloads" / "templates", tmp_path / "templates")
    with pytest.raises(ConfigError):
        load_payload_registry(path)


def test_published_verbatim_requires_license(tmp_path: Path) -> None:
    import yaml

    raw = {
        "schema_version": "1.0",
        "registry_version": "test",
        "payloads": [
            {
                "payload_id": "p1",
                "origin": "published_verbatim",
                "strategy_family": "instruction_override",
                "compatible_goals": ["false_negative"],
                "compatible_carriers": ["markdown"],
                "template_file": "templates/x.j2",
                "source_url": "https://example.com/x",
            }
        ],
    }
    path = tmp_path / "registry.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "x.j2").write_text("x", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_payload_registry(path)


def test_unknown_selection_is_error(registry) -> None:
    reg, _ = registry
    with pytest.raises(Exception):
        reg.select_one(
            strategy_family="does_not_exist",
            goal="false_negative",
            carrier="markdown",
        )
