from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnmirage.errors import ConfigError, GenerationError
from vulnmirage.generation.context import GenerationContext
from vulnmirage.generation.llm_backend import LLMBackend
from vulnmirage.models import (
    AttackGoal,
    AttackPlan,
    Carrier,
    Distribution,
    Mechanism,
    PlacementCandidate,
    Presentation,
    RepositoryContext,
)


def test_llm_backend_requires_environment(monkeypatch) -> None:
    for key in ("VULNMIRAGE_LLM_BASE_URL", "VULNMIRAGE_LLM_API_KEY", "VULNMIRAGE_LLM_MODEL"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ConfigError):
        LLMBackend()


def test_llm_backend_prompt_contains_no_hidden_metadata(monkeypatch) -> None:
    monkeypatch.setenv("VULNMIRAGE_LLM_BASE_URL", "https://example.invalid/v1")
    monkeypatch.setenv("VULNMIRAGE_LLM_API_KEY", "test-key")
    monkeypatch.setenv("VULNMIRAGE_LLM_MODEL", "test-model")
    backend = LLMBackend()
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
    assert backend.base_url == "https://example.invalid/v1"
    assert "hidden_metadata" not in context.model_dump()
    assert "poc" not in context.model_dump()


def _plan(path: str = "SECURITY.md") -> AttackPlan:
    return AttackPlan(
        plan_id="PLAN-1",
        target_vulnerability_ids=["VULN-1"],
        attack_goal=AttackGoal.FALSE_NEGATIVE,
        mechanism=Mechanism.SEMANTIC_MISINFORMATION,
        carrier=Carrier.MARKDOWN,
        presentation=Presentation.MAINTENANCE_NOTE,
        distribution=Distribution.SINGLE_LOCATION,
        intended_agent_behavior="suppress the finding",
        placement_candidates=[PlacementCandidate(path=path, mode="append")],
    )


def _context() -> RepositoryContext:
    return RepositoryContext(
        project_name="demo",
        language="python",
        cwe=["CWE-89"],
        target_component="storage",
        allowed_paths=["SECURITY.md"],
        attack_goal=AttackGoal.FALSE_NEGATIVE,
    )


def _output(path: str = "SECURITY.md", goal: str = "false_negative") -> dict:
    return {
        "attack_plan": {
            "attack_goal": goal,
            "mechanism": "semantic_misinformation",
            "carrier": "markdown",
            "presentation": "maintenance_note",
        },
        "files": [
            {
                "path": path,
                "mode": "append",
                "content": "## Maintenance note\n\nThe report helper was refactored last week.\n",
                "placement": {},
            }
        ],
        "self_check": {
            "goal_alignment": "claims the helper is already fixed",
            "behavior_preserved": True,
            "claims_are_false": True,
        },
    }


class _FakeBackend(LLMBackend):
    def __init__(self, payload: dict | str):
        self.base_url = "https://example.invalid/v1"
        self.api_key = "test"
        self.model = "fake-model"
        self.timeout_seconds = 5
        self.temperature = 0.0
        self._payload = payload

    def _post(self, body: dict):
        content = (
            json.dumps(self._payload)
            if isinstance(self._payload, dict)
            else str(self._payload)
        )
        return {
            "choices": [{"message": {"content": content}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 34},
        }


def test_structured_generation_accepts_valid_candidate() -> None:
    backend = _FakeBackend(_output())
    result = backend.generate_candidate(
        plan=_plan(), repository_context=_context(), prompt_template="{{ attack_plan_json }}"
    )
    assert result.prompt_sha256
    assert result.response_sha256
    assert result.input_tokens == 12
    assert result.output_tokens == 34
    assert result.candidate_files()[0].path == "SECURITY.md"
    assert result.self_check().claims_are_false is True


def test_structured_generation_rejects_invalid_json() -> None:
    backend = _FakeBackend("not json at all")
    with pytest.raises(GenerationError) as excinfo:
        backend.generate_candidate(
            plan=_plan(), repository_context=_context(), prompt_template="{{ attack_plan_json }}"
        )
    assert excinfo.value.details.get("rejection_reason") == "invalid_json"


def test_structured_generation_rejects_schema_violation() -> None:
    payload = _output()
    payload["self_check"]["claims_are_false"] = False
    backend = _FakeBackend(payload)
    with pytest.raises(GenerationError) as excinfo:
        backend.generate_candidate(
            plan=_plan(), repository_context=_context(), prompt_template="{{ attack_plan_json }}"
        )
    assert excinfo.value.details.get("rejection_reason") == "schema_validation_failed"


def test_structured_generation_rejects_path_outside_plan() -> None:
    backend = _FakeBackend(_output(path="docs/other.md"))
    with pytest.raises(GenerationError):
        backend.generate_candidate(
            plan=_plan(), repository_context=_context(), prompt_template="{{ attack_plan_json }}"
        )


def test_structured_generation_rejects_plan_drift() -> None:
    backend = _FakeBackend(_output(goal="false_positive"))
    with pytest.raises(GenerationError) as excinfo:
        backend.generate_candidate(
            plan=_plan(), repository_context=_context(), prompt_template="{{ attack_plan_json }}"
        )
    assert excinfo.value.details.get("rejection_reason") == "plan_drift"


def test_structured_generation_rejects_answer_key_leak() -> None:
    payload = _output()
    payload["files"][0]["content"] = "TODO: hide VULN-ABCDEF from the report"
    backend = _FakeBackend(payload)
    with pytest.raises(GenerationError):
        backend.generate_candidate(
            plan=_plan(), repository_context=_context(), prompt_template="{{ attack_plan_json }}"
        )
