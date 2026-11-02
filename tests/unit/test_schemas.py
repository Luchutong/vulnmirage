from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from tests.support import (
    make_decoy,
    make_envelope,
    make_instance,
    make_manipulation,
    make_oracle,
)
from vulnmirage.models import AgentRun, ValidationReport, ValidationResult
from vulnmirage.schemas import SCHEMA_FILES, build_schema, generate_schemas


@pytest.mark.parametrize(
    ("filename", "payload_factory"),
    [
        ("oracle.schema.json", make_oracle),
        ("manipulation.schema.json", make_manipulation),
        ("decoy.schema.json", make_decoy),
        ("finding.schema.json", make_envelope),
        ("instance.schema.json", make_instance),
    ],
)
def test_models_validate_against_exported_schema(
    tmp_path: Path, filename: str, payload_factory
) -> None:
    generate_schemas(tmp_path)
    schema = json.loads((tmp_path / filename).read_text(encoding="utf-8"))
    payload = payload_factory().model_dump(mode="json")
    jsonschema.validate(instance=payload, schema=schema)


def test_validation_report_schema(tmp_path: Path) -> None:
    generate_schemas(tmp_path)
    schema = json.loads((tmp_path / "validation.schema.json").read_text(encoding="utf-8"))
    report = ValidationReport(
        instance_id="VM-1",
        results=[
            ValidationResult(
                check_name="schema",
                status="pass",
                started_at="2026-01-01T00:00:00Z",
                duration_seconds=0.01,
            )
        ],
        ground_truth_preserved=True,
        release_eligible=True,
        validation_level="trace_grounded",
    ).with_digest()
    jsonschema.validate(instance=report.model_dump(mode="json"), schema=schema)


def test_run_schema(tmp_path: Path) -> None:
    generate_schemas(tmp_path)
    schema = json.loads((tmp_path / "run.schema.json").read_text(encoding="utf-8"))
    run = AgentRun(
        run_id="RUN-1",
        instance_id="VM-1",
        repetition=1,
        model_provider="dummy",
        model_name="dummy",
        scaffold="subprocess",
        prompt_sha256="a" * 64,
        tool_policy={},
        time_budget_seconds=60,
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:01:00Z",
        status="success",
        raw_events_path="runs/RUN-1/events.raw.jsonl",
        normalized_events_path="runs/RUN-1/events.normalized.jsonl",
        tool_calls_path="runs/RUN-1/tool_calls.jsonl",
        file_access_path="runs/RUN-1/file_access.jsonl",
        process_events_path="runs/RUN-1/process_events.jsonl",
        observability_grade="B",
        final_raw_path="runs/RUN-1/final_raw.txt",
        stdout_path="runs/RUN-1/stdout.log",
        stderr_path="runs/RUN-1/stderr.log",
    )
    jsonschema.validate(instance=run.model_dump(mode="json"), schema=schema)


def test_extra_fields_rejected_by_schema(tmp_path: Path) -> None:
    generate_schemas(tmp_path)
    schema = json.loads((tmp_path / "instance.schema.json").read_text(encoding="utf-8"))
    payload = make_instance().model_dump(mode="json")
    payload["surprise"] = "nope"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=payload, schema=schema)


def test_all_schema_files_generated(tmp_path: Path) -> None:
    from vulnmirage.schemas import dataset_schema_files

    expected = {**SCHEMA_FILES, **dataset_schema_files()}
    digests = generate_schemas(tmp_path)
    assert set(digests) == set(expected)
    for filename in expected:
        schema = json.loads((tmp_path / filename).read_text(encoding="utf-8"))
        assert schema["$schema"].startswith("https://json-schema.org/draft/2020-12")
        assert "title" in schema


def test_build_schema_refs_are_local() -> None:
    schema = build_schema(make_oracle().__class__)
    text = json.dumps(schema)
    assert "#/$defs/" in text
    assert "http://" not in text.replace("https://json-schema.org", "")

