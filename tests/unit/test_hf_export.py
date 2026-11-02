"""Hugging Face dataset export: tables, joins, splits and manifest."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from tests.support import make_oracle


def _load_exporter():
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts" / "export_hf_dataset.py"
    spec = importlib.util.spec_from_file_location("export_hf_dataset", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _normalized(tmp_path: Path) -> Path:
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    imported = []
    for index, repo in enumerate(
        ["https://github.com/acme/one", "https://github.com/acme/two"]
    ):
        base_oracle = make_oracle()
        oracle = base_oracle.model_copy(
            update={
                "hidden_metadata": {
                    **base_oracle.hidden_metadata,
                    "report_id": f"case-{index}",
                    "evidence_scope": "entry_and_sink_only",
                    "trace_available": False,
                    "poc_available": False,
                    "repovuln": {
                        "repo_full_name": repo.rsplit("/", 1)[-1],
                        "repo_id": str(index),
                        "primary_language": "Python",
                        "snapshot_id": f"snap-{index}",
                        "data_scope": ["live"],
                        "review_grade": ["A"],
                        "proof_methods": ["version_range_plus_code"],
                        "limitation": "no trace",
                    },
                }
            }
        ).model_copy(
            update={
                "repository": make_oracle().repository.model_copy(
                    update={"repo_url": repo}
                ),
                "vulnerabilities": [
                    vulnerability.model_copy(
                        update={
                            "paths": [
                                path.model_copy(update={"trace": []})
                                for path in vulnerability.paths
                            ]
                        }
                    )
                    for vulnerability in base_oracle.vulnerabilities
                ],
            }
        )
        file = f"VMO-{index}.json"
        (normalized / file).write_text(
            json.dumps(oracle.model_dump(mode="json")), encoding="utf-8"
        )
        imported.append(
            {
                "oracle_id": oracle.oracle_id,
                "file": file,
                "sha256": "0" * 64,
                "repo_url": repo,
                "vulnerable_commit": oracle.repository.vulnerable_commit,
            }
        )
    (normalized / "index.json").write_text(
        json.dumps(
            {
                "imported": imported,
                "limitations": {
                    "evidence_scope": "entry_and_sink_only",
                    "trace_available": False,
                    "poc_available": False,
                },
                "workbook": "synthetic.xlsx",
                "workbook_sha256": "1" * 64,
            }
        ),
        encoding="utf-8",
    )
    return normalized


def test_export_tables_join_and_no_repo_overlap(tmp_path: Path) -> None:
    exporter = _load_exporter()
    result = exporter.export_hf_dataset(
        normalized_dir=_normalized(tmp_path),
        output_dir=tmp_path / "hf",
        dataset_version="test",
        dev_ratio=0.5,
        seed=7,
    )
    assert result["ok"] is True
    assert result["counts"]["cases"] == 2
    assert result["counts"]["vulnerabilities"] == 2
    assert result["counts"]["paths"] == 2
    assert result["repository_overlap"] == []

    cases = [
        json.loads(line)
        for split in ("dev", "test")
        for line in (tmp_path / "hf" / "data" / "cases" / f"{split}.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    vulnerabilities = [
        json.loads(line)
        for split in ("dev", "test")
        for line in (tmp_path / "hf" / "data" / "vulnerabilities" / f"{split}.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    paths = [
        json.loads(line)
        for split in ("dev", "test")
        for line in (tmp_path / "hf" / "data" / "paths" / f"{split}.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    case_ids = {row["case_id"] for row in cases}
    assert all(row["case_id"] in case_ids for row in vulnerabilities)
    assert {row["vulnerability_id"] for row in paths} <= {
        row["vulnerability_id"] for row in vulnerabilities
    }
    assert all(row["trace_available"] is False for row in paths)
    assert (tmp_path / "hf" / "README.md").is_file()
    manifest = json.loads(
        (tmp_path / "hf" / "dataset_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["files"]
    assert set(manifest["split_repositories"]) == {"dev", "test"}
