#!/usr/bin/env python3
"""Export an ingested VulnMirage/RepoVuln release as a Hugging Face dataset.

Layout (all UTF-8 JSONL, one object per line):

    hf_dataset/
      README.md                       # dataset card + config/split metadata
      dataset_manifest.json           # provenance, counts, checksums
      data/cases/{dev,test}.jsonl     # one repository snapshot per row
      data/vulnerabilities/{dev,test}.jsonl
      data/paths/{dev,test}.jsonl
      LICENSE-NOTES.md                # no license is invented

Keys: ``case_id`` joins cases/vulnerabilities; ``vulnerability_id`` joins
vulnerabilities/paths.  Ground truth is intentionally in the dataset and must
never be shown to the audited agent at run time.

Usage:
    python scripts/export_hf_dataset.py \
      --normalized workspace/repovuln/normalized \
      --output hf_dataset/repovuln-50 \
      --dataset-version 2026.10.30 \
      --dev-ratio 0.7 --seed 20261030
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

try:  # fail with an actionable message instead of an import traceback
    import pydantic  # noqa: F401
except ModuleNotFoundError:
    venv_python = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
    if not venv_python.is_file():
        venv_python = PROJECT_ROOT / ".venv" / "bin" / "python"
    raise SystemExit(
        "This script is running with an interpreter that lacks the project "
        "dependencies (pydantic).\n"
        f"Current interpreter: {sys.executable}\n"
        f"Project venv: {venv_python}\n"
        f"Run: {venv_python} scripts/export_hf_dataset.py ...\n"
        "Or:  .venv/Scripts/python -m pip install -e \".[dev]\" "
        "(plus `datasets` if you want dataset_info)."
    )

HF_SCHEMA_VERSION = "1.0"
SPLITS = {"dev": "dev-known", "test": "test-heldout-repository"}


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _assign_split(
    repo_url: str,
    *,
    dev_ratio: float,
    seed: int,
    split_policy: str,
) -> str:
    if split_policy == "none":
        return "dev"
    digest = hashlib.sha256(f"{seed}|{repo_url}".encode("utf-8")).hexdigest()
    bucket = int(digest[:8], 16) / 0xFFFFFFFF
    return "dev" if bucket < dev_ratio else "test"


def _case_row(oracle, oracle_path: Path, split_name: str) -> dict[str, Any]:
    metadata = oracle.hidden_metadata or {}
    repo_vuln = metadata.get("repovuln") or {}
    repo = oracle.repository
    case_id = metadata.get("report_id") or f"case:{oracle.oracle_id}"
    return {
        "case_id": case_id,
        "oracle_id": oracle.oracle_id,
        "schema_version": HF_SCHEMA_VERSION,
        "dataset_split": SPLITS[split_name],
        "split_name": split_name,
        "repo_id": repo_vuln.get("repo_id") or "",
        "repo_full_name": repo_vuln.get("repo_full_name") or "",
        "repo_url": repo.repo_url,
        "vulnerable_commit": repo.vulnerable_commit,
        "fixed_commit": repo.fixed_commit,
        "primary_language": repo_vuln.get("primary_language"),
        "snapshot_id": repo_vuln.get("snapshot_id"),
        "data_scope": repo_vuln.get("data_scope"),
        "evaluation_target": repo_vuln.get("evaluation_target"),
        "review_grade": repo_vuln.get("review_grade") or [],
        "proof_methods": repo_vuln.get("proof_methods") or [],
        "vulnerability_count": len(oracle.vulnerabilities),
        "vulnerability_ids": [
            vulnerability.vulnerability_id for vulnerability in oracle.vulnerabilities
        ],
        "evidence_scope": metadata.get("evidence_scope") or "",
        "trace_available": bool(metadata.get("trace_available", False)),
        "poc_available": bool(metadata.get("poc_available", False)),
        "oracle_file": oracle_path.name,
        "limitation": repo_vuln.get("limitation") or "",
    }


def _severity(vulnerability) -> dict[str, Any] | None:
    severity = vulnerability.severity
    if severity is None:
        return None
    return {
        "scheme": severity.scheme,
        "level": severity.level.value,
        "score": severity.score,
        "vector": severity.vector,
        "rationale": severity.rationale,
        "validation_status": severity.validation_status.value,
        "source": severity.source.model_dump(mode="json"),
    }


def _vulnerability_row(
    oracle, vulnerability, case_id: str, split_name: str
) -> dict[str, Any]:
    paths = vulnerability.paths
    entry_points = [
        {
            "path_id": path.path_id,
            "file": path.entry_point.file,
            "start_line": path.entry_point.start_line,
            "end_line": path.entry_point.end_line,
        }
        for path in paths
    ]
    critical_operations = [
        {
            "path_id": path.path_id,
            "file": path.critical_operation.file,
            "start_line": path.critical_operation.start_line,
            "end_line": path.critical_operation.end_line,
        }
        for path in paths
    ]
    return {
        "vulnerability_id": vulnerability.vulnerability_id,
        "case_id": case_id,
        "oracle_id": oracle.oracle_id,
        "dataset_split": SPLITS[split_name],
        "repo_url": oracle.repository.repo_url,
        "vulnerable_commit": oracle.repository.vulnerable_commit,
        "dataset_identifiers": list(vulnerability.aliases),
        "title": vulnerability.title,
        "category_l1": vulnerability.category_l1 or "",
        "category_l2": vulnerability.category_l2 or "",
        "cwe_ids": list(vulnerability.cwe),
        "severity": _severity(vulnerability),
        "root_cause": vulnerability.root_cause or "",
        "path_count": len(paths),
        "entry_points": entry_points,
        "critical_operations": critical_operations,
        "affected_files": list(vulnerability.affected_files),
        "poc_available": bool(vulnerability.poc_commands),
        "regression_commands_available": bool(vulnerability.regression_commands),
    }


def _path_rows(oracle, vulnerability, case_id: str, split_name: str):
    for path in vulnerability.paths:
        yield {
            "path_id": path.path_id,
            "vulnerability_id": vulnerability.vulnerability_id,
            "case_id": case_id,
            "dataset_split": SPLITS[split_name],
            "entry_point": {
                "file": path.entry_point.file,
                "start_line": path.entry_point.start_line,
                "end_line": path.entry_point.end_line,
            },
            "trace": [
                {
                    "file": node.file,
                    "start_line": node.start_line,
                    "end_line": node.end_line,
                }
                for node in path.trace
            ],
            "critical_operation": {
                "file": path.critical_operation.file,
                "start_line": path.critical_operation.start_line,
                "end_line": path.critical_operation.end_line,
            },
            "trace_available": bool(path.trace),
        }


def _dataset_card(
    *,
    dataset_version: str,
    source_workbook: str,
    source_sha256: str,
    counts: dict[str, Any],
    limitations: dict[str, Any],
) -> str:
    return f"""---
pretty_name: "RepoVuln-50 repository vulnerability benchmark"
language:
  - en
tags:
  - security
  - vulnerability-detection
  - code-audit
  - benchmark
  - repository-level
task_categories:
  - text-generation
  - question-answering
configs:
  - config_name: cases
    data_files:
      - split: dev
        path: data/cases/dev.jsonl
      - split: test
        path: data/cases/test.jsonl
  - config_name: vulnerabilities
    data_files:
      - split: dev
        path: data/vulnerabilities/dev.jsonl
      - split: test
        path: data/vulnerabilities/test.jsonl
  - config_name: paths
    data_files:
      - split: dev
        path: data/paths/dev.jsonl
      - split: test
        path: data/paths/test.jsonl
---

# RepoVuln-50 (Hugging Face export)

Dataset version: `{dataset_version}`
Source workbook: `{source_workbook}`
Source SHA-256: `{source_sha256}`
Records: {counts['cases']} repository snapshots, {counts['vulnerabilities']} vulnerabilities, {counts['paths']} paths.

## Schema

- **cases**: one repository snapshot = one `(repo_url, vulnerable_commit)`.
  `case_id` is the primary key.
- **vulnerabilities**: one numbered vulnerability (CVE/GHSA/etc.) per row.
  `vulnerability_id` is the canonical key; `dataset_identifiers` holds CVE/GHSA
  aliases. `case_id` joins to `cases`.
- **paths**: one entry-point → trace → critical-operation path per row.
  `vulnerability_id` joins to `vulnerabilities`. Multi-path vulnerabilities are
  multiple rows; a vulnerability counts as detected when any path matches.

Splits are assigned **by repository**, never by vulnerability or template, so
the same repository/commit cannot appear in both dev and test. Split policy is
recorded in `dataset_manifest.json`.

## Important limitations

- `evidence_scope`: `{limitations.get('evidence_scope')}`. The source workbook
  provides entry and sink locations but **no ordered trace nodes**.
- `trace_available`: `{limitations.get('trace_available')}`.
- `poc_available`: `{limitations.get('poc_available')}`.
- No safe-target/decoy annotations are included; false-positive attacks need
  separate annotations.
- **Ground truth warning:** `vulnerabilities` and `paths` contain the answer.
  Never expose these files to an audited agent; only `cases` metadata, the
  repository checkout, and the audit task may be visible.
- Source code is **not** redistributed. Fetch each repository at
  `repo_url`/`vulnerable_commit` yourself and comply with its licence.
- Annotation/release licensing must be decided by the dataset owner; this
  export does not invent a license.

## Loading

```python
from datasets import load_dataset
cases = load_dataset("path/to/hf_dataset", "cases")
vulns = load_dataset("path/to/hf_dataset", "vulnerabilities")
paths = load_dataset("path/to/hf_dataset", "paths")
```

For larger releases, convert the JSONL files to Parquet (`pyarrow`) and keep the
same config/split layout.
"""


def augment_dataset_info(output_dir: Path) -> dict[str, Any] | None:
    """Add a ``dataset_info`` block (features + split stats) via ``datasets``.

    The Hub viewer can auto-infer JSONL, but explicit ``dataset_info`` makes the
    preview deterministic and surfaces schema/feature errors locally instead of
    after upload.  This is optional: without ``datasets`` the card keeps the
    ``configs`` block.
    """
    import os

    # Keep the builder cache inside the export directory: the user's global HF
    # cache may be read-only, and the card must not depend on it.  Set this
    # *before* importing datasets, which snapshots the location at import time.
    cache_root = output_dir / ".hf-cache"
    previous = {key: os.environ.get(key) for key in ("HF_HOME", "HF_DATASETS_CACHE")}
    os.environ["HF_HOME"] = str(cache_root / "home")
    os.environ["HF_DATASETS_CACHE"] = str(cache_root / "datasets")
    try:
        from datasets import Dataset
        from datasets.info import DatasetInfo, DatasetInfosDict
        from datasets.splits import SplitDict, SplitInfo
    except Exception:  # noqa: BLE001 - optional dependency
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return None
    infos: dict[str, Any] = {}
    for table in ("cases", "vulnerabilities", "paths"):
        features = None
        splits = SplitDict()
        for split_name in ("dev", "test"):
            path = output_dir / "data" / table / f"{split_name}.jsonl"
            dataset = Dataset.from_json(str(path))
            if features is None:
                features = dataset.features
            elif dataset.features != features:
                raise SystemExit(
                    f"dev/test schema mismatch in {table}: "
                    f"{features} != {dataset.features}"
                )
            if dataset.num_rows:
                splits.add(
                    SplitInfo(
                        name=split_name,
                        num_bytes=path.stat().st_size,
                        num_examples=dataset.num_rows,
                    )
                )
        infos[table] = DatasetInfo(
            config_name=table, features=features, splits=splits
        )
    DatasetInfosDict(infos).write_to_directory(str(output_dir), overwrite=False)
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    import shutil

    shutil.rmtree(cache_root, ignore_errors=True)
    return {
        "dataset_info_configs": sorted(infos),
        "features": {table: list(info.features) for table, info in infos.items()},
    }


def export_hf_dataset(
    *,
    normalized_dir: Path,
    output_dir: Path,
    dataset_version: str,
    dev_ratio: float = 0.7,
    seed: int = 20261030,
    split_policy: str = "repo-hash",
) -> dict[str, Any]:
    from vulnmirage.models import CanonicalVulnerabilityOracle

    normalized_dir = Path(normalized_dir)
    output_dir = Path(output_dir)
    index_path = normalized_dir / "index.json"
    if not index_path.is_file():
        raise SystemExit(f"index.json not found in {normalized_dir}")
    index = _read_json(index_path)
    if not index.get("imported"):
        raise SystemExit("normalized index has no imported oracles")

    buckets: dict[str, dict[str, list[dict[str, Any]]]] = {
        "cases": {"dev": [], "test": []},
        "vulnerabilities": {"dev": [], "test": []},
        "paths": {"dev": [], "test": []},
    }
    seen_cases: set[str] = set()
    for entry in index["imported"]:
        oracle_path = normalized_dir / entry["file"]
        oracle = CanonicalVulnerabilityOracle.model_validate(_read_json(oracle_path))
        split_name = _assign_split(
            oracle.repository.repo_url,
            dev_ratio=dev_ratio,
            seed=seed,
            split_policy=split_policy,
        )
        case_row = _case_row(oracle, oracle_path, split_name)
        case_id = case_row["case_id"]
        if case_id in seen_cases:
            raise SystemExit(f"duplicate case_id in normalized input: {case_id}")
        seen_cases.add(case_id)
        buckets["cases"][split_name].append(case_row)
        for vulnerability in oracle.vulnerabilities:
            buckets["vulnerabilities"][split_name].append(
                _vulnerability_row(oracle, vulnerability, case_id, split_name)
            )
            buckets["paths"][split_name].extend(
                _path_rows(oracle, vulnerability, case_id, split_name)
            )

    for table, splits in buckets.items():
        for split_name, rows in splits.items():
            rows.sort(key=lambda row: (row["case_id"], row.get("vulnerability_id") or "", row.get("path_id") or ""))
            _write_jsonl(output_dir / "data" / table / f"{split_name}.jsonl", rows)

    counts = {
        "cases": sum(len(rows) for rows in buckets["cases"].values()),
        "vulnerabilities": sum(
            len(rows) for rows in buckets["vulnerabilities"].values()
        ),
        "paths": sum(len(rows) for rows in buckets["paths"].values()),
        "split_cases": {
            split_name: len(rows) for split_name, rows in buckets["cases"].items()
        },
        "split_vulnerabilities": {
            split_name: len(rows)
            for split_name, rows in buckets["vulnerabilities"].items()
        },
    }
    split_repos = {
        split_name: sorted(
            {
                row["repo_url"]
                for row in rows
                if row["repo_url"]
            }
        )
        for split_name, rows in buckets["cases"].items()
    }
    overlap = sorted(set(split_repos["dev"]) & set(split_repos["test"]))
    if overlap:
        raise SystemExit(
            "repository split overlap detected: " + ", ".join(overlap[:5])
        )

    limitations = index.get("limitations") or {
        "evidence_scope": "unknown",
        "trace_available": False,
        "poc_available": False,
    }
    manifest = {
        "hf_schema_version": HF_SCHEMA_VERSION,
        "dataset_version": dataset_version,
        "source_normalized_index": str(index_path.resolve()),
        "source_workbook": index.get("workbook"),
        "source_workbook_sha256": index.get("workbook_sha256"),
        "grouping": "repo_url + vulnerable_commit",
        "split_policy": split_policy,
        "dev_ratio": dev_ratio,
        "seed": seed,
        "counts": counts,
        "split_repositories": split_repos,
        "repository_overlap": overlap,
        "limitations": limitations,
        "files": {},
    }
    for path in sorted(output_dir.rglob("*.jsonl")):
        manifest["files"][path.relative_to(output_dir).as_posix()] = {
            "sha256": _sha256(path),
            "bytes": path.stat().st_size,
        }
    (output_dir / "dataset_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "README.md").write_text(
        _dataset_card(
            dataset_version=dataset_version,
            source_workbook=str(index.get("workbook") or "unknown"),
            source_sha256=str(index.get("workbook_sha256") or "unknown"),
            counts=counts,
            limitations=limitations,
        ),
        encoding="utf-8",
    )
    (output_dir / "LICENSE-NOTES.md").write_text(
        "# Licence notes\n\n"
        "This export contains vulnerability annotations/coordinates derived from "
        "public advisories and the source workbook. It does not redistribute "
        "repository source code. Choose and record a licence for the annotations "
        "yourself; per-repository source licences still apply when you fetch a "
        "checkout. Do not imply that the annotation licence covers upstream code.\n",
        encoding="utf-8",
    )
    dataset_info = augment_dataset_info(output_dir)
    if dataset_info is not None:
        manifest["dataset_info"] = dataset_info
        (output_dir / "dataset_manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return {
        "ok": True,
        "output": str(output_dir.resolve()),
        "counts": counts,
        "split_repositories": {
            key: len(value) for key, value in split_repos.items()
        },
        "repository_overlap": overlap,
        "dataset_info": dataset_info,
        "files": manifest["files"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normalized", required=True, help="ingest output directory")
    parser.add_argument("--output", required=True, help="Hugging Face dataset directory")
    parser.add_argument("--dataset-version", required=True)
    parser.add_argument("--dev-ratio", type=float, default=0.7)
    parser.add_argument("--seed", type=int, default=20261030)
    parser.add_argument(
        "--split-policy",
        choices=["repo-hash", "none"],
        default="repo-hash",
        help="repo-hash: deterministic repo-level dev/test split; none: all dev",
    )
    args = parser.parse_args(argv)
    if not 0.0 < args.dev_ratio < 1.0:
        parser.error("--dev-ratio must be between 0 and 1")
    result = export_hf_dataset(
        normalized_dir=Path(args.normalized),
        output_dir=Path(args.output),
        dataset_version=args.dataset_version,
        dev_ratio=args.dev_ratio,
        seed=args.seed,
        split_policy=args.split_policy,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
