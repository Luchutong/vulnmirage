"""Generic JSONL adapter.

Accepted line formats:

1. a complete ``CanonicalVulnerabilityOracle`` object;
2. ``{"report": {...}, "entries": [...]}``;
3. a flat advisory object with an ``entries`` list.

This keeps the pipeline usable with datasets other than VulnGym without
weakening the canonical oracle contract.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import SCHEMA_VERSION
from ..errors import DatasetError
from ..hashing import atomic_write_json, sha256_file
from ..models import CanonicalVulnerabilityOracle
from .base import build_oracle, now_iso, read_jsonl, write_oracle


def ingest_generic_jsonl(
    *,
    input_path: Path,
    output_dir: Path,
    source_dataset: str = "generic",
    allow_unverified: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    records = read_jsonl(input_path)
    if limit is not None:
        records = records[: max(limit, 0)]
    imported: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for line_number, record in records:
        try:
            if "oracle_id" in record and "vulnerabilities" in record:
                payload = dict(record)
                payload["source_dataset"] = payload.get("source_dataset") or source_dataset
                oracle = CanonicalVulnerabilityOracle.model_validate(payload)
            else:
                report = record.get("report", record)
                entries = record.get("entries", report.get("entries"))
                if not isinstance(report, dict) or not isinstance(entries, list):
                    raise DatasetError(
                        "record must be an oracle, {report, entries} or a flat advisory with entries"
                    )
                clean_report = {key: value for key, value in report.items() if key != "entries"}
                oracle = build_oracle(
                    clean_report,
                    entries,
                    dataset_name=source_dataset,
                    allow_unverified=allow_unverified,
                )
        except Exception as exc:
            rejected.append(
                {
                    "line": line_number,
                    "reason": str(getattr(exc, "message", exc)),
                }
            )
            continue
        path = write_oracle(
            oracle,
            output_dir,
            extra_metadata={"source_dataset": source_dataset, "line": line_number},
        )
        imported.append(
            {
                "oracle_id": oracle.oracle_id,
                "file": path.name,
                "sha256": sha256_file(path),
                "repo_url": oracle.repository.repo_url,
                "vulnerable_commit": oracle.repository.vulnerable_commit,
                "vulnerability_count": len(oracle.vulnerabilities),
            }
        )
    if not imported:
        raise DatasetError(
            "no generic records could be imported", details={"rejected": rejected[:20]}
        )
    index = {
        "schema_version": SCHEMA_VERSION,
        "source_dataset": source_dataset,
        "generated_at": now_iso(),
        "input_file": str(input_path.resolve()),
        "input_sha256": sha256_file(input_path),
        "imported": imported,
        "rejected": rejected,
    }
    atomic_write_json(output_dir / "index.json", index)
    return {
        "ok": True,
        "output": str(output_dir.resolve()),
        "imported": len(imported),
        "rejected": len(rejected),
        "oracles": imported,
        "rejected_details": rejected,
    }
