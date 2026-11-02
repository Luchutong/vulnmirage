"""VulnGym ``reports.jsonl`` + ``entries.jsonl`` adapter."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from .. import SCHEMA_VERSION
from ..errors import DatasetError
from ..hashing import atomic_write_json, sha256_file
from ..models import CanonicalVulnerabilityOracle
from .base import build_oracle, first_value, now_iso, read_jsonl, write_oracle


def _record_id(record: dict[str, Any]) -> str | None:
    value = first_value(record, "report_id", "advisory_id", "report")
    return str(value) if value is not None else None


def ingest_vulngym(
    *,
    reports_path: Path,
    entries_path: Path,
    output_dir: Path,
    allow_unverified: bool = False,
    limit: int | None = None,
    dataset_name: str = "vulngym",
) -> dict[str, Any]:
    reports_path = Path(reports_path)
    entries_path = Path(entries_path)
    output_dir = Path(output_dir)
    reports = read_jsonl(reports_path)
    entries = read_jsonl(entries_path)

    reports_by_id: dict[str, dict[str, Any]] = {}
    report_line: dict[str, int] = {}
    duplicate_reports: list[str] = []
    for line_number, record in reports:
        report_id = _record_id(record)
        if not report_id:
            raise DatasetError(
                "report record has no report_id",
                details={"path": str(reports_path), "line": line_number},
            )
        if report_id in reports_by_id:
            duplicate_reports.append(report_id)
            continue
        reports_by_id[report_id] = record
        report_line[report_id] = line_number

    entries_by_report: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    orphan_entries: list[dict[str, Any]] = []
    for line_number, record in entries:
        report_id = _record_id(record)
        if not report_id:
            orphan_entries.append({"line": line_number, "reason": "entry has no report_id"})
            continue
        if report_id not in reports_by_id:
            orphan_entries.append(
                {"line": line_number, "report_id": report_id, "reason": "unknown report_id"}
            )
            continue
        entries_by_report[report_id].append((line_number, record))

    selected_ids = sorted(
        reports_by_id,
        key=lambda rid: (str(first_value(reports_by_id[rid], "repo_url", "repo", "repository", default="")), rid),
    )
    if limit is not None:
        if limit < 0:
            raise DatasetError("--limit must be non-negative")
        selected_ids = selected_ids[:limit]

    imported: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = list(orphan_entries)
    for report_id in selected_ids:
        report = reports_by_id[report_id]
        record_entries = [record for _, record in entries_by_report.get(report_id, [])]
        if not record_entries:
            rejected.append({"report_id": report_id, "reason": "advisory has no entries"})
            continue
        try:
            oracle = build_oracle(
                report,
                record_entries,
                dataset_name=dataset_name,
                allow_unverified=allow_unverified,
            )
        except DatasetError as exc:
            rejected.append(
                {
                    "report_id": report_id,
                    "reason": exc.message,
                    "details": exc.details,
                }
            )
            continue
        except Exception as exc:  # malformed pydantic records become dataset errors
            rejected.append(
                {
                    "report_id": report_id,
                    "reason": "invalid advisory record",
                    "details": {"error": str(exc)},
                }
            )
            continue
        path = write_oracle(
            oracle,
            output_dir,
            extra_metadata={
                "source_dataset": dataset_name,
                "report_id": report_id,
                "report_line": report_line.get(report_id),
                "entry_count": len(record_entries),
            },
        )
        imported.append(
            {
                "oracle_id": oracle.oracle_id,
                "file": path.name,
                "sha256": sha256_file(path),
                "report_id": report_id,
                "repo_url": oracle.repository.repo_url,
                "vulnerable_commit": oracle.repository.vulnerable_commit,
                "vulnerability_count": len(oracle.vulnerabilities),
                "entry_count": len(record_entries),
                "suggested_difficulty": oracle.suggested_difficulty.value,
                "validation_level": oracle.validation_level,
            }
        )

    if not imported:
        raise DatasetError(
            "no advisories could be imported",
            details={"rejected": rejected[:20], "reports": len(selected_ids)},
        )

    index = {
        "schema_version": SCHEMA_VERSION,
        "source_dataset": dataset_name,
        "generated_at": now_iso(),
        "reports_file": str(reports_path.resolve()),
        "entries_file": str(entries_path.resolve()),
        "reports_sha256": sha256_file(reports_path),
        "entries_sha256": sha256_file(entries_path),
        "imported": imported,
        "rejected": rejected,
        "duplicate_report_ids": sorted(set(duplicate_reports)),
        "allow_unverified": allow_unverified,
    }
    atomic_write_json(output_dir / "index.json", index)
    return {
        "ok": True,
        "output": str(output_dir.resolve()),
        "imported": len(imported),
        "rejected": len(rejected),
        "oracles": imported,
        "rejected_details": rejected,
        "duplicate_report_ids": index["duplicate_report_ids"],
        "index": str((output_dir / "index.json").resolve()),
    }


def load_oracles(directory: Path) -> list[CanonicalVulnerabilityOracle]:
    """Load all oracle JSON files in an ingest output directory."""
    import json

    directory = Path(directory)
    oracles = []
    for path in sorted(directory.glob("*.json")):
        if path.name == "index.json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict) or "oracle_id" not in data:
            continue
        if path.name.endswith(".meta.json") or "vulnerabilities" not in data:
            continue
        oracles.append(CanonicalVulnerabilityOracle.model_validate(data))
    return oracles
