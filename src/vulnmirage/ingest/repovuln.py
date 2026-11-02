"""RepoVuln-50 workbook importer (stdlib-only XLSX reader).

The workbook is a *per-vulnerability* table.  Benchmark cases are
repository snapshots, so rows are grouped by ``(repo_url, vulnerable_commit)``:
each group becomes one oracle containing every numbered vulnerability that is
present at that snapshot.  Repositories with several snapshots produce several
oracles rather than silently mixing commits.

Only fields present in the workbook are used.  The workbook does **not** carry
ordered trace nodes, PoC commands or proof logs, so every imported oracle is
marked ``evidence_scope="entry_and_sink_only"`` and ``trace_available=false``;
validation/remapping still checks the entry and sink locations against the
checkout.  Do not describe these oracles as fully trace-grounded.
"""

from __future__ import annotations

import json
import re
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from .. import SCHEMA_VERSION
from ..errors import DatasetError
from ..hashing import atomic_write_json, sha256_file
from ..models import CanonicalVulnerabilityOracle
from .base import build_oracle, now_iso, write_oracle

_SHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_COL_RE = re.compile(r"^([A-Z]+)(\d+)$")
_REQUIRED_COLUMNS = {
    "repo_url",
    "repo_full_name",
    "vulnerability_id",
    "vulnerable_commit",
    "title",
    "cwe_ids",
    "severity_level",
    "file",
    "line",
    "entry_file",
    "entry_line",
}


def _text(node) -> str:
    return "".join(part.text or "" for part in node.iter(f"{{{_SHEET_NS}}}t"))


def _shared_strings(archive: zipfile.ZipFile) -> list[str]:
    try:
        root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
    except KeyError:
        return []
    return [_text(si) for si in root.findall(f"{{{_SHEET_NS}}}si")]


def _cell_value(cell, shared: list[str]) -> str:
    kind = cell.get("t")
    value = cell.find(f"{{{_SHEET_NS}}}v")
    inline = cell.find(f"{{{_SHEET_NS}}}is")
    if kind == "s" and value is not None and value.text is not None:
        index = int(value.text)
        return shared[index] if 0 <= index < len(shared) else ""
    if kind == "inlineStr" and inline is not None:
        return _text(inline)
    return value.text if value is not None and value.text is not None else ""


def _sheet_rows(archive: zipfile.ZipFile, target: str) -> list[dict[str, str]]:
    root = ET.fromstring(archive.read(target))
    shared = _shared_strings(archive)
    output: list[dict[str, str]] = []
    for row in root.findall(f".//{{{_SHEET_NS}}}sheetData/{{{_SHEET_NS}}}row"):
        cells: dict[str, str] = {}
        for cell in row.findall(f"{{{_SHEET_NS}}}c"):
            match = _COL_RE.match(cell.get("r") or "")
            if not match:
                continue
            cells[match.group(1)] = _cell_value(cell, shared)
        if cells:
            output.append(cells)
    return output


def _sheet_targets(archive: zipfile.ZipFile) -> list[tuple[str, str]]:
    workbook = ET.fromstring(archive.read("xl/workbook.xml"))
    rels = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
    relmap = {
        item.get("Id"): item.get("Target")
        for item in rels.findall(
            "{http://schemas.openxmlformats.org/package/2006/relationships}Relationship"
        )
    }
    output: list[tuple[str, str]] = []
    sheets = workbook.find(f"{{{_SHEET_NS}}}sheets")
    for sheet in list(sheets) if sheets is not None else []:
        target = relmap.get(sheet.get(f"{{{_REL_NS}}}id"))
        if not target:
            continue
        if not target.startswith("xl/"):
            target = "xl/" + target.lstrip("/")
        output.append((sheet.get("name") or "", target))
    return output


def read_repovuln_workbook(path: Path, *, sheet: str | None = None) -> list[dict[str, str]]:
    """Return the vulnerability rows of the workbook as dictionaries."""
    path = Path(path)
    if not path.is_file():
        raise DatasetError("workbook does not exist", details={"path": str(path)})
    with zipfile.ZipFile(path) as archive:
        candidates: list[tuple[str, str]] = []
        for name, target in _sheet_targets(archive):
            try:
                rows = _sheet_rows(archive, target)
            except (KeyError, ET.ParseError):
                continue
            if not rows:
                continue
            header = rows[0]
            names = set(header.values())
            if _REQUIRED_COLUMNS.issubset(names):
                candidates.append((name, target))
                if sheet is None or name == sheet:
                    return _records_from_rows(rows)
        if sheet is not None and not candidates:
            raise DatasetError(
                "no sheet has the RepoVuln-50 vulnerability header",
                details={"requested_sheet": sheet},
            )
    raise DatasetError(
        "no sheet with the RepoVuln-50 vulnerability header was found",
        details={"required_columns": sorted(_REQUIRED_COLUMNS)},
    )


def _records_from_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    header = rows[0]
    columns = sorted(header, key=lambda item: (len(item), item))
    names = {column: header[column] for column in columns}
    records: list[dict[str, str]] = []
    for raw in rows[1:]:
        record = {names[column]: raw.get(column, "") for column in columns}
        if not str(record.get("vulnerability_id") or "").strip():
            continue
        records.append(record)
    return records


def _split_ids(value: str) -> list[str]:
    return [
        item.strip()
        for item in re.split(r"[;,|]", value or "")
        if item.strip()
    ]


def _entry(record: dict[str, str]) -> dict[str, Any]:
    severity_level = (record.get("severity_level") or "").strip().lower() or None
    score = (record.get("severity_score") or "").strip()
    vector = (record.get("severity_vector") or "").strip() or None
    entry: dict[str, Any] = {
        "entry_id": record["vulnerability_id"].strip(),
        "title": record.get("title") or record["vulnerability_id"],
        "vulnerability_type": record.get("category_l2") or record.get("category_l1") or "vulnerability",
        "cwe": _split_ids(record.get("cwe_ids", "")),
        "file": record["file"].strip(),
        "line": record["line"].strip(),
        "critical_operation": {
            "file": record["file"].strip(),
            "line": record["line"].strip(),
            "description": "critical operation (RepoVuln-50)",
        },
        "entry_point": {
            "file": record["entry_file"].strip(),
            "line": record["entry_line"].strip(),
            "description": "entry point (RepoVuln-50)",
        },
        "function": record.get("function") or None,
        "category_l1": record.get("category_l1") or "",
        "category_l2": record.get("category_l2") or "",
        # build_oracle uses description as root_cause; keep it a string so the
        # JSONL schema does not flip between null and string across rows.
        "description": record.get("category_l2") or record.get("title") or "",
    }
    if severity_level:
        severity: dict[str, Any] = {
            "level": severity_level,
            "rationale": record.get("title") or f"RepoVuln-50 {record.get('vulnerability_id')}",
            "source": {
                "kind": "dataset_annotation",
                "reference": record.get("advisory_url") or None,
            },
            # The workbook records reviewed/adjudicated grades; keep that
            # provenance.  CVSS 4.0 scores cannot be recomputed by the local
            # 3.1 calculator, and the model requires an adjudicated record.
            "validation_status": (
                "adjudicated"
                if (record.get("review_status") or "").upper() == "PASS"
                else "unreviewed"
            ),
            "scheme": (
                "cvss_v4.0"
                if (record.get("severity_vector") or "").upper().startswith("CVSS:4.0")
                else "cvss_v3.1"
            ),
        }
        if score:
            try:
                severity["score"] = float(score)
            except ValueError:
                pass
        if vector:
            severity["vector"] = vector
        entry["severity"] = severity
    return entry


def _group_key(record: dict[str, str]) -> tuple[str, str]:
    return (
        (record.get("repo_url") or "").strip(),
        (record.get("vulnerable_commit") or "").strip().lower(),
    )


def ingest_repovuln_xlsx(
    *,
    workbook_path: Path,
    output_dir: Path,
    sheet: str | None = None,
    data_scope: str | None = None,
    limit_groups: int | None = None,
    dataset_name: str = "repovuln-50",
) -> dict[str, Any]:
    """Group workbook rows into one oracle per repository snapshot and import."""
    workbook_path = Path(workbook_path)
    output_dir = Path(output_dir)
    records = read_repovuln_workbook(workbook_path, sheet=sheet)
    if data_scope:
        wanted = {item.strip().lower() for item in data_scope.split(",") if item.strip()}
        records = [item for item in records if (item.get("data_scope") or "").lower() in wanted]
    if not records:
        raise DatasetError("no RepoVuln-50 rows selected", details={"sheet": sheet})

    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    rejected: list[dict[str, Any]] = []
    for record in records:
        if (record.get("review_status") or "").strip().upper() != "PASS":
            rejected.append(
                {
                    "vulnerability_id": record.get("vulnerability_id"),
                    "reason": "review_status is not PASS",
                }
            )
            continue
        repo_url, commit = _group_key(record)
        if not repo_url or not commit:
            rejected.append(
                {
                    "vulnerability_id": record.get("vulnerability_id"),
                    "reason": "missing repo_url or vulnerable_commit",
                }
            )
            continue
        grouped[(repo_url, commit)].append(record)

    groups = sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1]))
    if limit_groups is not None:
        groups = groups[: max(limit_groups, 0)]
    imported: list[dict[str, Any]] = []
    for (repo_url, commit), rows in groups:
        repo_full_name = rows[0].get("repo_full_name") or repo_url
        report_id = f"repovuln:{repo_full_name}:{commit[:12]}"
        entries = [_entry(row) for row in rows]
        verify = int(
            all((row.get("review_status") or "").upper() == "PASS" for row in rows)
        )
        report = {
            "report_id": report_id,
            "repo_url": repo_url,
            "vulnerable_commit": commit,
            "fixed_commit": rows[0].get("first_fix_sha") or None,
            "title": f"RepoVuln-50 {repo_full_name} @ {commit[:12]}",
            "verify": verify,
            "published_at": rows[0].get("published_at") or None,
            "advisory_url": rows[0].get("advisory_url") or None,
            "data_scope": rows[0].get("data_scope") or None,
            "snapshot_id": rows[0].get("snapshot_id") or None,
        }
        try:
            oracle = build_oracle(
                report,
                entries,
                dataset_name=dataset_name,
                allow_unverified=False,
            )
        except Exception as exc:  # noqa: BLE001 - one snapshot must not abort import
            rejected.append(
                {
                    "report_id": report_id,
                    "repo_url": repo_url,
                    "vulnerable_commit": commit,
                    "reason": str(getattr(exc, "message", exc)),
                    "detail": getattr(exc, "details", None),
                }
            )
            continue
        # Expose CVE/GHSA identifiers as aliases so operators can target a
        # vulnerability by its dataset id, while evaluation keeps canonical
        # internal VULN ids (stable_id("VULN", report_id, entry_id)).
        from ..hashing import stable_id as _stable_id

        aliases_by_vuln = {
            _stable_id("VULN", report_id, row["vulnerability_id"].strip()): sorted(
                {
                    *_split_ids(row.get("aliases") or ""),
                    *_split_ids(row.get("cve_ids") or ""),
                    row["vulnerability_id"].strip(),
                }
            )
            for row in rows
        }
        oracle = oracle.model_copy(
            update={
                "vulnerabilities": [
                    vulnerability.model_copy(
                        update={
                            "aliases": sorted(
                                {
                                    *vulnerability.aliases,
                                    *aliases_by_vuln.get(vulnerability.vulnerability_id, []),
                                }
                            )
                        }
                    )
                    for vulnerability in oracle.vulnerabilities
                ]
            }
        )
        scopes = sorted(
            {row.get("data_scope") or "unknown" for row in rows}
        )
        oracle = oracle.model_copy(
            update={
                "hidden_metadata": {
                    **oracle.hidden_metadata,
                    "evidence_scope": "entry_and_sink_only",
                    "trace_available": False,
                    "poc_available": False,
                    "repovuln": {
                        "repo_full_name": repo_full_name,
                        "repo_id": rows[0].get("repo_id"),
                        "primary_language": rows[0].get("primary_language"),
                        "snapshot_id": rows[0].get("snapshot_id"),
                        "data_scope": scopes,
                        "evaluation_target": sorted(
                            {row.get("evaluation_target") or "" for row in rows}
                        ),
                        "review_grade": sorted(
                            {row.get("review_grade") or "" for row in rows}
                        ),
                        "proof_methods": sorted(
                            {
                                row.get("proof_method") or ""
                                for row in rows
                                if row.get("proof_method")
                            }
                        ),
                        "vulnerability_ids": sorted(
                            row["vulnerability_id"] for row in rows
                        ),
                        "row_count": len(rows),
                        "limitation": (
                            "workbook provides entry/sink locations but no ordered "
                            "trace nodes, PoC commands or proof logs"
                        ),
                    },
                }
            }
        )
        path = write_oracle(
            oracle,
            output_dir,
            extra_metadata={
                "source_dataset": dataset_name,
                "report_id": report_id,
                "repo_full_name": repo_full_name,
                "vulnerability_count": len(rows),
                "data_scope": scopes,
                "evidence_scope": "entry_and_sink_only",
            },
        )
        imported.append(
            {
                "oracle_id": oracle.oracle_id,
                "file": path.name,
                "sha256": sha256_file(path),
                "report_id": report_id,
                "repo_full_name": repo_full_name,
                "repo_url": repo_url,
                "vulnerable_commit": commit,
                "vulnerability_count": len(rows),
                "vulnerability_ids": sorted(row["vulnerability_id"] for row in rows),
                "data_scope": scopes,
                "evidence_scope": "entry_and_sink_only",
                "trace_available": False,
            }
        )

    if not imported:
        raise DatasetError(
            "no RepoVuln-50 repository snapshots could be imported",
            details={"rejected": rejected[:20]},
        )
    index = {
        "schema_version": SCHEMA_VERSION,
        "source_dataset": dataset_name,
        "generated_at": now_iso(),
        "workbook": str(workbook_path.resolve()),
        "workbook_sha256": sha256_file(workbook_path),
        "sheet": sheet,
        "grouping": "repo_url + vulnerable_commit",
        "records": len(records),
        "repository_snapshots": len(imported),
        "vulnerabilities": sum(item["vulnerability_count"] for item in imported),
        "imported": imported,
        "rejected": rejected,
        "limitations": {
            "evidence_scope": "entry_and_sink_only",
            "trace_available": False,
            "poc_available": False,
            "multi_commit_repositories": "one oracle per commit; never mixed",
        },
    }
    atomic_write_json(output_dir / "index.json", index)
    return {
        "ok": True,
        "output": str(output_dir.resolve()),
        "workbook": str(workbook_path.resolve()),
        "records": len(records),
        "repository_snapshots": len(imported),
        "vulnerabilities": index["vulnerabilities"],
        "rejected": len(rejected),
        "oracles": imported,
        "limitations": index["limitations"],
    }
