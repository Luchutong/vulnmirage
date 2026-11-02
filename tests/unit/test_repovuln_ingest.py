"""RepoVuln-50 workbook ingestion: grouping, aliases and multi-vuln oracles."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from vulnmirage.generation.targets import resolve_target_vulnerability
from vulnmirage.ingest.repovuln import ingest_repovuln_xlsx, read_repovuln_workbook

HEADER = [
    "repo_id",
    "repo_full_name",
    "repo_url",
    "vulnerability_id",
    "aliases",
    "title",
    "advisory_url",
    "data_scope",
    "evaluation_target",
    "cwe_ids",
    "severity_level",
    "severity_score",
    "severity_vector",
    "vulnerable_commit",
    "first_fix_sha",
    "file",
    "line",
    "entry_file",
    "entry_line",
    "function",
    "category_l1",
    "category_l2",
    "review_status",
    "review_grade",
    "snapshot_status",
    "proof_method",
]


def _col(index: int) -> str:
    letters = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        letters = chr(65 + rem) + letters
    return letters


def _xlsx(path: Path, rows: list[list[str]], sheet_name: str = "漏洞总表") -> Path:
    def cell(ref: str, value: str) -> str:
        escaped = (
            value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )
        return f'<c r="{ref}" t="inlineStr"><is><t>{escaped}</t></is></c>'

    sheet_rows = []
    for row_index, row in enumerate(rows, start=1):
        cells = "".join(
            cell(f"{_col(col_index)}{row_index}", value)
            for col_index, value in enumerate(row)
        )
        sheet_rows.append(f'<row r="{row_index}">{cells}</row>')
    sheet = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData>{"".join(sheet_rows)}</sheetData></worksheet>'
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets><sheet name="{sheet_name}" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Target="worksheets/sheet1.xml" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"/>'
        "</Relationships>"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", rels)
        archive.writestr("xl/worksheets/sheet1.xml", sheet)
    return path


def _row(vuln_id: str, *, scope="live", title="SQL injection", file="src/db.py", line="10-12"):
    values = {
        "repo_id": "1",
        "repo_full_name": "acme/app",
        "repo_url": "https://github.com/acme/app",
        "vulnerability_id": vuln_id,
        "aliases": f"{vuln_id}; GHSA-test",
        "title": title,
        "advisory_url": "https://example.invalid/advisory",
        "data_scope": scope,
        "evaluation_target": "1" if scope == "live" else "0",
        "cwe_ids": "CWE-89",
        "severity_level": "high",
        "severity_score": "8.1",
        "severity_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "vulnerable_commit": "a" * 40,
        "first_fix_sha": "b" * 40,
        "file": file,
        "line": line,
        "entry_file": "src/http.py",
        "entry_line": "3-5",
        "function": "query",
        "category_l1": "injection",
        "category_l2": "sql_injection",
        "review_status": "PASS",
        "review_grade": "A",
        "snapshot_status": "confirmed_affected",
        "proof_method": "version_range_plus_code",
    }
    return [values[name] for name in HEADER]


def test_workbook_is_grouped_into_one_multi_vuln_oracle(tmp_path: Path) -> None:
    workbook = _xlsx(
        tmp_path / "vulns.xlsx",
        [
            HEADER,
            _row("CVE-2026-0001"),
            _row("CVE-2026-0002", title="Second bug", file="src/other.py", line="20-22"),
            _row("CVE-2026-0003", scope="historical"),
        ],
    )
    rows = read_repovuln_workbook(workbook)
    assert len(rows) == 3
    result = ingest_repovuln_xlsx(
        workbook_path=workbook,
        output_dir=tmp_path / "normalized",
    )
    assert result["repository_snapshots"] == 1
    assert result["vulnerabilities"] == 3
    oracle = json.loads(
        (tmp_path / "normalized" / result["oracles"][0]["file"]).read_text(encoding="utf-8")
    )
    assert len(oracle["vulnerabilities"]) == 3
    aliases = {
        alias
        for vulnerability in oracle["vulnerabilities"]
        for alias in vulnerability["aliases"]
    }
    assert {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"} <= aliases
    assert oracle["hidden_metadata"]["evidence_scope"] == "entry_and_sink_only"


def test_data_scope_filter_and_alias_target_resolution(tmp_path: Path) -> None:
    workbook = _xlsx(
        tmp_path / "vulns.xlsx",
        [HEADER, _row("CVE-2026-0001"), _row("CVE-2026-0002", scope="historical")],
    )
    result = ingest_repovuln_xlsx(
        workbook_path=workbook,
        output_dir=tmp_path / "normalized-live",
        data_scope="live",
    )
    assert result["vulnerabilities"] == 1
    from vulnmirage.models import CanonicalVulnerabilityOracle

    oracle = CanonicalVulnerabilityOracle.model_validate(
        json.loads(
            (tmp_path / "normalized-live" / result["oracles"][0]["file"]).read_text(
                encoding="utf-8"
            )
        )
    )
    resolved = resolve_target_vulnerability(oracle, target_vulnerability_id="CVE-2026-0001")
    assert resolved.vulnerability_id.startswith("VULN-")


def test_several_commits_produce_separate_oracles(tmp_path: Path) -> None:
    row1 = _row("CVE-2026-0001")
    row2 = _row("CVE-2026-0002")
    commit_index = HEADER.index("vulnerable_commit")
    row2[commit_index] = "c" * 40
    workbook = _xlsx(tmp_path / "vulns.xlsx", [HEADER, row1, row2])
    result = ingest_repovuln_xlsx(
        workbook_path=workbook,
        output_dir=tmp_path / "normalized",
    )
    assert result["repository_snapshots"] == 2
    assert result["vulnerabilities"] == 2
