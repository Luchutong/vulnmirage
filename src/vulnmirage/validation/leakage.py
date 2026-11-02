"""Detect hidden ground truth leaking into agent-visible files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field

from ..models import CanonicalVulnerabilityOracle, DecoyRecord, ManipulationSpec
from ..paths import normalize_relpath

_HIDDEN_FILENAMES = {
    "oracle.json",
    "validation.json",
    "manipulation.json",
    "decoys.json",
    "state.json",
    "instance.json",
    "evidence_contract.json",
}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.I)


class LeakageMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str
    line: int
    kind: str
    identifier: str


class LeakageReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passed: bool
    matches: list[LeakageMatch] = Field(default_factory=list)
    files_scanned: int = 0
    identifiers_checked: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def collect_hidden_identifiers(
    oracle: CanonicalVulnerabilityOracle,
    manipulation: ManipulationSpec | None = None,
    decoys: list[DecoyRecord] | None = None,
    evidence_contract=None,
) -> dict[str, str]:
    identifiers: dict[str, str] = {
        "oracle_id": oracle.oracle_id,
        "report_id": str(oracle.hidden_metadata.get("report_id") or ""),
    }
    for record_id in oracle.source_record_ids:
        identifiers[f"source_record_id:{record_id}"] = record_id
    for key in ("cve_ids", "ghsa_ids"):
        for value in oracle.hidden_metadata.get(key, []) or []:
            identifiers[f"{key}:{value}"] = str(value)
    advisory_title = oracle.hidden_metadata.get("advisory_title")
    if isinstance(advisory_title, str) and len(advisory_title) >= 24:
        identifiers["advisory_title"] = advisory_title
    if manipulation is not None:
        for decoy_id in manipulation.target_decoy_ids:
            identifiers[f"decoy_id:{decoy_id}"] = decoy_id
    for decoy in decoys or []:
        identifiers[f"decoy_id:{decoy.decoy_id}"] = decoy.decoy_id
    if evidence_contract is not None:
        for claim in evidence_contract.claims:
            identifiers[f"claim_id:{claim.claim_id}"] = claim.claim_id
    return {kind: value for kind, value in identifiers.items() if value}


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:4096]


def _iter_text_files(root: Path) -> Iterable[Path]:
    root = Path(root)
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        yield path


def scan_text(
    text: str,
    *,
    file: str,
    identifiers: dict[str, str],
    patterns: bool = True,
) -> list[LeakageMatch]:
    matches: list[LeakageMatch] = []
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    for line_number, line in enumerate(lines, start=1):
        for kind, value in identifiers.items():
            if not value:
                continue
            # Very short numeric/hex ids produce too many incidental matches;
            # exact oracle ids and advisory ids are always checked.
            if len(value) < 4 and ":" in kind:
                continue
            if value in line:
                matches.append(
                    LeakageMatch(
                        file=file,
                        line=line_number,
                        kind=kind.split(":", 1)[0],
                        identifier=value,
                    )
                )
        if patterns:
            for regex, kind in ((_CVE_RE, "cve_pattern"), (_GHSA_RE, "ghsa_pattern")):
                for found in regex.findall(line):
                    if any(found.lower() == value.lower() for value in identifiers.values()):
                        continue
                    # Only report patterns when they are the advisory's own ids;
                    # unrelated upstream CVEs must not fail a valid instance.
                    matches.append(
                        LeakageMatch(
                            file=file,
                            line=line_number,
                            kind=kind,
                            identifier=found,
                        )
                    )
    return matches


def scan_repository(
    root: Path,
    *,
    identifiers: dict[str, str],
    scan_advisory_patterns: bool = True,
    max_file_bytes: int = 4 * 1024 * 1024,
) -> LeakageReport:
    root = Path(root)
    matches: list[LeakageMatch] = []
    files_scanned = 0
    notes: list[str] = []
    own_advisory_ids = {
        value.lower()
        for kind, value in identifiers.items()
        if kind.startswith(("cve_ids:", "ghsa_ids:"))
    }
    if not root.is_dir():
        return LeakageReport(
            passed=False,
            matches=[],
            files_scanned=0,
            identifiers_checked=sorted(identifiers),
            notes=["repository root does not exist"],
        )
    for path in _iter_text_files(root):
        relative = normalize_relpath(path.relative_to(root).as_posix())
        if path.name in _HIDDEN_FILENAMES:
            matches.append(
                LeakageMatch(
                    file=relative,
                    line=1,
                    kind="hidden_filename",
                    identifier=path.name,
                )
            )
            continue
        if path.stat().st_size > max_file_bytes:
            notes.append(f"skipped large file: {relative}")
            continue
        data = path.read_bytes()
        if _is_binary(data):
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")
        files_scanned += 1
        found = scan_text(
            text,
            file=relative,
            identifiers=identifiers,
            patterns=False,
        )
        if scan_advisory_patterns:
            for match in scan_text(
                text, file=relative, identifiers=identifiers, patterns=True
            ):
                if match.kind.endswith("_pattern"):
                    if match.identifier.lower() not in own_advisory_ids:
                        continue
                found.append(match)
        matches.extend(found)
    # De-duplicate repeated identifiers on the same line.
    unique: list[LeakageMatch] = []
    seen: set[tuple[str, int, str, str]] = set()
    for match in matches:
        key = (match.file, match.line, match.kind, match.identifier)
        if key in seen:
            continue
        seen.add(key)
        unique.append(match)
    return LeakageReport(
        passed=not unique,
        matches=unique,
        files_scanned=files_scanned,
        identifiers_checked=sorted(identifiers),
        notes=notes,
    )


def scan_task(task_text: str, identifiers: dict[str, str]) -> LeakageReport:
    matches = scan_text(task_text, file="task.md", identifiers=identifiers, patterns=True)
    return LeakageReport(
        passed=not matches,
        matches=matches,
        files_scanned=1,
        identifiers_checked=sorted(identifiers),
    )


def scan_instance_visible(
    repo_root: Path,
    task_text: str,
    *,
    oracle: CanonicalVulnerabilityOracle,
    manipulation: ManipulationSpec | None = None,
    decoys: list[DecoyRecord] | None = None,
    evidence_contract=None,
    scan_advisory_patterns: bool = True,
) -> dict[str, Any]:
    identifiers = collect_hidden_identifiers(
        oracle, manipulation, decoys, evidence_contract
    )
    repo_report = scan_repository(
        repo_root,
        identifiers=identifiers,
        scan_advisory_patterns=scan_advisory_patterns,
    )
    task_report = scan_task(task_text, identifiers)
    passed = repo_report.passed and task_report.passed
    return {
        "passed": passed,
        "repo": repo_report.model_dump(mode="json"),
        "task": task_report.model_dump(mode="json"),
        "identifiers_count": len(identifiers),
    }
