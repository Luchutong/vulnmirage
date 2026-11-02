"""Resolve oracle code snippets and remap locations after manipulation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..errors import RepositoryError, ValidationError
from ..hashing import code_sha256, normalize_code
from ..models import (
    CanonicalVulnerabilityOracle,
    CodeLocation,
    VulnerabilityPath,
    VulnerabilityRecord,
)
from ..paths import safe_join
from .git import tree_hash, worktree_digest


def read_repository_text(root: Path, relative: str) -> str:
    path = safe_join(Path(root), relative)
    if not path.is_file():
        raise RepositoryError(
            "code location file does not exist in the repository",
            details={"file": relative},
        )
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise RepositoryError("cannot decode repository file as text", details={"file": relative})


def extract_code(root: Path, location: CodeLocation) -> str:
    text = read_repository_text(root, location.file)
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    if location.end_line > len(lines):
        raise ValidationError(
            "code location exceeds file length",
            details={
                "file": location.file,
                "start_line": location.start_line,
                "end_line": location.end_line,
                "file_lines": len(lines),
            },
        )
    snippet = "\n".join(lines[location.start_line - 1 : location.end_line])
    return snippet + "\n" if snippet else ""


def resolve_location(root: Path, location: CodeLocation) -> CodeLocation:
    actual = extract_code(root, location)
    if location.code is not None and normalize_code(location.code) != normalize_code(actual):
        raise ValidationError(
            "provided code snippet does not match the repository content",
            details={
                "file": location.file,
                "start_line": location.start_line,
                "end_line": location.end_line,
                "expected_sha256": code_sha256(actual),
                "provided_sha256": code_sha256(location.code),
            },
        )
    updated = location.model_copy(
        update={"code": actual, "code_sha256": code_sha256(actual)}
    )
    return updated


def resolve_path(root: Path, path: VulnerabilityPath) -> VulnerabilityPath:
    return path.model_copy(
        update={
            "entry_point": resolve_location(root, path.entry_point),
            "trace": [resolve_location(root, item) for item in path.trace],
            "critical_operation": resolve_location(root, path.critical_operation),
        }
    )


def resolve_oracle_locations(
    oracle: CanonicalVulnerabilityOracle, root: Path
) -> tuple[CanonicalVulnerabilityOracle, dict[str, object]]:
    resolved_vulnerabilities: list[VulnerabilityRecord] = []
    total = 0
    for vulnerability in oracle.vulnerabilities:
        paths = []
        for path in vulnerability.paths:
            paths.append(resolve_path(root, path))
            total += 2 + len(path.trace)
        resolved_vulnerabilities.append(
            vulnerability.model_copy(update={"paths": paths})
        )
    repository = oracle.repository.model_copy(
        update={"source_tree_sha256": worktree_digest(root)}
    )
    updated = oracle.model_copy(
        update={"vulnerabilities": resolved_vulnerabilities, "repository": repository}
    )
    return updated, {"locations_resolved": total, "source_tree_sha256": repository.source_tree_sha256}


class RemappedLocation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str
    original_start_line: int
    original_end_line: int
    new_start_line: int
    new_end_line: int
    matches: int
    ambiguous: bool
    resolved: bool
    code_sha256: str | None = None


class RemapReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    locations_checked: int = 0
    locations_resolved: int = 0
    unresolved: list[str] = Field(default_factory=list)
    ambiguous: list[str] = Field(default_factory=list)
    details: list[RemappedLocation] = Field(default_factory=list)

    @property
    def all_resolved(self) -> bool:
        return not self.unresolved


@dataclass
class RemapResult:
    oracle: CanonicalVulnerabilityOracle
    report: RemapReport
    path_reports: dict[str, RemapReport] = field(default_factory=dict)


def _find_occurrences(haystack: list[str], needle: list[str]) -> list[int]:
    if not needle:
        return []
    results: list[int] = []
    limit = len(haystack) - len(needle)
    for start in range(limit + 1):
        if haystack[start : start + len(needle)] == needle:
            results.append(start)
    return results


def remap_location(
    location: CodeLocation,
    clean_root: Path,
    variant_root: Path,
) -> tuple[CodeLocation, RemappedLocation]:
    original = resolve_location(clean_root, location)
    try:
        variant_text = read_repository_text(variant_root, original.file)
    except RepositoryError:
        return original, RemappedLocation(
            file=original.file,
            original_start_line=original.start_line,
            original_end_line=original.end_line,
            new_start_line=original.start_line,
            new_end_line=original.end_line,
            matches=0,
            ambiguous=False,
            resolved=False,
            code_sha256=original.code_sha256,
        )
    variant_lines = [
        line.rstrip(" \t")
        for line in variant_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    ]
    if variant_lines and variant_lines[-1] == "":
        variant_lines = variant_lines[:-1]
    target_lines = normalize_code(original.code or "").rstrip("\n").split("\n")
    if not target_lines or target_lines == [""]:
        return original, RemappedLocation(
            file=original.file,
            original_start_line=original.start_line,
            original_end_line=original.end_line,
            new_start_line=original.start_line,
            new_end_line=original.end_line,
            matches=0,
            ambiguous=False,
            resolved=False,
            code_sha256=original.code_sha256,
        )
    occurrences = _find_occurrences(variant_lines, target_lines)
    if not occurrences:
        return original, RemappedLocation(
            file=original.file,
            original_start_line=original.start_line,
            original_end_line=original.end_line,
            new_start_line=original.start_line,
            new_end_line=original.end_line,
            matches=0,
            ambiguous=False,
            resolved=False,
            code_sha256=original.code_sha256,
        )
    zero_based_original = original.start_line - 1
    chosen = min(occurrences, key=lambda start: (abs(start - zero_based_original), start))
    ambiguous = len(occurrences) > 1
    new_start = chosen + 1
    new_end = chosen + len(target_lines)
    actual = "\n".join(variant_lines[chosen : chosen + len(target_lines)]) + "\n"
    updated = original.model_copy(
        update={
            "start_line": new_start,
            "end_line": new_end,
            "code": actual,
            "code_sha256": code_sha256(actual),
        }
    )
    return updated, RemappedLocation(
        file=original.file,
        original_start_line=original.start_line,
        original_end_line=original.end_line,
        new_start_line=new_start,
        new_end_line=new_end,
        matches=len(occurrences),
        ambiguous=ambiguous,
        resolved=True,
        code_sha256=code_sha256(actual),
    )


def remap_path(
    path: VulnerabilityPath, clean_root: Path, variant_root: Path
) -> tuple[VulnerabilityPath, RemapReport]:
    report = RemapReport()
    updates = {}
    for label, location in (
        ("entry_point", path.entry_point),
        ("critical_operation", path.critical_operation),
    ):
        updated, detail = remap_location(location, clean_root, variant_root)
        report.locations_checked += 1
        report.details.append(detail)
        if detail.resolved:
            report.locations_resolved += 1
        else:
            report.unresolved.append(f"{path.path_id}:{label}")
        if detail.ambiguous:
            report.ambiguous.append(f"{path.path_id}:{label}")
        updates[label] = updated
    trace = []
    for index, location in enumerate(path.trace):
        updated, detail = remap_location(location, clean_root, variant_root)
        report.locations_checked += 1
        report.details.append(detail)
        if detail.resolved:
            report.locations_resolved += 1
        else:
            report.unresolved.append(f"{path.path_id}:trace[{index}]")
        if detail.ambiguous:
            report.ambiguous.append(f"{path.path_id}:trace[{index}]")
        trace.append(updated)
    updates["trace"] = trace
    return path.model_copy(update=updates), report


def remap_oracle(
    oracle: CanonicalVulnerabilityOracle,
    clean_root: Path,
    variant_root: Path,
) -> RemapResult:
    report = RemapReport()
    path_reports: dict[str, RemapReport] = {}
    vulnerabilities = []
    for vulnerability in oracle.vulnerabilities:
        paths = []
        for path in vulnerability.paths:
            updated, path_report = remap_path(path, clean_root, variant_root)
            paths.append(updated)
            path_reports[path.path_id] = path_report
            report.locations_checked += path_report.locations_checked
            report.locations_resolved += path_report.locations_resolved
            report.unresolved.extend(path_report.unresolved)
            report.ambiguous.extend(path_report.ambiguous)
            report.details.extend(path_report.details)
        vulnerabilities.append(vulnerability.model_copy(update={"paths": paths}))
    return RemapResult(
        oracle=oracle.model_copy(update={"vulnerabilities": vulnerabilities}),
        report=report,
        path_reports=path_reports,
    )


def verify_oracle_code(oracle: CanonicalVulnerabilityOracle, root: Path) -> list[str]:
    """Return a list of error strings for locations whose code no longer matches."""
    errors: list[str] = []
    for vulnerability, path in oracle.all_paths():
        for label, location in (
            ("entry_point", path.entry_point),
            ("critical_operation", path.critical_operation),
            *[(f"trace[{i}]", item) for i, item in enumerate(path.trace)],
        ):
            try:
                actual = extract_code(root, location)
            except (RepositoryError, ValidationError) as exc:
                errors.append(f"{vulnerability.vulnerability_id}/{path.path_id}/{label}: {exc}")
                continue
            if location.code_sha256 and code_sha256(actual) != location.code_sha256:
                errors.append(
                    f"{vulnerability.vulnerability_id}/{path.path_id}/{label}: code hash mismatch"
                )
    return errors
