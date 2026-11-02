"""Dataset ingestion primitives and canonical oracle construction."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import SCHEMA_VERSION
from ..errors import DatasetError
from ..hashing import atomic_write_json, sha256_text, stable_id, stable_digest
from ..models import (
    ORACLE_SCHEMA_VERSION,
    AuditDifficulty,
    CanonicalVulnerabilityOracle,
    CodeLocation,
    RepositoryRef,
    SafeTargetContract,
    SeverityLevel,
    SeverityRecord,
    ValidatorCommand,
    VulnerabilityPath,
    VulnerabilityRecord,
)
from ..normalization import normalize_cwe_list, normalize_severity

_LINE_RANGE_RE = re.compile(r"L?\s*(\d+)\s*(?:-|:|–|—|to)\s*L?\s*(\d+)", re.I)
_SINGLE_LINE_RE = re.compile(r"L?\s*(\d+)", re.I)
_DIFFICULTIES = {item.value for item in AuditDifficulty}
_SEVERITIES = {item.value for item in SeverityLevel}


def read_jsonl(path: Path, *, allow_empty: bool = False) -> list[tuple[int, dict[str, Any]]]:
    path = Path(path)
    if not path.is_file():
        raise DatasetError("JSONL file does not exist", details={"path": str(path)})
    records: list[tuple[int, dict[str, Any]]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise DatasetError(
                    "invalid JSON line",
                    details={"path": str(path), "line": line_number, "error": str(exc)},
                ) from exc
            if not isinstance(value, dict):
                raise DatasetError(
                    "each JSONL line must be an object",
                    details={"path": str(path), "line": line_number},
                )
            records.append((line_number, value))
    if not records and not allow_empty:
        raise DatasetError("JSONL file contains no records", details={"path": str(path)})
    return records


def first_value(record: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in record and record[key] is not None:
            return record[key]
    return default


def parse_line_range(value: Any) -> tuple[int, int]:
    if isinstance(value, bool):
        raise DatasetError("line range must not be a boolean", details={"value": value})
    if isinstance(value, int):
        if value < 1:
            raise DatasetError("line numbers start at 1", details={"value": value})
        return value, value
    if isinstance(value, (list, tuple)) and len(value) == 2:
        start, end = int(value[0]), int(value[1])
        if start < 1 or end < start:
            raise DatasetError("invalid line range", details={"value": value})
        return start, end
    if isinstance(value, dict):
        start = first_value(value, "start_line", "start", "line_start", "from")
        end = first_value(value, "end_line", "end", "line_end", "to", default=start)
        if start is None:
            raise DatasetError("line range object has no start", details={"value": value})
        return parse_line_range([start, end])
    if isinstance(value, str):
        text = value.strip()
        match = _LINE_RANGE_RE.search(text)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start < 1 or end < start:
                raise DatasetError("invalid line range", details={"value": value})
            return start, end
        match = _SINGLE_LINE_RE.search(text)
        if match:
            line = int(match.group(1))
            if line < 1:
                raise DatasetError("line numbers start at 1", details={"value": value})
            return line, line
    raise DatasetError("cannot parse line range", details={"value": value})


def _code_line_count(code: str) -> int:
    normalized = code.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    return max(len(lines), 1)


def parse_location(
    raw: Any,
    *,
    default_file: str | None = None,
    default_line: Any = None,
    default_code: str | None = None,
    description: str | None = None,
) -> CodeLocation:
    if raw is None:
        if default_file is None:
            raise DatasetError("missing code location")
        raw = {}
    if isinstance(raw, str):
        # Accept "path/to/file.py:10-20"; otherwise treat as a file path.
        match = re.match(r"^(?P<file>[^:]+):(?P<line>\d+(?:\s*-\s*\d+)?)$", raw.strip())
        if match:
            raw = {"file": match.group("file"), "line": match.group("line")}
        else:
            raw = {"file": raw}
    if not isinstance(raw, dict):
        raise DatasetError("code location must be an object or string", details={"value": raw})

    file_value = first_value(raw, "file", "path", "file_path", "filename", default=default_file)
    if not file_value:
        raise DatasetError("code location has no file", details={"value": raw})
    line_value = first_value(
        raw,
        "line",
        "lines",
        "line_range",
        "start_line",
        "range",
        default=default_line,
    )
    code = first_value(raw, "code", "snippet", "content", default=default_code)
    if line_value is None:
        if code:
            start, end = 1, _code_line_count(code)
        else:
            raise DatasetError(
                "code location has no line information and no code snippet",
                details={"file": file_value},
            )
    else:
        if isinstance(line_value, int) and "end_line" in raw:
            start, end = parse_line_range([line_value, raw["end_line"]])
        else:
            start, end = parse_line_range(line_value)
    if isinstance(code, str) and code:
        lines = code.replace("\r\n", "\n").split("\n")
        if lines and lines[-1] == "":
            lines = lines[:-1]
        if end - start + 1 < len(lines):
            end = start + len(lines) - 1
        code_value = "\n".join(lines) + "\n"
    else:
        code_value = None
    return CodeLocation(
        file=file_value,
        start_line=start,
        end_line=end,
        code=code_value,
        description=description or first_value(raw, "description", "label"),
    )


def parse_commands(raw: Any) -> list[ValidatorCommand]:
    if raw is None:
        return []
    items: list[Any]
    if isinstance(raw, dict):
        items = [raw]
    elif isinstance(raw, list):
        items = raw
    else:
        raise DatasetError("commands must be a list or object", details={"value": raw})
    commands: list[ValidatorCommand] = []
    for index, item in enumerate(items):
        try:
            if isinstance(item, (list, tuple)):
                commands.append(
                    ValidatorCommand(
                        name=f"command_{index + 1}",
                        argv=[str(part) for part in item],
                    )
                )
            elif isinstance(item, str):
                raise DatasetError(
                    "shell-string commands are not accepted; provide an argv array",
                    details={"value": item},
                )
            elif isinstance(item, dict):
                payload = dict(item)
                payload.setdefault("name", f"command_{index + 1}")
                commands.append(ValidatorCommand.model_validate(payload))
            else:
                raise DatasetError("invalid command entry", details={"value": item})
        except DatasetError:
            raise
        except Exception as exc:
            raise DatasetError(
                "invalid validator command", details={"value": item, "error": str(exc)}
            ) from exc
    return commands


def parse_severity(raw: Any, source: str) -> SeverityRecord | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        level = normalize_severity(raw)
        return SeverityRecord(
            level=level,
            rationale=f"Imported from {source}",
            source={"kind": "unknown", "reference": source},
        )
    if isinstance(raw, dict):
        payload = dict(raw)
        level = first_value(payload, "level", "severity", "rating")
        score = first_value(payload, "score", "cvss_score", "cvss")
        if level is None and score is not None:
            from ..normalization import severity_from_score

            level = severity_from_score(float(score))
        if level is None and score is None and payload.get("vector") is None:
            return None
        if level is None:
            from ..cvss import vector_base_score
            from ..normalization import severity_from_score

            computed = vector_base_score(str(payload.get("vector")))
            if computed is None:
                raise DatasetError("severity has no level and no computable score")
            level = severity_from_score(computed)
            payload.setdefault("score", computed)
        source_value = first_value(payload, "source", default=source)
        if isinstance(source_value, dict):
            severity_source = source_value
        else:
            severity_source = {"kind": "unknown", "reference": str(source_value)}
        return SeverityRecord(
            scheme=str(first_value(payload, "scheme", default="cvss_v3.1")),
            level=normalize_severity(level),
            score=float(score) if score is not None else None,
            vector=first_value(payload, "vector", "cvss_vector"),
            rationale=str(
                first_value(
                    payload,
                    "rationale",
                    "description",
                    default=f"Imported from {source}",
                )
            ),
            assumptions=list(first_value(payload, "assumptions", default=[]) or []),
            source=severity_source,
            validation_status=first_value(
                payload, "validation_status", default="unreviewed"
            ),
            confidence=first_value(payload, "confidence"),
        )
    raise DatasetError("invalid severity record", details={"value": raw})


def parse_safe_targets(
    raw: Any,
    *,
    default_cwe: str,
    source: str = "dataset",
    default_vulnerability_type: str | None = None,
) -> list[SafeTargetContract]:
    """Parse declared safe targets.

    A declaration must name a proof method and (unless it is a fix-commit
    provenance target) at least one argv validator.  Nothing is marked
    ``validated_safe`` here: that only happens after the validator executed.
    """
    if raw is None:
        return []
    items = raw if isinstance(raw, list) else [raw]
    contracts: list[SafeTargetContract] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise DatasetError("safe target declarations must be objects", details={"value": item})
        payload = dict(item)
        file_value = first_value(payload, "file", "path")
        if not file_value:
            raise DatasetError("safe target has no file", details={"value": payload})
        line_value = first_value(payload, "line", "lines", "start_line", default=1)
        start, end = parse_line_range(line_value)
        if payload.get("end_line") is not None:
            start, end = parse_line_range([start, payload["end_line"]])
        cwe_value = first_value(payload, "cwe", default=default_cwe)
        proof = first_value(payload, "proof_method", "proof", default=None)
        source_value = first_value(payload, "source", "target_source", default=None)
        if proof is None:
            proof = (
                "validated_decoy"
                if source_value in {"synthetic_decoy", "validated_decoy"}
                else "human_annotated"
            )
        commands = parse_commands(
            first_value(payload, "validator_commands", "validators", "validator")
        )
        evidence = [
            parse_location(entry, default_file=file_value)
            for entry in first_value(payload, "evidence_locations", "evidence", default=[]) or []
        ]
        contracts.append(
            SafeTargetContract(
                safe_target_id=str(
                    first_value(
                        payload,
                        "safe_target_id",
                        "id",
                        default=f"SAFE-{stable_id('SAFE', file_value, start, index)[-12:]}",
                    )
                ),
                file=file_value,
                start_line=start,
                end_line=end,
                vulnerability_type=str(
                    first_value(
                        payload,
                        "vulnerability_type",
                        "type",
                        default=default_vulnerability_type or "safe component",
                    )
                ),
                cwe=str(cwe_value),
                safety_claim=str(
                    first_value(
                        payload,
                        "safety_claim",
                        "claim",
                        default=f"Declared safe by {source}",
                    )
                ),
                proof_method=proof,
                validator_commands=commands,
                evidence_locations=evidence,
                validated_safe=False,
                source=source_value or "human_annotation",
                source_reference=first_value(payload, "source_reference", "reference"),
            )
        )
    return contracts


def _truthy_verified(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) == 1
    return str(value).strip().lower() in {"1", "true", "yes", "verified", "ok"}


def is_verified(report: dict[str, Any], entries: list[dict[str, Any]]) -> bool:
    values = []
    for record in [report, *entries]:
        value = first_value(record, "verify", "verified", "is_verified")
        if value is not None:
            values.append(_truthy_verified(value))
    return all(values) if values else True


def _collect_repo(records: list[dict[str, Any]]) -> tuple[str, str, str | None, str | None]:
    urls: set[str] = set()
    commits: set[str] = set()
    fixed: set[str] = set()
    license_value: str | None = None
    for record in records:
        repo = first_value(record, "repo_url", "repository_url", "repo", "repository_url", "repository")
        if isinstance(repo, dict):
            license_value = license_value or first_value(repo, "license", "spdx_id")
            repo = first_value(repo, "url", "html_url", "clone_url")
        if repo:
            urls.add(str(repo).strip())
        commit = first_value(
            record,
            "commit",
            "vulnerable_commit",
            "base_commit",
            "fix_base_commit",
            "revision",
        )
        if commit:
            commits.add(str(commit).strip().lower())
        fix = first_value(record, "fixed_commit", "fix_commit", "patched_commit")
        if fix:
            fixed.add(str(fix).strip().lower())
        license_value = license_value or first_value(record, "license", "upstream_license", "spdx_id")
    if not urls:
        raise DatasetError("advisory has no repository URL")
    if not commits:
        raise DatasetError("advisory has no vulnerable commit")
    if len(urls) > 1:
        raise DatasetError(
            "repository URL is inconsistent across an advisory",
            details={"values": sorted(urls)},
        )
    if len(commits) > 1:
        raise DatasetError(
            "vulnerable commit is inconsistent across an advisory",
            details={"values": sorted(commits)},
        )
    if len(fixed) > 1:
        raise DatasetError(
            "fixed commit is inconsistent across an advisory",
            details={"values": sorted(fixed)},
        )
    commit = next(iter(commits))
    if not re.match(r"^[0-9a-f]{40}$", commit):
        raise DatasetError(
            "vulnerable commit must be a full 40-character hexadecimal hash",
            details={"commit": commit},
        )
    return next(iter(urls)), commit, next(iter(fixed)) if fixed else None, license_value


def _entry_commands(entry: dict[str, Any], report: dict[str, Any], kind: str) -> list[ValidatorCommand]:
    keys = (f"{kind}_commands", f"{kind}_command", kind, f"{kind}s")
    raw = first_value(entry, *keys)
    if raw is None:
        raw = first_value(report, *keys)
    return parse_commands(raw)


def _entry_location(
    entry: dict[str, Any],
    keys: tuple[str, ...],
    *,
    default_file: str | None,
    default_line: Any,
    default_code: str | None = None,
    description: str | None = None,
) -> CodeLocation | None:
    raw = first_value(entry, *keys)
    if raw is None:
        return None
    return parse_location(
        raw,
        default_file=default_file,
        default_line=default_line,
        default_code=default_code,
        description=description,
    )


def _extract_trace(entry: dict[str, Any], default_file: str | None) -> list[CodeLocation]:
    raw = first_value(entry, "trace", "path", "call_chain", "flow")
    if raw is None:
        return []
    if isinstance(raw, dict) and "nodes" in raw:
        raw = raw["nodes"]
    if not isinstance(raw, list):
        raise DatasetError("trace must be a list", details={"value": raw})
    trace: list[CodeLocation] = []
    for item in raw:
        if isinstance(item, str) and not re.match(r"^[^:]+:\d", item):
            # Plain source snippet rather than a location: attach to default file.
            if default_file is None:
                raise DatasetError("trace string has no file context", details={"value": item})
            trace.append(
                parse_location({"file": default_file, "line": 1, "code": item})
            )
        else:
            trace.append(parse_location(item, default_file=default_file))
    return trace


def _extract_entry_locations(
    entry: dict[str, Any], report: dict[str, Any]
) -> tuple[CodeLocation, list[CodeLocation], CodeLocation, str, str]:
    file_value = first_value(entry, "file", "path", "file_path", "target_file", "filename")
    if not file_value:
        raise DatasetError("entry has no file", details={"entry_id": first_value(entry, "entry_id")})
    line_value = first_value(entry, "line", "lines", "line_range", "start_line")
    if line_value is None:
        code = first_value(entry, "code", "snippet")
        if code:
            line_value = 1
    if line_value is None:
        raise DatasetError(
            "entry has no line information",
            details={"entry_id": first_value(entry, "entry_id"), "file": file_value},
        )
    default_line = line_value
    code = first_value(entry, "code", "snippet")
    ep = _entry_location(
        entry,
        ("entry_point", "source", "entry", "source_location"),
        default_file=file_value,
        default_line=default_line,
        default_code=code,
        description="entry point",
    ) or parse_location(
        {"file": file_value, "line": default_line, "code": code},
        description="entry point",
    )
    co = _entry_location(
        entry,
        ("critical_operation", "sink", "sink_location", "dangerous_operation"),
        default_file=file_value,
        default_line=default_line,
        description="critical operation",
    )
    if co is None:
        sink_file = first_value(entry, "sink_file", "critical_operation_file")
        sink_line = first_value(entry, "sink_line", "critical_operation_line")
        if sink_file or sink_line:
            co = parse_location(
                {
                    "file": sink_file or file_value,
                    "line": sink_line or default_line,
                },
                description="critical operation",
            )
        else:
            co = ep.model_copy(update={"description": "critical operation (co-located with entry)"})
    trace = _extract_trace(entry, file_value)
    return ep, trace, co, ep.file, co.file


def _difficulty_for(
    vulnerabilities: list[VulnerabilityRecord], entries: list[dict[str, Any]], report: dict[str, Any]
) -> tuple[AuditDifficulty, AuditDifficulty | None, str]:
    manual = first_value(
        report,
        "audit_difficulty",
        "difficulty",
        "final_difficulty",
        "manual_difficulty",
    )
    if isinstance(manual, str):
        normalized = manual.strip().upper()
        if normalized in _DIFFICULTIES:
            return AuditDifficulty(normalized), AuditDifficulty(normalized), "human"
    if len(vulnerabilities) > 1:
        return AuditDifficulty.D4_MULTI_VULNERABILITY, None, "automatic"
    explicit_context = any(
        bool(first_value(entry, "depends_on_context", "depends_on_configuration", "context_dependent"))
        for entry in entries
    ) or bool(first_value(report, "depends_on_context", "depends_on_configuration"))
    if explicit_context:
        return AuditDifficulty.D3_CONTEXT_DEPENDENT, None, "automatic"
    files: set[str] = set()
    functions: set[str] = set()
    for vulnerability in vulnerabilities:
        for path in vulnerability.paths:
            files.add(path.entry_point.file)
            files.add(path.critical_operation.file)
            files.update(item.file for item in path.trace)
    for entry in entries:
        function = first_value(entry, "function", "function_name", "symbol")
        if function:
            functions.add(str(function))
        for item in first_value(entry, "functions", default=[]) or []:
            functions.add(str(item))
    if len(files) >= 2:
        return AuditDifficulty.D2_CROSS_FILE, None, "automatic"
    if len(functions) >= 2:
        return AuditDifficulty.D1_INTRAFILE_INTERPROCEDURAL, None, "automatic"
    return AuditDifficulty.D0_DIRECT_LOCAL, None, "automatic"


def build_oracle(
    report: dict[str, Any],
    entries: list[dict[str, Any]],
    *,
    dataset_name: str = "vulngym",
    allow_unverified: bool = False,
) -> CanonicalVulnerabilityOracle:
    if not entries:
        raise DatasetError("advisory has no entries")
    report_id = first_value(report, "report_id", "advisory_id", "id")
    if not report_id:
        raise DatasetError("advisory has no report_id")
    if not is_verified(report, entries):
        if not allow_unverified:
            raise DatasetError(
                "advisory is not verified (verify != 1); pass --allow-unverified for a dev set",
                details={"report_id": report_id},
            )
    repo_url, commit, fixed_commit, license_value = _collect_repo([report, *entries])

    vulnerabilities: list[VulnerabilityRecord] = []
    report_title = str(first_value(report, "title", "advisory_title", "summary", default=""))
    report_cwe = normalize_cwe_list(first_value(report, "cwe", "cwe_ids", "cwes"))
    report_severity = parse_severity(
        first_value(report, "severity", "cvss", "severity_record"), "advisory"
    )
    seen_entries: set[str] = set()
    for index, entry in enumerate(entries):
        entry_id_raw = first_value(entry, "entry_id", "id", "record_id", default=f"entry-{index + 1}")
        entry_id = str(entry_id_raw)
        if entry_id in seen_entries:
            raise DatasetError("duplicate entry_id within advisory", details={"entry_id": entry_id})
        seen_entries.add(entry_id)
        ep, trace, co, ep_file, co_file = _extract_entry_locations(entry, report)
        entry_title = first_value(entry, "title", "entry_title")
        entry_type = first_value(entry, "vulnerability_type", "vuln_type", "category")
        title = str(
            entry_title
            or entry_type
            or f"Vulnerability at {ep_file}:{ep.start_line}"
        )
        cwe = normalize_cwe_list(first_value(entry, "cwe", "cwe_ids", "cwes")) or report_cwe
        severity = parse_severity(
            first_value(entry, "severity", "severity_record"), "entry"
        ) or report_severity
        vulnerability = VulnerabilityRecord(
            vulnerability_id=stable_id("VULN", report_id, entry_id),
            aliases=[],
            title=title,
            cwe=cwe,
            category_l1=first_value(entry, "category_l1", "category"),
            category_l2=first_value(entry, "category_l2", "subcategory"),
            root_cause=first_value(entry, "root_cause", "description", "summary"),
            paths=[
                VulnerabilityPath(
                    path_id=stable_id("PATH", report_id, entry_id),
                    entry_point=ep,
                    trace=trace,
                    critical_operation=co,
                )
            ],
            affected_files=sorted({ep_file, co_file, *(item.file for item in trace)}),
            severity=severity,
            poc_commands=_entry_commands(entry, report, "poc"),
            regression_commands=_entry_commands(entry, report, "regression"),
        )
        vulnerabilities.append(vulnerability)

    suggested, final, source = _difficulty_for(vulnerabilities, entries, report)
    verify = is_verified(report, entries)
    raw_safe_targets = first_value(
        report, "safe_targets", "safe_target_contracts", "verified_safe_targets"
    )
    oracle_safe_targets: list[SafeTargetContract] = []
    if raw_safe_targets is not None:
        default_cwe = (
            vulnerabilities[0].cwe[0] if vulnerabilities and vulnerabilities[0].cwe else "CWE-0"
        )
        oracle_safe_targets = parse_safe_targets(
            raw_safe_targets,
            default_cwe=default_cwe,
            source=dataset_name,
            default_vulnerability_type=vulnerabilities[0].title,
        )
    cve_ids = _identifier_list(report, "cve_id", "cve", "cves", "cve_ids")
    ghsa_ids = _identifier_list(report, "ghsa_id", "ghsa", "ghsa_ids", "advisory_id")
    published = first_value(report, "published", "published_at", "date", "disclosure_date")
    source_url = first_value(report, "url", "html_url", "advisory_url", "source_link", "link")
    hidden_metadata = {
        "advisory_title": report_title or None,
        "advisory_summary": first_value(report, "summary", "description", "details"),
        "cve_ids": cve_ids,
        "ghsa_ids": ghsa_ids,
        "published_at": published,
        "source_url": source_url,
        "report_id": str(report_id),
        "entry_ids": sorted(seen_entries),
        "verify": verify,
        "entries": [
            {
                key: first_value(entry, key)
                for key in ("entry_id", "function", "vulnerability_type", "file", "line")
                if first_value(entry, key) is not None
            }
            for entry in entries
        ],
        "difficulty_notes": first_value(report, "difficulty_notes", "difficulty_source"),
    }
    oracle = CanonicalVulnerabilityOracle(
        oracle_id=stable_id("VMO", dataset_name, report_id, repo_url, commit),
        schema_version=ORACLE_SCHEMA_VERSION,
        source_dataset=dataset_name,
        source_record_ids=sorted(seen_entries),
        repository=RepositoryRef(
            repo_url=repo_url,
            vulnerable_commit=commit,
            fixed_commit=fixed_commit,
            upstream_license=license_value,
        ),
        vulnerabilities=vulnerabilities,
        suggested_difficulty=suggested,
        final_difficulty=final,
        difficulty_source=source,
        validation_level="trace_grounded" if verify else "unverified",
        hidden_metadata=hidden_metadata,
        safe_targets=oracle_safe_targets,
    )
    return oracle


def _identifier_list(record: dict[str, Any], *keys: str) -> list[str]:
    value = first_value(record, *keys)
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    output: list[str] = []
    for item in items:
        text = str(item).strip()
        if text and text not in output:
            output.append(text)
    return sorted(output)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_oracle(
    oracle: CanonicalVulnerabilityOracle,
    output_dir: Path,
    *,
    extra_metadata: dict[str, Any] | None = None,
) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{oracle.oracle_id}.json"
    payload = oracle.model_dump(mode="json")
    atomic_write_json(path, payload)
    if extra_metadata is not None:
        atomic_write_json(
            output_dir / f"{oracle.oracle_id}.meta.json",
            {
                "oracle_id": oracle.oracle_id,
                "sha256": sha256_text(json.dumps(payload, sort_keys=True, ensure_ascii=False)),
                **extra_metadata,
            },
        )
    return path


def oracle_digest(oracle: CanonicalVulnerabilityOracle) -> str:
    return stable_digest("oracle", oracle.model_dump(mode="json"))
