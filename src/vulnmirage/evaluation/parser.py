"""Parse structured agent findings without silent LLM repair.

Two output contracts are accepted, and which one was used is recorded rather than
inferred:

* ``dual_output`` -- ``{schema_version, report_markdown, findings, audit_summary}``,
  the current contract (agent-written report *and* machine-readable findings);
* ``findings_only`` -- ``{schema_version, findings, audit_summary}``, kept so that
  archived runs from before the contract change stay parseable.  These runs are
  flagged, not silently upgraded: a missing report is ``report_status=missing``.

No stage here calls a model to repair output.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError as PydanticValidationError

from ..errors import OutputParseError
from ..hashing import sha256_text, utc_now_iso
from ..models import (
    AgentFinding,
    AuditReportEnvelope,
    AuditSummary,
    CodeLocation,
    FindingEnvelope,
)
from ..normalization import normalize_cwe_list, normalize_severity
from ..paths import is_safe_relpath, normalize_relpath

_FENCE_RE = re.compile(r"```(?:json|JSON)?\s*\n?(.*?)```", re.S)

#: Top-level keys the dual-output contract defines.
AUDIT_CONTRACT_KEYS = ("schema_version", "report_markdown", "findings", "audit_summary")

#: Finding ids the report is expected to repeat, e.g. ``F-12``.
_FINDING_ID_RE = re.compile(r"\bF-?\d{1,3}\b", re.I)

OUTPUT_CONSISTENCY_VERSION = "1.0"


class ParsedOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    envelope: FindingEnvelope
    raw_sha256: str
    source_path: str | None = None
    extraction: str = "plain_json"
    duplicates_removed: int = 0
    warnings: list[str] = Field(default_factory=list)
    #: ``dual_output`` when the answer carried ``report_markdown``.
    output_contract: str = "findings_only"
    report_markdown: str | None = None
    report_sha256: str | None = None
    ignored_keys: list[str] = Field(default_factory=list)

    @property
    def findings(self) -> list[AgentFinding]:
        return self.envelope.findings

    @property
    def has_report(self) -> bool:
        return bool(self.report_markdown and self.report_markdown.strip())


def _normalize_path(value: Any, repo_root: Path | None) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    if repo_root is not None and text.startswith("/"):
        try:
            relative = Path(text).resolve().relative_to(Path(repo_root).resolve()).as_posix()
            text = relative
        except ValueError:
            pass
    if text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        normalized = text.replace("\\", "/")
        if "/repo/" in normalized:
            text = normalized.split("/repo/", 1)[1]
    return text


def _normalize_location(raw: Any, repo_root: Path | None) -> Any:
    if not isinstance(raw, dict):
        return raw
    payload = dict(raw)
    if "file" in payload:
        payload["file"] = _normalize_path(payload["file"], repo_root)
    if "start_line" not in payload and "line" in payload:
        line = payload.pop("line")
        if isinstance(line, int):
            payload["start_line"] = line
            payload.setdefault("end_line", line)
    if "end_line" not in payload and "start_line" in payload:
        payload["end_line"] = payload["start_line"]
    return payload


def _normalize_finding(raw: Any, repo_root: Path | None) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise OutputParseError("each finding must be a JSON object")
    payload = dict(raw)
    if "severity" in payload:
        try:
            payload["severity"] = normalize_severity(payload["severity"]).value
        except Exception as exc:
            raise OutputParseError(f"invalid severity: {payload['severity']!r}") from exc
    if "cwe" in payload:
        try:
            payload["cwe"] = normalize_cwe_list(payload["cwe"])
        except Exception:
            pass
    for key in ("locations", "trace"):
        if key in payload and isinstance(payload[key], list):
            payload[key] = [_normalize_location(item, repo_root) for item in payload[key]]
    for key in ("entry_point", "critical_operation"):
        if key in payload and payload[key] is not None:
            payload[key] = _normalize_location(payload[key], repo_root)
    if isinstance(payload.get("evidence_citations"), list):
        citations = []
        for citation in payload["evidence_citations"]:
            if not isinstance(citation, dict):
                continue
            item = dict(citation)
            if isinstance(item.get("location"), dict):
                item["location"] = _normalize_location(item["location"], repo_root)
            citations.append(item)
        payload["evidence_citations"] = citations
    return payload


def _balanced_objects(text: str) -> list[str]:
    objects: list[str] = []
    depth = 0
    start: int | None = None
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    objects.append(text[start : index + 1])
                    start = None
    return objects


def extract_json_objects(text: str) -> list[dict[str, Any]]:
    """Return every balanced JSON object that looks like a finding envelope."""
    objects: list[dict[str, Any]] = []
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            objects.append(payload)
    for block in _balanced_objects(text):
        try:
            payload = json.loads(block)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload not in objects:
            objects.append(payload)
    return [item for item in objects if "findings" in item]


def extract_json_object(text: str) -> tuple[dict[str, Any], str]:
    stripped = text.strip()
    if not stripped:
        raise OutputParseError("agent output is empty")
    try:
        payload = json.loads(stripped)
        if isinstance(payload, dict):
            return payload, "plain_json"
    except json.JSONDecodeError:
        pass
    candidates: list[tuple[dict[str, Any], str]] = []
    for block in _FENCE_RE.findall(text):
        try:
            payload = json.loads(block.strip())
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and "findings" in payload:
            candidates.append((payload, "markdown_fence"))
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        raise OutputParseError("multiple JSON objects found in markdown fences")
    for candidate in _balanced_objects(text):
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and "findings" in payload:
            return payload, "balanced_object"
    raise OutputParseError("no JSON finding envelope could be extracted")


def parse_agent_output(
    text: str,
    *,
    repo_root: Path | None = None,
    source_path: Path | None = None,
    require_report: bool = False,
) -> ParsedOutput:
    raw_sha = sha256_text(text)
    payload, extraction = extract_json_object(text)
    if not isinstance(payload.get("findings"), list):
        raise OutputParseError("envelope has no findings array", details={"raw_sha256": raw_sha})
    normalized = dict(payload)
    normalized["findings"] = [
        _normalize_finding(item, repo_root) for item in payload.get("findings", [])
    ]
    audit_summary = payload.get("audit_summary")
    if not isinstance(audit_summary, dict):
        normalized["audit_summary"] = AuditSummary().model_dump(mode="json")

    # The dual-output contract is detected from the payload, never assumed, so an
    # archived findings-only answer is not misreported as a missing report.
    has_contract_report = "report_markdown" in payload
    model = AuditReportEnvelope if has_contract_report else FindingEnvelope
    try:
        parsed_envelope = model.model_validate(normalized)
    except PydanticValidationError as exc:
        raise OutputParseError(
            f"agent output does not conform to the finding schema: {exc}",
            details={"raw_sha256": raw_sha, "errors": exc.errors(include_url=False)},
        ) from exc
    report_markdown = getattr(parsed_envelope, "report_markdown", None)
    envelope = FindingEnvelope(
        schema_version="1.0",
        findings=list(parsed_envelope.findings),
        audit_summary=parsed_envelope.audit_summary,
    )
    ignored = sorted(set(payload) - set(AUDIT_CONTRACT_KEYS))
    warnings: list[str] = []
    if ignored:
        warnings.append("ignored unknown top-level keys: " + ", ".join(ignored))
    if require_report and not (report_markdown or "").strip():
        warnings.append("the dual-output contract requires a non-empty report_markdown")

    deduped: list[AgentFinding] = []
    seen: set[tuple[Any, ...]] = set()
    duplicates = 0
    for finding in envelope.findings:
        location = finding.critical_operation or (finding.locations[0] if finding.locations else None)
        try:
            normalized_cwe = tuple(normalize_cwe_list(finding.cwe))
        except Exception:
            normalized_cwe = tuple(finding.cwe)
        key = (
            normalized_cwe,
            finding.vulnerability_type.strip().lower(),
            location.file if location else None,
            location.start_line if location else None,
        )
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        deduped.append(finding)
    if duplicates:
        envelope = envelope.model_copy(update={"findings": deduped})
    return ParsedOutput(
        envelope=envelope,
        raw_sha256=raw_sha,
        source_path=str(source_path) if source_path else None,
        extraction=extraction,
        duplicates_removed=duplicates,
        warnings=warnings,
        output_contract="dual_output" if has_contract_report else "findings_only",
        report_markdown=report_markdown,
        report_sha256=sha256_text(report_markdown) if report_markdown else None,
        ignored_keys=ignored,
    )


def parse_output_file(
    path: Path, *, repo_root: Path | None = None, require_report: bool = False
) -> ParsedOutput:
    path = Path(path)
    if not path.is_file():
        raise OutputParseError("agent output file does not exist", details={"path": str(path)})
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_agent_output(
        text, repo_root=repo_root, source_path=path, require_report=require_report
    )


class OutputConsistency(BaseModel):
    """Report-to-findings correspondence for one run.

    Only unambiguous relations are asserted: which ``finding_id`` the JSON
    contains, which ids the report mentions, and whether the report exists at all.
    Contradictions in *content* are left to adjudication rather than guessed from
    text similarity.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = OUTPUT_CONSISTENCY_VERSION
    raw_sha256: str | None = None
    report_present: bool = False
    report_sha256: str | None = None
    report_chars: int = 0
    report_truncated: bool = False
    output_contract: str = "findings_only"
    finding_ids: list[str] = Field(default_factory=list)
    ids_in_report: list[str] = Field(default_factory=list)
    findings_missing_from_report: list[str] = Field(default_factory=list)
    report_ids_missing_from_findings: list[str] = Field(default_factory=list)
    consistent: bool = False
    status: str = "unknown"
    notes: list[str] = Field(default_factory=list)
    produced_at: str = Field(default_factory=utc_now_iso)


def output_consistency(
    parsed: ParsedOutput | None,
    *,
    max_report_chars: int | None = None,
    require_report: bool = True,
) -> OutputConsistency:
    """Compare the agent's report with its structured findings."""
    if parsed is None:
        return OutputConsistency(
            status="no_output",
            consistent=False,
            notes=["no parsed output: consistency cannot be evaluated"],
        )
    report = parsed.report_markdown or ""
    truncated = False
    if max_report_chars and len(report) > max_report_chars:
        report = report[:max_report_chars]
        truncated = True
    finding_ids = [item.finding_id for item in parsed.findings]
    ids_in_report = sorted({match.upper() for match in _FINDING_ID_RE.findall(report)})
    normalized_report_ids = {item.upper().replace("-", "") for item in ids_in_report}
    missing_from_report = [
        item for item in finding_ids if item.upper().replace("-", "") not in normalized_report_ids
    ]
    normalized_finding_ids = {item.upper().replace("-", "") for item in finding_ids}
    report_only = [
        item for item in ids_in_report if item.upper().replace("-", "") not in normalized_finding_ids
    ]
    present = bool(parsed.report_markdown and parsed.report_markdown.strip())
    notes: list[str] = []
    if not present:
        notes.append(
            "the answer carried no report_markdown" + (
                " although the contract requires one" if require_report else ""
            )
        )
    if present and missing_from_report:
        notes.append("findings missing from the report text: " + ", ".join(missing_from_report))
    if report_only:
        notes.append("ids mentioned in the report but absent from findings: " + ", ".join(report_only))
    if truncated:
        notes.append(f"report truncated at {max_report_chars} characters for comparison")
    consistent = present and not missing_from_report and not report_only
    if not present:
        status = "report_missing"
    elif truncated:
        status = "report_truncated"
    elif consistent:
        status = "consistent"
    else:
        status = "divergent"
    return OutputConsistency(
        raw_sha256=parsed.raw_sha256,
        report_present=present,
        report_sha256=parsed.report_sha256,
        report_chars=len(parsed.report_markdown or ""),
        report_truncated=truncated,
        output_contract=parsed.output_contract,
        finding_ids=finding_ids,
        ids_in_report=ids_in_report,
        findings_missing_from_report=missing_from_report,
        report_ids_missing_from_findings=report_only,
        consistent=consistent,
        status=status,
        notes=notes,
    )


def finding_key(finding: AgentFinding) -> str:
    return json.dumps(finding.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
