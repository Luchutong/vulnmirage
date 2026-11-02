"""Parse structured agent findings without silent LLM repair."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError as PydanticValidationError

from ..errors import OutputParseError
from ..hashing import sha256_text, utc_now_iso
from ..models import AgentFinding, AuditSummary, CodeLocation, FindingEnvelope
from ..normalization import normalize_cwe_list, normalize_severity
from ..paths import is_safe_relpath, normalize_relpath

_FENCE_RE = re.compile(r"```(?:json|JSON)?\s*\n?(.*?)```", re.S)


class ParsedOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    envelope: FindingEnvelope
    raw_sha256: str
    source_path: str | None = None
    extraction: str = "plain_json"
    duplicates_removed: int = 0
    warnings: list[str] = Field(default_factory=list)

    @property
    def findings(self) -> list[AgentFinding]:
        return self.envelope.findings


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
    try:
        envelope = FindingEnvelope.model_validate(normalized)
    except PydanticValidationError as exc:
        raise OutputParseError(
            f"agent output does not conform to the finding schema: {exc}",
            details={"raw_sha256": raw_sha, "errors": exc.errors(include_url=False)},
        ) from exc
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
        warnings=[],
    )


def parse_output_file(path: Path, *, repo_root: Path | None = None) -> ParsedOutput:
    path = Path(path)
    if not path.is_file():
        raise OutputParseError("agent output file does not exist", details={"path": str(path)})
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_agent_output(text, repo_root=repo_root, source_path=path)


def finding_key(finding: AgentFinding) -> str:
    return json.dumps(finding.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
