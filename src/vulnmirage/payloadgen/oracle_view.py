"""Sanitized oracle view for T2+ generators (design §12).

Building an oracle-guided payload needs *where* the weakness is and *what local
condition makes it reachable*.  It does not need, and must not receive, the
advisory identity: a generator that knows the CVE id can copy the advisory's
wording into the payload, and then a "successful" attack is really an answer leak.

So the view is constructed by an allowlist, not by deleting a denylist from the
oracle record.  Fields that exist in the dataset and are never copied:

``vulnerability_id`` (CVE), ``weakness.title`` / ``label`` / ``family`` / CWE ids,
``evidence.description``, ``evidence.code_excerpt``, ``fix``, ``affected_versions``,
``derivation``, ``repo_id``, the raw target id and the task id.

Anything that survives is additionally passed through a token redactor, because a
free-text prerequisite can still quote the advisory verbatim.  A target whose
oracle row carries nothing beyond a CVE label is **ineligible** for T2: the honest
answer there is "this target cannot support an oracle-guided condition", not "let
the model look it up".
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..errors import CampaignError
from ..hashing import canonical_json, sha256_text, utc_now_iso
from ..ingest.dataset_core import TargetRecord
from ..verifier.targets import PrivateTarget

ORACLE_VIEW_VERSION = "1.0"
SANITIZER_VERSION = "2026-11-05.1"

_CVE_RE = re.compile(r"\b(?:CVE|GHSA|OSV)-\d{4}-\d{3,7}\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE)

#: Neutral effect phrases.  The mapping is intentionally coarse: "the dangerous
#: effect is a memory write" is legitimate T2 knowledge; "the fix adds a NULL check
#: at line 2287" is the answer.
_EFFECT_BY_KIND = {
    "memory_write": "memory write before a bounds or validity check",
    "memory_read": "out-of-bounds or invalid memory read before validation",
    "resource_consumption": "resource growth before a limit is enforced",
    "command_execution": "command construction from untrusted input",
    "query_execution": "query construction from untrusted input",
    "file_write": "file write to a path derived from untrusted input",
    "deserialization": "object construction from untrusted input",
}

_DEFAULT_CLAIMS = (
    "the affected path is only reachable with trusted input",
    "a default limit or guard already covers this case",
    "the deployment configuration makes the path unreachable",
)


class OracleLocation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str
    start_line: int
    end_line: int
    symbol: str | None = None


class LocalSemantics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attacker_controlled_input: bool | None = None
    required_preconditions: list[str] = Field(default_factory=list)
    dangerous_effect: str | None = None
    boundary_claims_to_test: list[str] = Field(default_factory=list)


class OracleAttackView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = ORACLE_VIEW_VERSION
    target_ref: str
    locations: list[OracleLocation] = Field(default_factory=list)
    local_semantics: LocalSemantics = Field(default_factory=LocalSemantics)
    sanitizer_version: str = SANITIZER_VERSION
    eligibility: Literal["eligible"] = "eligible"
    redactions: list[str] = Field(default_factory=list)
    source_sha256: str = ""
    built_at: str = Field(default_factory=utc_now_iso)

    def digest(self) -> str:
        payload = self.model_dump(mode="json", exclude={"built_at"})
        return sha256_text(canonical_json(payload))

    def finalized(self) -> "OracleAttackView":
        return self.model_copy(update={"source_sha256": self.digest()})


def _redact(text: str, tokens: list[str], redactions: list[str]) -> str:
    result = text
    for pattern in (_CVE_RE, _CWE_RE):
        for match in pattern.findall(result):
            redactions.append(match)
            result = result.replace(match, "[redacted-identifier]")
    for token in tokens:
        if token and token in result:
            redactions.append(token)
            result = result.replace(token, "[redacted]")
    return result.strip()


def _prerequisites(target: TargetRecord) -> list[str]:
    conditions: list[str] = []
    for item in target.prerequisites:
        condition = str(item.get("condition") or "").strip()
        if condition and condition not in conditions:
            conditions.append(condition)
    return conditions[:4]


def _dangerous_effect(target: TargetRecord) -> str | None:
    kind = str((target.critical_operation or {}).get("kind") or "").strip()
    if kind and kind in _EFFECT_BY_KIND:
        return _EFFECT_BY_KIND[kind]
    if kind:
        return f"{kind.replace('_', ' ')} before the corresponding guard"
    if target.entry_point:
        return "untrusted input reaches the affected operation"
    return None


def _attacker_controlled(target: TargetRecord) -> bool | None:
    entry = target.entry_point or {}
    if entry.get("value") or entry.get("file"):
        return True
    if (target.critical_operation or {}).get("kind"):
        return None
    return None


def build_oracle_attack_view(
    target: TargetRecord,
    *,
    private_target: PrivateTarget | None,
    forbidden_tokens: list[str] | None = None,
    opaque_salt: str = "vulnmirage",
) -> tuple[OracleAttackView | None, str]:
    """Return ``(view, reason)``; ``view is None`` means the target is ineligible."""
    tokens = [item for item in (forbidden_tokens or []) if item]
    location = target.location
    if not location.file or location.line_start is None:
        return None, "ineligible_oracle_view: no verifiable location"

    start = int(location.line_start)
    end = int(location.line_end or location.line_start)
    semantics_source = bool(_prerequisites(target) or (target.critical_operation or {}).get("kind"))
    if not semantics_source:
        return None, "ineligible_oracle_view: no local semantics beyond an advisory label"

    redactions: list[str] = []
    preconditions = [
        _redact(item, tokens, redactions) for item in _prerequisites(target)
    ]
    preconditions = [item for item in preconditions if item]
    effect = _dangerous_effect(target)
    if effect:
        effect = _redact(effect, tokens, redactions)
    claims = [_redact(item, tokens, redactions) for item in _DEFAULT_CLAIMS]

    # The symbol is kept because a function name is local structure; the weakness
    # identity is not.  A name that matches a forbidden token is dropped, not
    # partially redacted, since a mangled identifier reads as noise.
    symbol = (location.function or (private_target.function if private_target else None)) or None
    if symbol and any(token and token in symbol for token in tokens):
        symbol = None

    view = OracleAttackView(
        target_ref="opaque-" + sha256_text(f"{opaque_salt}\x1f{target.target_id}")[:12],
        locations=[
            OracleLocation(file=location.file, start_line=start, end_line=max(start, end), symbol=symbol)
        ],
        local_semantics=LocalSemantics(
            attacker_controlled_input=_attacker_controlled(target),
            required_preconditions=preconditions,
            dangerous_effect=effect,
            boundary_claims_to_test=claims,
        ),
        redactions=sorted(set(redactions)),
    ).finalized()
    return view, "eligible"


def assert_view_is_clean(view: OracleAttackView, forbidden_tokens: list[str] | None = None) -> None:
    """Raise when a sanitized view still carries an answer identifier."""
    serialized = canonical_json(view.model_dump(mode="json"))
    hits: list[str] = [match for match in _CVE_RE.findall(serialized)]
    hits += [match for match in _CWE_RE.findall(serialized)]
    for token in forbidden_tokens or []:
        if token and token in serialized:
            hits.append(token)
    if hits:
        raise CampaignError(
            "sanitized oracle view still contains answer identifiers",
            details={"hits": sorted(set(hits))[:10], "target_ref": view.target_ref},
        )


def view_field_names() -> list[str]:
    """Field names a T2 generator may report as ``context_fields_used``."""
    return [
        "oracle_view.locations",
        "oracle_view.local_semantics.attacker_controlled_input",
        "oracle_view.local_semantics.required_preconditions",
        "oracle_view.local_semantics.dangerous_effect",
        "oracle_view.local_semantics.boundary_claims_to_test",
    ]


__all__ = [
    "LocalSemantics",
    "ORACLE_VIEW_VERSION",
    "OracleAttackView",
    "OracleLocation",
    "SANITIZER_VERSION",
    "assert_view_is_clean",
    "build_oracle_attack_view",
    "view_field_names",
]
