"""Repository facts extracted from the actual snapshot.

The distinction this module enforces:

* a :class:`RepositoryFact` is something *extracted from the repository* by a
  named method (AST lookup, file scan, ...), carrying its file/line evidence and
  a content hash;
* a *generated claim* (:class:`~vulnmirage.models.attack_plan.FalseClaim`) is a
  product under test and never becomes a repository fact merely because a model
  produced it;
* a *report claim* (:mod:`vulnmirage.models.reference`) is what a reference audit
  said.  It may be extracted and quoted, but it stays ``report_claim`` until an
  independent verification links it to the oracle or to a validated safe target.

None of these models may be serialized into a :class:`GeneratorRequest` except
through the explicit allowlist projection in
:mod:`vulnmirage.generation.request`.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..paths import normalize_relpath


class FactKind(str, Enum):
    """What a repository fact states."""

    TARGET_ENTRY_POINT = "target_entry_point"
    TARGET_CRITICAL_OPERATION = "target_critical_operation"
    TARGET_TRACE = "target_trace"
    SYMBOL = "symbol"
    CALL_SITE = "call_site"
    PROTECTION = "protection"
    ROUTE = "route"
    CONFIG_DEFAULT = "config_default"
    TEST = "test"
    DOCUMENTATION = "documentation"
    DOCUMENTATION_STYLE = "documentation_style"
    RELATED_FILE = "related_file"


class FactMethod(str, Enum):
    """How the fact was established (recorded so it can be audited)."""

    PYTHON_AST = "python_ast"
    TEXT_PATTERN = "text_pattern"
    FILE_SCAN = "file_scan"
    IMPORT_GRAPH = "import_graph"
    DOCUMENTATION_SCAN = "documentation_scan"
    MANUAL = "manual"


class FactStatus(str, Enum):
    """Trust status of a fact.

    ``verified`` means a concrete extraction method produced it from this
    snapshot.  ``candidate`` means the method found a plausible but unresolved
    match (for example a same-name call in another module).  ``unknown`` means
    the property could not be decided; it is never upgraded to a pass.
    """

    VERIFIED = "verified"
    CANDIDATE = "candidate"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"


class FactEvidence(BaseModel):
    """Traceable evidence for one fact."""

    model_config = ConfigDict(extra="forbid")

    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    snippet: str | None = None
    snippet_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    truncated: bool = False
    reference: str | None = None

    @field_validator("file")
    @classmethod
    def _file(cls, value: str) -> str:
        return normalize_relpath(value)

    @model_validator(mode="after")
    def _span(self) -> "FactEvidence":
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        if self.snippet is not None and self.snippet_sha256 is None:
            import hashlib

            object.__setattr__(
                self,
                "snippet_sha256",
                hashlib.sha256(self.snippet.encode("utf-8")).hexdigest(),
            )
        return self


class RepositoryFact(BaseModel):
    """One verified/candidate/unknown statement about the fixed snapshot."""

    model_config = ConfigDict(extra="forbid")

    fact_id: str
    kind: FactKind
    statement: str
    evidence: list[FactEvidence] = Field(default_factory=list)
    method: FactMethod
    status: FactStatus = FactStatus.VERIFIED
    capability: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    notes: list[str] = Field(default_factory=list)

    @field_validator("fact_id", "statement")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value


class DocumentationStyle(BaseModel):
    """Observed documentation conventions of the snapshot (not a guess)."""

    model_config = ConfigDict(extra="forbid")

    files: list[str] = Field(default_factory=list)
    suffixes: list[str] = Field(default_factory=list)
    heading_levels: list[str] = Field(default_factory=list)
    terminology: list[str] = Field(default_factory=list)
    mean_paragraph_chars: float | None = None
    comment_prefix: str | None = None
    samples: list[FactEvidence] = Field(default_factory=list)

    @field_validator("files", "suffixes", "heading_levels", "terminology")
    @classmethod
    def _sorted_unique(cls, value: list[str]) -> list[str]:
        return sorted({item for item in value if item.strip()})


class ContextBudget(BaseModel):
    """Explicit context budget; truncation is recorded, never hidden."""

    model_config = ConfigDict(extra="forbid")

    max_files: int = Field(default=8, ge=1)
    max_snippets: int = Field(default=24, ge=1)
    max_chars: int = Field(default=12_000, ge=256)
    max_style_samples: int = Field(default=4, ge=0)

    @model_validator(mode="after")
    def _consistent(self) -> "ContextBudget":
        if self.max_style_samples > self.max_files:
            object.__setattr__(self, "max_style_samples", self.max_files)
        return self


class ContextUsage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    files: int = 0
    snippets: int = 0
    chars: int = 0
    truncated: bool = False
    omitted_files: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class RepositoryFacts(BaseModel):
    """All facts extracted for one target, plus extraction capabilities."""

    model_config = ConfigDict(extra="forbid")

    target_handle: str | None = None
    target_vulnerability_id: str | None = None
    target_safe_target_id: str | None = None
    target_file: str | None = None
    language: str | None = None
    language_capability: dict[str, str] = Field(default_factory=dict)
    facts: list[RepositoryFact] = Field(default_factory=list)
    documentation_style: DocumentationStyle | None = None
    budget: ContextBudget = Field(default_factory=ContextBudget)
    usage: ContextUsage = Field(default_factory=ContextUsage)
    missing: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    repository_tree_sha256: str | None = None
    snapshot_id: str | None = None

    def of_kind(self, kind: FactKind) -> list[RepositoryFact]:
        return [fact for fact in self.facts if fact.kind == kind]

    def fact(self, fact_id: str) -> RepositoryFact | None:
        for fact in self.facts:
            if fact.fact_id == fact_id:
                return fact
        return None

    def digest(self) -> str:
        import hashlib
        import json

        payload: dict[str, Any] = {
            "target": [self.target_vulnerability_id, self.target_safe_target_id],
            "facts": [
                {
                    "id": fact.fact_id,
                    "kind": fact.kind.value,
                    "status": fact.status.value,
                    "statement": fact.statement,
                    "evidence": [
                        [item.file, item.start_line, item.end_line, item.snippet_sha256]
                        for item in fact.evidence
                    ],
                }
                for fact in self.facts
            ],
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
