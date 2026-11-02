"""Code-location and repository reference models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..hashing import code_sha256
from ..paths import normalize_relpath


class CodeLocation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    code: str | None = None
    description: str | None = None
    code_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("file")
    @classmethod
    def _file(cls, value: str) -> str:
        return normalize_relpath(value)

    @model_validator(mode="after")
    def _ranges(self) -> "CodeLocation":
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        if self.code is not None:
            digest = code_sha256(self.code)
            if self.code_sha256 is None:
                object.__setattr__(self, "code_sha256", digest)
            elif self.code_sha256 != digest:
                raise ValueError("code_sha256 does not match the normalized code snippet")
        return self

    def same_span(self, other: "CodeLocation") -> bool:
        return self.file == other.file and self.start_line == other.start_line and self.end_line == other.end_line


class RepositoryRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_url: str
    vulnerable_commit: str = Field(pattern=r"^[0-9a-fA-F]{40}$")
    fixed_commit: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{40}$")
    upstream_license: str | None = None
    source_tree_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("repo_url")
    @classmethod
    def _url(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ch in value for ch in ("\n", "\r", "\x00")):
            raise ValueError("repo_url is empty or contains control characters")
        return value

    @field_validator("vulnerable_commit", "fixed_commit")
    @classmethod
    def _commit(cls, value: str | None) -> str | None:
        return value.lower() if value else value
