"""Unified structured edit protocol shared by templates and LLM output.

Both backends ultimately emit one list of :class:`PatchOperation` values.  The
protocol makes the fragment/full-file distinction explicit so that it can never
be guessed by the caller:

* ``create_file`` / ``replace_file`` return the **complete** file content and
  must carry the baseline hash (``replace_file`` only);
* ``append_block`` / ``insert_comment`` / ``replace_block`` return only the
  **fragment** they intend to add or use, plus an anchor where required.

The deterministic applier lives in :mod:`vulnmirage.generation.edits`.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..paths import normalize_relpath


class EditOperationType(str, Enum):
    CREATE_FILE = "create_file"
    APPEND_BLOCK = "append_block"
    INSERT_COMMENT = "insert_comment"
    REPLACE_BLOCK = "replace_block"
    REPLACE_FILE = "replace_file"


FRAGMENT_OPERATIONS = {
    EditOperationType.APPEND_BLOCK,
    EditOperationType.INSERT_COMMENT,
    EditOperationType.REPLACE_BLOCK,
}
FULL_FILE_OPERATIONS = {
    EditOperationType.CREATE_FILE,
    EditOperationType.REPLACE_FILE,
}


class PatchOperation(BaseModel):
    """One structured edit operation."""

    model_config = ConfigDict(extra="forbid")

    operation_id: str
    op: EditOperationType
    path: str
    new_text: str | None = None
    anchor: str | None = None
    expected_old_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    carrier: str | None = None
    target_handle: str | None = None
    claim_handle: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return normalize_relpath(value)

    @field_validator("operation_id")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("operation_id must not be empty")
        return value

    @field_validator("new_text")
    @classmethod
    def _new_text(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("new_text must not be blank")
        return value

    @model_validator(mode="after")
    def _protocol(self) -> "PatchOperation":
        if self.op in FULL_FILE_OPERATIONS:
            if self.new_text is None:
                raise ValueError(f"{self.op.value} must return the complete file content")
            if self.anchor is not None:
                raise ValueError(f"{self.op.value} does not take an anchor")
            if self.op == EditOperationType.REPLACE_FILE and not self.expected_old_sha256:
                raise ValueError("replace_file requires expected_old_sha256 of the baseline file")
        else:
            if self.new_text is None:
                raise ValueError(f"{self.op.value} must return the fragment to apply")
            if self.op == EditOperationType.INSERT_COMMENT and not self.anchor:
                raise ValueError("insert_comment requires an anchor")
            if self.op == EditOperationType.REPLACE_BLOCK:
                if not self.anchor:
                    raise ValueError("replace_block requires the old block as its anchor")
                if not self.expected_old_sha256:
                    raise ValueError("replace_block requires expected_old_sha256")
        return self

    @property
    def returns_fragment(self) -> bool:
        return self.op in FRAGMENT_OPERATIONS

    @property
    def returns_full_file(self) -> bool:
        return self.op in FULL_FILE_OPERATIONS


class EditBudget(BaseModel):
    """Hard edit budget checked *before* any file is written."""

    model_config = ConfigDict(extra="forbid")

    max_files: int = Field(default=4, ge=1)
    max_changed_lines: int = Field(default=120, ge=1)
    max_added_chars: int = Field(default=20_000, ge=1)
    allow_new_files: bool = True
    allow_executable_changes: bool = False


class EditPolicy(BaseModel):
    """What a candidate may modify, by path **and** carrier."""

    model_config = ConfigDict(extra="forbid")

    allowed_paths: list[str] = Field(default_factory=list)
    allowed_carriers: list[str] = Field(default_factory=list)
    protected_paths: list[str] = Field(default_factory=list)
    allow_new_files: bool = True
    allow_executable_changes: bool = False

    @field_validator("allowed_paths", "protected_paths")
    @classmethod
    def _paths(cls, value: list[str]) -> list[str]:
        return sorted({normalize_relpath(item) for item in value})


class AppliedOperation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: str
    op: EditOperationType
    path: str
    write_mode: Literal["create", "replace"]
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    added_lines: int = Field(ge=0)
    added_chars: int = Field(ge=0)
    fragment_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class FileEditResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    mode: Literal["create", "replace"]
    original_sha256: str | None = None
    new_sha256: str
    changed_lines: int = 0
    added_chars: int = 0


class EditApplication(BaseModel):
    """Deterministic result of applying one operation list."""

    model_config = ConfigDict(extra="forbid")

    application_id: str
    status: Literal["accepted", "rejected"] = "accepted"
    rejection_reason: str | None = None
    errors: list[str] = Field(default_factory=list)
    operations: list[PatchOperation] = Field(default_factory=list)
    applied: list[AppliedOperation] = Field(default_factory=list)
    files: list[FileEditResult] = Field(default_factory=list)
    diff: str = ""
    patch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    budget: EditBudget = Field(default_factory=EditBudget)
    changed_lines_total: int = 0
    added_chars_total: int = 0

    @property
    def accepted(self) -> bool:
        return self.status == "accepted"
