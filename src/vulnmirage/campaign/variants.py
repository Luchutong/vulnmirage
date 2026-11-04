"""Build variant trees from structured edits.

Each variant is constructed **independently from the same clean snapshot**: method
two is never applied on top of method one. A variant therefore has one cause, and a
difference between clean and attack trees has one explanation.

An edit is a structured operation, not a free-form patch:

``create``          write a new file (refuses to overwrite an existing path)
``append``          append to an existing file (refuses a missing file)
``insert_before``   insert text before the first occurrence of an anchor string

Every operation fails loudly when its precondition is not met.  A silently skipped
edit would produce a "variant" that is really the clean tree, and the experiment
would compare C with C while reporting it as an attack.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..campaign.task_prompt import assert_variant_is_answer_free
from ..config import VariantSpecConfig
from ..errors import CampaignError
from ..hashing import sha256_text, utc_now_iso
from ..paths import safe_join
from ..repository.archive import tree_digest

VARIANT_SCHEMA_VERSION = "1.0"


class AppliedEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    op: str
    path: str
    chars: int
    sha256: str
    detail: str | None = None


class VariantBuild(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = VARIANT_SCHEMA_VERSION
    variant_id: str
    kind: str
    payload_id: str | None = None
    method_id: str | None = None
    carrier: str | None = None
    goal: str = "none"
    knowledge: str = "public_context"
    reproduction_status: str | None = None
    template_sha256: str | None = None
    rendered_sha256: str | None = None
    base_tree_sha256: str
    tree_sha256: str
    edits: list[AppliedEdit] = Field(default_factory=list)
    files_touched: list[str] = Field(default_factory=list)
    rejected_edits: list[str] = Field(default_factory=list)
    forbidden_hits: list[str] = Field(default_factory=list)
    built_at: str = Field(default_factory=utc_now_iso)


def _apply_create(root: Path, path: str, text: str) -> AppliedEdit:
    target = safe_join(root, path)
    if target.exists():
        raise CampaignError(
            "create edit targets an existing path",
            details={"path": path, "root": root.as_posix()},
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")
    return AppliedEdit(
        op="create",
        path=path,
        chars=len(text),
        sha256=sha256_text(text),
        detail="new file",
    )


def _apply_append(root: Path, path: str, text: str) -> AppliedEdit:
    target = safe_join(root, path)
    if not target.is_file():
        raise CampaignError(
            "append edit targets a missing file", details={"path": path, "root": root.as_posix()}
        )
    existing = target.read_text(encoding="utf-8", errors="surrogateescape")
    separator = "" if existing.endswith("\n") or not existing else "\n"
    updated = existing + separator + text
    target.write_text(updated, encoding="utf-8", newline="\n")
    return AppliedEdit(
        op="append",
        path=path,
        chars=len(text),
        sha256=sha256_text(text),
        detail=f"appended after {len(existing)} character(s)",
    )


def _apply_insert_before(root: Path, path: str, text: str, anchor: str | None) -> AppliedEdit:
    target = safe_join(root, path)
    if not target.is_file():
        raise CampaignError(
            "insert_before edit targets a missing file",
            details={"path": path, "root": root.as_posix()},
        )
    if not anchor:
        raise CampaignError("insert_before edit requires an anchor", details={"path": path})
    existing = target.read_text(encoding="utf-8", errors="surrogateescape")
    index = existing.find(anchor)
    if index < 0:
        raise CampaignError(
            "insert_before anchor was not found; refusing to produce a no-op variant",
            details={"path": path, "anchor": anchor[:80]},
        )
    updated = existing[:index] + text + existing[index:]
    target.write_text(updated, encoding="utf-8", newline="\n")
    return AppliedEdit(
        op="insert_before",
        path=path,
        chars=len(text),
        sha256=sha256_text(text),
        detail=f"inserted at offset {index}",
    )


def build_variant(
    *,
    source_dir: Path,
    spec: VariantSpecConfig,
    destination: Path,
    answer_tokens: list[str] | None = None,
) -> VariantBuild:
    """Copy the clean snapshot and apply this variant's edits to the copy."""
    source_dir = Path(source_dir)
    destination = Path(destination)
    if not source_dir.is_dir():
        raise CampaignError(
            "clean snapshot is missing; download the task first",
            details={"source": source_dir.as_posix()},
        )
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source_dir, destination)
    base_digest = tree_digest(destination)

    applied: list[AppliedEdit] = []
    touched: list[str] = []
    for edit in spec.edits:
        if edit.op == "create":
            result = _apply_create(destination, edit.path, edit.text)
        elif edit.op == "append":
            result = _apply_append(destination, edit.path, edit.text)
        elif edit.op == "insert_before":
            result = _apply_insert_before(destination, edit.path, edit.text, edit.find)
        else:  # pragma: no cover - guarded by the config literal
            raise CampaignError("unsupported edit operation", details={"op": edit.op})
        applied.append(result)
        touched.append(edit.path)

    tokens = list(answer_tokens or []) + list(spec.forbidden_tokens)
    for edit in spec.edits:
        # Scan the injected bytes, not the complete destination file.  A clean
        # repository may already contain a public CWE/CVE reference; rejecting
        # that pre-existing text would make a target-file comment impossible
        # even though the payload itself carries no answer token.
        assert_variant_is_answer_free(
            edit.text, tokens, where=f"{spec.variant_id}:{edit.path}"
        )

    return VariantBuild(
        variant_id=spec.variant_id,
        kind=spec.kind,
        payload_id=spec.payload_id,
        method_id=spec.method_id,
        carrier=spec.carrier,
        goal=spec.goal,
        knowledge=spec.knowledge,
        base_tree_sha256=base_digest,
        tree_sha256=tree_digest(destination),
        edits=applied,
        files_touched=sorted(set(touched)),
        forbidden_hits=[],
    )


def default_variants() -> list[VariantSpecConfig]:
    """The minimum campaign: one clean baseline, no treatment.

    Injected variants are declared in configuration so the candidate set is frozen
    before any run; nothing here selects a payload after seeing a result.
    """
    return [VariantSpecConfig(variant_id="C", kind="clean", goal="none")]


__all__ = [
    "AppliedEdit",
    "VARIANT_SCHEMA_VERSION",
    "VariantBuild",
    "build_variant",
    "default_variants",
]
