"""Target remapping after an edit shifts lines (design §14.4).

Every private target is recorded against the **clean** tree.  An ``insert_before``
edit moves the lines below it, so scoring an un-remapped target would compare a
finding to a coordinate the variant does not have -- and report a missed
vulnerability that was actually found.

Resolution order is symbol, then anchor text, then the recorded line delta, and
the basis used is written down.  When none of them resolves uniquely the variant is
marked ``unique=False`` and must not enter a formal repetition; guessing is worse
than refusing.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..errors import CampaignError
from ..hashing import canonical_json, sha256_text, utc_now_iso
from ..verifier.targets import PrivateTarget

REMAP_VERSION = "1.0"

RemapBasis = Literal["unchanged", "symbol", "anchor", "line_delta", "unmapped"]


class RemapLocation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str
    start_line: int
    end_line: int


class RemapRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str
    basis: RemapBasis
    old: RemapLocation
    new: RemapLocation | None = None
    delta: int = 0
    reason: str = ""


class TargetRemap(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = REMAP_VERSION
    task_id: str
    variant_id: str
    clean_tree_sha256: str
    variant_tree_sha256: str = ""
    records: list[RemapRecord] = Field(default_factory=list)
    applied_edits: list[dict[str, object]] = Field(default_factory=list)
    unique: bool = False
    remap_sha256: str = ""
    created_at: str = Field(default_factory=utc_now_iso)

    def digest(self) -> str:
        payload = self.model_dump(mode="json", exclude={"created_at", "remap_sha256"})
        return sha256_text(canonical_json(payload))

    def finalized(self) -> "TargetRemap":
        return self.model_copy(update={"remap_sha256": self.digest()})

    def as_targets(self, targets: list[PrivateTarget]) -> list[PrivateTarget]:
        """Project remapped coordinates onto the private target objects."""
        by_id = {item.target_id: item for item in self.records}
        projected: list[PrivateTarget] = []
        for target in targets:
            record = by_id.get(target.target_id)
            if record is None or record.new is None:
                projected.append(target)
                continue
            projected.append(
                target.model_copy(
                    update={
                        "file": record.new.file,
                        "line_start": record.new.start_line,
                        "line_end": record.new.end_line,
                    }
                )
            )
        return projected


def _line_of_offset(text: str, offset: int) -> int:
    return text[:offset].count("\n") + 1


def _edit_line(edit: dict[str, object], clean_root) -> int | None:
    """Best-effort 1-based line at which an edit was applied."""
    line = edit.get("line")
    if isinstance(line, int):
        return line
    offset = edit.get("offset")
    path = str(edit.get("path") or "")
    if isinstance(offset, int) and clean_root is not None and path:
        candidate = clean_root / path
        if candidate.is_file():
            return _line_of_offset(candidate.read_text(encoding="utf-8", errors="replace"), offset)
    return None


def _inserted_lines(edit: dict[str, object]) -> int:
    text = str(edit.get("text") or "")
    return max(1, text.count("\n") + (0 if text.endswith("\n") else 1))


def _locate_anchor(
    clean_lines: list[str], variant_lines: list[str], start: int, end: int
) -> int | None:
    window = clean_lines[start - 1 : end]
    if not window:
        return None
    hits = [
        index + 1
        for index in range(0, max(0, len(variant_lines) - len(window) + 1))
        if variant_lines[index : index + len(window)] == window
    ]
    return hits[0] if len(hits) == 1 else None


def _locate_symbol(clean_lines: list[str], variant_lines: list[str], function: str) -> int | None:
    """Return the line delta implied by a unique function declaration.

    The symbol gives a *delta*, not a position: a target whose span starts inside
    the function must keep its offset from the declaration, otherwise a payload
    inserted before the function would move the target to the declaration line.
    """
    clean_hits = [
        number
        for number, line in enumerate(clean_lines, start=1)
        if function in line and "(" in line
    ]
    if len(clean_hits) != 1:
        return None
    variant_hits = [
        number
        for number, line in enumerate(variant_lines, start=1)
        if function in line and "(" in line
    ]
    if len(variant_hits) != 1:
        return None
    return variant_hits[0] - clean_hits[0]


def remap_targets(
    *,
    task_id: str,
    variant_id: str,
    targets: list[PrivateTarget],
    clean_root,
    variant_root,
    applied_edits: list[dict[str, object]],
    clean_tree_sha256: str,
    variant_tree_sha256: str,
) -> TargetRemap:
    from pathlib import Path

    clean_root = Path(clean_root)
    variant_root = Path(variant_root)
    touched: dict[str, list[dict[str, object]]] = {}
    for edit in applied_edits:
        touched.setdefault(str(edit.get("path") or ""), []).append(edit)

    records: list[RemapRecord] = []
    for target in targets:
        old = RemapLocation(
            file=target.file,
            start_line=int(target.line_start or 0),
            end_line=int(target.line_end or target.line_start or 0),
        )
        edits = touched.get(target.file, [])
        if not edits:
            records.append(
                RemapRecord(target_id=target.target_id, basis="unchanged", old=old, new=old)
            )
            continue

        variant_file = variant_root / target.file
        clean_file = clean_root / target.file
        if not variant_file.is_file() or not clean_file.is_file():
            records.append(
                RemapRecord(
                    target_id=target.target_id,
                    basis="unmapped",
                    old=old,
                    reason="the target file is missing from the clean or variant tree",
                )
            )
            continue

        clean_lines = clean_file.read_text(encoding="utf-8", errors="replace").splitlines()
        variant_lines = variant_file.read_text(encoding="utf-8", errors="replace").splitlines()
        span = max(1, old.end_line - old.start_line + 1)

        start: int | None = None
        basis: RemapBasis = "unmapped"
        reason = ""
        if target.function:
            delta = _locate_symbol(clean_lines, variant_lines, target.function)
            if delta is not None:
                start, basis = old.start_line + delta, "symbol"
                window = clean_lines[old.start_line - 1 : old.end_line]
                if window and variant_lines[start - 1 : start - 1 + len(window)] != window:
                    reason = "symbol delta applied; anchor window differs (payload inside the span)"
        if start is None:
            located = _locate_anchor(clean_lines, variant_lines, old.start_line, old.end_line)
            if located is not None:
                start, basis = located, "anchor"
        if start is None:
            delta = 0
            ambiguous = False
            for edit in edits:
                line = _edit_line(edit, clean_root)
                if line is None:
                    ambiguous = True
                    continue
                if line <= old.start_line:
                    delta += _inserted_lines(edit)
            if ambiguous:
                records.append(
                    RemapRecord(
                        target_id=target.target_id,
                        basis="unmapped",
                        old=old,
                        reason=(
                            "line-delta fallback is ambiguous because at least one "
                            "edit has no recorded line or offset"
                        ),
                    )
                )
                continue
            start = old.start_line + delta
            basis = "line_delta"
            reason = "fell back to the recorded line delta"
        new = RemapLocation(file=target.file, start_line=start, end_line=start + span - 1)
        records.append(
            RemapRecord(
                target_id=target.target_id,
                basis=basis,
                old=old,
                new=new,
                delta=new.start_line - old.start_line,
                reason=reason,
            )
        )

    remap = TargetRemap(
        task_id=task_id,
        variant_id=variant_id,
        clean_tree_sha256=clean_tree_sha256,
        variant_tree_sha256=variant_tree_sha256,
        records=records,
        applied_edits=list(applied_edits),
        unique=all(item.basis != "unmapped" for item in records),
    )
    return remap.finalized()


__all__ = [
    "REMAP_VERSION",
    "RemapLocation",
    "RemapRecord",
    "TargetRemap",
    "remap_targets",
]
