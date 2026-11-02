"""Deterministic application of structured edit operations.

Guarantees:

* repository-relative path normalisation and escape/symlink rejection;
* allowlist by path **and** carrier, with an explicit new-file switch;
* anchor uniqueness, stale-hash detection, duplicate/conflicting operations;
* file / changed-line / added-character budgets checked before writing;
* all-or-nothing application: the candidate is simulated in memory first, the
  original bytes are backed up, and any write failure restores every file;
* deterministic unified diff, per-operation record and patch hash.
"""

from __future__ import annotations

import difflib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..code_semantics import (
    SemanticStatus,
    compare_semantics,
    is_documentation,
    language_for,
    normalize_text,
    read_text,
    syntax_valid,
)
from ..errors import GenerationError
from ..hashing import sha256_text
from ..models.edits import (
    AppliedOperation,
    EditApplication,
    EditBudget,
    EditOperationType,
    EditPolicy,
    FileEditResult,
    PatchOperation,
)
from ..paths import is_safe_relpath, normalize_relpath, safe_join


def content_sha256(text: str) -> str:
    """Hash of normalised content (stable across CRLF/LF)."""
    return sha256_text(normalize_text(text))


_CARRIER_ALIASES = {
    "markdown": "markdown",
    "comment": "code_comment",
    "code_comment": "code_comment",
    "string": "string_literal",
    "string_literal": "string_literal",
    "source_identifier": "source_identifier",
    "configuration": "configuration",
    "test": "test",
    "example_code": "example_code",
}


def normalize_carrier(value: str | None) -> str:
    text = str(value or "").strip().lower()
    return _CARRIER_ALIASES.get(text, text)


def _comment_style(path: str) -> tuple[str, bool]:
    language = language_for(path)
    if language in {"python", "ruby", "shell"}:
        return "#", False
    if language == "sql":
        return "--", False
    if language is not None:
        return "//", False
    suffix = Path(path).suffix.lower()
    if suffix in {".md", ".html", ".htm", ".xml", ".adoc"}:
        return "<!--", True
    return "#", False


def _looks_like_comment(line: str, prefix: str) -> bool:
    stripped = line.lstrip()
    if prefix == "<!--":
        return stripped.startswith("<!--")
    if prefix == "#":
        return stripped == "#" or stripped.startswith("# ")
    return stripped.startswith(prefix)


def comment_block(text: str, path: str) -> str:
    prefix, block_style = _comment_style(path)
    body = normalize_text(text).strip("\n")
    if block_style:
        return f"{prefix}\n{body}\n-->\n"
    rendered: list[str] = []
    for line in body.split("\n"):
        if not line.strip():
            rendered.append(prefix)
        elif _looks_like_comment(line, prefix):
            rendered.append(line)
        else:
            rendered.append(f"{prefix} {line}")
    return "\n".join(rendered) + "\n"


def _code_insertion_line(lines: list[str], index: int) -> int:
    """Never insert before a shebang or a PEP 263 encoding declaration."""
    if index > 0:
        return index
    if lines and lines[0].startswith("#!"):
        index = 1
        if len(lines) > 1 and "coding" in lines[1] and lines[1].lstrip().startswith("#"):
            index = 2
    return index


def _split_lines(text: str) -> list[str]:
    normalized = normalize_text(text)
    return normalized.split("\n")


def _count_occurrences(haystack: str, needle: str) -> int:
    if not needle:
        return 0
    count = 0
    start = 0
    while True:
        found = haystack.find(needle, start)
        if found < 0:
            return count
        count += 1
        start = found + len(needle)


def _resolve_path(repo_root: Path, relative: str) -> Path:
    if not is_safe_relpath(relative):
        raise GenerationError(
            "edit path is not a safe repository-relative path",
            details={"path": relative},
        )
    root = Path(repo_root).resolve()
    target = safe_join(root, relative)
    # Reject symlinks anywhere in the path (escape via link).
    current = root
    for part in Path(normalize_relpath(relative)).parts:
        current = current / part
        if current.is_symlink():
            raise GenerationError(
                "edit path traverses a symbolic link", details={"path": relative}
            )
    return target


@dataclass
class _SimulatedFile:
    path: str
    mode: str
    original: str | None
    content: str
    operations: list[tuple[PatchOperation, AppliedOperation]]


def _check_policy(operation: PatchOperation, policy: EditPolicy, exists: bool) -> None:
    if operation.path not in set(policy.allowed_paths):
        raise GenerationError(
            "edit is outside the authorised paths",
            details={"path": operation.path, "allowed": policy.allowed_paths},
        )
    if operation.path in set(policy.protected_paths):
        raise GenerationError("edit targets a protected path", details={"path": operation.path})
    if policy.allowed_carriers:
        carrier = normalize_carrier(operation.carrier)
        if carrier not in {normalize_carrier(item) for item in policy.allowed_carriers}:
            raise GenerationError(
                "carrier is not authorised for this edit",
                details={"carrier": carrier, "allowed": policy.allowed_carriers},
            )
    if not exists and not policy.allow_new_files:
        raise GenerationError("new files are not authorised", details={"path": operation.path})
    if operation.op == EditOperationType.CREATE_FILE and exists:
        raise GenerationError(
            "create_file targets an existing file", details={"path": operation.path}
        )
    if operation.op != EditOperationType.CREATE_FILE and not exists:
        raise GenerationError(
            f"{operation.op.value} targets a missing file", details={"path": operation.path}
        )


def _apply_one(
    operation: PatchOperation,
    *,
    original: str | None,
    content: str,
) -> tuple[str, AppliedOperation]:
    path = operation.path
    if operation.op == EditOperationType.CREATE_FILE:
        new_content = normalize_text(operation.new_text or "")
        lines = _split_lines(new_content)
        applied = AppliedOperation(
            operation_id=operation.operation_id,
            op=operation.op,
            path=path,
            write_mode="create",
            start_line=1,
            end_line=max(1, len(lines)),
            added_lines=len([line for line in lines if line]) or 1,
            added_chars=len(operation.new_text or ""),
            fragment_sha256=sha256_text(operation.new_text or ""),
        )
        return new_content, applied

    assert original is not None
    base_lines = _split_lines(original)
    if operation.op == EditOperationType.REPLACE_FILE:
        expected = operation.expected_old_sha256
        if expected and content_sha256(original) != expected:
            raise GenerationError(
                "replace_file baseline hash does not match the current file",
                details={"path": path},
            )
        new_content = normalize_text(operation.new_text or "")
        return new_content, AppliedOperation(
            operation_id=operation.operation_id,
            op=operation.op,
            path=path,
            write_mode="replace",
            start_line=1,
            end_line=max(1, len(_split_lines(new_content))),
            added_lines=len(_split_lines(new_content)),
            added_chars=len(new_content),
            fragment_sha256=sha256_text(new_content),
        )

    if operation.op == EditOperationType.REPLACE_BLOCK:
        anchor = operation.anchor or ""
        if _count_occurrences(original, anchor) != 1:
            raise GenerationError(
                "replace_block anchor is missing or not unique",
                details={"path": path, "anchor_sha256": sha256_text(anchor)},
            )
        expected = operation.expected_old_sha256
        if expected and content_sha256(original) != expected:
            raise GenerationError(
                "replace_block baseline hash does not match the current file",
                details={"path": path},
            )
        fragment = normalize_text(operation.new_text or "")
        new_content = original.replace(anchor, fragment, 1)
        start_line = original[: original.find(anchor)].count("\n") + 1
        added_lines = len(_split_lines(fragment))
        return new_content, AppliedOperation(
            operation_id=operation.operation_id,
            op=operation.op,
            path=path,
            write_mode="replace",
            start_line=start_line,
            end_line=start_line + max(0, added_lines - 1),
            added_lines=added_lines,
            added_chars=len(fragment),
            fragment_sha256=sha256_text(fragment),
        )

    if operation.op == EditOperationType.APPEND_BLOCK:
        fragment = normalize_text(operation.new_text or "").strip("\n")
        if not fragment.strip():
            raise GenerationError("append_block fragment is empty", details={"path": path})
        if is_documentation(path):
            block = fragment + "\n"
        else:
            # Appending prose to source code needs a comment marker.
            block = comment_block(fragment, path)
        if original and not original.endswith("\n"):
            new_content = original + "\n\n" + block
        else:
            new_content = original + ("\n" if original else "") + block
        start_line = max(1, len(base_lines))
        return new_content, AppliedOperation(
            operation_id=operation.operation_id,
            op=operation.op,
            path=path,
            write_mode="replace",
            start_line=start_line,
            end_line=start_line + max(0, len(_split_lines(block)) - 1),
            added_lines=len([line for line in _split_lines(block) if line]),
            added_chars=len(block),
            fragment_sha256=sha256_text(block),
        )

    if operation.op == EditOperationType.INSERT_COMMENT:
        anchor = operation.anchor or ""
        if _count_occurrences(original, anchor) != 1:
            raise GenerationError(
                "insert_comment anchor is missing or not unique",
                details={"path": path, "anchor_sha256": sha256_text(anchor)},
            )
        anchor_offset = original.find(anchor)
        anchor_line = original[:anchor_offset].count("\n")
        block = comment_block(operation.new_text or "", path)
        insert_at = _code_insertion_line(base_lines, anchor_line)
        inserted = _split_lines(block.rstrip("\n")) + [""]
        new_lines = base_lines[:insert_at] + inserted + base_lines[insert_at:]
        new_content = "\n".join(new_lines)
        return new_content, AppliedOperation(
            operation_id=operation.operation_id,
            op=operation.op,
            path=path,
            write_mode="replace",
            start_line=insert_at + 1,
            end_line=insert_at + max(1, len(inserted)),
            added_lines=len([line for line in inserted if line]),
            added_chars=len(block),
            fragment_sha256=sha256_text(block),
        )

    raise GenerationError("unsupported edit operation", details={"op": operation.op.value})


def _unified_diff(before: dict[str, str | None], after: dict[str, str]) -> str:
    pieces: list[str] = []
    for path in sorted(after):
        old = before.get(path)
        old_lines = _split_lines(old) if old is not None else []
        new_lines = _split_lines(after[path])
        from_file = f"a/{path}" if old is not None else "/dev/null"
        to_file = f"b/{path}"
        pieces.extend(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=from_file,
                tofile=to_file,
                lineterm="",
            )
        )
    text = "\n".join(pieces)
    return text + "\n" if text and not text.endswith("\n") else text


def _changed_line_count(before: str | None, after: str) -> int:
    old_lines = _split_lines(before) if before is not None else []
    diff = difflib.unified_diff(old_lines, _split_lines(after), lineterm="")
    return sum(
        1
        for line in diff
        if (line.startswith("+") or line.startswith("-"))
        and not line.startswith("+++")
        and not line.startswith("---")
    )


def apply_operations(
    repo_root: Path,
    operations: Iterable[PatchOperation],
    *,
    policy: EditPolicy,
    budget: EditBudget | None = None,
    dry_run: bool = False,
) -> EditApplication:
    """Validate and (unless ``dry_run``) atomically apply the operation list."""
    budget = budget or EditBudget()
    repo_root = Path(repo_root)
    operations = list(operations)
    if not operations:
        raise GenerationError("an edit application needs at least one operation")
    paths = [item.path for item in operations]
    if len(paths) != len(set(paths)):
        raise GenerationError(
            "conflicting edits: more than one operation targets the same path",
            details={"paths": sorted(paths)},
        )
    if len(operations) > budget.max_files:
        raise GenerationError(
            "edit budget exceeded: too many files",
            details={"max_files": budget.max_files, "requested": len(operations)},
        )

    originals: dict[str, str | None] = {}
    simulated: dict[str, _SimulatedFile] = {}
    applied: list[AppliedOperation] = []
    added_chars_total = 0
    for operation in operations:
        target = _resolve_path(repo_root, operation.path)
        exists = target.is_file()
        if operation.path not in originals:
            originals[operation.path] = read_text(target) if exists else None
        original = originals[operation.path]
        _check_policy(operation, policy, exists)
        new_content, record = _apply_one(operation, original=original, content=original or "")
        added_chars_total += record.added_chars
        if added_chars_total > budget.max_added_chars:
            raise GenerationError(
                "edit budget exceeded: too many added characters",
                details={"max_added_chars": budget.max_added_chars, "requested": added_chars_total},
            )
        if original is not None and not policy.allow_executable_changes:
            verdict = compare_semantics(operation.path, original, new_content)
            if verdict.status == SemanticStatus.CHANGED:
                raise GenerationError(
                    "edit changes executable semantics",
                    details={"path": operation.path, "reason": verdict.reason},
                )
            if (
                verdict.status == SemanticStatus.UNKNOWN
                and not is_documentation(operation.path)
                and language_for(operation.path) is not None
            ):
                raise GenerationError(
                    "executable semantics are undecidable; refusing to apply",
                    details={"path": operation.path, "reason": verdict.reason},
                )
        if language_for(operation.path) is not None:
            valid, error = syntax_valid(operation.path, new_content)
            if not valid:
                raise GenerationError(
                    "edited file is not syntactically valid",
                    details={"path": operation.path, "error": error},
                )
        applied.append(record)
        simulated[operation.path] = _SimulatedFile(
            path=operation.path,
            mode=record.write_mode,
            original=original,
            content=new_content,
            operations=[(operation, record)],
        )

    changed_total = sum(
        _changed_line_count(item.original, item.content) for item in simulated.values()
    )
    if changed_total > budget.max_changed_lines:
        raise GenerationError(
            "edit budget exceeded: too many changed lines",
            details={"max_changed_lines": budget.max_changed_lines, "requested": changed_total},
        )

    before = {path: originals[path] for path in simulated}
    after = {path: item.content for path, item in simulated.items()}
    diff = _unified_diff(before, after)
    patch_sha = sha256_text(diff)
    application_id = f"EDIT-{sha256_text('|'.join(sorted(paths)) + patch_sha)[:20].upper()}"

    if dry_run:
        return EditApplication(
            application_id=application_id,
            status="accepted",
            operations=operations,
            applied=applied,
            files=[
                FileEditResult(
                    path=path,
                    mode=item.mode,
                    original_sha256=(
                        content_sha256(item.original) if item.original is not None else None
                    ),
                    new_sha256=content_sha256(item.content),
                    changed_lines=_changed_line_count(item.original, item.content),
                    added_chars=sum(record.added_chars for _, record in item.operations),
                )
                for path, item in sorted(simulated.items())
            ],
            diff=diff,
            patch_sha256=patch_sha,
            budget=budget,
            changed_lines_total=changed_total,
            added_chars_total=added_chars_total,
        )

    backups: dict[Path, str | None] = {}
    created: list[Path] = []
    try:
        for path in sorted(simulated):
            target = _resolve_path(repo_root, path)
            backups[target] = read_text(target) if target.is_file() else None
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                created.append(target)
            target.write_text(simulated[path].content, encoding="utf-8")
    except Exception:
        for target, content in backups.items():
            try:
                if content is None:
                    if target.exists():
                        target.unlink()
                else:
                    target.write_text(content, encoding="utf-8")
            except OSError:
                pass
        raise

    return EditApplication(
        application_id=application_id,
        status="accepted",
        operations=operations,
        applied=applied,
        files=[
            FileEditResult(
                path=path,
                mode=item.mode,
                original_sha256=(
                    content_sha256(item.original) if item.original is not None else None
                ),
                new_sha256=content_sha256(item.content),
                changed_lines=_changed_line_count(item.original, item.content),
                added_chars=sum(record.added_chars for _, record in item.operations),
            )
            for path, item in sorted(simulated.items())
        ],
        diff=diff,
        patch_sha256=patch_sha,
        budget=budget,
        changed_lines_total=changed_total,
        added_chars_total=added_chars_total,
    )


def operations_from_change_plan(plan) -> list[PatchOperation]:
    """Best-effort conversion of a template ``ChangePlan`` into operations.

    The conversion is verified by :func:`verify_template_equivalence`; it never
    replaces the template application path, it only records how the rendered
    change maps onto the unified protocol.
    """
    operations: list[PatchOperation] = []
    for index, planned in enumerate(plan.files):
        operation_id = f"OP-{index + 1}"
        if planned.mode == "create":
            operations.append(
                PatchOperation(
                    operation_id=operation_id,
                    op=EditOperationType.CREATE_FILE,
                    path=planned.path,
                    new_text=planned.content,
                    carrier=planned.carrier,
                )
            )
            continue
        original = planned.original_content or ""
        operation = _derive_replace_operation(
            index, planned, original, planned.content, operation_id
        )
        operations.append(operation)
    return operations


def _derive_replace_operation(
    index: int, planned, original: str, content: str, operation_id: str
) -> PatchOperation:
    # Appended block: the new content starts with the original.
    normalized_original = original.rstrip("\n")
    if content.startswith(normalized_original) and len(content) > len(normalized_original):
        fragment = content[len(normalized_original) :].strip("\n")
        if fragment.strip():
            return PatchOperation(
                operation_id=operation_id,
                op=EditOperationType.APPEND_BLOCK,
                path=planned.path,
                new_text=fragment,
                carrier=planned.carrier,
                metadata={"derived_from": "template_change_plan"},
            )
    # Top-of-file comment insertion.
    if planned.carrier in {"comment", "code_comment"}:
        original_lines = _split_lines(original)
        new_lines = _split_lines(content)
        insert_at = _code_insertion_line(original_lines, 0)
        suffix = original_lines[insert_at:]
        suffix_matches = bool(suffix) and new_lines[-len(suffix) :] == suffix
        if suffix_matches:
            prefix_len = len(new_lines) - len(suffix)
            fragment = "\n".join(new_lines[:prefix_len]).strip("\n")
            anchor_candidates = [line for line in original_lines if line.strip()]
            if fragment and anchor_candidates:
                return PatchOperation(
                    operation_id=operation_id,
                    op=EditOperationType.INSERT_COMMENT,
                    path=planned.path,
                    new_text=fragment,
                    anchor=anchor_candidates[0],
                    carrier=planned.carrier,
                    metadata={"derived_from": "template_change_plan"},
                )
    return PatchOperation(
        operation_id=operation_id,
        op=EditOperationType.REPLACE_FILE,
        path=planned.path,
        new_text=content,
        expected_old_sha256=content_sha256(original),
        carrier=planned.carrier,
        metadata={"derived_from": "template_change_plan", "fallback": "full_file"},
    )


def verify_template_equivalence(
    repo_root: Path,
    operations: list[PatchOperation],
    expected: dict[str, str],
) -> list[str]:
    """Check that applying the derived operations reproduces the rendered files."""
    try:
        application = apply_operations(
            repo_root,
            operations,
            policy=EditPolicy(
                allowed_paths=sorted(expected),
                allow_new_files=True,
                allow_executable_changes=True,
            ),
            budget=EditBudget(max_files=max(1, len(expected))),
            dry_run=True,
        )
    except GenerationError as exc:
        return [exc.message]
    problems = []
    for path, content in expected.items():
        simulated = next(
            (item for item in application.files if item.path == path), None
        )
        if simulated is None:
            problems.append(f"derived operations do not touch {path}")
    return problems


def copy_tree(source: Path, destination: Path) -> None:
    """Copy a candidate repository tree (used by tests and dry-run previews)."""
    shutil.copytree(source, destination, dirs_exist_ok=True, symlinks=False)
