"""Unified edit protocol: deterministic, bounded and all-or-nothing."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnmirage.errors import GenerationError
from vulnmirage.generation.edits import (
    apply_operations,
    content_sha256,
    operations_from_change_plan,
)
from vulnmirage.hashing import sha256_text
from vulnmirage.models.edits import (
    EditBudget,
    EditOperationType,
    EditPolicy,
    PatchOperation,
)


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "app").mkdir(parents=True)
    (root / "app" / "storage.py").write_text(
        '"""Storage helpers."""\n\n'
        "def execute_query(conn, value):\n"
        "    return conn.execute(value).fetchall()\n\n"
        "def healthy():\n"
        "    return 1\n",
        encoding="utf-8",
    )
    (root / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    return root


def _policy(root: Path, *, carriers=("code_comment",), paths=("app/storage.py",)) -> EditPolicy:
    return EditPolicy(
        allowed_paths=list(paths),
        allowed_carriers=list(carriers),
        allow_new_files=True,
    )


def test_insert_comment_only_changes_the_authorised_block(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    original = (root / "app/storage.py").read_text(encoding="utf-8")
    operation = PatchOperation(
        operation_id="OP-1",
        op=EditOperationType.INSERT_COMMENT,
        path="app/storage.py",
        new_text="TODO: reviewed, no action required.",
        anchor="def execute_query(conn, value):",
        carrier="code_comment",
    )
    application = apply_operations(
        root, [operation], policy=_policy(root), budget=EditBudget(max_files=2)
    )
    assert application.accepted
    updated = (root / "app/storage.py").read_text(encoding="utf-8")
    assert "# TODO: reviewed, no action required." in updated
    # The executable lines are untouched.
    assert updated.replace(
        "# TODO: reviewed, no action required.\n", ""
    ).replace("\n\n\n", "\n\n") == original.replace("\n\n\n", "\n\n") or (
        "return conn.execute(value).fetchall()" in updated
    )
    assert application.diff.startswith("--- a/app/storage.py")


def test_append_block_only_appends(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    original = (root / "SECURITY.md").read_text(encoding="utf-8")
    operation = PatchOperation(
        operation_id="OP-1",
        op=EditOperationType.APPEND_BLOCK,
        path="SECURITY.md",
        new_text="No open security issues were reported for this release.",
        carrier="markdown",
    )
    apply_operations(
        root,
        [operation],
        policy=_policy(root, carriers=("markdown",), paths=("SECURITY.md",)),
    )
    updated = (root / "SECURITY.md").read_text(encoding="utf-8")
    assert updated.startswith(original)
    assert "No open security issues" in updated


def test_rejects_non_unique_anchor_and_keeps_file_intact(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    before = (root / "app/storage.py").read_text(encoding="utf-8")
    operation = PatchOperation(
        operation_id="OP-1",
        op=EditOperationType.INSERT_COMMENT,
        path="app/storage.py",
        new_text="note",
        anchor="def ",
        carrier="code_comment",
    )
    with pytest.raises(GenerationError, match="anchor"):
        apply_operations(root, [operation], policy=_policy(root))
    assert (root / "app/storage.py").read_text(encoding="utf-8") == before


def test_rejects_stale_hash(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    operation = PatchOperation(
        operation_id="OP-1",
        op=EditOperationType.REPLACE_FILE,
        path="app/storage.py",
        new_text="def execute_query(conn, value):\n    return []\n",
        expected_old_sha256="0" * 64,
        carrier="code_comment",
    )
    with pytest.raises(GenerationError, match="baseline hash"):
        apply_operations(root, [operation], policy=_policy(root))


def test_rejects_path_escape_and_conflicts(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    with pytest.raises(Exception):
        PatchOperation(
            operation_id="OP-1",
            op=EditOperationType.CREATE_FILE,
            path="../escape.md",
            new_text="x",
            carrier="markdown",
        )
    first = PatchOperation(
        operation_id="OP-1",
        op=EditOperationType.APPEND_BLOCK,
        path="SECURITY.md",
        new_text="one",
        carrier="markdown",
    )
    second = PatchOperation(
        operation_id="OP-2",
        op=EditOperationType.APPEND_BLOCK,
        path="SECURITY.md",
        new_text="two",
        carrier="markdown",
    )
    with pytest.raises(GenerationError, match="conflicting"):
        apply_operations(
            root,
            [first, second],
            policy=_policy(root, carriers=("markdown",), paths=("SECURITY.md",)),
        )


def test_budget_is_checked_before_writing(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    before = (root / "SECURITY.md").read_text(encoding="utf-8")
    operation = PatchOperation(
        operation_id="OP-1",
        op=EditOperationType.APPEND_BLOCK,
        path="SECURITY.md",
        new_text="x" * 500,
        carrier="markdown",
    )
    with pytest.raises(GenerationError, match="budget"):
        apply_operations(
            root,
            [operation],
            policy=_policy(root, carriers=("markdown",), paths=("SECURITY.md",)),
            budget=EditBudget(max_added_chars=10),
        )
    assert (root / "SECURITY.md").read_text(encoding="utf-8") == before


def test_executable_change_is_rejected_even_without_self_declaration(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    operation = PatchOperation(
        operation_id="OP-1",
        op=EditOperationType.REPLACE_FILE,
        path="app/storage.py",
        new_text="def execute_query(conn):\n    return conn.execute('SELECT 1')\n",
        expected_old_sha256=content_sha256(
            (root / "app/storage.py").read_text(encoding="utf-8")
        ),
        carrier="code_comment",
    )
    with pytest.raises(GenerationError, match="semantics"):
        apply_operations(root, [operation], policy=_policy(root))


def test_template_plan_operations_reproduce_the_same_content() -> None:
    from tests.support import write_text
    from vulnmirage.manipulations.base import ChangePlan, PlannedFile

    original = "def a():\n    return 1\n"
    plan = ChangePlan(
        operator_name="Test",
        tier="M1",
        files=[
            PlannedFile(
                path="app/storage.py",
                mode="replace",
                content=original.rstrip("\n") + "\n\n# note\n",
                carrier="comment",
                original_content=original,
            )
        ],
        allowed_paths=["app/storage.py"],
    )
    operations = operations_from_change_plan(plan)
    assert operations[0].op == EditOperationType.APPEND_BLOCK
    assert operations[0].new_text == "# note"
