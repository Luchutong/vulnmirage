"""Regression tests for comment lexing and fail-closed semantic equality."""

from __future__ import annotations

from pathlib import Path

from vulnmirage.code_semantics import (
    SemanticStatus,
    compare_semantics,
    strip_comment_lines,
)


def test_c_pointer_dereference_change_is_detected() -> None:
    before = "int f(int *p) {\n    *p = 1;\n    return 0;\n}\n"
    after = "int f(int *p) {\n    *p = 2;\n    return 0;\n}\n"
    verdict = compare_semantics("src/pointer.c", before, after)
    assert verdict.status == SemanticStatus.CHANGED
    assert verdict.preserved is False


def test_c_block_comment_change_is_comment_only() -> None:
    before = "/*\n * old explanation\n */\nint x = 1;\n"
    after = "/*\n * new explanation, reworded\n * with a second line\n */\nint x = 1;\n"
    verdict = compare_semantics("src/comment.c", before, after)
    assert verdict.status == SemanticStatus.COMMENT_ONLY
    assert verdict.preserved is True


def test_cpp_block_comment_inner_star_is_not_code() -> None:
    before = "/*\n * note one\n */\nint f() { return 1; }\n"
    after = "/*\n * note two\n */\nint f() { return 1; }\n"
    verdict = compare_semantics("src/comment.cpp", before, after)
    assert verdict.status == SemanticStatus.COMMENT_ONLY


def test_javascript_multiplication_change_is_detected() -> None:
    before = "function total(a, b) { return a * b; }\n"
    after = "function total(a, b) { return a + b; }\n"
    verdict = compare_semantics("web/total.js", before, after)
    assert verdict.status == SemanticStatus.CHANGED


def test_python_comment_change_preserves_ast() -> None:
    before = "# old comment\n\ndef f():\n    return 1\n"
    after = "# a completely different comment\n\ndef f():\n    return 1\n"
    verdict = compare_semantics("app/module.py", before, after)
    assert verdict.status == SemanticStatus.EQUAL


def test_python_statement_change_fails() -> None:
    before = "def f():\n    return 1\n"
    after = "def f():\n    return 2\n"
    verdict = compare_semantics("app/module.py", before, after)
    assert verdict.status == SemanticStatus.CHANGED


def test_unknown_language_is_fail_closed(tmp_path: Path) -> None:
    # A language without a verified lexer must never be declared preserved.
    verdict = compare_semantics("src/module.hs", "main = putStrLn \"a\"\n", "main = putStrLn \"b\"\n")
    assert verdict.status == SemanticStatus.UNKNOWN
    assert verdict.preserved is False


def test_strip_comment_lines_keeps_pointer_code() -> None:
    stripped = strip_comment_lines("// header\n*p = 1;\n/* tail */\n", "c")
    assert "*p = 1;" in stripped
