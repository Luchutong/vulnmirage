from __future__ import annotations

import os

import pytest

from vulnmirage.errors import UnsafePathError
from vulnmirage.paths import (
    normalize_relpath,
    posix_relative,
    safe_join,
    ensure_within,
)


@pytest.mark.parametrize(
    "value",
    ["/etc/passwd", "../secret", "a/../../b", "C:\\Windows\\system.ini", "", ".", "/"],
)
def test_normalize_rejects_unsafe(value: str) -> None:
    with pytest.raises(UnsafePathError):
        normalize_relpath(value)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a/b.py", "a/b.py"),
        ("./a/b.py", "a/b.py"),
        ("a\\b.py", "a/b.py"),
        ("a//b.py", "a/b.py"),
        ("a/./b.py", "a/b.py"),
    ],
)
def test_normalize_accepts_relative(raw: str, expected: str) -> None:
    assert normalize_relpath(raw) == expected


def test_safe_join_stays_under_root(tmp_path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = safe_join(root, "src/main.py")
    assert target == root / "src" / "main.py"
    assert str(target).startswith(str(root))


def test_safe_join_rejects_dot_git(tmp_path) -> None:
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path, ".git/config")
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path, "sub/.git/HEAD")


def test_symlink_escape_is_rejected(tmp_path) -> None:
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "link"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")
    with pytest.raises(UnsafePathError):
        safe_join(root, "link/secret.txt")


def test_ensure_within(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "a" / "b.txt"
    inside.parent.mkdir()
    inside.write_text("x", encoding="utf-8")
    assert ensure_within(root, inside, must_exist=True) == inside
    with pytest.raises(UnsafePathError):
        ensure_within(root, tmp_path / "other.txt")


def test_posix_relative(tmp_path) -> None:
    root = tmp_path / "root"
    path = root / "a" / "b.py"
    path.parent.mkdir(parents=True)
    path.write_text("x", encoding="utf-8")
    assert posix_relative(path, root) == "a/b.py"
