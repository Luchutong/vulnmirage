from __future__ import annotations

import json

from vulnmirage.hashing import (
    atomic_write_json,
    canonical_json,
    code_sha256,
    derive_seed,
    normalize_code,
    safe_slug,
    sha256_file,
    sha256_text,
    stable_digest,
    stable_id,
)


def test_stable_id_is_deterministic_and_not_builtin_hash() -> None:
    first = stable_id("VMO", "dataset", "report-1")
    second = stable_id("VMO", "dataset", "report-1")
    different = stable_id("VMO", "dataset", "report-2")
    assert first == second
    assert first != different
    assert first.startswith("VMO-")
    assert len(first.split("-")[-1]) == 12


def test_stable_id_sanitizes_prefix() -> None:
    identifier = stable_id("VM/../X", "a")
    assert ".." not in identifier
    assert "/" not in identifier


def test_derive_seed_stable_and_in_range() -> None:
    a = derive_seed(20261020, "oracle", "M2")
    b = derive_seed(20261020, "oracle", "M2")
    c = derive_seed(20261020, "oracle", "M1")
    assert a == b != c
    assert 0 <= a < 2**63


def test_normalize_code_and_hash() -> None:
    left = "  def f():\r\n\treturn 1  \r\n\r\n"
    right = "  def f():\n\treturn 1\n"
    assert normalize_code(left) == right
    assert code_sha256(left) == sha256_text(right)
    assert normalize_code("") == ""


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})
    assert canonical_json({"x": "中"}) == '{"x":"中"}'


def test_sha256_file(tmp_path) -> None:
    path = tmp_path / "data.bin"
    path.write_bytes(b"vulnmirage")
    assert sha256_file(path) == sha256_text("vulnmirage")


def test_atomic_write_json(tmp_path) -> None:
    target = tmp_path / "nested" / "manifest.json"
    atomic_write_json(target, {"b": 2, "a": 1})
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1, "b": 2}
    assert not list(target.parent.glob("*.tmp"))


def test_stable_digest_handles_models() -> None:
    from tests.support import make_finding

    digest = stable_digest("finding", make_finding().model_dump(mode="json"))
    assert len(digest) == 64


def test_safe_slug() -> None:
    assert safe_slug("Hello World / ../x") == "hello-world-x"
    assert safe_slug("") == "item"
