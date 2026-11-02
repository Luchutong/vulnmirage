"""Deterministic output repair: extraction only, never an LLM rewrite."""

from __future__ import annotations

import difflib
import json
from pathlib import Path

from ..errors import OutputParseError
from ..hashing import atomic_write_json, atomic_write_text, sha256_text
from .parser import parse_agent_output


def repair_output_file(*, raw_path: Path, output_path: Path, repo_root: Path | None = None) -> dict:
    raw_path = Path(raw_path)
    output_path = Path(output_path)
    if not raw_path.is_file():
        raise OutputParseError("raw output file does not exist", details={"path": str(raw_path)})
    raw = raw_path.read_text(encoding="utf-8", errors="replace")
    parsed = parse_agent_output(raw, repo_root=repo_root, source_path=raw_path)
    repaired = json.dumps(parsed.envelope.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"
    atomic_write_text(output_path, repaired)
    diff_path = output_path.with_suffix(output_path.suffix + ".diff")
    diff = "".join(
        difflib.unified_diff(
            raw.splitlines(keepends=True),
            repaired.splitlines(keepends=True),
            fromfile=str(raw_path),
            tofile=str(output_path),
        )
    )
    atomic_write_text(diff_path, diff)
    return {
        "ok": True,
        "raw": str(raw_path),
        "output": str(output_path),
        "diff": str(diff_path),
        "extraction": parsed.extraction,
        "raw_sha256": sha256_text(raw),
        "output_sha256": sha256_text(repaired),
        "finding_count": len(parsed.findings),
    }
