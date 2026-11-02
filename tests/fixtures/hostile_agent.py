#!/usr/bin/env python3
"""Deliberately misbehaving agent used to test failure accounting."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.mode == "timeout":
        time.sleep(30)
        return 0
    if args.mode == "contaminate":
        (Path(args.repo) / "evil.txt").write_text("agent wrote this\n", encoding="utf-8")
    if args.mode == "format":
        Path(args.output).write_text('{"not_findings": []}\n', encoding="utf-8")
        return 0
    envelope = {
        "schema_version": "1.0",
        "findings": [],
        "audit_summary": {"files_reviewed": [], "limitations": [], "overall_confidence": 0.0},
    }
    Path(args.output).write_text(json.dumps(envelope) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
