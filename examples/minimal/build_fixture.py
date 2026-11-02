#!/usr/bin/env python3
"""Build the deterministic local VulnMirage fixture repository.

Usage:
    python examples/minimal/build_fixture.py --output workspace/fixture
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.fixture_repo import create_fixture_repo  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="workspace/fixture")
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    fixture = create_fixture_repo(output)
    print(
        json.dumps(
            {
                "ok": True,
                "repo": str(fixture.path),
                "repo_url": fixture.repo_url,
                "vulnerable_commit": fixture.vulnerable_commit,
                "fixed_commit": fixture.fixed_commit,
                "reports": str(fixture.reports_path),
                "entries": str(fixture.entries_path),
                "ingest_index": str(output / "ingest" / "index.json"),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
