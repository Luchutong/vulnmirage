"""``python -m vulnmirage.verifier`` -- score one frozen bundle in its own process.

The process boundary is the point of this entry point: the harness that ran the
agent does not hold the oracle, and this process does not hold the agent's
environment.  Nothing from the bundle is executed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..config import load_config
from ..errors import VulnMirageError
from .service import evaluate_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vulnmirage.verifier",
        description="Score a frozen run bundle against the private target set",
    )
    parser.add_argument("--private", required=True, help="evaluator private root (oracle)")
    parser.add_argument("--bundle", required=True, help="frozen bundle directory")
    parser.add_argument("--out", required=True, help="output directory for score artefacts")
    parser.add_argument("--config", default=None, help="optional application config YAML")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = None
    if args.config:
        config = load_config(Path(args.config)).config.verifier
    try:
        result = evaluate_bundle(
            private_root=Path(args.private),
            bundle_dir=Path(args.bundle),
            output_dir=Path(args.out),
            config=config,
            mode="separate_process",
        )
    except VulnMirageError as exc:
        print(json.dumps(exc.to_dict(), ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
