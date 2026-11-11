"""Capture a real OpenCode JSONL trace against a deterministic local model stub.

No external model or network service is used. OpenCode still performs its normal
agent/tool loop; only the OpenAI-compatible inference endpoint is replaced with a
localhost SSE server. Dynamic identifiers are normalized before the fixture is
committed so the regression is reproducible and contains no host paths.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from vulnmirage.hashing import sha256_text

FINAL_ANSWER = json.dumps(
    {
        "schema_version": "1.0",
        "report_markdown": "Fixture audit completed.",
        "findings": [],
        "audit_summary": {
            "files_reviewed": ["fixture.txt"],
            "limitations": [],
            "overall_confidence": 1.0,
        },
    },
    separators=(",", ":"),
)


def _sse(handler: BaseHTTPRequestHandler, chunks: list[dict[str, Any]]) -> None:
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-cache")
    handler.end_headers()
    for chunk in chunks:
        handler.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
    handler.wfile.write(b"data: [DONE]\n\n")
    handler.wfile.flush()


def _chunk(delta: dict[str, Any], finish_reason: str | None = None) -> dict[str, Any]:
    return {
        "id": "chatcmpl-fixture",
        "object": "chat.completion.chunk",
        "created": 1_700_000_000,
        "model": "fixture-model",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
    }


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        messages = payload.get("messages") or []
        has_tool_result = any(
            isinstance(item, dict) and item.get("role") == "tool" for item in messages
        )
        if has_tool_result:
            _sse(
                self,
                [
                    _chunk({"role": "assistant", "content": FINAL_ANSWER}),
                    _chunk({}, "stop"),
                ],
            )
            return
        read_properties: dict[str, Any] = {}
        for tool in payload.get("tools") or []:
            if not isinstance(tool, dict):
                continue
            function = tool.get("function")
            if not isinstance(function, dict) or function.get("name") != "read":
                continue
            parameters = function.get("parameters")
            if isinstance(parameters, dict) and isinstance(
                parameters.get("properties"), dict
            ):
                read_properties = parameters["properties"]
                break
        path_key = "path" if "path" in read_properties else "filePath"
        arguments = json.dumps({path_key: "fixture.txt"}, separators=(",", ":"))
        _sse(
            self,
            [
                _chunk(
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_fixture_read",
                                "type": "function",
                                "function": {"name": "read", "arguments": arguments},
                            }
                        ],
                    }
                ),
                _chunk({}, "tool_calls"),
            ],
        )


def _sanitize_string(value: str, *, repo: Path, temp_root: Path) -> str:
    sanitized = value
    for path, replacement in ((repo, "<REPO>"), (temp_root, "<TEMP>")):
        variants = {
            str(path),
            path.as_posix(),
            str(path).removeprefix(f"{path.drive}\\"),
        }
        for variant in sorted(variants, key=len, reverse=True):
            if variant:
                sanitized = sanitized.replace(variant, replacement)
    # OpenCode 1.17 on Windows may omit the drive prefix in a display title.
    sanitized = re.sub(
        r"(?i)(?:[^<>\r\n]*[\\/])?vm-opencode-fixture-[^\\/]+[\\/]repo",
        "<REPO>",
        sanitized,
    )
    return sanitized


def _normalize(value: Any, *, repo: Path, temp_root: Path) -> Any:
    if isinstance(value, list):
        return [_normalize(item, repo=repo, temp_root=temp_root) for item in value]
    if not isinstance(value, dict):
        if isinstance(value, str):
            return _sanitize_string(value, repo=repo, temp_root=temp_root)
        return value
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key in {"timestamp", "createdAt"}:
            result[key] = 1_700_000_000_000
        elif key in {"sessionID", "sessionId"}:
            result[key] = "ses_fixture"
        elif key in {"messageID", "messageId"}:
            result[key] = "msg_fixture"
        elif key == "id" and isinstance(item, str) and item.startswith("prt_"):
            result[key] = "prt_fixture"
        elif key in {"partID", "partId"}:
            result[key] = "prt_fixture"
        elif key in {"callID", "callId"}:
            result[key] = "call_fixture_read"
        elif key == "time" and isinstance(item, dict):
            result[key] = {
                time_key: 1_700_000_000_000 + index
                for index, time_key in enumerate(item)
            }
        else:
            result[key] = _normalize(item, repo=repo, temp_root=temp_root)
    return result


def capture(output_root: Path, *, opencode: str) -> dict[str, Any]:
    version_run = subprocess.run(
        [opencode, "--version"], capture_output=True, text=True, timeout=10, check=True
    )
    version_output = version_run.stdout.strip() or version_run.stderr.strip()
    version_match = re.search(r"(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)", version_output)
    if version_match is None:
        raise RuntimeError(f"could not parse OpenCode version from: {version_output!r}")
    version = version_match.group(1)
    major_version = int(version.split(".", maxsplit=1)[0])
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="vm-opencode-fixture-") as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "fixture.txt").write_text("fixture evidence\n", encoding="utf-8")
            config = root / "opencode.json"
            config.write_text(
                json.dumps(
                    {
                        "$schema": "https://opencode.ai/config.json",
                        "autoupdate": False,
                        "share": "disabled",
                        "agent": {
                            "fixture-agent": {
                                "description": "Deterministic trace fixture agent",
                                "mode": "primary",
                                "temperature": 0,
                                "prompt": "Read fixture.txt, then return the requested JSON.",
                                "permission": {
                                    "read": "allow",
                                    "edit": "deny",
                                    "write": "deny",
                                    "bash": "deny",
                                    "webfetch": "deny",
                                    "external_directory": "deny",
                                },
                            }
                        },
                        "provider": {
                            "fixture": {
                                "npm": "@ai-sdk/openai-compatible",
                                "name": "Local fixture provider",
                                "options": {
                                    "baseURL": f"http://127.0.0.1:{server.server_port}/v1",
                                    "apiKey": "fixture-key",
                                },
                                "models": {"fixture-model": {"name": "Fixture model"}},
                            }
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            env = {
                key: value
                for key, value in os.environ.items()
                if key.upper()
                in {
                    "PATH",
                    "PATHEXT",
                    "SYSTEMROOT",
                    "WINDIR",
                    "TEMP",
                    "TMP",
                    "USER",
                }
            }
            home = root / "home"
            home.mkdir()
            for name in ("config", "data", "cache", "state"):
                (root / f"xdg-{name}").mkdir()
            env.update(
                {
                    "HOME": str(home),
                    "XDG_CONFIG_HOME": str(root / "xdg-config"),
                    "XDG_DATA_HOME": str(root / "xdg-data"),
                    "XDG_CACHE_HOME": str(root / "xdg-cache"),
                    "XDG_STATE_HOME": str(root / "xdg-state"),
                }
            )
            env["OPENCODE_CONFIG"] = str(config)
            if major_version >= 2:
                command = [
                    opencode,
                    "--standalone",
                    "run",
                    "--model",
                    "fixture/fixture-model",
                    "--agent",
                    "fixture-agent",
                    "--format",
                    "json",
                    "--auto",
                    "--archived",
                    "Read fixture.txt and return the final JSON.",
                ]
            else:
                command = [
                    opencode,
                    "--pure",
                    "run",
                    "--model",
                    "fixture/fixture-model",
                    "--agent",
                    "fixture-agent",
                    "--format",
                    "json",
                    "--auto",
                    "--dir",
                    str(repo),
                    "Read fixture.txt and return the final JSON.",
                ]
            run = subprocess.run(
                command,
                cwd=repo,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if run.returncode != 0:
                raise RuntimeError(f"OpenCode fixture capture failed: {run.stderr[-2000:]}")
            events = []
            for line in run.stdout.splitlines():
                if not line.strip():
                    continue
                events.append(_normalize(json.loads(line), repo=repo, temp_root=root))
            event_types = [str(item.get("type")) for item in events]
            required = {"step_start", "tool_use", "text", "step_finish"}
            if not required.issubset(event_types):
                raise RuntimeError(f"incomplete OpenCode fixture: {event_types}")
            terminal_tools = [
                item
                for item in events
                if item.get("type") == "tool_use"
                and isinstance(item.get("part"), dict)
                and isinstance(item["part"].get("state"), dict)
                and item["part"]["state"].get("status") == "completed"
                and item["part"]["state"].get("output")
            ]
            if not terminal_tools:
                raise RuntimeError("OpenCode fixture contains no successful tool result")
            fixture_dir = output_root / version
            fixture_dir.mkdir(parents=True, exist_ok=True)
            text = "".join(json.dumps(item, sort_keys=True) + "\n" for item in events)
            # Bytes preserve LF on Windows so the frozen hash is cross-platform.
            (fixture_dir / "run-format-json.jsonl").write_bytes(text.encode("utf-8"))
            manifest = {
                "schema_version": "1.0",
                "framework": "opencode",
                "framework_version": version,
                "capture_kind": "real_cli_local_deterministic_stub",
                "external_model_calls": 0,
                "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "sanitized_dynamic_fields": True,
                "event_types": event_types,
                "source_sha256": sha256_text(text),
            }
            (fixture_dir / "fixture_manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            return manifest
    finally:
        server.shutdown()
        thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opencode", default="opencode")
    parser.add_argument(
        "--output-root", type=Path, default=Path("tests/fixtures/opencode")
    )
    args = parser.parse_args()
    print(json.dumps(capture(args.output_root, opencode=args.opencode), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
