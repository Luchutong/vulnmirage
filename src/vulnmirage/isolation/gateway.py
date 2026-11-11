"""Allowlisted inference relay used by the Linux network-namespace runtime.

The agent namespace has no external interface. OpenCode sends HTTP to loopback;
``namespace_child`` relays that connection to this Unix socket, and this trusted
server forwards only to the provider base URLs frozen in ``opencode.json``.
"""

from __future__ import annotations

import http.client
import json
import os
import socketserver
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..errors import IsolationError

_HOP_HEADERS = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


@dataclass(frozen=True)
class ProviderRoute:
    provider: str
    upstream_base_url: str


def rewrite_opencode_for_gateway(
    source: Path,
    destination: Path,
    *,
    gateway_base_url: str,
    allowed_upstream_hosts: set[str],
) -> tuple[ProviderRoute, ...]:
    """Freeze a runtime config whose providers can reach only the local relay."""
    payload = json.loads(source.read_text(encoding="utf-8"))
    providers = payload.get("provider")
    if not isinstance(providers, dict) or not providers:
        raise IsolationError("OpenCode config declares no providers", details={})
    routes: list[ProviderRoute] = []
    for provider, raw in sorted(providers.items()):
        if not isinstance(raw, dict):
            raise IsolationError(
                "invalid OpenCode provider entry", details={"provider": provider}
            )
        options = raw.get("options")
        base_url = options.get("baseURL") if isinstance(options, dict) else None
        parsed = urlsplit(str(base_url or ""))
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not host or host not in allowed_upstream_hosts:
            raise IsolationError(
                "provider baseURL is not an allowlisted HTTPS inference endpoint",
                details={"provider": provider, "host": host, "scheme": parsed.scheme},
            )
        routes.append(ProviderRoute(str(provider), str(base_url).rstrip("/")))
        options["baseURL"] = f"{gateway_base_url.rstrip('/')}/{provider}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return tuple(routes)


if hasattr(socketserver, "UnixStreamServer"):

    class _UnixHTTPServer(  # type: ignore[misc]
        socketserver.ThreadingMixIn, socketserver.UnixStreamServer
    ):
        daemon_threads = True
        allow_reuse_address = False

else:

    class _UnixHTTPServer:  # pragma: no cover - instantiated only on Linux
        def __init__(self, *_: object, **__: object) -> None:
            raise OSError("Unix-domain inference gateway requires Linux")


class InferenceGateway:
    """Context-managed Unix-socket HTTP relay with a fixed provider route table."""

    def __init__(self, socket_path: Path, routes: tuple[ProviderRoute, ...]) -> None:
        self.socket_path = socket_path
        self.routes = {item.provider: item.upstream_base_url for item in routes}
        self._server: _UnixHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> InferenceGateway:
        from http.server import BaseHTTPRequestHandler

        gateway = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802
                self._forward()

            def do_POST(self) -> None:  # noqa: N802
                self._forward()

            def _forward(self) -> None:
                route, separator, suffix = self.path.lstrip("/").partition("/")
                upstream = gateway.routes.get(route)
                if not separator or upstream is None:
                    self.send_error(404, "unknown inference route")
                    return
                parsed = urlsplit(upstream)
                base_path = parsed.path.rstrip("/")
                target = f"{base_path}/{suffix}"
                if self.command == "GET" and self.headers.get("Content-Length"):
                    self.send_error(400, "GET request must not contain a body")
                    return
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else None
                headers = {
                    key: value
                    for key, value in self.headers.items()
                    if key.lower() not in _HOP_HEADERS
                }
                connection = http.client.HTTPSConnection(
                    parsed.hostname,
                    parsed.port or 443,
                    timeout=120,
                )
                try:
                    connection.request(self.command, target, body=body, headers=headers)
                    response = connection.getresponse()
                    self.send_response(response.status, response.reason)
                    for key, value in response.getheaders():
                        if key.lower() not in _HOP_HEADERS:
                            self.send_header(key, value)
                    self.send_header("Connection", "close")
                    self.end_headers()
                    while True:
                        chunk = response.read(64 * 1024)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                except (OSError, http.client.HTTPException) as exc:
                    if not self.wfile.closed:
                        self.send_error(502, f"inference upstream failed: {type(exc).__name__}")
                finally:
                    connection.close()

        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            self.socket_path.unlink()
        self._server = _UnixHTTPServer(str(self.socket_path), Handler)
        os.chmod(self.socket_path, 0o600)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self.socket_path.exists():
            self.socket_path.unlink()


__all__ = ["InferenceGateway", "ProviderRoute", "rewrite_opencode_for_gateway"]
