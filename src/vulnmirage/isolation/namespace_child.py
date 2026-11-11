"""Child-side relay and evidence collector for a rootless Linux net namespace."""

from __future__ import annotations

import argparse
import json
import os
import selectors
import socket
import socketserver
import subprocess
import sys
import threading
from pathlib import Path


class _RelayServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = False


class _RelayHandler(socketserver.BaseRequestHandler):
    unix_socket_path = ""

    def handle(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
            upstream.connect(self.unix_socket_path)
            selector = selectors.DefaultSelector()
            selector.register(self.request, selectors.EVENT_READ, upstream)
            selector.register(upstream, selectors.EVENT_READ, self.request)
            while True:
                events = selector.select(timeout=30)
                if not events:
                    return
                for key, _ in events:
                    data = key.fileobj.recv(64 * 1024)
                    if not data:
                        return
                    key.data.sendall(data)


def _netns_id() -> str:
    return os.readlink("/proc/self/ns/net")


def _interfaces() -> list[str]:
    return sorted(path.name for path in Path("/sys/class/net").iterdir())


def _default_routes() -> list[str]:
    routes: list[str] = []
    route_file = Path("/proc/net/route")
    if not route_file.is_file():
        return routes
    for line in route_file.read_text(encoding="utf-8").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "00000000":
            routes.append(fields[0])
    return sorted(routes)


def _external_connect_blocked() -> bool:
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=0.5):
            return False
    except OSError:
        return True


def _write_evidence(
    path: Path,
    *,
    parent_netns: str,
    relay_port: int,
    relay_reachable: bool,
) -> dict[str, object]:
    child_netns = _netns_id()
    interfaces = _interfaces()
    routes = _default_routes()
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "backend": "linux_user_network_namespace_unix_gateway",
        "parent_netns": parent_netns,
        "child_netns": child_netns,
        "network_namespace_distinct": child_netns != parent_netns,
        "interfaces": interfaces,
        "loopback_only": interfaces == ["lo"],
        "default_routes": routes,
        "external_connect_blocked": _external_connect_blocked(),
        "relay_port": relay_port,
        "relay_reachable": relay_reachable,
    }
    payload["enforcement_verified"] = all(
        (
            payload["network_namespace_distinct"],
            payload["loopback_only"],
            not routes,
            payload["external_connect_blocked"],
            relay_reachable,
        )
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unix-socket", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--parent-netns", required=True)
    parser.add_argument("--probe-only", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    _RelayHandler.unix_socket_path = args.unix_socket
    server = _RelayServer(("127.0.0.1", args.port), _RelayHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        try:
            with socket.create_connection(("127.0.0.1", args.port), timeout=2):
                relay_reachable = True
        except OSError:
            relay_reachable = False
        evidence = _write_evidence(
            args.evidence,
            parent_netns=args.parent_netns,
            relay_port=args.port,
            relay_reachable=relay_reachable,
        )
        if not evidence["enforcement_verified"]:
            return 125
        if args.probe_only:
            return 0
        command = list(args.command)
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            return 126
        return subprocess.run(command, check=False).returncode
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())

