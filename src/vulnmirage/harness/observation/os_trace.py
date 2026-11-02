"""Optional Linux strace observer and parser.

On Linux, the harness can prepend ``strace -f`` to the agent command and parse
the resulting trace.  On other platforms the observer is unavailable and the
run's observability grade is lowered; no fake OS events are generated.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...hashing import stable_id
from ...models import EventSource, EventType, RawEventEnvelope, UnifiedEvent
from .base import SourceResult, event_payload_hash, now_utc

_STRACE_CALL = re.compile(
    r"^(?P<pid>\d+)\s+(?P<call>openat|statx|readlink|execve)\((?P<args>.*)\)\s+=\s+(?P<ret>-?\d+)"
)
_STRACE_PATH = re.compile(r'"((?:[^"\\]|\\.)*)"')


@dataclass(frozen=True)
class TraceProbe:
    """Result of a short, side-effect-free tracing capability probe."""

    available: bool
    status: str
    exit_code: int | None = None
    executable: str | None = None
    reason: str | None = None
    stderr_excerpt: str | None = None
    cached: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "status": self.status,
            "exit_code": self.exit_code,
            "executable": self.executable,
            "reason": self.reason,
            "stderr_excerpt": self.stderr_excerpt,
            "cached": self.cached,
        }


_PROBE_CACHE: dict[tuple[str, str, str], TraceProbe] = {}
_PTRACE_DENIED_MARKERS = (
    "operation not permitted",
    "ptrace",
    "eperm",
    "seccomp",
    "permission denied",
)


def _is_linux(platform_name: str | None = None) -> bool:
    name = platform_name if platform_name is not None else os.name
    if name != "posix":
        return False
    try:
        return os.uname().sysname.lower().startswith("linux")
    except (AttributeError, OSError):
        return True


def probe_os_trace(
    mode: str,
    *,
    timeout_seconds: float = 5.0,
    platform_name: str | None = None,
    which=shutil.which,
    runner=None,
    cache: bool = True,
) -> TraceProbe:
    """Check whether tracing actually works, before launching the agent.

    Merely finding ``strace`` is not enough: containers frequently install
    strace while denying ``ptrace``, in which case the wrapped agent never
    starts.  The probe runs ``strace ... -- true`` (no repository, no model) and
    classifies the failure.  Results are cached per (platform, executable,
    timeout) for the lifetime of the process.
    """
    if mode == "off":
        return TraceProbe(False, "disabled", reason="os_trace=off")
    if not _is_linux(platform_name):
        return TraceProbe(
            False,
            "unsupported_platform",
            reason="OS trace requires Linux; observability grade capped at B",
        )
    executable = which("strace")
    if executable is None:
        return TraceProbe(
            False, "strace_missing", reason="strace executable not found"
        )
    key = (platform_name or os.name, str(executable), str(timeout_seconds))
    if cache and key in _PROBE_CACHE:
        cached = _PROBE_CACHE[key]
        return TraceProbe(
            cached.available,
            cached.status,
            cached.exit_code,
            cached.executable,
            cached.reason,
            cached.stderr_excerpt,
            cached=True,
        )
    if runner is None:
        runner = subprocess.run
    probe_output = Path(tempfile.mkstemp(prefix="vulnmirage-strace-probe-", suffix=".log")[1])
    try:
        argv = [
            str(executable),
            "-f",
            "-q",
            "-e",
            "trace=none",
            "-o",
            str(probe_output),
            "--",
            os.environ.get("VULNMIRAGE_TRACE_PROBE_COMMAND", "true"),
        ]
        try:
            proc = runner(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result = TraceProbe(
                False,
                "probe_timeout",
                executable=str(executable),
                reason=f"trace probe timed out after {timeout_seconds}s",
            )
        except OSError as exc:
            result = TraceProbe(
                False,
                "probe_error",
                executable=str(executable),
                reason=f"trace probe could not start: {exc}",
            )
        else:
            stderr = (proc.stderr or "").strip()
            if proc.returncode == 0:
                result = TraceProbe(True, "available", 0, str(executable))
            else:
                lowered = stderr.lower()
                status = (
                    "ptrace_denied"
                    if any(marker in lowered for marker in _PTRACE_DENIED_MARKERS)
                    else "probe_failed"
                )
                result = TraceProbe(
                    False,
                    status,
                    proc.returncode,
                    str(executable),
                    reason=stderr[-500:] or f"strace exited {proc.returncode}",
                    stderr_excerpt=stderr[-1000:] or None,
                )
    finally:
        try:
            probe_output.unlink()
        except OSError:
            pass
    if cache:
        _PROBE_CACHE[key] = result
    return result


def os_trace_available(mode: str) -> tuple[bool, list[str]]:
    """Compatibility wrapper around :func:`probe_os_trace`."""
    probe = probe_os_trace(mode)
    return probe.available, [probe.reason] if probe.reason else []


def wrap_with_strace(argv: list[str], output_path: Path) -> list[str]:
    return [
        "strace",
        "-f",
        "-e",
        "trace=openat,statx,readlink,execve",
        "-o",
        str(output_path),
        "--",
        *argv,
    ]


def parse_strace(
    path: Path,
    *,
    run_id: str,
    repo_root: Path,
    scratch_root: Path | None,
    started_monotonic_ns: int = 0,
) -> SourceResult:
    result = SourceResult(source=EventSource.OS.value)
    path = Path(path)
    if not path.is_file():
        return result
    index = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = _STRACE_CALL.match(line.strip())
            if not match:
                continue
            index += 1
            call = match.group("call")
            raw_path = None
            for candidate in _STRACE_PATH.findall(match.group("args")):
                candidate = candidate.replace("\\", "/")
                is_absolute = candidate.startswith("/") or bool(
                    re.match(r"^[A-Za-z]:/", candidate)
                )
                if (
                    is_absolute
                    and not candidate.startswith("/dev/")
                    and not candidate.startswith("/proc/")
                ):
                    raw_path = candidate
                    break
            if raw_path is None:
                continue
            relative = _relative(raw_path, repo_root, scratch_root)
            if relative is None:
                continue
            operation = "open" if call == "openat" else ("stat" if call == "statx" else "readlink")
            event_type = EventType.PROCESS_START if call == "execve" else EventType.FILE_ACCESS
            if event_type == EventType.PROCESS_START:
                operation = None
            payload = {
                "event_type": event_type.value,
                "path": relative,
                "operation": operation,
                "pid": int(match.group("pid")),
                "syscall": call,
                "return": int(match.group("ret")),
                "raw_line": line.strip(),
            }
            envelope = RawEventEnvelope(
                event_id=stable_id("EV-RAW", run_id, "os", index),
                run_id=run_id,
                source=EventSource.OS,
                timestamp_utc=now_utc(),
                monotonic_ns=started_monotonic_ns + index * 1_000_000,
                raw_payload_sha256=event_payload_hash(payload),
                raw_payload=payload,
            )
            event = UnifiedEvent(
                event_id=envelope.event_id,
                run_id=run_id,
                sequence=0,
                timestamp_utc=envelope.timestamp_utc,
                monotonic_ns=envelope.monotonic_ns,
                event_type=event_type,
                source=EventSource.OS,
                path=relative,
                operation=operation if operation else None,
                metadata={"pid": payload["pid"], "syscall": call, "raw_return": payload["return"]},
            )
            result.raw_events.append(envelope)
            result.events.append(event)
    return result


def _relative(value: str, repo_root: Path, scratch_root: Path | None) -> str | None:
    try:
        resolved = Path(value).resolve()
    except OSError:
        return None
    try:
        relative = resolved.relative_to(repo_root.resolve()).as_posix()
        # Directory-level access on the repository root is not a file access.
        return None if relative in {"", "."} else relative
    except ValueError:
        if scratch_root is not None:
            try:
                return f"scratch/{resolved.relative_to(scratch_root.resolve()).as_posix()}"
            except ValueError:
                return None
    return None
