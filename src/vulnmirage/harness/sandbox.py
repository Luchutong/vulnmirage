"""Process control for one audit run.

The campaign runs the agent as a child process in its own session, redirects
stdout/stderr to files inside the archived run directory, and enforces a wall-clock
limit by killing the whole process tree (an interrupted audit must not leave a
child holding the workspace open).

Environment construction is *not* here: :mod:`vulnmirage.isolation.network` owns it,
because the egress policy and its probe belong to the exposure boundary.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path


def kill_process_tree(proc: subprocess.Popen[bytes]) -> None:
    """Terminate ``proc`` and its children; used on timeout and on cancellation."""
    if proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                timeout=30,
                check=False,
                shell=False,
            )
        except Exception:  # noqa: BLE001 - best effort, fall back to kill()
            proc.kill()
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:  # noqa: BLE001
            proc.kill()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()


def run_agent_process(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int,
    stdout_path: Path,
    stderr_path: Path,
) -> tuple[int | None, bool, str, float]:
    """Run ``argv`` with a hard timeout.

    Returns ``(exit_code, timed_out, error, duration_seconds)``.  ``exit_code`` is
    ``None`` only when the process could not be started; that is reported as an
    execution error, never as a model failure.
    """
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    creationflags = 0
    start_new_session = False
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        start_new_session = True
    started = time.monotonic()
    timed_out = False
    with stdout_path.open("wb") as out_handle, stderr_path.open("wb") as err_handle:
        try:
            proc = subprocess.Popen(
                argv,
                cwd=str(cwd),
                env=env,
                stdout=out_handle,
                stderr=err_handle,
                stdin=subprocess.DEVNULL,
                shell=False,
                creationflags=creationflags,
                start_new_session=start_new_session,
            )
        except OSError as exc:
            err_handle.write(f"failed to start agent: {exc}\n".encode())
            return None, False, f"failed to start agent: {exc}", time.monotonic() - started
        try:
            proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_process_tree(proc)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        if proc.poll() is None:
            kill_process_tree(proc)
    return proc.returncode, timed_out, "", time.monotonic() - started


__all__ = ["kill_process_tree", "run_agent_process"]
