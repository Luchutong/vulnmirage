"""Shell-free command execution with timeouts, log files and tree cleanup."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from ..config import CommandSpec
from ..models import ValidatorCommand
from ..paths import safe_join

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclass
class CommandOutcome:
    name: str
    argv: list[str]
    cwd: str
    repo_root: str
    exit_code: int | None
    expected_exit_codes: list[int]
    timed_out: bool
    duration_seconds: float
    stdout_path: str
    stderr_path: str
    stdout_text: str
    stderr_text: str

    @property
    def passed(self) -> bool:
        return not self.timed_out and self.exit_code in self.expected_exit_codes


def _unique_name(name: str, used: set[str]) -> str:
    base = _SAFE_NAME_RE.sub("-", name).strip("-") or "command"
    candidate = base
    counter = 2
    while candidate in used:
        candidate = f"{base}-{counter}"
        counter += 1
    used.add(candidate)
    return candidate


def _base_env(allowlist: list[str] | None = None, extra: dict[str, str] | None = None) -> dict[str, str]:
    keys = [
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
        "LANG",
        "LC_ALL",
        "SYSTEMDRIVE",
        "APPDATA",
        "LOCALAPPDATA",
    ]
    if allowlist:
        keys.extend(allowlist)
    env = {key: os.environ[key] for key in keys if key in os.environ}
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    if extra:
        env.update(extra)
    return env


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
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
        except Exception:
            proc.kill()
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            proc.kill()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def normalize_command_output(text: str, repo_root: Path) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = normalized.replace(str(repo_root), "<REPO>")
    normalized = normalized.replace(str(repo_root).replace("\\", "/"), "<REPO>")
    return re.sub(r"\s+", " ", normalized).strip()


def run_validation_command(
    spec: ValidatorCommand | CommandSpec,
    *,
    repo_root: Path,
    log_dir: Path,
    name: str | None = None,
    network_allowed: bool = False,
    timeout_override: int | None = None,
    used_names: set[str] | None = None,
) -> CommandOutcome:
    repo_root = Path(repo_root).resolve()
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    used = used_names if used_names is not None else set()
    label = _unique_name(name or getattr(spec, "name", "command"), used)
    cwd = repo_root if spec.cwd in (".", "") else safe_join(repo_root, spec.cwd)
    if not cwd.is_dir():
        raise FileNotFoundError(f"command cwd does not exist: {cwd}")
    argv = list(spec.argv)
    if argv and argv[0] in {"python", "python3"}:
        argv[0] = sys.executable
    timeout = timeout_override or spec.timeout_seconds
    stdout_path = log_dir / f"{label}.stdout.log"
    stderr_path = log_dir / f"{label}.stderr.log"
    env = _base_env(spec.env_allowlist)
    if not network_allowed:
        # Best-effort process-level network denial.  This is not an OS sandbox;
        # it blocks HTTP clients that honour proxy variables and is recorded in
        # the validation report.
        env["HTTP_PROXY"] = env["http_proxy"] = "http://127.0.0.1:9"
        env["HTTPS_PROXY"] = env["https_proxy"] = "http://127.0.0.1:9"
        env["ALL_PROXY"] = env["all_proxy"] = "http://127.0.0.1:9"
        env["NO_PROXY"] = env["no_proxy"] = ""
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
            err_handle.write(f"failed to start command: {exc}\n".encode("utf-8"))
            duration = time.monotonic() - started
            return CommandOutcome(
                name=label,
                argv=argv,
                cwd=str(cwd),
                repo_root=str(repo_root),
                exit_code=None,
                expected_exit_codes=list(spec.expected_exit_codes),
                timed_out=False,
                duration_seconds=duration,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                stdout_text="",
                stderr_text=f"failed to start command: {exc}",
            )
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree(proc)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        if proc.poll() is None:
            _kill_tree(proc)
    duration = time.monotonic() - started
    return CommandOutcome(
        name=label,
        argv=argv,
        cwd=str(cwd),
        repo_root=str(repo_root),
        exit_code=proc.returncode,
        expected_exit_codes=list(spec.expected_exit_codes),
        timed_out=timed_out,
        duration_seconds=duration,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        stdout_text=_read(stdout_path),
        stderr_text=_read(stderr_path),
    )


def dedupe_commands(
    commands: list[ValidatorCommand], extra: list[CommandSpec] | None = None
) -> list[ValidatorCommand]:
    output: list[ValidatorCommand] = []
    seen: set[tuple[str, ...]] = set()
    for command in commands:
        key = (command.cwd, *command.argv)
        if key in seen:
            continue
        seen.add(key)
        output.append(command)
    for spec in extra or []:
        key = (spec.cwd, *spec.argv)
        if key in seen:
            continue
        seen.add(key)
        output.append(
            ValidatorCommand(
                name=spec.name,
                argv=list(spec.argv),
                cwd=spec.cwd,
                timeout_seconds=spec.timeout_seconds,
                expected_exit_codes=list(spec.expected_exit_codes),
                env_allowlist=list(spec.env_allowlist),
            )
        )
    return output
