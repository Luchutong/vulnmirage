"""Run sandbox: isolated repo copies, environment allowlist and process control."""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from ..errors import HarnessError
from ..paths import safe_join

_BASE_ENV_KEYS = [
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


def copy_repository(source: Path, destination: Path) -> Path:
    source = Path(source)
    destination = Path(destination)
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".pytest_cache"),
    )
    return destination


def snapshot_tree(root: Path) -> dict[str, str]:
    root = Path(root)
    entries: dict[str, str] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        entries[relative.as_posix()] = digest.hexdigest()
    return entries


def changed_since(before: dict[str, str], after: dict[str, str]) -> list[str]:
    changed = set()
    for path, digest in after.items():
        if before.get(path) != digest:
            changed.add(path)
    for path in before:
        if path not in after:
            changed.add(path)
    return sorted(changed)


def build_environment(
    allowlist: list[str],
    *,
    network_enabled: bool,
    credential_allowlist: list[str] | None = None,
) -> tuple[dict[str, str], list[str]]:
    """Build the child environment.

    ``credential_allowlist`` names are read from the parent environment by
    *name* and copied into the child environment so a declared credential is
    actually usable by the agent (P0-2).  Values never appear in notes, argv or
    any serialised record; only the names are returned via the notes.
    """
    env = {key: os.environ[key] for key in _BASE_ENV_KEYS if key in os.environ}
    notes: list[str] = []
    for key in allowlist:
        if key in os.environ:
            env[key] = os.environ[key]
    credential_names = [str(item).strip() for item in (credential_allowlist or []) if str(item).strip()]
    forwarded: list[str] = []
    for key in credential_names:
        if key in env:
            continue
        value = os.environ.get(key)
        if value:
            env[key] = value
            forwarded.append(key)
    if forwarded:
        notes.append(
            "credential variables forwarded by name: " + ", ".join(sorted(forwarded))
        )
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    if not network_enabled:
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env[key] = "http://127.0.0.1:9"
        env["NO_PROXY"] = env["no_proxy"] = ""
        notes.append(
            "network disabled via proxy environment variables (best-effort; not an OS firewall)"
        )
    else:
        notes.append("network explicitly enabled; recorded in run manifest")
    return env, notes


def kill_process_tree(proc: subprocess.Popen[bytes]) -> None:
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


def run_agent_process(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int,
    stdout_path: Path,
    stderr_path: Path,
) -> tuple[int | None, bool, str, float]:
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
            err_handle.write(f"failed to start agent: {exc}\n".encode("utf-8"))
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


@dataclass
class SandboxPaths:
    run_dir: Path
    repo_dir: Path
    task_path: Path
    output_path: Path
    trace_path: Path
    stdout_path: Path
    stderr_path: Path
    scratch_dir: Path
    final_raw_path: Path
    raw_events_path: Path
    normalized_events_path: Path
    tool_calls_path: Path
    file_access_path: Path
    process_events_path: Path
    meta_path: Path
    findings_path: Path
    matches_path: Path
    trajectory_path: Path
    verification_path: Path
    metrics_path: Path


def prepare_sandbox(
    *,
    source_repo: Path,
    instance_task_path: Path,
    run_dir: Path,
) -> SandboxPaths:
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    repo_dir = run_dir / "repo"
    copy_repository(source_repo, repo_dir)
    task_path = run_dir / "task.md"
    shutil.copy2(instance_task_path, task_path)
    scratch = run_dir / "scratch"
    scratch.mkdir(exist_ok=True)
    return SandboxPaths(
        run_dir=run_dir,
        repo_dir=repo_dir,
        task_path=task_path,
        output_path=run_dir / "findings_raw.txt",
        trace_path=run_dir / "trace.jsonl",
        stdout_path=run_dir / "stdout.log",
        stderr_path=run_dir / "stderr.log",
        scratch_dir=scratch,
        final_raw_path=run_dir / "final_raw.txt",
        raw_events_path=run_dir / "events.raw.jsonl",
        normalized_events_path=run_dir / "events.normalized.jsonl",
        tool_calls_path=run_dir / "tool_calls.jsonl",
        file_access_path=run_dir / "file_access.jsonl",
        process_events_path=run_dir / "process_events.jsonl",
        meta_path=run_dir / "meta.json",
        findings_path=run_dir / "findings.json",
        matches_path=run_dir / "matches.json",
        trajectory_path=run_dir / "trajectory_enriched.jsonl",
        verification_path=run_dir / "verification_assessments.json",
        metrics_path=run_dir / "metrics.json",
    )
