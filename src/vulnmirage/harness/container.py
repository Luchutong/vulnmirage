"""Optional container execution backend (P1-4).

The subprocess backend is a **development mode**: the agent gets an isolated
repository copy and an environment allowlist, but nothing prevents it from
reading the host workspace (oracle, releases, other runs) with an absolute
path.  Formal experiments should use :class:`ContainerBackend`, which mounts
only:

* the audited repository, read-only;
* a per-run writable scratch directory;
* a per-run writable output directory.

The host project directory, oracle files, release metadata, other run
directories and the Docker socket are never mounted.  A writable working copy
for build/test steps is opt-in (:func:`writable_copy`), with contamination
detection performed by the harness.

If no container runtime is available the backend fails loudly; it never
silently falls back to the subprocess mode.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import HarnessError


def container_runtime(configured: str | None = None) -> str | None:
    candidates = [configured] if configured else ["docker", "podman"]
    for candidate in candidates:
        if candidate and shutil.which(candidate):
            return candidate
    return None


def container_available(configured: str | None = None) -> tuple[bool, str]:
    runtime = container_runtime(configured)
    if runtime is None:
        return False, "no container runtime (docker/podman) on PATH"
    try:
        proc = subprocess.run(
            [runtime, "info"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"container runtime check failed: {exc}"
    if proc.returncode != 0:
        return False, (proc.stderr or "container runtime is not running").strip()[-500:]
    return True, runtime


@dataclass(frozen=True)
class ContainerMount:
    source: Path
    target: str
    mode: str  # ro | rw


@dataclass
class ContainerBackend:
    runtime: str
    image: str
    network: str = "none"
    mounts: list[ContainerMount] = field(default_factory=list)
    env_names: list[str] = field(default_factory=list)
    #: Literal, non-secret values (HOME/XDG/OPENCODE_CONFIG inside the
    #: container).  Credential names must never be passed this way.
    env_values: dict[str, str] = field(default_factory=dict)
    read_only_root: bool = True
    #: Unique container name so a timed-out run can be force-removed (P1-1 #6).
    name: str | None = None
    agent_state_dir: Path | None = None
    agent_executable: str | None = None
    agent_version: str | None = None

    @property
    def enforcement(self) -> dict[str, object]:
        return {
            "enforcement": "container",
            "runtime": self.runtime,
            "image": self.image,
            "network": self.network,
            "network_separation": (
                "tools_and_model_both_blocked"
                if self.network == "none"
                else "best_effort_same_network_for_model_and_tools"
            ),
            "network_policy_note": (
                "container_network=none blocks tool egress and the model API; "
                "network separation between model access and repository tools is "
                "best_effort_same_network_for_model_and_tools for bridge"
            ),
            "mounts": [
                {"source": mount.source.as_posix(), "target": mount.target, "mode": mount.mode}
                for mount in self.mounts
            ],
            "host_project_mounted": False,
            "oracle_mounted": False,
            "docker_socket_mounted": False,
            "agent_state_mounted": bool(self.agent_state_dir),
            "open_code_config_path": (
                "/agent-state/opencode.json" if self.agent_state_dir else None
            ),
            "agent_executable": self.agent_executable,
            "agent_version": self.agent_version,
            "timeout_cleanup": "docker rm -f <run container> after every run",
        }

    def build_argv(self, container_argv: list[str], *, cwd: str = "/repo") -> list[str]:
        argv = [
            self.runtime,
            "run",
            "--rm",
        ]
        if self.name:
            argv.extend(["--name", self.name])
        argv.extend(
            [
                "--network",
                self.network,
                "--workdir",
                cwd,
                "--security-opt",
                "no-new-privileges",
            ]
        )
        if self.read_only_root:
            argv.extend(["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m"])
        for mount in self.mounts:
            argv.extend(
                ["-v", f"{mount.source.resolve()}:{mount.target}:{mount.mode}"]
            )
        for name in self.env_names:
            # Name-only: the host value is inherited by the runtime and never
            # appears in the process arguments (P0-2 #4).
            argv.extend(["-e", name])
        for name, value in sorted(self.env_values.items()):
            if name in self.env_names:
                continue
            argv.extend(["-e", f"{name}={value}"])
        argv.append(self.image)
        argv.extend(container_argv)
        return argv

    def cleanup(self) -> dict[str, object]:
        """Force-remove the run container; safe to call more than once."""
        if not self.name:
            return {"attempted": False}
        try:
            proc = subprocess.run(
                [self.runtime, "rm", "-f", self.name],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except Exception as exc:  # noqa: BLE001
            return {"attempted": True, "container": self.name, "error": str(exc)}
        return {
            "attempted": True,
            "container": self.name,
            "returncode": proc.returncode,
            "stderr": (proc.stderr or "").strip()[-300:],
        }


def container_agent_version(
    runtime: str | None,
    image: str,
    executable: str,
    *,
    timeout_seconds: int = 60,
) -> dict[str, object]:
    """Ask the image for the agent version (doctor / P1-1 #4)."""
    resolved = container_runtime(runtime)
    if resolved is None:
        return {"status": "unavailable", "reason": "no container runtime on PATH"}
    if not image:
        return {"status": "unavailable", "reason": "container_image is not configured"}
    try:
        proc = subprocess.run(
            [resolved, "run", "--rm", "--entrypoint", executable, image, "--version"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return {"status": "unavailable", "reason": str(exc), "runtime": resolved}
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return {
        "status": "ok" if proc.returncode == 0 and output else "warn",
        "runtime": resolved,
        "image": image,
        "executable": executable,
        "returncode": proc.returncode,
        "version": output[-300:] or None,
    }


def build_backend(
    *,
    configured_runtime: str | None,
    image: str,
    network: str,
    repo_dir: Path,
    scratch_dir: Path,
    output_dir: Path,
    env_names: list[str],
    credential_names: list[str] | None = None,
    agent_state_dir: Path | None = None,
    env_values: dict[str, str] | None = None,
    name: str | None = None,
    agent_executable: str | None = None,
    agent_version: str | None = None,
) -> ContainerBackend:
    available, detail = container_available(configured_runtime)
    if not available:
        raise HarnessError(
            "container execution backend is required but unavailable",
            details={
                "failure_type": "observation_setup_failure",
                "reason": detail,
                "runtime": configured_runtime,
            },
        )
    if not image:
        raise HarnessError("container_image must be configured")
    required_dirs = [repo_dir, scratch_dir, output_dir]
    if agent_state_dir is not None:
        required_dirs.append(agent_state_dir)
    if not all(Path(item).is_dir() for item in required_dirs):
        raise HarnessError("container mount directories must exist")
    credentials = {str(item).strip() for item in (credential_names or []) if str(item).strip()}
    literals = {
        str(key): str(value)
        for key, value in (env_values or {}).items()
        if str(key) not in credentials
    }
    mounts = [
        ContainerMount(Path(repo_dir), "/repo", "ro"),
        ContainerMount(Path(scratch_dir), "/scratch", "rw"),
        ContainerMount(Path(output_dir), "/output", "rw"),
    ]
    if agent_state_dir is not None:
        mounts.append(ContainerMount(Path(agent_state_dir), "/agent-state", "rw"))
    return ContainerBackend(
        runtime=detail,
        image=image,
        network=network,
        mounts=mounts,
        env_names=list(dict.fromkeys(env_names)),
        env_values=literals,
        name=name,
        agent_state_dir=Path(agent_state_dir) if agent_state_dir is not None else None,
        agent_executable=agent_executable,
        agent_version=agent_version,
    )



def writable_copy(repo_dir: Path, scratch_dir: Path) -> tuple[Path, dict[str, object]]:
    """Opt-in writable working copy for build/test steps.

    The copy lives under the run scratch directory; the read-only mount is
    retained so contamination of the original is impossible.
    """
    target = scratch_dir / "repo_workcopy"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(repo_dir, target)
    return target, {
        "strategy": "scratch_copy",
        "source": repo_dir.as_posix(),
        "target": target.as_posix(),
        "original_read_only": True,
        "contamination_check": "snapshot original repository tree before/after",
    }
