"""How one audit is executed, and how the answer is collected.

Two shapes are supported, and they differ only in where the answer comes from:

``argv``
    the command is given ``{repo}``, ``{output}`` and ``{task}`` and writes the final
    answer into ``{output}`` itself;
``stdout``
    the command prints; the harness captures stdout and extracts the last JSON
    object (or the last text part of a ``jsonl`` event stream, which is what OpenCode
    emits).

Both run through :func:`vulnmirage.harness.sandbox.run_agent_process`, so both get
the same process control, the same redirect-to-file behaviour and the same timeout
handling.  Neither interprets the answer: extraction only *locates* it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..errors import CampaignError
from ..harness.sandbox import run_agent_process

#: File names an ``argv`` executor may write the answer to, in priority order.
ANSWER_FILENAMES: tuple[str, ...] = ("final_raw.txt", "final_answer.txt", "answer.json")


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    exit_code: int | None = None
    duration_seconds: float | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    answer_path: str | None = None
    error: str | None = None


class AuditExecutor(Protocol):
    mode: str

    def run(
        self,
        *,
        repo: Path,
        output: Path,
        task_file: Path,
        env: dict[str, str],
        run_dir: Path,
        timeout_seconds: int,
    ) -> ExecutionResult: ...


def expand_argv(
    argv: list[str] | tuple[str, ...], *, repo: Path, output: Path, task: Path
) -> list[str]:
    """Substitute the placeholders an agent config is allowed to use."""
    values = {
        "repo": repo.as_posix(),
        "output": output.as_posix(),
        "task": task.as_posix(),
        "prompt": task.as_posix(),
    }
    expanded: list[str] = []
    for item in argv:
        try:
            expanded.append(item.format(**values))
        except KeyError as exc:
            raise CampaignError(
                "agent argv uses an unknown placeholder",
                details={"argument": item, "unknown": str(exc), "allowed": sorted(values)},
            ) from exc
    if not os_path_in(expanded, values["repo"]):
        raise CampaignError(
            "agent argv never references {repo}: the audit would not see the workspace",
            details={"argv": expanded},
        )
    return expanded


def os_path_in(argv: list[str], needle: str) -> bool:
    return any(needle in item for item in argv)


def _balanced_objects(text: str) -> list[str]:
    """Return top-level balanced ``{...}`` blocks, ignoring braces in strings."""
    blocks: list[str] = []
    depth = 0
    start: int | None = None
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                blocks.append(text[start : index + 1])
                start = None
    return blocks


def _looks_like_answer(text: str) -> bool:
    stripped = text.strip()
    if not stripped.startswith("{"):
        return False
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return False
    return isinstance(payload, dict) and "findings" in payload


def extract_final_answer(stdout_text: str, *, strategy: str = "jsonl_events") -> str | None:
    """Locate the agent's final answer inside captured stdout.

    Nothing is repaired or completed here: the returned text is either an exact
    block the agent printed, or ``None``.  A ``None`` answer becomes a recorded
    format failure, never an empty "no findings" result.
    """
    text = stdout_text or ""
    if not text.strip():
        return None
    if strategy == "tail":
        return text.strip()
    if strategy == "jsonl_events":
        parts: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            part = event.get("part")
            candidate = None
            if isinstance(part, dict):
                candidate = part.get("text")
            if candidate is None:
                candidate = event.get("text")
            if isinstance(candidate, str) and candidate.strip():
                parts.append(candidate.strip())
        for candidate in reversed(parts):
            if _looks_like_answer(candidate):
                return candidate
        for candidate in reversed(parts):
            for block in reversed(_balanced_objects(candidate)):
                if _looks_like_answer(block):
                    return block
        return parts[-1] if parts else None
    # json_last_object
    stripped = text.strip()
    if _looks_like_answer(stripped):
        return stripped
    for block in reversed(_balanced_objects(text)):
        if _looks_like_answer(block):
            return block
    return None


@dataclass(frozen=True)
class CommandExecutor:
    """The command writes the answer file itself (``{output}`` is writable)."""

    argv: tuple[str, ...]
    answer_filename: str = ANSWER_FILENAMES[0]
    mode: str = "argv"

    def run(
        self,
        *,
        repo: Path,
        output: Path,
        task_file: Path,
        env: dict[str, str],
        run_dir: Path,
        timeout_seconds: int,
    ) -> ExecutionResult:
        argv = expand_argv(self.argv, repo=repo, output=output, task=task_file)
        stdout_path = run_dir / "stdout.log"
        stderr_path = run_dir / "stderr.log"
        code, timed_out, error, duration = run_agent_process(
            argv,
            cwd=repo,
            env=env,
            timeout_seconds=timeout_seconds,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
        answer = output / self.answer_filename
        status = _status(code, timed_out, error)
        if status == "success" and not answer.is_file():
            status = "missing_answer"
        return ExecutionResult(
            status=status,
            exit_code=code,
            duration_seconds=duration,
            stdout_path=stdout_path.as_posix(),
            stderr_path=stderr_path.as_posix(),
            answer_path=answer.as_posix() if answer.is_file() else None,
            error=error or (None if answer.is_file() else "the command wrote no answer file"),
        )


@dataclass(frozen=True)
class StdoutExecutor:
    """The command prints; stdout is captured and the answer is extracted from it."""

    argv: tuple[str, ...]
    answer_extractor: str = "jsonl_events"
    mode: str = "stdout"

    def run(
        self,
        *,
        repo: Path,
        output: Path,
        task_file: Path,
        env: dict[str, str],
        run_dir: Path,
        timeout_seconds: int,
    ) -> ExecutionResult:
        argv = expand_argv(self.argv, repo=repo, output=output, task=task_file)
        stdout_path = run_dir / "stdout.log"
        stderr_path = run_dir / "stderr.log"
        code, timed_out, error, duration = run_agent_process(
            argv,
            cwd=repo,
            env=env,
            timeout_seconds=timeout_seconds,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
        status = _status(code, timed_out, error)
        answer_path = output / ANSWER_FILENAMES[0]
        if status == "success":
            captured = stdout_path.read_text(encoding="utf-8", errors="replace")
            extracted = extract_final_answer(captured, strategy=self.answer_extractor)
            if extracted is None:
                return ExecutionResult(
                    status="missing_answer",
                    exit_code=code,
                    duration_seconds=duration,
                    stdout_path=stdout_path.as_posix(),
                    stderr_path=stderr_path.as_posix(),
                    error="no final answer could be located in stdout",
                )
            output.mkdir(parents=True, exist_ok=True)
            answer_path.write_text(extracted + "\n", encoding="utf-8")
        return ExecutionResult(
            status=status,
            exit_code=code,
            duration_seconds=duration,
            stdout_path=stdout_path.as_posix(),
            stderr_path=stderr_path.as_posix(),
            answer_path=answer_path.as_posix() if answer_path.is_file() else None,
            error=error,
        )


@dataclass(frozen=True)
class NullExecutor:
    """No agent is executed: the workspace is prepared and attested only."""

    mode: str = "none"

    def run(self, **_: object) -> ExecutionResult:
        return ExecutionResult(status="not_run", error="no executor configured")


def _status(code: int | None, timed_out: bool, error: str) -> str:
    if error:
        return "error"
    if timed_out:
        return "timeout"
    if code != 0:
        return "failed"
    return "success"


def build_executor(agent_config) -> AuditExecutor:
    """Pick the executor shape the agent config asks for."""
    argv = tuple(agent_config.argv)
    if not argv:
        raise CampaignError("agent config has an empty argv", details={})
    if agent_config.mode == "argv":
        return CommandExecutor(argv=argv)
    return StdoutExecutor(argv=argv, answer_extractor=agent_config.answer_extractor)


__all__ = [
    "ANSWER_FILENAMES",
    "AuditExecutor",
    "CommandExecutor",
    "ExecutionResult",
    "NullExecutor",
    "StdoutExecutor",
    "build_executor",
    "expand_argv",
    "extract_final_answer",
]
