"""Isolated repository copies for build/test/PoC validation commands."""

from __future__ import annotations

import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from ..config import CommandSpec
from ..config import LoadedConfig
from ..models import ValidatorCommand
from .exec import CommandOutcome, run_validation_command


@contextmanager
def isolated_repo_copy(source: Path, workspace: Path, label: str) -> Iterator[Path]:
    workspace.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f"vm-{label}-", dir=str(workspace)))
    destination = temporary / "repo"
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".pytest_cache"),
    )
    try:
        yield destination
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def outcome_details(outcome: CommandOutcome) -> dict[str, object]:
    return {
        "name": outcome.name,
        "argv": outcome.argv,
        "cwd": outcome.cwd,
        "repo_root": outcome.repo_root,
        "exit_code": outcome.exit_code,
        "expected_exit_codes": outcome.expected_exit_codes,
        "timed_out": outcome.timed_out,
        "duration_seconds": round(outcome.duration_seconds, 3),
        "stdout_path": outcome.stdout_path,
        "stderr_path": outcome.stderr_path,
        "stdout_tail": outcome.stdout_text[-500:],
        "stderr_tail": outcome.stderr_text[-500:],
    }


def run_commands_in_copy(
    loaded: LoadedConfig,
    source_repo: Path,
    commands: list[ValidatorCommand] | list[CommandSpec],
    *,
    label: str,
    log_dir: Path,
) -> tuple[list[CommandOutcome], Path]:
    outcomes: list[CommandOutcome] = []
    workspace = loaded.paths.runs / "_validation"
    with isolated_repo_copy(source_repo, workspace, label) as repo:
        used: set[str] = set()
        for command in commands:
            outcome = run_validation_command(
                command,
                repo_root=repo,
                log_dir=log_dir,
                network_allowed=loaded.config.validation.allow_command_network,
                used_names=used,
            )
            outcomes.append(outcome)
    return outcomes, source_repo
