"""Shared validation context and result helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import LoadedConfig
from ..hashing import utc_now_iso
from ..models import (
    BenchmarkInstance,
    CanonicalVulnerabilityOracle,
    CheckStatus,
    DecoyRecord,
    ManipulationSpec,
    ValidationResult,
)
from ..store import InstanceState, InstanceStore


@dataclass
class ValidationContext:
    loaded: LoadedConfig
    store: InstanceStore
    instance: BenchmarkInstance
    state: InstanceState
    oracle: CanonicalVulnerabilityOracle
    clean_instance: BenchmarkInstance
    clean_oracle: CanonicalVulnerabilityOracle
    manipulation: ManipulationSpec | None
    decoys: list[DecoyRecord]
    repo: Path
    clean_repo: Path
    profile: str
    log_dir: Path

    @property
    def is_clean(self) -> bool:
        return self.instance.variant_kind.value == "clean"

    @property
    def is_benign(self) -> bool:
        return self.instance.variant_kind.value == "benign_control"

    @property
    def is_adversarial(self) -> bool:
        return self.instance.variant_kind.value == "adversarial"

    @property
    def has_patch(self) -> bool:
        return self.instance.patch_file is not None

    @property
    def config(self):
        return self.loaded.config

    @property
    def patch_meta(self) -> dict[str, Any] | None:
        import json

        path = self.store.instance_dir(self.instance.instance_id) / "patch_meta.json"
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None


def result(
    name: str,
    status: CheckStatus,
    started_at: str,
    duration_seconds: float,
    *,
    details: dict[str, Any] | None = None,
    command: list[str] | None = None,
    exit_code: int | None = None,
    stdout_path: str | None = None,
    stderr_path: str | None = None,
) -> ValidationResult:
    return ValidationResult(
        check_name=name,
        status=status,
        started_at=started_at,
        duration_seconds=max(duration_seconds, 0.0),
        command=command,
        exit_code=exit_code,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        details=details or {},
    )


def new_started() -> str:
    return utc_now_iso()
