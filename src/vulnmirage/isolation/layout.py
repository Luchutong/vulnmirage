"""Run-level exposure boundary: one workspace, one variant, no answers."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from ..errors import IsolationError
from ..paths import ensure_within


@dataclass(frozen=True)
class ExposureLayout:
    """Directory policy for one audit run.

    ``<root>`` is the campaign archive root (``workspace/``).  The three areas are
    deliberately disjoint:

    * ``prep/<task>/``     trusted preparation: source snapshot + every variant
                           tree.  Never mounted for an audit run.
    * ``exposed/<run>/``   the only tree the agent sees: ``repo/`` (read) and
                           ``out/`` (write).  Created per run and removed after.
    * ``state/<run>/``     fresh tool/session state; reusing it would leak the
                           previous score.
    """

    root: Path
    task_id: str
    run_id: str
    variant_id: str
    variant_kind: str = "clean"

    # ------------------------------------------------------------------ layout
    #: Scratch area for this task; removed once the task is archived and verified.
    @property
    def tmp_dir(self) -> Path:
        return self.root / "tmp" / self.task_id

    @property
    def exposed_dir(self) -> Path:
        return self.tmp_dir / "exposed" / self.run_id

    @property
    def repo_dir(self) -> Path:
        return self.exposed_dir / "repo"

    @property
    def output_dir(self) -> Path:
        return self.exposed_dir / "out"

    @property
    def state_dir(self) -> Path:
        return self.tmp_dir / "state" / self.run_id

    @property
    def prep_dir(self) -> Path:
        return self.tmp_dir / "prep"

    @property
    def source_dir(self) -> Path:
        return self.prep_dir / "source"

    @property
    def variants_dir(self) -> Path:
        return self.prep_dir / "variants"

    @property
    def variant_dir(self) -> Path:
        return self.variants_dir / self.variant_id

    @property
    def archive_dir(self) -> Path:
        return self.root / "archives" / self.task_id

    @property
    def control_dir(self) -> Path:
        return self.root / "control"

    @property
    def private_dir(self) -> Path:
        return self.root / "private"

    @property
    def runs_dir(self) -> Path:
        return self.archive_dir / "runs"

    def run_dir(self) -> Path:
        return self.runs_dir / self.run_id

    def as_dict(self) -> dict[str, str]:
        return {
            "root": self.root.as_posix(),
            "task_id": self.task_id,
            "run_id": self.run_id,
            "variant_id": self.variant_id,
            "variant_kind": self.variant_kind,
            "exposed_dir": self.exposed_dir.as_posix(),
            "repo_dir": self.repo_dir.as_posix(),
            "output_dir": self.output_dir.as_posix(),
            "state_dir": self.state_dir.as_posix(),
            "prep_dir": self.prep_dir.as_posix(),
            "variant_dir": self.variant_dir.as_posix(),
            "archive_dir": self.archive_dir.as_posix(),
        }

    #: Paths that must be outside the exposed tree.  Used by the attestation.
    def private_paths(self) -> dict[str, Path]:
        return {
            "prep": self.prep_dir,
            "variants": self.variants_dir,
            "variant": self.variant_dir,
            "state": self.state_dir,
            "private": self.private_dir,
            "control": self.control_dir,
            "archives": self.archive_dir,
        }

    # ------------------------------------------------------------- life cycle
    def ensure(self) -> None:
        self.exposed_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def assert_contained(self) -> None:
        """Reject a layout whose ancestors already hold private material."""
        for name, path in self.private_paths().items():
            try:
                ensure_within(self.exposed_dir, path)
            except Exception:
                continue
            raise IsolationError(
                "private path resolves inside the exposed root",
                details={"area": name, "path": str(path), "exposed": str(self.exposed_dir)},
            )

    def reset_exposed(self) -> None:
        """Remove the exposed tree and state so a run starts from nothing."""
        for path in (self.exposed_dir, self.state_dir):
            if path.exists():
                shutil.rmtree(path)
        self.ensure()

    def cleanup(self) -> list[str]:
        """Delete only this run's exposed tree, state and scratch."""
        removed: list[str] = []
        for path in (self.exposed_dir, self.state_dir):
            if path.exists():
                shutil.rmtree(path)
                removed.append(path.as_posix())
        return removed

    def exposed_children(self) -> list[str]:
        if not self.exposed_dir.is_dir():
            return []
        return sorted(item.name for item in self.exposed_dir.iterdir())


__all__ = ["ExposureLayout"]
