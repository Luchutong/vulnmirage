"""Frozen, hash-bound input bundle handed to the independent evaluator.

The evaluator never sees the agent's environment and the agent never sees the
oracle.  The only thing that crosses the boundary is this bundle: named files,
each pinned by sha256 in ``bundle_manifest.json``, produced by the harness from
the run directory.  If a file changes after freezing, the bundle is rejected
rather than re-read.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..errors import VerifierError
from ..hashing import atomic_write_json, sha256_file, utc_now_iso

BUNDLE_SCHEMA_VERSION = "1.0"

#: Files an evaluator may consume.  Anything else is not part of the contract.
BUNDLE_FILES: tuple[str, ...] = (
    "final_raw.txt",
    "events.normalized.jsonl",
    "run.json",
    "meta.json",
    "isolation_attestation.json",
)

#: Optional files: present only when the producing stage supported them.
OPTIONAL_BUNDLE_FILES: tuple[str, ...] = (
    "file_access.jsonl",
    "tool_calls.jsonl",
    "trace_manifest.json",
    "trace_completeness.json",
)

#: Names/content that mean the oracle leaked into the bundle.
_ORACLE_NAME_PREFIXES = ("target-", "oracle")
_ORACLE_CONTENT_MARKERS = ('"vulnerability_id"', '"weakness"', '"snippet_sha256"')


class BundleEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    present: bool
    sha256: str | None = None
    bytes: int | None = None
    missing_reason: str | None = None


class BundleManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = BUNDLE_SCHEMA_VERSION
    bundle_id: str
    task_id: str
    run_id: str
    variant_id: str
    entries: list[BundleEntry] = Field(default_factory=list)
    frozen_at: str = Field(default_factory=utc_now_iso)
    producer: str = "harness"


class RunBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root: str
    manifest: BundleManifest

    def path(self, name: str) -> Path | None:
        entry = next((item for item in self.manifest.entries if item.name == name), None)
        if entry is None or not entry.present:
            return None
        return Path(self.root) / name

    def read_text(self, name: str) -> str | None:
        path = self.path(name)
        return path.read_text(encoding="utf-8", errors="replace") if path else None


def freeze_bundle(
    run_dir: Path,
    bundle_dir: Path,
    *,
    task_id: str,
    run_id: str,
    variant_id: str,
    bundle_id: str | None = None,
) -> RunBundle:
    """Copy the contract files out of a run directory into a frozen bundle."""
    run_dir = Path(run_dir)
    bundle_dir = Path(bundle_dir)
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    entries: list[BundleEntry] = []
    for name in (*BUNDLE_FILES, *OPTIONAL_BUNDLE_FILES):
        source = run_dir / name
        required = name in BUNDLE_FILES
        if not source.is_file():
            entries.append(
                BundleEntry(
                    name=name,
                    present=False,
                    missing_reason=(
                        "required run artefact is missing"
                        if required
                        else "this stage did not produce the artefact"
                    ),
                )
            )
            continue
        target = bundle_dir / name
        shutil.copyfile(source, target)
        entries.append(
            BundleEntry(
                name=name,
                present=True,
                sha256=sha256_file(target),
                bytes=target.stat().st_size,
            )
        )
    manifest = BundleManifest(
        bundle_id=bundle_id or f"{task_id}__{run_id}",
        task_id=task_id,
        run_id=run_id,
        variant_id=variant_id,
        entries=entries,
    )
    atomic_write_json(bundle_dir / "bundle_manifest.json", manifest)
    return RunBundle(root=bundle_dir.as_posix(), manifest=manifest)


def verify_bundle(bundle_dir: Path) -> dict[str, object]:
    """Recompute every hash; refuse a bundle that changed after freezing."""
    bundle_dir = Path(bundle_dir)
    manifest_path = bundle_dir / "bundle_manifest.json"
    if not manifest_path.is_file():
        raise VerifierError("bundle manifest is missing", details={"bundle": str(bundle_dir)})
    manifest = BundleManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    errors: list[str] = []
    for entry in manifest.entries:
        path = bundle_dir / entry.name
        if not entry.present:
            if path.exists():
                errors.append(f"{entry.name}: manifest says absent but the file exists")
            continue
        if not path.is_file():
            errors.append(f"{entry.name}: manifest says present but the file is missing")
            continue
        if entry.sha256 and sha256_file(path) != entry.sha256:
            errors.append(f"{entry.name}: sha256 does not match the frozen bundle")
        if entry.bytes is not None and path.stat().st_size != entry.bytes:
            errors.append(f"{entry.name}: size does not match the frozen bundle")
    if not any(entry.name == "final_raw.txt" and entry.present for entry in manifest.entries):
        errors.append("final_raw.txt is required but absent: there is nothing to evaluate")
    return {
        "ok": not errors,
        "errors": errors,
        "bundle_id": manifest.bundle_id,
        "files": [entry.name for entry in manifest.entries if entry.present],
    }


def assert_bundle_has_no_oracle(bundle_dir: Path) -> list[str]:
    """Refuse a bundle that carries ground truth.

    This is the direction the isolation work usually forgets: the evaluator must
    not be fed the answer *through* the submission channel.  Therefore a bundle
    containing a target dump, or text that looks like one, is rejected.
    """
    bundle_dir = Path(bundle_dir)
    problems: list[str] = []
    for path in sorted(bundle_dir.rglob("*")):
        if not path.is_file():
            continue
        name = path.name.lower()
        if any(name.startswith(prefix) for prefix in _ORACLE_NAME_PREFIXES) and name.endswith(
            (".json", ".jsonl")
        ):
            problems.append(f"oracle-like file in bundle: {path.relative_to(bundle_dir).as_posix()}")
            continue
        if path.suffix in {".json", ".jsonl", ".txt", ".md"}:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")[:200_000]
            except OSError:  # pragma: no cover - unreadable file
                continue
            for marker in _ORACLE_CONTENT_MARKERS:
                if marker in text:
                    problems.append(
                        f"{path.relative_to(bundle_dir).as_posix()} contains the oracle marker {marker}"
                    )
                    break
    return problems


def assert_bundle_outside_private(bundle_dir: Path, private_root: Path) -> None:
    """The bundle and the private evaluator area must be disjoint."""
    bundle_dir = Path(bundle_dir).resolve()
    private_root = Path(private_root).resolve()
    if bundle_dir == private_root or bundle_dir.is_relative_to(private_root):
        raise VerifierError(
            "the bundle must not be stored inside the private evaluator root",
            details={"bundle": str(bundle_dir), "private": str(private_root)},
        )
    if private_root.is_relative_to(bundle_dir):
        raise VerifierError(
            "the private evaluator root must not live inside the submitted bundle",
            details={"bundle": str(bundle_dir), "private": str(private_root)},
        )


__all__ = [
    "BUNDLE_FILES",
    "BUNDLE_SCHEMA_VERSION",
    "BundleEntry",
    "BundleManifest",
    "OPTIONAL_BUNDLE_FILES",
    "RunBundle",
    "assert_bundle_has_no_oracle",
    "assert_bundle_outside_private",
    "freeze_bundle",
    "verify_bundle",
]
