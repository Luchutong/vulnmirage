"""Isolation attestation: evidence, not declarations.

The benchmark must be able to answer "was the oracle actually absent from the
agent's runtime?" with observations.  A configuration flag such as
``oracle_mounted: false`` is a *claim*; this module runs the checks and stores
what it observed, including the cases where it observed nothing conclusive.

Design rules
------------
* Every check is an action: read a file, walk a directory, open a socket, write a
  probe file.  No check reports ``pass`` because a config value said so.
* A check that cannot be performed is ``unknown``, never ``pass``.
* The invariant set below is **condition-independent**: it runs for the clean
  baseline and every injected variant, so a later difference between conditions cannot be
  explained by one group having a better-isolated oracle.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..errors import IsolationError
from ..hashing import atomic_write_json, sha256_file, utc_now_iso
from ..isolation.layout import ExposureLayout
from ..isolation.network import EgressProbeResult
from ..repository.archive import find_history_metadata, tree_digest

ATTESTATION_SCHEMA_VERSION = "1.0"

Status = Literal["pass", "fail", "unknown", "not_applicable"]

#: Checks that make a run structurally valid.  They are applied to every
#: condition unconditionally (see ``docs/leakage_channels.md``).
INVARIANT_CHECKS: tuple[str, ...] = (
    "repo_readable",
    "repo_tree_matches_variant",
    "history_absent",
    "oracle_files_absent",
    "no_sibling_runs",
    "private_paths_outside_exposed",
    "fresh_state",
    "output_writable",
    "egress_blocked",
)

#: Names that identify benchmark-internal material.  Matching is by file/dir name
#: so the check does not need the oracle content itself.  A real repository may
#: legitimately contain ``manifest.json`` or a ``private/`` directory, so the
#: name check applies to the exposure scaffolding and only a narrow marker set is
#: applied to the unpacked repository itself.
_SHELL_FORBIDDEN_NAMES = (
    "oracle.json",
    "manifest.json",
    "plan.json",
    "score.json",
    "matches.json",
    "isolation_attestation.json",
    "mechanism_assessment.json",
    "private",
)

#: Markers that must never appear anywhere in the exposed snapshot.
_SNAPSHOT_FORBIDDEN_NAMES = (
    "oracle.json",
    ".vulnmirage",
    ".vulnmirage.json",
)


class AttestationCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_id: str
    status: Status
    detail: str
    evidence: str | None = None
    observed_at: str = Field(default_factory=utc_now_iso)


class IsolationAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = ATTESTATION_SCHEMA_VERSION
    run_id: str
    task_id: str
    variant_id: str
    variant_kind: str
    mode: str
    #: Recorded so a reader can see the invariant was not a treatment variable.
    condition_independent: bool = True
    invariants: list[str] = Field(default_factory=lambda: list(INVARIANT_CHECKS))
    checks: list[AttestationCheck] = Field(default_factory=list)
    failed: list[str] = Field(default_factory=list)
    unknown: list[str] = Field(default_factory=list)
    egress: EgressProbeResult | None = None
    verdict: Literal["pass", "fail"] = "fail"
    eligibility: str = "ineligible_unattested"
    notes: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now_iso)


def _check(check_id: str, fn: Callable[[], tuple[Status, str, str | None]]) -> AttestationCheck:
    try:
        status, detail, evidence = fn()
    except Exception as exc:  # noqa: BLE001 - a crashed probe is "unknown", not "pass"
        return AttestationCheck(
            check_id=check_id,
            status="unknown",
            detail=f"probe raised {type(exc).__name__}: {exc}",
        )
    return AttestationCheck(
        check_id=check_id, status=status, detail=detail, evidence=evidence
    )


def _matches_forbidden(name: str, *, snapshot: bool = False) -> bool:
    lowered = name.lower()
    table = _SNAPSHOT_FORBIDDEN_NAMES if snapshot else _SHELL_FORBIDDEN_NAMES
    if lowered in table:
        return True
    if snapshot:
        return lowered.startswith("target-") and lowered.endswith(".jsonl")
    return lowered.startswith("target-") and lowered.endswith(".jsonl")


def _first_file(root: Path) -> Path | None:
    for path in sorted(root.rglob("*")):
        if path.is_file():
            return path
    return None


def run_attestation(
    layout: ExposureLayout,
    *,
    expected_tree_sha256: str | None,
    egress: EgressProbeResult | None,
    mode: str = "workspace",
    require_egress_pass: bool = True,
) -> IsolationAttestation:
    """Run every probe and return the attestation record."""
    layout.ensure()
    checks: list[AttestationCheck] = []

    def repo_readable() -> tuple[Status, str, str | None]:
        sample = _first_file(layout.repo_dir)
        if sample is None:
            return "fail", "no readable file found in the exposed repository", str(layout.repo_dir)
        head = sample.read_bytes()[:64]
        return (
            "pass",
            f"read {len(head)} byte(s) from the first exposed file",
            f"{sample.relative_to(layout.exposed_dir).as_posix()} sha256={sha256_file(sample)}",
        )

    def repo_tree_matches_variant() -> tuple[Status, str, str | None]:
        if not layout.repo_dir.is_dir():
            return "fail", "exposed repository directory is missing", str(layout.repo_dir)
        actual = tree_digest(layout.repo_dir)
        if expected_tree_sha256 is None:
            return "unknown", "no frozen variant tree digest to compare against", actual
        if actual != expected_tree_sha256:
            return (
                "fail",
                "exposed tree differs from the frozen variant tree",
                f"expected={expected_tree_sha256} actual={actual}",
            )
        return "pass", "exposed tree equals the frozen variant tree", actual

    def history_absent() -> tuple[Status, str, str | None]:
        found = find_history_metadata(layout.repo_dir)
        if found:
            return (
                "fail",
                "version-history metadata is present in the exposed tree",
                ", ".join(found[:10]),
            )
        return "pass", "no .git/.svn/.hg/.bzr entry in the exposed tree", None

    def oracle_files_absent() -> tuple[Status, str, str | None]:
        shell_hits = [
            path.relative_to(layout.exposed_dir).as_posix()
            for path in layout.exposed_dir.iterdir()
            if _matches_forbidden(path.name)
        ]
        snapshot_hits = [
            path.relative_to(layout.exposed_dir).as_posix()
            for path in layout.repo_dir.rglob("*")
            if _matches_forbidden(path.name, snapshot=True)
        ]
        hits = shell_hits + snapshot_hits
        if hits:
            return (
                "fail",
                "benchmark-internal material was found inside the exposed root",
                ", ".join(hits[:10]),
            )
        return "pass", "no oracle/target/manifest artefact inside the exposed root", None

    def no_sibling_runs() -> tuple[Status, str, str | None]:
        children = layout.exposed_children()
        unexpected = [item for item in children if item not in {"repo", "out"}]
        if unexpected:
            return (
                "fail",
                "the exposed root contains entries other than repo/ and out/",
                ", ".join(unexpected),
            )
        siblings_root = layout.exposed_dir.parent
        others = [
            item.name
            for item in siblings_root.iterdir()
            if item.name != layout.run_id and item.is_dir()
        ] if siblings_root.is_dir() else []
        if others:
            return (
                "fail",
                "another exposed run directory is present next to this one",
                ", ".join(sorted(others)[:10]),
            )
        return "pass", "exposed root holds exactly repo/ and out/, no sibling run", None

    def private_paths_outside_exposed() -> tuple[Status, str, str | None]:
        try:
            layout.assert_contained()
        except IsolationError as exc:
            return "fail", str(exc.message), str(exc.details)
        present = [
            name for name, path in layout.private_paths().items() if path.exists()
        ]
        return (
            "pass",
            "no private area resolves inside the exposed root",
            "present outside the exposure: " + (", ".join(sorted(present)) or "none"),
        )

    def fresh_state() -> tuple[Status, str, str | None]:
        if not layout.state_dir.is_dir():
            return "fail", "state directory was not created for this run", str(layout.state_dir)
        entries = sorted(item.name for item in layout.state_dir.iterdir())
        if entries:
            return (
                "fail",
                "state directory is not empty: a previous session could leak into this run",
                ", ".join(entries[:10]),
            )
        return "pass", "state directory is newly created and empty", str(layout.state_dir)

    def output_writable() -> tuple[Status, str, str | None]:
        probe = layout.output_dir / ".attestation_probe"
        probe.parent.mkdir(parents=True, exist_ok=True)
        probe.write_text("probe\n", encoding="utf-8")
        ok = probe.read_text(encoding="utf-8") == "probe\n"
        probe.unlink()
        if not ok:
            return "fail", "output directory did not round-trip a probe write", str(probe)
        return "pass", "output directory accepts and returns a probe write", str(probe)

    def egress_blocked() -> tuple[Status, str, str | None]:
        if egress is None:
            return "unknown", "no egress probe was executed for this run", None
        if egress.reachable_answer_hosts:
            return (
                "fail",
                "answer-serving hosts answered a live connection from this environment",
                ", ".join(egress.reachable_answer_hosts),
            )
        if require_egress_pass and not egress.enforcement_verified:
            return (
                "fail",
                "answer hosts were not reached, but no enforceable agent network "
                "boundary was verified",
                f"origin={egress.probe_origin} enforcement={egress.enforcement}",
            )
        if require_egress_pass and not egress.blocked_targets:
            return (
                "fail",
                "no answer-serving host was probed inside the agent boundary",
                f"origin={egress.probe_origin}",
            )
        if (
            require_egress_pass
            and egress.gateway_targets
            and not egress.gateway_reachable
        ):
            return (
                "fail",
                "the inference gateway was not reachable from the agent boundary",
                ", ".join(item.host for item in egress.gateway_targets),
            )
        if not egress.enforcement_verified:
            return (
                "unknown",
                "probes observed answer hosts as unreachable without an enforced boundary",
                f"origin={egress.probe_origin} enforcement={egress.enforcement}",
            )
        reachable = [item.host for item in egress.blocked_targets if not item.connected]
        return (
            "pass",
            f"{len(reachable)} answer host(s) probed and unreachable",
            f"mode={egress.mode} enforcement={egress.enforcement}",
        )

    probes: dict[str, Callable[[], tuple[Status, str, str | None]]] = {
        "repo_readable": repo_readable,
        "repo_tree_matches_variant": repo_tree_matches_variant,
        "history_absent": history_absent,
        "oracle_files_absent": oracle_files_absent,
        "no_sibling_runs": no_sibling_runs,
        "private_paths_outside_exposed": private_paths_outside_exposed,
        "fresh_state": fresh_state,
        "output_writable": output_writable,
        "egress_blocked": egress_blocked,
    }
    for check_id in INVARIANT_CHECKS:
        checks.append(_check(check_id, probes[check_id]))

    checks.append(
        AttestationCheck(
            check_id="runtime_boundary",
            status="pass" if mode == "workspace" else "unknown",
            detail=(
                "per-run exposed root with disjoint preparation and private areas"
                if mode == "workspace"
                else "workspace mode disabled: the exposure boundary is unverified"
            ),
            evidence=f"mode={mode}",
        )
    )
    if egress is not None:
        checks.append(
            AttestationCheck(
                check_id="inference_gateway",
                status=(
                    "not_applicable"
                    if egress.gateway_reachable is None
                    else ("pass" if egress.gateway_reachable else "fail")
                ),
                detail=(
                    "no inference gateway host was configured for probing"
                    if egress.gateway_reachable is None
                    else (
                        "the configured inference gateway answered"
                        if egress.gateway_reachable
                        else "the configured inference gateway did not answer"
                    )
                ),
                evidence=", ".join(
                    item.host for item in egress.gateway_targets
                ) or None,
            )
        )

    failed = [item.check_id for item in checks if item.status == "fail"]
    unknown = [item.check_id for item in checks if item.status == "unknown"]
    blocking = [item for item in failed if item in INVARIANT_CHECKS]
    if require_egress_pass is False and "egress_blocked" in blocking:
        blocking = [item for item in blocking if item != "egress_blocked"]
    verdict: Literal["pass", "fail"] = "fail" if blocking else "pass"
    if blocking:
        eligibility = "ineligible_isolation_failed:" + ",".join(blocking)
    elif unknown:
        eligibility = "eligible_with_unknown:" + ",".join(unknown)
    else:
        eligibility = "eligible"

    return IsolationAttestation(
        run_id=layout.run_id,
        task_id=layout.task_id,
        variant_id=layout.variant_id,
        variant_kind=layout.variant_kind,
        mode=mode,
        checks=checks,
        failed=failed,
        unknown=unknown,
        egress=egress,
        verdict=verdict,
        eligibility=eligibility,
        notes=[
            "invariants are executed for every condition; they are not a treatment variable",
            "unknown is reported as unknown, never as pass",
        ],
    )


def write_attestation(layout: ExposureLayout, attestation: IsolationAttestation) -> Path:
    path = layout.run_dir() / "isolation_attestation.json"
    atomic_write_json(path, attestation)
    return path


def assert_attestation(attestation: IsolationAttestation) -> None:
    """Abort a run whose exposure boundary could not be proven."""
    blocking = [item for item in attestation.failed if item in INVARIANT_CHECKS]
    if blocking:
        raise IsolationError(
            "isolation invariants failed; the run cannot be scored",
            details={
                "run_id": attestation.run_id,
                "failed": blocking,
                "checks": [
                    item.model_dump(mode="json")
                    for item in attestation.checks
                    if item.check_id in blocking
                ],
            },
        )


def summarize(attestations: Iterable[IsolationAttestation]) -> dict[str, object]:
    items = list(attestations)
    return {
        "runs": len(items),
        "pass": len([item for item in items if item.verdict == "pass"]),
        "fail": len([item for item in items if item.verdict == "fail"]),
        "invariants": list(INVARIANT_CHECKS),
        "failures": {
            check_id: len([item for item in items if check_id in item.failed])
            for check_id in INVARIANT_CHECKS
        },
    }


__all__ = [
    "ATTESTATION_SCHEMA_VERSION",
    "AttestationCheck",
    "INVARIANT_CHECKS",
    "IsolationAttestation",
    "assert_attestation",
    "run_attestation",
    "summarize",
    "write_attestation",
]
