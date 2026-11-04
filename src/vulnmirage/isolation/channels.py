"""Leakage channels and the control + verification attached to each one.

A benchmark that only removes an ``oracle.json`` still leaks through Git
objects, hosted fix commits and the task identifier.  This module enumerates the
channels instead of assuming one is "the" leak, binds each one to a control and
to a check that can fail, and reports the residual risk that remains.

The registry is data, not prose: :func:`build_control_report` joins it with the
attestation records, the prompt scan and the verifier guard so the published
package can state, per channel, *what was observed*.  A channel whose check is
not executed is reported as ``unknown``; it never defaults to ``controlled``.

Sources of the channel list: SWE-Bench Pro Verified's enumeration of reference
answer channels, CyberGym's discussion of network shortcuts, and the Terminal-Bench
separation of agent and verifier environments.  Adopting the list is not evidence
that these channels are closed for *this* package -- only the checks below are.
"""

from __future__ import annotations

from typing import Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..hashing import utc_now_iso
from ..isolation.attestation import IsolationAttestation

CHANNEL_REPORT_VERSION = "1.0"

ChannelStatus = Literal["controlled", "failed", "unknown", "not_applicable"]


class LeakageChannel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel_id: str
    title: str
    description: str
    source: str
    control: str
    verification: list[str] = Field(default_factory=list)
    residual_risk: str
    #: ``true`` when an ordinary repository test suite is legitimately visible and
    #: must not be deleted in the name of isolation.
    legitimate_material: bool = False


#: The channels this benchmark claims to handle.  ``verification`` entries are
#: attestation check ids, ``prompt_scan``/``verifier_guard``/``archive_scan``
#: pseudo-checks executed by the surrounding stages.
CHANNELS: tuple[LeakageChannel, ...] = (
    LeakageChannel(
        channel_id="local_oracle_and_logs",
        title="Local oracle, validation logs, previous reports",
        description=(
            "Ground-truth files written next to the workspace, or reports left by an "
            "earlier run, are readable by the agent without any network access."
        ),
        source="SWE-Bench Pro Verified (reference-answer channels)",
        control=(
            "The oracle is never written under the campaign root; scoring reads it from "
            "the dataset package after the run, in the verifier"
        ),
        verification=["oracle_files_absent"],
        residual_risk=(
            "Host-level path guessing is not blocked in subprocess mode; only a container "
            "namespace or an unprivileged account closes it"
        ),
    ),
    LeakageChannel(
        channel_id="git_history",
        title="Fix commits, future objects, nested repository history",
        description=(
            "A clone exposes later commits, other branches and the fix; the fix diff is "
            "the answer."
        ),
        source="SWE-Bench Pro Verified; CyberGym operational notes",
        control=(
            "Materialize the hosting provider's archive for the exact commit: file content "
            "only, no .git, no submodule history; a single-commit repository is built in the "
            "trusted prep area only when an operator needs a diff"
        ),
        verification=["history_absent", "archive_scan"],
        residual_risk=(
            "Vendored archives or bundled patch files inside upstream sources are not "
            "history but can still contain a fix; the archive scan reports them, it does "
            "not remove them"
        ),
    ),
    LeakageChannel(
        channel_id="hosted_answers",
        title="Hosted dataset, fix commits, advisory search",
        description=(
            "The repository and the vulnerability are public; a single web request "
            "recovers the fix or the advisory text."
        ),
        source="CyberGym FAQ (network shortcuts); SWE-Bench Pro Verified limitation",
        control=(
            "Tools are offline by environment and by policy; model calls go through one "
            "fixed inference gateway; the live egress probe must show answer hosts "
            "unreachable"
        ),
        verification=["egress_blocked", "inference_gateway"],
        residual_risk=(
            "Domain allowlists and blocklists are incomplete, and a model that memorized "
            "the advisory needs no network at all"
        ),
    ),
    LeakageChannel(
        channel_id="prompt_and_labels",
        title="Task prompt, instance name and manifest labels",
        description=(
            "The dataset prompt names the repository, the commit, the tag and the "
            "advisory; the instance id encodes the pair; the manifest lists counts."
        ),
        source="SWE-Bench Pro Verified (metadata filtering)",
        control=(
            "Field whitelist: the agent receives only a normalized task and the stable "
            "workspace path; repository identity, commit, tag, CVE/CWE ids and advisory "
            "titles are stripped and the result is re-scanned before it is used"
        ),
        verification=["prompt_scan"],
        residual_risk=(
            "Upstream sources may still identify themselves in package metadata, which is "
            "legitimate audit material and is not removed"
        ),
    ),
    LeakageChannel(
        channel_id="session_state",
        title="Session cache and previous scoring",
        description=(
            "A reused tool/session state directory carries the earlier conversation, and a "
            "score file written back into the run directory feeds the next attempt."
        ),
        source="Evaluation-hygiene requirement of the revision plan",
        control=(
            "A fresh state directory per run, asserted empty before the audit; scores are "
            "written only to the archive run directory, never into the agent's workspace"
        ),
        verification=["fresh_state"],
        residual_risk="A model provider that caches conversations by session id is outside this control",
    ),
    LeakageChannel(
        channel_id="sibling_variants",
        title="Parent directory, sibling clean/attack variants",
        description=(
            "Comparing the current tree with a sibling variant reveals which text was "
            "injected, turning a blind audit into a diff."
        ),
        source="Revision plan section 5 (workspace containment)",
        control=(
            "Variant trees live under the preparation area; only one variant is copied into "
            "the exposure root, and the run directory is removed before the next variant starts"
        ),
        verification=["no_sibling_runs", "repo_tree_matches_variant"],
        residual_risk=(
            "Sequential execution plus removal makes the sibling absent at audit time; it "
            "does not stop an agent from reading the preparation area by absolute path "
            "outside a container"
        ),
    ),
    LeakageChannel(
        channel_id="evaluator_interfaces",
        title="Evaluator files, admin endpoints, scoring service",
        description=(
            "The agent discovers the scoring code, its rules or a management interface and "
            "shapes the answer to the metric."
        ),
        source="Terminal-Bench agent/verifier separation",
        control=(
            "The verifier runs from the private area with its own process and reads a frozen "
            "bundle; nothing under the exposure root resolves into the private area"
        ),
        verification=["private_paths_outside_exposed", "verifier_guard"],
        residual_risk="A shared host account can still read another process's files",
    ),
    LeakageChannel(
        channel_id="report_to_scoring_injection",
        title="Report text entering the scoring stage",
        description=(
            "The submitted report contains instructions aimed at the judge, a shell "
            "command, or a payload that the scoring stage executes."
        ),
        source="Prompt-injection robustness requirement for LLM judges",
        control=(
            "The verifier treats the report as data: bounded length, control characters "
            "removed, no execution, no shell, and structural matching only"
        ),
        verification=["verifier_guard"],
        residual_risk=(
            "If a human or an LLM adjudicates, delimiter wrapping reduces but does not "
            "eliminate the influence of report text"
        ),
    ),
    LeakageChannel(
        channel_id="upstream_tests",
        title="Ordinary test suite shipped with the repository",
        description=(
            "Repository tests are legitimate audit material: they document behaviour and "
            "are visible in any honest snapshot."
        ),
        source="Revision plan section 5 (do not delete every test)",
        control=(
            "Kept as-is. Only benchmark-added material (private PoC, fix patch, answer "
            "labels) is hidden; the snapshot scan reports whether a test names the target"
        ),
        verification=["archive_scan"],
        residual_risk=(
            "A regression test added by the upstream fix may name the vulnerability; this is "
            "recorded as a snapshot property, not silently removed"
        ),
        legitimate_material=True,
    ),
)


def _status_from_checks(
    channel: LeakageChannel, attestation: IsolationAttestation | None
) -> tuple[ChannelStatus, list[str], list[str]]:
    """Derive a channel status from attestation checks that actually ran."""
    statuses: list[ChannelStatus] = []
    evidence: list[str] = []
    missing: list[str] = []
    for check_id in channel.verification:
        if check_id in {"prompt_scan", "verifier_guard", "archive_scan"}:
            continue
        if attestation is None:
            statuses.append("unknown")
            missing.append(check_id)
            continue
        item = next(
            (check for check in attestation.checks if check.check_id == check_id), None
        )
        if item is None:
            statuses.append("unknown")
            missing.append(check_id)
            continue
        if item.status == "fail":
            statuses.append("failed")
        elif item.status == "unknown":
            statuses.append("unknown")
        elif item.status == "not_applicable":
            statuses.append("not_applicable")
        else:
            statuses.append("controlled")
        evidence.append(f"{check_id}={item.status}: {item.detail}")
    if "failed" in statuses:
        return "failed", evidence, missing
    if not statuses:
        return "unknown", evidence, missing
    if "unknown" in statuses:
        return "unknown", evidence, missing
    if all(item == "not_applicable" for item in statuses):
        return "not_applicable", evidence, missing
    return "controlled", evidence, missing


class ChannelReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel_id: str
    title: str
    status: ChannelStatus
    control: str
    residual_risk: str
    legitimate_material: bool = False
    evidence: list[str] = Field(default_factory=list)
    unexecuted_checks: list[str] = Field(default_factory=list)


class LeakageControlReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = CHANNEL_REPORT_VERSION
    scope: str
    channels: list[ChannelReport] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    produced_at: str = Field(default_factory=utc_now_iso)


def build_control_report(
    *,
    attestations: Iterable[IsolationAttestation] = (),
    stage_evidence: dict[str, dict[str, object]] | None = None,
    scope: str = "campaign",
) -> LeakageControlReport:
    """Join the registry with observed evidence for every run in scope."""
    observed = list(attestations)
    extra = stage_evidence or {}
    reports: list[ChannelReport] = []
    for channel in CHANNELS:
        statuses: list[ChannelStatus] = []
        evidence: list[str] = []
        missing: list[str] = []
        if observed:
            for attestation in observed:
                status, lines, absent = _status_from_checks(channel, attestation)
                statuses.append(status)
                evidence.extend(f"{attestation.run_id}: {line}" for line in lines)
                missing.extend(absent)
        stage = extra.get(channel.channel_id)
        if stage is not None:
            raw = str(stage.get("status", "unknown"))
            mapped: ChannelStatus = (
                raw if raw in {"controlled", "failed", "unknown", "not_applicable"} else "unknown"
            )
            statuses.append(mapped)  # type: ignore[arg-type]
            if stage.get("detail"):
                evidence.append(str(stage["detail"]))
        if not statuses:
            final: ChannelStatus = "unknown"
        elif "failed" in statuses:
            final = "failed"
        elif "unknown" in statuses:
            final = "unknown"
        elif all(item == "not_applicable" for item in statuses):
            final = "not_applicable"
        else:
            final = "controlled"
        reports.append(
            ChannelReport(
                channel_id=channel.channel_id,
                title=channel.title,
                status=final,
                control=channel.control,
                residual_risk=channel.residual_risk,
                legitimate_material=channel.legitimate_material,
                evidence=evidence[:20],
                unexecuted_checks=sorted(set(missing)),
            )
        )
    counts: dict[str, int] = {}
    for report in reports:
        counts[report.status] = counts.get(report.status, 0) + 1
    return LeakageControlReport(
        scope=scope,
        channels=reports,
        counts=dict(sorted(counts.items())),
        notes=[
            "a channel is 'controlled' only because a check ran and passed",
            "named external benchmarks are used for the channel list; they are not evidence "
            "that this package closes the channel",
            "repository tests are legitimate audit material and are kept",
        ],
    )


__all__ = [
    "CHANNELS",
    "CHANNEL_REPORT_VERSION",
    "ChannelReport",
    "LeakageChannel",
    "LeakageControlReport",
    "build_control_report",
]
