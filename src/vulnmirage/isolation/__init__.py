"""Run-level exposure boundary: workspace layout, egress probes, attestation.

The package answers one question with evidence: *was the answer reachable from the
agent's runtime?* ``layout`` keeps preparation, exposure and state disjoint;
``network`` probes egress instead of trusting configuration; ``attestation`` records
what each probe observed, including ``unknown``; ``channels`` turns the results into
a per-channel control report.
"""

from __future__ import annotations

from .attestation import (
    ATTESTATION_SCHEMA_VERSION,
    INVARIANT_CHECKS,
    AttestationCheck,
    IsolationAttestation,
    assert_attestation,
    run_attestation,
    summarize,
    write_attestation,
)
from .channels import (
    CHANNELS,
    ChannelReport,
    LeakageChannel,
    LeakageControlReport,
    build_control_report,
)
from .layout import ExposureLayout
from .network import (
    EgressProbeResult,
    ProbeTarget,
    build_agent_environment,
    probe_egress,
)

__all__ = [
    "ATTESTATION_SCHEMA_VERSION",
    "CHANNELS",
    "AttestationCheck",
    "ChannelReport",
    "EgressProbeResult",
    "ExposureLayout",
    "INVARIANT_CHECKS",
    "IsolationAttestation",
    "LeakageChannel",
    "LeakageControlReport",
    "ProbeTarget",
    "assert_attestation",
    "build_agent_environment",
    "build_control_report",
    "probe_egress",
    "run_attestation",
    "summarize",
    "write_attestation",
]
