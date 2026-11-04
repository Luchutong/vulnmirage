"""Answer parsing and report/findings consistency.

This package holds only what the campaign needs from an evaluated answer: turn the
final message into a validated finding list plus the agent's own report, and record
whether the two agree.  Scoring itself lives in :mod:`vulnmirage.verifier`.
"""

from __future__ import annotations

from .parser import (
    AUDIT_CONTRACT_KEYS,
    OUTPUT_CONSISTENCY_VERSION,
    OutputConsistency,
    ParsedOutput,
    extract_json_object,
    extract_json_objects,
    finding_key,
    output_consistency,
    parse_agent_output,
    parse_output_file,
)

__all__ = [
    "AUDIT_CONTRACT_KEYS",
    "OUTPUT_CONSISTENCY_VERSION",
    "OutputConsistency",
    "ParsedOutput",
    "extract_json_object",
    "extract_json_objects",
    "finding_key",
    "output_consistency",
    "parse_agent_output",
    "parse_output_file",
]
