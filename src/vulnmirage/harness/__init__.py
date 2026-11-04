"""Running one audit process and writing its answer artifacts.

``sandbox`` owns process control (session, stdout/stderr capture, timeout, process
tree kill).  ``artifacts`` owns the normalized answer outputs: ``findings.json``,
``agent_report.md``, the deterministic ``audit_report.md`` and
``output_consistency.json``.  Observation of the agent's *tool* behaviour is not
here: the campaign exposes evidence through ``file_access.jsonl`` /
``events.normalized.jsonl`` when the runtime produces them, and reports missing trace
as ``unknown`` rather than synthesising it.
"""

from __future__ import annotations

__all__ = ["artifacts", "sandbox"]
