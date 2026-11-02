"""VulnMirage: adversarial repository-manipulation benchmark for code agents.

The package separates benchmark *construction* (ingest, materialize, generate,
validate, export) from *experimentation* (run, evaluate).  See README.md and
docs/ for the data contracts.
"""

from __future__ import annotations

__all__ = ["__version__", "SCHEMA_VERSION"]

__version__ = "0.1.0"

#: Version written into every persisted data envelope.
SCHEMA_VERSION = "1.0"
