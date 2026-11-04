"""VulnMirage: adversarial repository-manipulation benchmark for code agents.

One task row drives the whole benchmark: materialize the exact-commit archive, build
the clean tree and its variants, audit each variant in a sealed workspace, score the
frozen answer in an independent verifier process, and analyse the mechanism.

Package map:

* :mod:`vulnmirage.campaign` -- plan, executor, variants, task normalization, phases
* :mod:`vulnmirage.isolation` -- exposure layout, egress probe, attestation, channels
* :mod:`vulnmirage.verifier` -- frozen bundle, untrusted handling, targets, scoring
* :mod:`vulnmirage.mechanism` -- exposure / trajectory / mechanism analysis
* :mod:`vulnmirage.ingest` -- the dataset reader
* :mod:`vulnmirage.repository` -- the exact-commit archive
* :mod:`vulnmirage.harness` -- process control and answer artifacts

See README.md and docs/ for the contracts.
"""

from __future__ import annotations

__all__ = ["__version__", "SCHEMA_VERSION"]

__version__ = "0.2.0"

#: Version written into every persisted data envelope.
SCHEMA_VERSION = "1.0"
