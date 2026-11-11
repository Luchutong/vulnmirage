"""Independent evaluator package.

Entry points:

* :func:`vulnmirage.verifier.service.evaluate_bundle` -- in-process call used by
  tests and by campaigns configured with ``verifier.mode: in_process``;
* ``python -m vulnmirage.verifier --private DIR --bundle DIR --out DIR`` -- the
  separated process used for real runs, which keeps the oracle out of the
  collecting process.

Contract: the only input is a frozen bundle; the outputs include ``score.json``,
``matches.json``, ``rubric_scores.json``, ``safe_decoy_matches.json``,
``output_consistency.json``, ``untrusted_input.json`` and
``verifier_attestation.json``, written outside both the bundle and the private root.
"""

from __future__ import annotations

from .bundle import (
    BundleEntry,
    BundleManifest,
    RunBundle,
    assert_bundle_has_no_oracle,
    assert_bundle_outside_private,
    freeze_bundle,
    verify_bundle,
)
from .rubrics import (
    EvidenceRequirement,
    RubricLocation,
    RubricScoreReport,
    TargetRubric,
    TargetRubricScore,
    build_target_rubric,
    score_target_rubrics,
)
from .service import RunScore, VerifierAttestation, evaluate_bundle, load_target_set
from .targets import PrivateTarget, SafeDecoy, TargetSet, finding_views, match_targets
from .untrusted import assert_no_execution_sinks, fence_untrusted, sanitize_untrusted

__all__ = [
    "BundleEntry",
    "BundleManifest",
    "EvidenceRequirement",
    "PrivateTarget",
    "RunBundle",
    "RunScore",
    "RubricLocation",
    "RubricScoreReport",
    "SafeDecoy",
    "TargetSet",
    "TargetRubric",
    "TargetRubricScore",
    "VerifierAttestation",
    "assert_bundle_has_no_oracle",
    "assert_bundle_outside_private",
    "assert_no_execution_sinks",
    "build_target_rubric",
    "evaluate_bundle",
    "fence_untrusted",
    "finding_views",
    "freeze_bundle",
    "load_target_set",
    "match_targets",
    "sanitize_untrusted",
    "score_target_rubrics",
    "verify_bundle",
]
