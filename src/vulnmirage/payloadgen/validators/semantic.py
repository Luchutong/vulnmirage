"""Semantic validation: the payload must not change what the code does.

The strong, cheap case is a comment carrier: if every non-blank inserted line is a
comment in the target file's syntax, the tree's behaviour cannot change and no
parser needs to agree with us.  The other cases are honestly weaker:

* a created ``.py`` file is parsed, and a safe-decoy carrier must additionally pass
  the narrow no-execution certificate;
* a created file in a language with no parser here returns ``unknown`` for
  build equivalence -- never ``pass``, because "we did not check" is not a result.
"""

from __future__ import annotations

import ast
from pathlib import Path

from ...errors import CampaignError
from ..contracts import ValidatorResult
from ..render import certify_python_safe_decoy, comment_prefix_for
from .base import ValidationInputs


def _result(status: str, reason: str, *, required: bool, **evidence: object) -> ValidatorResult:
    return ValidatorResult(
        validator="semantic",
        status=status,  # type: ignore[arg-type]
        required=required,
        reason=reason,
        evidence=dict(evidence),
    )


def validate(inputs: ValidationInputs) -> ValidatorResult:
    candidate = inputs.candidate
    context = inputs.context
    path = candidate.target_file or ""
    suffix = Path(path).suffix.lower()

    if candidate.edit_op in {"append", "insert_before"}:
        try:
            prefix = comment_prefix_for(path)
        except CampaignError:
            return _result(
                "fail",
                "no comment syntax for this carrier, so the edit could change code",
                required=True,
                path=path,
            )
        offenders = [
            line
            for line in candidate.rendered_text.splitlines()
            if line.strip() and not line.lstrip().startswith(prefix)
        ]
        if offenders:
            return _result(
                "fail",
                "payload inserts non-comment lines into a source file",
                required=True,
                path=path,
                examples=offenders[:3],
            )
        return _result(
            "pass",
            "every inserted line is a comment, so repository behaviour is unchanged",
            required=True,
            path=path,
            carrier="comment",
        )

    if suffix == ".py":
        try:
            ast.parse(candidate.rendered_text)
        except SyntaxError as exc:
            return _result("fail", "created Python file does not parse", required=True, error=str(exc))
        if context.placement == "safe_decoy_file":
            try:
                proof = certify_python_safe_decoy(candidate.rendered_text, payload_id=context.method_id)
            except CampaignError as exc:
                return _result(
                    "fail",
                    "safe decoy exceeds the certified no-execution subset",
                    required=True,
                    error=exc.message,
                )
            return _result(
                "pass",
                "parsed and inside the certified no-execution subset",
                required=True,
                proof_kind="python_no_execution_subset_v1",
                proof_sha256=proof,
            )
        return _result(
            "unknown",
            "created Python file parses, but no execution profile proves equivalence",
            required=True,
            profile="absent",
        )

    return _result(
        "not_applicable",
        "no parser or execution profile is available for this carrier",
        required=False,
        path=path,
        parse_status="unknown",
    )


__all__ = ["validate"]
