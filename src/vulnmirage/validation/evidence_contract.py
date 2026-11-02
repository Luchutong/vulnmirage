"""Evidence-contract completeness and integrity validation."""

from __future__ import annotations

import time

from ..generation.evidence_contract import validate_evidence_contract
from ..models import CheckStatus
from .context import ValidationContext, new_started, result


def check_evidence_contract(ctx: ValidationContext):
    started = new_started()
    began = time.monotonic()
    errors: list[str] = []
    contract = ctx.store.load_evidence_contract(ctx.instance.instance_id)
    if contract is None:
        errors.append("evidence_contract.json is missing")
    elif contract.instance_id != ctx.instance.instance_id:
        errors.append("evidence contract instance_id does not match the instance")
    elif ctx.is_clean or ctx.is_benign:
        errors.extend(validate_evidence_contract(contract, repo_root=ctx.repo, is_clean=True))
        if ctx.is_clean and ctx.instance.evidence_contract_ref is None:
            errors.append("clean instance has no evidence_contract_ref")
    else:
        errors.extend(validate_evidence_contract(contract, repo_root=ctx.repo))
        if ctx.instance.evidence_contract_ref is None:
            errors.append("adversarial instance has no evidence_contract_ref")
        if ctx.manipulation is None:
            errors.append("adversarial instance has no manipulation spec")
        elif ctx.manipulation.evidence_contract_ref != ctx.instance.evidence_contract_ref:
            errors.append("manipulation and instance evidence contract refs disagree")
        if contract is not None and ctx.manipulation is not None:
            if not contract.claims:
                errors.append("adversarial evidence contract has no claims")
            for claim in contract.claims:
                if claim.manipulation_id != ctx.manipulation.manipulation_id:
                    errors.append(f"claim {claim.claim_id} references a different manipulation")
                if any(
                    action.action_kind in {"build", "test", "poc"} and not action.argv
                    for action in claim.acceptable_actions
                ):
                    errors.append(f"claim {claim.claim_id} has an executable action without argv")
    details = {
        "errors": errors,
        "evidence_contract_complete": not errors,
        "claim_count": len(contract.claims) if contract is not None else 0,
        "contract_sha256": contract.contract_sha256 if contract is not None else None,
    }
    return result(
        "evidence_contract",
        CheckStatus.PASS if not errors else CheckStatus.FAIL,
        started,
        time.monotonic() - began,
        details=details,
    )
