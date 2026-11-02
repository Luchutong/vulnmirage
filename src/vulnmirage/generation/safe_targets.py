"""Resolution and execution of :class:`SafeTargetContract` validators.

A safe target is only usable as false-positive ground truth after its validator
commands ran and returned an expected exit code.  Targets are declared by the
dataset (fix commit / human annotation) or produced by a synthetic decoy
operator; they are never inferred from "this file is not in the oracle".
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import LoadedConfig
from ..hashing import canonical_json, sha256_text, utc_now_iso
from ..models import (
    CanonicalVulnerabilityOracle,
    CheckStatus,
    CodeLocation,
    SafeTargetContract,
    SafeTargetProofMethod,
    SafeTargetSource,
    ValidatorCommand,
    VulnerabilityRecord,
)
from ..validation.command_support import outcome_details, run_commands_in_copy
from ..validation.exec import run_validation_command

_FIXED_PATH_SCRIPT = r"""
import subprocess
import sys

FILE = {file!r}
VULNERABLE = {vulnerable!r}
FIXED = {fixed!r}
START = {start}
END = {end}


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True)


if git("cat-file", "-e", FIXED + "^{{commit}}").returncode != 0:
    print("fixed commit is not present in the repository")
    sys.exit(3)
if git("cat-file", "-e", f"{{FIXED}}:{{FILE}}").returncode != 0:
    print("fixed commit does not contain the declared path")
    sys.exit(4)
touched = git("diff", "--name-only", f"{{VULNERABLE}}..{{FIXED}}", "--", FILE)
if FILE not in touched.stdout.splitlines():
    print("fixed commit did not modify the declared path")
    sys.exit(5)
before = git("show", f"{{VULNERABLE}}:{{FILE}}")
after = git("show", f"{{FIXED}}:{{FILE}}")
if before.returncode != 0 or after.returncode != 0:
    print("cannot read the declared path at both commits")
    sys.exit(6)
before_lines = before.stdout.splitlines()
old_span = "\n".join(before_lines[START - 1 : END])
if not old_span.strip():
    print("declared span is empty at the vulnerable commit")
    sys.exit(7)
if old_span in after.stdout:
    print("declared vulnerable region is unchanged by the fix commit")
    sys.exit(8)
print("fixed-commit path verified")
sys.exit(0)
"""


class SafeTargetError(ValueError):
    """Raised when a safe target cannot be bound to a repository."""


@dataclass
class SafeTargetResolution:
    accepted: list[SafeTargetContract] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)

    @property
    def validated(self) -> list[SafeTargetContract]:
        return [item for item in self.accepted if item.validated_safe]

    def for_cwe(self, cwe: set[str]) -> list[SafeTargetContract]:
        return [item for item in self.validated if item.cwe in cwe]

    def ids(self) -> list[str]:
        return [item.safe_target_id for item in self.accepted]


@dataclass
class SafeTargetValidation:
    contracts: list[SafeTargetContract]
    details: list[dict[str, Any]]
    log_sha256: str
    log_path: Path | None = None

    @property
    def validated(self) -> list[SafeTargetContract]:
        return [item for item in self.contracts if item.validated_safe]

    @property
    def rejected(self) -> list[SafeTargetContract]:
        return [item for item in self.contracts if not item.validated_safe]


def _cwe_for(vulnerability: VulnerabilityRecord) -> str:
    return vulnerability.cwe[0] if vulnerability.cwe else ""


def _matching_vulnerability(
    oracle: CanonicalVulnerabilityOracle, cwe: str
) -> VulnerabilityRecord | None:
    for vulnerability in oracle.vulnerabilities:
        if cwe in vulnerability.cwe:
            return vulnerability
    return None


def _normalized_span(contract: SafeTargetContract, repo_root: Path) -> tuple[int, int] | None:
    try:
        path = (Path(repo_root) / contract.file).resolve()
        if Path(repo_root).resolve() not in path.parents and path != Path(repo_root).resolve():
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = text.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    if not lines:
        return None
    start = min(contract.start_line, len(lines))
    end = min(contract.end_line, len(lines))
    if start < 1 or end < start:
        return None
    return start, end


def fixed_commit_validator(
    oracle: CanonicalVulnerabilityOracle, contract: SafeTargetContract
) -> ValidatorCommand | None:
    """Build a git-backed validator for a ``fixed_commit_path`` target."""
    fixed = oracle.repository.fixed_commit
    if not fixed:
        return None
    script = _FIXED_PATH_SCRIPT.format(
        file=contract.file,
        vulnerable=oracle.repository.vulnerable_commit,
        fixed=fixed,
        start=contract.start_line,
        end=contract.end_line,
    )
    return ValidatorCommand(
        name=f"fixed-path-{contract.safe_target_id}"[:80],
        argv=[sys.executable, "-c", script],
        timeout_seconds=120,
    )


def prepare_safe_targets(
    oracle: CanonicalVulnerabilityOracle, repo_root: Path
) -> SafeTargetResolution:
    """Validate the *declaration* of each safe target (not its safety yet)."""
    resolution = SafeTargetResolution()
    seen: set[str] = set()
    for contract in oracle.all_safe_targets():
        if contract.safe_target_id in seen:
            resolution.rejected.append(
                {
                    "safe_target_id": contract.safe_target_id,
                    "reason": "duplicate_safe_target_id",
                }
            )
            continue
        seen.add(contract.safe_target_id)
        vulnerability = _matching_vulnerability(oracle, contract.cwe)
        if vulnerability is None:
            resolution.rejected.append(
                {
                    "safe_target_id": contract.safe_target_id,
                    "reason": "safe_target_cwe_not_in_oracle",
                    "cwe": contract.cwe,
                }
            )
            continue
        if _normalized_span(contract, repo_root) is None:
            resolution.rejected.append(
                {
                    "safe_target_id": contract.safe_target_id,
                    "reason": "safe_target_location_missing",
                    "file": contract.file,
                }
            )
            continue
        commands = list(contract.validator_commands)
        if contract.proof_method == SafeTargetProofMethod.FIX_COMMIT_PATH and not commands:
            generated = fixed_commit_validator(oracle, contract)
            if generated is None:
                resolution.rejected.append(
                    {
                        "safe_target_id": contract.safe_target_id,
                        "reason": "fix_commit_required_but_absent",
                    }
                )
                continue
            commands = [generated]
        if not commands:
            resolution.rejected.append(
                {
                    "safe_target_id": contract.safe_target_id,
                    "reason": "validator_commands_required",
                    "proof_method": contract.proof_method.value,
                }
            )
            continue
        resolution.accepted.append(
            contract.model_copy(
                update={"validator_commands": commands, "validated_safe": False}
            )
        )
    return resolution


def _log_digest(details: list[dict[str, Any]]) -> str:
    return sha256_text(canonical_json(details))


def execute_safe_target_validation(
    contracts: list[SafeTargetContract],
    *,
    loaded: LoadedConfig,
    repo_root: Path,
    log_dir: Path,
    instance_id: str,
) -> SafeTargetValidation:
    """Run every validator; ``validated_safe`` becomes true only on success."""
    repo_root = Path(repo_root)
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    updated: list[SafeTargetContract] = []
    details: list[dict[str, Any]] = []
    git_validators: list[SafeTargetContract] = []
    copy_validators: list[SafeTargetContract] = []
    for contract in contracts:
        if contract.proof_method == SafeTargetProofMethod.FIX_COMMIT_PATH:
            git_validators.append(contract)
        else:
            copy_validators.append(contract)

    def record(contract: SafeTargetContract, outcomes: list[Any]) -> SafeTargetContract:
        passed = bool(outcomes) and all(item.passed for item in outcomes)
        entry = {
            "safe_target_id": contract.safe_target_id,
            "proof_method": contract.proof_method.value,
            "commands": [outcome_details(item) for item in outcomes],
            "validated_safe": passed,
        }
        details.append(entry)
        if not passed:
            return contract.model_copy(
                update={"validated_safe": False, "validation_log_sha256": None}
            )
        return contract.model_copy(
            update={
                "validated_safe": True,
                "validation_log_sha256": _log_digest([entry]),
                "validated_at": utc_now_iso(),
            }
        )

    # Git-backed validators need the real history, so they run in the worktree
    # and are restricted to read-only git plumbing by construction.
    for contract in git_validators:
        used: set[str] = set()
        outcomes = []
        for command in contract.validator_commands:
            outcomes.append(
                run_validation_command(
                    command,
                    repo_root=repo_root,
                    log_dir=log_dir / contract.safe_target_id,
                    name=command.name,
                    network_allowed=False,
                    used_names=used,
                )
            )
        updated.append(record(contract, outcomes))

    for contract in copy_validators:
        outcomes, _ = run_commands_in_copy(
            loaded,
            repo_root,
            contract.validator_commands,
            label=f"{instance_id}-safetarget-{contract.safe_target_id}"[:100],
            log_dir=log_dir / contract.safe_target_id,
        )
        updated.append(record(contract, outcomes))

    payload = {
        "instance_id": instance_id,
        "validated_at": utc_now_iso(),
        "contracts": details,
        "log_sha256": _log_digest(details),
    }
    log_path = log_dir / "safe_target_validation.json"
    log_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return SafeTargetValidation(
        contracts=updated,
        details=details,
        log_sha256=payload["log_sha256"],
        log_path=log_path,
    )


def safe_target_status(contract: SafeTargetContract) -> CheckStatus:
    return CheckStatus.PASS if contract.validated_safe else CheckStatus.FAIL


def build_safe_target_location(contract: SafeTargetContract) -> CodeLocation:
    return contract.location


def preselect_safe_target_id(
    oracle: CanonicalVulnerabilityOracle, repo_root: Path
) -> str | None:
    """Deterministically pre-select the one safe target an FP variant will bind.

    Only *declaration* checks are performed here (CWE presence, file/line span,
    validator availability), so the choice is available before the variant
    instance id is derived and is independent of execution outcomes.  If this
    target later fails its executable validator the candidate is rejected
    instead of silently switching to another safe target (P0-5 #3).
    """
    accepted = prepare_safe_targets(oracle, repo_root).accepted
    ids = sorted(item.safe_target_id for item in accepted)
    return ids[0] if ids else None


def select_safe_targets(
    contracts: list[SafeTargetContract],
    *,
    code_only: bool = False,
    requested: set[str] | None = None,
) -> list[SafeTargetContract]:
    """Validated safe targets, optionally restricted to the *bound* one (P0-5).

    ``requested`` is the target set recorded in the manipulation spec.  When it
    names a target, no other validated safe target may be substituted: a
    candidate either attacks the declared target or is rejected.
    """
    from ..generation.context import is_code

    selected = [item for item in contracts if item.validated_safe]
    if requested:
        selected = [item for item in selected if item.safe_target_id in requested]
    if code_only:
        selected = [item for item in selected if is_code(item.file)]
    return sorted(selected, key=lambda item: item.safe_target_id)
