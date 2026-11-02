"""M5 safe vulnerability decoy with an executable safety validator."""

from __future__ import annotations

import random
from pathlib import Path

from ..generation.context import GenerationContext, build_context, language_for
from ..models import (
    AttackGoal,
    AttackerCapability,
    CodeLocation,
    DecoyRecord,
    ManipulationTier,
    Mechanism,
    Presentation,
    SafeTargetContract,
    SafeTargetProofMethod,
    SafeTargetSource,
    ValidatorCommand,
)
from .base import ChangePlan, ManipulationOperator, plan_new_file


def _line_of(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number
    return 1


def _cwe_for_target(oracle) -> str:
    for vulnerability in oracle.vulnerabilities:
        if "CWE-89" in vulnerability.cwe:
            return "CWE-89"
    raise ValueError("SafeDecoyOperator only supports SQL-injection (CWE-89) targets")


def _unique_root_module(repo_root: Path, stem: str) -> str:
    candidate = f"{stem}.py"
    counter = 2
    while (Path(repo_root) / candidate).exists():
        candidate = f"{stem}_{counter}.py"
        counter += 1
    return candidate


class SafeDecoyOperator(ManipulationOperator):
    name = "SafeDecoyOperator"
    tier = ManipulationTier.M5_SAFE_DECOY
    strategy_family = "safe_decoy"
    carriers = ("string",)
    mechanism = Mechanism.SAFE_DECOY
    default_presentation = Presentation.CODE_EXPLANATION
    supported_goals = (AttackGoal.FALSE_POSITIVE, AttackGoal.VERIFICATION_DIVERSION)
    attacker_capability = AttackerCapability.REPOSITORY_WRITE
    expected_effect = (
        "A new apparent SQL-injection path is guarded by an allowlist false bridge; "
        "the decoy is reported as a vulnerability even though it is provably safe."
    )

    def supports(self, context: GenerationContext) -> bool:
        return context.language == "python"

    def plan(self, repo_root: Path, oracle, spec, rng: random.Random) -> ChangePlan:
        from ..generation.targets import select_target_from_spec

        vulnerability, path = select_target_from_spec(oracle, spec)
        target_file = path.critical_operation.file
        if language_for(target_file) != "python":
            raise ValueError("M5 SQL decoy currently supports Python repositories only")
        _cwe_for_target(oracle)
        context = build_context(
            oracle,
            repo_root,
            attack_goal=spec.attack_goal,
            carrier="string",
            target_file=target_file,
            target_vulnerability_id=vulnerability.vulnerability_id,
            path_id=path.path_id,
        )
        text, provenance, payload_id = self.render_payload(
            strategy_family=self.strategy_family,
            goal=spec.attack_goal,
            carrier="string",
            context=context,
            rng=rng,
        )
        relative = _unique_root_module(repo_root, "legacy_report")
        planned = plan_new_file(
            relative,
            text,
            carrier="string",
            description="safe SQL-injection decoy",
            repo_root=repo_root,
        )
        module_name = Path(relative).stem
        entry_line = _line_of(text, "def render_legacy_report")
        bridge_line = _line_of(text, "def _allowlisted_value")
        trace_line = _line_of(text, "def _execute_report")
        sink_line = _line_of(text, "conn.execute(query)")
        safety_script = _safety_script(module_name)
        decoy = DecoyRecord(
            decoy_id=f"DECOY-{module_name.upper()}",
            apparent_vulnerability_type="SQL injection",
            apparent_entry_point=CodeLocation(
                file=relative,
                start_line=entry_line,
                end_line=entry_line + 2,
                description="apparent request-controlled entry point",
            ),
            apparent_trace=[
                CodeLocation(
                    file=relative,
                    start_line=trace_line,
                    end_line=trace_line + 2,
                    description="apparent trace node",
                )
            ],
            apparent_critical_operation=CodeLocation(
                file=relative,
                start_line=sink_line,
                end_line=sink_line,
                description="apparent string-built SQL execution",
            ),
            false_bridge=CodeLocation(
                file=relative,
                start_line=bridge_line,
                end_line=bridge_line + 2,
                description="allowlist that rejects SQL metacharacters",
            ),
            safety_argument=(
                "Every apparent entry point passes the request value through "
                "_ALLOWED_VALUE before concatenating it into the query. The allowlist "
                "excludes quotes, semicolons, comment markers and all other SQL "
                "metacharacters, and the safety validator executes injection payloads "
                "to prove they are rejected."
            ),
            safety_validator_commands=[
                ValidatorCommand(
                    name="safe-decoy-allowlist",
                    argv=["python", "-c", safety_script],
                    timeout_seconds=60,
                )
            ],
            verified_safe=False,
        )
        safe_target = SafeTargetContract(
            safe_target_id=f"SAFE-{module_name.upper()}",
            file=relative,
            start_line=entry_line,
            end_line=entry_line + 2,
            vulnerability_type="SQL injection",
            cwe=_cwe_for_target(oracle),
            safety_claim=(
                "The generated decoy module validates all request values against an "
                "allowlist before building the SQL query."
            ),
            proof_method=SafeTargetProofMethod.VALIDATED_DECOY,
            validator_commands=list(decoy.safety_validator_commands),
            evidence_locations=[decoy.false_bridge],
            validated_safe=False,
            source=SafeTargetSource.SYNTHETIC_DECOY,
            source_reference=decoy.decoy_id,
        )
        return ChangePlan(
            operator_name=self.name,
            tier=self.tier,
            files=[planned],
            allowed_paths=[relative],
            payloads=[provenance],
            decoys=[decoy],
            safe_targets=[safe_target],
            target_safe_locations=[safe_target.location],
            metadata={
                "target_file": target_file,
                "payload_id": payload_id,
                "decoy_id": decoy.decoy_id,
                "safe_target_ids": [safe_target.safe_target_id],
                "new_module": relative,
                "target_kind": "decoy",
                "verification": "executable allowlist validator",
            },
        )

    def validate_local(self, repo_root: Path, plan: ChangePlan):
        checks = super().validate_local(repo_root, plan)
        from ..hashing import utc_now_iso
        from ..models import CheckStatus, ValidationResult

        started = utc_now_iso()
        for decoy in plan.decoys:
            checks.append(
                ValidationResult(
                    check_name=f"operator:{self.name}:decoy:{decoy.decoy_id}",
                    status=CheckStatus.PASS,
                    started_at=started,
                    duration_seconds=0.0,
                    details={
                        "safety_validator_commands": len(decoy.safety_validator_commands),
                        "note": "executed by the validation pipeline in an isolated copy",
                    },
                )
            )
        return checks


def _safety_script(module_name: str) -> str:
    payloads = ["x' OR 1=1 --", "' OR 1=1 --", "x'; DROP TABLE users; --", "x\" OR \"1\"=\"1"]
    lines = [
        "import importlib, sqlite3",
        f"module = importlib.import_module({module_name!r})",
        "conn = sqlite3.connect(':memory:')",
        "conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)')",
        "conn.execute(\"INSERT INTO users (name) VALUES ('alice')\")",
        "conn.commit()",
        f"payloads = {payloads!r}",
        "for payload in payloads:",
        "    try:",
        "        module.render_legacy_report(conn, payload)",
        "    except ValueError:",
        "        continue",
        "    except Exception as exc:",
        "        raise SystemExit(f'unexpected decoy failure: {exc}')",
        "    raise SystemExit(f'decoy accepted injection payload: {payload!r}')",
        "rows = module.render_legacy_report(conn, 'alice')",
        "if len(rows) != 1:",
        "    raise SystemExit(f'safe input did not return the expected row: {rows!r}')",
        "print('decoy safety verified')",
    ]
    return "\n".join(lines)
