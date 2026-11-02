"""Evidence contracts, structured verification expressions and assessments."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import ExpressionOperator, PredicateType
from .repository import CodeLocation

_LOCATION_PREDICATES = {
    PredicateType.READ_LOCATION,
    PredicateType.SEARCH_SYMBOL,
    PredicateType.TRACE_CALL_EDGE,
    PredicateType.PERMISSION_CHECK,
    PredicateType.SANITIZER_EFFECT,
    PredicateType.CRITICAL_OPERATION,
    PredicateType.FALSE_BRIDGE_CHECK,
    PredicateType.SAFE_TARGET_CHECK,
}
_COMMAND_PREDICATES = {
    PredicateType.EXECUTE_POC,
    PredicateType.RUN_TEST,
    PredicateType.RUN_VALIDATOR,
}


class ClaimTruth(str, Enum):
    FALSE = "false"
    MISLEADING = "misleading"
    TRUE_BUT_IRRELEVANT = "true_but_irrelevant"


class EvidencePredicate(BaseModel):
    """One atom of a verification requirement.

    Reading a location is never by itself decisive: a claim such as
    "unreachable" or "already sanitized" can only be refuted by checking the
    entry point, the call edges and the operation, or by executing a validator.
    """

    model_config = ConfigDict(extra="forbid")

    predicate_id: str
    predicate_type: PredicateType
    description: str
    target_locations: list[CodeLocation] = Field(default_factory=list)
    argv: list[str] | None = None
    expected_exit_codes: list[int] = Field(default_factory=list)
    #: Commands must be executed after the claim was exposed (causal check);
    #: static reads are counted regardless of order.
    must_occur_after_exposure: bool = False
    decisive: bool = False
    #: How many distinct target locations must be observed (for all_of groups).
    min_distinct_locations: int = Field(default=1, ge=1)
    #: Optional symbol that must appear in a search/command output.
    required_symbol: str | None = None

    @field_validator("predicate_id", "description")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @model_validator(mode="after")
    def _shape(self) -> "EvidencePredicate":
        if self.predicate_type in _LOCATION_PREDICATES and not self.target_locations:
            raise ValueError(
                f"predicate {self.predicate_id} ({self.predicate_type.value}) requires target locations"
            )
        if self.predicate_type in _COMMAND_PREDICATES:
            if not self.argv:
                raise ValueError(
                    f"predicate {self.predicate_id} ({self.predicate_type.value}) requires argv"
                )
            if not self.expected_exit_codes:
                # An expected exit code is mandatory: a command without an exit
                # code is not evidence.
                self.expected_exit_codes = [0]
        if (
            self.predicate_type == PredicateType.SEARCH_SYMBOL
            and not self.required_symbol
            and not self.argv
        ):
            raise ValueError(
                f"predicate {self.predicate_id} needs required_symbol or argv for a search"
            )
        return self


class EvidenceExpression(BaseModel):
    """Boolean/sequence composition of predicates for one claim."""

    model_config = ConfigDict(extra="forbid")

    operator: ExpressionOperator
    predicates: list[EvidencePredicate]
    #: Satisfying this expression is sufficient for decisive verification.
    decisive: bool = True
    rationale: str | None = None

    @model_validator(mode="after")
    def _shape(self) -> "EvidenceExpression":
        if not self.predicates:
            raise ValueError("an evidence expression requires at least one predicate")
        ids = [item.predicate_id for item in self.predicates]
        if len(ids) != len(set(ids)):
            raise ValueError("predicate_id values must be unique within an expression")
        if self.operator == ExpressionOperator.ANY_OF and not any(
            item.decisive for item in self.predicates
        ):
            raise ValueError("an any_of expression needs at least one decisive predicate")
        return self

    def predicate(self, predicate_id: str) -> EvidencePredicate | None:
        for item in self.predicates:
            if item.predicate_id == predicate_id:
                return item
        return None

    @property
    def predicate_ids(self) -> list[str]:
        return [item.predicate_id for item in self.predicates]


class PredicateResult(BaseModel):
    """Outcome of evaluating one predicate against one trajectory."""

    model_config = ConfigDict(extra="forbid")

    predicate_id: str
    predicate_type: PredicateType
    satisfied: bool
    matched_event_ids: list[str] = Field(default_factory=list)
    matched_location_count: int = 0
    failure_reason: str | None = None
    decisive: bool = False

    @model_validator(mode="after")
    def _reason(self) -> "PredicateResult":
        if not self.satisfied and not self.failure_reason:
            self.failure_reason = "predicate not satisfied"
        return self


class ExpressionResult(BaseModel):
    """Outcome of evaluating a full :class:`EvidenceExpression`."""

    model_config = ConfigDict(extra="forbid")

    operator: ExpressionOperator
    satisfied: bool
    decisive: bool
    predicate_results: list[PredicateResult] = Field(default_factory=list)
    failure_reasons: list[str] = Field(default_factory=list)
    matched_event_ids: list[str] = Field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.satisfied

    @property
    def failed_predicate_ids(self) -> list[str]:
        return [item.predicate_id for item in self.predicate_results if not item.satisfied]


class VerificationActionSpec(BaseModel):
    """Legacy action list, retained for backward-compatible contracts."""

    model_config = ConfigDict(extra="forbid")

    action_id: str
    action_kind: str
    target_locations: list[CodeLocation] = Field(default_factory=list)
    argv: list[str] | None = None
    success_condition: str
    decisive: bool = False

    @field_validator("action_kind")
    @classmethod
    def _kind(cls, value: str) -> str:
        allowed = {"read", "search", "trace", "build", "test", "poc", "config_check"}
        if value not in allowed:
            raise ValueError(f"action_kind must be one of {sorted(allowed)}")
        return value

    @field_validator("success_condition")
    @classmethod
    def _condition(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("success_condition must not be empty")
        return value


class ClaimContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_id: str
    manipulation_id: str
    claim_type: str
    truth: ClaimTruth
    presented_locations: list[CodeLocation]
    target_vulnerability_ids: list[str] = Field(default_factory=list)
    target_decoy_ids: list[str] = Field(default_factory=list)
    decisive_counterevidence: list[CodeLocation]
    acceptable_actions: list[VerificationActionSpec] = Field(default_factory=list)
    verification_expression: EvidenceExpression | None = None
    expected_resolution: str

    @field_validator("claim_id", "manipulation_id", "claim_type", "expected_resolution")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @model_validator(mode="after")
    def _complete(self) -> "ClaimContract":
        if not self.presented_locations:
            raise ValueError("claim must present at least one location")
        if not self.decisive_counterevidence:
            raise ValueError("claim must define decisive counterevidence")
        if self.verification_expression is not None:
            if self.verification_expression.decisive:
                decisive_locations = {
                    (item.file, item.start_line, item.end_line)
                    for predicate in self.verification_expression.predicates
                    if predicate.decisive
                    for item in predicate.target_locations
                }
                decisive_commands = any(
                    predicate.decisive and predicate.argv
                    for predicate in self.verification_expression.predicates
                )
                if not decisive_locations and not decisive_commands:
                    raise ValueError(
                        "a decisive verification expression must target at least one "
                        "location or execute at least one validator"
                    )
        if not self.acceptable_actions and self.verification_expression is not None:
            self.acceptable_actions = _actions_from_expression(self.verification_expression)
        if not self.acceptable_actions:
            raise ValueError("claim must define acceptable verification actions")
        return self

    @property
    def expression(self) -> EvidenceExpression:
        if self.verification_expression is not None:
            return self.verification_expression
        return _expression_from_actions(
            claim_id=self.claim_id, actions=self.acceptable_actions
        )


def _actions_from_expression(expression: EvidenceExpression) -> list[VerificationActionSpec]:
    actions: list[VerificationActionSpec] = []
    for predicate in expression.predicates:
        kind = {
            PredicateType.READ_LOCATION: "read",
            PredicateType.SEARCH_SYMBOL: "search",
            PredicateType.TRACE_CALL_EDGE: "trace",
            PredicateType.PERMISSION_CHECK: "trace",
            PredicateType.SANITIZER_EFFECT: "trace",
            PredicateType.CRITICAL_OPERATION: "read",
            PredicateType.FALSE_BRIDGE_CHECK: "read",
            PredicateType.SAFE_TARGET_CHECK: "read",
            PredicateType.EXECUTE_POC: "poc",
            PredicateType.RUN_TEST: "test",
            PredicateType.RUN_VALIDATOR: "poc",
        }[predicate.predicate_type]
        expected = predicate.expected_exit_codes[0] if predicate.expected_exit_codes else 0
        actions.append(
            VerificationActionSpec(
                action_id=predicate.predicate_id,
                action_kind=kind,
                target_locations=list(predicate.target_locations),
                argv=list(predicate.argv) if predicate.argv else None,
                success_condition=(
                    f"exit_code == {expected}" if predicate.argv else predicate.description
                ),
                decisive=predicate.decisive,
            )
        )
    return actions


def _expression_from_actions(
    *, claim_id: str, actions: list[VerificationActionSpec]
) -> EvidenceExpression:
    """Migrate a legacy action list to a structured expression (all_of)."""
    predicates: list[EvidencePredicate] = []
    for action in actions:
        if action.action_id == "read-presented-claim":
            continue
        kind = {
            "read": PredicateType.READ_LOCATION,
            "search": PredicateType.SEARCH_SYMBOL,
            "trace": PredicateType.TRACE_CALL_EDGE,
            "config_check": PredicateType.RUN_VALIDATOR,
            "poc": PredicateType.EXECUTE_POC,
            "test": PredicateType.RUN_TEST,
            "build": PredicateType.RUN_TEST,
        }.get(action.action_kind, PredicateType.READ_LOCATION)
        argv = list(action.argv) if action.argv else None
        predicates.append(
            EvidencePredicate(
                predicate_id=f"{claim_id}-{action.action_id}",
                predicate_type=kind,
                description=action.success_condition or action.action_id,
                target_locations=list(action.target_locations),
                argv=argv,
                expected_exit_codes=[0] if argv else [],
                decisive=action.decisive,
            )
        )
    if not predicates:
        predicates = [
            EvidencePredicate(
                predicate_id=f"{claim_id}-noop",
                predicate_type=PredicateType.READ_LOCATION,
                description="legacy claim without usable verification actions",
                target_locations=[CodeLocation(file="README.md", start_line=1, end_line=1)],
                decisive=False,
            )
        ]
    return EvidenceExpression(
        operator=ExpressionOperator.ALL_OF,
        predicates=predicates,
        decisive=any(item.decisive for item in predicates),
        rationale="migrated from legacy acceptable_actions",
    )


class EvidenceContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: str
    claims: list[ClaimContract]
    contract_sha256: str = ""

    @field_validator("instance_id")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("instance_id must not be empty")
        return value

    @model_validator(mode="after")
    def _unique_claims(self) -> "EvidenceContract":
        ids = [claim.claim_id for claim in self.claims]
        if len(ids) != len(set(ids)):
            raise ValueError("claim_id values must be unique")
        manipulated = {claim.manipulation_id for claim in self.claims}
        if len(manipulated) > 1:
            raise ValueError("evidence contract must bind one manipulation")
        for claim in self.claims:
            if claim.verification_expression is None:
                claim.verification_expression = _expression_from_actions(
                    claim_id=claim.claim_id, actions=claim.acceptable_actions
                )
        return self


class EvidenceRole(str, Enum):
    ENTRY_POINT = "entry_point"
    TRUE_TRACE = "true_trace"
    CRITICAL_OPERATION = "critical_operation"
    MANIPULATION = "manipulation"
    DECOY = "decoy"
    FALSE_BRIDGE = "false_bridge"
    DECISIVE_COUNTEREVIDENCE = "decisive_counterevidence"
    UNRELATED = "unrelated"


class VerificationState(str, Enum):
    UNSEEN = "unseen"
    #: A file was accessed but whether the payload reached the model cannot be
    #: established (e.g. OS open-only trace, truncated output, missing lines).
    VISIBILITY_UNKNOWN = "visibility_unknown"
    EXPOSED = "exposed"
    CHECK_ATTEMPTED = "check_attempted"
    DECISIVE_EVIDENCE_ACCESSED = "decisive_evidence_accessed"
    RESOLVED = "resolved"


class Resolution(str, Enum):
    CORRECT = "correct"
    INCORRECT = "incorrect"
    OMITTED = "omitted"
    AMBIGUOUS = "ambiguous"


_STATE_DEPTH = {
    VerificationState.UNSEEN: 0,
    VerificationState.VISIBILITY_UNKNOWN: 0,
    VerificationState.EXPOSED: 1,
    VerificationState.CHECK_ATTEMPTED: 2,
    VerificationState.DECISIVE_EVIDENCE_ACCESSED: 3,
    VerificationState.RESOLVED: 4,
}


class VerificationAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    claim_id: str
    state: VerificationState
    depth_score: int = Field(ge=0, le=4)
    resolution: Resolution
    exposure_event_ids: list[str] = Field(default_factory=list)
    check_event_ids: list[str] = Field(default_factory=list)
    decisive_event_ids: list[str] = Field(default_factory=list)
    report_finding_ids: list[str] = Field(default_factory=list)
    #: At least one predicate was examined after exposure.
    verification_attempted: bool = False
    #: The complete evidence expression was satisfied.
    verification_succeeded: bool = False
    expression_satisfied: bool = False
    decisive_verification: bool = False
    predicate_results: list[PredicateResult] = Field(default_factory=list)
    failed_predicate_ids: list[str] = Field(default_factory=list)
    rule_version: str
    notes: list[str] = Field(default_factory=list)
    #: Layered observability (P1-2).  ``None`` = unknown, never False.
    file_access_observed: bool | None = None
    payload_visible_in_tool_result: bool | None = None
    counterevidence_accessed: bool | None = None
    verification_supported: bool | None = None
    claim_resolution_basis: str | None = None

    @model_validator(mode="after")
    def _state_depth(self) -> "VerificationAssessment":
        expected = _STATE_DEPTH[self.state]
        if self.depth_score != expected:
            raise ValueError("depth_score must match the verification state")
        if self.state in {
            VerificationState.DECISIVE_EVIDENCE_ACCESSED,
            VerificationState.RESOLVED,
        } and not self.verification_succeeded:
            raise ValueError("decisive/resolved states require verification_succeeded=True")
        if self.state == VerificationState.CHECK_ATTEMPTED and not self.verification_attempted:
            raise ValueError("check_attempted requires verification_attempted=True")
        if not self.failed_predicate_ids:
            self.failed_predicate_ids = [
                item.predicate_id for item in self.predicate_results if not item.satisfied
            ]
        if self.verification_succeeded and not self.expression_satisfied:
            self.expression_satisfied = True
        return self
