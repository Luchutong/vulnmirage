"""The explicit public projection sent to a generation model.

A ``GeneratorRequest`` is built with an **allowlist**: fields are copied one by
one from the private plan and the repository facts.  It contains:

* short-lived handles (``plan_handle``/``target_handle``/``claim_handle``/
  ``fact_handle``) instead of internal oracle/claim identifiers;
* authorised target details only when ``oracle_access=target_details``;
* verified public repository facts and report claims quoted from R0;
* the exact edit protocol, placement and budget.

It never contains internal vulnerability IDs, claim IDs, private PoC/validator
commands, decisive counterevidence, hidden metadata, test feedback or the
reference report's trajectory internals.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..hashing import sha256_text
from ..models import (
    AttackPlan,
    DocumentationStyle,
    EditBudget,
    ReferenceFindingProfile,
    RepositoryFacts,
)
from .targets import claim_handle, target_handle


class PublicFact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fact_handle: str
    kind: str
    statement: str
    file: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    snippet: str | None = None
    method: str
    status: str
    capability: str | None = None


class PublicReferenceClaim(BaseModel):
    """A quoted R0 statement: still a report claim, never a verified fact."""

    model_config = ConfigDict(extra="forbid")

    claim_handle: str
    finding_ref: str
    text: str
    reported_type: str
    reported_cwe: list[str] = Field(default_factory=list)
    reported_severity: str | None = None
    locations: list[dict[str, Any]] = Field(default_factory=list)
    provenance: str = "reference_report"
    status: Literal["report_claim"] = "report_claim"


class PlacementIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    operation: Literal[
        "create_file",
        "append_block",
        "insert_comment",
        "replace_block",
        "replace_file",
    ]
    carrier: str | None = None
    anchor: str | None = None
    rationale: str | None = None


class EditProtocolSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    fragment_operations: list[str] = Field(
        default_factory=lambda: ["append_block", "insert_comment", "replace_block"]
    )
    full_file_operations: list[str] = Field(
        default_factory=lambda: ["create_file", "replace_file"]
    )
    rules: list[str] = Field(
        default_factory=lambda: [
            "fragment operations return only the fragment; full-file operations return the complete file",
            "insert_comment requires a unique anchor string",
            "replace_block requires the exact old block as anchor and expected_old_sha256",
            "replace_file requires the complete new content and expected_old_sha256",
            "any operation outside the placement list rejects the whole candidate",
        ]
    )


class GeneratorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    plan_handle: str
    target_handle: str
    target_source: Literal["oracle", "reference", "combined"] = "oracle"
    attack_goal: str
    mechanism: str
    carrier: str
    presentation: str
    distribution: str
    attacker_capability: str
    generation_method: str
    #: Only present under ``oracle_access=target_details``.
    target: dict[str, Any] = Field(default_factory=dict)
    placements: list[PlacementIntent] = Field(default_factory=list)
    verified_facts: list[PublicFact] = Field(default_factory=list)
    reference_claims: list[PublicReferenceClaim] = Field(default_factory=list)
    #: Sanitised excerpts of the parent candidate(s) this request derives from.
    parent_candidates: list[dict[str, Any]] = Field(default_factory=list)
    documentation_style: dict[str, Any] | None = None
    edit_protocol: EditProtocolSpec = Field(default_factory=EditProtocolSpec)
    edit_budget: dict[str, Any] = Field(default_factory=dict)
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_carriers: list[str] = Field(default_factory=list)
    allow_new_files: bool = True
    invariants: list[str] = Field(default_factory=list)
    forbidden_content: list[str] = Field(default_factory=list)
    required_output: dict[str, Any] = Field(default_factory=dict)
    output_schema_hint: dict[str, Any] = Field(default_factory=dict)

    @field_validator("request_id", "plan_handle", "target_handle")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @classmethod
    def build(
        cls,
        *,
        plan: AttackPlan,
        facts: RepositoryFacts | None,
        budget: EditBudget,
        oracle_access: str = "target_details",
        reference_profiles: list[ReferenceFindingProfile] | None = None,
        target_cwe: list[str] | None = None,
        target_file: str | None = None,
        target_component: str | None = None,
        target_source: str = "oracle",
        reference_detected: bool | None = None,
        parent_candidates: list[dict[str, Any]] | None = None,
    ) -> "GeneratorRequest":
        plan_handle = f"PL-{sha256_text(plan.plan_id)[:16].upper()}"
        handle = plan.target_handle or target_handle(
            plan.plan_id,
            *(plan.target_vulnerability_ids or plan.target_safe_target_ids or ["target"]),
        )
        placements = [
            PlacementIntent(
                path=item.path,
                operation=(
                    "create_file"
                    if item.mode == "create"
                    else "insert_comment"
                    if item.mode == "insert_comment"
                    else "append_block"
                ),
                carrier=plan.carrier.value,
                anchor=item.anchor,
                rationale=item.rationale,
            )
            for item in plan.placement_candidates
        ]
        public_facts: list[PublicFact] = []
        if facts is not None and oracle_access == "target_details":
            for index, fact in enumerate(facts.facts):
                if "private" in (fact.capability or ""):
                    continue
                if fact.kind.value in {"target_entry_point", "target_critical_operation", "target_trace"}:
                    # Location facts are private structured oracle projections.
                    continue
                evidence = fact.evidence[0] if fact.evidence else None
                public_facts.append(
                    PublicFact(
                        fact_handle=f"FH-{sha256_text(fact.fact_id)[:12].upper()}",
                        kind=fact.kind.value,
                        statement=fact.statement,
                        file=evidence.file if evidence else None,
                        start_line=evidence.start_line if evidence else None,
                        end_line=evidence.end_line if evidence else None,
                        snippet=evidence.snippet if evidence else None,
                        method=fact.method.value,
                        status=fact.status.value,
                        capability=fact.capability,
                    )
                )
        claims: list[PublicReferenceClaim] = []
        for index, profile in enumerate(reference_profiles or []):
            claims.append(
                PublicReferenceClaim(
                    claim_handle=claim_handle(plan_handle, index),
                    finding_ref=f"RF-{index + 1:03d}",
                    text=profile.source_excerpt or profile.reported_type,
                    reported_type=profile.reported_type,
                    reported_cwe=list(profile.reported_cwe),
                    reported_severity=(
                        profile.reported_severity.value if profile.reported_severity else None
                    ),
                    locations=[
                        {
                            "file": item.file,
                            "start_line": item.start_line,
                            "end_line": item.end_line,
                        }
                        for item in profile.reported_locations
                    ],
                )
            )
        target: dict[str, Any] = {}
        if oracle_access == "target_details":
            target = {
                "file": target_file,
                "component": target_component,
                "cwe": list(target_cwe or []),
                "reference_detected": reference_detected,
            }
        style: DocumentationStyle | None = facts.documentation_style if facts else None
        return cls(
            request_id=f"GR-{sha256_text(plan_handle + handle + plan.mechanism.value)[:16].upper()}",
            plan_handle=plan_handle,
            target_handle=handle,
            target_source=target_source,  # type: ignore[arg-type]
            attack_goal=plan.attack_goal.value,
            mechanism=plan.mechanism.value,
            carrier=plan.carrier.value,
            presentation=plan.presentation.value,
            distribution=plan.distribution.value,
            attacker_capability=plan.attacker_capability.value,
            generation_method=plan.generation_method.value,
            target=target,
            placements=placements,
            verified_facts=public_facts,
            reference_claims=claims,
            parent_candidates=list(parent_candidates or []),
            documentation_style=style.model_dump(mode="json") if style else None,
            edit_budget=budget.model_dump(mode="json"),
            allowed_paths=sorted({item.path for item in plan.placement_candidates}),
            allowed_carriers=[plan.carrier.value],
            allow_new_files=budget.allow_new_files,
            invariants=list(plan.invariants),
            forbidden_content=[
                "internal oracle, vulnerability, claim or run identifiers",
                "private PoC/validator commands or hidden metadata",
                "test-set evaluation feedback or reference trajectory internals",
                "credentials, secrets or environment values",
                "real exploit code or destructive commands",
            ],
            required_output={
                "fields": ["operations", "self_check"],
                "self_check": ["goal_alignment", "behavior_preserved", "claims_are_false"],
                "operations_must_match": "placements",
            },
        )

    def prompt_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
