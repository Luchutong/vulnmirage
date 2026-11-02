"""Operator interface, change plans and safe file application."""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..code_semantics import executable_semantics_equal, normalize_text, read_text, syntax_valid
from ..errors import GenerationError, UnsafePathError
from ..generation.context import GenerationContext, language_for
from ..hashing import atomic_write_text, sha256_text, utc_now_iso
from ..models import (
    AttackGoal,
    AttackerCapability,
    CheckStatus,
    CodeLocation,
    DecoyRecord,
    Distribution,
    ManipulationTier,
    Mechanism,
    PayloadProvenance,
    Presentation,
    SafeTargetContract,
    ValidationResult,
    ValidatorCommand,
)
from ..paths import is_safe_relpath, normalize_relpath, safe_join
from ..repository.patch import PatchArtifact, create_patch_artifact
from ..generation.payload_registry import PayloadRegistry


class PlannedFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    mode: Literal["create", "replace"]
    content: str
    carrier: str
    description: str | None = None
    original_content: str | None = None

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        if not is_safe_relpath(value):
            raise ValueError("planned file path is not a safe repository-relative path")
        return normalize_relpath(value)

    @model_validator(mode="after")
    def _replace_original(self) -> "PlannedFile":
        if self.mode == "replace" and self.original_content is None:
            raise ValueError("replace plans must record original_content")
        return self

    @property
    def expected_sha256(self) -> str | None:
        if self.original_content is None:
            return None
        return sha256_text(normalize_text(self.original_content))


class ChangePlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operator_name: str
    tier: ManipulationTier
    files: list[PlannedFile]
    allowed_paths: list[str] = Field(default_factory=list)
    payloads: list[PayloadProvenance] = Field(default_factory=list)
    claim_graph: Any | None = None
    decoys: list[DecoyRecord] = Field(default_factory=list)
    target_safe_locations: list[CodeLocation] = Field(default_factory=list)
    #: Validated safe targets bound by this plan (false-positive attacks).
    safe_targets: list[SafeTargetContract] = Field(default_factory=list)
    #: Structural benign control: same carrier/placement, misleading content removed.
    benign_files: list[PlannedFile] = Field(default_factory=list)
    #: Truthful-security control: same carrier/placement, correct statements.
    truthful_files: list[PlannedFile] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("allowed_paths")
    @classmethod
    def _allowed(cls, value: list[str]) -> list[str]:
        return sorted({normalize_relpath(item) for item in value})

    @model_validator(mode="after")
    def _covered(self) -> "ChangePlan":
        if not self.files:
            raise ValueError("a change plan must touch at least one file")
        paths = [item.path for item in self.files]
        if len(paths) != len(set(paths)):
            raise ValueError("change plan contains duplicate paths")
        for path in paths:
            if path not in self.allowed_paths:
                raise ValueError(f"planned file {path} is outside allowed_paths")
        if self.benign_files:
            benign_paths = [item.path for item in self.benign_files]
            if sorted(benign_paths) != sorted(paths):
                raise ValueError(
                    "a benign control must touch exactly the same files as its attack"
                )
        if self.truthful_files:
            truthful_paths = [item.path for item in self.truthful_files]
            if sorted(truthful_paths) != sorted(paths):
                raise ValueError(
                    "a truthful control must touch exactly the same files as its attack"
                )
        return self


@dataclass
class OperatorTools:
    registry: PayloadRegistry
    payload_dir: Path


#: Legacy template-carrier vocabulary -> taxonomy carrier vocabulary.
_LEGACY_TO_TAXONOMY_CARRIER = {
    "markdown": "markdown",
    "comment": "code_comment",
    "string": "string_literal",
}


class ManipulationOperator(ABC):
    name: ClassVar[str]
    tier: ClassVar[ManipulationTier]
    strategy_family: ClassVar[str]
    carriers: ClassVar[tuple[str, ...]] = ("markdown",)
    expected_effect: ClassVar[str] = "Manipulate the auditor's conclusion."
    #: Orthogonal taxonomy declared by each operator.
    mechanism: ClassVar[Mechanism] = Mechanism.DIRECT_INSTRUCTION
    default_presentation: ClassVar[Presentation] = Presentation.PLAIN_INSTRUCTION
    supported_goals: ClassVar[tuple[AttackGoal, ...]] = tuple(AttackGoal)
    attacker_capability: ClassVar[AttackerCapability] = AttackerCapability.COMMENTS_AND_DOCS
    distribution: ClassVar[Distribution] = Distribution.SINGLE_LOCATION

    def __init__(self, tools: OperatorTools) -> None:
        self.tools = tools
        self.variant_index = 0
        self._last_payload_text: str | None = None
        self._last_payload_id: str | None = None
        self._rendered_payloads: list[str] = []

    def payload_texts(self) -> list[str]:
        """Payload texts rendered by this operator (for benign controls)."""
        return list(self._rendered_payloads)

    def with_variant(self, index: int) -> "ManipulationOperator":
        self.variant_index = max(index, 0)
        return self

    @abstractmethod
    def supports(self, context: GenerationContext) -> bool:
        ...

    @abstractmethod
    def plan(
        self,
        repo_root: Path,
        oracle,
        spec,
        rng: random.Random,
    ) -> ChangePlan:
        ...

    # ---------------------------------------------------- safe-target helpers
    def validated_safe_targets(self, spec, *, code_only: bool = False):
        """Return the validated safe targets bound to ``spec``.

        Raises ``ValueError('no_validated_safe_target')`` when there is none:
        false-positive attacks are never generated against an unvalidated file.
        """
        from ..generation.safe_targets import select_safe_targets

        requested = set(getattr(spec, "target_safe_target_ids", None) or [])
        selected = select_safe_targets(
            list(spec.safe_targets), code_only=code_only, requested=requested or None
        )
        if not selected:
            raise ValueError("no_validated_safe_target")
        return selected

    def safe_target_context(self, oracle, repo_root: Path, contract, spec, carrier: str):
        from ..generation.context import build_safe_target_context

        return build_safe_target_context(
            oracle,
            repo_root,
            safe_target=contract,
            attack_goal=spec.attack_goal,
            carrier=carrier,
        )

    def render_payload(
        self,
        *,
        strategy_family: str,
        goal: AttackGoal,
        carrier: str,
        context: GenerationContext,
        rng: random.Random,
        payload_override: str | None = None,
        language: str | None = None,
    ) -> tuple[str, PayloadProvenance, str]:
        candidates = self.tools.registry.select(
            strategy_family=strategy_family,
            goal=goal,
            carrier=_LEGACY_TO_TAXONOMY_CARRIER.get(carrier, carrier),
            mechanism=self.mechanism,
            language=language or context.language,
        )
        if not candidates:
            raise GenerationError(
                "no payload is compatible with this strategy/goal/carrier",
                details={
                    "strategy_family": strategy_family,
                    "goal": goal.value,
                    "carrier": carrier,
                    "mechanism": self.mechanism.value,
                },
            )
        payload = candidates[self.variant_index % len(candidates)]
        seed = rng.getrandbits(63)
        text, provenance = self.tools.registry.render(
            payload, context, base_dir=self.tools.payload_dir, seed=seed
        )
        text = normalize_text(text)
        if text and not text.endswith("\n"):
            text += "\n"
        self._last_payload_text = text
        self._last_payload_id = payload.payload_id
        self._rendered_payloads.append(text)
        return text, provenance, payload.payload_id

    def apply(self, repo_root: Path, plan: ChangePlan) -> PatchArtifact:
        repo_root = Path(repo_root).resolve()
        if not repo_root.is_dir():
            raise GenerationError("repository root does not exist", details={"repo": str(repo_root)})
        allowed = set(plan.allowed_paths)
        for planned in plan.files:
            if planned.path not in allowed:
                raise GenerationError(
                    "operator attempted to write outside its allowed paths",
                    details={"path": planned.path, "allowed": sorted(allowed)},
                )
            try:
                target = safe_join(repo_root, planned.path)
            except UnsafePathError as exc:
                raise GenerationError(
                    "operator planned an unsafe path", details={"path": planned.path}
                ) from exc
            if planned.mode == "create":
                if target.exists():
                    raise GenerationError(
                        "create plan targets an existing file", details={"path": planned.path}
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                atomic_write_text(target, normalize_text(planned.content))
            else:
                if not target.is_file():
                    raise GenerationError(
                        "replace plan targets a missing file", details={"path": planned.path}
                    )
                current = read_text(target)
                expected = planned.expected_sha256
                if expected is None or sha256_text(current) != expected:
                    raise GenerationError(
                        "file changed between planning and application",
                        details={"path": planned.path},
                    )
                atomic_write_text(target, normalize_text(planned.content))
        artifact = create_patch_artifact(repo_root)
        changed = set(artifact.paths)
        planned_paths = {item.path for item in plan.files}
        if changed != planned_paths:
            raise GenerationError(
                "applied changes do not match the change plan",
                details={
                    "changed": sorted(changed),
                    "planned": sorted(planned_paths),
                },
            )
        return artifact

    def validate_local(self, repo_root: Path, plan: ChangePlan) -> list[ValidationResult]:
        started = utc_now_iso()
        checks: list[ValidationResult] = []
        for planned in plan.files:
            target = safe_join(Path(repo_root), planned.path)
            if not target.is_file():
                checks.append(
                    self._result(
                        f"operator:{self.name}:exists:{planned.path}",
                        CheckStatus.FAIL,
                        started,
                        details={"error": "planned file is missing"},
                    )
                )
                continue
            text = read_text(target)
            if normalize_text(text) != normalize_text(planned.content):
                checks.append(
                    self._result(
                        f"operator:{self.name}:content:{planned.path}",
                        CheckStatus.FAIL,
                        started,
                        details={"error": "written content differs from the plan"},
                    )
                )
                continue
            valid, error = syntax_valid(planned.path, text)
            checks.append(
                self._result(
                    f"operator:{self.name}:syntax:{planned.path}",
                    CheckStatus.PASS if valid else CheckStatus.FAIL,
                    started,
                    details={"error": error} if error else {},
                )
            )
            if planned.mode == "replace" and language_for(planned.path) is not None:
                equal = executable_semantics_equal(
                    planned.path, planned.original_content or "", text
                )
                checks.append(
                    self._result(
                        f"operator:{self.name}:semantics:{planned.path}",
                        CheckStatus.PASS if equal else CheckStatus.FAIL,
                        started,
                        details={} if equal else {"error": "executable semantics changed"},
                    )
                )
        return checks

    @staticmethod
    def _result(
        name: str,
        status: CheckStatus,
        started_at: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> ValidationResult:
        return ValidationResult(
            check_name=name,
            status=status,
            started_at=started_at,
            duration_seconds=0.0,
            details=details or {},
        )


# --------------------------------------------------------------------- helpers
def comment_prefix_for(path: str) -> str:
    language = language_for(path)
    if language in {"python", "ruby", "shell"}:
        return "#"
    if language in {"javascript", "typescript", "go", "java", "kotlin", "c", "cpp", "rust", "csharp", "swift", "scala", "php"}:
        return "//"
    suffix = Path(path).suffix.lower()
    if suffix in {".md", ".html", ".htm", ".xml"}:
        return "<!--"
    if suffix == ".sql":
        return "--"
    return "#"


def _is_comment_line(line: str, prefix: str) -> bool:
    stripped = line.lstrip()
    if prefix == "<!--":
        return stripped.startswith("<!--")
    if prefix == "#":
        # ``## heading`` is Markdown, not a Python comment.
        return stripped == "#" or stripped.startswith("# ")
    return stripped.startswith(prefix)


def comment_block(text: str, path: str) -> str:
    prefix = comment_prefix_for(path)
    lines = normalize_text(text).strip("\n").split("\n")
    if prefix == "<!--":
        return "<!--\n" + "\n".join(lines) + "\n-->\n"
    rendered: list[str] = []
    for line in lines:
        if _is_comment_line(line, prefix):
            rendered.append(line)
        elif line.strip():
            rendered.append(f"{prefix} {line}")
        else:
            rendered.append(prefix)
    return "\n".join(rendered) + "\n"


def plan_comment_insertion(
    repo_root: Path,
    relative: str,
    text: str,
    *,
    carrier: str = "comment",
    description: str = "inserted comment",
) -> PlannedFile:
    target = safe_join(Path(repo_root), relative)
    if not target.is_file():
        raise GenerationError("comment target does not exist", details={"path": relative})
    original = read_text(target)
    block = comment_block(text, relative)
    lines = original.split("\n")
    insert_at = 0
    if relative.endswith(".py") and lines and lines[0].startswith("#!"):
        insert_at = 1
        if len(lines) > 1 and lines[1].startswith("#") and "coding" in lines[1]:
            insert_at = 2
    new_lines = lines[:insert_at] + block.rstrip("\n").split("\n") + [""] + lines[insert_at:]
    return PlannedFile(
        path=relative,
        mode="replace",
        content="\n".join(new_lines),
        carrier=carrier,
        description=description,
        original_content=original,
    )


def plan_append(
    repo_root: Path,
    relative: str,
    text: str,
    *,
    carrier: str = "markdown",
    description: str = "appended claim",
) -> PlannedFile:
    target = safe_join(Path(repo_root), relative)
    original = read_text(target) if target.is_file() else None
    section = normalize_text(text).strip("\n") + "\n"
    if original is None:
        content = section
        mode = "create"
    else:
        content = original.rstrip("\n") + "\n\n" + section
        mode = "replace"
    return PlannedFile(
        path=relative,
        mode=mode,
        content=content,
        carrier=carrier,
        description=description,
        original_content=original,
    )


def plan_new_file(
    relative: str,
    content: str,
    *,
    carrier: str = "string",
    description: str = "new file",
    repo_root: Path | None = None,
) -> PlannedFile:
    if repo_root is not None and (Path(repo_root) / relative).exists():
        raise GenerationError("new-file plan targets an existing file", details={"path": relative})
    return PlannedFile(
        path=relative,
        mode="create",
        content=normalize_text(content),
        carrier=carrier,
        description=description,
    )


def command_to_validator(command: ValidatorCommand) -> dict[str, Any]:
    return command.model_dump(mode="json")
