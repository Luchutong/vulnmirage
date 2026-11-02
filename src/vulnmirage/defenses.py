"""Composable defense conditions (P1-1).

The base audit task, the finding output schema and the defense instructions are
kept separate.  The harness composes base task + defense instructions *outside*
the audited repository; a repository payload can never override or disable a
defense.  Switching D0/D1/D2 only changes the appended instruction text and is
recorded in the execution-condition identity.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import DefenseConditionConfig, LoadedConfig
from .errors import ConfigError
from .hashing import sha256_text


@dataclass(frozen=True)
class ResolvedDefense:
    spec: DefenseConditionConfig
    instructions: str
    instructions_sha256: str
    base_prompt_sha256: str | None = None

    @property
    def id(self) -> str:
        return self.spec.id

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def version(self) -> str:
        return self.spec.version

    @property
    def identity(self) -> dict[str, object]:
        """Content identity, independent of the configured *name*.

        Two configurations that produce identical instructions share identity;
        renaming D1 does not create a new condition.
        """
        return {
            "id": self.spec.id,
            "name": self.spec.name,
            "version": self.spec.version,
            "instructions_sha256": self.instructions_sha256,
            "runtime_evidence_gate": bool(self.spec.implements_runtime_evidence_gate),
        }

    def compose(self, base_prompt: str) -> str:
        base = base_prompt.replace("\r\n", "\n").replace("\r", "\n").rstrip() + "\n"
        if not self.instructions.strip():
            return base
        instructions = (
            self.instructions.replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
        )
        return f"{base}\n{instructions}"


def resolve_defense(loaded: LoadedConfig, defense_id: str | None = None) -> ResolvedDefense:
    wanted = defense_id or loaded.config.defense.default
    spec = next(
        (item for item in loaded.config.defense.conditions if item.id == wanted),
        None,
    )
    if spec is None:
        raise ConfigError(
            f"unknown defense condition {wanted!r}",
            details={
                "available": [item.id for item in loaded.config.defense.conditions]
            },
        )
    instructions = ""
    if spec.instructions_file:
        path = loaded.resolve_asset(spec.instructions_file)
        instructions = path.read_text(encoding="utf-8")
        if not instructions.strip():
            raise ConfigError(
                f"defense instructions file is empty: {path}",
                details={"defense_id": spec.id},
            )
    return ResolvedDefense(
        spec=spec,
        instructions=instructions,
        instructions_sha256=sha256_text(instructions),
    )


def compose_task(
    loaded: LoadedConfig,
    base_prompt: str,
    defense: ResolvedDefense,
) -> tuple[str, dict[str, str]]:
    """Return ``(effective_prompt, hashes)`` used by the harness and runner."""
    effective = defense.compose(base_prompt)
    hashes = {
        "base_prompt_sha256": sha256_text(base_prompt),
        "defense_instructions_sha256": defense.instructions_sha256,
        "effective_prompt_sha256": sha256_text(effective),
    }
    return effective, hashes
