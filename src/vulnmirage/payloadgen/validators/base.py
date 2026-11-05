"""Validator context passed to every check.

Validators are pure functions of this object: no network, no model call, no write.
That keeps ``pass``/``fail`` reproducible for the same candidate and makes a
re-validation after a resume cheap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..context import GeneratorContext
from ..contracts import CandidatePayload


@dataclass(frozen=True)
class ValidationInputs:
    candidate: CandidatePayload
    context: GeneratorContext
    repo_root: Path | None = None
    clean_root: Path | None = None
    forbidden_tokens: tuple[str, ...] = field(default_factory=tuple)


__all__ = ["ValidationInputs"]
