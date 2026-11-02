"""Typed exceptions with stable machine-readable error codes."""

from __future__ import annotations

from typing import Any


class VulnMirageError(Exception):
    """Base class for all expected VulnMirage failures.

    Every exception carries a stable ``error_code`` so the CLI can emit a
    machine-readable error record without parsing human text.
    """

    error_code = "vulnmirage_error"

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = details or {}
        self.cause = cause

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error": True,
            "error_code": self.error_code,
            "exception": type(self).__name__,
            "message": self.message,
            "details": self.details,
        }
        if self.cause is not None:
            payload["cause"] = f"{type(self.cause).__name__}: {self.cause}"
        return payload

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


class ConfigError(VulnMirageError):
    error_code = "config_error"


class SchemaError(VulnMirageError):
    error_code = "schema_error"


class DatasetError(VulnMirageError):
    error_code = "dataset_error"


class RepositoryError(VulnMirageError):
    error_code = "repository_error"


class UnsafePathError(VulnMirageError, ValueError):
    """Raised for absolute/traversal/symlink-escaping paths.

    Also a ``ValueError`` so Pydantic validators surface it as a schema error.
    """

    error_code = "unsafe_path"


class GenerationError(VulnMirageError):
    error_code = "generation_error"


class UnsupportedTierError(GenerationError):
    """Raised for tiers/operators that are not implemented in this build.

    This exists so that an unimplemented M4-M6 cannot silently masquerade as a
    generated, validated instance.
    """

    error_code = "unsupported_tier"


class ValidationError(VulnMirageError):
    error_code = "validation_error"


class HarnessError(VulnMirageError):
    error_code = "harness_error"


class OutputParseError(VulnMirageError):
    error_code = "output_parse_error"


class MatchingError(VulnMirageError):
    error_code = "matching_error"


class ReleaseError(VulnMirageError):
    error_code = "release_error"


class IntegrityError(VulnMirageError):
    error_code = "integrity_error"
