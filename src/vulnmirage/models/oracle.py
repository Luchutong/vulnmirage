"""Canonical vulnerability oracle models (schema v2)."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..cvss import cvss_version, vector_base_score
from ..paths import normalize_relpath
from ..normalization import normalize_cwe, normalize_severity, severity_from_score
from .enums import (
    AuditDifficulty,
    SafeTargetProofMethod,
    SafeTargetSource,
    SeverityLevel,
    SeveritySourceKind,
    SeverityValidationStatus,
    ValidationLevel,
)
from .repository import CodeLocation, RepositoryRef
from .safe_target import EvaluationEligibility

#: Canonical oracle schema written by this build.
ORACLE_SCHEMA_VERSION = "2.0"
#: Schema versions this build can still read (they are migrated on load).
SUPPORTED_ORACLE_SCHEMA_VERSIONS = ("1.0", "2.0")

_SEVERITY_SCHEMES = {
    "cvss_v2",
    "cvss_v3",
    "cvss_v3.0",
    "cvss_v3.1",
    "cvss_v4",
    "cvss_v4.0",
    "vendor_qualitative",
    "custom_ordinal",
}
_SCORE_TOLERANCE = 0.05


class SeveritySource(BaseModel):
    """Where a severity assessment came from."""

    model_config = ConfigDict(extra="forbid")

    kind: SeveritySourceKind = SeveritySourceKind.UNKNOWN
    reference: str | None = None

    @field_validator("reference")
    @classmethod
    def _reference(cls, value: str | None) -> str | None:
        if value is None:
            return value
        value = value.strip()
        return value or None


class SeverityRecord(BaseModel):
    """Structured, provenance-bearing severity assessment.

    A missing severity is represented by ``VulnerabilityRecord.severity is
    None``; it must never be guessed.  Cases without a reviewed/adjudicated
    severity are excluded from severity-manipulation experiments by
    :class:`~vulnmirage.models.safe_target.EvaluationEligibility`.
    """

    model_config = ConfigDict(extra="forbid")

    scheme: str = "cvss_v3.1"
    level: SeverityLevel
    score: float | None = Field(default=None, ge=0.0, le=10.0)
    vector: str | None = None
    rationale: str
    assumptions: list[str] = Field(default_factory=list)
    source: SeveritySource = Field(default_factory=SeveritySource)
    validation_status: SeverityValidationStatus = SeverityValidationStatus.UNREVIEWED
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    @model_validator(mode="before")
    @classmethod
    def _legacy_fields(cls, data: Any) -> Any:
        """Explicit migration of the v1 ``cvss_score``/``cvss_vector`` fields."""
        if not isinstance(data, dict):
            return data
        values = dict(data)
        if "cvss_score" in values:
            legacy_score = values.pop("cvss_score")
            if values.get("score") is None:
                values["score"] = legacy_score
        if "cvss_vector" in values:
            legacy_vector = values.pop("cvss_vector")
            if values.get("vector") is None:
                values["vector"] = legacy_vector
        # v1 stored a free-form string source.
        source = values.get("source")
        if isinstance(source, str):
            values["source"] = {
                "kind": _source_kind_from_text(source).value,
                "reference": source,
            }
        elif source is None:
            values["source"] = {"kind": SeveritySourceKind.UNKNOWN.value}
        level = values.get("level")
        if level is None and values.get("score") is not None:
            try:
                values["level"] = severity_from_score(float(values["score"])).value
            except (TypeError, ValueError):
                pass
        elif isinstance(level, str):
            try:
                values["level"] = normalize_severity(level).value
            except Exception:
                pass
        return values

    @field_validator("scheme")
    @classmethod
    def _scheme(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in _SEVERITY_SCHEMES:
            raise ValueError(f"severity scheme must be one of {sorted(_SEVERITY_SCHEMES)}")
        return value

    @field_validator("rationale")
    @classmethod
    def _rationale(cls, value: str) -> str:
        if not value.strip():
            raise ValueError(
                "severity rationale is required; a severity without a rationale is not auditable"
            )
        return value

    @field_validator("assumptions")
    @classmethod
    def _assumptions(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value if item and item.strip()]
        return cleaned

    @model_validator(mode="after")
    def _consistency(self) -> "SeverityRecord":
        if self.score is not None and self.level is not None:
            expected = severity_from_score(self.score)
            if expected != self.level:
                raise ValueError(
                    "severity level and score disagree: "
                    f"score {self.score} implies {expected.value}, got {self.level.value}"
                )
        if self.vector:
            computed = vector_base_score(self.vector)
            if computed is not None:
                if self.score is None:
                    # A vector without a score is allowed only for adjudicated records.
                    return self
                if abs(computed - self.score) > _SCORE_TOLERANCE:
                    raise ValueError(
                        "CVSS vector and score disagree: "
                        f"vector {self.vector} computes {computed}, record says {self.score}"
                    )
            elif cvss_version(self.vector) is None:
                raise ValueError(f"unparseable CVSS vector: {self.vector!r}")
            elif self.validation_status not in {
                SeverityValidationStatus.REVIEWED,
                SeverityValidationStatus.ADJUDICATED,
            }:
                raise ValueError(
                    "a CVSS vector whose score cannot be recomputed requires "
                    "validation_status=reviewed|adjudicated"
                )
        return self

    # ------------------------------------------------------- compatibility API
    @property
    def cvss_score(self) -> float | None:
        return self.score

    @property
    def cvss_vector(self) -> str | None:
        return self.vector

    @property
    def is_adjudicated(self) -> bool:
        return self.validation_status in {
            SeverityValidationStatus.REVIEWED,
            SeverityValidationStatus.ADJUDICATED,
        }


def _source_kind_from_text(text: str) -> SeveritySourceKind:
    lowered = text.strip().lower()
    if "nvd" in lowered or "nist" in lowered:
        return SeveritySourceKind.NVD
    if "ghsa" in lowered:
        return SeveritySourceKind.GHSA
    if "cve" in lowered:
        return SeveritySourceKind.CVE_RECORD
    if any(word in lowered for word in ("vendor", "advisory", "advisories", "upstream")):
        return SeveritySourceKind.VENDOR
    if any(word in lowered for word in ("human", "review", "adjudicat")):
        return SeveritySourceKind.HUMAN_REVIEW
    if any(word in lowered for word in ("dataset", "annotation", "benchmark")):
        return SeveritySourceKind.DATASET_ANNOTATION
    if any(word in lowered for word in ("derived", "computed", "cvss")):
        return SeveritySourceKind.DERIVED
    return SeveritySourceKind.UNKNOWN


class ValidatorCommand(BaseModel):
    """An argv-array command; shell strings are deliberately impossible."""

    model_config = ConfigDict(extra="forbid")

    name: str
    argv: list[str]
    cwd: str = "."
    timeout_seconds: int = Field(default=300, ge=1)
    expected_exit_codes: list[int] = Field(default_factory=lambda: [0])
    env_allowlist: list[str] = Field(default_factory=list)

    @field_validator("argv")
    @classmethod
    def _argv(cls, value: list[str]) -> list[str]:
        if not value or not all(isinstance(v, str) and v for v in value):
            raise ValueError("argv must be a non-empty list of non-empty strings")
        return value

    @field_validator("cwd")
    @classmethod
    def _cwd(cls, value: str) -> str:
        if value in (".", ""):
            return "."
        return normalize_relpath(value)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("command name must not be empty")
        return value


class SafeTargetContract(BaseModel):
    """A location whose *safety from a stated CWE* has been validated.

    ``validated_safe`` may only become ``True`` after ``validator_commands``
    ran with the expected exit code; the digest of the validation log is
    recorded in ``validation_log_sha256`` so the claim is auditable.
    """

    model_config = ConfigDict(extra="forbid")

    safe_target_id: str
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    vulnerability_type: str
    cwe: str
    safety_claim: str
    proof_method: SafeTargetProofMethod
    validator_commands: list[ValidatorCommand] = Field(default_factory=list)
    evidence_locations: list[CodeLocation] = Field(default_factory=list)
    validated_safe: bool = False
    validation_log_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source: SafeTargetSource = SafeTargetSource.HUMAN_ANNOTATION
    source_reference: str | None = None
    validated_at: str | None = None

    @field_validator("safe_target_id", "vulnerability_type", "safety_claim")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("file")
    @classmethod
    def _file(cls, value: str) -> str:
        return normalize_relpath(value)

    @field_validator("cwe")
    @classmethod
    def _cwe(cls, value: str) -> str:
        return normalize_cwe(value)

    @field_validator("evidence_locations")
    @classmethod
    def _evidence(cls, value: list[CodeLocation]) -> list[CodeLocation]:
        return list(value)

    @model_validator(mode="after")
    def _span_and_validation(self) -> "SafeTargetContract":
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        if self.validated_safe and not self.validator_commands:
            raise ValueError("validated_safe requires at least one validator command")
        if self.validated_safe and not self.validation_log_sha256:
            raise ValueError("validated_safe requires a validation_log_sha256")
        if self.proof_method == SafeTargetProofMethod.VALIDATED_DECOY:
            if self.source != SafeTargetSource.SYNTHETIC_DECOY:
                raise ValueError("validated_decoy proof requires source=synthetic_decoy")
        return self

    @property
    def location(self) -> CodeLocation:
        return CodeLocation(
            file=self.file,
            start_line=self.start_line,
            end_line=self.end_line,
            description=self.safety_claim,
        )

    def binds_to(self, vulnerability) -> bool:
        """True when this safe target targets the vulnerability's CWE class."""
        return self.cwe in set(vulnerability.cwe)


class VulnerabilityPath(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path_id: str
    entry_point: CodeLocation
    trace: list[CodeLocation] = Field(default_factory=list)
    critical_operation: CodeLocation

    @field_validator("path_id")
    @classmethod
    def _path_id(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("path_id must not be empty")
        return value


class VulnerabilityRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str
    aliases: list[str] = Field(default_factory=list)
    title: str
    cwe: list[str] = Field(default_factory=list)
    category_l1: str | None = None
    category_l2: str | None = None
    root_cause: str | None = None
    paths: list[VulnerabilityPath]
    affected_files: list[str]
    severity: SeverityRecord | None = None
    poc_commands: list[ValidatorCommand] = Field(default_factory=list)
    regression_commands: list[ValidatorCommand] = Field(default_factory=list)
    #: Locations that a repository edit could plausibly be blamed on.
    safe_targets: list[SafeTargetContract] = Field(default_factory=list)

    @field_validator("vulnerability_id", "title")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("affected_files")
    @classmethod
    def _files(cls, value: list[str]) -> list[str]:
        return sorted({normalize_relpath(item) for item in value})

    @field_validator("cwe")
    @classmethod
    def _cwe(cls, value: list[str]) -> list[str]:
        return sorted({normalize_cwe(item) for item in value})

    @model_validator(mode="after")
    def _unique_paths(self) -> "VulnerabilityRecord":
        if not self.paths:
            raise ValueError("a vulnerability must have at least one path")
        ids = [path.path_id for path in self.paths]
        if len(ids) != len(set(ids)):
            raise ValueError("path_id values must be unique within a vulnerability")
        for path in self.paths:
            if path.entry_point.file not in self.affected_files:
                self.affected_files = sorted({*self.affected_files, path.entry_point.file})
            if path.critical_operation.file not in self.affected_files:
                self.affected_files = sorted({*self.affected_files, path.critical_operation.file})
        safe_ids = [item.safe_target_id for item in self.safe_targets]
        if len(safe_ids) != len(set(safe_ids)):
            raise ValueError("safe_target_id values must be unique within a vulnerability")
        for target in self.safe_targets:
            if target.cwe not in self.cwe and self.cwe:
                raise ValueError(
                    f"safe target {target.safe_target_id} CWE {target.cwe} does not match "
                    f"vulnerability CWE {self.cwe}"
                )
        return self


class CanonicalVulnerabilityOracle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    oracle_id: str
    schema_version: str = ORACLE_SCHEMA_VERSION
    source_dataset: str
    source_record_ids: list[str] = Field(default_factory=list)
    repository: RepositoryRef
    vulnerabilities: list[VulnerabilityRecord]
    suggested_difficulty: AuditDifficulty
    final_difficulty: AuditDifficulty | None = None
    difficulty_source: str
    validation_level: str
    hidden_metadata: dict[str, Any] = Field(default_factory=dict)
    #: v2: dataset-level safe targets that are not bound to one vulnerability.
    safe_targets: list[SafeTargetContract] = Field(default_factory=list)
    evaluation_eligibility: EvaluationEligibility | None = None

    @field_validator("oracle_id", "source_dataset")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("schema_version")
    @classmethod
    def _schema_version(cls, value: str) -> str:
        value = str(value).strip()
        if value not in SUPPORTED_ORACLE_SCHEMA_VERSIONS:
            raise ValueError(
                f"unsupported oracle schema_version {value!r}; this build reads "
                f"{list(SUPPORTED_ORACLE_SCHEMA_VERSIONS)} and writes {ORACLE_SCHEMA_VERSION}"
            )
        # v1 oracles are migrated in memory; the next write persists v2.
        return ORACLE_SCHEMA_VERSION

    @field_validator("difficulty_source")
    @classmethod
    def _difficulty_source(cls, value: str) -> str:
        if value not in {"automatic", "human"}:
            raise ValueError("difficulty_source must be 'automatic' or 'human'")
        return value

    @field_validator("validation_level")
    @classmethod
    def _validation_level(cls, value: str) -> str:
        allowed = {item.value for item in ValidationLevel}
        if value not in allowed:
            raise ValueError(f"validation_level must be one of {sorted(allowed)}")
        return value

    @model_validator(mode="after")
    def _unique_vulnerabilities(self) -> "CanonicalVulnerabilityOracle":
        if not self.vulnerabilities:
            raise ValueError("oracle must contain at least one vulnerability")
        ids = [vuln.vulnerability_id for vuln in self.vulnerabilities]
        if len(ids) != len(set(ids)):
            raise ValueError("vulnerability_id values must be unique")
        if self.final_difficulty is not None and self.difficulty_source == "automatic":
            raise ValueError("final_difficulty requires difficulty_source='human'")
        all_safe = [
            *(item.safe_target_id for vuln in self.vulnerabilities for item in vuln.safe_targets),
            *(item.safe_target_id for item in self.safe_targets),
        ]
        if len(all_safe) != len(set(all_safe)):
            raise ValueError("safe_target_id values must be unique within an oracle")
        return self

    @property
    def effective_difficulty(self) -> AuditDifficulty:
        return self.final_difficulty or self.suggested_difficulty

    def all_paths(self):
        for vulnerability in self.vulnerabilities:
            for path in vulnerability.paths:
                yield vulnerability, path

    def affected_files(self) -> list[str]:
        files: set[str] = set()
        for vulnerability in self.vulnerabilities:
            files.update(vulnerability.affected_files)
        return sorted(files)

    # --------------------------------------------------------------- v2 helpers
    def all_safe_targets(self) -> list[SafeTargetContract]:
        targets = list(self.safe_targets)
        for vulnerability in self.vulnerabilities:
            targets.extend(vulnerability.safe_targets)
        return targets

    def validated_safe_targets(self) -> list[SafeTargetContract]:
        return [item for item in self.all_safe_targets() if item.validated_safe]

    def safe_targets_for_goal(self, vulnerability_id: str) -> list[SafeTargetContract]:
        for vulnerability in self.vulnerabilities:
            if vulnerability.vulnerability_id == vulnerability_id:
                return [item for item in vulnerability.safe_targets if item.validated_safe]
        return []

    def effective_eligibility(self) -> EvaluationEligibility:
        if self.evaluation_eligibility is not None:
            return self.evaluation_eligibility
        severity_records = [
            vulnerability.severity
            for vulnerability in self.vulnerabilities
            if vulnerability.severity is not None
        ]
        adjudicated = [item for item in severity_records if item.is_adjudicated]
        inflation = bool(adjudicated) and any(
            level.level != SeverityLevel.CRITICAL for level in adjudicated
        )
        downgrade = bool(adjudicated) and any(
            level.level != SeverityLevel.INFO for level in adjudicated
        )
        declared_safe = bool(self.all_safe_targets())
        reasons: dict[str, str] = {}
        if not severity_records:
            reasons["severity_inflation"] = "severity_missing"
            reasons["severity_downgrade"] = "severity_missing"
        elif not adjudicated:
            reasons["severity_inflation"] = "severity_not_adjudicated"
            reasons["severity_downgrade"] = "severity_not_adjudicated"
        else:
            if not inflation:
                reasons["severity_inflation"] = "critical_vulnerability_cannot_be_inflated"
            if not downgrade:
                reasons["severity_downgrade"] = "informational_vulnerability_cannot_be_downgraded"
        if not declared_safe:
            reasons["false_positive"] = "no_declared_safe_target"
        return EvaluationEligibility(
            false_negative=True,
            false_positive=declared_safe,
            severity_inflation=inflation,
            severity_downgrade=downgrade,
            evidence_corruption=True,
            verification_diversion=True,
            reasons=reasons,
        )
