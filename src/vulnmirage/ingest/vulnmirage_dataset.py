"""First-class VulnMirage-Audit dataset adapter (``dataset.yaml`` + ``cases.jsonl``).

This adapter is the reference path for building new audit datasets.  It is
deliberately strict: missing severity is *allowed* (the case then only supports
detection/false-negative experiments), but a severity that is present must be
internally consistent and attributable, and severity manipulation requires a
reviewed/adjudicated record.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .. import SCHEMA_VERSION
from ..errors import DatasetError
from ..hashing import atomic_write_json, sha256_file, stable_id
from ..models import (
    ORACLE_SCHEMA_VERSION,
    AttackGoal,
    AuditDifficulty,
    CanonicalVulnerabilityOracle,
    CodeLocation,
    EvaluationEligibility,
    RepositoryRef,
    SafeTargetContract,
    SeverityLevel,
    SeverityRecord,
    ValidationLevel,
    ValidatorCommand,
    VulnerabilityPath,
    VulnerabilityRecord,
)
from ..normalization import normalize_cwe_list, severity_from_score
from ..paths import is_safe_relpath
from .base import (
    first_value,
    parse_commands,
    parse_line_range,
    parse_location,
    parse_safe_targets,
    parse_severity,
    read_jsonl,
    write_oracle,
)
from .adapter import (
    DatasetAdapter,
    DatasetCapabilities,
    DatasetInspection,
    DatasetIssue,
    NormalizationResult,
    RawRecord,
)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SPLIT_GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class DatasetManifestDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    language: str | None = None
    validation_level: str = "trace_grounded"
    license: str | None = None
    audit_difficulty: str | None = None
    attack_goals: list[AttackGoal] = Field(default_factory=list)

    @field_validator("validation_level")
    @classmethod
    def _level(cls, value: str) -> str:
        allowed = {item.value for item in ValidationLevel}
        if value not in allowed:
            raise ValueError(f"validation_level must be one of {sorted(allowed)}")
        return value

    @field_validator("audit_difficulty")
    @classmethod
    def _difficulty(cls, value: str | None) -> str | None:
        if value is None:
            return value
        allowed = {item.value for item in AuditDifficulty}
        if value not in allowed:
            raise ValueError(f"audit_difficulty must be one of {sorted(allowed)}")
        return value


class DatasetManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    dataset_name: str
    version: str | None = None
    description: str | None = None
    license: str | None = None
    homepage: str | None = None
    languages: list[str] = Field(default_factory=list)
    defaults: DatasetManifestDefaults = Field(default_factory=DatasetManifestDefaults)
    attack_goals: list[AttackGoal] = Field(default_factory=list)
    cases_sha256: str | None = None

    @field_validator("dataset_name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("dataset_name must not be empty")
        return value

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: str) -> str:
        if value not in {"1.0", "2.0"}:
            raise ValueError("dataset manifest schema_version must be 1.0 or 2.0")
        return value

    @model_validator(mode="after")
    def _goals(self) -> "DatasetManifest":
        goals = {goal.value for goal in AttackGoal}
        for goal in [*self.attack_goals, *self.defaults.attack_goals]:
            if goal.value not in goals:
                raise ValueError(f"unknown attack goal {goal.value}")
        return self


def _issue(code: str, message: str, *, case_id: str | None = None, path: str | None = None,
           line: int | None = None, severity: str = "error", **details: Any) -> DatasetIssue:
    return DatasetIssue(
        code=code,
        severity=severity,  # type: ignore[arg-type]
        message=message,
        case_id=case_id,
        path=path,
        line=line,
        details=details,
    )


def _commit(value: Any, *, field: str, case_id: str, required: bool) -> tuple[str | None, DatasetIssue | None]:
    if value is None or not str(value).strip():
        if required:
            return None, _issue(
                "commit_missing", f"{field} is required", case_id=case_id
            )
        return None, None
    text = str(value).strip().lower()
    if not _COMMIT_RE.match(text):
        return None, _issue(
            "commit_incomplete",
            f"{field} must be a full 40-character hexadecimal commit hash",
            case_id=case_id,
            value=text,
        )
    return text, None


def _repository(
    raw: Any, *, case_id: str, defaults: DatasetManifestDefaults
) -> tuple[RepositoryRef | None, list[DatasetIssue]]:
    issues: list[DatasetIssue] = []
    if not isinstance(raw, dict):
        return None, [
            _issue("repository_missing", "case has no repository object", case_id=case_id)
        ]
    url = first_value(raw, "repo_url", "url", "repository_url", "clone_url")
    if not url or not str(url).strip():
        issues.append(_issue("repository_url_missing", "repository URL is required", case_id=case_id))
        url = None
    vulnerable, issue = _commit(
        first_value(raw, "vulnerable_commit", "commit", "base_commit"),
        field="vulnerable_commit",
        case_id=case_id,
        required=True,
    )
    if issue:
        issues.append(issue)
    fixed, issue = _commit(
        first_value(raw, "fixed_commit", "fix_commit"),
        field="fixed_commit",
        case_id=case_id,
        required=False,
    )
    if issue:
        issues.append(issue)
    licence = first_value(raw, "upstream_license", "license", default=defaults.license)
    if issues:
        return None, issues
    return (
        RepositoryRef(
            repo_url=str(url).strip(),
            vulnerable_commit=vulnerable or "",
            fixed_commit=fixed,
            upstream_license=licence,
        ),
        issues,
    )


def _locations(
    payload: dict[str, Any], *, case_id: str, file_hint: str | None = None
) -> tuple[CodeLocation | None, list[CodeLocation], CodeLocation | None, list[DatasetIssue]]:
    issues: list[DatasetIssue] = []
    entry = None
    critical = None
    trace: list[CodeLocation] = []
    location_raw = first_value(payload, "location", "vulnerable_location", "sink_location")
    if location_raw is not None:
        try:
            critical = parse_location(location_raw)
        except DatasetError as exc:
            issues.append(
                _issue("location_invalid", exc.message, case_id=case_id, details=exc.details)
            )
    entry_raw = first_value(payload, "entry_point", "entry")
    if entry_raw is not None:
        try:
            entry = parse_location(entry_raw, default_file=critical.file if critical else file_hint)
        except DatasetError as exc:
            issues.append(
                _issue("entry_point_invalid", exc.message, case_id=case_id, details=exc.details)
            )
    trace_raw = first_value(payload, "trace", "call_chain", default=[]) or []
    if not isinstance(trace_raw, list):
        issues.append(
            _issue("trace_invalid", "trace must be a list of locations", case_id=case_id)
        )
        trace_raw = []
    for item in trace_raw:
        try:
            trace.append(parse_location(item, default_file=critical.file if critical else file_hint))
        except DatasetError as exc:
            issues.append(
                _issue("trace_invalid", exc.message, case_id=case_id, details=exc.details)
            )
    if entry is not None and critical is not None and entry.file == critical.file:
        issues.append(
            _issue(
                "entry_equals_critical",
                "entry_point and critical_operation must not be the same location",
                case_id=case_id,
                severity="warning",
            )
        )
    return entry, trace, critical, issues


def _severity_step(
    raw: Any, *, case_id: str
) -> tuple[SeverityRecord | None, list[DatasetIssue]]:
    if raw is None:
        return None, []
    issues: list[DatasetIssue] = []
    if isinstance(raw, dict):
        if not first_value(raw, "rationale", "description"):
            issues.append(
                _issue(
                    "severity_rationale_missing",
                    "a declared severity requires a rationale",
                    case_id=case_id,
                )
            )
        level = first_value(raw, "level", "severity", "rating")
        score = first_value(raw, "score", "cvss_score", "cvss")
        if level is not None and score is not None:
            try:
                expected = severity_from_score(float(score))
            except (TypeError, ValueError):
                issues.append(
                    _issue("severity_score_invalid", "score is not numeric", case_id=case_id)
                )
                expected = None
            if expected is not None and str(level).strip().lower() != expected.value:
                issues.append(
                    _issue(
                        "severity_level_score_mismatch",
                        f"level {level!r} disagrees with score {score}",
                        case_id=case_id,
                        expected_level=expected.value,
                    )
                )
        vector = first_value(raw, "vector", "cvss_vector")
        if vector and score is not None:
            try:
                from ..cvss import vector_base_score

                computed = vector_base_score(str(vector))
            except Exception:
                computed = None
            if computed is None:
                issues.append(
                    _issue(
                        "cvss_vector_unparseable",
                        "CVSS vector cannot be parsed",
                        case_id=case_id,
                        vector=vector,
                    )
                )
            elif abs(computed - float(score)) > 0.05:
                issues.append(
                    _issue(
                        "cvss_vector_score_mismatch",
                        f"vector computes {computed}, record says {score}",
                        case_id=case_id,
                        computed=computed,
                        recorded=float(score),
                    )
                )
    try:
        severity = parse_severity(raw, "dataset")
    except DatasetError as exc:
        issues.append(
            _issue("severity_invalid", exc.message, case_id=case_id, details=exc.details)
        )
        return None, issues
    except Exception as exc:  # pydantic level/score consistency
        message = str(exc)
        code = (
            "cvss_vector_score_mismatch"
            if "vector and score disagree" in message
            else "severity_level_score_mismatch"
            if "level and score disagree" in message
            else "severity_invalid"
        )
        issues.append(_issue(code, message, case_id=case_id))
        return None, issues
    return severity, issues


def _eligibility_for(
    severities: list[SeverityRecord],
    safe_targets: list[SafeTargetContract],
) -> EvaluationEligibility:
    """Compute which attacks a case can participate in *right now*.

    ``false_positive`` requires a safe target whose validator has already run.
    A merely declared target is kept on the oracle so generation can validate it,
    but the import-time eligibility stays false.
    """
    adjudicated = [item for item in severities if item.is_adjudicated]
    reasons: dict[str, str] = {}
    if not severities:
        reasons[AttackGoal.SEVERITY_INFLATION.value] = "severity_missing"
        reasons[AttackGoal.SEVERITY_DOWNGRADE.value] = "severity_missing"
        inflation = downgrade = False
    elif not adjudicated:
        reasons[AttackGoal.SEVERITY_INFLATION.value] = "severity_not_reviewed"
        reasons[AttackGoal.SEVERITY_DOWNGRADE.value] = "severity_not_reviewed"
        inflation = downgrade = False
    else:
        inflation = any(item.level != SeverityLevel.CRITICAL for item in adjudicated)
        downgrade = any(item.level != SeverityLevel.INFO for item in adjudicated)
        if not inflation:
            reasons[AttackGoal.SEVERITY_INFLATION.value] = (
                "critical_vulnerability_cannot_be_inflated"
            )
        if not downgrade:
            reasons[AttackGoal.SEVERITY_DOWNGRADE.value] = (
                "informational_vulnerability_cannot_be_downgraded"
            )
    validated = [item for item in safe_targets if item.validated_safe]
    if not validated:
        reasons[AttackGoal.FALSE_POSITIVE.value] = "no_validated_safe_target"
    return EvaluationEligibility(
        false_negative=True,
        false_positive=bool(validated),
        severity_inflation=inflation,
        severity_downgrade=downgrade,
        evidence_corruption=True,
        verification_diversion=True,
        reasons=reasons,
    )


class VulnMirageDatasetAdapter(DatasetAdapter):
    name = "vulnmirage"

    def __init__(self, manifest_path: Path, cases_path: Path, *, dataset_name: str | None = None):
        self._manifest_path = Path(manifest_path)
        self._cases_path = Path(cases_path)
        self._dataset_name_override = dataset_name
        self._manifest: DatasetManifest | None = None
        self._issues: list[DatasetIssue] = []
        self._cases: list[tuple[int, dict[str, Any]]] = []
        self._load()

    # ------------------------------------------------------------------ loading
    def _load(self) -> None:
        if not self._manifest_path.is_file():
            raise DatasetError(
                "dataset manifest does not exist", details={"path": str(self._manifest_path)}
            )
        if not self._cases_path.is_file():
            raise DatasetError(
                "dataset cases file does not exist", details={"path": str(self._cases_path)}
            )
        try:
            raw = yaml.safe_load(self._manifest_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise DatasetError(
                "invalid dataset manifest YAML", details={"error": str(exc)}
            ) from exc
        if not isinstance(raw, dict):
            raise DatasetError("dataset manifest root must be a mapping")
        try:
            self._manifest = DatasetManifest.model_validate(raw)
        except Exception as exc:
            raise DatasetError(
                f"invalid dataset manifest: {exc}", details={"path": str(self._manifest_path)}
            ) from exc
        self._cases = read_jsonl(self._cases_path, allow_empty=True)

    @property
    def manifest(self) -> DatasetManifest:
        assert self._manifest is not None
        return self._manifest

    @property
    def manifest_path(self) -> Path:
        return self._manifest_path

    @property
    def cases_path(self) -> Path:
        return self._cases_path

    # ------------------------------------------------------------------ inspect
    def iter_raw_records(self) -> Iterator[RawRecord]:
        for index, (line_number, payload) in enumerate(self._cases):
            yield RawRecord(
                index=index,
                case_id=first_value(payload, "case_id", "id"),
                payload={**payload, "_line_number": line_number},
            )

    def _validate_case(
        self, payload: dict[str, Any], *, index: int
    ) -> tuple[CanonicalVulnerabilityOracle | None, list[DatasetIssue], EligibilityReportLike]:
        case_id = first_value(payload, "case_id", "id")
        issues: list[DatasetIssue] = []
        if not case_id or not str(case_id).strip():
            issues.append(
                _issue("case_id_missing", "case has no case_id", line=payload.get("_line_number"))
            )
            case_id = f"case-{index}"
        case_id = str(case_id).strip()
        split_group = first_value(payload, "split_group_id", "split_group")
        if not split_group or not _SPLIT_GROUP_RE.match(str(split_group)):
            issues.append(
                _issue(
                    "split_group_id_missing",
                    "split_group_id is required and must be a short stable identifier",
                    case_id=case_id,
                )
            )
        repository, repo_issues = _repository(
            first_value(payload, "repository", "repo", default=payload),
            case_id=case_id,
            defaults=self.manifest.defaults,
        )
        issues.extend(repo_issues)
        default_validation = first_value(
            payload, "validation_level", default=self.manifest.defaults.validation_level
        )
        if default_validation not in {item.value for item in ValidationLevel}:
            issues.append(
                _issue(
                    "validation_level_invalid",
                    f"unknown validation_level {default_validation!r}",
                    case_id=case_id,
                )
            )

        vulnerabilities_raw = first_value(payload, "vulnerabilities", "vulnerability")
        if vulnerabilities_raw is None:
            issues.append(
                _issue("vulnerability_missing", "case has no vulnerability", case_id=case_id)
            )
            return None, issues, _NoEligibility()
        if isinstance(vulnerabilities_raw, dict):
            vulnerabilities_raw = [vulnerabilities_raw]
        if not isinstance(vulnerabilities_raw, list) or not vulnerabilities_raw:
            issues.append(
                _issue(
                    "vulnerability_invalid",
                    "vulnerability must be an object or a non-empty list",
                    case_id=case_id,
                )
            )
            return None, issues, _NoEligibility()

        vulnerabilities: list[VulnerabilityRecord] = []
        seen_ids: set[str] = set()
        all_safe_targets: list[SafeTargetContract] = []
        severities: list[SeverityRecord] = []
        for vuln_index, raw in enumerate(vulnerabilities_raw):
            if not isinstance(raw, dict):
                issues.append(
                    _issue("vulnerability_invalid", "vulnerability is not an object", case_id=case_id)
                )
                continue
            vuln_id = str(
                first_value(
                    raw,
                    "vulnerability_id",
                    "id",
                    default=f"{case_id}-vuln-{vuln_index + 1}",
                )
            ).strip()
            if not vuln_id:
                issues.append(
                    _issue("vulnerability_id_missing", "vulnerability_id is empty", case_id=case_id)
                )
                continue
            if vuln_id in seen_ids:
                issues.append(
                    _issue(
                        "duplicate_vulnerability_id",
                        f"duplicate vulnerability_id {vuln_id}",
                        case_id=case_id,
                    )
                )
                continue
            seen_ids.add(vuln_id)
            cwe_raw = first_value(raw, "cwe", "cwe_ids", "cwes", default=payload.get("cwe"))
            try:
                cwe = normalize_cwe_list(cwe_raw)
            except Exception as exc:
                issues.append(
                    _issue("cwe_invalid", f"invalid CWE: {exc}", case_id=case_id)
                )
                continue
            if not cwe:
                issues.append(
                    _issue("cwe_missing", "vulnerability has no CWE", case_id=case_id)
                )
                continue
            title = str(
                first_value(raw, "title", "vulnerability_type", "name", default=f"{case_id} vulnerability")
            ).strip()
            file_hint = first_value(raw, "file", "path")
            entry, trace, critical, location_issues = _locations(
                raw, case_id=case_id, file_hint=file_hint
            )
            issues.extend(location_issues)
            if critical is None and entry is not None:
                critical = entry
            if entry is None and critical is not None:
                entry = critical
            if critical is None or entry is None:
                issues.append(
                    _issue(
                        "location_missing",
                        "vulnerability requires location/entry_point/critical_operation",
                        case_id=case_id,
                    )
                )
                continue
            severity, severity_issues = _severity_step(
                first_value(raw, "severity", default=payload.get("severity")), case_id=case_id
            )
            issues.extend(severity_issues)
            if severity is not None:
                severities.append(severity)
            safe_raw = first_value(raw, "safe_targets", default=payload.get("safe_targets"))
            try:
                safe_targets = parse_safe_targets(
                    safe_raw,
                    default_cwe=cwe[0],
                    source=self.manifest.dataset_name,
                    default_vulnerability_type=str(first_value(raw, "vulnerability_type", default=title)),
                )
            except DatasetError as exc:
                issues.append(
                    _issue("safe_target_invalid", exc.message, case_id=case_id, details=exc.details)
                )
                safe_targets = []
            except Exception as exc:
                issues.append(_issue("safe_target_invalid", str(exc), case_id=case_id))
                safe_targets = []
            for target in safe_targets:
                if target.cwe not in cwe:
                    issues.append(
                        _issue(
                            "safe_target_cwe_mismatch",
                            f"safe target {target.safe_target_id} CWE {target.cwe} "
                            f"does not match {cwe}",
                            case_id=case_id,
                        )
                    )
            all_safe_targets.extend(safe_targets)
            try:
                poc = parse_commands(first_value(raw, "poc_commands", default=payload.get("poc_commands")))
                regression = parse_commands(
                    first_value(raw, "regression_commands", default=payload.get("regression_commands"))
                )
            except DatasetError as exc:
                issues.append(
                    _issue("validator_command_invalid", exc.message, case_id=case_id)
                )
                poc, regression = [], []
            path_id = str(
                first_value(raw, "path_id", default=f"{vuln_id}-path-1")
            ).strip()
            if not path_id:
                issues.append(
                    _issue("path_id_missing", "path_id is empty", case_id=case_id)
                )
                continue
            vulnerabilities.append(
                VulnerabilityRecord(
                    vulnerability_id=vuln_id,
                    title=title,
                    cwe=cwe,
                    root_cause=first_value(raw, "root_cause", "description"),
                    paths=[
                        VulnerabilityPath(
                            path_id=path_id,
                            entry_point=entry,
                            trace=trace,
                            critical_operation=critical,
                        )
                    ],
                    affected_files=sorted(
                        {entry.file, critical.file, *(item.file for item in trace)}
                    ),
                    severity=severity,
                    poc_commands=poc,
                    regression_commands=regression,
                )
            )

        blocking = [item for item in issues if item.blocking]
        if blocking:
            return None, issues, _NoEligibility()
        if not vulnerabilities:
            issues.append(
                _issue("vulnerability_missing", "no usable vulnerability records", case_id=case_id)
            )
            return None, issues, _NoEligibility()

        eligibility_raw = first_value(payload, "evaluation_eligibility")
        if eligibility_raw is not None:
            try:
                eligibility = EvaluationEligibility.model_validate(eligibility_raw)
            except Exception as exc:
                issues.append(
                    _issue("eligibility_invalid", str(exc), case_id=case_id)
                )
                return None, issues, _NoEligibility()
            # Import-time guarantees are not overridable.
            if eligibility.false_positive and not any(
                item.validated_safe for item in all_safe_targets
            ):
                eligibility = eligibility.model_copy(
                    update={
                        "false_positive": False,
                        "reasons": {
                            **eligibility.reasons,
                            AttackGoal.FALSE_POSITIVE.value: "no_validated_safe_target",
                        },
                    }
                )
        else:
            eligibility = _eligibility_for(severities, all_safe_targets)

        difficulty_raw = first_value(
            payload,
            "audit_difficulty",
            "difficulty",
            default=self.manifest.defaults.audit_difficulty,
        )
        difficulty = AuditDifficulty(str(difficulty_raw).upper()) if difficulty_raw else (
            AuditDifficulty.D4_MULTI_VULNERABILITY
            if len(vulnerabilities) > 1
            else AuditDifficulty.D2_CROSS_FILE
        )
        oracle_id = str(
            first_value(
                payload,
                "oracle_id",
                default=stable_id(
                    "VMO",
                    self._dataset_name_override or self.manifest.dataset_name,
                    case_id,
                    repository.repo_url if repository else "",
                    repository.vulnerable_commit if repository else "",
                ),
            )
        )
        oracle = CanonicalVulnerabilityOracle(
            oracle_id=oracle_id,
            schema_version=ORACLE_SCHEMA_VERSION,
            source_dataset=self._dataset_name_override or self.manifest.dataset_name,
            source_record_ids=[case_id],
            repository=repository,
            vulnerabilities=vulnerabilities,
            suggested_difficulty=difficulty,
            difficulty_source="automatic",
            validation_level=str(default_validation),
            safe_targets=all_safe_targets,
            evaluation_eligibility=eligibility,
            hidden_metadata={
                "case_id": case_id,
                "split_group_id": str(split_group),
                "dataset_version": self.manifest.version,
                "dataset_license": self.manifest.license,
                "case_language": first_value(
                    payload, "language", default=self.manifest.defaults.language
                ),
                "attack_goals": [
                    goal.value
                    for goal in (
                        first_value(payload, "attack_goals", default=[]) or []
                    )
                ],
                "notes": first_value(payload, "notes", "description"),
            },
        )
        return oracle, issues, _Eligibility(eligibility, oracle_id, case_id)

    def validate_source(self) -> list[DatasetIssue]:
        issues: list[DatasetIssue] = list(self._issues)
        seen_case_ids: set[str] = set()
        seen_split_groups: set[str] = set()
        for raw in self.iter_raw_records():
            payload = {key: value for key, value in raw.payload.items() if key != "_line_number"}
            payload.setdefault("_line_number", raw.payload.get("_line_number"))
            case_id = str(payload.get("case_id") or payload.get("id") or "")
            if case_id and case_id in seen_case_ids:
                issues.append(
                    _issue(
                        "duplicate_case_id",
                        f"duplicate case_id {case_id}",
                        case_id=case_id,
                        line=payload.get("_line_number"),
                    )
                )
            seen_case_ids.add(case_id)
            split_group = payload.get("split_group_id") or payload.get("split_group")
            if split_group:
                seen_split_groups.add(str(split_group))
            _, case_issues, _ = self._validate_case(payload, index=raw.index)
            issues.extend(case_issues)
        if not seen_split_groups:
            issues.append(
                _issue(
                    "split_group_id_missing",
                    "no case declares a split_group_id; repository-level split isolation "
                    "is impossible",
                )
            )
        return issues

    def normalize(self) -> NormalizationResult:
        issues: list[DatasetIssue] = []
        oracles: list[CanonicalVulnerabilityOracle] = []
        eligibility: dict[str, Any] = {}
        seen_case_ids: set[str] = set()
        seen_oracle_ids: set[str] = set()
        seen_vulnerability_ids: dict[str, str] = {}
        seen_path_ids: dict[str, str] = {}
        for raw in self.iter_raw_records():
            payload = {key: value for key, value in raw.payload.items() if key != "_line_number"}
            payload.setdefault("_line_number", raw.payload.get("_line_number"))
            case_id = str(payload.get("case_id") or payload.get("id") or "")
            if case_id and case_id in seen_case_ids:
                issues.append(
                    _issue(
                        "duplicate_case_id",
                        f"duplicate case_id {case_id}",
                        case_id=case_id,
                        line=payload.get("_line_number"),
                    )
                )
                continue
            if case_id:
                seen_case_ids.add(case_id)
            oracle, case_issues, report = self._validate_case(payload, index=raw.index)
            issues.extend(case_issues)
            if oracle is None:
                continue
            duplicate_ids = False
            for vulnerability in oracle.vulnerabilities:
                owner = seen_vulnerability_ids.get(vulnerability.vulnerability_id)
                if owner is not None and owner != case_id:
                    issues.append(
                        _issue(
                            "duplicate_vulnerability_id",
                            f"vulnerability_id {vulnerability.vulnerability_id} is used by "
                            f"case {owner}",
                            case_id=case_id,
                        )
                    )
                    duplicate_ids = True
                seen_vulnerability_ids[vulnerability.vulnerability_id] = case_id
                for path in vulnerability.paths:
                    owner = seen_path_ids.get(path.path_id)
                    if owner is not None and owner != case_id:
                        issues.append(
                            _issue(
                                "duplicate_path_id",
                                f"path_id {path.path_id} is used by case {owner}",
                                case_id=case_id,
                            )
                        )
                        duplicate_ids = True
                    seen_path_ids[path.path_id] = case_id
            if duplicate_ids:
                continue
            if oracle.oracle_id in seen_oracle_ids:
                issues.append(
                    _issue(
                        "duplicate_oracle_id",
                        f"duplicate oracle_id {oracle.oracle_id}",
                        case_id=case_id,
                    )
                )
                continue
            seen_oracle_ids.add(oracle.oracle_id)
            oracles.append(oracle)
            eligibility[report.case_id or oracle.oracle_id] = {
                "oracle_id": oracle.oracle_id,
                "eligible_goals": report.eligibility.enabled_goals(),
                "blocked_goals": report.eligibility.blocked_goals(),
                "safe_target_ids": sorted(
                    item.safe_target_id for item in oracle.all_safe_targets()
                ),
            }
        return NormalizationResult(
            dataset_name=self.manifest.dataset_name,
            oracles=oracles,
            issues=issues,
            eligibility=eligibility,
        )

    def describe(self) -> DatasetCapabilities:
        result = self.normalize()
        oracles = result.oracles
        severities = [
            vulnerability.severity
            for oracle in oracles
            for vulnerability in oracle.vulnerabilities
            if vulnerability.severity is not None
        ]
        safe_targets = [item for oracle in oracles for item in oracle.all_safe_targets()]
        languages = sorted(
            {
                str(oracle.hidden_metadata.get("case_language") or self.manifest.defaults.language or "")
                for oracle in oracles
            }
            - {""}
        )
        return DatasetCapabilities(
            dataset_name=self.manifest.dataset_name,
            languages=languages or list(self.manifest.languages),
            has_severity=bool(severities),
            has_adjudicated_severity=any(item.is_adjudicated for item in severities),
            has_safe_targets=bool(safe_targets),
            has_validated_safe_targets=any(item.validated_safe for item in safe_targets),
            has_fix_commits=any(oracle.repository.fixed_commit for oracle in oracles),
            has_poc_commands=any(
                vulnerability.poc_commands
                for oracle in oracles
                for vulnerability in oracle.vulnerabilities
            ),
            has_regression_commands=any(
                vulnerability.regression_commands
                for oracle in oracles
                for vulnerability in oracle.vulnerabilities
            ),
            has_split_groups=all(
                bool(oracle.hidden_metadata.get("split_group_id")) for oracle in oracles
            )
            if oracles
            else False,
            has_validation_level=bool(oracles),
            supported_goals=_supported_goals(result),
            notes=[
                "severity manipulation requires validation_status=reviewed|adjudicated",
                "false_positive requires a validator-verified SafeTargetContract",
            ],
        )

    def inspect(self) -> DatasetInspection:
        result = self.normalize()
        issues = self.validate_source()
        oracles = result.oracles
        split_groups = {
            str(oracle.hidden_metadata.get("split_group_id"))
            for oracle in oracles
            if oracle.hidden_metadata.get("split_group_id")
        }
        repositories = {oracle.repository.repo_url for oracle in oracles}
        return DatasetInspection(
            dataset_name=self.manifest.dataset_name,
            manifest_path=str(self._manifest_path),
            cases_path=str(self._cases_path),
            case_count=len(self._cases),
            split_group_count=len(split_groups),
            repository_count=len(repositories),
            sample_case_ids=[oracle.source_record_ids[0] for oracle in oracles[:10]],
            capabilities=self.describe(),
            issues=issues,
        )

    # ------------------------------------------------------------------ CLI glue
    def repository(self, case_id: str) -> dict[str, Any] | None:
        for raw in self.iter_raw_records():
            if raw.case_id == case_id:
                return first_value(raw.payload, "repository")
        return None


def _supported_goals(result: NormalizationResult) -> list[str]:
    goals: set[str] = set()
    for oracle in result.oracles:
        eligibility = oracle.evaluation_eligibility or oracle.effective_eligibility()
        goals.update(eligibility.enabled_goals())
    return sorted(goals)


class _NoEligibility(BaseModel):
    """Placeholder for rejected cases."""

    model_config = ConfigDict(extra="forbid")
    case_id: str | None = None
    eligibility: EvaluationEligibility = Field(default_factory=EvaluationEligibility)
    oracle_id: str | None = None


class _EligibilityLike:
    pass


class _Eligibility:
    def __init__(self, eligibility: EvaluationEligibility, oracle_id: str, case_id: str | None):
        self.eligibility = eligibility
        self.oracle_id = oracle_id
        self.case_id = case_id


# Backwards-compatible name for type checkers/readers.
EligibilityReportLike = Any


def ingest_vulnmirage_dataset(
    *,
    manifest_path: Path,
    cases_path: Path,
    output_dir: Path,
    dataset_name: str | None = None,
    limit: int | None = None,
    strict: bool = True,
) -> dict[str, Any]:
    adapter = VulnMirageDatasetAdapter(
        manifest_path, cases_path, dataset_name=dataset_name
    )
    inspection = adapter.inspect()
    result = adapter.normalize()
    issues = list(result.issues)
    if strict and result.errors:
        raise DatasetError(
            "dataset contains validation errors",
            details={
                "errors": [item.model_dump(mode="json") for item in result.errors[:20]],
                "error_count": len(result.errors),
            },
        )
    oracles = result.oracles[: limit if limit is not None else len(result.oracles)]
    if not oracles:
        raise DatasetError(
            "no dataset cases could be normalized",
            details={
                "issues": [item.model_dump(mode="json") for item in issues[:20]],
                "cases": inspection.case_count,
            },
        )
    output_dir = Path(output_dir)
    imported: list[dict[str, Any]] = []
    for oracle in oracles:
        path = write_oracle(
            oracle,
            output_dir,
            extra_metadata={
                "source_dataset": oracle.source_dataset,
                "case_id": oracle.source_record_ids[0] if oracle.source_record_ids else None,
                "split_group_id": oracle.hidden_metadata.get("split_group_id"),
                "dataset_manifest": str(Path(manifest_path).resolve()),
                "manifest_sha256": sha256_file(Path(manifest_path)),
            },
        )
        imported.append(
            {
                "oracle_id": oracle.oracle_id,
                "file": path.name,
                "sha256": sha256_file(path),
                "case_id": oracle.source_record_ids[0] if oracle.source_record_ids else None,
                "split_group_id": oracle.hidden_metadata.get("split_group_id"),
                "repo_url": oracle.repository.repo_url,
                "vulnerable_commit": oracle.repository.vulnerable_commit,
                "vulnerability_count": len(oracle.vulnerabilities),
                "severity_present": any(
                    item.severity is not None for item in oracle.vulnerabilities
                ),
                "eligibility": result.eligibility.get(
                    oracle.source_record_ids[0], {}
                ),
            }
        )
    index = {
        "schema_version": SCHEMA_VERSION,
        "dataset_schema_version": adapter.manifest.schema_version,
        "source_dataset": adapter.manifest.dataset_name,
        "dataset_version": adapter.manifest.version,
        "manifest_file": str(Path(manifest_path).resolve()),
        "manifest_sha256": sha256_file(Path(manifest_path)),
        "cases_file": str(Path(cases_path).resolve()),
        "cases_sha256": sha256_file(Path(cases_path)),
        "capabilities": inspection.capabilities.model_dump(mode="json"),
        "inspection": inspection.model_dump(mode="json"),
        "imported": imported,
        "issues": [item.model_dump(mode="json") for item in issues],
        "issue_counts": {
            "error": sum(1 for item in issues if item.blocking),
            "warning": sum(1 for item in issues if not item.blocking),
        },
        "eligibility": result.eligibility,
    }
    atomic_write_json(output_dir / "index.json", index)
    return {
        "ok": True,
        "output": str(output_dir.resolve()),
        "dataset_name": adapter.manifest.dataset_name,
        "case_count": inspection.case_count,
        "imported": len(imported),
        "issues": len(issues),
        "error_count": index["issue_counts"]["error"],
        "warning_count": index["issue_counts"]["warning"],
        "oracles": imported,
        "capabilities": index["capabilities"],
        "eligibility": result.eligibility,
        "index": str((output_dir / "index.json").resolve()),
    }
