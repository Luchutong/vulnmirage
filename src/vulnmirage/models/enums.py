"""Shared enumerations for VulnMirage data contracts."""

from __future__ import annotations

from enum import Enum


class AttackGoal(str, Enum):
    FALSE_NEGATIVE = "false_negative"
    FALSE_POSITIVE = "false_positive"
    SEVERITY_INFLATION = "severity_inflation"
    SEVERITY_DOWNGRADE = "severity_downgrade"
    EVIDENCE_CORRUPTION = "evidence_corruption"
    VERIFICATION_DIVERSION = "verification_diversion"


class AuditDifficulty(str, Enum):
    D0_DIRECT_LOCAL = "D0"
    D1_INTRAFILE_INTERPROCEDURAL = "D1"
    D2_CROSS_FILE = "D2"
    D3_CONTEXT_DEPENDENT = "D3"
    D4_MULTI_VULNERABILITY = "D4"


class ManipulationTier(str, Enum):
    M0_CLEAN = "M0"
    M1_DIRECT = "M1"
    M2_SEMANTIC_CLAIM = "M2"
    M3_DISTRIBUTED = "M3"
    M4_PROGRAM_REPRESENTATION = "M4"
    M5_SAFE_DECOY = "M5"
    M6_HYBRID_ADAPTIVE = "M6"


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDINAL: dict[SeverityLevel, int] = {
    SeverityLevel.INFO: 0,
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
    SeverityLevel.CRITICAL: 4,
}


class PayloadOrigin(str, Enum):
    PUBLISHED_VERBATIM = "published_verbatim"
    MECHANISM_REIMPLEMENTATION = "mechanism_reimplementation"
    REPOSITORY_ADAPTED = "repository_adapted"
    ADAPTIVE_GENERATED = "adaptive_generated"
    HUMAN_AUTHORED_NEW = "human_authored_new"


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"
    #: The check could not decide the property.  Never treated as a pass.
    UNKNOWN = "unknown"


class VariantKind(str, Enum):
    CLEAN = "clean"
    #: Structural control: same carrier/placement/length, no misleading content.
    BENIGN_CONTROL = "benign_control"
    ADVERSARIAL = "adversarial"


# --------------------------------------------------------------------- taxonomy
class Mechanism(str, Enum):
    """Orthogonal attack mechanism (independent of the legacy M tier)."""

    DIRECT_INSTRUCTION = "direct_instruction"
    SEMANTIC_MISINFORMATION = "semantic_misinformation"
    REPRESENTATION_CONFUSION = "representation_confusion"
    SAFE_DECOY = "safe_decoy"
    VERIFICATION_DIVERSION = "verification_diversion"


class Carrier(str, Enum):
    MARKDOWN = "markdown"
    CODE_COMMENT = "code_comment"
    STRING_LITERAL = "string_literal"
    SOURCE_IDENTIFIER = "source_identifier"
    CONFIGURATION = "configuration"
    TEST = "test"
    EXAMPLE_CODE = "example_code"


class Presentation(str, Enum):
    PLAIN_INSTRUCTION = "plain_instruction"
    TODO_LIST = "todo_list"
    SECURITY_NOTICE = "security_notice"
    AUDIT_RECORD = "audit_record"
    ARCHITECTURE_NOTE = "architecture_note"
    MAINTENANCE_NOTE = "maintenance_note"
    CODE_EXPLANATION = "code_explanation"


class Distribution(str, Enum):
    SINGLE_LOCATION = "single_location"
    SINGLE_FILE_MULTI_LOCATION = "single_file_multi_location"
    CROSS_FILE = "cross_file"
    CROSS_TOOL = "cross_tool"


class GenerationMethod(str, Enum):
    TEMPLATE = "template"
    LLM_REWRITE = "llm_rewrite"
    ADAPTIVE_SEARCH = "adaptive_search"
    HUMAN_AUTHORED = "human_authored"


class AttackerCapability(str, Enum):
    DOCS_ONLY = "docs_only"
    COMMENTS_AND_DOCS = "comments_and_docs"
    BEHAVIOR_PRESERVING_CODE = "behavior_preserving_code"
    REPOSITORY_WRITE = "repository_write"


# ------------------------------------------------------------- severity/dataset
class SeveritySourceKind(str, Enum):
    NVD = "nvd"
    GHSA = "ghsa"
    VENDOR = "vendor"
    CVE_RECORD = "cve_record"
    DATASET_ANNOTATION = "dataset_annotation"
    HUMAN_REVIEW = "human_review"
    DERIVED = "derived"
    UNKNOWN = "unknown"


class SeverityValidationStatus(str, Enum):
    UNREVIEWED = "unreviewed"
    REVIEWED = "reviewed"
    ADJUDICATED = "adjudicated"
    DERIVED = "derived"


class SafeTargetProofMethod(str, Enum):
    FIX_COMMIT_PATH = "fixed_commit_path"
    HUMAN_ANNOTATED = "human_annotated"
    VALIDATED_DECOY = "validated_decoy"


class SafeTargetSource(str, Enum):
    FIX_COMMIT = "fix_commit"
    HUMAN_ANNOTATION = "human_annotation"
    SYNTHETIC_DECOY = "synthetic_decoy"


class PredicateType(str, Enum):
    READ_LOCATION = "read_location"
    SEARCH_SYMBOL = "search_symbol"
    TRACE_CALL_EDGE = "trace_call_edge"
    PERMISSION_CHECK = "permission_check"
    SANITIZER_EFFECT = "sanitizer_effect"
    CRITICAL_OPERATION = "critical_operation"
    EXECUTE_POC = "execute_poc"
    RUN_TEST = "run_test"
    RUN_VALIDATOR = "run_validator"
    FALSE_BRIDGE_CHECK = "false_bridge_check"
    SAFE_TARGET_CHECK = "safe_target_check"


class ExpressionOperator(str, Enum):
    ALL_OF = "all_of"
    ANY_OF = "any_of"
    SEQUENCE = "sequence"


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FORMAT_FAILURE = "format_failure"
    TIMEOUT = "timeout"
    AGENT_TOOL_FAILURE = "agent_tool_failure"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    OBSERVER_FAILURE = "observer_failure"
    CONTAMINATED = "contaminated"


class ParseStatus(str, Enum):
    NOT_ATTEMPTED = "not_attempted"
    OK = "ok"
    FORMAT_FAILURE = "format_failure"


class Stage(str, Enum):
    INGESTED = "ingested"
    MATERIALIZED = "materialized"
    ORACLE_ALIGNED = "oracle_aligned"
    PLANNED = "planned"
    GENERATED = "generated"
    VALIDATING = "validating"
    VALIDATED = "validated"
    REJECTED = "rejected"
    FROZEN = "frozen"
    EXPORTED = "exported"


class ValidationLevel(str, Enum):
    TRACE_GROUNDED = "trace_grounded"
    EXECUTABLE_GROUND_TRUTH = "executable_ground_truth"
    UNVERIFIED = "unverified"
