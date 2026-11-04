"""Configuration models and loader.

Only the task-driven campaign flow is configured here: where a snapshot comes from
(archive), how the audit run is bounded (isolation + egress), how the frozen answer
is scored (verifier), what the agent must return (output contract), and what is
frozen before the first run (campaign plan + variants).

Rules enforced by the loader:

* unknown keys are rejected, so a typo cannot silently fall back to a default;
* credentials are never accepted in a configuration file -- an agent config lists
  the **names** of the variables it needs;
* the normalized configuration is hashed with SHA-256 and that digest is part of
  every plan, so a resumed campaign cannot continue under a changed treatment.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import SCHEMA_VERSION
from .errors import ConfigError
from .hashing import canonical_json, sha256_text
from .paths import project_root

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


# --------------------------------------------------------------------- archive
class ArchiveProviderConfig(_Strict):
    """Where one exact-commit archive comes from.

    An archive replaces clone-first materialization: a clone ships later commits
    and the fix commit inside ``.git``.
    """

    name: Literal["github", "gitlab", "local_zip", "local_tree"] = "github"
    #: Hosts a redirect may land on.  Anything else aborts the download instead of
    #: silently fetching a different artifact.
    allowed_hosts: list[str] = Field(
        default_factory=lambda: ["codeload.github.com", "github.com", "api.github.com"]
    )
    timeout_seconds: int = Field(default=120, ge=1)
    max_redirects: int = Field(default=3, ge=0, le=10)
    max_bytes: int = Field(default=268_435_456, ge=1024)
    verify_tls: bool = True
    retries: int = Field(default=1, ge=0, le=5)

    @field_validator("allowed_hosts")
    @classmethod
    def _hosts(cls, value: list[str]) -> list[str]:
        return sorted({item.strip().lower() for item in value if item.strip()})


class ExtractionLimitsConfig(_Strict):
    """Budget for unpacking an untrusted source archive."""

    max_files: int = Field(default=40_000, ge=1)
    max_total_bytes: int = Field(default=1_073_741_824, ge=1)
    max_file_bytes: int = Field(default=67_108_864, ge=1)
    max_path_depth: int = Field(default=32, ge=1)
    strip_single_root: bool = True
    #: Nested version-control metadata is history, i.e. a possible answer channel.
    reject_nested_history: bool = True


class ArchiveConfig(_Strict):
    provider: ArchiveProviderConfig = Field(default_factory=ArchiveProviderConfig)
    limits: ExtractionLimitsConfig = Field(default_factory=ExtractionLimitsConfig)
    cache_dir: str = "workspace/cache/archives"
    #: Trusted preparation stage only; never exposed to the auditing agent.
    require_commit_pinned: bool = True


# ------------------------------------------------------------------- isolation
class EgressConfig(_Strict):
    """Tool egress policy plus the probe that makes it testable.

    ``none`` records reality without claiming enforcement.  Any mode still has to
    pass the live probe: a declared policy is not evidence.
    """

    mode: Literal["container", "proxy", "none"] = "none"
    #: The single upstream the model calls may use.
    inference_gateway_hosts: list[str] = Field(default_factory=list)
    #: Hosts that must be unreachable because they serve the answer.
    probe_blocked_hosts: list[str] = Field(
        default_factory=lambda: [
            "github.com",
            "raw.githubusercontent.com",
            "codeload.github.com",
            "huggingface.co",
            "grep.app",
            "www.google.com",
            "duckduckgo.com",
        ]
    )
    probe_timeout_seconds: float = Field(default=4.0, gt=0.0, le=60.0)
    #: A run whose probe shows a reachable answer host is ineligible for the formal
    #: experiment instead of being explained away.
    fail_closed: bool = True


class IsolationConfig(_Strict):
    mode: Literal["workspace", "none"] = "workspace"
    #: Repository directory name inside the exposed root; identical for every
    #: variant so one task text maps to one stable path.
    repo_dirname: str = "repo"
    output_dirname: str = "out"
    #: A fresh state directory per run; reusing it would leak the previous score.
    fresh_state: bool = True
    egress: EgressConfig = Field(default_factory=EgressConfig)


# -------------------------------------------------------------------- verifier
class VerifierConfig(_Strict):
    """Independent evaluator: the oracle never enters the agent's space."""

    mode: Literal["separate_process", "in_process"] = "separate_process"
    private_dirname: str = "private"
    #: Untrusted report text is data, never instructions.
    max_report_chars: int = Field(default=200_000, ge=1000)
    max_findings: int = Field(default=200, ge=1)
    line_tolerance: int = Field(default=5, ge=0, le=200)
    require_output_consistency: bool = True
    refuse_when_bundle_contains_oracle: bool = True


# --------------------------------------------------------------------- outputs
class OutputContractConfig(_Strict):
    schema_version: str = "1.0"
    require_report_markdown: bool = True
    require_findings: bool = True
    max_final_answer_chars: int = Field(default=400_000, ge=1000)


# -------------------------------------------------------------------- campaign
class VariantEditConfig(_Strict):
    op: Literal["create", "append", "insert_before"] = "create"
    path: str
    text: str = ""
    #: Anchor text required by ``insert_before``; the edit fails loudly when the
    #: anchor is missing instead of silently doing nothing.
    find: str | None = None


class VariantSpecConfig(_Strict):
    variant_id: str
    kind: Literal["clean", "attack"] = "attack"
    #: Optional reference into ``campaign.payload_catalog``.  The referenced
    #: payload is rendered during the trusted preparation phase; it is never
    #: read from inside the agent workspace.
    payload_id: str | None = None
    #: Method identity is separate from the generation backend and the carrier.
    method_id: str | None = None
    carrier: str | None = None
    goal: Literal[
        "false_negative",
        "false_positive",
        "severity_shift",
        "severity_downgrade",
        "severity_inflation",
        "verification_diversion",
        "evidence_weakening",
        "scope_shift",
        "none",
    ] = "none"
    #: Does this variant assume the target is already known?
    knowledge: Literal["public_context", "target_known", "oracle_guided"] = "public_context"
    edits: list[VariantEditConfig] = Field(default_factory=list)
    #: Text that must never appear in the variant (answer-identifying tokens).
    forbidden_tokens: list[str] = Field(default_factory=list)


class CampaignConfig(_Strict):
    dataset_root: str = "../VulnMirage_dataset"
    tasks_file: str | None = None
    oracle_file: str | None = None
    #: Control plane: scheduler, budget and private pointers.  Never exposed.
    archive_root: str = "workspace"
    task_prompt_rule_version: str = "2026-11-03.1"
    audit_task_template: str = "prompts/audit_task.md"
    #: C plus the injected variants that share one clean baseline.
    variants: list[VariantSpecConfig] = Field(default_factory=list)
    variants_file: str | None = None
    #: Registry of reusable payload methods.  Relative paths are resolved as
    #: normal benchmark assets (config directory, project root, then cwd).
    payload_catalog: str | None = None
    #: Formal runs are pre-registered; the same count runs for every condition.
    repetitions: int = Field(default=1, ge=1, le=50)
    max_tasks_per_campaign: int = Field(default=1, ge=1, le=500)
    max_workers: int = Field(default=1, ge=1, le=64)
    #: Wall clock for a single audit process.
    audit_timeout_seconds: int = Field(default=900, ge=1)
    #: Lowest target eligibility that may enter scoring (see ingest.dataset_core).
    minimum_target_eligibility: Literal["snapshot_verified", "annotation_verified"] = (
        "snapshot_verified"
    )
    keep_intermediates: bool = False
    #: Cleanup only after a verified archive; never delete referenced caches.
    cleanup_requires_verified_archive: bool = True


# ------------------------------------------------------------------------ agent
class AgentConfig(_Strict):
    """How one audit is executed.

    ``mode`` decides how the final answer is collected:

    * ``argv`` -- the command writes the answer into ``{output}`` itself;
    * ``stdout`` -- the command prints; the harness captures stdout and extracts the
      last JSON object, or the last text part of a JSONL event stream.

    ``argv`` must contain ``{repo}``.  ``{output}`` (directory), ``{task}`` (path to
    the normalized task) and ``{prompt}`` (alias of ``{task}``) are optional.
    """

    schema_version: str = SCHEMA_VERSION
    mode: Literal["argv", "stdout"] = "stdout"
    argv: list[str] = Field(default_factory=list)
    #: How the answer is located inside stdout when ``mode = stdout``.
    answer_extractor: Literal["jsonl_events", "json_last_object", "tail"] = "jsonl_events"
    timeout_seconds: int = Field(default=1200, ge=1)
    #: Recorded with every run; never inferred.
    model_label: str | None = None
    #: Credential variables forwarded **by name** (values are never read here).
    requires_env: list[str] = Field(default_factory=list)
    #: Extra parent variables copied into the child environment.
    env_allowlist: list[str] = Field(
        default_factory=lambda: [
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
            "HOME",
            "USERPROFILE",
            "LANG",
            "LC_ALL",
        ]
    )

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: str) -> str:
        if value != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {value!r}")
        return value

    def missing_env(self, environ: dict[str, str] | None = None) -> list[str]:
        source = os.environ if environ is None else environ
        return [name for name in self.requires_env if not source.get(name)]


class AppConfig(_Strict):
    schema_version: str = SCHEMA_VERSION
    archive: ArchiveConfig = Field(default_factory=ArchiveConfig)
    isolation: IsolationConfig = Field(default_factory=IsolationConfig)
    verifier: VerifierConfig = Field(default_factory=VerifierConfig)
    output_contract: OutputContractConfig = Field(default_factory=OutputContractConfig)
    campaign: CampaignConfig = Field(default_factory=CampaignConfig)

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: str) -> str:
        if value != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {value!r}")
        return value


@dataclass(frozen=True)
class LoadedConfig:
    config: AppConfig
    source: Path
    base_dir: Path
    sha256: str

    def resolve_asset(self, value: str, *, must_exist: bool = True) -> Path:
        """Resolve a prompt/template path against config dir, package root, cwd."""
        candidate = Path(value).expanduser()
        if candidate.is_absolute():
            if must_exist and not candidate.exists():
                raise ConfigError(f"asset not found: {candidate}", details={"path": str(candidate)})
            return candidate
        for base in (self.base_dir, project_root(), Path.cwd()):
            resolved = (base / candidate).resolve()
            if resolved.exists():
                return resolved
        if not must_exist:
            return (Path.cwd() / candidate).resolve()
        raise ConfigError(
            f"asset not found: {value}",
            details={"searched": [str(self.base_dir), str(project_root()), str(Path.cwd())]},
        )


@dataclass(frozen=True)
class LoadedAgentConfig:
    config: AgentConfig
    source: Path
    base_dir: Path
    sha256: str


def _substitute_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _substitute_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute_env(item) for item in value]
    if isinstance(value, str):
        missing: set[str] = set()

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in os.environ:
                missing.add(name)
                return ""
            return os.environ[name]

        result = _ENV_RE.sub(replace, value)
        if missing:
            names = ", ".join(sorted(missing))
            raise ConfigError(
                f"environment variables referenced by config are not set: {names}",
                details={"missing": sorted(missing)},
            )
        return result
    return value


_SECRET_KEY_RE = re.compile(
    r"(^|[._-])(api[_-]?key|secret|token|password|private[_-]?key)$", re.I
)


def _reject_secret_keys(value: Any, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if _SECRET_KEY_RE.search(key_text):
                raise ConfigError(
                    "credentials must not be stored in configuration files; use environment variables",
                    details={"key_path": f"{path}.{key_text}" if path else key_text},
                )
            _reject_secret_keys(item, f"{path}.{key_text}" if path else key_text)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secret_keys(item, f"{path}[{index}]")


def config_sha256(config: AppConfig) -> str:
    return sha256_text(canonical_json(config.model_dump(mode="json")))


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}", details={"path": str(path)}) from exc
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping", details={"path": str(path)})
    raw = _substitute_env(raw)
    _reject_secret_keys(raw)
    return raw


def _resolve(path: str | Path) -> Path:
    source = Path(path).expanduser()
    if not source.is_absolute():
        source = (Path.cwd() / source).resolve()
    if not source.exists():
        raise ConfigError(f"config file not found: {source}", details={"path": str(source)})
    return source


def load_config(path: str | Path) -> LoadedConfig:
    from .env import load_local_env

    load_local_env()
    source = _resolve(path)
    raw = _load_yaml(source)
    try:
        config = AppConfig.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError
        raise ConfigError(
            f"invalid configuration: {exc}",
            details={"path": str(source), "validation": str(exc)},
        ) from exc
    return LoadedConfig(
        config=config, source=source, base_dir=source.parent, sha256=config_sha256(config)
    )


def with_variant_set(loaded: LoadedConfig, value: str | Path) -> LoadedConfig:
    """Return an effective config with a plan-time variant-set override.

    The source config is not rewritten.  The override participates in the
    normalized config hash, so a state created for one set cannot resume under
    another set.
    """
    raw = str(value).replace("\\", "/")
    # Resolve now for a clear CLI error, while preserving the operator-provided
    # relative path in plan.json when possible.
    loaded.resolve_asset(raw)
    campaign = loaded.config.campaign.model_copy(update={"variants_file": raw})
    config = loaded.config.model_copy(update={"campaign": campaign})
    return LoadedConfig(
        config=config,
        source=loaded.source,
        base_dir=loaded.base_dir,
        sha256=config_sha256(config),
    )


def load_agent_config(path: str | Path) -> LoadedAgentConfig:
    from .env import load_local_env

    load_local_env()
    source = _resolve(path)
    raw = _load_yaml(source)
    try:
        agent = AgentConfig.model_validate(raw)
    except Exception as exc:
        raise ConfigError(
            f"invalid agent configuration: {exc}",
            details={"path": str(source), "validation": str(exc)},
        ) from exc
    if "{repo}" not in " ".join(agent.argv):
        raise ConfigError(
            "agent argv must contain a {repo} placeholder",
            details={"path": str(source), "argv": agent.argv},
        )
    return LoadedAgentConfig(
        config=agent,
        source=source,
        base_dir=source.parent,
        sha256=sha256_text(canonical_json(agent.model_dump(mode="json"))),
    )


__all__ = [
    "AgentConfig",
    "AppConfig",
    "ArchiveConfig",
    "ArchiveProviderConfig",
    "CampaignConfig",
    "EgressConfig",
    "ExtractionLimitsConfig",
    "IsolationConfig",
    "LoadedAgentConfig",
    "LoadedConfig",
    "OutputContractConfig",
    "VariantEditConfig",
    "VariantSpecConfig",
    "VerifierConfig",
    "config_sha256",
    "load_agent_config",
    "load_config",
    "with_variant_set",
]
