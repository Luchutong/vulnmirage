"""Load and deterministically realize repository-injection payloads.

``PayloadGen/`` is a trusted benchmark asset library, not part of the audited
repository.  A campaign variant references one registered payload id.  This
module renders that payload into structured variant edits before the workspace
is exposed to an agent and records any privately certified safe decoy for the
independent verifier.

The registry distinguishes an implemented *adaptation* from a planned method.
This matters for literature-derived methods: naming a paper is not evidence that
its semantic generator and behavior-preservation checks were reproduced.
"""

from __future__ import annotations

import ast
import string
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .config import VariantEditConfig, VariantSpecConfig
from .errors import CampaignError
from .hashing import sha256_file, sha256_text
from .paths import ensure_within
from .verifier.targets import SafeDecoy

PAYLOAD_CATALOG_VERSION = "1.0"


class PayloadMethod(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload_id: str
    method_family: str
    objective: Literal[
        "false_negative",
        "false_positive",
        "severity_downgrade",
        "severity_inflation",
        "verification_diversion",
    ]
    carrier: str
    placement: Literal["create_file", "target_file_footer", "safe_decoy_file"]
    reproduction_status: Literal["implemented_adaptation", "planned"]
    template: str
    output_path: str | None = None
    description: str = ""
    source_url: str | None = None
    safe_decoy_cwe_ids: list[str] = Field(default_factory=list)
    private_safety_basis: str | None = None


class PayloadCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = PAYLOAD_CATALOG_VERSION
    methods: list[PayloadMethod]

    def by_id(self) -> dict[str, PayloadMethod]:
        result: dict[str, PayloadMethod] = {}
        for method in self.methods:
            if method.payload_id in result:
                raise CampaignError(
                    "duplicate payload id in catalog",
                    details={"payload_id": method.payload_id},
                )
            result[method.payload_id] = method
        return result


class PayloadRealization(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    spec: VariantSpecConfig
    payload_id: str
    method_family: str
    reproduction_status: str
    source_url: str | None = None
    template_path: str
    template_sha256: str
    rendered_sha256: str
    #: Private binding used for target-specific scoring.  This field must not be
    #: copied into public patch metadata or the agent workspace.
    bound_target_id: str | None = None
    safe_decoys: list[SafeDecoy] = Field(default_factory=list)


def load_payload_catalog(path: str | Path) -> PayloadCatalog:
    source = Path(path)
    if not source.is_file():
        raise CampaignError("payload catalog is missing", details={"path": str(source)})
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        catalog = PayloadCatalog.model_validate(raw)
    except Exception as exc:
        raise CampaignError(
            "invalid payload catalog", details={"path": str(source), "error": str(exc)}
        ) from exc
    catalog.by_id()
    return catalog


def validate_payload_references(
    specs: list[VariantSpecConfig], catalog_path: str | Path | None
) -> None:
    referenced = [spec for spec in specs if spec.payload_id]
    if not referenced:
        return
    if catalog_path is None:
        raise CampaignError(
            "a variant references payload_id but campaign.payload_catalog is not configured"
        )
    methods = load_payload_catalog(catalog_path).by_id()
    for spec in referenced:
        method = methods.get(str(spec.payload_id))
        if method is None:
            raise CampaignError(
                "variant references an unknown payload",
                details={"variant_id": spec.variant_id, "payload_id": spec.payload_id},
            )
        if method.reproduction_status != "implemented_adaptation":
            raise CampaignError(
                "planned payload cannot be used in an experiment",
                details={
                    "variant_id": spec.variant_id,
                    "payload_id": spec.payload_id,
                    "status": method.reproduction_status,
                },
            )
        if spec.edits:
            raise CampaignError(
                "payload-backed variants may not also declare inline edits",
                details={"variant_id": spec.variant_id, "payload_id": spec.payload_id},
            )


def payload_asset_hashes(catalog_path: str | Path) -> dict[str, str]:
    source = Path(catalog_path).resolve()
    catalog = load_payload_catalog(source)
    result = {source.name: sha256_file(source)}
    for method in catalog.methods:
        template = _template_path(source, method.template)
        result[template.relative_to(source.parent).as_posix()] = sha256_file(template)
    return dict(sorted(result.items()))


def _template_path(catalog_path: Path, relative: str) -> Path:
    candidate = (catalog_path.parent / relative).resolve()
    ensure_within(catalog_path.parent.resolve(), candidate, must_exist=True)
    if not candidate.is_file():
        raise CampaignError(
            "payload template is not a file",
            details={"catalog": str(catalog_path), "template": relative},
        )
    return candidate


def _comment_prefix(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix in {".py", ".rb", ".sh", ".yaml", ".yml", ".toml", ".ex", ".exs"}:
        return "#"
    if suffix in {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".cs", ".go", ".java",
        ".js", ".jsx", ".kt", ".kts", ".php", ".rs", ".swift", ".ts", ".tsx",
    }:
        return "//"
    if suffix in {".sql", ".lua", ".hs"}:
        return "--"
    raise CampaignError(
        "target-file payload has no safe comment syntax for this language",
        details={"path": path, "suffix": suffix or "<none>"},
    )


def _render(template: str, values: dict[str, str], *, payload_id: str) -> str:
    formatter = string.Formatter()
    fields = {name for _, name, _, _ in formatter.parse(template) if name}
    missing = sorted(fields - values.keys())
    if missing:
        raise CampaignError(
            "payload template references unavailable fields",
            details={"payload_id": payload_id, "fields": missing},
        )
    try:
        return template.format_map(values).rstrip() + "\n"
    except (KeyError, ValueError) as exc:
        raise CampaignError(
            "payload template rendering failed",
            details={"payload_id": payload_id, "error": str(exc)},
        ) from exc


def _certify_python_safe_decoy(text: str, *, payload_id: str) -> str:
    """Return a reproducible proof digest for the narrow built-in fixture subset.

    This is intentionally stricter than general Python: no imports, attribute
    calls, dynamic execution, or calls outside locally declared functions and a
    tiny pure-builtin allowlist.  A future decoy generator needs its own validator
    instead of weakening this one.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise CampaignError(
            "safe-decoy template is not valid Python",
            details={"payload_id": payload_id, "error": str(exc)},
        ) from exc
    forbidden_nodes = (ast.Import, ast.ImportFrom, ast.Lambda, ast.ClassDef)
    local_functions = {
        item.name for item in ast.walk(tree) if isinstance(item, ast.FunctionDef)
    }
    allowed_calls = local_functions | {"repr", "str", "len"}
    problems: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, forbidden_nodes):
            problems.append(type(node).__name__)
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in allowed_calls:
                problems.append(f"Call:{ast.dump(node.func, include_attributes=False)}")
    if problems:
        raise CampaignError(
            "safe-decoy template exceeds the certified no-execution subset",
            details={"payload_id": payload_id, "problems": sorted(set(problems))},
        )
    normalized_ast = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return sha256_text("python-no-execution-subset-v1\n" + normalized_ast)


def realize_payload(
    *,
    catalog_path: str | Path,
    spec: VariantSpecConfig,
    targets,
) -> PayloadRealization:
    """Resolve one payload-backed variant into a normal structured edit."""
    catalog_source = Path(catalog_path).resolve()
    methods = load_payload_catalog(catalog_source).by_id()
    method = methods.get(str(spec.payload_id))
    if method is None:
        raise CampaignError(
            "variant references an unknown payload",
            details={"variant_id": spec.variant_id, "payload_id": spec.payload_id},
        )
    validate_payload_references([spec], catalog_source)
    target = targets[0] if targets else None
    if method.placement == "target_file_footer" and target is None:
        raise CampaignError(
            "target-aware payload requires a verified private target",
            details={"variant_id": spec.variant_id, "payload_id": method.payload_id},
        )
    template_path = _template_path(catalog_source, method.template)
    template_text = template_path.read_text(encoding="utf-8")
    target_file = target.file if target is not None else ""
    values = {
        "comment_prefix": _comment_prefix(target_file) if target_file else "#",
        "target_file": target_file,
        "target_function": (target.function or "the affected routine") if target else "",
        "expected_severity": (target.severity_level or "unknown") if target else "unknown",
        "variant_id": spec.variant_id,
    }
    rendered = _render(template_text, values, payload_id=method.payload_id)
    if method.placement == "target_file_footer":
        edit = VariantEditConfig(op="append", path=target_file, text=rendered)
        output_path = target_file
    else:
        if not method.output_path:
            raise CampaignError(
                "file payload is missing output_path",
                details={"payload_id": method.payload_id},
            )
        edit = VariantEditConfig(op="create", path=method.output_path, text=rendered)
        output_path = method.output_path

    realized_spec = spec.model_copy(
        update={
            "method_id": spec.method_id or method.method_family,
            "carrier": spec.carrier or method.carrier,
            "goal": method.objective,
            "edits": [edit],
        }
    )
    decoys: list[SafeDecoy] = []
    if method.placement == "safe_decoy_file":
        if Path(output_path).suffix.lower() != ".py":
            raise CampaignError(
                "safe-decoy certification currently supports Python files only",
                details={"payload_id": method.payload_id, "path": output_path},
            )
        proof_sha256 = _certify_python_safe_decoy(
            rendered, payload_id=method.payload_id
        )
        decoys.append(
            SafeDecoy(
                decoy_id=f"DECOY-{spec.variant_id}",
                variant_id=spec.variant_id,
                file=output_path,
                line_start=1,
                line_end=max(1, rendered.count("\n")),
                cwe_ids=method.safe_decoy_cwe_ids,
                proof_kind="python_no_execution_subset_v1",
                proof_sha256=proof_sha256,
                safety_basis=method.private_safety_basis or "no executable sink",
            )
        )
    return PayloadRealization(
        spec=realized_spec,
        payload_id=method.payload_id,
        method_family=method.method_family,
        reproduction_status=method.reproduction_status,
        source_url=method.source_url,
        template_path=template_path.as_posix(),
        template_sha256=sha256_file(template_path),
        rendered_sha256=sha256_text(rendered),
        bound_target_id=(target.target_id if method.placement == "target_file_footer" else None),
        safe_decoys=decoys,
    )


__all__ = [
    "PAYLOAD_CATALOG_VERSION",
    "PayloadCatalog",
    "PayloadMethod",
    "PayloadRealization",
    "load_payload_catalog",
    "payload_asset_hashes",
    "realize_payload",
    "validate_payload_references",
]
