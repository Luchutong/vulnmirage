"""The pre-package rendering path, kept as a compatibility facade.

The campaign no longer uses this function to decide what a condition contains --
:mod:`vulnmirage.payloadgen.engine` does, and it records candidates, validators
and a selection instead of producing one take-it-or-leave-it render.  What stays
here is the exact rendering behaviour the T0 goldens pin, plus the private
safe-decoy certificate, so the migration can be checked byte for byte.

One intentional behaviour change: ``expected_severity`` is **never** filled from
the private oracle.  It used to be, which meant a template could silently import
oracle knowledge into a condition declared as public-context.  No shipped template
uses the placeholder, so the goldens are unaffected.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..config import VariantEditConfig, VariantSpecConfig
from ..errors import CampaignError
from ..hashing import sha256_file, sha256_text
from ..tiers import Tier, is_implemented
from ..verifier.targets import SafeDecoy
from .catalog import PayloadMethod, load_payload_catalog
from .render import comment_prefix_for, render_template, resolve_template_path


class PayloadRealization(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    spec: VariantSpecConfig
    payload_id: str
    method_family: str
    reproduction_status: str
    tier: Tier = "T0"
    source_url: str | None = None
    template_path: str
    template_sha256: str
    rendered_sha256: str
    #: Private binding used for target-specific scoring.  This field must not be
    #: copied into public patch metadata or the agent workspace.
    bound_target_id: str | None = None
    safe_decoys: list[SafeDecoy] = Field(default_factory=list)


def validate_payload_references(
    specs: list[VariantSpecConfig],
    catalog_path: str | Path | None,
    *,
    threat_model_id: str | None = None,
    primary_objective: str | None = None,
) -> None:
    """Refuse a condition inconsistent with its realization or threat model."""
    from ..errors import UnsupportedTierError

    referenced = [spec for spec in specs if spec.realization_id]
    if not referenced:
        return
    if catalog_path is None:
        raise CampaignError(
            "a variant references realization_id but campaign.payload_catalog is not configured"
        )
    methods = load_payload_catalog(catalog_path).by_id()
    for spec in referenced:
        method = methods.get(str(spec.realization_id))
        if method is None:
            raise CampaignError(
                "variant references an unknown realization",
                details={
                    "variant_id": spec.variant_id,
                    "realization_id": spec.realization_id,
                },
            )
        if method.reproduction_status != "implemented_adaptation":
            raise CampaignError(
                "planned payload cannot be used in an experiment",
                details={
                    "variant_id": spec.variant_id,
                    "realization_id": spec.realization_id,
                    "status": method.reproduction_status,
                },
            )
        if spec.edits:
            raise CampaignError(
                "payload-backed variants may not also declare inline edits",
                details={
                    "variant_id": spec.variant_id,
                    "realization_id": spec.realization_id,
                },
            )
        if threat_model_id and threat_model_id not in method.allowed_threat_models:
            raise CampaignError(
                "realization is not admitted by the selected threat model",
                details={
                    "variant_id": spec.variant_id,
                    "realization_id": spec.realization_id,
                    "threat_model_id": threat_model_id,
                },
            )
        if primary_objective and method.objective != primary_objective:
            raise CampaignError(
                "variant set mixes objectives",
                details={
                    "variant_id": spec.variant_id,
                    "expected": primary_objective,
                    "actual": method.objective,
                },
            )
        if spec.objective != "none" and spec.objective != method.objective:
            raise CampaignError(
                "variant objective contradicts its realization",
                details={"variant_id": spec.variant_id, "actual": spec.objective},
            )
        if spec.method_id and spec.method_id != method.method_id:
            raise CampaignError(
                "variant method_id contradicts its realization",
                details={"variant_id": spec.variant_id, "actual": spec.method_id},
            )
        tier = str(spec.generator_tier)
        if not method.supports(tier):
            raise UnsupportedTierError(
                "payload method does not implement the declared tier",
                details={
                    "variant_id": spec.variant_id,
                    "realization_id": spec.realization_id,
                    "tier": tier,
                    "supported_tiers": method.supported_tiers,
                },
            )
        if not is_implemented(tier):
            raise UnsupportedTierError(
                "this build implements T0-T2 only",
                details={"variant_id": spec.variant_id, "tier": tier},
            )


def payload_asset_hashes(catalog_path: str | Path) -> dict[str, str]:
    source = Path(catalog_path).resolve()
    catalog = load_payload_catalog(source)
    result = {source.name: sha256_file(source)}
    for relative in catalog.threat_model_files:
        threat_model = (source.parent / relative).resolve()
        result[threat_model.relative_to(source.parent).as_posix()] = sha256_file(threat_model)
    for method in catalog.methods:
        for relative in method.referenced_templates():
            template = resolve_template_path(source, relative)
            result[template.relative_to(source.parent).as_posix()] = sha256_file(template)
    return dict(sorted(result.items()))


def _place(
    method: PayloadMethod,
    *,
    target_file: str,
    rendered: str,
) -> tuple[VariantEditConfig, str]:
    if method.placement == "target_file_footer":
        return (
            VariantEditConfig(op="append", path=target_file, text=rendered),
            target_file,
        )
    if not method.output_path:
        raise CampaignError(
            "file payload is missing output_path",
            details={"payload_id": method.payload_id},
        )
    return (
        VariantEditConfig(op="create", path=method.output_path, text=rendered),
        method.output_path,
    )


def realize_payload(
    *,
    catalog_path: str | Path,
    spec: VariantSpecConfig,
    targets,
) -> PayloadRealization:
    """Resolve one payload-backed variant into a normal structured edit."""
    catalog_source = Path(catalog_path).resolve()
    methods = load_payload_catalog(catalog_source).by_id()
    method = methods.get(str(spec.realization_id))
    if method is None:
        raise CampaignError(
            "variant references an unknown payload",
            details={"variant_id": spec.variant_id, "realization_id": spec.realization_id},
        )
    validate_payload_references([spec], catalog_source)
    target = targets[0] if targets else None
    if method.placement == "target_file_footer" and target is None:
        raise CampaignError(
            "target-aware payload requires a verified private target",
            details={"variant_id": spec.variant_id, "payload_id": method.payload_id},
        )
    tier = str(spec.generator_tier)
    template_rel = method.template_for(tier)
    template_path = resolve_template_path(catalog_source, template_rel)
    template_text = template_path.read_text(encoding="utf-8")
    target_file = target.file if target is not None else ""
    values = {
        "comment_prefix": comment_prefix_for(target_file) if target_file else "#",
        "target_file": target_file,
        "target_function": (target.function or "the affected routine") if target else "",
        "expected_severity": "unknown",
        "variant_id": spec.variant_id,
        "precondition": "the documented precondition",
        "dangerous_effect": "the reviewed effect",
        "boundary_claim": "the documented boundary remains in place",
    }
    rendered = render_template(template_text, values, payload_id=method.payload_id)
    edit, output_path = _place(method, target_file=target_file, rendered=rendered)
    realized_spec = spec.model_copy(
        update={
            "method_id": method.method_id,
            "carrier": spec.carrier or method.carrier,
            "objective": method.objective,
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
        from .render import certify_python_safe_decoy

        proof_sha256 = certify_python_safe_decoy(rendered, payload_id=method.payload_id)
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
        tier=tier,
        source_url=method.source_url,
        template_path=template_path.as_posix(),
        template_sha256=sha256_file(template_path),
        rendered_sha256=sha256_text(rendered),
        bound_target_id=(target.target_id if method.placement == "target_file_footer" else None),
        safe_decoys=decoys,
    )


__all__ = [
    "PayloadRealization",
    "payload_asset_hashes",
    "realize_payload",
    "validate_payload_references",
]
