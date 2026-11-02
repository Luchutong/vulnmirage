"""Candidate generation orchestration and cross-candidate deduplication."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import LoadedConfig
from ..hashing import sha256_text
from ..models import AttackPlan
from ..store import InstanceStore
from .attack_plan import token_set
from .dedup import jaccard


@dataclass
class CandidateRef:
    instance_id: str
    candidate_id: str
    plan: AttackPlan | None
    patch_sha256: str
    added_text: str
    text_hash: str
    plan_hash: str | None
    tokens: set[str]
    #: Deduplication scope: candidates for different targets are never merged.
    target_scope: str = "unspecified"


def _added_text(patch_text: str) -> str:
    lines = [
        line[1:]
        for line in patch_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    return "\n".join(lines)


def load_candidate_ref(store: InstanceStore, instance_id: str) -> CandidateRef:
    directory = store.instance_dir(instance_id)
    attack_plan = None
    plan_path = directory / "attack_plan.json"
    if plan_path.is_file():
        try:
            payload = json.loads(plan_path.read_text(encoding="utf-8"))
            attack_plan = AttackPlan.model_validate(payload["attack_plan"])
        except Exception:
            attack_plan = None
    patch_path = store.patch_path(instance_id)
    patch_text = patch_path.read_text(encoding="utf-8") if patch_path.is_file() else ""
    added = _added_text(patch_text)
    normalized = " ".join(added.lower().split())
    target_scope = "unspecified"
    instance_file = directory / "instance.json"
    if instance_file.is_file():
        try:
            instance_payload = json.loads(instance_file.read_text(encoding="utf-8"))
            target_scope = "|".join(
                [
                    str(instance_payload.get("target_kind") or "unknown"),
                    str(instance_payload.get("target_id") or "unknown"),
                    str(instance_payload.get("oracle_ref") or ""),
                ]
            )
        except Exception:
            target_scope = "unreadable_instance"
    return CandidateRef(
        instance_id=instance_id,
        candidate_id=(
            attack_plan.plan_id if attack_plan is not None else instance_id
        ),
        plan=attack_plan,
        patch_sha256=sha256_text(patch_text),
        added_text=added,
        text_hash=sha256_text(normalized),
        plan_hash=attack_plan.structural_fingerprint() if attack_plan else None,
        tokens=token_set(added),
        target_scope=target_scope,
    )


def deduplicate_instances(
    store: InstanceStore,
    instance_ids: list[str],
    *,
    threshold: float = 0.90,
) -> tuple[list[str], list[dict[str, Any]]]:
    kept: list[str] = []
    dropped: list[dict[str, Any]] = []
    refs: list[CandidateRef] = []
    for instance_id in instance_ids:
        ref = load_candidate_ref(store, instance_id)
        duplicate = None
        for prior in refs:
            if prior.target_scope != ref.target_scope:
                # Identical text aimed at a different target is a template
                # approximation, not a duplicate: dropping it would destroy
                # target coverage.
                continue
            if ref.patch_sha256 and ref.patch_sha256 == prior.patch_sha256:
                duplicate = ("identical_patch_hash", prior, 1.0)
                break
            if ref.plan_hash and ref.plan_hash == prior.plan_hash and ref.text_hash == prior.text_hash:
                duplicate = ("identical_plan_and_text", prior, 1.0)
                break
            similarity = jaccard(ref.tokens, prior.tokens)
            if similarity >= threshold:
                duplicate = ("near_duplicate_text", prior, similarity)
                break
        if duplicate is not None:
            reason, prior, similarity = duplicate
            dropped.append(
                {
                    "instance_id": instance_id,
                    "candidate_id": ref.candidate_id,
                    "reason": reason,
                    "duplicate_of": prior.instance_id,
                    "duplicate_of_candidate": prior.candidate_id,
                    "similarity": round(similarity, 4),
                }
            )
            continue
        refs.append(ref)
        kept.append(instance_id)
    return kept, dropped


SELECTION_MANIFEST_VERSION = "2.0"
SELECTION_MANIFEST_NAME = "selection_manifest.json"


def _coverage_summary(schedule_records: list[dict[str, Any]]) -> dict[str, Any]:
    by_strategy: dict[str, set[str]] = {}
    for record in schedule_records:
        key = f"{record.get('tier', record.get('goal', '?'))}|{record.get('goal', '?')}"
        by_strategy.setdefault(key, set()).add(str(record.get("operator")))
    return {
        "by_tier_goal": {
            key: sorted(value) for key, value in sorted(by_strategy.items())
        },
        "distinct_operators": sorted(
            {str(record.get("operator")) for record in schedule_records}
        ),
    }


def _write_selection_manifest(
    *,
    store: InstanceStore,
    generated: list[dict[str, Any]],
    dropped: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    kept: list[str],
    policy: str,
    slots: int,
    threshold: float,
    matrix_version: str,
    budget: dict[str, Any],
    schedule: list[dict[str, Any]],
    target_count: int,
) -> tuple[dict[str, Any], Path]:
    from ..hashing import atomic_write_json, sha256_file, utc_now_iso

    path = store.paths.instances / SELECTION_MANIFEST_NAME
    existing: dict[str, Any] = {}
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    entries: dict[str, dict[str, Any]] = {
        item.get("instance_id"): item
        for item in existing.get("candidates", [])
        if item.get("instance_id")
    }
    duplicate_info = {item["instance_id"]: item for item in dropped}
    kept_set = set(kept)
    for item in generated:
        instance_id = item["instance_id"]
        duplicate = duplicate_info.get(instance_id)
        entries[instance_id] = {
            "candidate_id": item.get("candidate_id"),
            "instance_id": instance_id,
            "target_kind": item.get("target_kind"),
            "target_id": item.get("target_id"),
            "operator": item.get("operator"),
            "tier": item.get("tier"),
            "goal": item.get("goal"),
            "validation_status": (
                "validated" if item.get("release_eligible") else "rejected"
            ),
            "duplicate_of": duplicate.get("duplicate_of") if duplicate else None,
            "dedup_reason": duplicate.get("reason") if duplicate else None,
            "dedup_scope": "target_kind|target_id|oracle_ref",
            "selected_for_release": bool(
                item.get("release_eligible") and instance_id in kept_set and not duplicate
            ),
            "selection_policy": policy,
            "candidate_slot": item.get("candidate_index"),
        }
    for item in rejected:
        instance_id = item.get("instance_id")
        if not instance_id:
            continue
        entries.setdefault(
            instance_id,
            {
                "candidate_id": item.get("candidate_id"),
                "instance_id": instance_id,
                "target_id": item.get("target_id"),
                "target_kind": item.get("target_kind"),
                "operator": item.get("operator"),
                "tier": item.get("tier"),
                "goal": item.get("goal"),
                "validation_status": "rejected",
                "duplicate_of": None,
                "dedup_reason": None,
                "dedup_scope": "target_kind|target_id|oracle_ref",
                "selected_for_release": False,
                "selection_policy": policy,
                "rejection_reason": item.get("reason")
                or item.get("rejection_reason"),
            },
        )
    for item in dropped:
        instance_id = item.get("instance_id")
        if not instance_id:
            continue
        entry = entries.setdefault(instance_id, {"instance_id": instance_id})
        entry.update(
            {
                "candidate_id": item.get("candidate_id"),
                "duplicate_of": item.get("duplicate_of"),
                "dedup_reason": item.get("reason"),
                "dedup_scope": "target_kind|target_id|oracle_ref",
                "selected_for_release": False,
            }
        )
    payload = {
        "schema_version": SELECTION_MANIFEST_VERSION,
        "generated_at": utc_now_iso(),
        "schedule_policy": policy,
        "candidate_slots": slots,
        "target_count": target_count,
        "deduplication_threshold": threshold,
        "deduplication_scope": "target_kind|target_id|oracle_ref",
        "compatibility_matrix_version": matrix_version,
        "budget": budget,
        "schedule": schedule,
        "candidates": [
            entries[key] for key in sorted(entries) if key
        ],
    }
    atomic_write_json(path, payload)
    payload["manifest_sha256"] = sha256_file(path)
    # Store the digest alongside the content without changing the file itself.
    return payload, path


def oracle_target_ids(loaded: LoadedConfig, oracle_path: Path) -> list[str]:
    """Target ids declared by the oracle, in stable id order.

    Explicit ``generation.target_vulnerability_ids`` takes precedence; unknown
    ids fail loudly instead of being dropped.
    """
    from ..models import CanonicalVulnerabilityOracle

    oracle = CanonicalVulnerabilityOracle.model_validate(
        json.loads(Path(oracle_path).read_text(encoding="utf-8"))
    )
    known = sorted(item.vulnerability_id for item in oracle.vulnerabilities)
    requested = list(loaded.config.generation.target_vulnerability_ids)
    if requested:
        unknown = [item for item in requested if item not in set(known)]
        if unknown:
            from ..errors import GenerationError

            raise GenerationError(
                "generation.target_vulnerability_ids references unknown vulnerabilities",
                details={"unknown": unknown, "known": known},
            )
        return [item for item in known if item in set(requested)]
    return known


def generate_candidates_for_oracle(
    *,
    loaded: LoadedConfig,
    oracle_path: Path,
    tiers: str | list[str] | None = None,
    goals: str | list[str] | None = None,
    seed: int | None = None,
    force: bool = False,
    resume: bool = False,
    split: str | None = None,
    max_variants: int | None = None,
    candidates_per_strategy: int | None = None,
    deduplication_threshold: float | None = None,
    target_vulnerability_id: str | None = None,
    target_vulnerability_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Generate candidates for one or more single-target variants.

    Every (target, candidate index) pair is a separate ``generate_for_oracle``
    call, so multi-target oracles produce several single-target instances
    instead of one silently-chosen target.
    """
    from .pipeline import generate_for_oracle

    from .compatibility import load_compatibility_matrix
    from .pipeline import parse_goals, parse_tiers

    count = candidates_per_strategy or loaded.config.generation.candidates_per_strategy
    threshold = (
        deduplication_threshold
        if deduplication_threshold is not None
        else loaded.config.generation.deduplication_threshold
    )
    policy = loaded.config.generation.candidate_schedule
    matrix = load_compatibility_matrix(
        loaded.resolve_asset(loaded.config.generation.compatibility_matrix)
    )
    selected_tiers = parse_tiers(tiers, loaded.config.generation.tiers)
    selected_goals = parse_goals(goals, loaded.config.generation.goals)
    from ..manipulations import compatible_operator_candidates

    max_compatible = 1
    for tier in selected_tiers:
        if tier.value == "M0":
            continue
        for goal in selected_goals:
            max_compatible = max(
                max_compatible, len(compatible_operator_candidates(tier, goal, matrix))
            )
    slots = max(1, count)
    if policy == "exhaustive":
        # Operator coverage is a first-class goal: at least one slot per
        # compatible operator, even when candidates_per_strategy=1.
        slots = max(slots, max_compatible)
    store = InstanceStore(loaded.paths)
    generated: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    safe_target_rejections: list[dict[str, Any]] = []
    clean: dict[str, Any] | None = None
    if target_vulnerability_id:
        targets = [target_vulnerability_id]
    elif target_vulnerability_ids:
        targets = list(dict.fromkeys(target_vulnerability_ids))
    else:
        targets = oracle_target_ids(loaded, oracle_path)
    limit_targets = loaded.config.generation.max_targets_per_oracle
    if limit_targets and len(targets) > limit_targets:
        skipped.append(
            {
                "reason": "max_targets_per_oracle",
                "targets_requested": targets,
                "limit": limit_targets,
                "not_generated": targets[limit_targets:],
            }
        )
        targets = targets[:limit_targets]
    total_budget = (
        max_variants
        if max_variants is not None
        else loaded.config.generation.max_variants_per_oracle
    )
    attempted_total = 0
    schedule_records: list[dict[str, Any]] = []
    budget_exhausted = False
    for target in targets:
        if budget_exhausted:
            break
        for index in range(slots):
            remaining = None if total_budget is None else max(total_budget - attempted_total, 0)
            if remaining is not None and remaining <= 0:
                skipped.append(
                    {
                        "reason": "generation_budget_exhausted",
                        "target": target,
                        "candidate_index": index,
                        "budget_unit": "attempted_job",
                        "max_variants": total_budget,
                    }
                )
                budget_exhausted = True
                break
            result = generate_for_oracle(
                loaded=loaded,
                oracle_path=oracle_path,
                tiers=tiers,
                goals=goals,
                seed=seed,
                force=force,
                resume=resume,
                split=split,
                max_variants=remaining,
                candidate_index=index,
                target_vulnerability_id=target,
                schedule_policy=policy,
            )
            clean = clean or result.get("clean")
            generated.extend(result.get("generated", []))
            skipped.extend(result.get("skipped", []))
            rejected.extend(result.get("rejected", []))
            safe_target_rejections.extend(result.get("safe_target_rejections", []))
            schedule_records.extend(result.get("schedule", []))
            attempted_total += int(result.get("attempted_count") or 0)
            if total_budget is not None and attempted_total >= total_budget:
                budget_exhausted = True
                break
    instance_ids = [item["instance_id"] for item in generated]
    kept, dropped = deduplicate_instances(store, instance_ids, threshold=threshold)
    kept_set = set(kept)
    duplicate_of = {item["instance_id"]: item for item in dropped}
    for item in generated:
        item["duplicate"] = item["instance_id"] in duplicate_of
        if item["instance_id"] in duplicate_of:
            item["duplicate_of"] = duplicate_of[item["instance_id"]]["duplicate_of"]
            item["duplicate_reason"] = duplicate_of[item["instance_id"]]["reason"]
    manifest_path = None
    manifest: dict[str, Any] = {}
    if loaded.config.generation.selection_manifest:
        manifest, manifest_path = _write_selection_manifest(
            store=store,
            generated=generated,
            dropped=dropped,
            rejected=rejected,
            kept=kept,
            policy=policy,
            slots=slots,
            threshold=threshold,
            matrix_version=matrix.matrix_version,
            budget={
                "unit": "attempted_job",
                "max": total_budget,
                "attempted": attempted_total,
                "generated": len(generated),
                "rejected": len(rejected),
                "unique": len(kept),
                "selected": len(kept),
            },
            schedule=schedule_records,
            target_count=len(targets),
        )
    if not loaded.config.generation.preserve_all_candidates:
        # Remove duplicates from the public result **and** their instance
        # directories.  Candidate records for accepted/legacy instances are
        # never deleted when preserve_all_candidates is on.
        for item in generated:
            if item["instance_id"] in duplicate_of:
                directory = store.instance_dir(item["instance_id"])
                if directory.exists():
                    import shutil

                    shutil.rmtree(directory, ignore_errors=True)
        generated = [item for item in generated if item["instance_id"] in kept_set]
    return {
        "ok": True,
        "candidates_per_strategy": max(1, count),
        "candidate_slots": slots,
        "candidate_schedule": policy,
        "operator_coverage": _coverage_summary(schedule_records),
        "deduplication_threshold": threshold,
        "deduplication_scope": "target_kind|target_id|oracle_ref",
        "preserve_all_candidates": loaded.config.generation.preserve_all_candidates,
        "budget": {
            "unit": "attempted_job",
            "max": total_budget,
            "attempted": attempted_total,
            "generated": len(generated),
            "unique": len(kept),
            "budget_exhausted": budget_exhausted,
        },
        "selection_manifest_path": str(manifest_path) if manifest_path else None,
        "selection_manifest_sha256": manifest.get("manifest_sha256"),
        "generated": generated,
        "generated_count": len(generated),
        "unique_count": len(kept),
        "duplicates": dropped,
        "duplicate_count": len(dropped),
        "skipped": skipped,
        "skipped_count": len(skipped),
        "rejected": rejected,
        "rejected_count": len(rejected),
        "safe_target_rejections": safe_target_rejections,
        "clean": clean,
        "backend": loaded.config.generation.backend,
    }
