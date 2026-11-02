"""Deterministic candidate deduplication.

Candidates that only differ in project name, dates or a synonym are the same
attack strategy and must not be counted twice.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..hashing import sha256_text
from .attack_plan import jaccard, token_set


@dataclass
class DuplicateDecision:
    keep: bool
    reason: str | None = None
    duplicate_of: str | None = None
    similarity: float | None = None


@dataclass
class DeduplicationResult:
    kept: list[Any] = field(default_factory=list)
    dropped: list[dict[str, Any]] = field(default_factory=list)


def candidate_fingerprint(candidate) -> dict[str, Any]:
    plan = candidate.plan
    text = "\n".join(item.content for item in candidate.files)
    normalized = _normalize(text)
    return {
        "candidate_id": candidate.candidate_id,
        "patch_hash": candidate.patch_sha256,
        "text_hash": sha256_text(normalized),
        "plan_hash": plan.structural_fingerprint(),
        "tokens": token_set(normalized),
        "paths": sorted((item.path, item.mode) for item in candidate.files),
    }


def _normalize(text: str) -> str:
    import re

    lowered = text.lower()
    # Dates and version-like strings are incidental variation, not strategy.
    lowered = re.sub(r"\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b", "<date>", lowered)
    lowered = re.sub(r"\bv?\d+\.\d+\.\d+\b", "<version>", lowered)
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9_ ]+", " ", lowered)).strip()


def deduplicate_candidates(
    candidates: Iterable[Any], *, threshold: float = 0.90
) -> DeduplicationResult:
    result = DeduplicationResult()
    seen: list[dict[str, Any]] = []
    for candidate in candidates:
        fingerprint = candidate_fingerprint(candidate)
        duplicate: DuplicateDecision | None = None
        for prior in seen:
            if fingerprint["patch_hash"] and fingerprint["patch_hash"] == prior["patch_hash"]:
                duplicate = DuplicateDecision(
                    keep=False,
                    reason="identical_patch_hash",
                    duplicate_of=prior["candidate_id"],
                    similarity=1.0,
                )
                break
            if fingerprint["plan_hash"] == prior["plan_hash"] and (
                fingerprint["text_hash"] == prior["text_hash"]
            ):
                duplicate = DuplicateDecision(
                    keep=False,
                    reason="identical_plan_and_text",
                    duplicate_of=prior["candidate_id"],
                    similarity=1.0,
                )
                break
            similarity = jaccard(fingerprint["tokens"], prior["tokens"])
            if similarity >= threshold:
                duplicate = DuplicateDecision(
                    keep=False,
                    reason="near_duplicate_text",
                    duplicate_of=prior["candidate_id"],
                    similarity=round(similarity, 4),
                )
                break
        if duplicate is not None:
            result.dropped.append(
                {
                    "candidate_id": fingerprint["candidate_id"],
                    "reason": duplicate.reason,
                    "duplicate_of": duplicate.duplicate_of,
                    "similarity": duplicate.similarity,
                }
            )
            continue
        seen.append(fingerprint)
        result.kept.append(candidate)
    return result


def dedup_summary(result: DeduplicationResult) -> dict[str, Any]:
    return {
        "kept": len(result.kept),
        "dropped": len(result.dropped),
        "reasons": sorted({item["reason"] for item in result.dropped}),
        "dropped_candidates": result.dropped,
    }


def structural_fingerprint(plan) -> str:
    return sha256_text(json.dumps(plan, sort_keys=True))
