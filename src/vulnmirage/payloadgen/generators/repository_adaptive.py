"""T1: repository-adaptive placement without oracle knowledge.

The generator sees the public tree only.  Placement is chosen by ranking the
index's symbols with a seeded digest, so the choice is reproducible and has no
relationship to where the vulnerability actually is -- which is exactly the
quantity T0 -> T1 -> T2 is supposed to isolate.
"""

from __future__ import annotations

from ...hashing import sha256_text
from ..context import GeneratorContext
from ..contracts import CandidatePayload
from ...errors import GenerationError
from ..repository_index import IndexedSymbol, RepositoryIndex
from . import base


def _writable_symbols(index: RepositoryIndex, context: GeneratorContext) -> list[IndexedSymbol]:
    from ..render import comment_prefix_for

    def annotatable(path: str) -> bool:
        try:
            comment_prefix_for(path)
        except Exception:  # noqa: BLE001 - a carrier without comment syntax is skipped
            return False
        return True

    writable = [
        item
        for item in index.symbols
        if index.role_of(item.path) == "source"
        and index.language_of(item.path) is not None
        and annotatable(item.path)
    ]
    sink_paths = set(index.sink_files)
    language_aliases = {
        "c++": "cpp",
        "c#": "csharp",
        "js": "javascript",
        "ts": "typescript",
    }
    primary = (context.task.primary_language or "").strip().lower()
    primary = language_aliases.get(primary, primary)

    def rank(item: IndexedSymbol) -> tuple[int, int, str]:
        # These signals are public and target-independent: security-relevant code
        # first, then the task's primary language, then deterministic diversity.
        return (
            0 if item.path in sink_paths else 1,
            0 if primary and index.language_of(item.path) == primary else 1,
            sha256_text(
                f"{context.seed}\x1f{context.variant_id}\x1f{context.method_id}"
                f"\x1f{item.path}\x1f{item.name}\x1f{item.line_start}"
            ),
        )

    return sorted(writable, key=rank)


def _fallback_file(index: RepositoryIndex, context: GeneratorContext) -> str | None:
    candidates = [path for path in index.source_files if index.comment_styles]
    if not candidates:
        return None
    ordered = sorted(candidates, key=lambda path: sha256_text(f"{context.seed}\x1f{path}"))
    return ordered[0]


def generate(context: GeneratorContext) -> list[CandidatePayload]:
    context.assert_matches_tier()
    index = context.index
    if index is None:
        raise GenerationError(
            "T1 generation requires a repository index",
            details={"method_id": context.method_id},
        )
    used_fields = [
        "task.task_id",
        "method.template",
        "index.files",
        "index.symbols",
        "index.comment_styles",
        "index.sink_files",
    ]
    if context.placement in {"create_file", "safe_decoy_file"}:
        ranked = _writable_symbols(index, context)
        symbol = ranked[0].name if ranked else None
        placement = base.create_placement(
            context, basis="repository_index", symbol=symbol
        )
        return [
            base.candidate(
                context,
                placement=placement,
                rendered=base.render(context, placement=placement),
                rationale=(
                    "the carrier path is fixed, while its wording is adapted to a "
                    "symbol selected from the public repository index"
                ),
                fields_used=used_fields,
                generator="repository_adaptive",
            )
        ]

    ranked = _writable_symbols(index, context)
    candidates: list[CandidatePayload] = []
    seen: set[tuple[str, str | None, str]] = set()
    for ordinal in range(context.budget.candidates):
        placement = None
        if ranked:
            symbol = ranked[(ordinal // 2) % len(ranked)]
            if ordinal % 2 == 1:
                placement = base.insert_placement(
                    context, path=symbol.path, symbol=symbol.name, basis="repository_index"
                )
            if placement is None:
                placement = base.footer_placement(
                    context, path=symbol.path, symbol=symbol.name, basis="repository_index"
                )
        else:
            path = _fallback_file(index, context)
            if path is None:
                raise GenerationError(
                    "the index has no source file this method can annotate",
                    details={"method_id": context.method_id, "file_count": index.file_count},
                )
            placement = base.footer_placement(
                context, path=path, symbol=None, basis="repository_index"
            )
        rendered = base.render(context, placement=placement)
        key = (rendered, placement.target_file, placement.anchor)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            base.candidate(
                context,
                placement=placement,
                rendered=rendered,
                rationale=(
                    "placement ranked from the public index by seeded digest; "
                    "no oracle location was consulted"
                ),
                fields_used=used_fields,
                generator="repository_adaptive",
                ordinal=ordinal,
            )
        )
    if not candidates:
        raise GenerationError(
            "T1 generator produced no distinct candidate",
            details={"method_id": context.method_id},
        )
    return candidates


__all__ = ["generate"]
