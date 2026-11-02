"""Language-aware checks that repository edits preserve executable semantics.

The old implementation treated any line starting with ``*`` as a comment,
which silently classified C pointer writes such as ``*p = 1;`` -> ``*p = 2;``
as "comment-only".  This module instead lexes the source: only text inside a
real line/block comment is removed, and string literals are preserved verbatim.

Languages without a verified lexer return :attr:`SemanticStatus.UNKNOWN`
(fail-closed) rather than ``passed``.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .generation.context import is_documentation, language_for


class SemanticStatus(str, Enum):
    #: AST-identical (Python) or documentation (changes are semantic by design).
    EQUAL = "equal"
    #: Only comment spans changed; proven by the language lexer.
    COMMENT_ONLY = "comment_only"
    #: Executable text changed (or Python AST changed).
    CHANGED = "changed"
    #: The property could not be decided; never treat as a pass.
    UNKNOWN = "unknown"
    #: Not an executable artifact (documentation).
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class SemanticVerdict:
    status: SemanticStatus
    reason: str
    evidence: dict[str, object] = field(default_factory=dict)
    language: str | None = None

    @property
    def preserved(self) -> bool:
        """True only when preservation is *proven*."""
        return self.status in {
            SemanticStatus.EQUAL,
            SemanticStatus.COMMENT_ONLY,
            SemanticStatus.NOT_APPLICABLE,
        }

    @property
    def decidable(self) -> bool:
        return self.status != SemanticStatus.UNKNOWN

    def __bool__(self) -> bool:  # convenient in assertions
        return self.preserved


#: Languages whose comment lexer is implemented and tested.
LEXER_VERIFIED_LANGUAGES = frozenset(
    {
        "python",
        "javascript",
        "typescript",
        "go",
        "java",
        "kotlin",
        "c",
        "cpp",
        "csharp",
        "rust",
        "ruby",
        "php",
        "shell",
        "swift",
        "scala",
    }
)

_HASH_COMMENT = {"python", "ruby", "shell", "php"}
_SLASH_COMMENT = {
    "javascript",
    "typescript",
    "go",
    "java",
    "kotlin",
    "c",
    "cpp",
    "csharp",
    "rust",
    "php",
    "swift",
    "scala",
}
_BLOCK_COMMENT = {
    "javascript",
    "typescript",
    "go",
    "java",
    "kotlin",
    "c",
    "cpp",
    "csharp",
    "rust",
    "php",
    "swift",
    "scala",
}
_BACKTICK_STRINGS = {"javascript", "typescript", "go"}
_TRIPLE_QUOTE = {"python"}
_DASH_COMMENT = {"sql"}
_HASH_LANGS = _HASH_COMMENT


def normalize_text(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _lex_comment_spans(text: str, language: str) -> list[tuple[int, int]]:
    """Return ``[start, end)`` spans that are comment text (newlines kept)."""
    spans: list[tuple[int, int]] = []
    length = len(text)
    index = 0
    line_comment = language in _HASH_COMMENT or language in _DASH_COMMENT
    hash_marker = "#" if language in _HASH_COMMENT else ("--" if language in _DASH_COMMENT else None)
    slash_marker = language in _SLASH_COMMENT
    block_marker = language in _BLOCK_COMMENT
    backtick = language in _BACKTICK_STRINGS
    triple = language in _TRIPLE_QUOTE
    while index < length:
        char = text[index]
        nxt = text[index + 1] if index + 1 < length else ""
        # Triple-quoted Python strings are strings, not comments.
        if triple and text.startswith('"""', index) or triple and text.startswith("'''", index):
            quote = text[index : index + 3]
            end = text.find(quote, index + 3)
            index = length if end < 0 else end + 3
            continue
        if char in {'"', "'"} or (backtick and char == "`"):
            end = _scan_string(text, index, char)
            index = end
            continue
        if block_marker and text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = length if end < 0 else end + 2
            spans.append((index, end))
            index = end
            continue
        if slash_marker and text.startswith("//", index):
            end = text.find("\n", index)
            end = length if end < 0 else end
            spans.append((index, end))
            index = end
            continue
        if line_comment and hash_marker and text.startswith(hash_marker, index):
            # ``#`` only starts a comment when it is not inside an identifier.
            if index == 0 or text[index - 1] in " \t\n;({[,=":
                end = text.find("\n", index)
                end = length if end < 0 else end
                spans.append((index, end))
                index = end
                continue
        index += 1
    return spans


def _scan_string(text: str, start: int, quote: str) -> int:
    index = start + 1
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == quote:
            return index + 1
        if quote != "`" and char == "\n":
            # Unterminated string: stop at the newline, do not swallow code.
            return index
        index += 1
    return length


def strip_comment_lines(text: str, language: str) -> str:
    """Remove comment spans while preserving line structure.

    The name is kept for backward compatibility; the implementation no longer
    inspects line prefixes, so ``*p = 1;`` is never mistaken for a comment.
    """
    normalized = normalize_text(text)
    if language not in LEXER_VERIFIED_LANGUAGES:
        # Fail closed: the caller must not infer "comment only" from this text.
        return normalized
    spans = _lex_comment_spans(normalized, language)
    if not spans:
        return _normalize_code_lines(normalized)
    pieces: list[str] = []
    cursor = 0
    for start, end in spans:
        pieces.append(normalized[cursor:start])
        # Preserve newlines so line numbers stay stable.
        pieces.append("\n" * normalized[start:end].count("\n"))
        cursor = end
    pieces.append(normalized[cursor:])
    return _normalize_code_lines("".join(pieces))


def _normalize_code_lines(text: str) -> str:
    """Drop whitespace-only lines so inserted comment blocks compare equal."""
    lines = [line.rstrip() for line in text.split("\n")]
    return "\n".join(line for line in lines if line).strip("\n")


def strip_comments(text: str, language: str) -> str:
    return strip_comment_lines(text, language)


def python_ast_dump(text: str) -> str | None:
    try:
        tree = ast.parse(normalize_text(text))
    except (SyntaxError, ValueError):
        return None
    return ast.dump(tree, include_attributes=False)


def semantic_fingerprint(path: str, text: str) -> str:
    if is_documentation(path):
        return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()
    language = language_for(path)
    if language == "python":
        dump = python_ast_dump(text)
        if dump is not None:
            return hashlib.sha256(dump.encode("utf-8")).hexdigest()
    stripped = strip_comment_lines(text, language or "")
    return hashlib.sha256(stripped.encode("utf-8")).hexdigest()


def compare_semantics(path: str, before: str, after: str) -> SemanticVerdict:
    """Decide whether ``after`` preserves the executable semantics of ``before``."""
    if is_documentation(path):
        return SemanticVerdict(
            status=SemanticStatus.NOT_APPLICABLE,
            reason="documentation change is semantic by design",
            language=None,
            evidence={"path": path},
        )
    language = language_for(path)
    if language is None or language not in LEXER_VERIFIED_LANGUAGES:
        return SemanticVerdict(
            status=SemanticStatus.UNKNOWN,
            reason=f"no verified semantic checker for language {language!r}",
            language=language,
            evidence={"path": path},
        )
    if language == "python":
        before_dump = python_ast_dump(before)
        after_dump = python_ast_dump(after)
        if before_dump is None or after_dump is None:
            return SemanticVerdict(
                status=SemanticStatus.UNKNOWN,
                reason="python source does not parse; semantic equality is undecidable",
                language=language,
                evidence={"path": path},
            )
        if before_dump == after_dump:
            return SemanticVerdict(
                status=SemanticStatus.EQUAL,
                reason="AST is identical",
                language=language,
                evidence={"checker": "python_ast"},
            )
        return SemanticVerdict(
            status=SemanticStatus.CHANGED,
            reason="python AST changed",
            language=language,
            evidence={"checker": "python_ast"},
        )
    before_stripped = strip_comment_lines(before, language)
    after_stripped = strip_comment_lines(after, language)
    if before_stripped == after_stripped:
        return SemanticVerdict(
            status=SemanticStatus.COMMENT_ONLY,
            reason="only comment spans changed",
            language=language,
            evidence={
                "checker": "comment_lexer",
                "before_sha256": hashlib.sha256(before_stripped.encode("utf-8")).hexdigest(),
                "after_sha256": hashlib.sha256(after_stripped.encode("utf-8")).hexdigest(),
            },
        )
    return SemanticVerdict(
        status=SemanticStatus.CHANGED,
        reason="non-comment source text changed",
        language=language,
        evidence={"checker": "comment_lexer"},
    )


def executable_semantics_equal(path: str, before: str, after: str) -> bool:
    """Backward-compatible boolean wrapper.

    ``True`` means preservation was *proven*; ``UNKNOWN`` is ``False`` so that
    callers cannot accidentally release an undecidable instance.
    """
    return compare_semantics(path, before, after).preserved


def syntax_valid(path: str, text: str) -> tuple[bool, str | None]:
    language = language_for(path)
    if language == "python":
        try:
            ast.parse(normalize_text(text))
        except SyntaxError as exc:
            return False, f"line {exc.lineno}: {exc.msg}"
        return True, None
    # Other languages are checked by build/tests during validation.
    return True, None


def read_text(path: Path) -> str:
    return normalize_text(Path(path).read_text(encoding="utf-8", errors="replace"))
