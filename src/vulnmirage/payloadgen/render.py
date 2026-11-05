"""Deterministic rendering of trusted benchmark templates.

Rendering is deliberately boring: no model calls, no filesystem discovery, no
formatting that depends on the host.  The same template plus the same values must
produce the same bytes, which is what makes the T0 migration checkable
(byte-for-byte parity with the pre-package implementation).
"""

from __future__ import annotations

import ast
import string
from pathlib import Path

from ..errors import CampaignError
from ..hashing import sha256_text
from ..paths import ensure_within

#: Suffix -> comment prefix.  A carrier that is not listed here is refused rather
#: than guessed: wrong comment syntax silently breaks the file it is appended to.
_COMMENT_PREFIX = {
    ".py": "#",
    ".rb": "#",
    ".sh": "#",
    ".yaml": "#",
    ".yml": "#",
    ".toml": "#",
    ".ex": "#",
    ".exs": "#",
    ".c": "//",
    ".cc": "//",
    ".cpp": "//",
    ".cxx": "//",
    ".h": "//",
    ".hpp": "//",
    ".cs": "//",
    ".go": "//",
    ".java": "//",
    ".js": "//",
    ".jsx": "//",
    ".kt": "//",
    ".kts": "//",
    ".php": "//",
    ".rs": "//",
    ".swift": "//",
    ".ts": "//",
    ".tsx": "//",
    ".sql": "--",
    ".lua": "--",
    ".hs": "--",
}


def comment_prefix_for(path: str) -> str:
    suffix = Path(path).suffix.lower()
    prefix = _COMMENT_PREFIX.get(suffix)
    if prefix is None:
        raise CampaignError(
            "target-file payload has no safe comment syntax for this language",
            details={"path": path, "suffix": suffix or "<none>"},
        )
    return prefix


def render_template(template: str, values: dict[str, str], *, payload_id: str) -> str:
    """Format ``template`` with named placeholders only.

    Missing fields are an error instead of an empty substitution: a payload that
    renders ``{target_function}`` as the empty string reads as a template bug and
    would be compared as if it were a real treatment.
    """
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


def resolve_template_path(catalog_path: Path, relative: str) -> Path:
    """Resolve a template inside the payload library, refusing escapes."""
    catalog_path = Path(catalog_path).resolve()
    candidate = (catalog_path.parent / relative).resolve()
    ensure_within(catalog_path.parent.resolve(), candidate, must_exist=True)
    if not candidate.is_file():
        raise CampaignError(
            "payload template is not a file",
            details={"catalog": str(catalog_path), "template": relative},
        )
    return candidate


_FORBIDDEN_NODES = (ast.Import, ast.ImportFrom, ast.Lambda, ast.ClassDef)


def certify_python_safe_decoy(text: str, *, payload_id: str) -> str:
    """Return a reproducible proof digest for the narrow no-execution subset.

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
    local_functions = {
        item.name for item in ast.walk(tree) if isinstance(item, ast.FunctionDef)
    }
    allowed_calls = local_functions | {"repr", "str", "len"}
    problems: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, _FORBIDDEN_NODES):
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


def looks_like_python(path: str | None, text: str) -> bool:
    if path and Path(path).suffix.lower() == ".py":
        return True
    return text.lstrip().startswith(('"""', "'''", "import ", "def ", "class "))


__all__ = [
    "certify_python_safe_decoy",
    "comment_prefix_for",
    "looks_like_python",
    "render_template",
    "resolve_template_path",
]
