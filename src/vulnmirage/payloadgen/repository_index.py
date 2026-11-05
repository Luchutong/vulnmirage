"""Deterministic repository index for repository-adaptive generation (design §11).

T1+ generators must not crawl the repository on their own.  They consume this
index, which means two things are checkable after the fact: the same clean tree
plus the same indexer version produce the same digest, and every placement a
generator chose can be traced back to a recorded entry.

The index carries **no oracle labels**.  Sensitive sinks are recorded as files
that contain sink-like calls, not as "the vulnerable location"; that distinction is
the whole point of a T1 attacker who does not know where the bug is.
"""

from __future__ import annotations

import ast
import re
import warnings
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..hashing import canonical_json, sha256_bytes, sha256_text, utc_now_iso

INDEX_SCHEMA_VERSION = "1.0"
INDEXER_VERSION = "2026-11-05.1"

_LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".swift": "swift",
    ".ex": "elixir",
    ".exs": "elixir",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".sql": "sql",
    ".lua": "lua",
    ".dart": "dart",
    ".m": "objc",
    ".mm": "objc",
    ".pl": "perl",
    ".r": "r",
    ".hs": "haskell",
}

_CONFIG_SUFFIXES = {".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".conf", ".gradle"}
_DOC_SUFFIXES = {".md", ".rst", ".adoc", ".markdown"}
_VENDOR_PARTS = {"vendor", "third_party", "thirdparty", "node_modules", "external", "deps", "bower_components"}
_GENERATED_PARTS = {"dist", "build", "out", "target", "generated", "__generated__", ".next"}
_TEST_PARTS = {"test", "tests", "spec", "specs", "__tests__", "testdata"}
_LOCKFILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "composer.lock",
}

#: Sink-like patterns.  Recorded as "this file contains a sink-shaped call", never
#: joined with a target id -- that join only exists in the private oracle.
_SINK_PATTERNS = re.compile(
    r"\b(?:exec|eval|system|popen|spawn|execve|memcpy|strcpy|strcat|sprintf|"
    r"pickle\.loads|yaml\.load|innerHTML|dangerouslySetInnerHTML|Deserialize|readObject)\s*\(",
)

_SYMBOL_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|async|export|def|function|func|fn|sub)\s+)*"
    r"(?:(?:class|interface|struct|enum|def|function|func|fn)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(",
)

_COMMENT_STYLE = {
    "python": "#",
    "ruby": "#",
    "shell": "#",
    "perl": "#",
    "r": "#",
    "elixir": "#",
    "yaml": "#",
    "c": "//",
    "cpp": "//",
    "csharp": "//",
    "java": "//",
    "javascript": "//",
    "typescript": "//",
    "kotlin": "//",
    "php": "//",
    "rust": "//",
    "swift": "//",
    "go": "//",
    "dart": "//",
    "scala": "//",
    "sql": "--",
    "lua": "--",
    "haskell": "--",
}


class IndexLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_files: int = Field(default=20_000, ge=1)
    max_total_bytes: int = Field(default=64 * 1024 * 1024, ge=1)
    max_file_bytes: int = Field(default=2 * 1024 * 1024, ge=1)
    max_symbols_per_file: int = Field(default=200, ge=1)
    include_hidden: bool = False


class IndexedFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    language: str | None = None
    role: str = "other"
    bytes: int = 0
    sha256: str = ""
    line_count: int = 0
    binary: bool = False
    parse_status: str = "not_parsed"


class IndexedSymbol(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    name: str
    kind: str = "function"
    line_start: int = 0
    line_end: int = 0


class RepositoryIndex(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = INDEX_SCHEMA_VERSION
    indexer_version: str = INDEXER_VERSION
    tree_sha256: str = ""
    file_count: int = 0
    total_bytes: int = 0
    truncated: bool = False
    files: list[IndexedFile] = Field(default_factory=list)
    symbols: list[IndexedSymbol] = Field(default_factory=list)
    comment_styles: dict[str, str] = Field(default_factory=dict)
    todo_lines: int = 0
    sink_files: list[str] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
    test_files: list[str] = Field(default_factory=list)
    doc_files: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    index_sha256: str = ""
    built_at: str = Field(default_factory=utc_now_iso)

    def digest(self) -> str:
        """Hash the index content, excluding volatile fields.

        ``built_at`` and ``index_sha256`` are excluded so two builds of the same
        tree in different seconds still compare equal.
        """
        payload = self.model_dump(mode="json", exclude={"built_at", "index_sha256"})
        return sha256_text(canonical_json(payload))

    def finalized(self) -> "RepositoryIndex":
        return self.model_copy(update={"index_sha256": self.digest()})

    def language_of(self, path: str) -> str | None:
        for item in self.files:
            if item.path == path:
                return item.language
        return None

    def role_of(self, path: str) -> str:
        for item in self.files:
            if item.path == path:
                return item.role
        return "other"

    def symbols_in(self, path: str) -> list[IndexedSymbol]:
        return [item for item in self.symbols if item.path == path]

    def by_role(self, role: str) -> list[IndexedFile]:
        return [item for item in self.files if item.role == role]


def _classify(path: str, suffix: str) -> str:
    parts = {part.lower() for part in path.split("/")[:-1]}
    lower_name = path.rsplit("/", 1)[-1].lower()
    if parts & _VENDOR_PARTS:
        return "vendor"
    if (
        parts & _GENERATED_PARTS
        or any("generated" in part for part in parts)
        or lower_name.endswith(
            (".min.js", "_pb2.py", ".g.cs", ".pb.h", ".pb.cc", ".upb.h", ".upb.c")
        )
    ):
        return "generated"
    if lower_name in _LOCKFILES:
        return "config"
    if parts & _TEST_PARTS or lower_name.startswith("test_") or lower_name.endswith(("_test.go", ".test.js", ".spec.ts")):
        return "test"
    if parts & {"docs", "doc", "documentation"} or suffix in _DOC_SUFFIXES:
        return "docs"
    if suffix in _CONFIG_SUFFIXES or lower_name in {"makefile", "dockerfile", "cmakelists.txt"}:
        return "config"
    if suffix in _LANGUAGE_BY_SUFFIX:
        return "source"
    return "other"


def _python_symbols(text: str, path: str, limit: int) -> list[IndexedSymbol] | None:
    """AST symbols, or ``None`` when the file does not parse.

    A file that does not parse is not silently reported as ``ast``: the caller
    falls back to a text scan and records ``parse_status: text_only``, so nobody
    can mistake a regex hit for a validated symbol.
    """
    try:
        # Third-party snapshots commonly contain old regex strings that emit
        # SyntaxWarning under a newer benchmark Python. They do not affect AST
        # extraction and must not pollute the campaign's machine-readable stdout.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text)
    except SyntaxError:
        return None
    found: list[IndexedSymbol] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            found.append(
                IndexedSymbol(
                    path=path,
                    name=node.name,
                    kind=kind,
                    line_start=getattr(node, "lineno", 0),
                    line_end=getattr(node, "end_lineno", 0) or 0,
                )
            )
            if len(found) >= limit:
                break
    return sorted(found, key=lambda item: (item.line_start, item.name))


def _text_symbols(text: str, path: str, limit: int) -> list[IndexedSymbol]:
    found: list[IndexedSymbol] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if len(found) >= limit:
            break
        match = _SYMBOL_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        if name in {"if", "for", "while", "switch", "catch", "return", "sizeof", "new"}:
            continue
        found.append(IndexedSymbol(path=path, name=name, kind="function", line_start=number, line_end=number))
    return found


def build_repository_index(
    root: str | Path,
    *,
    limits: IndexLimits | None = None,
    tree_sha256: str | None = None,
) -> RepositoryIndex:
    """Index ``root`` without ever following a path outside it."""
    from ..repository.archive import tree_digest

    limits = limits or IndexLimits()
    base = Path(root)
    if not base.is_dir():
        raise FileNotFoundError(base.as_posix())
    files: list[IndexedFile] = []
    symbols: list[IndexedSymbol] = []
    sink_files: list[str] = []
    excluded: list[str] = []
    todo_lines = 0
    total = 0
    truncated = False

    candidates = sorted(
        (item for item in base.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(base).as_posix(),
    )
    for item in candidates:
        relative = item.relative_to(base).as_posix()
        if relative.split("/")[0] == ".git":
            excluded.append(relative)
            continue
        if not limits.include_hidden and any(part.startswith(".") and part not in {"."} for part in relative.split("/")[:-1]):
            excluded.append(relative)
            continue
        if len(files) >= limits.max_files or total >= limits.max_total_bytes:
            truncated = True
            excluded.append(relative)
            continue
        size = item.stat().st_size
        if size > limits.max_file_bytes:
            excluded.append(relative)
            continue
        raw = item.read_bytes()
        total += len(raw)
        suffix = Path(relative).suffix.lower()
        language = _LANGUAGE_BY_SUFFIX.get(suffix)
        role = _classify(relative, suffix)
        binary = b"\x00" in raw[:4096]
        text = "" if binary else raw.decode("utf-8", errors="replace")
        entry = IndexedFile(
            path=relative,
            language=language,
            role=role,
            bytes=len(raw),
            sha256=sha256_bytes(raw),
            line_count=text.count("\n") + (1 if text else 0),
            binary=binary,
            parse_status="not_parsed",
        )
        files.append(entry)
        if binary:
            continue
        todo_lines += len(re.findall(r"\b(?:TODO|FIXME|XXX)\b", text))
        if _SINK_PATTERNS.search(text):
            sink_files.append(relative)
        if language == "python":
            parsed = _python_symbols(text, relative, limits.max_symbols_per_file)
            if parsed is not None:
                entry = entry.model_copy(update={"parse_status": "ast"})
                symbols.extend(parsed)
            else:
                entry = entry.model_copy(update={"parse_status": "text_only"})
                symbols.extend(_text_symbols(text, relative, limits.max_symbols_per_file))
            files[-1] = entry
        elif language and role in {"source", "test"}:
            entry = entry.model_copy(update={"parse_status": "text_only"})
            symbols.extend(_text_symbols(text, relative, limits.max_symbols_per_file))
            files[-1] = entry

    index = RepositoryIndex(
        tree_sha256=tree_sha256 or tree_digest(base),
        file_count=len(files),
        total_bytes=total,
        truncated=truncated,
        files=files,
        symbols=sorted(symbols, key=lambda item: (item.path, item.line_start, item.name)),
        comment_styles={
            language: style for language, style in sorted(_COMMENT_STYLE.items())
            if any(item.language == language for item in files)
        },
        todo_lines=todo_lines,
        sink_files=sorted(set(sink_files)),
        source_files=sorted(item.path for item in files if item.role == "source"),
        test_files=sorted(item.path for item in files if item.role == "test"),
        doc_files=sorted(item.path for item in files if item.role == "docs"),
        excluded_paths=sorted(excluded),
    )
    return index.finalized()


__all__ = [
    "INDEXER_VERSION",
    "INDEX_SCHEMA_VERSION",
    "IndexLimits",
    "IndexedFile",
    "IndexedSymbol",
    "RepositoryIndex",
    "build_repository_index",
]
