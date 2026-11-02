"""Repository fact extraction for generation.

Facts are extracted from the fixed snapshot with a named method and line-level
evidence.  The extractor is deliberately conservative:

* Python uses :mod:`ast` for symbol location and *direct* call sites (same file
  or a file that imports the target module).  Import strings and same-name
  functions in unrelated files are recorded as ``candidate`` callers, never as a
  proven call edge.
* Other languages fall back to text patterns and declare
  ``capability: text_pattern``; they never claim full data-flow analysis.
* Missing context is recorded in ``RepositoryFacts.missing`` instead of being
  invented.

Generated payload text and reference-report statements cannot enter these facts.
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import Iterable

from ..code_semantics import is_documentation, language_for, read_text
from ..models.facts import (
    ContextBudget,
    ContextUsage,
    DocumentationStyle,
    FactEvidence,
    FactKind,
    FactMethod,
    FactStatus,
    RepositoryFact,
    RepositoryFacts,
)
from ..models import CanonicalVulnerabilityOracle, VulnerabilityPath, VulnerabilityRecord
from ..paths import is_safe_relpath, normalize_relpath, safe_join
from .targets import resolve_target_path, resolve_target_vulnerability

_PROTECTION_NAME = re.compile(
    r"(?:sanitiz|escape|validate|verify|check|quote|param|allow|auth|permission|"
    r"csrf|filter|normaliz|encode|safe)",
    re.I,
)
_ROUTE_DECORATOR = re.compile(
    r"^\s*@\w*(?:route|get|post|put|delete|patch|api)\b", re.I
)
_PERMISSION_DECORATOR = re.compile(
    r"^\s*@\w*(?:login_required|permission|auth|requires|role|admin)\w*", re.I
)
_UPPER_ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]{2,})\s*=\s*(.+)$")
_PYTHON_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _iter_source_files(root: Path, *, limit: int = 4000) -> list[Path]:
    output: list[Path] = []
    for path in sorted(Path(root).rglob("*")):
        if len(output) >= limit:
            break
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in _PYTHON_SKIP_DIRS for part in relative.parts):
            continue
        if path.suffix.lower() not in {
            ".py",
            ".js",
            ".mjs",
            ".cjs",
            ".ts",
            ".tsx",
            ".jsx",
            ".go",
            ".java",
            ".kt",
            ".c",
            ".h",
            ".cc",
            ".cpp",
            ".hpp",
            ".cs",
            ".rs",
            ".rb",
            ".php",
            ".swift",
            ".scala",
            ".sh",
        }:
            continue
        output.append(path)
    return output


def _iter_doc_files(root: Path, *, limit: int = 200) -> list[Path]:
    output: list[Path] = []
    for path in sorted(Path(root).rglob("*")):
        if len(output) >= limit:
            break
        if not path.is_file():
            continue
        if any(part in _PYTHON_SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.suffix.lower() in {".md", ".rst", ".txt", ".adoc"}:
            output.append(path)
    return output


def _line_index(text: str) -> list[int]:
    offsets = [0]
    for index, char in enumerate(text):
        if char == "\n":
            offsets.append(index + 1)
    return offsets


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _ast_symbols(tree: ast.AST) -> list[ast.AST]:
    output: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            output.append(node)
    return output


def _span_of(node: ast.AST) -> tuple[int, int]:
    return (getattr(node, "lineno", 1), getattr(node, "end_lineno", getattr(node, "lineno", 1)))


def _enclosing_symbol(tree: ast.AST, line: int) -> ast.AST | None:
    best: ast.AST | None = None
    for node in _ast_symbols(tree):
        start, end = _span_of(node)
        if start <= line <= end:
            if best is None or _span_of(best)[0] <= start:
                best = node
    return best


def _symbol_name(node: ast.AST) -> str:
    return getattr(node, "name", "<module>")


def _snippet(
    text: str,
    relative: str,
    start_line: int,
    end_line: int,
    *,
    max_chars: int,
    method: FactMethod,
    capability: str,
) -> FactEvidence:
    lines = text.split("\n")
    start_line = max(1, min(start_line, len(lines)))
    end_line = max(start_line, min(end_line, len(lines)))
    snippet = "\n".join(lines[start_line - 1 : end_line]) + "\n"
    truncated = False
    if len(snippet) > max_chars:
        snippet = snippet[:max_chars]
        truncated = True
    return FactEvidence(
        file=normalize_relpath(relative),
        start_line=start_line,
        end_line=end_line,
        snippet=snippet,
        truncated=truncated,
        reference=f"{method.value}:{capability}",
    )


def _python_call_sites(root: Path, target_path: str, symbols: list[str]) -> tuple[list[RepositoryFact], list[str]]:
    facts: list[RepositoryFact] = []
    notes: list[str] = []
    target_module = Path(target_path).stem
    importing_files: list[Path] = []
    for path in _iter_source_files(root):
        if path.suffix.lower() != ".py" or _relative(root, path) == target_path:
            continue
        body = read_text(path)
        try:
            tree = ast.parse(body)
        except SyntaxError:
            continue
        imports_target = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[-1] == target_module:
                imports_target = True
            elif isinstance(node, ast.Import) and any(
                alias.name.split(".")[-1] == target_module for alias in node.names
            ):
                imports_target = True
        if imports_target:
            importing_files.append(path)
    resolved_relatives = {target_path, *(_relative(root, path) for path in importing_files)}
    wanted = set(symbols)
    for path in _iter_source_files(root):
        relative = _relative(root, path)
        if relative not in resolved_relatives:
            continue
        body = read_text(path)
        try:
            tree = ast.parse(body)
        except SyntaxError:
            continue
        relative = _relative(root, path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name not in wanted:
                continue
            caller = _enclosing_symbol(tree, getattr(node, "lineno", 1))
            caller_name = _symbol_name(caller) if caller else "<module>"
            line = getattr(node, "lineno", 1)
            evidence = _snippet(
                body,
                relative,
                line,
                line,
                max_chars=400,
                method=FactMethod.PYTHON_AST,
                capability="ast_direct_call",
            )
            facts.append(
                RepositoryFact(
                    fact_id=f"FACT-CALL-{len(facts) + 1:03d}",
                    kind=FactKind.CALL_SITE,
                    statement=(
                        f"direct call to {name}() inside {caller_name} in {relative}"
                    ),
                    evidence=[evidence],
                    method=FactMethod.PYTHON_AST,
                    status=FactStatus.VERIFIED,
                    capability="python_ast_direct_call",
                    confidence=1.0,
                )
            )
    # Same-name calls elsewhere are candidates only (no proven edge).
    for path in _iter_source_files(root):
        relative = _relative(root, path)
        if relative in resolved_relatives or path.suffix.lower() != ".py":
            continue
        body = read_text(path)
        if not any(re.search(rf"\b{re.escape(name)}\s*\(", body) for name in wanted):
            continue
        notes.append(
            f"same-name call text in {relative} is an unresolved candidate (module does not import the target)"
        )
    return facts, notes


def _protection_facts(root: Path, target_path: str, tree: ast.AST | None, body: str) -> list[RepositoryFact]:
    facts: list[RepositoryFact] = []
    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else None
            )
            if not name or not _PROTECTION_NAME.search(name):
                continue
            line = getattr(node, "lineno", 1)
            facts.append(
                RepositoryFact(
                    fact_id=f"FACT-PROT-{len(facts) + 1:03d}",
                    kind=FactKind.PROTECTION,
                    statement=f"call to {name}() exists in {target_path} at line {line}",
                    evidence=[
                        _snippet(
                            body,
                            target_path,
                            line,
                            line,
                            max_chars=400,
                            method=FactMethod.PYTHON_AST,
                            capability="ast_call_site",
                        )
                    ],
                    method=FactMethod.PYTHON_AST,
                    status=FactStatus.VERIFIED,
                    capability="protection_call_site_only",
                    notes=["presence of a guard call does not prove coverage"],
                )
            )
    for index, line in enumerate(body.split("\n"), start=1):
        if _ROUTE_DECORATOR.match(line) or _PERMISSION_DECORATOR.match(line):
            kind = (
                FactKind.ROUTE
                if _ROUTE_DECORATOR.match(line)
                else FactKind.PROTECTION
            )
            facts.append(
                RepositoryFact(
                    fact_id=f"FACT-DECOR-{len(facts) + 1:03d}",
                    kind=kind,
                    statement=f"decorator on line {index} of {target_path}: {line.strip()}",
                    evidence=[
                        _snippet(
                            body,
                            target_path,
                            index,
                            index,
                            max_chars=300,
                            method=FactMethod.TEXT_PATTERN,
                            capability="decorator_text",
                        )
                    ],
                    method=FactMethod.TEXT_PATTERN,
                    status=FactStatus.VERIFIED,
                    capability="text_pattern_only",
                )
            )
    for index, line in enumerate(body.split("\n"), start=1):
        match = _UPPER_ASSIGNMENT.match(line)
        if not match:
            continue
        name, value = match.groups()
        if not re.search(r"(debug|allow|origin|host|bind|auth|enabled|secure)", name, re.I):
            continue
        facts.append(
            RepositoryFact(
                fact_id=f"FACT-CONF-{len(facts) + 1:03d}",
                kind=FactKind.CONFIG_DEFAULT,
                statement=f"module-level default {name} = {value.strip()} in {target_path}",
                evidence=[
                    _snippet(
                        body,
                        target_path,
                        index,
                        index,
                        max_chars=300,
                        method=FactMethod.TEXT_PATTERN,
                        capability="assignment_text",
                    )
                ],
                method=FactMethod.TEXT_PATTERN,
                status=FactStatus.VERIFIED,
                capability="text_pattern_only",
            )
        )
    return facts


def _test_facts(root: Path, target_path: str) -> list[RepositoryFact]:
    facts: list[RepositoryFact] = []
    stem = Path(target_path).stem
    for path in _iter_source_files(root):
        relative = _relative(root, path)
        name = path.name.lower()
        if not (name.startswith("test_") or name.endswith("_test.py") or "tests" in relative.split("/")):
            continue
        body = read_text(path)
        if stem not in body:
            continue
        line = next(
            (index for index, text in enumerate(body.split("\n"), 1) if stem in text), 1
        )
        facts.append(
            RepositoryFact(
                fact_id=f"FACT-TEST-{len(facts) + 1:03d}",
                kind=FactKind.TEST,
                statement=f"test file {relative} references module {stem}",
                evidence=[
                    _snippet(
                        body,
                        relative,
                        line,
                        line,
                        max_chars=300,
                        method=FactMethod.FILE_SCAN,
                        capability="text_reference",
                    )
                ],
                method=FactMethod.FILE_SCAN,
                status=FactStatus.VERIFIED,
                capability="test_file_reference_only",
            )
        )
        if len(facts) >= 8:
            break
    return facts


def _documentation_style(root: Path, budget: ContextBudget) -> tuple[DocumentationStyle | None, list[RepositoryFact], list[str]]:
    docs = _iter_doc_files(root)
    if not docs:
        return None, [], ["no documentation file found"]
    suffixes: set[str] = set()
    heading_levels: set[str] = set()
    terms: set[str] = set()
    paragraph_lengths: list[int] = []
    samples: list[FactEvidence] = []
    files: list[str] = []
    for path in docs[: budget.max_files]:
        relative = _relative(root, path)
        body = read_text(path)
        if not body.strip():
            continue
        files.append(relative)
        suffixes.add(path.suffix.lower())
        for line in body.split("\n"):
            match = re.match(r"^(#{1,6})\s+(.+)$", line)
            if match:
                heading_levels.add(f"h{len(match.group(1))}")
        for paragraph in re.split(r"\n\s*\n", body):
            text = paragraph.strip()
            if text and not text.startswith("#"):
                paragraph_lengths.append(len(text))
        for word in re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", body.lower()):
            if word in {
                "security",
                "vulnerability",
                "sanitize",
                "sanitized",
                "validate",
                "validated",
                "permission",
                "authentication",
                "authorization",
                "deployment",
                "configuration",
                "maintainer",
                "upstream",
                "deprecated",
                "release",
                "audit",
            }:
                terms.add(word)
        if len(samples) < budget.max_style_samples:
            samples.append(
                _snippet(
                    body,
                    relative,
                    1,
                    min(8, len(body.split("\n"))),
                    max_chars=600,
                    method=FactMethod.DOCUMENTATION_SCAN,
                    capability="style_sample",
                )
            )
    style = DocumentationStyle(
        files=files,
        suffixes=sorted(suffixes),
        heading_levels=sorted(heading_levels),
        terminology=sorted(terms),
        mean_paragraph_chars=(
            sum(paragraph_lengths) / len(paragraph_lengths) if paragraph_lengths else None
        ),
        comment_prefix="<!--" if any(item.endswith(".md") for item in files) else None,
        samples=samples,
    )
    facts = [
        RepositoryFact(
            fact_id="FACT-DOCSTYLE",
            kind=FactKind.DOCUMENTATION_STYLE,
            statement=(
                "documentation inventory: "
                + ", ".join(files[: budget.max_files])
                + "; headings "
                + ",".join(sorted(heading_levels))
            ),
            evidence=samples,
            method=FactMethod.DOCUMENTATION_SCAN,
            status=FactStatus.VERIFIED,
            capability="documentation_inventory",
        )
    ]
    return style, facts, []


def extract_repository_facts(
    oracle: CanonicalVulnerabilityOracle,
    repo_root: Path,
    *,
    target_vulnerability_id: str | None = None,
    path_id: str | None = None,
    target_safe_target_id: str | None = None,
    target_handle: str | None = None,
    budget: ContextBudget | None = None,
    include_documentation: bool = True,
) -> RepositoryFacts:
    root = Path(repo_root)
    budget = budget or ContextBudget()
    missing: list[str] = []
    facts: list[RepositoryFact] = []
    usage = ContextUsage()
    if target_safe_target_id:
        contract = next(
            (
                item
                for item in oracle.all_safe_targets()
                if item.safe_target_id == target_safe_target_id
            ),
            None,
        )
        if contract is None:
            raise ValueError(f"unknown safe target id: {target_safe_target_id}")
        target_file = contract.file
        language = language_for(target_file)
        capability = (
            "python_ast"
            if language == "python"
            else "text_pattern"
            if language
            else "unsupported"
        )
        body = read_text(safe_join(root, target_file))
        facts.append(
            RepositoryFact(
                fact_id="FACT-TARGET-SAFE",
                kind=FactKind.TARGET_CRITICAL_OPERATION,
                statement=(
                    f"validated safe target {contract.safe_target_id} at {target_file}:"
                    f"{contract.start_line}-{contract.end_line} ({contract.cwe})"
                ),
                evidence=[
                    _snippet(
                        body,
                        target_file,
                        contract.start_line,
                        contract.end_line,
                        max_chars=budget.max_chars,
                        method=FactMethod.PYTHON_AST
                        if language == "python"
                        else FactMethod.TEXT_PATTERN,
                        capability=capability,
                    )
                ],
                method=FactMethod.PYTHON_AST if language == "python" else FactMethod.TEXT_PATTERN,
                status=FactStatus.VERIFIED,
                capability=f"{capability}_safe_target_span",
            )
        )
        vulnerability_id = None
    else:
        vulnerability = resolve_target_vulnerability(
            oracle, target_vulnerability_id=target_vulnerability_id
        )
        path = resolve_target_path(vulnerability, path_id=path_id)
        vulnerability_id = vulnerability.vulnerability_id
        target_file = path.critical_operation.file
        language = language_for(target_file)
        for label, location in (
            ("entry_point", path.entry_point),
            ("critical_operation", path.critical_operation),
        ):
            kind = (
                FactKind.TARGET_ENTRY_POINT
                if label == "entry_point"
                else FactKind.TARGET_CRITICAL_OPERATION
            )
            evidence = [
                FactEvidence(
                    file=location.file,
                    start_line=location.start_line,
                    end_line=location.end_line,
                    snippet=location.code,
                    truncated=False,
                    reference=f"oracle:{vulnerability.vulnerability_id}:{path.path_id}:{label}",
                )
            ]
            facts.append(
                RepositoryFact(
                    fact_id=f"FACT-TARGET-{label.upper()}",
                    kind=kind,
                    statement=(
                        f"{label.replace('_', ' ')} of {vulnerability.vulnerability_id} is "
                        f"{location.file}:{location.start_line}-{location.end_line}"
                    ),
                    evidence=evidence,
                    method=FactMethod.MANUAL,
                    status=FactStatus.VERIFIED,
                    capability="oracle_authorised_location",
                )
            )
        for index, location in enumerate(path.trace):
            facts.append(
                RepositoryFact(
                    fact_id=f"FACT-TARGET-TRACE-{index + 1:02d}",
                    kind=FactKind.TARGET_TRACE,
                    statement=(
                        f"declared trace node {index + 1} of {vulnerability.vulnerability_id}: "
                        f"{location.file}:{location.start_line}-{location.end_line}"
                    ),
                    evidence=[
                        FactEvidence(
                            file=location.file,
                            start_line=location.start_line,
                            end_line=location.end_line,
                            snippet=location.code,
                            reference=f"oracle:{vulnerability.vulnerability_id}:{path.path_id}:trace",
                        )
                    ],
                    method=FactMethod.MANUAL,
                    status=FactStatus.VERIFIED,
                    capability="oracle_declared_trace",
                )
            )
        for test_command in vulnerability.poc_commands:
            facts.append(
                RepositoryFact(
                    fact_id=f"FACT-TARGET-POC-{len(facts) + 1:03d}",
                    kind=FactKind.TEST,
                    statement=f"declared PoC command for {vulnerability.vulnerability_id}: {test_command.name}",
                    evidence=[],
                    method=FactMethod.MANUAL,
                    status=FactStatus.VERIFIED,
                    capability="private_oracle_only",
                    notes=["private command; never serialized into a generation request"],
                )
            )

    if not is_safe_relpath(target_file):
        raise ValueError(f"target file is not a safe repository-relative path: {target_file}")
    target_path = safe_join(root, target_file)
    if not target_path.is_file():
        raise ValueError(f"target file does not exist in the snapshot: {target_file}")
    body = read_text(target_path)
    tree: ast.AST | None = None
    if language == "python":
        try:
            tree = ast.parse(body)
        except SyntaxError as exc:
            missing.append(f"python AST unavailable: line {exc.lineno}: {exc.msg}")
    elif language is None:
        missing.append(f"unsupported language for {target_file}")

    symbols: list[str] = []
    if tree is not None:
        for node in _ast_symbols(tree):
            name = _symbol_name(node)
            symbols.append(name)
            start, end = _span_of(node)
            facts.append(
                RepositoryFact(
                    fact_id=f"FACT-SYM-{len(symbols):03d}",
                    kind=FactKind.SYMBOL,
                    statement=f"{type(node).__name__.lower()} {name} spans {target_file}:{start}-{end}",
                    evidence=[
                        _snippet(
                            body,
                            target_file,
                            start,
                            min(end, start + 12),
                            max_chars=800,
                            method=FactMethod.PYTHON_AST,
                            capability="ast_symbol",
                        )
                    ],
                    method=FactMethod.PYTHON_AST,
                    status=FactStatus.VERIFIED,
                    capability="python_ast_symbol",
                )
            )
        critical_line = path.critical_operation.start_line if not target_safe_target_id else 1
        enclosing = _enclosing_symbol(tree, critical_line)
        if enclosing is not None:
            start, end = _span_of(enclosing)
            facts.append(
                RepositoryFact(
                    fact_id="FACT-TARGET-CONTEXT",
                    kind=FactKind.TARGET_CRITICAL_OPERATION,
                    statement=(
                        f"critical operation is inside {type(enclosing).__name__.lower()} "
                        f"{_symbol_name(enclosing)} ({target_file}:{start}-{end})"
                    ),
                    evidence=[
                        _snippet(
                            body,
                            target_file,
                            start,
                            min(end, start + 40),
                            max_chars=budget.max_chars,
                            method=FactMethod.PYTHON_AST,
                            capability="enclosing_symbol",
                        )
                    ],
                    method=FactMethod.PYTHON_AST,
                    status=FactStatus.VERIFIED,
                    capability="python_ast_enclosing_symbol",
                )
            )
    elif language is not None:
        pattern = re.compile(
            r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+|def\s+|func\s+|fn\s+)?"
            r"([A-Za-z_]\w*)\s*\(",
            re.M,
        )
        for index, match in enumerate(pattern.finditer(body), start=1):
            name = match.group(1)
            if name in {"if", "for", "while", "switch", "return", "catch"}:
                continue
            symbols.append(name)
            line = _line_of(body, match.start())
            facts.append(
                RepositoryFact(
                    fact_id=f"FACT-SYM-{index:03d}",
                    kind=FactKind.SYMBOL,
                    statement=f"text-pattern symbol candidate {name} at {target_file}:{line}",
                    evidence=[
                        _snippet(
                            body,
                            target_file,
                            line,
                            line,
                            max_chars=400,
                            method=FactMethod.TEXT_PATTERN,
                            capability="text_pattern",
                        )
                    ],
                    method=FactMethod.TEXT_PATTERN,
                    status=FactStatus.CANDIDATE,
                    capability="text_pattern_symbol_only",
                    notes=["no verified parser available for this language"],
                )
            )

    facts.extend(_protection_facts(root, target_file, tree, body))
    if tree is not None and symbols:
        call_facts, notes = _python_call_sites(root, target_file, symbols)
        facts.extend(call_facts)
        missing.extend(notes)
    elif language is not None:
        missing.append("call-graph extraction is unsupported for this language")

    facts.extend(_test_facts(root, target_file))
    if include_documentation:
        style, style_facts, style_notes = _documentation_style(root, budget)
        missing.extend(style_notes)
        facts.extend(style_facts)
    else:
        style = None

    related_files = sorted(
        {
            item.file
            for fact in facts
            for item in fact.evidence
            if item.file
        }
    )
    for index, relative in enumerate(related_files[: budget.max_files]):
        facts.append(
            RepositoryFact(
                fact_id=f"FACT-FILE-{index + 1:02d}",
                kind=FactKind.RELATED_FILE,
                statement=f"file referenced by at least one extracted fact: {relative}",
                evidence=[],
                method=FactMethod.FILE_SCAN,
                status=FactStatus.VERIFIED,
                capability="relative_path_only",
            )
        )

    # Apply the character/snippet budget deterministically.
    kept: list[RepositoryFact] = []
    chars = 0
    snippets = 0
    omitted: list[str] = []
    truncated = False
    for fact in facts:
        cost = sum(len(item.snippet or "") for item in fact.evidence)
        if snippets >= budget.max_snippets or chars + cost > budget.max_chars:
            truncated = True
            omitted.append(fact.fact_id)
            continue
        kept.append(fact)
        snippets += len(fact.evidence)
        chars += cost
    usage = ContextUsage(
        files=len({item.file for fact in kept for item in fact.evidence}),
        snippets=snippets,
        chars=chars,
        truncated=truncated,
        omitted_files=sorted(
            {Path(item).as_posix() for item in omitted if item.startswith(("/", "src", "app", "lib"))}
        ),
        reasons=["context_budget_exceeded"] if truncated else [],
    )
    if usage.files > budget.max_files:
        missing.append("context file budget exceeded; extra files omitted")

    language_capability = {
        "symbol_lookup": "python_ast" if language == "python" and tree is not None else (
            "text_pattern" if language else "unsupported"
        ),
        "call_graph": "python_ast_direct_calls"
        if language == "python" and tree is not None
        else "unsupported",
        "data_flow": "unsupported",
        "documentation_style": "extracted" if style is not None else "unsupported",
    }
    if language is not None and tree is None:
        missing.append("AST unavailable; symbol facts are text-pattern candidates")

    return RepositoryFacts(
        target_handle=target_handle,
        target_vulnerability_id=vulnerability_id,
        target_safe_target_id=target_safe_target_id,
        target_file=target_file,
        language=language,
        language_capability=language_capability,
        facts=kept,
        documentation_style=style,
        budget=budget,
        usage=usage,
        missing=missing,
    )
