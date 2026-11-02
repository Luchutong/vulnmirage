"""Minimal generation context and repository introspection helpers."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from ..models import AttackGoal, CanonicalVulnerabilityOracle, VulnerabilityRecord
from ..paths import safe_join

_LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
}

_DOC_SUFFIXES = {".md", ".rst", ".txt", ".adoc", ".org"}

_FUNCTION_PATTERNS = {
    "python": [re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)", re.M)],
    "javascript": [
        re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", re.M),
        re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(", re.M),
    ],
    "typescript": [
        re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", re.M),
        re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(", re.M),
    ],
    "go": [re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)", re.M)],
    "java": [re.compile(r"\b(?:public|private|protected|static|final|\s)+[\w<>\[\]]+\s+([A-Za-z_]\w*)\s*\(", re.M)],
    "kotlin": [re.compile(r"\bfun\s+([A-Za-z_]\w*)", re.M)],
    "c": [re.compile(r"^[A-Za-z_][\w \t*]*\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{", re.M)],
    "cpp": [re.compile(r"^[A-Za-z_][\w \t*:&<>]*\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{", re.M)],
    "csharp": [re.compile(r"\b(?:public|private|protected|internal|static|\s)+[\w<>\[\]]+\s+([A-Za-z_]\w*)\s*\(", re.M)],
    "rust": [re.compile(r"\bfn\s+([A-Za-z_]\w*)", re.M)],
    "ruby": [re.compile(r"^\s*def\s+([A-Za-z_]\w*[?!]?)", re.M)],
    "php": [re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(", re.M)],
    "shell": [re.compile(r"^\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(\)\s*\{", re.M)],
}


class GenerationContext(BaseModel):
    """The minimal binding context allowed to reach a payload template."""

    model_config = ConfigDict(extra="forbid")

    project_name: str
    language: str | None
    vulnerability_type: str
    cwe: list[str]
    target_component: str
    visible_function_names: list[str]
    attack_goal: AttackGoal
    carrier: str


def language_for(path: str) -> str | None:
    return _LANGUAGE_BY_SUFFIX.get(Path(path).suffix.lower())


def is_documentation(path: str) -> bool:
    return Path(path).suffix.lower() in _DOC_SUFFIXES


def is_code(path: str) -> bool:
    return language_for(path) is not None


def project_name_from_repo_url(repo_url: str) -> str:
    text = repo_url.rstrip("/")
    if "://" in text and not text.startswith("file:"):
        text = text.split("?", 1)[0]
        name = text.rsplit("/", 1)[-1]
    else:
        name = Path(text.replace("file://", "")).name
    name = name.removesuffix(".git")
    return name or "repository"


def visible_function_names(root: Path, relative: str, limit: int = 50) -> list[str]:
    try:
        path = safe_join(Path(root), relative)
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    language = language_for(relative)
    if language == "python":
        try:
            tree = ast.parse(text)
        except SyntaxError:
            tree = None
        if tree is not None:
            names: list[str] = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if node.name not in names:
                        names.append(node.name)
                    if len(names) >= limit:
                        return names
            return names
    patterns = _FUNCTION_PATTERNS.get(language or "", [])
    names = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            name = match.group(1)
            if name and name not in names:
                names.append(name)
            if len(names) >= limit:
                return names
    return names


def _pick_vulnerability(
    oracle: CanonicalVulnerabilityOracle,
    target_vulnerability_id: str | None,
    target_file: str | None,
) -> VulnerabilityRecord:
    if target_vulnerability_id:
        for vulnerability in oracle.vulnerabilities:
            if vulnerability.vulnerability_id == target_vulnerability_id:
                return vulnerability
        raise ValueError(f"unknown target vulnerability id: {target_vulnerability_id}")
    if target_file:
        for vulnerability in oracle.vulnerabilities:
            if any(
                path.entry_point.file == target_file or path.critical_operation.file == target_file
                for path in vulnerability.paths
            ):
                return vulnerability
    return sorted(oracle.vulnerabilities, key=lambda item: item.vulnerability_id)[0]


def build_context(
    oracle: CanonicalVulnerabilityOracle,
    root: Path,
    *,
    attack_goal: AttackGoal,
    carrier: str,
    target_file: str | None = None,
    vulnerability_type: str | None = None,
    target_vulnerability_id: str | None = None,
    path_id: str | None = None,
) -> GenerationContext:
    vulnerability = _pick_vulnerability(oracle, target_vulnerability_id, target_file)
    paths = vulnerability.paths
    selected_path = paths[0]
    if path_id:
        selected_path = next((item for item in paths if item.path_id == path_id), None) or paths[0]
    elif target_file:
        selected_path = next(
            (
                item
                for item in paths
                if target_file in {item.entry_point.file, item.critical_operation.file}
            ),
            paths[0],
        )
    file_for_component = target_file or selected_path.critical_operation.file
    return GenerationContext(
        project_name=project_name_from_repo_url(oracle.repository.repo_url),
        language=language_for(file_for_component),
        vulnerability_type=vulnerability_type or vulnerability.title,
        cwe=list(vulnerability.cwe),
        target_component=Path(file_for_component).stem,
        visible_function_names=visible_function_names(root, file_for_component),
        attack_goal=attack_goal,
        carrier=carrier,
    )


def _iter_repository_files(root: Path) -> list[str]:
    root = Path(root)
    files: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        files.append(relative.as_posix())
    return sorted(files)


def build_safe_target_context(
    oracle: CanonicalVulnerabilityOracle,
    root: Path,
    *,
    safe_target,
    attack_goal: AttackGoal,
    carrier: str,
) -> GenerationContext:
    """Build the payload context for a **validated** safe target.

    The vulnerability type and CWE come from the safe target contract itself;
    they are never overwritten with a hard-coded CWE.
    """
    vulnerability = None
    for candidate in oracle.vulnerabilities:
        if safe_target.cwe in candidate.cwe:
            vulnerability = candidate
            break
    return GenerationContext(
        project_name=project_name_from_repo_url(oracle.repository.repo_url),
        language=language_for(safe_target.file),
        vulnerability_type=safe_target.vulnerability_type,
        cwe=[safe_target.cwe],
        target_component=Path(safe_target.file).stem,
        visible_function_names=visible_function_names(root, safe_target.file),
        attack_goal=attack_goal,
        carrier=carrier,
    )


def source_files_with_extensions(root: Path, extensions: set[str], limit: int = 400) -> list[str]:
    return [
        item
        for item in _iter_repository_files(root)
        if Path(item).suffix.lower() in extensions
    ][:limit]
