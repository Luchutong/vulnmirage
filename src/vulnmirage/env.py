"""Minimal, dependency-free ``.env`` loading for local credentials.

Only *local* convenience is provided: values are loaded into ``os.environ`` and
never printed or logged.  Existing process environment variables always win, so
a shell export can override a stale ``.env`` without editing the file.

Supported syntax (deliberately small):

* ``KEY=value`` / ``export KEY=value``
* single/double quoted values (double quotes support ``\\n``, ``\\t``, ``\\"``,
  ``\\\\``)
* blank lines and ``#`` comments, plus trailing `` # comment`` on unquoted values
* keys must match ``[A-Za-z_][A-Za-z0-9_]*``

Variable expansion, command substitution and multi-line values are **not**
implemented; malformed lines are skipped and reported (without their value).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .paths import project_root

ENV_FILE_VARIABLE = "VULNMIRAGE_ENV_FILE"
_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}

_LAST_LOADED: dict[str, "FloatPath"] = {}
_FROM_FILE: set[str] = set()


@dataclass(frozen=True)
class FloatPath:
    path: Path
    mtime_ns: int


@dataclass
class EnvLoadResult:
    """Outcome of loading a ``.env`` file; contains no secret values."""

    loaded: bool = False
    path: Path | None = None
    keys: list[str] = field(default_factory=list)
    skipped_existing: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    searched: list[Path] = field(default_factory=list)

    def status(self) -> dict[str, object]:
        return {
            "loaded": self.loaded,
            "path": str(self.path) if self.path else None,
            "keys": sorted(self.keys),
            "skipped_existing": sorted(self.skipped_existing),
            "warnings": list(self.warnings),
            "values_are_never_logged": True,
        }


def find_env_file(explicit: str | Path | None = None) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        return path
    configured = os.environ.get(ENV_FILE_VARIABLE)
    if configured:
        path = Path(configured).expanduser()
        return path if path.is_absolute() else (Path.cwd() / path).resolve()
    for base in (Path.cwd(), project_root()):
        candidate = base / ".env"
        if candidate.is_file():
            return candidate.resolve()
    return None


def _unquote(value: str) -> tuple[str, str | None]:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        quote = value[0]
        body = value[1:-1]
        if quote == '"':
            out: list[str] = []
            index = 0
            while index < len(body):
                char = body[index]
                if char == "\\" and index + 1 < len(body):
                    following = body[index + 1]
                    out.append(_ESCAPES.get(following, following))
                    index += 2
                    continue
                out.append(char)
                index += 1
            return "".join(out), None
        return body, None
    # Trailing comment only when preceded by whitespace (URLs may contain '#').
    match = re.search(r"\s+#", value)
    if match:
        value = value[: match.start()]
    return value.strip(), None


def parse_env_text(text: str) -> tuple[dict[str, str], list[str]]:
    """Parse ``.env`` content into values, returning malformed-line warnings."""
    values: dict[str, str] = {}
    warnings: list[str] = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            warnings.append(f"line {line_number}: missing '='; skipped")
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not _KEY_RE.match(key):
            warnings.append(f"line {line_number}: invalid key; skipped")
            continue
        parsed, error = _unquote(value.strip())
        if error:
            warnings.append(f"line {line_number}: {error}; skipped")
            continue
        values[key] = parsed
    return values, warnings


def load_env_file(
    path: str | Path | None = None,
    *,
    override: bool = False,
) -> EnvLoadResult:
    """Load one ``.env`` file into ``os.environ`` without logging values."""
    resolved = find_env_file(path)
    result = EnvLoadResult()
    if resolved is None:
        result.warnings.append("no .env file found")
        return result
    result.path = resolved
    if not resolved.is_file():
        result.warnings.append(f".env file not found: {resolved}")
        return result
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        result.warnings.append(f"cannot read .env file: {exc}")
        return result
    values, warnings = parse_env_text(text)
    result.warnings.extend(warnings)
    for key, value in values.items():
        if key in os.environ and not override:
            result.skipped_existing.append(key)
            continue
        os.environ[key] = value
        _FROM_FILE.add(key)
        result.keys.append(key)
    try:
        mode = resolved.stat().st_mode
        if os.name != "nt" and mode & 0o077:
            result.warnings.append(
                ".env is readable by group/others; consider chmod 600"
            )
    except OSError:
        pass
    result.loaded = True
    try:
        _LAST_LOADED[str(resolved)] = FloatPath(
            resolved, resolved.stat().st_mtime_ns
        )
    except OSError:
        pass
    return result


def load_local_env(
    path: str | Path | None = None,
    *,
    override: bool = False,
    once: bool = True,
) -> EnvLoadResult:
    """Load the local ``.env`` at most once per file version.

    ``once=True`` avoids repeated parsing in library calls; pass ``override=True``
    or a different ``path`` to force a reload.
    """
    resolved = find_env_file(path)
    if resolved is not None and once and not override:
        try:
            mtime = resolved.stat().st_mtime_ns
        except OSError:
            mtime = -1
        previous = _LAST_LOADED.get(str(resolved))
        if previous is not None and previous.mtime_ns == mtime:
            return EnvLoadResult(
                loaded=True,
                path=resolved,
                keys=[],
                warnings=["already loaded in this process"],
            )
    return load_env_file(resolved, override=override)


def reset_env_cache() -> None:
    """Test helper: forget which files were loaded."""
    _LAST_LOADED.clear()
    _FROM_FILE.clear()


def secret_environment_status(names: Iterable[str]) -> list[dict[str, object]]:
    """Report presence/source of secret variables without their values.

    Returned as a list of ``{name, present, source}`` objects so that logging
    redaction cannot replace the whole status entry merely because the variable
    name ends in ``_API_KEY``.
    """
    output: list[dict[str, object]] = []
    for name in names:
        value = os.environ.get(name)
        output.append(
            {
                "name": name,
                "present": bool(value),
                "source": (
                    "env_file"
                    if value and name in _FROM_FILE
                    else "environment"
                    if value
                    else "missing"
                ),
            }
        )
    return output


def last_loaded_path() -> Path | None:
    if not _LAST_LOADED:
        return None
    return next(iter(_LAST_LOADED.values())).path

