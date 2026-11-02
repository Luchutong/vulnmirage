"""CWE and severity normalization shared by ingestion and evaluation."""

from __future__ import annotations

import re

from .errors import SchemaError
from .models.enums import SEVERITY_ORDINAL, SeverityLevel

_CWE_RE = re.compile(r"(?:CWE[-_ ]?)?(\d{1,6})", re.I)

_SEVERITY_ALIASES = {
    "critical": SeverityLevel.CRITICAL,
    "crit": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "important": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "moderate": SeverityLevel.MEDIUM,
    "med": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "minor": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
    "informational": SeverityLevel.INFO,
    "information": SeverityLevel.INFO,
    "none": SeverityLevel.INFO,
    "negligible": SeverityLevel.INFO,
}


def normalize_cwe(value: str | int) -> str:
    """Normalize CWE representations to ``CWE-<number>``.

    Raises :class:`SchemaError` if no CWE number can be recovered.
    """
    text = str(value).strip()
    match = _CWE_RE.search(text)
    if not match:
        raise SchemaError(f"cannot normalize CWE value: {value!r}", details={"value": text})
    number = int(match.group(1))
    if number <= 0:
        raise SchemaError(f"invalid CWE number: {value!r}", details={"value": text})
    return f"CWE-{number}"


def normalize_cwe_list(values: str | int | list[str] | tuple[str, ...] | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, int)):
        raw = [str(values)]
    else:
        raw = [str(item) for item in values]
    output: list[str] = []
    for item in raw:
        for piece in re.split(r"[,;|]", item):
            piece = piece.strip()
            if not piece:
                continue
            cwe = normalize_cwe(piece)
            if cwe not in output:
                output.append(cwe)
    return sorted(output)


def normalize_severity(value: str | SeverityLevel | None) -> SeverityLevel:
    if isinstance(value, SeverityLevel):
        return value
    if value is None or not str(value).strip():
        raise SchemaError("severity is missing")
    text = str(value).strip().lower()
    if text in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[text]
    # Accept "CVSS 8.1"-style values only when an explicit word is present.
    for word, level in _SEVERITY_ALIASES.items():
        if word in text:
            return level
    raise SchemaError(f"cannot normalize severity: {value!r}", details={"value": text})


def severity_ordinal(level: SeverityLevel | str) -> int:
    return SEVERITY_ORDINAL[level if isinstance(level, SeverityLevel) else SeverityLevel(level)]


def severity_from_score(score: float) -> SeverityLevel:
    if score >= 9.0:
        return SeverityLevel.CRITICAL
    if score >= 7.0:
        return SeverityLevel.HIGH
    if score >= 4.0:
        return SeverityLevel.MEDIUM
    if score > 0.0:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


def severity_from_ordinal(value: int) -> SeverityLevel:
    for level, ordinal in SEVERITY_ORDINAL.items():
        if ordinal == value:
            return level
    raise SchemaError(f"severity ordinal out of range: {value}")
