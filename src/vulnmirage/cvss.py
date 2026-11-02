"""CVSS v2/v3 base-score arithmetic used for dataset validation.

The dataset adapter refuses severity records whose ``vector`` and ``score``
disagree, so a real (small) calculator is required rather than a table of
magic numbers.  CVSS v4 vectors are parsed for their metric set but their score
is not recomputed (the v4 scoring model differs); those records must carry an
adjudicated score.
"""

from __future__ import annotations

import math
import re

from .errors import SchemaError

_CVSS31_PREFIXES = ("CVSS:3.0/", "CVSS:3.1/")

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_SCOPE = {"U": False, "C": True}

_CVSS2_AV = {"L": 0.395, "A": 0.646, "N": 1.0}
_CVSS2_AC = {"H": 0.35, "M": 0.61, "L": 0.71}
_CVSS2_AU = {"M": 0.45, "S": 0.56, "N": 0.704}
_CVSS2_CIA = {"N": 0.0, "P": 0.275, "C": 0.660}
_CVSS2_IMPACT_WEIGHT = {"N": 0.0, "P": 0.275, "C": 0.660}

_VECTOR_RE = re.compile(r"^(?:CVSS:[0-9.]+/)?(?P<body>[A-Za-z]{1,2}:[A-Za-z]+(?:/[A-Za-z]{1,2}:[A-Za-z]+)+)$")
_SIMPLE_VERSION_RE = re.compile(r"CVSS:([0-9]+(?:\.[0-9]+)?)")


def cvss_version(vector: str) -> str | None:
    """Return ``"3.0"``/``"3.1"``/``"2.0"``/``"4.0"`` when detectable."""
    text = (vector or "").strip()
    match = _SIMPLE_VERSION_RE.match(text)
    if match:
        value = match.group(1)
        if value.startswith("4"):
            return "4.0"
        if value.startswith("3"):
            return value
        if value.startswith("2"):
            return "2.0"
        return value
    if text.startswith("AV:") and "/" in text:
        return "2.0"
    return None


def parse_vector(vector: str) -> dict[str, str]:
    text = (vector or "").strip()
    if not text:
        raise SchemaError("CVSS vector is empty")
    for prefix in _CVSS31_PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    else:
        if text.startswith("CVSS:"):
            prefix, _, rest = text.partition("/")
            text = rest
    metrics: dict[str, str] = {}
    for part in text.split("/"):
        if not part:
            continue
        key, _, value = part.partition(":")
        if not key or not value:
            raise SchemaError(f"malformed CVSS vector component: {part!r}", details={"vector": vector})
        metrics[key.upper()] = value.upper()
    if not metrics:
        raise SchemaError("CVSS vector has no metrics", details={"vector": vector})
    return metrics


def _round_up(value: float) -> float:
    # CVSS v3.1 uses "round up" (ceiling) at one decimal place, not half-even.
    integer = int(value * 10 + 0.999999999)
    return integer / 10.0


def cvss31_base_score(metrics: dict[str, str]) -> float | None:
    try:
        changed = _SCOPE[metrics["S"]]
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[metrics["PR"]]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except KeyError as exc:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if changed:
        return _round_up(min(1.08 * (impact + exploitability), 10.0))
    return _round_up(min(impact + exploitability, 10.0))


def cvss2_base_score(metrics: dict[str, str]) -> float | None:
    try:
        av = _CVSS2_AV[metrics["AV"]]
        ac = _CVSS2_AC[metrics["AC"]]
        au = _CVSS2_AU[metrics["AU"]]
        cia = [_CVSS2_CIA[metrics[key]] for key in ("C", "I", "A")]
    except KeyError:
        return None
    impact = 10.41 * (1 - math.prod(1 - value for value in cia))
    exploitability = 20 * av * ac * au
    f_impact = 0.0 if impact == 0 else 1.176
    return round(min(10.0, (0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact, 1)


def vector_base_score(vector: str) -> float | None:
    """Compute the base score for a supported vector; ``None`` when unsupported."""
    version = cvss_version(vector)
    try:
        metrics = parse_vector(vector)
    except SchemaError:
        return None
    if version in {"3.0", "3.1"}:
        return cvss31_base_score(metrics)
    if version == "2.0":
        return cvss2_base_score(metrics)
    return None


def vector_metric(vector: str, name: str) -> str | None:
    try:
        return parse_vector(vector).get(name.upper())
    except SchemaError:
        return None
