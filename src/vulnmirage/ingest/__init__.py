"""Dataset adapters."""

from __future__ import annotations

from .adapter import (
    DatasetAdapter,
    DatasetCapabilities,
    DatasetInspection,
    DatasetIssue,
    NormalizationResult,
    RawRecord,
)
from .base import build_oracle, parse_line_range, read_jsonl
from .generic_jsonl import ingest_generic_jsonl
from .vulngym import ingest_vulngym, load_oracles
from .vulnmirage_dataset import VulnMirageDatasetAdapter, ingest_vulnmirage_dataset

__all__ = [
    "DatasetAdapter",
    "DatasetCapabilities",
    "DatasetInspection",
    "DatasetIssue",
    "NormalizationResult",
    "RawRecord",
    "VulnMirageDatasetAdapter",
    "build_oracle",
    "ingest_generic_jsonl",
    "ingest_vulngym",
    "ingest_vulnmirage_dataset",
    "load_oracles",
    "parse_line_range",
    "read_jsonl",
]
