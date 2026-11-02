"""Backward-compatible import location for the dataset adapter interface."""

from __future__ import annotations

from .adapter import (
    DatasetAdapter,
    DatasetCapabilities,
    DatasetInspection,
    DatasetIssue,
    NormalizationResult,
    RawRecord,
)

__all__ = [
    "DatasetAdapter",
    "DatasetCapabilities",
    "DatasetInspection",
    "DatasetIssue",
    "NormalizationResult",
    "RawRecord",
]
