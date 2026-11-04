"""Dataset input.

One reader: :mod:`vulnmirage.ingest.dataset_core` for the published package
(``manifest.json`` + task JSONL + private oracle JSONL).  No second dataset layout is
supported, so there is no second schema to keep in sync.
"""

from __future__ import annotations

from .dataset_core import (
    DatasetCore,
    TargetRecord,
    TaskRecord,
    eligibility_level,
    load_dataset_core,
    task_index_rows,
)

__all__ = [
    "DatasetCore",
    "TargetRecord",
    "TaskRecord",
    "eligibility_level",
    "load_dataset_core",
    "task_index_rows",
]
