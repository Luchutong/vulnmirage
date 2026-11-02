"""Validation pipeline.

The package ``__init__`` is deliberately lazy: ``vulnmirage.generation`` needs
individual validation helpers (command execution) while the validation pipeline
itself imports generation modules.  Eagerly importing the pipeline here would
create a circular import.
"""

from __future__ import annotations

from typing import Any


def validate_instance(*args: Any, **kwargs: Any):
    from .pipeline import validate_instance as _validate_instance

    return _validate_instance(*args, **kwargs)


def __getattr__(name: str) -> Any:
    if name == "check_semantic_preservation":
        from .oracle_invariance import check_semantic_preservation

        return check_semantic_preservation
    raise AttributeError(name)


__all__ = ["validate_instance"]
