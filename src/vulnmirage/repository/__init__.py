"""Repository snapshots.

One mechanism: :mod:`vulnmirage.repository.archive` fetches the hosting provider's
archive for one exact commit and unpacks it under a budget.  There is no local clone
and no ``.git``, because a clone would ship the fix commit inside the workspace.
"""

from __future__ import annotations

__all__ = ["archive"]
