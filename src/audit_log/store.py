"""In-memory append-only storage for audit entries.

The store models the durability layer an audit log would normally delegate to a
database or write-once medium. It is deliberately minimal but enforces the one
invariant that matters: records can be *appended* and *read*, never *mutated*
or *removed*. Any attempt to overwrite or delete an existing entry raises
:class:`AppendOnlyError`.

Part of Audit Log by Viprasol Tech Private Limited (https://viprasol.com).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from audit_log.log import Entry


class AppendOnlyError(RuntimeError):
    """Raised when code attempts to mutate or delete an existing entry."""


class InMemoryStore:
    """A list-like store that only permits appends and reads.

    The store owns its entries privately and exposes them through an immutable
    tuple snapshot. Indexed reads (including ``store[-1]``) are allowed for
    convenience, but item assignment and deletion are rejected to preserve the
    append-only guarantee.

    Example:
        >>> store = InMemoryStore()
        >>> len(store)
        0
    """

    def __init__(self) -> None:
        """Create an empty append-only store."""
        self._entries: list[Entry] = []

    def append(self, entry: Entry) -> None:
        """Append a new entry to the end of the store.

        Args:
            entry: The entry to store.
        """
        self._entries.append(entry)

    def entries(self) -> tuple[Entry, ...]:
        """Return an immutable snapshot of all entries in append order."""
        return tuple(self._entries)

    def __len__(self) -> int:
        """Return the number of stored entries."""
        return len(self._entries)

    def __getitem__(self, index: int) -> Entry:
        """Return the entry at ``index`` (negative indices allowed)."""
        return self._entries[index]

    def __iter__(self):  # type: ignore[no-untyped-def]
        """Iterate over stored entries in append order."""
        return iter(self._entries)

    def __setitem__(self, index: int, value: Entry) -> None:
        """Reject in-place mutation of an existing entry."""
        raise AppendOnlyError("audit entries are immutable; mutation is not permitted")

    def __delitem__(self, index: int) -> None:
        """Reject deletion of an existing entry."""
        raise AppendOnlyError("audit entries cannot be deleted from an append-only log")
