"""Append-only audit log with SHA-256 hash chaining.

Each :class:`Entry` carries a ``hash`` computed over its own fields *and* the
hash of the entry before it (``prev_hash``). The first entry chains from a
fixed genesis value of 64 zero hex characters. Because every hash depends on
the entire history, altering any field of any past entry breaks the chain from
that point forward — which :func:`audit_log.verify.verify_chain` detects.

The hashing is fully deterministic: the same sequence of appends always yields
byte-identical hashes, so two independent replicas of the log can be compared
hash-for-hash.

Part of Audit Log by Viprasol Tech Private Limited (https://viprasol.com).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field

from audit_log.store import InMemoryStore

#: Genesis ``prev_hash`` for the very first entry: 64 zero hex characters.
GENESIS_PREV_HASH = "0" * 64


def compute_hash(
    *,
    index: int,
    actor: str,
    action: str,
    target: str,
    metadata: Mapping[str, object],
    prev_hash: str,
) -> str:
    """Return the SHA-256 hex digest binding an entry to its predecessor.

    The pre-image is a canonical JSON object with sorted keys and compact
    separators, so the digest depends only on the values — never on dict
    ordering or incidental whitespace. This makes the hash deterministic and
    reproducible across processes and platforms.

    Args:
        index: Zero-based position of the entry in the chain.
        actor: Who performed the action.
        action: What was done.
        target: What the action was performed on.
        metadata: Arbitrary JSON-serialisable context.
        prev_hash: Hash of the preceding entry (genesis for the first).

    Returns:
        A 64-character lowercase hex SHA-256 digest.
    """
    payload = {
        "index": index,
        "actor": actor,
        "action": action,
        "target": target,
        "metadata": metadata,
        "prev_hash": prev_hash,
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class Entry(BaseModel):
    """A single immutable record in the audit chain.

    Attributes:
        index: Zero-based position in the chain.
        actor: The principal that performed the action.
        action: The action performed (e.g. ``"login"``, ``"delete"``).
        target: The object acted upon (e.g. a resource id).
        metadata: Arbitrary JSON-serialisable context for the event.
        prev_hash: Hash of the previous entry (genesis for the first).
        hash: This entry's hash; see :func:`compute_hash`.
    """

    model_config = ConfigDict(frozen=True)

    index: int = Field(ge=0)
    actor: str
    action: str
    target: str
    metadata: dict[str, object] = Field(default_factory=dict)
    prev_hash: str
    hash: str

    def recompute_hash(self) -> str:
        """Recompute this entry's hash from its current field values."""
        return compute_hash(
            index=self.index,
            actor=self.actor,
            action=self.action,
            target=self.target,
            metadata=self.metadata,
            prev_hash=self.prev_hash,
        )


class AuditLog:
    """An append-only, hash-chained audit log.

    Wraps an append-only store (defaulting to an in-memory one) and links every
    new entry to the previous one via :func:`compute_hash`. Entries can only be
    appended; the underlying store rejects any mutation of existing records.

    Example:
        >>> log = AuditLog()
        >>> e0 = log.append("alice", "login", "console")
        >>> e1 = log.append("alice", "delete", "record:42")
        >>> e1.prev_hash == e0.hash
        True
    """

    def __init__(self, store: InMemoryStore | None = None) -> None:
        """Create a log, optionally backed by a custom append-only store."""
        self._store = store if store is not None else InMemoryStore()

    def append(
        self,
        actor: str,
        action: str,
        target: str,
        metadata: Mapping[str, object] | None = None,
    ) -> Entry:
        """Append a new event and return the created :class:`Entry`.

        Args:
            actor: Who performed the action.
            action: What was done.
            target: What the action was performed on.
            metadata: Optional JSON-serialisable context.

        Returns:
            The newly appended, hash-chained entry.
        """
        index = len(self._store)
        prev_hash = self._store[-1].hash if index else GENESIS_PREV_HASH
        meta: dict[str, object] = dict(metadata) if metadata else {}
        entry_hash = compute_hash(
            index=index,
            actor=actor,
            action=action,
            target=target,
            metadata=meta,
            prev_hash=prev_hash,
        )
        entry = Entry(
            index=index,
            actor=actor,
            action=action,
            target=target,
            metadata=meta,
            prev_hash=prev_hash,
            hash=entry_hash,
        )
        self._store.append(entry)
        return entry

    @property
    def entries(self) -> tuple[Entry, ...]:
        """An immutable snapshot of all entries in append order."""
        return self._store.entries()

    @property
    def head(self) -> str:
        """Hash of the latest entry, or the genesis hash if the log is empty."""
        return self._store[-1].hash if len(self._store) else GENESIS_PREV_HASH

    def __len__(self) -> int:
        """Number of entries currently in the log."""
        return len(self._store)
