"""Verification of audit-log integrity.

:func:`verify_chain` walks a sequence of entries and confirms three properties
at every position:

1. **Index monotonicity** — each entry's ``index`` equals its position.
2. **Link integrity** — each entry's ``prev_hash`` equals the previous entry's
   ``hash`` (the genesis value for the first entry).
3. **Content integrity** — each entry's ``hash`` equals a fresh recomputation
   over its own fields.

The first position where any check fails is reported, so callers can pinpoint
exactly where tampering occurred.

Part of Audit Log by Viprasol Tech Private Limited (https://viprasol.com).
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel

from audit_log.log import GENESIS_PREV_HASH, Entry


class VerificationResult(BaseModel):
    """Outcome of verifying a chain.

    Attributes:
        ok: ``True`` if the entire chain is intact.
        first_tampered_index: Index of the first broken entry, or ``None`` when
            the chain is intact.
        reason: Human-readable explanation when ``ok`` is ``False``.
        length: Number of entries inspected.
    """

    ok: bool
    first_tampered_index: int | None = None
    reason: str | None = None
    length: int = 0


def verify_chain(entries: Sequence[Entry]) -> VerificationResult:
    """Verify that a sequence of entries forms an intact hash chain.

    Args:
        entries: Entries in append order (as returned by ``AuditLog.entries``).

    Returns:
        A :class:`VerificationResult`. For an empty sequence the result is
        ``ok=True``. Otherwise ``first_tampered_index`` points at the earliest
        position that fails any integrity check.
    """
    expected_prev = GENESIS_PREV_HASH
    for position, entry in enumerate(entries):
        if entry.index != position:
            return VerificationResult(
                ok=False,
                first_tampered_index=position,
                reason=f"index mismatch: expected {position}, found {entry.index}",
                length=len(entries),
            )
        if entry.prev_hash != expected_prev:
            return VerificationResult(
                ok=False,
                first_tampered_index=position,
                reason=f"broken link at index {position}: prev_hash does not match prior hash",
                length=len(entries),
            )
        if entry.recompute_hash() != entry.hash:
            return VerificationResult(
                ok=False,
                first_tampered_index=position,
                reason=f"content tampered at index {position}: hash does not match fields",
                length=len(entries),
            )
        expected_prev = entry.hash

    return VerificationResult(ok=True, first_tampered_index=None, length=len(entries))
