"""Tests for hash chaining, verification, and the append-only store."""

from __future__ import annotations

import itertools

import pytest

from audit_log.log import GENESIS_PREV_HASH, AuditLog, compute_hash
from audit_log.store import AppendOnlyError, InMemoryStore
from audit_log.verify import verify_chain


def _sample_log() -> AuditLog:
    log = AuditLog()
    log.append("alice", "login", "console", {"ip": "10.0.0.1"})
    log.append("alice", "create", "record:42", {"fields": 3})
    log.append("bob", "update", "record:42", {"amount": 100})
    log.append("bob", "delete", "record:42", {"reason": "cleanup"})
    return log


def test_first_entry_chains_from_genesis() -> None:
    log = AuditLog()
    entry = log.append("alice", "login", "console")
    assert entry.index == 0
    assert entry.prev_hash == GENESIS_PREV_HASH
    assert len(entry.hash) == 64


def test_each_entry_links_to_prev_hash() -> None:
    entries = _sample_log().entries
    for prev, curr in itertools.pairwise(entries):
        assert curr.prev_hash == prev.hash


def test_verify_passes_on_intact_chain() -> None:
    result = verify_chain(_sample_log().entries)
    assert result.ok is True
    assert result.first_tampered_index is None
    assert result.length == 4


def test_empty_chain_is_valid() -> None:
    result = verify_chain(())
    assert result.ok is True
    assert result.length == 0


def test_mutating_middle_entry_detected_at_right_index() -> None:
    entries = _sample_log().entries
    forged = entries[2].model_copy(update={"metadata": {"amount": 999_999}})
    tampered = (*entries[:2], forged, *entries[3:])

    result = verify_chain(tampered)
    assert result.ok is False
    assert result.first_tampered_index == 2


def test_broken_link_detected() -> None:
    entries = _sample_log().entries
    # Recompute a valid hash for tampered content so the content check passes,
    # leaving only the prev_hash link broken at index 1.
    bad = entries[1].model_copy(update={"prev_hash": GENESIS_PREV_HASH})
    bad = bad.model_copy(update={"hash": bad.recompute_hash()})
    tampered = (entries[0], bad, *entries[2:])

    result = verify_chain(tampered)
    assert result.ok is False
    assert result.first_tampered_index == 1
    assert result.reason is not None and "link" in result.reason


def test_hashing_is_deterministic() -> None:
    a = _sample_log().entries
    b = _sample_log().entries
    assert [e.hash for e in a] == [e.hash for e in b]


def test_compute_hash_known_value() -> None:
    # Locks the genesis hashing recipe to a known digest so accidental changes
    # to the canonical encoding are caught.
    digest = compute_hash(
        index=0,
        actor="alice",
        action="login",
        target="console",
        metadata={},
        prev_hash=GENESIS_PREV_HASH,
    )
    assert digest == "483b3ecbc1416adf875a0b29649c3c85f4cb30ee46565fe253fdca39df19f45e"


def test_store_rejects_mutation() -> None:
    log = AuditLog()
    entry = log.append("alice", "login", "console")
    store = InMemoryStore()
    store.append(entry)
    with pytest.raises(AppendOnlyError):
        store[0] = entry


def test_store_rejects_deletion() -> None:
    log = AuditLog()
    entry = log.append("alice", "login", "console")
    store = InMemoryStore()
    store.append(entry)
    with pytest.raises(AppendOnlyError):
        del store[0]
