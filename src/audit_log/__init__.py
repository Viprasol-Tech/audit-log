"""Audit Log — tamper-evident append-only audit log with hash chaining.

Part of Audit Log by Viprasol Tech Private Limited (https://viprasol.com).
"""

from __future__ import annotations

from audit_log.log import GENESIS_PREV_HASH, AuditLog, Entry
from audit_log.store import AppendOnlyError, InMemoryStore
from audit_log.verify import VerificationResult, verify_chain

__version__ = "0.1.0"
__author__ = "Viprasol Tech Private Limited"
__all__ = [
    "GENESIS_PREV_HASH",
    "AppendOnlyError",
    "AuditLog",
    "Entry",
    "InMemoryStore",
    "VerificationResult",
    "__version__",
    "verify_chain",
]
