"""Tamper-evident audit log: SHA-256 hash chain + Ed25519 signatures. Owner: A (after h6).

Entry ``n``::

    payload_sha256 = sha256(canonical_json(event))
    hash           = sha256(prev_hash || payload_sha256 || seq)      # hex
    signature      = ed25519_sign(hash)                               # hex

``prev_hash`` of entry 0 is 64 zeros. ``canonical_json`` = ``json.dumps(obj,
sort_keys=True, separators=(",", ":"), default=str)``.

Storage is one SQLite table ``audit_log(seq, event_id, event_json, payload_sha256,
prev_hash, hash, signature)``. ``verify()`` re-reads every row, recomputes the payload
hash from ``event_json``, the chain hash and the signature, and reports the first bad
``seq``. Editing a single byte of any stored event must make ``verify()`` fail at
exactly that entry (this is a live demo moment).
"""

from __future__ import annotations

from pathlib import Path

from urbanshield.schemas import AgentEvent, AuditEntry, VerifyResult

GENESIS = "0" * 64


def canonical_json(obj: object) -> str:
    raise NotImplementedError


class AuditLog:
    def __init__(self, db_path: Path, signing_key_hex: str | None = None) -> None:
        """Open or create the log. With no key, generate one and keep it in memory
        (fine for the demo; the verify key is exposed for judges)."""
        raise NotImplementedError

    @property
    def verify_key_hex(self) -> str:
        raise NotImplementedError

    def append(self, event: AgentEvent) -> AuditEntry:
        raise NotImplementedError

    def entries(self) -> list[AuditEntry]:
        raise NotImplementedError

    def verify(self) -> VerifyResult:
        raise NotImplementedError
