"""Tamper-evident audit log: SHA-256 hash chain + Ed25519 signatures. Owner: S.

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

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

from urbanshield.schemas import AgentEvent, AuditEntry, VerifyResult

GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL,
    event_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    signature TEXT NOT NULL
)
"""
_COLUMNS = "seq, event_id, payload_sha256, prev_hash, hash, signature"


def canonical_json(obj: object) -> str:
    """Deterministic JSON: sorted keys, no whitespace, non-JSON values via ``str``."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _chain_hash(prev_hash: str, payload_sha256: str, seq: int) -> str:
    return _sha256(f"{prev_hash}{payload_sha256}{seq}")


class AuditLog:
    def __init__(self, db_path: Path, signing_key_hex: str | None = None) -> None:
        """Open or create the log. With no key, generate one and keep it in memory
        (fine for the demo; the verify key is exposed for judges)."""
        self._db_path = Path(db_path)
        self._key = SigningKey(bytes.fromhex(signing_key_hex)) if signing_key_hex else SigningKey.generate()
        with closing(self._connect()) as conn, conn:
            conn.execute(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    @property
    def verify_key_hex(self) -> str:
        """Public Ed25519 key, hex: anyone can check signatures with it."""
        return self._key.verify_key.encode().hex()

    def append(self, event: AgentEvent) -> AuditEntry:
        """Hash, chain, sign and store one event; returns its entry."""
        event_json = canonical_json(event.model_dump(mode="json"))
        payload_sha256 = _sha256(event_json)
        with closing(self._connect()) as conn, conn:
            # Take the write lock before reading the head, so concurrent appends queue up
            # instead of racing for the same seq.
            conn.execute("BEGIN IMMEDIATE")
            last = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev_hash = (last[0] + 1, last[1]) if last else (0, GENESIS)
            digest = _chain_hash(prev_hash, payload_sha256, seq)
            signature = self._key.sign(bytes.fromhex(digest)).signature.hex()
            conn.execute(
                "INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?, ?)",
                (seq, event.id, event_json, payload_sha256, prev_hash, digest, signature),
            )
        return AuditEntry(
            seq=seq,
            event_id=event.id,
            payload_sha256=payload_sha256,
            prev_hash=prev_hash,
            hash=digest,
            signature=signature,
        )

    def entries(self, after_seq: int = -1, limit: int | None = None) -> list[AuditEntry]:
        """Stored entries in ``seq`` order (as stored; ``verify()`` checks them), optionally
        only those after ``after_seq`` and at most ``limit`` of them."""
        query = f"SELECT {_COLUMNS} FROM audit_log WHERE seq > ? ORDER BY seq"
        params: tuple[int, ...] = (after_seq,)
        if limit is not None:
            query, params = f"{query} LIMIT ?", (after_seq, limit)
        with closing(self._connect()) as conn:
            rows = conn.execute(query, params).fetchall()
        return [AuditEntry(**dict(zip(_COLUMNS.split(", "), row, strict=True))) for row in rows]

    def head(self) -> AuditEntry | None:
        """The latest entry, or None for an empty log."""
        with closing(self._connect()) as conn:
            row = conn.execute(f"SELECT {_COLUMNS} FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        return AuditEntry(**dict(zip(_COLUMNS.split(", "), row, strict=True))) if row else None

    def verify(self) -> VerifyResult:
        """Recompute every payload hash, chain link and signature; report the first bad ``seq``."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT seq, event_id, event_json, payload_sha256, prev_hash, hash, signature "
                "FROM audit_log ORDER BY seq"
            ).fetchall()
        verify_key = self._key.verify_key
        expected_prev = GENESIS
        for n, row in enumerate(rows):
            digest, signature = row[5], row[6]
            reason = _check_row(n, row, expected_prev)
            if reason is None:
                try:
                    verify_key.verify(bytes.fromhex(digest), bytes.fromhex(signature))
                except (BadSignatureError, ValueError):
                    reason = "bad signature"
            if reason is not None:
                return VerifyResult(ok=False, entries=len(rows), first_bad_seq=n, reason=reason)
            expected_prev = digest
        return VerifyResult(ok=True, entries=len(rows))


def _check_row(n: int, row: tuple, expected_prev: str) -> str | None:
    """Why row ``n`` (all ``audit_log`` columns) is bad, or None if its hashes and links check out."""
    seq, event_id, event_json, payload_sha256, prev_hash, digest, _ = row
    if seq != n:
        return f"seq {seq} out of order (expected {n})"
    if _sha256(event_json) != payload_sha256:
        return "event does not match payload_sha256"
    try:
        stored_id = json.loads(event_json).get("id")
    except (json.JSONDecodeError, AttributeError):
        return "event_json is not a JSON object"
    if stored_id != event_id:
        return "event_id does not match event"
    if prev_hash != expected_prev:
        return "prev_hash does not link to previous entry"
    if _chain_hash(prev_hash, payload_sha256, seq) != digest:
        return "hash does not match chain"
    return None
