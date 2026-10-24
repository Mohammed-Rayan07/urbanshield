"""Pinned vulnerability feed (CISA KEV + FIRST EPSS + NVD CVSS snapshot). Owner: A.

The snapshot lives in ``data/feeds/feed_snapshot.json`` and its SHA-256 in
``data/feeds/feed_snapshot.sha256``. The default snapshot's digest is **also pinned in
code** (``FEED_SHA256``): the sidecar sits next to the data, so on its own it only catches
accidental or partial edits; the in-code pin means swapping both files still fails, and any
change to the pin shows up in code review. Every read re-hashes both files and fails closed: a
missing, altered or malformed feed raises ``FeedIntegrityError``; nothing falls back to
unverified data.

Snapshot format::

    {
      "generated": "2026-10-24",
      "sources": ["cisa-kev", "first-epss", "nvd"],
      "records": [
        {"cve_id": "CVE-2024-12345", "cvss": 7.5, "epss": 0.31, "kev": true,
         "vendor": "…", "product": "…", "summary": "…"}
      ]
    }
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from urbanshield.config import DATA_DIR
from urbanshield.schemas import Vulnerability

FEED_PATH = DATA_DIR / "feeds" / "feed_snapshot.json"
FEED_HASH_PATH = DATA_DIR / "feeds" / "feed_snapshot.sha256"
# Regenerate with scripts/build_feed_snapshot.py, which prints the new value.
FEED_SHA256 = "985cc150904f382802a7104e0caad4f9307ca029c0a14e2a0e8a3de35547e6f2"

_HEX64 = re.compile(r"[0-9a-f]{64}")


class FeedIntegrityError(RuntimeError):
    """The feed is missing, does not match its pinned SHA-256, or is malformed."""


def sha256_file(path: Path) -> str:
    """Hex SHA-256 of a file's bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_feed(path: Path = FEED_PATH, hash_path: Path = FEED_HASH_PATH) -> dict[str, Vulnerability]:
    """Verify the pinned hash, then return ``{cve_id: Vulnerability}``."""
    try:
        return {
            cve_id: Vulnerability(cve_id=cve_id, cvss=r["cvss"], epss=r["epss"], kev=r.get("kev", False))
            for cve_id, r in _records(path, hash_path).items()
        }
    except (KeyError, TypeError, ValidationError) as exc:
        raise FeedIntegrityError(f"invalid vulnerability record in {path.name}: {exc}") from exc


def feed_record(
    cve_id: str, path: Path = FEED_PATH, hash_path: Path = FEED_HASH_PATH
) -> dict[str, Any] | None:
    """Raw record for one CVE from the *verified* feed (used by the quarantine cross-check).

    ``None`` means "this CVE is not in the verified feed". A missing or tampered feed raises
    instead, so a caller can never mistake an unavailable feed for an unknown CVE.
    """
    record = _records(path, hash_path).get(cve_id)
    return dict(record) if record is not None else None


def _records(path: Path, hash_path: Path) -> dict[str, dict[str, Any]]:
    """Verified records keyed by CVE id. Both files are read and the digest checked on every
    call (the snapshot is ~20 KB); only the parse of an already-verified digest is cached.
    The in-code pin applies to the default snapshot; other paths (tests) rely on the sidecar."""
    try:
        data, pin = path.read_bytes(), hash_path.read_bytes()
    except FileNotFoundError as exc:
        raise FeedIntegrityError(f"missing feed or its pin: {exc.filename}") from exc
    actual = hashlib.sha256(data).hexdigest()
    words = pin.decode("ascii", errors="replace").split()
    expected = words[0].lower() if words else ""
    if not _HEX64.fullmatch(expected):
        raise FeedIntegrityError(f"malformed feed pin: {hash_path.name}")
    if not hmac.compare_digest(expected, actual):
        raise FeedIntegrityError(f"{path.name} does not match its pin ({expected[:12]}… ≠ {actual[:12]}…)")
    if path.resolve() == FEED_PATH.resolve() and not hmac.compare_digest(FEED_SHA256, actual):
        raise FeedIntegrityError(f"{path.name} does not match FEED_SHA256 pinned in city/feeds.py")
    return _parse(data, path.name)


@lru_cache(maxsize=8)
def _parse(data: bytes, name: str) -> dict[str, dict[str, Any]]:
    """Parse already-verified bytes; identical content is parsed once."""
    try:
        by_id: dict[str, dict[str, Any]] = {}
        for record in json.loads(data)["records"]:
            cve_id = record["cve_id"]
            if cve_id in by_id:
                raise FeedIntegrityError(f"duplicate record for {cve_id} in {name}")
            by_id[cve_id] = record
    except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError) as exc:
        raise FeedIntegrityError(f"invalid feed snapshot {name}: {exc}") from exc
    return by_id
