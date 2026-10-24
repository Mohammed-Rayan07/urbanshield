"""Pinned vulnerability feed (CISA KEV + FIRST EPSS + NVD CVSS snapshot). Owner: A.

The snapshot lives in ``data/feeds/feed_snapshot.json`` and its SHA-256 in
``data/feeds/feed_snapshot.sha256``. Loading verifies the hash first, so a tampered
feed is refused instead of silently changing every plan.

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
from pathlib import Path

from urbanshield.config import DATA_DIR
from urbanshield.schemas import Vulnerability

FEED_PATH = DATA_DIR / "feeds" / "feed_snapshot.json"
FEED_HASH_PATH = DATA_DIR / "feeds" / "feed_snapshot.sha256"


class FeedIntegrityError(RuntimeError):
    """The feed file does not match its pinned SHA-256."""


def sha256_file(path: Path) -> str:
    """Hex SHA-256 of a file's bytes."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_feed(path: Path = FEED_PATH, hash_path: Path = FEED_HASH_PATH) -> dict[str, Vulnerability]:
    """Verify the pinned hash, then return ``{cve_id: Vulnerability}``.

    Raises ``FeedIntegrityError`` if the hash file is missing or does not match.
    """
    try:
        expected = hash_path.read_text(encoding="utf-8").strip().split()[0]
    except (FileNotFoundError, IndexError) as exc:
        raise FeedIntegrityError(f"missing or empty feed hash: {hash_path}") from exc

    try:
        actual = sha256_file(path)
    except FileNotFoundError as exc:
        raise FeedIntegrityError(f"missing feed snapshot: {path}") from exc
    if not hmac.compare_digest(expected, actual):
        raise FeedIntegrityError(f"feed hash mismatch for {path}: expected {expected}, got {actual}")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        records = payload["records"]
    except (FileNotFoundError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise FeedIntegrityError(f"invalid feed snapshot: {path}") from exc

    try:
        return {
            record["cve_id"]: Vulnerability(
                cve_id=record["cve_id"],
                cvss=record["cvss"],
                epss=record["epss"],
                kev=record.get("kev", False),
            )
            for record in records
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise FeedIntegrityError(f"invalid vulnerability record in {path}") from exc


def feed_record(cve_id: str, path: Path = FEED_PATH) -> dict | None:
    """Raw record for one CVE (used by quarantine cross-checks), or None if absent."""
    hash_path = FEED_HASH_PATH if path == FEED_PATH else path.with_suffix(".sha256")

    if hash_path.exists():
        load_feed(path, hash_path)

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        if isinstance(exc, FileNotFoundError):
            return None
        raise FeedIntegrityError(f"invalid feed snapshot: {path}") from exc

    return next((record for record in payload.get("records", []) if record.get("cve_id") == cve_id), None)
