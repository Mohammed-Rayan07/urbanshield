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

from pathlib import Path

from urbanshield.config import DATA_DIR
from urbanshield.schemas import Vulnerability

FEED_PATH = DATA_DIR / "feeds" / "feed_snapshot.json"
FEED_HASH_PATH = DATA_DIR / "feeds" / "feed_snapshot.sha256"


class FeedIntegrityError(RuntimeError):
    """The feed file does not match its pinned SHA-256."""


def sha256_file(path: Path) -> str:
    """Hex SHA-256 of a file's bytes."""
    raise NotImplementedError


def load_feed(path: Path = FEED_PATH, hash_path: Path = FEED_HASH_PATH) -> dict[str, Vulnerability]:
    """Verify the pinned hash, then return ``{cve_id: Vulnerability}``.

    Raises ``FeedIntegrityError`` if the hash file is missing or does not match.
    """
    raise NotImplementedError


def feed_record(cve_id: str, path: Path = FEED_PATH) -> dict | None:
    """Raw record for one CVE (used by quarantine cross-checks), or None if absent."""
    raise NotImplementedError
