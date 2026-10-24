"""Build the pinned vulnerability snapshot used by the city generator.

Operator-run, once, by hand; never imported by the application. It downloads the public
CISA KEV catalogue and FIRST EPSS scores, keeps only entries for **embedded IoT / OT
vendors** (routers, cameras, PLCs, SCADA, cellular gateways: the kind of firmware that
runs street furniture), looks up CVSS on NVD, and writes a balanced selection plus its
SHA-256. The application only reads the committed snapshot through
``urbanshield.city.feeds.load_feed``, which also checks the digest pinned in code.

    uv run python scripts/build_feed_snapshot.py     # then paste the printed digest into
                                                     # city/feeds.py:FEED_SHA256
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
import time
import zlib
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from urbanshield.config import DATA_DIR

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
USER_AGENT = "UrbanShield-feed-builder/2.0"
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
DEFAULT_LIMIT = 40
NVD_DELAY_SECONDS = 6.0  # NVD's public rate limit without an API key

# Vendors whose KEV entries are embedded network / OT firmware comparable to city devices.
IOT_OT_VENDORS = frozenset(
    {
        "D-Link", "NETGEAR", "Zyxel", "TP-Link", "Hikvision", "Dahua", "Ubiquiti", "MikroTik",
        "DrayTek", "Tenda", "Siemens", "Schneider Electric", "Realtek", "Sierra Wireless",
        "Unitronics", "Edimax", "GeoVision", "Sunhillo", "Trihedral", "Linksys", "TOTOLINK",
    }
)  # fmt: skip

Record = dict[str, Any]


def _download(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=120) as response:
        data = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise RuntimeError(f"{url} is larger than {MAX_DOWNLOAD_BYTES} bytes")
    return data


def _gunzip(data: bytes) -> bytes:
    inflater = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    out = inflater.decompress(data, MAX_DOWNLOAD_BYTES)
    if inflater.unconsumed_tail:
        raise RuntimeError("decompressed EPSS file exceeds the size cap")
    return out


def _load_kev() -> list[Record]:
    rows = json.loads(_download(CISA_KEV_URL)).get("vulnerabilities", [])
    return [
        row
        for row in rows
        if row.get("vendorProject") in IOT_OT_VENDORS and CVE_ID.match(str(row.get("cveID", "")))
    ]


def _load_epss() -> dict[str, float]:
    text = _gunzip(_download(EPSS_URL)).decode("utf-8", errors="replace")
    lines = (line for line in io.StringIO(text) if not line.startswith("#"))
    return {row["cve"]: float(row["epss"]) for row in csv.DictReader(lines) if row.get("cve")}


def _nvd(cve_id: str, cache_dir: Path) -> Record | None:
    """CVSS base score + English summary from NVD, cached on disk. Network failures are
    reported, never silently dropped; the rate-limit delay applies to every network call."""
    cached = cache_dir / f"{cve_id}.json"
    if cached.exists():
        payload = json.loads(cached.read_text(encoding="utf-8"))
    else:
        try:
            payload = json.loads(_download(NVD_URL.format(cve_id)))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(f"  skip {cve_id}: NVD lookup failed ({exc})", file=sys.stderr)
            return None
        finally:
            time.sleep(NVD_DELAY_SECONDS)
        cached.write_text(json.dumps(payload), encoding="utf-8", newline="\n")
    items = payload.get("vulnerabilities", [])
    if not items:
        return None
    cve = items[0].get("cve", {})
    metrics = cve.get("metrics", {})
    for name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        data = metrics[name][0].get("cvssData", {}) if metrics.get(name) else {}
        if "baseScore" in data:
            descriptions = cve.get("descriptions", [])
            summary = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
            return {"cvss": float(data["baseScore"]), "summary": summary}
    return None


def _band(cvss: float) -> str:
    return "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium"


def select_balanced(records: list[Record], limit: int) -> list[Record]:
    """Deterministic pick: round-robin over vendors within each CVSS band, newest first, so no
    vendor dominates and every band the demo needs (medium shared-firmware CVEs, critical
    decoys) is represented."""
    quota = {"medium": limit * 3 // 10, "high": limit * 4 // 10}
    quota["critical"] = limit - sum(quota.values())
    newest_first = sorted(records, key=lambda r: r["cve_id"], reverse=True)
    chosen: list[Record] = []
    for band, wanted in quota.items():
        by_vendor: dict[str, list[Record]] = defaultdict(list)
        for record in newest_first:
            if _band(record["cvss"]) == band:
                by_vendor[record["vendor"]].append(record)
        queues = [by_vendor[v] for v in sorted(by_vendor)]
        picked: list[Record] = []
        while len(picked) < wanted and any(queues):
            for queue in queues:
                if queue and len(picked) < wanted:
                    picked.append(queue.pop(0))
        chosen += picked
    taken = {r["cve_id"] for r in chosen}
    chosen += [r for r in newest_first if r["cve_id"] not in taken][: limit - len(chosen)]
    return sorted(chosen, key=lambda r: r["cve_id"])


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)  # bytes, so the digest is identical on every OS
    os.replace(tmp, path)


def build_snapshot(limit: int, cache_dir: Path) -> tuple[Path, str]:
    """Download, select and write the snapshot; return its path and SHA-256."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    epss = _load_epss()
    records: list[Record] = []
    for row in _load_kev():
        nvd = _nvd(row["cveID"], cache_dir)
        if nvd is None or not 4.0 <= nvd["cvss"] <= 10.0:
            continue
        records.append(
            {
                "cve_id": row["cveID"],
                "cvss": nvd["cvss"],
                "epss": round(epss.get(row["cveID"], 0.0), 5),
                "kev": True,
                "vendor": row["vendorProject"],
                "product": row["product"],
                "summary": nvd["summary"] or row.get("shortDescription", ""),
            }
        )
    if len(records) < limit:
        raise RuntimeError(f"only {len(records)} usable IoT/OT records; wanted {limit}")

    payload = {
        "generated": datetime.now(UTC).date().isoformat(),
        "sources": ["cisa-kev", "first-epss", "nvd"],
        "selection": "CISA KEV entries for embedded IoT/OT vendors, balanced by CVSS band and vendor",
        "records": select_balanced(records, limit),
    }
    feed_path = DATA_DIR / "feeds" / "feed_snapshot.json"
    feed_path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    _write_atomic(feed_path, data)
    _write_atomic(feed_path.with_suffix(".sha256"), f"{digest}  {feed_path.name}\n".encode())
    return feed_path, digest


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--cache", type=Path, default=Path(".nvd_cache"), help="NVD response cache dir")
    args = parser.parse_args()
    feed_path, digest = build_snapshot(args.limit, args.cache)
    print(f"wrote {feed_path}")
    print(f'FEED_SHA256 = "{digest}"  # paste into city/feeds.py')


if __name__ == "__main__":
    main()
