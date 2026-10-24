"""Build the pinned vulnerability snapshot used by the city generator.

This is an operator-run script, not an application dependency.  It downloads the
public CISA KEV and FIRST EPSS feeds once, queries NVD for CVSS details, and writes
the resulting JSON together with a SHA-256 pin.  The application only reads the
committed snapshot through ``urbanshield.city.feeds.load_feed``.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from urbanshield.config import DATA_DIR

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
DEFAULT_LIMIT = 40
NVD_DELAY_SECONDS = 6.0
KEYWORDS = re.compile(
    r"router|camera|controller|industrial|plc|scada|ics|energy|charger|gateway|iot|"
    r"webcam|firmware|switch|access point|vpn|network|telemetry|building",
    re.IGNORECASE,
)


def _download(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "UrbanShield-feed-builder/1.0"})
    with urlopen(request, timeout=120) as response:
        return response.read()


def _load_kev() -> list[dict[str, object]]:
    payload = json.loads(_download(CISA_KEV_URL))
    return list(payload.get("vulnerabilities", []))


def _load_epss() -> dict[str, float]:
    content = gzip.decompress(_download(EPSS_URL)).decode("utf-8", errors="replace")
    scores: dict[str, float] = {}
    for row in csv.DictReader(line for line in content.splitlines() if not line.startswith("#")):
        cve_id = row.get("cve", "")
        if cve_id:
            scores[cve_id] = float(row.get("epss", 0.0))
    return scores


def _nvd_record(cve_id: str) -> dict[str, object] | None:
    request = Request(NVD_URL.format(cve_id), headers={"User-Agent": "UrbanShield-feed-builder/1.0"})
    try:
        with urlopen(request, timeout=120) as response:
            payload = json.load(response)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return None

    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0].get("cve", {})
    metrics = cve.get("metrics", {})
    metric = None
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(name):
            metric = metrics[name][0].get("cvssData", {})
            break
    if not metric or "baseScore" not in metric:
        return None

    descriptions = cve.get("descriptions", [])
    summary = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
    return {"cvss": float(metric["baseScore"]), "summary": summary}


def _candidate_rows(kev_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    matching = [
        row
        for row in kev_rows
        if KEYWORDS.search(
            f"{row.get('vendorProject', '')} {row.get('product', '')} {row.get('shortDescription', '')}"
        )
    ]
    remaining = [row for row in kev_rows if row not in matching]
    return sorted(matching, key=lambda row: str(row.get("cveID", ""))) + sorted(
        remaining, key=lambda row: str(row.get("cveID", ""))
    )


def build_snapshot(limit: int = DEFAULT_LIMIT, delay_seconds: float = NVD_DELAY_SECONDS) -> tuple[Path, Path]:
    """Download and pin a feed snapshot, returning its JSON and hash paths."""
    if limit < 1:
        raise ValueError("limit must be positive")

    kev_rows = _candidate_rows(_load_kev())
    epss = _load_epss()
    records: list[dict[str, object]] = []
    for row in kev_rows:
        cve_id = str(row.get("cveID", ""))
        if not cve_id:
            continue
        nvd = _nvd_record(cve_id)
        if nvd is None:
            time.sleep(delay_seconds)
            continue
        cvss = float(nvd["cvss"])
        if not 4.0 <= cvss <= 10.0:
            continue
        records.append(
            {
                "cve_id": cve_id,
                "cvss": cvss,
                "epss": epss.get(cve_id, 0.0),
                "kev": True,
                "vendor": row.get("vendorProject", "unknown"),
                "product": row.get("product", "unknown"),
                "summary": nvd["summary"] or row.get("shortDescription", ""),
            }
        )
        if len(records) >= limit:
            break
        time.sleep(delay_seconds)

    if len(records) < limit:
        raise RuntimeError(f"only collected {len(records)} valid records; wanted {limit}")

    records.sort(key=lambda record: str(record["cve_id"]))
    payload = {
        "generated": datetime.now(UTC).date().isoformat(),
        "sources": ["cisa-kev", "first-epss", "nvd"],
        "records": records,
    }
    output_dir = DATA_DIR / "feeds"
    output_dir.mkdir(parents=True, exist_ok=True)
    feed_path = output_dir / "feed_snapshot.json"
    hash_path = output_dir / "feed_snapshot.sha256"
    feed_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    digest = hashlib.sha256(feed_path.read_bytes()).hexdigest()
    hash_path.write_text(f"{digest}  {feed_path.name}\n", encoding="utf-8")
    return feed_path, hash_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--delay", type=float, default=NVD_DELAY_SECONDS)
    args = parser.parse_args()
    feed_path, hash_path = build_snapshot(args.limit, args.delay)
    print(f"wrote {feed_path}")
    print(f"wrote {hash_path}")


if __name__ == "__main__":
    main()
