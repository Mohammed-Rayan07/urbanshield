"""Deterministic city generator placed on real Mangaluru / Surathkal streets. Owner: A.

``generate_city(seed)`` must return the same city for the same seed, every time.

Demo structure that MUST exist (tests check it):

1. **Shared-firmware family**: at least 10 streetlights on the same firmware family
   (e.g. ``lumenos/4.1.x``) carrying the same *medium* CVSS (5.0-6.9) CVE, at least
   one of them exposed.
2. **Ambulance corridor**: at least 4 signals tagged ``ambulance_corridor`` along NH-66
   towards the district hospital, with criticality >= 0.9, reachable from the
   streetlight family through REACH edges (via a shared gateway or EV charger).
3. **Decoys**: at least 3 devices with CVSS >= 9.0 and criticality <= 0.2 and no
   outgoing DEPENDS edges (isolated, decorative). A CVSS-first plan wastes money here.
4. Every device has 2-5 ``ControlOption`` values; ``rotate_creds`` is ``Autonomy.AUTO``,
   anything with downtime > 0 is ``Autonomy.APPROVE``.

Device IDs are ``d-001`` .. ``d-NNN``. Coordinates stay inside the Mangaluru box
(lat 12.80-13.05, lon 74.78-74.92). Vendor names are fictional.
"""

from __future__ import annotations

from collections.abc import Callable
from itertools import pairwise

import numpy as np

from urbanshield.schemas import (
    Autonomy,
    Category,
    City,
    ControlKind,
    ControlOption,
    Device,
    Edge,
    EdgeKind,
    Vulnerability,
)

MANGALURU_BBOX = (12.80, 74.78, 13.05, 74.92)  # (lat_min, lon_min, lat_max, lon_max)
DEFAULT_SEED = 7
ZONE_CENTRES = {
    "Surathkal": (13.0108, 74.7943),
    "Panambur": (12.9419, 74.8090),
    "Kottara": (12.9050, 74.8380),
    "Hampankatta": (12.8698, 74.8430),
}
ZONE_ABBREVIATIONS = {
    "Surathkal": "SUR",
    "Panambur": "PAN",
    "Kottara": "KOT",
    "Hampankatta": "HAM",
}

_SYNTHETIC_FEED = {
    "CVE-2025-31337": Vulnerability(cve_id="CVE-2025-31337", cvss=6.1, epss=0.42, kev=True),
    "CVE-2023-29910": Vulnerability(cve_id="CVE-2023-29910", cvss=4.3, epss=0.05),
    "CVE-2024-48201": Vulnerability(cve_id="CVE-2024-48201", cvss=5.4, epss=0.18),
    "CVE-2024-48202": Vulnerability(cve_id="CVE-2024-48202", cvss=7.4, epss=0.13),
    "CVE-2025-10000": Vulnerability(cve_id="CVE-2025-10000", cvss=9.8, epss=0.02),
}


def generate_city(
    seed: int = DEFAULT_SEED,
    n_devices: int = 50,
    feed: dict[str, Vulnerability] | None = None,
) -> City:
    """Build the city twin. When ``feed`` is given, seed vulnerabilities from real records."""
    if n_devices < 1:
        raise ValueError("n_devices must be positive")

    rng = np.random.default_rng(seed)
    vulnerability_feed = _resolve_feed(feed)
    categories = _category_counts(n_devices)
    zone_names = tuple(ZONE_CENTRES)

    streetlight_count = categories[Category.STREETLIGHT]
    family_count = min(
        streetlight_count,
        max(10 if streetlight_count >= 10 else 1, round(streetlight_count * 0.6)),
    )
    remaining_lights = streetlight_count - family_count
    decoy_count = min(
        remaining_lights,
        max(3 if remaining_lights >= 3 else 0, round(streetlight_count * 0.15)),
    )

    shared = _pick_vulnerability(vulnerability_feed, lambda vuln: 5.0 <= vuln.cvss < 7.0, "CVE-2025-31337")
    signal_vulnerability = _pick_vulnerability(
        vulnerability_feed, lambda vuln: 4.0 <= vuln.cvss < 8.0, "CVE-2023-29910"
    )
    meter_vulnerability = _pick_vulnerability(
        vulnerability_feed, lambda vuln: 6.0 <= vuln.cvss < 9.0, "CVE-2024-48202"
    )
    ev_vulnerability = _pick_vulnerability(
        vulnerability_feed, lambda vuln: 4.0 <= vuln.cvss < 7.0, "CVE-2024-48201"
    )
    decoy_vulnerability = _pick_vulnerability(
        vulnerability_feed, lambda vuln: vuln.cvss >= 9.0, "CVE-2025-10000"
    )

    devices: list[Device] = []
    corridor_ids: list[str] = []
    family_ids: list[str] = []
    decoy_ids: set[str] = set()
    for category, count in categories.items():
        for category_position in range(count):
            device_number = len(devices) + 1
            device_id = f"d-{device_number:03d}"
            zone = zone_names[category_position % len(zone_names)]
            tags: list[str] = []
            vulnerability = ev_vulnerability
            firmware = _firmware_for(category, category_position)
            exposed = bool(rng.random() < 0.12)
            criticality = _criticality(rng, category)

            if category == Category.STREETLIGHT:
                if category_position < family_count:
                    firmware = f"lumenos/4.1.{3 + category_position % 3}"
                    vulnerability = shared
                    family_ids.append(device_id)
                    exposed = category_position == 0 or exposed
                    criticality = 0.30
                elif category_position < family_count + decoy_count:
                    firmware = "decorlite/1.0.0"
                    vulnerability = decoy_vulnerability
                    exposed = True
                    criticality = 0.10
                    tags.append("decorative")
                    decoy_ids.add(device_id)
            elif category == Category.SIGNAL:
                vulnerability = signal_vulnerability
                if category_position < min(4, count):
                    zone = zone_names[category_position]
                    corridor_ids.append(device_id)
                    tags.append("ambulance_corridor")
                    firmware = "trafikon/7.2.0"
                    criticality = 0.95
                    exposed = False
            elif category == Category.METER:
                vulnerability = meter_vulnerability
                firmware = f"metrix/3.{1 + category_position % 3}.0"
                if category_position == 0:
                    criticality = 0.85
            elif category == Category.EV_CHARGER:
                vulnerability = ev_vulnerability
                firmware = f"voltgrid/2.{1 + category_position % 2}.0"

            lat, lon = _coordinates(rng, zone, device_id in corridor_ids)
            devices.append(
                Device(
                    id=device_id,
                    name=f"{_display_name(category)} {ZONE_ABBREVIATIONS[zone]}-{device_number:03d}",
                    category=category,
                    zone=zone,
                    lat=lat,
                    lon=lon,
                    firmware=firmware,
                    vulns=[vulnerability],
                    exposed=exposed,
                    criticality=float(np.clip(criticality, 0.0, 1.0)),
                    controls=_controls(rng),
                    tags=tags,
                )
            )

    edges = _build_edges(
        devices,
        family_ids=family_ids,
        corridor_ids=corridor_ids,
        decoy_ids=decoy_ids,
        rng=rng,
    )
    return City(
        id="mangaluru-demo",
        name="Mangaluru city twin",
        seed=seed,
        devices=devices,
        edges=edges,
    )


def _resolve_feed(feed: dict[str, Vulnerability] | None) -> dict[str, Vulnerability]:
    if feed is not None:
        return feed

    from urbanshield.city.feeds import FEED_HASH_PATH, FEED_PATH, load_feed

    if FEED_PATH.exists() or FEED_HASH_PATH.exists():
        return load_feed()
    return {}


def _category_counts(n_devices: int) -> dict[Category, int]:
    proportions = (0.40, 0.25, 0.20, 0.15)
    if n_devices < len(proportions):
        counts = np.zeros(len(proportions), dtype=int)
        counts[:n_devices] = 1
    else:
        counts = np.ones(len(proportions), dtype=int)
        remaining = n_devices - len(proportions)
        raw = np.asarray(proportions) * remaining
        counts += np.floor(raw).astype(int)
        for index in np.argsort(-(raw - np.floor(raw)))[: remaining - int(np.floor(raw).sum())]:
            counts[index] += 1
    if n_devices >= 16 and counts[1] < 4:
        shift = min(4 - counts[1], max(0, counts[0] - 1))
        counts[1] += shift
        counts[0] -= shift
    return {
        Category.STREETLIGHT: int(counts[0]),
        Category.SIGNAL: int(counts[1]),
        Category.METER: int(counts[2]),
        Category.EV_CHARGER: int(counts[3]),
    }


def _pick_vulnerability(
    feed: dict[str, Vulnerability], predicate: Callable[[Vulnerability], bool], fallback: str
) -> Vulnerability:
    if feed:
        matching = sorted((vuln for vuln in feed.values() if predicate(vuln)), key=lambda vuln: vuln.cve_id)
        if matching:
            return matching[0]
        return sorted(feed.values(), key=lambda vuln: vuln.cve_id)[0]
    return _SYNTHETIC_FEED[fallback]


def _firmware_for(category: Category, position: int) -> str:
    if category == Category.STREETLIGHT:
        return f"lumenos/4.2.{position % 3}"
    if category == Category.SIGNAL:
        return f"trafikon/7.1.{position % 3}"
    if category == Category.METER:
        return f"metrix/3.{1 + position % 3}.0"
    return f"voltgrid/2.{1 + position % 2}.0"


def _display_name(category: Category) -> str:
    return {
        Category.STREETLIGHT: "Streetlight",
        Category.SIGNAL: "Signal",
        Category.METER: "Meter",
        Category.EV_CHARGER: "EV charger",
    }[category]


def _coordinates(rng: np.random.Generator, zone: str, corridor: bool) -> tuple[float, float]:
    centre_lat, centre_lon = ZONE_CENTRES[zone]
    if corridor:
        jitter_lat = float(rng.uniform(-0.002, 0.002))
        jitter_lon = float(rng.uniform(-0.002, 0.002))
    else:
        jitter_lat = float(rng.uniform(-0.01, 0.01))
        jitter_lon = float(rng.uniform(-0.01, 0.01))
    lat = float(np.clip(centre_lat + jitter_lat, MANGALURU_BBOX[0], MANGALURU_BBOX[2]))
    lon = float(np.clip(centre_lon + jitter_lon, MANGALURU_BBOX[1], MANGALURU_BBOX[3]))
    return lat, lon


def _criticality(rng: np.random.Generator, category: Category) -> float:
    if category == Category.SIGNAL:
        return float(rng.uniform(0.45, 0.85))
    if category == Category.METER:
        return float(rng.uniform(0.30, 0.75))
    if category == Category.EV_CHARGER:
        return float(rng.uniform(0.25, 0.65))
    return float(rng.uniform(0.20, 0.45))


def _controls(rng: np.random.Generator) -> list[ControlOption]:
    options = [
        ControlOption(
            kind=ControlKind.PATCH,
            cost_inr=int(rng.integers(30_000, 60_001)),
            downtime_h=4.0,
            exploit_mult=0.10,
            spread_mult=1.0,
            autonomy=Autonomy.APPROVE,
        ),
        ControlOption(
            kind=ControlKind.SEGMENT,
            cost_inr=int(rng.integers(18_000, 32_001)),
            downtime_h=2.0,
            exploit_mult=0.70,
            spread_mult=0.30,
            autonomy=Autonomy.APPROVE,
        ),
        ControlOption(
            kind=ControlKind.ROTATE_CREDS,
            cost_inr=int(rng.integers(2_000, 4_001)),
            downtime_h=0.0,
            exploit_mult=0.60,
            spread_mult=1.0,
            autonomy=Autonomy.AUTO,
        ),
        ControlOption(
            kind=ControlKind.DISABLE_REMOTE,
            cost_inr=int(rng.integers(4_000, 8_001)),
            downtime_h=0.0,
            exploit_mult=0.40,
            spread_mult=1.0,
            autonomy=Autonomy.APPROVE,
        ),
        ControlOption(
            kind=ControlKind.VIRTUAL_PATCH,
            cost_inr=int(rng.integers(10_000, 18_001)),
            downtime_h=0.5,
            exploit_mult=0.30,
            spread_mult=1.0,
            autonomy=Autonomy.APPROVE,
        ),
    ]
    selected = [options[0]]
    extra_count = int(rng.integers(1, 5))
    selected.extend(
        options[int(index) + 1] for index in rng.choice(len(options) - 1, extra_count, replace=False)
    )
    return selected


def _build_edges(
    devices: list[Device],
    *,
    family_ids: list[str],
    corridor_ids: list[str],
    decoy_ids: set[str],
    rng: np.random.Generator,
) -> list[Edge]:
    edge_keys: set[tuple[str, str, EdgeKind]] = set()

    def add(src: str, dst: str, kind: EdgeKind) -> None:
        if src != dst:
            edge_keys.add((src, dst, kind))

    by_zone: dict[str, list[str]] = {}
    for device in devices:
        by_zone.setdefault(device.zone, []).append(device.id)
    for zone_ids in by_zone.values():
        for src, dst in pairwise(zone_ids):
            add(src, dst, EdgeKind.REACH)
        for src, dst in zip(zone_ids, zone_ids[2:], strict=False):
            add(src, dst, EdgeKind.REACH)

    for src, dst in pairwise(family_ids):
        add(src, dst, EdgeKind.REACH)
    for src, dst in pairwise(corridor_ids):
        add(src, dst, EdgeKind.REACH)
        add(src, dst, EdgeKind.DEPENDS)

    ev_ids = [device.id for device in devices if device.category == Category.EV_CHARGER]
    if family_ids and corridor_ids and ev_ids:
        gateways = ev_ids[: min(2, len(ev_ids))]
        for position, gateway in enumerate(gateways):
            add(family_ids[-1 if position == 0 else 0], gateway, EdgeKind.REACH)
            add(gateway, corridor_ids[min(position, len(corridor_ids) - 1)], EdgeKind.REACH)

    meter_ids = [device.id for device in devices if device.category == Category.METER]
    if len(meter_ids) >= 2:
        substation = meter_ids[0]
        for meter_id in meter_ids[1:]:
            add(meter_id, substation, EdgeKind.DEPENDS)

    non_decoys = [device.id for device in devices if device.id not in decoy_ids]
    for src in non_decoys:
        if rng.random() >= 0.04 or len(non_decoys) < 2:
            continue
        dst = non_decoys[int(rng.integers(0, len(non_decoys)))]
        add(src, dst, EdgeKind.DEPENDS)

    return [
        Edge(src=src, dst=dst, kind=kind)
        for src, dst, kind in sorted(edge_keys, key=lambda edge: (edge[0], edge[1], edge[2].value))
    ]
