"""Deterministic city generator placed on real Mangaluru / Surathkal streets. Owner: A.

``generate_city(seed)`` returns the same city for the same seed, every time.

Demo structure that MUST exist (tests check it):

1. **Shared-firmware family**: at least 10 streetlights on the same firmware family
   (``lumenos/4.1.x``) carrying the same *medium* CVSS (5.0-6.9) CVE, at least one of
   them exposed.
2. **Ambulance corridor**: at least 4 signals tagged ``ambulance_corridor`` along NH-66
   towards the district hospital, with criticality >= 0.9, reachable from the
   streetlight family through REACH edges (via a shared gateway or EV charger).
3. **Decoys**: at least 3 devices with CVSS >= 9.0 and criticality <= 0.2 and no
   outgoing DEPENDS edges (isolated, decorative). A CVSS-first plan wastes money here.
4. Every device has 2-5 ``ControlOption`` values; ``rotate_creds`` is ``Autonomy.AUTO``,
   anything with downtime > 0 is ``Autonomy.APPROVE``.

How the topology encodes the story
----------------------------------
- Each category in each zone is its own field network: devices on it reach their
  neighbours (REACH both ways along a chain, plus a forward skip link).
- The ``lumenos/4.1.x`` family additionally shares one management network across zones.
- Networks only meet at **EV-charger gateways** (cellular backhaul in the charging depot,
  tagged ``gateway``): lights → gateway → meters in every zone, and the first two gateways
  bridge the light family into the corridor signals. Segmenting them is a real defence.
- Decoys have no edges at all; their critical CVSS is real but nothing depends on them.
- DEPENDS: corridor signals depend on each other in sequence and coordinate the other
  signals of their zone; the substation meter feeds every other meter and EV charger.

CVEs come from the pinned real feed by role: the family shares the medium-severity CVE most
likely to be exploited (highest EPSS); decoys carry the critical CVE least likely to be
exploited (lowest EPSS); corridor signals carry the medium CVE of median exploitability; every
other device draws one or two CVEs from the rest of the feed. A feed missing a needed
severity band raises; nothing is silently substituted.

Device IDs are ``d-001`` .. ``d-NNN``. Coordinates stay inside the Mangaluru box
(lat 12.80-13.05, lon 74.78-74.92). Vendor names are fictional.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
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
CITY_ID = "mangaluru-demo"
CORRIDOR_TAG = "ambulance_corridor"
DECOY_TAG = "decorative"
GATEWAY_TAG = "gateway"
N_CORRIDOR = 4
EXPOSURE_RATE = 0.12
FAMILY_SHARE, MIN_FAMILY = 0.6, 10  # of streetlights
DECOY_SHARE, MIN_DECOYS = 0.15, 3  # of streetlights
MIN_DEVICES = 40  # smallest city that holds the whole demo structure

# Zone centres, north to south; NH-66 runs through them towards the district hospital.
ZONE_CENTRES = {
    "Surathkal": (13.0108, 74.7943),
    "Panambur": (12.9419, 74.8090),
    "Kottara": (12.9050, 74.8380),
    "Hampankatta": (12.8698, 74.8430),
}
ZONE_ABBREVIATIONS = {"Surathkal": "SUR", "Panambur": "PAN", "Kottara": "KOT", "Hampankatta": "HAM"}
CATEGORY_SHARE = {
    Category.STREETLIGHT: 0.40,
    Category.SIGNAL: 0.25,
    Category.METER: 0.20,
    Category.EV_CHARGER: 0.15,
}
DISPLAY_NAME = {
    Category.STREETLIGHT: "Streetlight",
    Category.SIGNAL: "Signal",
    Category.METER: "Meter",
    Category.EV_CHARGER: "EV charger",
}
# kind: (cost range ₹, downtime h, exploit_mult, spread_mult, autonomy)
CONTROL_CATALOGUE = {
    ControlKind.PATCH: ((30_000, 60_000), 4.0, 0.10, 1.00, Autonomy.APPROVE),
    ControlKind.SEGMENT: ((18_000, 32_000), 2.0, 0.70, 0.30, Autonomy.APPROVE),
    ControlKind.ROTATE_CREDS: ((2_000, 4_000), 0.0, 0.60, 1.00, Autonomy.AUTO),
    ControlKind.DISABLE_REMOTE: ((4_000, 8_000), 0.0, 0.40, 1.00, Autonomy.APPROVE),
    ControlKind.VIRTUAL_PATCH: ((10_000, 18_000), 0.5, 0.30, 1.00, Autonomy.APPROVE),
}


@dataclass(frozen=True)
class _Roles:
    family: Vulnerability
    decoy: Vulnerability
    corridor: Vulnerability
    pool: tuple[Vulnerability, ...]


@dataclass
class _Layout:
    devices: list[Device] = field(default_factory=list)
    family: list[str] = field(default_factory=list)
    corridor: list[str] = field(default_factory=list)
    gateways: list[tuple[str, str]] = field(default_factory=list)  # (device id, zone)
    networks: dict[tuple[str, Category], list[str]] = field(default_factory=dict)  # decoys excluded


def generate_city(
    seed: int = DEFAULT_SEED,
    n_devices: int = 50,
    feed: dict[str, Vulnerability] | None = None,
) -> City:
    """Build the city twin from the pinned feed (or ``feed``, if given)."""
    if n_devices < MIN_DEVICES:
        raise ValueError(f"the demo structure needs at least {MIN_DEVICES} devices, got {n_devices}")
    rng = np.random.default_rng(seed)
    layout = _place_devices(rng, n_devices, _roles(_resolve_feed(feed)))
    return City(
        id=CITY_ID, name="Mangaluru city twin", seed=seed, devices=layout.devices, edges=_edges(layout)
    )


# --------------------------------------------------------------------------- vulnerabilities


def _resolve_feed(feed: dict[str, Vulnerability] | None) -> dict[str, Vulnerability]:
    if feed is not None:
        return feed
    from urbanshield.city.feeds import load_feed  # verified; fails closed if missing or altered

    return load_feed()


def _roles(feed: dict[str, Vulnerability]) -> _Roles:
    vulns = sorted(feed.values(), key=lambda v: v.cve_id)

    def pick(
        role: str, wanted: Callable[[Vulnerability], bool], rank: Callable[[Vulnerability], float]
    ) -> Vulnerability:
        matching = [v for v in vulns if wanted(v)]
        if not matching:
            raise ValueError(f"feed has no CVE suitable for the {role}")
        return min(matching, key=lambda v: (rank(v), v.cve_id))

    family = pick("shared-firmware family (CVSS 5.0-6.9)", lambda v: 5.0 <= v.cvss < 7.0, lambda v: -v.epss)
    decoy = pick("decoys (CVSS >= 9.0)", lambda v: v.cvss >= 9.0, lambda v: v.epss)
    medium = sorted(v.epss for v in vulns if 4.0 <= v.cvss < 7.0 and v != family)
    typical = medium[len(medium) // 2] if medium else 0.0
    corridor = pick(  # median likelihood: the corridor is at real risk, but less than the family
        "corridor signals (CVSS 4.0-6.9)",
        lambda v: 4.0 <= v.cvss < 7.0 and v != family,
        lambda v: abs(v.epss - typical),
    )
    pool = tuple(v for v in vulns if v not in (family, decoy, corridor))
    if not pool:
        raise ValueError("feed has no CVEs left for ordinary devices")
    return _Roles(family=family, decoy=decoy, corridor=corridor, pool=pool)


# --------------------------------------------------------------------------- devices


def _category_counts(n_devices: int) -> dict[Category, int]:
    """Largest-remainder split by ``CATEGORY_SHARE``: one per category when possible, and at
    least ``N_CORRIDOR`` signals once the city is big enough to hold the demo structure."""
    categories = list(CATEGORY_SHARE)
    counts = np.full(len(categories), min(1, n_devices // len(categories)))
    raw = np.array(list(CATEGORY_SHARE.values())) * (n_devices - counts.sum())
    counts += np.floor(raw).astype(int)
    for i in np.argsort(-(raw - np.floor(raw)), kind="stable")[: n_devices - counts.sum()]:
        counts[i] += 1
    signal, light = categories.index(Category.SIGNAL), categories.index(Category.STREETLIGHT)
    if n_devices >= 16 and counts[signal] < N_CORRIDOR:
        shift = N_CORRIDOR - counts[signal]
        counts[signal] += shift
        counts[light] -= shift
    return dict(zip(categories, (int(c) for c in counts), strict=True))


def _place_devices(rng: np.random.Generator, n_devices: int, roles: _Roles) -> _Layout:
    counts = _category_counts(n_devices)
    lights = counts[Category.STREETLIGHT]
    n_family = max(MIN_FAMILY, int(lights * FAMILY_SHARE + 0.5))
    n_decoy = max(MIN_DECOYS, int(lights * DECOY_SHARE + 0.5))
    zones = tuple(ZONE_CENTRES)
    layout = _Layout()

    for category, count in counts.items():
        for k in range(count):
            number = len(layout.devices) + 1
            device_id = f"d-{number:03d}"
            zone = zones[k % len(zones)]
            tags: list[str] = []
            exposed = bool(rng.random() < EXPOSURE_RATE)
            criticality = _criticality(rng, category)
            vulns = _pool_vulns(rng, roles.pool)
            lat, lon = _jitter(rng, ZONE_CENTRES[zone], 0.01)
            firmware = _firmware(category, k)
            on_network = True

            if category is Category.STREETLIGHT and k < n_family:
                firmware, vulns, criticality = f"lumenos/4.1.{3 + k % 3}", [roles.family], 0.30
                exposed = exposed or k == 0
                layout.family.append(device_id)
            elif category is Category.STREETLIGHT and k < n_family + n_decoy:
                firmware, vulns, criticality, exposed = "decorlite/1.0.0", [roles.decoy], 0.10, True
                tags.append(DECOY_TAG)
                on_network = False
            elif category is Category.SIGNAL and k < N_CORRIDOR:
                firmware, vulns, criticality, exposed = "trafikon/7.2.0", [roles.corridor], 0.95, False
                lat, lon = _jitter(rng, _nh66_point((k + 0.5) / N_CORRIDOR), 0.0008)
                tags.append(CORRIDOR_TAG)
                layout.corridor.append(device_id)
            elif category is Category.METER and k == 0:
                criticality = 0.85  # substation head-end meter
            elif category is Category.EV_CHARGER and k < len(zones):
                tags.append(GATEWAY_TAG)  # first charger of each zone hosts the depot backhaul
                layout.gateways.append((device_id, zone))

            if on_network:
                layout.networks.setdefault((zone, category), []).append(device_id)
            layout.devices.append(
                Device(
                    id=device_id,
                    name=f"{DISPLAY_NAME[category]} {ZONE_ABBREVIATIONS[zone]}-{number:03d}",
                    category=category,
                    zone=zone,
                    lat=lat,
                    lon=lon,
                    firmware=firmware,
                    vulns=vulns,
                    exposed=exposed,
                    criticality=float(np.clip(criticality, 0.0, 1.0)),
                    controls=_controls(rng),
                    tags=tags,
                )
            )
    return layout


def _pool_vulns(rng: np.random.Generator, pool: tuple[Vulnerability, ...]) -> list[Vulnerability]:
    """One CVE, or two (25%), from the ordinary pool; sorted for stable output."""
    size = min(len(pool), 2 if rng.random() < 0.25 else 1)
    picked = rng.choice(len(pool), size=size, replace=False)
    return sorted((pool[int(i)] for i in picked), key=lambda v: v.cve_id)


def _firmware(category: Category, k: int) -> str:
    return {
        Category.STREETLIGHT: f"lumenos/4.2.{k % 3}",
        Category.SIGNAL: f"trafikon/7.1.{k % 3}",
        Category.METER: f"metrix/3.{1 + k % 3}.0",
        Category.EV_CHARGER: f"voltgrid/2.{1 + k % 2}.0",
    }[category]


def _criticality(rng: np.random.Generator, category: Category) -> float:
    low, high = {
        Category.SIGNAL: (0.45, 0.85),
        Category.METER: (0.30, 0.75),
        Category.EV_CHARGER: (0.25, 0.65),
        Category.STREETLIGHT: (0.20, 0.45),
    }[category]
    return float(rng.uniform(low, high))


def _nh66_point(t: float) -> tuple[float, float]:
    """Point at fraction ``t`` (0..1) along NH-66, approximated by the zone-centre polyline."""
    points = np.array(list(ZONE_CENTRES.values()))
    lengths = np.linalg.norm(np.diff(points, axis=0), axis=1)
    target = t * lengths.sum()
    for (a, b), length in zip(pairwise(points), lengths, strict=True):
        if target <= length:
            lat, lon = a + (b - a) * (target / length)
            return float(lat), float(lon)
        target -= length
    return float(points[-1][0]), float(points[-1][1])


def _jitter(rng: np.random.Generator, centre: tuple[float, float], spread: float) -> tuple[float, float]:
    lat = float(np.clip(centre[0] + rng.uniform(-spread, spread), MANGALURU_BBOX[0], MANGALURU_BBOX[2]))
    lon = float(np.clip(centre[1] + rng.uniform(-spread, spread), MANGALURU_BBOX[1], MANGALURU_BBOX[3]))
    return round(lat, 6), round(lon, 6)


def _controls(rng: np.random.Generator) -> list[ControlOption]:
    """Patch plus 1-4 other options, in catalogue order."""
    others = [k for k in CONTROL_CATALOGUE if k is not ControlKind.PATCH]
    extra = set(rng.choice(len(others), size=int(rng.integers(1, 5)), replace=False).tolist())
    options = []
    for kind in [ControlKind.PATCH, *(k for i, k in enumerate(others) if i in extra)]:
        (low, high), downtime, exploit_mult, spread_mult, autonomy = CONTROL_CATALOGUE[kind]
        options.append(
            ControlOption(
                kind=kind,
                cost_inr=int(rng.integers(low, high + 1)),
                downtime_h=downtime,
                exploit_mult=exploit_mult,
                spread_mult=spread_mult,
                autonomy=autonomy,
            )
        )
    return options


# --------------------------------------------------------------------------- edges


def _edges(layout: _Layout) -> list[Edge]:
    keys: set[tuple[str, str, EdgeKind]] = set()

    def link(src: str, dst: str, kind: EdgeKind = EdgeKind.REACH, both: bool = False) -> None:
        if src != dst:
            keys.add((src, dst, kind))
            if both:
                keys.add((dst, src, kind))

    for members in layout.networks.values():  # each category's field network, per zone
        for a, b in pairwise(members):
            link(a, b, both=True)
        for a, b in zip(members, members[2:], strict=False):
            link(a, b)
    for a, b in pairwise(layout.family):  # the family's shared management network
        link(a, b, both=True)

    zones = tuple(ZONE_CENTRES)
    for gateway, zone in layout.gateways:  # gateways are the only bridges between networks
        if lights := layout.networks.get((zone, Category.STREETLIGHT)):
            link(lights[0], gateway)
        if meters := layout.networks.get((zone, Category.METER)):
            link(gateway, meters[0])
    if layout.family and layout.corridor:
        # Two bridges, entered from opposite ends of the family's management network.
        for k, (gateway, _) in enumerate(layout.gateways[:2]):
            link(layout.family[-1 if k == 0 else 0], gateway)
            link(gateway, layout.corridor[min(k, len(layout.corridor) - 1)])

    for a, b in pairwise(layout.corridor):  # the green wave: each junction depends on the last
        link(a, b)
        link(a, b, EdgeKind.DEPENDS)
    for k, junction in enumerate(layout.corridor):
        for signal in layout.networks.get((zones[k % len(zones)], Category.SIGNAL), []):
            link(junction, signal, EdgeKind.DEPENDS)
    meters = [d.id for d in layout.devices if d.category is Category.METER]
    if meters:
        for d in layout.devices:
            if d.category in (Category.METER, Category.EV_CHARGER):
                link(meters[0], d.id, EdgeKind.DEPENDS)

    return [Edge(src=s, dst=d, kind=k) for s, d, k in sorted(keys, key=lambda e: (e[0], e[1], e[2].value))]
