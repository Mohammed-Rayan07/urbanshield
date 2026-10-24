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

from urbanshield.schemas import City, Vulnerability

MANGALURU_BBOX = (12.80, 74.78, 13.05, 74.92)  # (lat_min, lon_min, lat_max, lon_max)
DEFAULT_SEED = 7


def generate_city(
    seed: int = DEFAULT_SEED,
    n_devices: int = 50,
    feed: dict[str, Vulnerability] | None = None,
) -> City:
    """Build the city twin. When ``feed`` is given, seed vulnerabilities from real records."""
    raise NotImplementedError
