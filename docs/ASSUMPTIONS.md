# Modelling assumptions

_Owner: A. One page; every number the model uses, and where it comes from._

| Item | Value | Source / rationale |
|---|---|---|
| Devices | 50 by default; generator scales to 500 and 5,000 | Synthetic devices placed within the Mangaluru bounding box; the default mix is approximately 40% streetlights, 25% signals, 20% meters and 15% EV chargers |
| Zones and corridor | Surathkal, Panambur, Kottara and Hampankatta; four corridor signals placed along NH-66 (approximated by the zone-centre polyline) towards the district hospital | Synthetic topology anchored on real Mangaluru locations; other devices are jittered within 0.01° of their zone centre; corridor signals have criticality 0.95 |
| Firmware families | `lumenos/4.1.x` (shared family, 60% of streetlights), `lumenos/4.2.x`, `trafikon/7.x`, `metrix/3.x`, `voltgrid/2.x`, plus `decorlite/1.0.0` decoys | Fictional vendor and firmware names; the shared family, gateways and corridor are deliberate demo structure |
| Attack paths (REACH) | Each category in each zone is its own field network (neighbours reach each other); the light family also shares a management network; networks meet only at the first EV charger of each zone (`gateway`), and two gateways bridge the light family into the corridor | Models segmented municipal networks joined by depot backhaul; segmenting the gateways genuinely cuts the family→corridor path (tested) |
| Damage paths (DEPENDS) | Corridor junctions depend on each other in sequence and coordinate their zone's signals; the substation meter feeds every meter and EV charger | Green-wave signal coordination and metering head-end dependency |
| Decoys | 15% of streetlights: exposed, CVSS ≥ 9.0, criticality 0.10, **no edges at all** | The CVSS-first trap: a critical score on a device nothing depends on |
| CVE / CVSS / EPSS / KEV | 40 real CISA KEV entries for embedded IoT/OT vendors (routers, cameras, PLCs, SCADA), balanced by CVSS band and vendor | Pinned snapshot (`backend/data/feeds/`, SHA-256 checked against the sidecar *and* a digest in code); built by `scripts/build_feed_snapshot.py` from CISA KEV, FIRST EPSS and NVD |
| CVE roles | Family: medium-CVSS CVE with the highest EPSS. Decoys: critical CVE with the lowest EPSS. Corridor: the medium CVE of median EPSS among the rest. Everyone else: 1–2 CVEs (25% get two) drawn from the remaining pool | Severity and real-world likelihood diverge, which is exactly what a CVSS-only ranking misses |
| Exposure | 12% of ordinary devices, the first family member, and all decoys are internet-exposed; corridor signals never are | Entry points for the simulator |
| Exploit odds | 1 − Π(1 − EPSS) | _to fill_ |
| Campaign rate | _to fill_ | |
| Control costs / downtime / multipliers | ₹2,000–₹60,000; 0–4 h; patch exploit multiplier 0.10, segment spread multiplier 0.30 | Synthetic planning assumptions; credential rotation is automatic, while controls with downtime require approval |

## Known simplifications

The city is a deterministic synthetic twin of Mangaluru rather than an inventory of real municipal assets. The
map coordinates and dependency/reachability edges are illustrative. The shared `lumenos/4.1.x` family carries
a medium-severity vulnerability so that the demo can show why topology and common firmware matter more than a
CVSS-only ranking; the high-CVSS `decorlite` devices are isolated decoys. Vendor names, device names, control
prices and all topology relationships are synthetic. Only the vulnerability identifiers and their CVSS, EPSS and
KEV values come from public pinned feeds.

- The optimiser's loss is additive over devices and double-counts overlapping cascades; every plan is
  re-checked in the full simulator and the gap is reported (`linear_gap`).
- External attacker exploiting known vulnerabilities only; zero-days, insiders and physical attacks are out of scope.
- Probabilities are estimates for ranking decisions, not predictions.
