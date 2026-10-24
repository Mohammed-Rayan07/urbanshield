# Modelling assumptions

_Owner: A. One page; every number the model uses, and where it comes from._

| Item | Value | Source / rationale |
|---|---|---|
| Devices | 50 by default; generator scales to 500 and 5,000 | Synthetic devices placed within the Mangaluru bounding box; the default mix is approximately 40% streetlights, 25% signals, 20% meters and 15% EV chargers |
| Zones and corridor | Surathkal, Panambur, Kottara and Hampankatta; four NH-66 corridor signals | Synthetic topology anchored on the documented Mangaluru centres; coordinates are jittered within 0.01° and corridor signals are criticality 0.95 |
| Firmware families | `lumenos/4.1.x`, `trafikon/7.x`, `metrix/3.x`, `voltgrid/2.x`, plus `decorlite/1.0.0` decoys | Fictional vendor and firmware names; the shared streetlight family, EV gateways and ambulance corridor are synthetic demo structure |
| CVE / CVSS / EPSS / KEV | 40 real records, CVSS 5.4–9.8 in the committed snapshot | Pinned snapshot of NVD, FIRST EPSS and CISA KEV (`backend/data/feeds/`); devices use the snapshot's CVSS, EPSS and KEV fields |
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
