# Modelling assumptions

_Owner: A. One page; every number the model uses, and where it comes from._

| Item | Value | Source / rationale |
|---|---|---|
| Devices | 50 in four categories | Synthetic, placed on Mangaluru streets |
| CVE / CVSS / EPSS / KEV | ~40 real records | Pinned snapshot of NVD, FIRST EPSS, CISA KEV (`backend/data/feeds/`) |
| Exploit odds | 1 − Π(1 − EPSS) | _to fill_ |
| Campaign rate | _to fill_ | |
| Control costs / downtime / multipliers | _to fill_ | |

## Known simplifications

- The optimiser's loss is additive over devices and double-counts overlapping cascades; every plan is
  re-checked in the full simulator and the gap is reported (`linear_gap`).
- External attacker exploiting known vulnerabilities only; zero-days, insiders and physical attacks are out of scope.
- Probabilities are estimates for ranking decisions, not predictions.
