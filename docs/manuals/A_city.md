# Manual A — City twin, graphs, vulnerability feed

**Owner:** Prabhav (`Prabhavravi`) · **Branch:** `a/city` · **Tests:** `tests/test_city.py`

## Why this part matters

Everything stands on your city. The simulator (S) attacks it, the optimiser (B) spends money on it, the
agents (C) call your BFS as a tool, and the dashboard draws your devices on the map of Mangaluru. The demo
story has to be **built into your city**: a CVSS-first plan wastes money on isolated decoys while a
medium-severity shared-firmware family sits one hop from the ambulance corridor.

## You own

```
backend/src/urbanshield/city/          generator.py, graphs.py, feeds.py (+ private helpers)
backend/scripts/build_feed_snapshot.py (new)
backend/data/feeds/                    feed_snapshot.json + feed_snapshot.sha256
docs/ASSUMPTIONS.md                    (city + data rows; S adds the simulator rows)
```

**Never touch:** `schemas.py`, `sim/`, `opt/`, `agents/`, `guard/`, `api/`, `frontend/`, other people's tests.

## Contracts you use (read `schemas.py`)

`City`, `Device`, `Edge`, `EdgeKind`, `Vulnerability`, `ControlOption`, `Autonomy`, `Category`.

---

## Tasks (in order)

### A1 · Graphs and BFS (target: h2)
Implement `city/graphs.py`: `build_graphs`, `bfs_reach`, `blast_radius`, `reach_centrality`.
- `scipy.sparse.csr_matrix` for `reach` and `depends`; index devices in `city.devices` order.
- `bfs_reach`: frontier loop over the sparse matrix (or `scipy.sparse.csgraph.breadth_first_order`);
  `blocked` nodes are never entered and never pass anything on.
- **Done when:** `uv run pytest -k "bfs_reach or blast_radius"` passes.

### A2 · City generator on Mangaluru (target: h4) ★ unblocks everyone
Implement `city/generator.py:generate_city(seed, n_devices, feed)`. Read its docstring: the
**demo structure is mandatory** and the tests check it.
- Zones and centres: Surathkal (13.0108, 74.7943), Panambur (12.9419, 74.8090),
  Kottara (12.9050, 74.8380), Hampankatta (12.8698, 74.8430). Jitter devices ±0.01°.
  Put the corridor signals roughly along NH-66 (the north→south line through those centres).
- Mix: ~40% streetlight, 25% signal, 20% meter, 15% EV charger.
- Fictional firmware: `lumenos/4.1.x` (the shared streetlight family), `trafikon/7.x` (signals),
  `voltgrid/2.x` (EV chargers), `metrix/3.x` (meters), `decorlite/1.0.0` (decoys).
- Control options per device (2–5): costs ₹2k–₹60k, downtime 0–6 h. `rotate_creds` = AUTO; anything with
  downtime > 0 = APPROVE. Patch: strongest `exploit_mult` (≈0.05–0.15) but has downtime. Segment: cuts
  `spread_mult` (≈0.2–0.4).
- REACH edges: sparse mesh within each zone, the streetlight family chained together, one or two EV chargers
  acting as gateways into the corridor signals. DEPENDS edges: corridor signals depend on each other in
  sequence; meters feed one substation-like meter; a few random ones.
- Must work for `n_devices` = 50, 500 and 5,000 (B's benchmark). Keep the demo structure; scale the rest.
- With `feed` given, take CVSS / EPSS / KEV for the CVEs you assign from it.
- **Done when:** all of `tests/test_city.py` except the feed tests passes. Tell the team in the group.

### A3 · Pinned vulnerability feed (target: h6)
1. `scripts/build_feed_snapshot.py` downloads **once, by hand** (never at runtime):
   - CISA KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
   - EPSS: `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`
   - CVSS for the chosen CVEs from NVD API 2.0: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>`
     (sleep 6 s between calls; no key needed).
   Choose ~40 real CVEs in IoT/ICS-style products (routers, cameras, controllers, chargers) with CVSS spread
   4–10, some on KEV. Write `data/feeds/feed_snapshot.json` (format in the `feeds.py` docstring) and its SHA-256
   in `data/feeds/feed_snapshot.sha256`.
2. Implement `city/feeds.py`: `sha256_file`, `load_feed` (check the hash first → `FeedIntegrityError`),
   `feed_record`.
3. Make `generate_city` use the real feed by default when the snapshot exists (tests pass `feed=None`
   explicitly where they need determinism without it).
- **Done when:** `uv run pytest -k feed` passes and both data files are committed.

### A4 · ASSUMPTIONS.md (target: h8)
Fill the city and data rows: device mix, zones, firmware families, control costs and multipliers, which
CVEs are real, what is synthetic. Plain sentences plus one table. Judges read this.

### A5 · Scale check (target: h10)
`generate_city(n_devices=5000)` must run in a few seconds and keep every test property. Profile if not.
Then help S and B: ask them what they need.

---

## Paste-ready prompt for your coding agent

```text
Do task A1 from docs/manuals/A_city.md. Implement only city/graphs.py with the exact signatures.
Use scipy.sparse. Then run `uv run pytest -k "bfs_reach or blast_radius" -p no:cacheprovider` in backend/
and show me the output. Then run `uv run ruff check . --fix` and `uv run ruff format .`.
```
Repeat for A2, A3, … one task at a time.

## Definition of done
All of `test_city.py` passes, ruff clean, feed snapshot + hash committed, ASSUMPTIONS.md city rows written, PR merged.
