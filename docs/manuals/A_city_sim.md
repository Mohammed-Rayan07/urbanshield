# Manual A — City twin, simulator, audit log

**Branch:** `a/city-sim` · **Tests:** `tests/test_city.py`, `tests/test_sim.py`, then `tests/test_guard.py` (audit log + Auditor parts)

## Why this part matters

Everything else stands on your city and your simulator. The optimiser (B) needs your loss matrix,
the agents (C) call your BFS and simulation as tools, and the dashboard (D) draws your devices on the
map. The demo story — *a CVSS-first plan wastes money on isolated decoys while a medium-severity
shared-firmware family sits one hop from the ambulance corridor* — has to be **built into your city**.

## You own

```
backend/src/urbanshield/city/          generator.py, graphs.py, feeds.py (+ private helpers)
backend/src/urbanshield/sim/           montecarlo.py (+ private helpers)
backend/src/urbanshield/guard/audit_log.py      (task A6, after h6)
backend/src/urbanshield/guard/auditor.py        (task A7, after h6)
backend/scripts/build_feed_snapshot.py          (new)
backend/data/feeds/                             (snapshot + sha256)
docs/ASSUMPTIONS.md
```

**Never touch:** `schemas.py`, `opt/`, `agents/`, `api/`, `frontend/`, other people's tests.

## Contracts you use (read `schemas.py`)

`City`, `Device`, `Edge`, `Vulnerability`, `ControlOption`, `Strategy`, `ScenarioLosses`,
`AgentEvent`, `AuditEntry`, `VerifyResult`, `Claim`, `ToolResult`.

---

## Tasks (in order)

### A1 · Graphs and BFS (target: h2)
Implement `city/graphs.py`: `build_graphs`, `bfs_reach`, `blast_radius`, `reach_centrality`.
- Use `scipy.sparse.csr_matrix` for `reach` and `depends`; index devices in `city.devices` order.
- `bfs_reach` uses `scipy.sparse.csgraph.breadth_first_order` or a simple frontier loop over the
  sparse matrix, skipping `blocked` nodes entirely (they are never entered and never pass on).
- **Done when:** `uv run pytest -k "bfs_reach or blast_radius"` passes.

### A2 · City generator on Mangaluru (target: h4)
Implement `city/generator.py:generate_city(seed, n_devices, feed)`. Read its docstring: the
**demo structure is mandatory** and the tests check it.
- Zones and centres: Surathkal (13.0108, 74.7943), Panambur (12.9419, 74.8090),
  Kottara (12.9050, 74.8380), Hampankatta (12.8698, 74.8430). Jitter devices ±0.01°.
  Put corridor signals roughly along NH-66 (north→south line between those centres).
- Categories: ~40% streetlight, 25% signal, 20% meter, 15% EV charger.
- Fictional vendors/firmware: `lumenos/4.1.x` (the shared streetlight family), `trafikon/7.x` (signals),
  `voltgrid/2.x` (EV), `metrix/3.x` (meters), `decorlite/1.0.0` (decoys).
- Control options: costs ₹2k–₹60k, downtime 0–6 h; `rotate_creds` = AUTO, anything with downtime = APPROVE.
  Patch has the strongest `exploit_mult` (≈0.05–0.15) but downtime; segment cuts `spread_mult` (≈0.2–0.4).
- REACH edges: within-zone mesh (sparse), the streetlight family chained together, one or two
  EV chargers acting as gateways into the corridor signals. DEPENDS edges: corridor signals depend on each
  other in sequence; meters → a substation-like meter; a few random ones.
- Must work for `n_devices` = 50, 500, 5000 (the benchmark uses big cities; keep the demo structure, scale the rest).
- When `feed` is given, take CVSS/EPSS/KEV for the CVEs you assign from it.
- **Done when:** all of `tests/test_city.py` except the feed tests passes.

### A3 · Pinned vulnerability feed (target: h5)
1. Write `scripts/build_feed_snapshot.py` that downloads, **once, by hand** (not at runtime):
   - CISA KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
   - EPSS scores: `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`
   - CVSS for ~40 chosen CVEs from NVD API 2.0: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>`
     (sleep 6 s between calls, no key needed).
   Choose ~40 real CVEs affecting IoT/ICS-style products (routers, cameras, controllers, chargers) with a
   spread of CVSS 4–10 and some on KEV. Write `data/feeds/feed_snapshot.json` (format in `feeds.py`
   docstring) and `data/feeds/feed_snapshot.sha256`.
2. Implement `city/feeds.py`: `sha256_file`, `load_feed` (verify hash first → `FeedIntegrityError`),
   `feed_record`.
3. Commit the snapshot and hash. Runtime never touches the network.
- **Done when:** `uv run pytest -k feed` passes.

### A4 · Monte Carlo simulator (target: h6) ★ unblocks B
Implement `sim/montecarlo.py:simulate`. Model is in the docstring. Requirements:
- Vectorised: arrays of shape (S, N). Spread over REACH by iterating *hops* (≤ N, usually < 10),
  each hop a sparse mat-mul of the frontier, never a loop over scenarios.
- Entry: each scenario picks 1–3 exposed devices (or the strategy's `entry_points`).
- Campaigns: `campaign_rate` of scenarios pick one CVE weighted by EPSS×carriers and make ONE exploit draw
  with that CVE's odds. If it fires, all carriers are compromised together and `campaign_cve[s]` = the CVE;
  if not, `campaign_cve[s]` = None and the scenario runs as an ordinary one.
- Common random numbers: draw every uniform for the seed up front, *then* compare with the controlled odds.
  Applying controls must not change which random numbers are used (otherwise plan comparisons are noise).
- Damage: device loss = criticality; cascade over DEPENDS from each lost device scaled by its
  `spread_mult` (1.0 if no control); attribute own loss + caused cascade to the device (`device_loss`).
- Controls: apply `exploit_mult` to the device's exploit odds and `spread_mult` to what it passes on.
- Strategy: `entry_points`, `target_category` (only count loss on that category... or bias entry toward
  paths to it — document your choice in ASSUMPTIONS.md), `pivot_shared_firmware` (compromising one
  family member compromises the family), `campaign_cve` (force campaigns on that CVE).
- **Done when:** all of `tests/test_sim.py` passes (including < 2 s for 2,000 × 50).
- Then message B: "simulate() is on my branch".

### A5 · ASSUMPTIONS.md (target: h7)
One page: every modelling choice and number (costs, multipliers, campaign rate, what is real data vs
synthetic, known simplifications). Judges will read it. Plain sentences, a table for numbers.

### A6 · Hash-chained audit log (target: h9)
Implement `guard/audit_log.py` per its docstring (SQLite + SHA-256 chain + PyNaCl Ed25519).
- `verify()` must report `first_bad_seq` exactly at the edited entry.
- **Done when:** `uv run pytest -k "chain or one_byte"` passes.

### A7 · Auditor (target: h11)
Implement `guard/auditor.py:check_claims` and `render` per the docstring.
- Reasons are short and human: "no tool call tc-404", "plan_b value 20.0 ≠ recorded 28.0", "delta ≠ b − a".
- `render` example: `Worst-case loss (CVaR 95%) falls from 40.0 to 28.0 (−30.0%).`
- **Done when:** `uv run pytest -k auditor` passes.

### A8 · Help B with scale (target: h14)
Make sure `generate_city(n_devices=5000)` + `simulate(n_scenarios=1000)` runs in seconds. Profile if not.

---

## Paste-ready prompt for your agent (after the setup prompt in README)

```text
Do task A1 from docs/manuals/A_city_sim.md. Implement only city/graphs.py. Keep the exact function
signatures. Use scipy.sparse. Then run `uv run pytest -k "bfs_reach or blast_radius" -p no:cacheprovider`
and show me the output. Then run ruff check --fix and ruff format.
```
Repeat with A2, A3, … one task at a time.

## Definition of done
All of `test_city.py`, `test_sim.py` and the audit-log + Auditor tests pass; ruff clean;
ASSUMPTIONS.md written; PR merged.
