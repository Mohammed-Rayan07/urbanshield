# Manual S — Attack simulator, audit log, Auditor

**Owner:** Anubhav (`anubhav10cs`) · **Branch:** `s/sim-audit` · **Tests:** `tests/test_sim.py`, then the audit-log and Auditor tests in `tests/test_guard.py`

## Why this part matters

The simulator produces every loss number in the project: the optimiser (B) plans on it, the Red-Team agent
attacks with it, and the headline result is measured with it. The audit log and the Auditor are the two
security features judges will try to break live: **edit one log row and the chain must break exactly there;
an agent that states a wrong number must be rejected.**

## You own

```
backend/src/urbanshield/sim/            montecarlo.py (+ private helpers)
backend/src/urbanshield/guard/audit_log.py
backend/src/urbanshield/guard/auditor.py
docs/ASSUMPTIONS.md                     (simulator rows only; A owns the rest)
```

**Never touch:** `schemas.py`, `city/`, `opt/`, `agents/`, `guard/allowlist.py`, `guard/quarantine.py`,
`api/`, `frontend/`, other people's tests.

## You don't need to wait for anyone

Your tests use `tiny_city` (6 devices, in `tests/conftest.py`). For graph work inside the simulator, build
your own sparse adjacency from `city.edges` in a private helper; don't import A's unfinished functions.
Only `test_fast_enough` needs A's `generate_city` (it skips until A merges).

---

## Tasks (in order)

### S1 · Monte Carlo simulator (target: h6) ★ unblocks B
Implement `sim/montecarlo.py:simulate`. The model is in its docstring; read it twice.
- **Vectorised:** arrays of shape (S, N). Spread over REACH edges hop by hop (≤ N hops, usually < 10),
  each hop one sparse mat-mul of the frontier. Never loop over scenarios.
- **Common random numbers:** draw all uniforms for the seed first, then compare with the controlled odds.
  Applying controls must not change which random numbers are used.
- **Entry:** each scenario picks 1–3 exposed devices, or the strategy's `entry_points`.
- **Campaigns:** `campaign_rate` of scenarios pick one CVE (weight = EPSS × number of carriers) and make ONE
  exploit draw with its odds. If it fires, every carrier is compromised together and `campaign_cve[s]` = that
  CVE; otherwise `campaign_cve[s]` = None and the scenario runs as an ordinary one.
- **Damage:** a lost device costs its `criticality`; loss cascades over DEPENDS edges from each lost device,
  scaled by its `spread_mult` (1.0 if no control). `device_loss[s, i]` = own loss + cascade it caused.
- **Controls:** `exploit_mult` scales the device's exploit odds; `spread_mult` scales what it passes on.
- **Strategy (Red-Team):** `entry_points`; `target_category` (bias entry toward devices that can reach that
  category; write your choice in ASSUMPTIONS.md); `pivot_shared_firmware` (one family member lost → whole
  family lost); `campaign_cve` (force campaigns on that CVE).
- **Done when:** all of `tests/test_sim.py` passes except `test_fast_enough` (that one after A merges:
  < 2 s for 2,000 scenarios × 50 devices). Then message B: "simulate() is on my branch".

### S2 · Hash-chained audit log (target: h9)
Implement `guard/audit_log.py` exactly as its docstring says: SQLite table, SHA-256 chain, PyNaCl Ed25519
signatures (`nacl.signing.SigningKey`), `verify()` that recomputes everything and reports the **first bad
seq**. Editing one byte of any stored event must fail at exactly that entry.
- **Done when:** `uv run pytest -k "chain or one_byte"` passes.

### S3 · The Auditor (target: h11)
Implement `guard/auditor.py:check_claims` and `render` per the docstring.
- Reasons are short and human: `no tool call tc-404`, `plan_b 20.0 ≠ recorded 28.0`, `delta ≠ plan_b − plan_a`.
- `render` example: `Worst-case loss (CVaR 95%) falls from 40.0 to 28.0 (−30.0%).`
- **Done when:** `uv run pytest -k auditor` passes.

### S4 · Simulator assumptions + speed (target: h13)
Write the simulator rows in `docs/ASSUMPTIONS.md` (exploit odds, entry points, campaign rate, cascade rule,
strategy handling). Then check `simulate(generate_city(n_devices=5000), n_scenarios=1000)` runs in seconds
for B's benchmark; profile and fix if not.

---

## Paste-ready prompt for your coding agent

```text
Do task S1 from docs/manuals/S_sim_audit.md. Implement only sim/montecarlo.py (private helpers allowed
in sim/). Keep the exact signature. Fully vectorised with NumPy and scipy.sparse; no loop over
scenarios. Then run `uv run pytest tests/test_sim.py -p no:cacheprovider` in backend/ and show me the
output. Then run `uv run ruff check . --fix` and `uv run ruff format .`.
```
Repeat for S2, S3, S4 one task at a time.

## Definition of done
`test_sim.py` and the audit-log + Auditor tests pass, ruff clean, simulator assumptions written, PR merged.
