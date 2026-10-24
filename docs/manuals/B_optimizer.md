# Manual B — Optimiser, baselines, evaluation, benchmark

**Owner:** Sai Varun (`Sai-Varun-Tej`) · **Branch:** `b/optimizer` · **Tests:** `tests/test_opt.py`

## Why this part matters

This is the headline number of the whole project: **same budget, UrbanShield cuts worst-case loss by X%
versus CVSS-first and versus BFS-only**, measured honestly on scenarios the optimiser never saw. You also
produce the scalability chart. Judges will ask "is this fair?" — every baseline gets the same budget,
downtime window and constraints, so the answer is yes.

## You own

```
backend/src/urbanshield/opt/        common.py, cvar.py, baselines.py, greedy.py, evaluate.py (+ private helpers)
backend/scripts/bench.py            (new)
backend/scripts/run_evals.py        (new)
docs/EVALS.md
```

**Never touch:** `schemas.py`, `city/`, `sim/`, `guard/`, `agents/`, `api/`, `frontend/`, other people's tests.

## Contracts you use

`City`, `ScenarioLosses` (your input: `device_loss` is S×N), `Budget`, `Constraint`, `ConstraintKind`,
`Objective`, `Plan`, `PlanMetrics`, `Solver`, `ControlKind`.

**You don't need A's simulator to start.** `tests/test_opt.py` builds a synthetic `ScenarioLosses`
fixture. Only `evaluate.py` / `compare` need `simulate()` (Anubhav delivers it ≈ h6) and `generate_city`
(Prabhav, ≈ h4).

---

## Tasks (in order)

### B1 · Shared helpers (target: h1)
`opt/common.py`: `cvar` (mean of the worst `tail_size(S, α)` losses — already written, it guards a float off-by-one; use it in the MILP too), `reduction` (r = 1 − exploit_mult × spread_mult
for that device's option of that kind), `is_feasible` (every rule in the module docstring).
**Done when:** `uv run pytest -k cvar_definition` passes.

### B2 · Baselines (target: h3)
`opt/baselines.py:rank_and_buy` for CVSS, CVSS_KEV_EPSS, LOSS_PER_INR, BFS_CENTRALITY. Walk the ranking,
buy the device's patch (or cheapest feasible option if patch is infeasible under constraints) while
budget and downtime allow; skip devices that don't fit and continue. `solver=Solver.RANKING`.
BFS_CENTRALITY uses `city.graphs.reach_centrality` (Prabhav's) — until it merges, rank by out-degree of REACH edges
in a private helper and switch later.
**Done when:** the four baseline cases of `test_every_planner_is_feasible` pass.

### B3 · Greedy tail heuristic (target: h5)
`opt/greedy.py:greedy_tail`: start empty; each step evaluate every affordable (device, control) swap/add,
pick the largest CVaR drop per rupee (vectorise: precompute `device_loss * r` columns), stop when nothing
improves. **Done when:** the greedy feasibility case passes.

### B4 · CVaR MILP (target: h8) ★ the core
`opt/cvar.py:solve` with HiGHS via `scipy.optimize.milp` (ported from PuLP + CBC at integration: PuLP 4
ships no CBC binary), exactly the formulation in the docstring.
- Variables: binary `x[i,k]` for each device's listed options, continuous `t`, `z[s] ≥ 0`.
- `L_s(x) = Σ_i loss[s,i] − Σ_i Σ_k loss[s,i]·r_ik·x_ik` (linear, because loss is data).
- Constraints: budget, downtime, ≤1 option per device, NO_DOWNTIME_ZONE (x=0 for options with downtime
  in that zone), MUST_FIX (Σ_k x ≥ 1), FORBID_CONTROL (x=0).
- `Objective.MEAN`: minimise `(1/S) Σ_s L_s(x)` instead. `Objective.PATCH_ONLY`: CVaR with only PATCH options.
- `pulp.PULP_CBC_CMD(msg=False, timeLimit=time_limit_s, warmStart=True)`; set initial values from
  `greedy_tail`. If status is not optimal **and** no incumbent, return the greedy plan with
  `solver=Solver.GREEDY`.
- Plan id: `plan-<objective>-<8-hex of sorted choices>`; record `solve_ms`.
**Done when:** all of `test_opt.py` except `test_compare_runs_everything` passes.

### B5 · Held-out evaluation (target: h11, needs S1 + A2)
`opt/evaluate.py`:
- `evaluate_plan`: `simulate(city, n, seed=TEST_SEED, controls=plan.choices)`; CVaR, mean, max cascade
  (max over scenarios of compromised + cascaded device count), bootstrap CI (resample scenarios with
  replacement, 500×, 2.5/97.5 percentiles of CVaR), `linear_gap` = (MILP-predicted CVaR on test −
  simulated CVaR) / simulated CVaR.
- `compare`: simulate train set (TRAIN_SEED) → run every objective → evaluate each on test → return
  CVaR first.
**Done when:** `uv run pytest -m slow` passes.

### B6 · Evaluation report (target: h13)
`scripts/run_evals.py` writes `docs/EVALS.md`: the comparison table (objective, cost, downtime,
CVaR test ± CI, mean, max cascade, solver, ms), the % reduction vs CVSS-first / BFS-only / MEAN, and a
sensitivity check (perturb costs and criticalities ±20% over 5 seeds; does the advantage survive?).
**Report honestly**, including any seed where we lose.

### B7 · Scalability benchmark (target: h16)
`scripts/bench.py`: for N in 50, 500, 5000 devices (A's generator) and S = 1000: time simulate, MILP
(30 s limit), greedy; record CVaR gap MILP vs greedy where both exist. Save `docs/bench.png`
(matplotlib is fine as a dev-only script dep — ask Rayan to add it) and a table in EVALS.md.

---

## Paste-ready prompt for your agent

```text
Do task B1 from docs/manuals/B_optimizer.md. Implement only opt/common.py, keeping the exact
signatures. Then run `uv run pytest -k cvar_definition -p no:cacheprovider` and show me the output.
Then ruff check --fix and ruff format.
```
Repeat B2, B3, … one at a time.

## Definition of done
All of `test_opt.py` passes (including `-m slow`); `docs/EVALS.md` and `docs/bench.png` generated by
scripts; ruff clean; PR merged.
