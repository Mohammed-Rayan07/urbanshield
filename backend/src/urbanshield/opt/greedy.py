"""Greedy tail heuristic: a baseline and the MILP's fallback. Owner: B.

Repeatedly buy (or swap to) the (device, control) pair with the largest CVaR reduction
per rupee until nothing affordable improves CVaR. Same option table as the MILP
(``_model.option_table``), so it scales to thousands of devices where an exact solve
cannot.

Each step is exact but lazy: for any candidate, ``CVaR(L - d) >= mean over the current
tail of (L - d)``, so its drop is at most the mean of ``d`` over the current tail. Every
candidate's bound comes from one matrix product; exact CVaRs are then computed in bound
order, a block at a time, and the scan stops once no remaining bound can beat the best.
"""

from __future__ import annotations

import time

import numpy as np

from urbanshield.opt._model import effective_budget, must_fix, option_table, plan_id
from urbanshield.opt.common import cvar, tail_size
from urbanshield.schemas import (
    Budget,
    City,
    Constraint,
    ControlKind,
    Objective,
    Plan,
    ScenarioLosses,
    Solver,
)

EPS = 1e-9
FREE_BONUS = 1e6  # a swap that saves money and lowers CVaR beats any paid move
BLOCK = 64  # candidates evaluated exactly per batch


def _score(drop: np.ndarray, d_cost: np.ndarray) -> np.ndarray:
    return np.where(d_cost > 0, drop / np.maximum(d_cost, EPS), drop * FREE_BONUS)


def greedy_tail(
    city: City,
    losses: ScenarioLosses,
    budget: Budget,
    constraints: list[Constraint] | None = None,
) -> Plan:
    """Return a feasible plan with ``objective=GREEDY_TAIL`` and ``solver=Solver.GREEDY``."""
    t0 = time.perf_counter()
    constraints = list(constraints or [])
    limits = effective_budget(budget, constraints)
    table = option_table(city, losses, constraints)
    s, m = table.saved.shape
    rows = np.ascontiguousarray(table.saved.T)  # (M, S): one option per row, cheap to gather
    k = tail_size(s, limits.alpha)

    current = np.full(len(city.devices), -1)  # chosen option per device (-1 = none)
    cost = downtime = 0.0
    loss = table.base.astype(float).copy()

    by_device: dict[int, list[int]] = {}
    for j, i in enumerate(table.device):
        by_device.setdefault(int(i), []).append(j)
    index = {d.id: i for i, d in enumerate(city.devices)}
    for device_id in must_fix(constraints):  # cheapest allowed control first, if it fits
        options = by_device.get(index.get(device_id, -1), [])
        if not options:
            continue
        j = min(options, key=lambda o: (table.cost[o], table.downtime[o]))
        if cost + table.cost[j] <= limits.inr and downtime + table.downtime[j] <= limits.downtime_h:
            current[table.device[j]] = j
            cost, downtime = cost + table.cost[j], downtime + table.downtime[j]
            loss -= rows[j]

    while m:
        held = current[table.device]  # option currently held by each candidate's device
        has = held >= 0
        safe = np.where(has, held, 0)
        d_cost = table.cost - np.where(has, table.cost[safe], 0.0)
        d_down = table.downtime - np.where(has, table.downtime[safe], 0.0)
        ok = (
            (held != np.arange(m))
            & (cost + d_cost <= limits.inr + EPS)
            & (downtime + d_down <= limits.downtime_h + EPS)
        )
        if not ok.any():
            break
        now = cvar(loss, limits.alpha)
        tail = np.argpartition(loss, s - k)[-k:] if k < s else np.arange(s)
        tail_mean = rows[:, tail].mean(axis=1)
        gain_tail = tail_mean - np.where(has, tail_mean[safe], 0.0)
        bound = np.where(ok & (gain_tail > EPS), _score(gain_tail, d_cost), -np.inf)

        order = np.argsort(-bound, kind="stable")
        best, best_score = -1, 0.0
        for start in range(0, m, BLOCK):
            block = order[start : start + BLOCK]
            block = block[bound[block] > max(best_score, 0.0)]
            if block.size == 0:
                break
            diff = rows[block] - has[block, None] * rows[safe[block]]
            cand = loss[None, :] - diff
            tail_part = np.partition(cand, s - k, axis=1)[:, -k:] if k < s else cand
            cand_cvar = tail_part.mean(axis=1)
            scores = np.where(now - cand_cvar > EPS, _score(now - cand_cvar, d_cost[block]), -np.inf)
            top = int(np.argmax(scores))
            if scores[top] > best_score:
                best, best_score = int(block[top]), float(scores[top])
        if best < 0:
            break
        i = table.device[best]
        if current[i] >= 0:
            loss += rows[current[i]]
        loss -= rows[best]
        cost, downtime = cost + d_cost[best], downtime + d_down[best]
        current[i] = best

    picked = [int(j) for j in current if j >= 0]
    choices: dict[str, ControlKind] = {table.keys[j][0]: table.keys[j][1] for j in picked}
    return Plan(
        id=plan_id(Objective.GREEDY_TAIL, choices),
        city_id=city.id,
        objective=Objective.GREEDY_TAIL,
        choices=choices,
        cost_inr=int(table.cost[picked].sum()),
        downtime_h=float(table.downtime[picked].sum()),
        solver=Solver.GREEDY,
        solve_ms=int((time.perf_counter() - t0) * 1000),
    )
