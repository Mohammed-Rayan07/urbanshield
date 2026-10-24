"""Honest baselines: same budget, same downtime window, same constraints. Owner: B.

Each baseline ranks devices, then walks the ranking buying the device's *patch*
(or its cheapest allowed control if the patch is not allowed or does not fit) while it
still fits; must-fix devices go first.

- CVSS: highest max-CVSS first.
- CVSS_KEV_EPSS: score = max_cvss/10 + 0.5*kev + epss.
- LOSS_PER_INR: expected loss removed per rupee (uses ``losses``).
- BFS_CENTRALITY: most devices reachable (``graphs.reach_centrality``). This is the
  "why not just BFS?" baseline.
"""

from __future__ import annotations

import time

from urbanshield.city.graphs import build_graphs, reach_centrality
from urbanshield.opt._model import allowed_options, effective_budget, must_fix, plan_id
from urbanshield.schemas import (
    Budget,
    City,
    Constraint,
    ControlKind,
    Device,
    Objective,
    Plan,
    ScenarioLosses,
    Solver,
)

BASELINES = (
    Objective.CVSS,
    Objective.CVSS_KEV_EPSS,
    Objective.LOSS_PER_INR,
    Objective.BFS_CENTRALITY,
)


def _scores(objective: Objective, city: City, losses: ScenarioLosses) -> dict[str, float]:
    if objective == Objective.BFS_CENTRALITY:
        return {d: float(v) for d, v in reach_centrality(build_graphs(city)).items()}
    if objective == Objective.LOSS_PER_INR:
        mean = dict(zip(losses.device_ids, losses.device_loss.mean(axis=0), strict=True))
        return {d.id: _loss_per_inr(d, float(mean.get(d.id, 0.0))) for d in city.devices}
    return {d.id: _vuln_score(objective, d) for d in city.devices}


def _vuln_score(objective: Objective, device: Device) -> float:
    max_cvss = max((v.cvss for v in device.vulns), default=0.0)
    if objective == Objective.CVSS:
        return max_cvss
    has_kev = any(v.kev for v in device.vulns)
    max_epss = max((v.epss for v in device.vulns), default=0.0)
    return max_cvss / 10.0 + (0.5 if has_kev else 0.0) + max_epss


def _loss_per_inr(device: Device, mean_loss: float) -> float:
    target = next((c for c in device.controls if c.kind == ControlKind.PATCH), None)
    target = target or (device.controls[0] if device.controls else None)
    if target is None:
        return 0.0
    removed = mean_loss * (1.0 - target.exploit_mult * target.spread_mult)
    return removed / target.cost_inr if target.cost_inr > 0 else removed * 1e6


def rank_and_buy(
    city: City,
    losses: ScenarioLosses,
    budget: Budget,
    objective: Objective,
    constraints: list[Constraint] | None = None,
) -> Plan:
    """Build the baseline plan for one of ``BASELINES`` with ``solver=Solver.RANKING``."""
    if objective not in BASELINES:
        raise ValueError(f"{objective} is not a ranking baseline")
    t0 = time.perf_counter()
    constraints = list(constraints or [])
    limits = effective_budget(budget, constraints)
    allowed = allowed_options(city, constraints)
    scores = _scores(objective, city, losses)

    first = set(must_fix(constraints))
    ranked = sorted(city.devices, key=lambda d: (d.id not in first, -scores[d.id], d.id))

    choices: dict[str, ControlKind] = {}
    cost, downtime = 0, 0.0
    for device in ranked:
        fits = [
            o
            for o in allowed[device.id]
            if cost + o.cost_inr <= limits.inr and downtime + o.downtime_h <= limits.downtime_h
        ]
        if not fits:
            continue
        patch = next((o for o in fits if o.kind == ControlKind.PATCH), None)
        chosen = patch or min(fits, key=lambda o: (o.cost_inr, o.downtime_h))
        choices[device.id] = chosen.kind
        cost += chosen.cost_inr
        downtime += chosen.downtime_h

    return Plan(
        id=plan_id(objective, choices),
        city_id=city.id,
        objective=objective,
        choices=choices,
        cost_inr=cost,
        downtime_h=float(downtime),
        solver=Solver.RANKING,
        solve_ms=int((time.perf_counter() - t0) * 1000),
    )
