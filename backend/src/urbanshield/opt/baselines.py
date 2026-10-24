"""Honest baselines: same budget, same downtime window, same constraints. Owner: B.

Each baseline ranks devices, then walks the ranking buying the device's *patch*
(or its cheapest feasible control if it has no patch) while it still fits.

- CVSS: highest max-CVSS first.
- CVSS_KEV_EPSS: score = max_cvss/10 + 0.5*kev + epss.
- LOSS_PER_INR: expected loss removed per rupee (uses ``losses``).
- BFS_CENTRALITY: most devices reachable (``graphs.reach_centrality``). This is the
  "why not just BFS?" baseline.
"""

import hashlib
import time

import numpy as np

from urbanshield.opt.common import reduction
from urbanshield.schemas import (
    Budget,
    City,
    Constraint,
    ConstraintKind,
    ControlKind,
    EdgeKind,
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


def _make_plan_id(objective: Objective, choices: dict[str, ControlKind]) -> str:
    sorted_items = sorted(
        (dev_id, kind.value if hasattr(kind, "value") else str(kind)) for dev_id, kind in choices.items()
    )
    repr_str = ",".join(f"{k}:{v}" for k, v in sorted_items)
    h = hashlib.sha256(repr_str.encode()).hexdigest()[:8]
    obj_str = objective.value if hasattr(objective, "value") else str(objective)
    return f"plan-{obj_str}-{h}"


def _reach_centrality(city: City) -> dict[str, float]:
    try:
        from urbanshield.city.graphs import build_graphs, reach_centrality

        graphs = build_graphs(city)
        return {k: float(v) for k, v in reach_centrality(graphs).items()}
    except Exception:
        # Fallback to out-degree of REACH edges until Track A reach_centrality merges
        reach_counts: dict[str, float] = {d.id: 0.0 for d in city.devices}
        for edge in city.edges:
            if edge.kind == EdgeKind.REACH:
                reach_counts[edge.src] = reach_counts.get(edge.src, 0.0) + 1.0
        return reach_counts


def _score_device(
    objective: Objective,
    device,
    losses: ScenarioLosses,
    city: City,
    bfs_scores: dict[str, float],
) -> float:
    if objective == Objective.CVSS:
        return max((v.cvss for v in device.vulns), default=0.0)
    elif objective == Objective.CVSS_KEV_EPSS:
        max_cvss = max((v.cvss for v in device.vulns), default=0.0)
        has_kev = any(v.kev for v in device.vulns)
        max_epss = max((v.epss for v in device.vulns), default=0.0)
        return (max_cvss / 10.0) + (0.5 if has_kev else 0.0) + max_epss
    elif objective == Objective.LOSS_PER_INR:
        if device.id not in losses.device_ids:
            return 0.0
        dev_idx = losses.device_ids.index(device.id)
        mean_loss = float(np.mean(losses.device_loss[:, dev_idx]))
        patch_opt = next((c for c in device.controls if c.kind == ControlKind.PATCH), None)
        target_opt = patch_opt if patch_opt is not None else (device.controls[0] if device.controls else None)
        if target_opt is None:
            return 0.0
        r = reduction(city, device.id, target_opt.kind)
        return (mean_loss * r) / target_opt.cost_inr if target_opt.cost_inr > 0 else (mean_loss * r * 1e6)
    elif objective == Objective.BFS_CENTRALITY:
        return bfs_scores.get(device.id, 0.0)
    return 0.0


def rank_and_buy(
    city: City,
    losses: ScenarioLosses,
    budget: Budget,
    objective: Objective,
    constraints: list[Constraint] | None = None,
) -> Plan:
    """Build the baseline plan for one of ``BASELINES`` with ``solver=Solver.RANKING``."""
    t0 = time.perf_counter()
    constraints = constraints or []

    no_downtime_zones = {
        str(c.params["zone"])
        for c in constraints
        if c.kind == ConstraintKind.NO_DOWNTIME_ZONE and "zone" in c.params
    }
    forbidden_kinds = {
        c.params["kind"].value if hasattr(c.params["kind"], "value") else str(c.params["kind"])
        for c in constraints
        if c.kind == ConstraintKind.FORBID_CONTROL and "kind" in c.params
    }
    must_fix_ids = [
        str(c.params["device_id"])
        for c in constraints
        if c.kind == ConstraintKind.MUST_FIX and "device_id" in c.params
    ]

    bfs_scores = _reach_centrality(city) if objective == Objective.BFS_CENTRALITY else {}
    device_scores = {d.id: _score_device(objective, d, losses, city, bfs_scores) for d in city.devices}

    # Deterministic ranking: highest score first, tie-break by device id
    ranked_devices = sorted(city.devices, key=lambda d: (-device_scores[d.id], d.id))

    # Prioritize must-fix devices if any
    must_fix_set = set(must_fix_ids)
    ordered_devices = [d for d in ranked_devices if d.id in must_fix_set] + [
        d for d in ranked_devices if d.id not in must_fix_set
    ]

    choices: dict[str, ControlKind] = {}
    rem_cost = budget.inr
    rem_dt = budget.downtime_h

    for dev in ordered_devices:
        valid_controls = [
            c
            for c in dev.controls
            if (c.kind.value if hasattr(c.kind, "value") else str(c.kind)) not in forbidden_kinds
            and not (dev.zone in no_downtime_zones and c.downtime_h > 0)
        ]
        if not valid_controls:
            continue

        patch_opt = next((c for c in valid_controls if c.kind == ControlKind.PATCH), None)
        chosen_opt = None
        if patch_opt is not None and rem_cost >= patch_opt.cost_inr and rem_dt >= patch_opt.downtime_h:
            chosen_opt = patch_opt
        else:
            # Fallback to cheapest feasible option
            cheapest = min(valid_controls, key=lambda c: (c.cost_inr, c.downtime_h))
            if rem_cost >= cheapest.cost_inr and rem_dt >= cheapest.downtime_h:
                chosen_opt = cheapest

        if chosen_opt is not None:
            choices[dev.id] = chosen_opt.kind
            rem_cost -= chosen_opt.cost_inr
            rem_dt -= chosen_opt.downtime_h

    solve_ms = int((time.perf_counter() - t0) * 1000)
    total_cost = budget.inr - rem_cost
    total_dt = float(budget.downtime_h - rem_dt)

    return Plan(
        id=_make_plan_id(objective, choices),
        city_id=city.id,
        objective=objective,
        choices=choices,
        cost_inr=total_cost,
        downtime_h=total_dt,
        solver=Solver.RANKING,
        solve_ms=solve_ms,
    )
