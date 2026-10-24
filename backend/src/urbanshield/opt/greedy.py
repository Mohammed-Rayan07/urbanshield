"""Greedy tail heuristic: a baseline and the MILP's fallback. Owner: B.

Repeatedly buy the (device, control) pair with the largest CVaR reduction per rupee
until nothing affordable improves CVaR. Uses the same linear loss model as the MILP,
so it can scale to thousands of devices where CBC cannot.
"""

import hashlib
import time

import numpy as np

from urbanshield.opt.common import cvar, reduction, tail_size
from urbanshield.schemas import (
    Budget,
    City,
    Constraint,
    ConstraintKind,
    ControlKind,
    Objective,
    Plan,
    ScenarioLosses,
    Solver,
)


def _make_plan_id(objective: Objective, choices: dict[str, ControlKind]) -> str:
    sorted_items = sorted(
        (dev_id, kind.value if hasattr(kind, "value") else str(kind)) for dev_id, kind in choices.items()
    )
    repr_str = ",".join(f"{k}:{v}" for k, v in sorted_items)
    h = hashlib.sha256(repr_str.encode()).hexdigest()[:8]
    obj_str = objective.value if hasattr(objective, "value") else str(objective)
    return f"plan-{obj_str}-{h}"


def greedy_tail(
    city: City,
    losses: ScenarioLosses,
    budget: Budget,
    constraints: list[Constraint] | None = None,
) -> Plan:
    """Return a feasible plan with ``objective=GREEDY_TAIL`` and ``solver=Solver.GREEDY``."""
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

    # Precompute device indices and valid options
    dev_idx_map = {did: idx for idx, did in enumerate(losses.device_ids)}

    # Precompute saved loss vectors for all valid device-control options
    # saved_loss[(dev_id, kind)] = device_loss[:, col] * r
    valid_options: dict[str, list] = {}
    saved_loss: dict[tuple[str, ControlKind], np.ndarray] = {}
    cost_map: dict[tuple[str, ControlKind], int] = {}
    dt_map: dict[tuple[str, ControlKind], float] = {}

    for d in city.devices:
        v_opts = []
        for opt in d.controls:
            kind_str = opt.kind.value if hasattr(opt.kind, "value") else str(opt.kind)
            if kind_str in forbidden_kinds:
                continue
            if d.zone in no_downtime_zones and opt.downtime_h > 0:
                continue
            v_opts.append(opt)
            col = dev_idx_map.get(d.id)
            if col is not None:
                r = reduction(city, d.id, opt.kind)
                saved_loss[(d.id, opt.kind)] = losses.device_loss[:, col] * r
            else:
                saved_loss[(d.id, opt.kind)] = np.zeros(losses.n_scenarios, dtype=float)
            cost_map[(d.id, opt.kind)] = opt.cost_inr
            dt_map[(d.id, opt.kind)] = float(opt.downtime_h)
        valid_options[d.id] = v_opts

    choices: dict[str, ControlKind] = {}
    current_cost = 0
    current_dt = 0.0

    # Initialize current scenario loss vector: additive sum of all device losses
    current_loss = losses.total.copy()

    # Pre-satisfy MUST_FIX constraints with the cheapest valid control
    for must_id in must_fix_ids:
        if must_id in choices or must_id not in valid_options or not valid_options[must_id]:
            continue
        cheapest_opt = min(valid_options[must_id], key=lambda c: (c.cost_inr, c.downtime_h))
        if (
            current_cost + cheapest_opt.cost_inr <= budget.inr
            and current_dt + cheapest_opt.downtime_h <= budget.downtime_h
        ):
            choices[must_id] = cheapest_opt.kind
            current_cost += cheapest_opt.cost_inr
            current_dt += cheapest_opt.downtime_h
            current_loss -= saved_loss[(must_id, cheapest_opt.kind)]

    current_cvar = cvar(current_loss, budget.alpha)

    # Iterative greedy search
    k_tail = tail_size(losses.n_scenarios, budget.alpha)

    while True:
        best_move = None
        best_metric = 0.0
        best_cvar_drop = 0.0
        best_new_loss = None
        best_d_cost = 0
        best_d_dt = 0.0

        # Exact pruning: only devices that have loss in the tail can reduce CVaR
        tail_idx = np.argpartition(current_loss, current_loss.size - k_tail)[-k_tail:]

        for dev_id, options in valid_options.items():
            curr_kind = choices.get(dev_id)
            curr_saved = saved_loss[(dev_id, curr_kind)] if curr_kind is not None else 0.0
            curr_c = cost_map[(dev_id, curr_kind)] if curr_kind is not None else 0
            curr_d = dt_map[(dev_id, curr_kind)] if curr_kind is not None else 0.0

            for opt in options:
                if opt.kind == curr_kind:
                    continue
                d_cost = opt.cost_inr - curr_c
                d_dt = opt.downtime_h - curr_d

                if current_cost + d_cost > budget.inr:
                    continue
                if current_dt + d_dt > budget.downtime_h:
                    continue

                new_saved = saved_loss[(dev_id, opt.kind)]
                diff = new_saved - curr_saved

                # Exact mathematical filter: if no reduction in any tail scenario, drop is <= 0
                if not np.any(diff[tail_idx] > 0):
                    continue

                # Compute new scenario loss
                cand_loss = current_loss - diff
                cand_cvar = cvar(cand_loss, budget.alpha)
                cvar_drop = current_cvar - cand_cvar

                if cvar_drop <= 1e-9:
                    continue

                metric = cvar_drop / d_cost if d_cost > 0 else cvar_drop * 1e6

                if metric > best_metric:
                    best_metric = metric
                    best_cvar_drop = cvar_drop
                    best_move = (dev_id, opt.kind)
                    best_new_loss = cand_loss
                    best_d_cost = d_cost
                    best_d_dt = d_dt

        if best_move is None or best_new_loss is None:
            break

        dev_id, new_kind = best_move
        choices[dev_id] = new_kind
        current_loss = best_new_loss
        current_cvar -= best_cvar_drop
        current_cost += best_d_cost
        current_dt += best_d_dt

    solve_ms = int((time.perf_counter() - t0) * 1000)

    return Plan(
        id=_make_plan_id(Objective.GREEDY_TAIL, choices),
        city_id=city.id,
        objective=Objective.GREEDY_TAIL,
        choices=choices,
        cost_inr=current_cost,
        downtime_h=float(current_dt),
        solver=Solver.GREEDY,
        solve_ms=solve_ms,
    )
