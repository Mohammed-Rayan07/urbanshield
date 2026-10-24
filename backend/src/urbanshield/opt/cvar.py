"""CVaR-minimising remediation plan as a MILP (Rockafellar-Uryasev). Owner: B.

    minimise   t + 1 / ((1 - alpha) * S) * sum_s z_s
    subject to z_s >= L_s(x) - t,  z_s >= 0
               sum c_ik x_ik <= Budget,  sum d_ik x_ik <= Window,  sum_k x_ik <= 1
               + constraints (zones, must-fix, forbidden controls)

Solve with PuLP + CBC. Warm-start from ``greedy_tail``; if CBC exceeds
``time_limit_s``, return the greedy plan with ``solver=Solver.GREEDY`` (the UI shows
which solver ran). ``objective=MEAN`` minimises expected loss with the same
constraints (ablation). ``patch_only=True`` restricts to PATCH (ablation).
"""

import hashlib
import time

import numpy as np
import pulp

from urbanshield.opt.common import reduction, tail_size
from urbanshield.opt.greedy import greedy_tail
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


def solve(
    city: City,
    losses: ScenarioLosses,
    budget: Budget,
    constraints: list[Constraint] | None = None,
    objective: Objective = Objective.CVAR,
    time_limit_s: float = 30.0,
) -> Plan:
    """Return the optimal (or fallback) plan. ``objective`` is CVAR, MEAN or PATCH_ONLY."""
    t0 = time.perf_counter()
    constraints = list(constraints or [])

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

    # Warm-start using greedy heuristic
    greedy_constraints = list(constraints)
    if objective == Objective.PATCH_ONLY:
        for k in ControlKind:
            if k != ControlKind.PATCH:
                greedy_constraints.append(Constraint(kind=ConstraintKind.FORBID_CONTROL, params={"kind": k}))
    greedy_plan = greedy_tail(city, losses, budget, greedy_constraints)

    prob = pulp.LpProblem("urbanshield_remediation", pulp.LpMinimize)

    # Decision variables x_{i, k} in {0, 1}
    x_vars: dict[tuple[str, ControlKind], pulp.LpVariable] = {}
    saved_loss: dict[tuple[str, ControlKind], np.ndarray] = {}
    cost_map: dict[tuple[str, ControlKind], int] = {}
    dt_map: dict[tuple[str, ControlKind], float] = {}

    dev_idx_map = {did: idx for idx, did in enumerate(losses.device_ids)}

    for dev in city.devices:
        for opt in dev.controls:
            if objective == Objective.PATCH_ONLY and opt.kind != ControlKind.PATCH:
                continue
            kind_str = opt.kind.value if hasattr(opt.kind, "value") else str(opt.kind)
            if kind_str in forbidden_kinds:
                continue
            if dev.zone in no_downtime_zones and opt.downtime_h > 0:
                continue

            var_name = f"x_{dev.id}_{kind_str}"
            var = pulp.LpVariable(var_name, cat=pulp.LpBinary)

            # Set warm-start value from greedy
            if greedy_plan.choices.get(dev.id) == opt.kind:
                var.setInitialValue(1)
            else:
                var.setInitialValue(0)

            x_vars[(dev.id, opt.kind)] = var
            cost_map[(dev.id, opt.kind)] = opt.cost_inr
            dt_map[(dev.id, opt.kind)] = float(opt.downtime_h)

            col = dev_idx_map.get(dev.id)
            if col is not None:
                r = reduction(city, dev.id, opt.kind)
                saved_loss[(dev.id, opt.kind)] = losses.device_loss[:, col] * r
            else:
                saved_loss[(dev.id, opt.kind)] = np.zeros(losses.n_scenarios, dtype=float)

    # Constraint: at most one option per device
    for dev in city.devices:
        dev_vars = [var for (d_id, _), var in x_vars.items() if d_id == dev.id]
        if dev_vars:
            prob += pulp.lpSum(dev_vars) <= 1, f"one_control_{dev.id}"

    # Constraint: MUST_FIX
    for must_id in must_fix_ids:
        must_vars = [var for (d_id, _), var in x_vars.items() if d_id == must_id]
        if must_vars:
            prob += pulp.lpSum(must_vars) >= 1, f"must_fix_{must_id}"

    # Constraint: budget (INR)
    prob += (
        pulp.lpSum(cost_map[key] * var for key, var in x_vars.items()) <= budget.inr,
        "budget_inr",
    )

    # Constraint: downtime (hours)
    prob += (
        pulp.lpSum(dt_map[key] * var for key, var in x_vars.items()) <= budget.downtime_h,
        "budget_downtime",
    )

    # Objective formulation
    n_scen = losses.n_scenarios
    if objective == Objective.MEAN:
        # Minimise expected loss: sum_s L_s(x) / S
        # Constant sum_s base_loss[s] omitted; minimise - sum_{i,k} (mean_saved_{i,k} * x_{i,k})
        mean_saved = {key: float(np.mean(saved_loss[key])) for key in x_vars}
        prob += (
            pulp.lpSum(-mean_saved[key] * var for key, var in x_vars.items()),
            "mean_loss_objective",
        )
    else:
        # CVaR (or PATCH_ONLY CVaR)
        k_tail = tail_size(n_scen, budget.alpha)
        t_var = pulp.LpVariable("t", cat=pulp.LpContinuous)
        z_vars = [pulp.LpVariable(f"z_{s}", lowBound=0, cat=pulp.LpContinuous) for s in range(n_scen)]

        prob += t_var + (1.0 / k_tail) * pulp.lpSum(z_vars), "cvar_objective"

        # z_s >= L_s(x) - t <=> z_s + t + sum_{i,k} saved_{i,k}[s] * x_{i,k} >= base_loss[s]
        base_losses = losses.total
        for s in range(n_scen):
            scen_terms = [
                saved_loss[key][s] * var for key, var in x_vars.items() if saved_loss[key][s] > 1e-9
            ]
            prob += (
                z_vars[s] + t_var + pulp.lpSum(scen_terms) >= float(base_losses[s]),
                f"cvar_tail_{s}",
            )

    solver = pulp.PULP_CBC_CMD(msg=False, timeLimit=time_limit_s, warmStart=True)
    status = prob.solve(solver)

    # Check status and extract solution
    is_optimal = status == pulp.constants.LpStatusOptimal or status == 1
    has_incumbent = any(var.varValue is not None and var.varValue > 0.5 for var in x_vars.values())

    if is_optimal or has_incumbent:
        choices = {}
        total_cost = 0
        total_dt = 0.0
        for (dev_id, kind), var in x_vars.items():
            if var.varValue is not None and var.varValue > 0.5:
                choices[dev_id] = kind
                total_cost += cost_map[(dev_id, kind)]
                total_dt += dt_map[(dev_id, kind)]

        solve_ms = int((time.perf_counter() - t0) * 1000)
        return Plan(
            id=_make_plan_id(objective, choices),
            city_id=city.id,
            objective=objective,
            choices=choices,
            cost_inr=total_cost,
            downtime_h=float(total_dt),
            solver=Solver.MILP,
            solve_ms=solve_ms,
        )
    else:
        # Fallback to greedy
        solve_ms = int((time.perf_counter() - t0) * 1000)
        return Plan(
            id=_make_plan_id(objective, greedy_plan.choices),
            city_id=city.id,
            objective=objective,
            choices=greedy_plan.choices,
            cost_inr=greedy_plan.cost_inr,
            downtime_h=greedy_plan.downtime_h,
            solver=Solver.GREEDY,
            solve_ms=solve_ms,
        )
