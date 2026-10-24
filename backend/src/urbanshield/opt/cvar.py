"""CVaR-minimising remediation plan as a MILP (Rockafellar-Uryasev). Owner: B.

    minimise   t + 1 / k * sum_s z_s                    (k = tail_size(S, alpha))
    subject to z_s >= L_s(x) - t,  z_s >= 0,  t >= 0
               L_s(x) = base_s - sum_j saved[s, j] * x_j
               sum c_j x_j <= Budget,  sum d_j x_j <= Window,  sum_{j of device i} x_j <= 1
               + constraints (zones, must-fix, forbidden controls; see ``_model``)

Solved with HiGHS through ``scipy.optimize.milp`` (bundled with SciPy: no external solver
binary). Scenarios with zero loss can never be in the tail, so they get no ``z`` variable.
If HiGHS hits ``time_limit_s`` it returns its best incumbent (``solver=Solver.MILP``); if it
has none, the greedy plan is returned with ``solver=Solver.GREEDY`` (the UI shows which
solver ran). ``objective=MEAN`` minimises expected loss with the same constraints
(ablation); ``objective=PATCH_ONLY`` is CVaR restricted to PATCH (ablation).
"""

from __future__ import annotations

import time

import numpy as np
from scipy import sparse
from scipy.optimize import Bounds, LinearConstraint, milp

from urbanshield.opt._model import OptionTable, effective_budget, must_fix, option_table, plan_id
from urbanshield.opt.common import tail_size
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

MIP_REL_GAP = 1e-6


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
    limits = effective_budget(budget, constraints)
    patch_only = objective == Objective.PATCH_ONLY
    table = option_table(city, losses, constraints, patch_only=patch_only)
    m = table.size

    # Rows shared by both objectives, over the x block only.
    one_per_device = sparse.csr_matrix(
        (np.ones(m), (table.device, np.arange(m))), shape=(len(city.devices), m)
    )
    rows = [
        LinearConstraint(table.cost[None, :], -np.inf, limits.inr),
        LinearConstraint(table.downtime[None, :], -np.inf, limits.downtime_h),
        LinearConstraint(one_per_device, -np.inf, 1.0),
    ]
    index = {d.id: i for i, d in enumerate(city.devices)}
    for device_id in must_fix(constraints):
        if device_id not in index:
            continue  # an unknown device can't be fixed; the plan is checked by is_feasible
        rows.append(LinearConstraint(one_per_device[index[device_id]], 1.0, np.inf))

    if objective == Objective.MEAN:
        c = -table.saved.mean(axis=0)
        n_extra = 0
    else:
        k = tail_size(losses.n_scenarios, limits.alpha)
        tail_rows = np.flatnonzero(table.base > 0)
        n_z = len(tail_rows)
        n_extra = 1 + n_z
        c = np.concatenate([np.zeros(m), [1.0], np.full(n_z, 1.0 / k)])
        # z_s + t + sum_j saved[s, j] x_j >= base_s
        tail = sparse.hstack(
            [
                sparse.csr_matrix(table.saved[tail_rows]),
                sparse.csr_matrix(np.ones((n_z, 1))),
                sparse.identity(n_z, format="csr"),
            ],
            format="csr",
        )
        rows = [_pad(r, n_extra) for r in rows]
        rows.append(LinearConstraint(tail, table.base[tail_rows], np.inf))

    integrality = np.concatenate([np.ones(m), np.zeros(n_extra)])
    upper = np.concatenate([np.ones(m), np.full(n_extra, np.inf)])
    result = milp(
        c,
        constraints=rows,
        integrality=integrality,
        bounds=Bounds(np.zeros(m + n_extra), upper),
        options={"time_limit": time_limit_s, "mip_rel_gap": MIP_REL_GAP, "disp": False},
    )

    if result.x is None:  # infeasible, or no incumbent before the time limit
        fallback = greedy_tail(city, losses, budget, _greedy_constraints(constraints, patch_only))
        return _plan(city, objective, fallback.choices, table, Solver.GREEDY, t0)
    chosen = np.flatnonzero(result.x[:m] > 0.5)
    choices = {table.keys[j][0]: table.keys[j][1] for j in chosen}
    return _plan(city, objective, choices, table, Solver.MILP, t0)


def _pad(row: LinearConstraint, n_extra: int) -> LinearConstraint:
    """Widen a constraint over the x block with zero columns for ``t`` and ``z``."""
    a = sparse.hstack([sparse.csr_matrix(row.A), sparse.csr_matrix((row.A.shape[0], n_extra))])
    return LinearConstraint(a.tocsr(), row.lb, row.ub)


def _greedy_constraints(constraints: list[Constraint], patch_only: bool) -> list[Constraint]:
    if not patch_only:
        return constraints
    return constraints + [
        Constraint(kind=ConstraintKind.FORBID_CONTROL, params={"kind": k.value})
        for k in ControlKind
        if k != ControlKind.PATCH
    ]


def _plan(
    city: City,
    objective: Objective,
    choices: dict[str, ControlKind],
    table: OptionTable,
    solver: Solver,
    t0: float,
) -> Plan:
    option = {(d.id, o.kind): o for d in city.devices for o in d.controls}
    picked = [option[(d, k)] for d, k in choices.items()]
    return Plan(
        id=plan_id(objective, choices),
        city_id=city.id,
        objective=objective,
        choices=choices,
        cost_inr=sum(o.cost_inr for o in picked),
        downtime_h=float(sum(o.downtime_h for o in picked)),
        solver=solver,
        solve_ms=int((time.perf_counter() - t0) * 1000),
    )
