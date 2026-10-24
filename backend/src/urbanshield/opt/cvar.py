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

from __future__ import annotations

from urbanshield.schemas import Budget, City, Constraint, Objective, Plan, ScenarioLosses


def solve(
    city: City,
    losses: ScenarioLosses,
    budget: Budget,
    constraints: list[Constraint] | None = None,
    objective: Objective = Objective.CVAR,
    time_limit_s: float = 30.0,
) -> Plan:
    """Return the optimal (or fallback) plan. ``objective`` is CVAR, MEAN or PATCH_ONLY."""
    raise NotImplementedError
