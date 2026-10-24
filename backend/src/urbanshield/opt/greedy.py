"""Greedy tail heuristic: a baseline and the MILP's fallback. Owner: B.

Repeatedly buy the (device, control) pair with the largest CVaR reduction per rupee
until nothing affordable improves CVaR. Uses the same linear loss model as the MILP,
so it can scale to thousands of devices where CBC cannot.
"""

from __future__ import annotations

from urbanshield.schemas import Budget, City, Constraint, Plan, ScenarioLosses


def greedy_tail(
    city: City,
    losses: ScenarioLosses,
    budget: Budget,
    constraints: list[Constraint] | None = None,
) -> Plan:
    """Return a feasible plan with ``objective=GREEDY_TAIL`` and ``solver=Solver.GREEDY``."""
    raise NotImplementedError
