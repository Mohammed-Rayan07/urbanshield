"""Honest baselines: same budget, same downtime window, same constraints. Owner: B.

Each baseline ranks devices, then walks the ranking buying the device's *patch*
(or its cheapest feasible control if it has no patch) while it still fits.

- CVSS: highest max-CVSS first.
- CVSS_KEV_EPSS: score = max_cvss/10 + 0.5*kev + epss.
- LOSS_PER_INR: expected loss removed per rupee (uses ``losses``).
- BFS_CENTRALITY: most devices reachable (``graphs.reach_centrality``). This is the
  "why not just BFS?" baseline.
"""

from __future__ import annotations

from urbanshield.schemas import Budget, City, Constraint, Objective, Plan, ScenarioLosses

BASELINES = (
    Objective.CVSS,
    Objective.CVSS_KEV_EPSS,
    Objective.LOSS_PER_INR,
    Objective.BFS_CENTRALITY,
)


def rank_and_buy(
    city: City,
    losses: ScenarioLosses,
    budget: Budget,
    objective: Objective,
    constraints: list[Constraint] | None = None,
) -> Plan:
    """Build the baseline plan for one of ``BASELINES`` with ``solver=Solver.RANKING``."""
    raise NotImplementedError
