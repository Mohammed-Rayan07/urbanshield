"""Red-Team agent: adversarial verification of the chosen plan. Owner: C.

Given plan P, propose up to 5 ``Strategy`` values. Each one generates attack scenarios
with ``sim.simulate(strategy=...)``; those are added to the evaluation set and P's CVaR
is recomputed. A **hole** means adding a strategy's scenarios raises P's CVaR by more
than ``HOLE_THRESHOLD`` (not "some scenario exceeds CVaR"; tail scenarios always do).
Holes go back to the Planner, which re-solves on the augmented set.

Outcome-verification metric: simulator calls needed to find a hole, Red-Team vs
``random_search`` over the same strategy menu with the same call budget.
"""

from __future__ import annotations

from urbanshield.schemas import City, Hole, Plan, Strategy

HOLE_THRESHOLD = 0.05
MAX_STRATEGIES = 5


def propose_strategies(city: City, plan: Plan, run_id: str) -> list[Strategy]:
    raise NotImplementedError


def probe(city: City, plan: Plan, strategies: list[Strategy]) -> list[Hole]:
    raise NotImplementedError


def random_search(city: City, plan: Plan, budget_calls: int, seed: int = 0) -> list[Hole]:
    """Baseline for the Red-Team: random strategies from the same menu."""
    raise NotImplementedError
