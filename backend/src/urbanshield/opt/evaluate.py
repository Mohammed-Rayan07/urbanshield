"""Fair evaluation on held-out scenarios. Owner: B.

Plans are optimised on a *train* scenario set (seed ``train_seed``) and scored on a
fresh *test* set (seed ``test_seed``) by re-running the full simulator with the plan's
controls applied, so the additive-loss approximation is checked, not trusted.
"""

from __future__ import annotations

from urbanshield.schemas import Budget, City, Constraint, Plan, PlanMetrics

TRAIN_SEED = 1
TEST_SEED = 2


def evaluate_plan(
    city: City,
    plan: Plan,
    alpha: float,
    n_scenarios: int = 2000,
    seed: int = TEST_SEED,
    n_bootstrap: int = 500,
) -> PlanMetrics:
    """Simulate with ``plan.choices`` applied; return CVaR, mean, max cascade, bootstrap
    95% CI on CVaR, and the linear-vs-simulated gap."""
    raise NotImplementedError


def compare(
    city: City,
    budget: Budget,
    constraints: list[Constraint] | None = None,
    n_scenarios: int = 2000,
) -> list[Plan]:
    """Every objective (CVaR, both ablations, greedy tail, all baselines) under the same
    budget and constraints, each with test-set ``metrics`` filled in, CVaR plan first."""
    raise NotImplementedError
