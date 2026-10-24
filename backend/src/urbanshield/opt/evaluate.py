"""Fair evaluation on held-out scenarios. Owner: B.

Plans are optimised on a *train* scenario set (seed ``train_seed``) and scored on a
fresh *test* set (seed ``test_seed``) by re-running the full simulator with the plan's
controls applied, so the planner's additive-savings model is checked, not trusted
(``linear_gap``).
"""

from __future__ import annotations

import numpy as np

from urbanshield.opt._model import option_table
from urbanshield.opt.baselines import BASELINES, rank_and_buy
from urbanshield.opt.common import cvar, tail_size
from urbanshield.opt.cvar import solve
from urbanshield.opt.greedy import greedy_tail
from urbanshield.schemas import (
    Budget,
    City,
    Constraint,
    Objective,
    Plan,
    PlanMetrics,
    ScenarioLosses,
)
from urbanshield.sim import montecarlo

TRAIN_SEED = 1
TEST_SEED = 2


def predicted_cvar(city: City, baseline: ScenarioLosses, plan: Plan, alpha: float) -> float:
    """CVaR the planner's model predicts for ``plan`` on ``baseline`` (uncontrolled) scenarios."""
    table = option_table(city, baseline, [])
    column = {key: j for j, key in enumerate(table.keys)}
    picked = [column[(d, k)] for d, k in plan.choices.items()]
    return cvar(table.base - table.saved[:, picked].sum(axis=1), alpha)


def _bootstrap_cvar(totals: np.ndarray, alpha: float, n_bootstrap: int, seed: int) -> np.ndarray:
    n = totals.size
    rng = np.random.default_rng(seed)
    samples = totals[rng.integers(0, n, size=(n_bootstrap, n))]
    k = tail_size(n, alpha)
    if k >= n:
        return samples.mean(axis=1)
    return np.partition(samples, n - k, axis=1)[:, -k:].mean(axis=1)


def evaluate_plan(
    city: City,
    plan: Plan,
    alpha: float,
    n_scenarios: int = 2000,
    seed: int = TEST_SEED,
    n_bootstrap: int = 500,
    baseline: ScenarioLosses | None = None,
) -> PlanMetrics:
    """Simulate with ``plan.choices`` applied; return CVaR, mean, max cascade, bootstrap
    95% CI on CVaR, and the predicted-vs-simulated gap. ``baseline`` is the uncontrolled
    run on the same seed, if the caller already has it (``compare`` shares one)."""
    simulated = montecarlo.simulate(city, n_scenarios=n_scenarios, seed=seed, controls=plan.choices)
    totals = simulated.total
    cvar_sim = cvar(totals, alpha)
    boot = _bootstrap_cvar(totals, alpha, n_bootstrap, seed)

    if baseline is None:
        baseline = montecarlo.simulate(city, n_scenarios=n_scenarios, seed=seed)
    predicted = predicted_cvar(city, baseline, plan, alpha)

    return PlanMetrics(
        cvar=cvar_sim,
        mean_loss=float(totals.mean()),
        max_cascade=int(simulated.compromised.sum(axis=1).max()) if simulated.compromised.size else 0,
        ci_low=float(min(np.percentile(boot, 2.5), cvar_sim)),
        ci_high=float(max(np.percentile(boot, 97.5), cvar_sim)),
        linear_gap=float((predicted - cvar_sim) / cvar_sim) if cvar_sim > 0 else 0.0,
        split="test",
    )


def compare(
    city: City,
    budget: Budget,
    constraints: list[Constraint] | None = None,
    n_scenarios: int = 2000,
) -> list[Plan]:
    """Every objective (CVaR, both ablations, greedy tail, all baselines) under the same
    budget and constraints, each with test-set ``metrics`` filled in, CVaR plan first."""
    constraints = list(constraints or [])
    train = montecarlo.simulate(city, n_scenarios=n_scenarios, seed=TRAIN_SEED)
    plans = [
        solve(city, train, budget, constraints, objective=Objective.CVAR),
        solve(city, train, budget, constraints, objective=Objective.MEAN),
        solve(city, train, budget, constraints, objective=Objective.PATCH_ONLY),
        greedy_tail(city, train, budget, constraints),
        *(rank_and_buy(city, train, budget, o, constraints) for o in BASELINES),
    ]
    test = montecarlo.simulate(city, n_scenarios=n_scenarios, seed=TEST_SEED)
    return [
        p.model_copy(
            update={
                "metrics": evaluate_plan(
                    city, p, budget.alpha, n_scenarios=n_scenarios, seed=TEST_SEED, baseline=test
                )
            }
        )
        for p in plans
    ]
