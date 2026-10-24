"""Fair evaluation on held-out scenarios. Owner: B.

Plans are optimised on a *train* scenario set (seed ``train_seed``) and scored on a
fresh *test* set (seed ``test_seed``) by re-running the full simulator with the plan's
controls applied, so the additive-loss approximation is checked, not trusted.
"""

from __future__ import annotations

import numpy as np

from urbanshield.opt.baselines import rank_and_buy
from urbanshield.opt.common import cvar, reduction, tail_size
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


def _linear_cvar(city: City, losses: ScenarioLosses, plan: Plan, alpha: float) -> float:
    scale = np.ones(len(city.devices))
    for dev_id, kind in plan.choices.items():
        if dev_id in losses.device_ids:
            scale[losses.device_ids.index(dev_id)] -= reduction(city, dev_id, kind)
    return cvar(losses.device_loss @ scale, alpha)


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
    sim_losses = montecarlo.simulate(city, n_scenarios=n_scenarios, seed=seed, controls=plan.choices)
    simulated_totals = sim_losses.total

    cvar_sim = cvar(simulated_totals, alpha)
    mean_loss = float(np.mean(simulated_totals))
    max_cascade = int(sim_losses.compromised.sum(axis=1).max()) if sim_losses.compromised.size > 0 else 0

    # Bootstrap 95% CI on CVaR (500x)
    rng = np.random.default_rng(seed)
    boot_indices = rng.choice(n_scenarios, size=(n_bootstrap, n_scenarios), replace=True)
    boot_samples = simulated_totals[boot_indices]
    k_tail = tail_size(n_scenarios, alpha)
    if k_tail >= n_scenarios:
        boot_cvars = boot_samples.mean(axis=1)
    else:
        part = np.partition(boot_samples, n_scenarios - k_tail, axis=1)
        boot_cvars = part[:, -k_tail:].mean(axis=1)

    ci_low = float(min(np.percentile(boot_cvars, 2.5), cvar_sim))
    ci_high = float(max(np.percentile(boot_cvars, 97.5), cvar_sim))

    # Linear-vs-simulated gap on test set: (MILP-predicted cvar - simulated cvar) / simulated cvar
    uncontrolled_losses = montecarlo.simulate(city, n_scenarios=n_scenarios, seed=seed, controls=None)
    pred_cvar = _linear_cvar(city, uncontrolled_losses, plan, alpha)
    linear_gap = float((pred_cvar - cvar_sim) / cvar_sim) if cvar_sim > 0 else 0.0

    return PlanMetrics(
        cvar=cvar_sim,
        mean_loss=mean_loss,
        max_cascade=max_cascade,
        ci_low=ci_low,
        ci_high=ci_high,
        linear_gap=linear_gap,
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
    train_losses = montecarlo.simulate(city, n_scenarios=n_scenarios, seed=TRAIN_SEED)

    # 1. UrbanShield CVaR MILP
    cvar_plan = solve(city, train_losses, budget, constraints, objective=Objective.CVAR)

    # 2. Ablations
    mean_plan = solve(city, train_losses, budget, constraints, objective=Objective.MEAN)
    patch_only_plan = solve(city, train_losses, budget, constraints, objective=Objective.PATCH_ONLY)

    # 3. Greedy tail
    greedy_plan = greedy_tail(city, train_losses, budget, constraints)

    # 4. Baselines
    cvss_plan = rank_and_buy(city, train_losses, budget, Objective.CVSS, constraints)
    cvss_kev_epss_plan = rank_and_buy(city, train_losses, budget, Objective.CVSS_KEV_EPSS, constraints)
    loss_per_inr_plan = rank_and_buy(city, train_losses, budget, Objective.LOSS_PER_INR, constraints)
    bfs_plan = rank_and_buy(city, train_losses, budget, Objective.BFS_CENTRALITY, constraints)

    raw_plans = [
        cvar_plan,
        mean_plan,
        patch_only_plan,
        greedy_plan,
        cvss_plan,
        cvss_kev_epss_plan,
        loss_per_inr_plan,
        bfs_plan,
    ]

    evaluated_plans: list[Plan] = []
    for plan in raw_plans:
        metrics = evaluate_plan(
            city,
            plan,
            alpha=budget.alpha,
            n_scenarios=n_scenarios,
            seed=TEST_SEED,
        )
        evaluated_plans.append(plan.model_copy(update={"metrics": metrics}))

    return evaluated_plans
