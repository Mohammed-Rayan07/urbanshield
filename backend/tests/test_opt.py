"""Optimiser, baselines and evaluation. Owner: B.

These check properties that must hold for ANY correct implementation. Whether CVaR
beats CVSS-first on the demo city is an empirical result: it goes in docs/EVALS.md,
not in CI.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from urbanshield.opt.baselines import BASELINES, rank_and_buy
from urbanshield.opt.common import cvar, is_feasible
from urbanshield.opt.cvar import solve
from urbanshield.opt.evaluate import compare
from urbanshield.opt.greedy import greedy_tail
from urbanshield.schemas import (
    Budget,
    Constraint,
    ConstraintKind,
    ControlKind,
    Objective,
    ScenarioLosses,
    Solver,
)


def test_cvar_definition() -> None:
    losses = np.arange(100, dtype=float)  # 0..99
    assert cvar(losses, 0.95) == pytest.approx(np.mean([95, 96, 97, 98, 99]))
    assert cvar(losses, 0.90) == pytest.approx(94.5)
    rng = np.random.default_rng(0)
    x = rng.exponential(size=1000)
    assert cvar(x, 0.95) >= x.mean()


@pytest.fixture
def losses(tiny_city) -> ScenarioLosses:
    rng = np.random.default_rng(0)
    s, n = 400, len(tiny_city.devices)
    loss = rng.exponential(0.5, size=(s, n)) * (rng.random((s, n)) < 0.3)
    loss[:20, 3:5] += 5.0  # a fat tail on the corridor signals
    return ScenarioLosses(
        city_id="tiny",
        seed=0,
        device_ids=tuple(d.id for d in tiny_city.devices),
        device_loss=loss,
        compromised=loss > 0,
        campaign_cve=(None,) * s,
    )


def _linear_cvar(city, losses: ScenarioLosses, plan, alpha: float) -> float:
    from urbanshield.opt.common import reduction

    scale = np.ones(len(city.devices))
    for dev_id, kind in plan.choices.items():
        scale[losses.device_ids.index(dev_id)] -= reduction(city, dev_id, kind)
    return cvar(losses.device_loss @ scale, alpha)


ALL_PLANNERS = [
    ("cvar", lambda c, sl, b, k: solve(c, sl, b, k, Objective.CVAR)),
    ("mean", lambda c, sl, b, k: solve(c, sl, b, k, Objective.MEAN)),
    ("patch_only", lambda c, sl, b, k: solve(c, sl, b, k, Objective.PATCH_ONLY)),
    ("greedy", lambda c, sl, b, k: greedy_tail(c, sl, b, k)),
    *[(o.value, lambda c, sl, b, k, o=o: rank_and_buy(c, sl, b, o, k)) for o in BASELINES],
]


@pytest.mark.parametrize(("name", "planner"), ALL_PLANNERS, ids=[p[0] for p in ALL_PLANNERS])
def test_every_planner_is_feasible(name, planner, tiny_city, losses, tiny_budget) -> None:
    constraints = [Constraint(kind=ConstraintKind.NO_DOWNTIME_ZONE, params={"zone": "Z1"})]
    plan = planner(tiny_city, losses, tiny_budget, constraints)
    assert is_feasible(tiny_city, plan, tiny_budget, constraints)
    assert plan.cost_inr <= tiny_budget.inr
    z1 = {d.id for d in tiny_city.devices if d.zone == "Z1"}
    for dev_id, kind in plan.choices.items():
        option = next(c for c in tiny_city.device(dev_id).controls if c.kind == kind)
        assert not (dev_id in z1 and option.downtime_h > 0)


def test_milp_beats_or_ties_greedy_on_its_own_objective(tiny_city, losses, tiny_budget) -> None:
    exact = solve(tiny_city, losses, tiny_budget, objective=Objective.CVAR)
    heuristic = greedy_tail(tiny_city, losses, tiny_budget)
    assert exact.solver == Solver.MILP
    a = _linear_cvar(tiny_city, losses, exact, tiny_budget.alpha)
    b = _linear_cvar(tiny_city, losses, heuristic, tiny_budget.alpha)
    assert a <= b + 1e-6


def test_ablations(tiny_city, losses, tiny_budget) -> None:
    patch_only = solve(tiny_city, losses, tiny_budget, objective=Objective.PATCH_ONLY)
    assert set(patch_only.choices.values()) <= {ControlKind.PATCH}
    full = solve(tiny_city, losses, tiny_budget, objective=Objective.CVAR)
    assert (
        _linear_cvar(tiny_city, losses, full, 0.95)
        <= _linear_cvar(tiny_city, losses, patch_only, 0.95) + 1e-6
    )


def test_must_fix_and_forbid(tiny_city, losses, tiny_budget) -> None:
    constraints = [
        Constraint(kind=ConstraintKind.MUST_FIX, params={"device_id": "d-006"}),
        Constraint(kind=ConstraintKind.FORBID_CONTROL, params={"kind": "segment"}),
    ]
    plan = solve(tiny_city, losses, tiny_budget, constraints)
    assert "d-006" in plan.choices
    assert ControlKind.SEGMENT not in plan.choices.values()


def test_time_limited_milp_is_never_worse_than_greedy(tiny_city, losses, tiny_budget) -> None:
    rushed = solve(tiny_city, losses, tiny_budget, objective=Objective.CVAR, time_limit_s=1e-3)
    heuristic = greedy_tail(tiny_city, losses, tiny_budget)
    assert is_feasible(tiny_city, rushed, tiny_budget)
    a = _linear_cvar(tiny_city, losses, rushed, tiny_budget.alpha)
    assert a <= _linear_cvar(tiny_city, losses, heuristic, tiny_budget.alpha) + 1e-6


@pytest.mark.slow
def test_compare_runs_everything() -> None:
    from urbanshield.city.generator import generate_city

    city = generate_city(seed=7)
    plans = compare(city, Budget(inr=600_000, downtime_h=24), n_scenarios=500)
    assert plans[0].objective == Objective.CVAR
    assert {p.objective for p in plans} == set(Objective)
    for p in plans:
        assert p.metrics is not None and p.metrics.split == "test"
        assert p.metrics.ci_low <= p.metrics.cvar <= p.metrics.ci_high
        assert math.isfinite(p.metrics.linear_gap)
