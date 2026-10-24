"""Simulated risk for the dashboard: where the worst-case loss comes from. Owner: C.

One held-out simulation per view (no controls, then each compared plan), on the evaluator's
test seed, so every number here matches the CVaR the plans table reports for the same controls.
"""

from __future__ import annotations

import numpy as np

from urbanshield.agents.engine import Engine
from urbanshield.opt.common import tail_size
from urbanshield.schemas import City, CityRisk, DeviceRisk, LossHistogram, Plan, ScenarioLosses

BINS = 48
HISTOGRAM_PLANS = ("cvss", "bfs_centrality", "cvar")  # the three the dashboard puts side by side


def _tail(losses: ScenarioLosses, alpha: float) -> np.ndarray:
    total = losses.total
    k = tail_size(len(total), alpha)
    return np.argsort(total, kind="stable")[-k:]


def device_risk(losses: ScenarioLosses, alpha: float) -> list[DeviceRisk]:
    tail = _tail(losses, alpha)
    mean = losses.device_loss.mean(axis=0)
    tail_mean = losses.device_loss[tail].mean(axis=0)
    p = losses.compromised.mean(axis=0)
    return [
        DeviceRisk(
            device_id=d,
            mean_loss=round(float(mean[i]), 4),
            tail_loss=round(float(tail_mean[i]), 4),
            p_compromised=round(float(p[i]), 4),
        )
        for i, d in enumerate(losses.device_ids)
    ]


def city_risk(engine: Engine, city: City, plans: list[Plan], n_scenarios: int, alpha: float) -> CityRisk:
    def run(choices: dict) -> ScenarioLosses:
        return engine.controlled(city, choices, n_scenarios=n_scenarios, seed=engine.test_seed)

    by_objective = {p.objective.value: p for p in plans}
    views: list[tuple[str, Plan | None, ScenarioLosses]] = [("none", None, run({}))]
    views += [
        (o, by_objective[o], run(dict(by_objective[o].choices))) for o in HISTOGRAM_PLANS if o in by_objective
    ]
    top = max(float(v[2].total.max()) for v in views)
    edges = np.linspace(0.0, top if top > 0 else 1.0, BINS + 1)
    histograms = []
    for label, plan, losses in views:
        total = losses.total
        tail = _tail(losses, alpha)
        counts, _ = np.histogram(total, bins=edges)
        histograms.append(
            LossHistogram(
                label=label,
                plan_id=plan.id if plan else None,
                cvar=round(float(engine.cvar(total, alpha)), 4),
                var=round(float(total[tail].min()), 4),
                mean_loss=round(float(total.mean()), 4),
                counts=[int(c) for c in counts],
            )
        )
    protected = next((v[2] for v in views if v[0] == "cvar"), views[0][2])
    return CityRisk(
        city_id=city.id,
        n_scenarios=n_scenarios,
        alpha=alpha,
        bin_edges=[round(float(e), 4) for e in edges],
        baseline=device_risk(views[0][2], alpha),
        protected=device_risk(protected, alpha),
        histograms=histograms,
    )
