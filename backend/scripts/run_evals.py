"""Regenerate sections 1 and 2 of docs/EVALS.md from the real pipeline. Owner: B.

    uv run python scripts/run_evals.py             # print the tables
    uv run python scripts/run_evals.py --write     # also rewrite docs/EVALS.md §1-2

Every number comes from ``opt.evaluate.compare``: plans are optimised on the train
scenarios and scored by the full simulator on held-out test scenarios.
"""

from __future__ import annotations

import argparse
import time

import numpy as np

from urbanshield.agents.evidence import replace_section
from urbanshield.city.generator import generate_city
from urbanshield.config import BACKEND_DIR, get_settings
from urbanshield.opt.evaluate import compare
from urbanshield.schemas import Budget, City, Objective, Plan

EVALS = BACKEND_DIR.parent / "docs" / "EVALS.md"
SENSITIVITY_SEEDS = (11, 23, 42, 89, 137)
N_SCENARIOS = 2000
N_SCENARIOS_SENSITIVITY = 1000


def _inr(value: int) -> str:
    """Indian digit grouping: 600000 -> 6,00,000."""
    head, tail = str(value)[:-3], str(value)[-3:]
    groups = []
    while len(head) > 2:
        groups.insert(0, head[-2:])
        head = head[:-2]
    return ",".join([g for g in [head, *groups] if g] + [tail])


def _cut(plan: Plan, other: Plan) -> float:
    """Percent by which ``plan`` lowers held-out CVaR versus ``other`` (positive = better)."""
    return 100.0 * (1.0 - plan.metrics.cvar / other.metrics.cvar) if other.metrics.cvar > 0 else 0.0


def plans_table(plans: list[Plan]) -> str:
    rows = [
        "| Objective | Cost (₹) | Downtime (h) | Test CVaR95 | 95% bootstrap CI | Mean loss | "
        "Max cascade | Model gap | Solver | Time (ms) |",
        "|---|---:|---:|---:|---|---:|---:|---:|---|---:|",
    ]
    for p in plans:
        m = p.metrics
        name = f"**{p.objective.value}**" if p.objective == Objective.CVAR else p.objective.value
        rows.append(
            f"| {name} | {_inr(p.cost_inr)} | {p.downtime_h:.1f} | {m.cvar:.2f} | "
            f"[{m.ci_low:.2f}, {m.ci_high:.2f}] | {m.mean_loss:.2f} | {m.max_cascade} | "
            f"{m.linear_gap:+.1%} | `{p.solver.value}` | {p.solve_ms} |"
        )
    return "\n".join(rows)


def headline(plans: list[Plan], budget: Budget, n_scenarios: int) -> str:
    by = {p.objective: p for p in plans}
    ours = by[Objective.CVAR]
    lines = [
        f"Same budget (₹{_inr(budget.inr)}, {budget.downtime_h:g} h downtime) and constraints for every "
        f"plan; CVaR95 measured on {n_scenarios:,} held-out scenarios.",
        "",
    ]
    for objective, label in (
        (Objective.CVSS, "CVSS-first"),
        (Objective.BFS_CENTRALITY, "BFS-only (reach centrality)"),
        (Objective.CVSS_KEV_EPSS, "CVSS + KEV + EPSS"),
        (Objective.MEAN, "mean-loss MILP (ablation)"),
        (Objective.PATCH_ONLY, "patch-only MILP (ablation)"),
        (Objective.GREEDY_TAIL, "greedy tail heuristic"),
    ):
        cut = _cut(ours, by[objective])
        lines.append(f"- vs {label}: **{abs(cut):.1f}% {'lower' if cut >= 0 else 'higher'}** worst-case loss")
    lines += [
        "",
        "_Model gap_ = (CVaR the planner's additive-savings model predicts on the test scenarios − "
        "simulated CVaR) / simulated CVaR. Negative means the model is optimistic (savings of "
        "controls that stop the same attack overlap); every number above is the simulated one.",
    ]
    return "\n".join(lines)


def perturbed(city: City, seed: int) -> City:
    """Costs and criticalities each scaled by an independent factor in [0.8, 1.2]."""
    rng = np.random.default_rng(seed)
    devices = []
    for d in city.devices:
        cost_factor, crit_factor = rng.uniform(0.8, 1.2, size=2)
        controls = [
            c.model_copy(update={"cost_inr": max(1, round(c.cost_inr * cost_factor))}) for c in d.controls
        ]
        criticality = float(np.clip(d.criticality * crit_factor, 0.0, 1.0))
        devices.append(d.model_copy(update={"controls": controls, "criticality": criticality}))
    return city.model_copy(update={"devices": devices})


def sensitivity(city: City, budget: Budget) -> str:
    rows = [
        "| Seed | CVaR plan | CVSS-first | BFS-only | Mean-loss | vs CVSS | vs BFS | vs mean "
        "| Beats both baselines |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    wins = 0
    for seed in SENSITIVITY_SEEDS:
        by = {
            p.objective: p
            for p in compare(perturbed(city, seed), budget, n_scenarios=N_SCENARIOS_SENSITIVITY)
        }
        ours, cvss, bfs, mean = (
            by[o] for o in (Objective.CVAR, Objective.CVSS, Objective.BFS_CENTRALITY, Objective.MEAN)
        )
        beats = ours.metrics.cvar < min(cvss.metrics.cvar, bfs.metrics.cvar)
        wins += beats
        rows.append(
            f"| {seed} | {ours.metrics.cvar:.2f} | {cvss.metrics.cvar:.2f} | {bfs.metrics.cvar:.2f} | "
            f"{mean.metrics.cvar:.2f} | {_cut(ours, cvss):+.1f}% | {_cut(ours, bfs):+.1f}% | "
            f"{_cut(ours, mean):+.1f}% | {'yes' if beats else '**no**'} |"
        )
    rows += [
        "",
        f"The CVaR plan beats both CVSS-first and BFS-only in **{wins} of {len(SENSITIVITY_SEEDS)}** "
        f"perturbed cities ({N_SCENARIOS_SENSITIVITY:,} held-out scenarios each). Every seed is "
        "reported, including losses.",
    ]
    return "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--write", action="store_true", help="rewrite docs/EVALS.md sections 1-2")
    args = parser.parse_args()

    settings = get_settings()
    city = generate_city(seed=settings.city_seed)
    budget = Budget(inr=settings.budget_inr, downtime_h=settings.downtime_h)
    started = time.perf_counter()
    plans = compare(city, budget, n_scenarios=N_SCENARIOS)
    section1 = f"{plans_table(plans)}\n\n{headline(plans, budget, N_SCENARIOS)}"
    print(section1, f"\n({time.perf_counter() - started:.1f}s)\n")
    section2 = sensitivity(city, budget)
    print(section2)
    if args.write:
        replace_section(EVALS, 1, section1)
        replace_section(EVALS, 2, section2)
        print(f"\nwrote {EVALS}")


if __name__ == "__main__":
    main()
