"""Precompute the budget frontier for the dashboard slider (fixtures/frontier.json).

    uv run python scripts/build_frontier.py [--budgets 50000,100000,...]

Runs the same ``compare`` as ``GET /plans`` at each budget (held-out CVaR95 on the evaluator's test
seed) and keeps the planners the slider shows. Deterministic: fixed city seed and scenario seeds.
"""

from __future__ import annotations

import argparse
import json
import sys

from urbanshield.agents.engine import default_engine, engine_ready
from urbanshield.agents.tools import plan_brief
from urbanshield.api.frontier import FRONTIER_PATH, FRONTIER_PLANS, Frontier, FrontierPoint
from urbanshield.config import get_settings
from urbanshield.schemas import Budget

DEFAULT_BUDGETS = "50000,100000,150000,250000,400000,600000"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--budgets", default=DEFAULT_BUDGETS, help="comma-separated budgets in INR")
    args = parser.parse_args(argv)
    budgets = sorted({int(b) for b in args.budgets.split(",") if b.strip()})

    settings = get_settings()
    engine = default_engine()
    if not engine_ready(engine):
        print("The city and optimiser are not ready (engine not ready).", file=sys.stderr)
        return 2
    city = engine.generate_city(seed=settings.city_seed)
    points = []
    for inr in budgets:
        budget = Budget(inr=inr, downtime_h=settings.downtime_h)
        plans = engine.compare(city, budget, [], n_scenarios=settings.n_scenarios)
        by_objective = {p.objective.value: p for p in plans if p.objective.value in FRONTIER_PLANS}
        point = FrontierPoint(
            budget_inr=inr,
            cvar={o: round(float(plan_brief(p)["cvar"]), 4) for o, p in by_objective.items()},
            cost_inr={o: p.cost_inr for o, p in by_objective.items()},
            controls={o: len(p.choices) for o, p in by_objective.items()},
        )
        points.append(point)
        c = point.cvar
        print(f"INR {inr:>9,}: cvar {c['cvar']:.2f}  cvss {c['cvss']:.2f}  bfs {c['bfs_centrality']:.2f}")
    frontier = Frontier(
        city_id=city.id,
        downtime_h=settings.downtime_h,
        n_scenarios=settings.n_scenarios,
        test_seed=engine.test_seed,
        points=points,
    )
    FRONTIER_PATH.write_text(json.dumps(frontier.model_dump(mode="json"), indent=1) + "\n", encoding="utf-8")
    print(f"wrote {FRONTIER_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
