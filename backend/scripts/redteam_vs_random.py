"""Red-Team vs random search: simulator calls to the first hole (EVALS.md section 3).

    uv run python scripts/redteam_vs_random.py [--seeds 20] [--budget 5] [--write]

Needs the real city and optimiser (engine ready) and LLM_MODE=live or replay: mock agents are
rule-based, so their numbers would say nothing about the model. ``--write`` replaces section 3
of docs/EVALS.md; the table always states the LLM mode it came from.
"""

from __future__ import annotations

import argparse
import sys

from urbanshield.agents.engine import default_engine, engine_ready
from urbanshield.agents.evidence import redteam_vs_random, replace_section, search_table
from urbanshield.agents.llm import get_llm
from urbanshield.agents.planner import run_planner
from urbanshield.agents.tools import RunContext
from urbanshield.config import BACKEND_DIR, get_settings
from urbanshield.schemas import Budget

EVALS = BACKEND_DIR.parent / "docs" / "EVALS.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--budget", type=int, default=5, help="strategies per searcher and seed")
    parser.add_argument("--write", action="store_true", help="write the table into docs/EVALS.md")
    args = parser.parse_args(argv)

    settings = get_settings()
    if settings.llm_mode == "mock":
        print("LLM_MODE=mock: mock agents are rule-based, not evidence. Use live or replay.", file=sys.stderr)
        return 2
    engine = default_engine()
    if not engine_ready(engine):
        print("The city and optimiser are not implemented yet (engine not ready).", file=sys.stderr)
        return 2
    city = engine.generate_city(seed=settings.city_seed)
    llm = get_llm(settings)
    budget = Budget(inr=settings.budget_inr, downtime_h=settings.downtime_h)

    def context(seed: int) -> RunContext:
        return RunContext(
            run_id=f"eval-redteam-{seed}",
            city=city,
            engine=engine,
            llm=llm,
            emit=lambda _: None,
            budget=budget,
            n_scenarios=settings.n_scenarios,
            redteam_seed=100 + seed,
        )

    base = context(0)
    run_planner(base, None)  # the plan under attack: the CVaR plan for the demo budget

    def attacked(seed: int) -> RunContext:
        ctx = context(seed)
        ctx.plans, ctx.candidate = dict(base.plans), base.candidate
        return ctx

    rows = redteam_vs_random(attacked, seeds=args.seeds, budget=args.budget)
    table = search_table(rows, settings.llm_mode, args.budget)
    print(table)
    if args.write:
        replace_section(EVALS, 3, table)
        print(f"wrote section 3 of {EVALS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
