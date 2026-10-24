"""Regenerate fixtures/demo/{city,plans,events}.json from the real pipeline (Flow A).

    uv run python scripts/build_demo.py [--advisory normal_01_lumenos] [--constraints "..."]

Needs the real city and optimiser (engine ready). Use LLM_MODE=replay (or live, which records
traces) so the events are the model's; the first event states the LLM mode either way. The
approval step is answered "approve" by this script, and the event says so (role: build_demo).
"""

from __future__ import annotations

import argparse
import json
import sys

from urbanshield.agents.engine import default_engine, engine_ready
from urbanshield.agents.llm import get_llm
from urbanshield.agents.orchestrator import ApprovalDecision, run_incident
from urbanshield.agents.tools import RunContext, plan_brief
from urbanshield.api.fixtures import DEMO_DIR
from urbanshield.config import get_settings
from urbanshield.guard.quarantine import load_presets
from urbanshield.schemas import AgentEvent, Budget

FRONTEND_CITY_ID = "mangaluru-demo"  # frontend/src/api.ts CITY_ID


class _ApproveAll:
    def ask(self, request: dict, timeout_s: float) -> ApprovalDecision:
        return ApprovalDecision(plan_id=request["plan_id"], approve=True, role="build_demo")


def _write(name: str, value: object) -> None:
    path = DEMO_DIR / name
    path.write_text(json.dumps(value, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--advisory", default="normal_01_lumenos", help="preset id from data/advisories")
    parser.add_argument("--constraints", default=None, help="operator constraint text for the Planner")
    args = parser.parse_args(argv)

    settings = get_settings()
    engine = default_engine()
    if not engine_ready(engine):
        print("The city and optimiser are not implemented yet (engine not ready).", file=sys.stderr)
        return 2
    presets = {p["id"]: p["text"] for p in load_presets()}
    if args.advisory not in presets:
        print(f"unknown preset {args.advisory!r}; choose from {', '.join(presets)}", file=sys.stderr)
        return 2

    city = engine.generate_city(seed=settings.city_seed)
    if city.id != FRONTEND_CITY_ID:
        print(
            f"warning: city id {city.id!r} differs from the frontend's {FRONTEND_CITY_ID!r}", file=sys.stderr
        )
    budget = Budget(inr=settings.budget_inr, downtime_h=settings.downtime_h)
    plans = engine.compare(city, budget, [], n_scenarios=settings.n_scenarios)
    plans = [p.model_copy(update={"tool_call_id": "tc-plans"}) for p in plans]

    events: list[AgentEvent] = []
    ctx = RunContext(
        run_id="run-demo",
        city=city,
        engine=engine,
        llm=get_llm(settings),
        emit=events.append,
        budget=budget,
        n_scenarios=settings.n_scenarios,
    )
    run_incident(ctx, presets[args.advisory], args.constraints, _ApproveAll())
    failed = [e for e in events if e.kind.value == "error"]

    _write("city.json", city.model_dump(mode="json"))
    _write("plans.json", [p.model_dump(mode="json") for p in plans])
    _write("events.json", [e.model_dump(mode="json") for e in events])
    print(
        f"{len(events)} events, LLM mode {settings.llm_mode}; plans: "
        + ", ".join(f"{p.objective.value} cvar={plan_brief(p).get('cvar')}" for p in plans)
    )
    if failed:
        print(f"{len(failed)} ERROR events in the run: {failed[0].summary}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
