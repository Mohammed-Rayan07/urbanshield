"""The deterministic engine the agents drive. Owner: C.

Agents never import the city, simulator or optimiser modules directly; they receive an
``Engine``. The default binds the real implementations; tests bind fakes. This is the
seam that lets the agent layer be built and tested while the modules it calls are
still being written, and it keeps every number traceable to one of these functions.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import numpy as np

from urbanshield.schemas import (
    Budget,
    City,
    Claim,
    Constraint,
    ControlKind,
    Objective,
    Plan,
    PlanMetrics,
    ScenarioLosses,
    ToolResult,
)


@dataclass(frozen=True)
class Engine:
    # city (owner A)
    generate_city: Callable[..., City]
    build_graphs: Callable[[City], Any]
    bfs_reach: Callable[..., set[str]]
    blast_radius: Callable[[Any, str], list[str]]
    feed_record: Callable[[str], dict | None]
    # simulator (owner S)
    simulate: Callable[..., ScenarioLosses]
    # optimiser (owner B)
    solve: Callable[..., Plan]
    compare: Callable[..., list[Plan]]
    evaluate_plan: Callable[..., PlanMetrics]
    cvar: Callable[[np.ndarray, float], float]
    train_seed: int
    test_seed: int
    # auditor (owner S)
    check_claims: Callable[[list[Claim], Mapping[str, ToolResult]], Any]
    render_claim: Callable[[Claim], str]

    def controlled(self, city: City, controls: Mapping[str, ControlKind], **kwargs: Any) -> ScenarioLosses:
        return self.simulate(city, controls=dict(controls), **kwargs)

    def solve_cvar(
        self, city: City, losses: ScenarioLosses, budget: Budget, constraints: list[Constraint]
    ) -> Plan:
        return self.solve(city, losses, budget, constraints, Objective.CVAR)


def default_engine() -> Engine:
    """Bind the real modules. Import lazily so a broken teammate module can't break import."""
    from urbanshield.city import feeds, generator, graphs
    from urbanshield.guard import auditor
    from urbanshield.opt import common, cvar, evaluate
    from urbanshield.sim import montecarlo

    return Engine(
        generate_city=generator.generate_city,
        build_graphs=graphs.build_graphs,
        bfs_reach=graphs.bfs_reach,
        blast_radius=graphs.blast_radius,
        feed_record=feeds.feed_record,
        simulate=montecarlo.simulate,
        solve=cvar.solve,
        compare=evaluate.compare,
        evaluate_plan=evaluate.evaluate_plan,
        cvar=common.cvar,
        train_seed=evaluate.TRAIN_SEED,
        test_seed=evaluate.TEST_SEED,
        check_claims=auditor.check_claims,
        render_claim=auditor.render,
    )


def engine_ready(engine: Engine) -> bool:
    """True once every module the live pipeline needs is implemented. Only a missing
    implementation counts as "not ready"; any other error is a real bug and propagates."""
    try:
        city = engine.generate_city(seed=0)
        losses = engine.simulate(city, n_scenarios=20, seed=0)
        engine.cvar(losses.total, 0.95)
        engine.build_graphs(city)
    except NotImplementedError:
        return False
    return True
