""" "Same attack, two cities": one worst-case scenario replayed hop by hop under two plans. Owner: C.

The simulator draws every random number before controls are applied (common random numbers), so
scenario ``s`` is the identical attack under every plan; only the plan differs. This module picks one
scenario from the uncontrolled city's worst 5% (the CVaR tail) on the evaluator's held-out seed and
reports, for no controls, CVSS-first and the CVaR plan, the hop at which each device is lost.

Selection is deterministic and stated in the response: among tail scenarios where CVSS-first still
loses an ambulance-corridor signal and the CVaR plan does not, the one with the largest loss gap
between the two plans; if there is none, the tail scenario with the largest gap.
"""

from __future__ import annotations

import numpy as np
from pydantic import Field

from urbanshield.agents.engine import Engine
from urbanshield.agents.tools import CORRIDOR_TAG
from urbanshield.opt.common import tail_size
from urbanshield.schemas import City, Contract, Plan
from urbanshield.sim.montecarlo import fall_hops

REPLAY_PLANS = ("cvss", "cvar")


class ReplayView(Contract):
    """One plan's outcome in the replayed scenario."""

    label: str = Field(description="none | cvss | cvar")
    plan_id: str | None = None
    cost_inr: int = 0
    hops: dict[str, int] = Field(description="device id -> spread hop at which it was lost (0 = first)")
    devices_lost: int
    corridor_lost: int
    loss: float
    tail_devices_lost: float = Field(description="Mean devices lost over the whole worst-5% set")
    tail_corridor_share: float = Field(description="Share of worst-5% scenarios losing a corridor signal")


class TwoCities(Contract):
    city_id: str
    scenario: int
    seed: int
    n_scenarios: int
    alpha: float
    tail_rank: int = Field(description="1 = the worst scenario with no controls")
    selection: str
    corridor_ids: list[str]
    max_hop: int
    views: list[ReplayView]
    tool_call_id: str | None = None


def _tail(base: np.ndarray, alpha: float) -> np.ndarray:
    """The worst ``1 - alpha`` share of scenarios with no controls."""
    return np.argsort(-base, kind="stable")[: tail_size(len(base), alpha)]


def _pick(
    totals: dict[str, np.ndarray], corridor_hit: dict[str, np.ndarray], alpha: float
) -> tuple[int, str]:
    """Keyed by view label ('none', 'cvss', 'cvar') so selection never depends on list order."""
    tail = _tail(totals["none"], alpha)
    gap = totals["cvss"] - totals["cvar"]
    story = tail[corridor_hit["cvss"][tail] & ~corridor_hit["cvar"][tail]]
    if len(story):
        return int(story[np.argmax(gap[story])]), (
            "worst-5% scenario where CVSS-first loses a corridor signal and UrbanShield does not, "
            "with the largest loss gap"
        )
    return int(tail[np.argmax(gap[tail])]), "worst-5% scenario with the largest loss gap"


def two_cities(engine: Engine, city: City, plans: list[Plan], n_scenarios: int, alpha: float) -> TwoCities:
    """Replay one tail scenario of the held-out run under no controls, CVSS-first and CVaR."""
    seed = engine.test_seed
    by_objective = {p.objective.value: p for p in plans}
    chosen = [by_objective[o] for o in REPLAY_PLANS]
    corridor = np.array([CORRIDOR_TAG in d.tags for d in city.devices])

    runs = [engine.simulate(city, n_scenarios=n_scenarios, seed=seed)]
    runs += [engine.controlled(city, p.choices, n_scenarios=n_scenarios, seed=seed) for p in chosen]
    labels = ("none", *REPLAY_PLANS)
    totals = {label: r.total for label, r in zip(labels, runs, strict=True)}
    corridor_hit = {
        label: r.compromised[:, corridor].any(axis=1) for label, r in zip(labels, runs, strict=True)
    }
    scenario, selection = _pick(totals, corridor_hit, alpha)
    rank = int((totals["none"] > totals["none"][scenario]).sum()) + 1
    tail = _tail(totals["none"], alpha)

    ids = [d.id for d in city.devices]
    views = []
    for label, plan, run in zip(labels, (None, *chosen), runs, strict=True):
        hit = corridor_hit[label]
        controls = dict(plan.choices) if plan else None
        hops = fall_hops(city, scenario, n_scenarios=n_scenarios, seed=seed, controls=controls)
        lost = hops >= 0
        views.append(
            ReplayView(
                label=label,
                plan_id=plan.id if plan else None,
                cost_inr=plan.cost_inr if plan else 0,
                hops={ids[i]: int(hops[i]) for i in np.flatnonzero(lost)},
                devices_lost=int(lost.sum()),
                corridor_lost=int((lost & corridor).sum()),
                loss=round(float(run.total[scenario]), 4),
                tail_devices_lost=round(float(run.compromised[tail].sum(axis=1).mean()), 2),
                tail_corridor_share=round(float(hit[tail].mean()), 4),
            )
        )
    return TwoCities(
        city_id=city.id,
        scenario=scenario,
        seed=seed,
        n_scenarios=n_scenarios,
        alpha=alpha,
        tail_rank=rank,
        selection=selection,
        corridor_ids=[ids[i] for i in np.flatnonzero(corridor)],
        max_hop=max((max(v.hops.values(), default=0) for v in views), default=0),
        views=views,
    )
