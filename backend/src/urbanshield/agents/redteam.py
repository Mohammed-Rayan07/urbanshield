"""Red-Team agent: adversarial verification of the chosen plan. Owner: C.

Given plan P, propose up to 5 ``Strategy`` values. Each one generates attack scenarios
with ``sim.simulate(strategy=...)``; those are added to the evaluation set and P's CVaR
is recomputed. A **hole** means adding a strategy's scenarios raises P's CVaR by more
than ``HOLE_THRESHOLD`` (not "some scenario exceeds CVaR"; tail scenarios always do).
Holes go back to the Planner, which re-solves on the augmented set.

Outcome-verification metric: simulator calls needed to find a hole, Red-Team vs
``random_search`` over the same strategy menu with the same call budget.

The Red-Team holds read-only tools (``list_controls``, ``bfs_reach``, ``simulate_strategy``);
the replan is the Planner's ``optimize`` call. ``increase_pct`` is a fraction (0.12 = +12%).
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from pydantic import BaseModel, ConfigDict, ValidationError

from urbanshield.agents import tools
from urbanshield.agents.llm import LLMOutputError
from urbanshield.agents.planner import stamp
from urbanshield.agents.tools import CORRIDOR_TAG, RunContext, StrategyArgs, ToolArgError
from urbanshield.schemas import AgentName, Category, EventKind, Hole, ScenarioLosses, Strategy

HOLE_THRESHOLD = 0.05
MAX_STRATEGIES = 5
MAX_ROUNDS = 2
MAX_ENTRY_POINTS = 10

SYSTEM = """You are the Red-Team agent of UrbanShield. You attack the remediation plan under review in a
simulated city to find where it fails. You cannot change anything: you propose attack strategies and
code simulates them against the plan.

A strategy has:
- "entry_points": device ids the attacker starts from (empty list = any internet-exposed device)
- "target_category": "signal", "meter", "streetlight" or "ev_charger" (the attacker prefers footholds
  that can reach it), or "" for no preference
- "pivot_shared_firmware": true if one compromised device of a firmware family compromises the others
- "campaign_cve": a CVE id to force a mass-exploitation campaign of it, or ""

Think like an attacker who knows the plan: exposed devices it leaves unprotected, gateways into the
ambulance-corridor signals, large firmware families without a patch, known-exploited (KEV) CVEs with
many unprotected carriers. If earlier probes found holes, re-test them against the current plan and
try variations of them.

Propose at most 5 different strategies, using only device ids and CVE ids from the context.
Reply with one JSON object and nothing else:
{"strategies": [{"entry_points": [], "target_category": "", "pivot_shared_firmware": false,
                 "campaign_cve": ""}]}"""


class Probe(BaseModel):
    """Result of attacking the plan under review with one strategy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    strategy_id: str
    cvar_before: float
    cvar_after_attack: float
    increase_pct: float
    hole: bool
    sim_calls: int

    def to_hole(self) -> Hole:
        return Hole(**self.model_dump(exclude={"hole"}))


@dataclass(frozen=True)
class RedTeamOutcome:
    rounds: int
    holes_found: list[Hole] = field(default_factory=list)
    residual: list[Hole] = field(default_factory=list)  # holes still open after the last round


# --------------------------------------------------------------------------- strategies


def strategy_args(strategy: Strategy) -> dict[str, Any]:
    """The flat ``simulate_strategy`` arguments for a strategy (inverse of ``strategy_from_args``)."""
    return {
        "entry_points": list(strategy.entry_points),
        "target_category": strategy.target_category.value if strategy.target_category else "",
        "pivot_shared_firmware": strategy.pivot_shared_firmware,
        "campaign_cve": strategy.campaign_cve or "",
    }


def strategy_from_args(ctx: RunContext, args: dict[str, Any]) -> Strategy:
    """Validate flat strategy arguments against this city; the id is a hash of the content,
    so the same strategy has the same id in every run. Raises ``ToolArgError``."""
    try:
        a = StrategyArgs.model_validate(args)
    except ValidationError as exc:
        raise ToolArgError(f"strategy: {exc.errors()[0]['msg']}") from None
    known = {d.id for d in ctx.city.devices}
    entry = sorted(set(a.entry_points))
    unknown = [d for d in entry if d not in known]
    if unknown:
        raise ToolArgError(f"unknown device ids: {', '.join(unknown[:5])}")
    if len(entry) > MAX_ENTRY_POINTS:
        raise ToolArgError(f"at most {MAX_ENTRY_POINTS} entry points")
    categories = [c.value for c in Category]
    if a.target_category and a.target_category not in categories:
        raise ToolArgError(f"target_category must be one of {', '.join(categories)} or empty")
    cve = a.campaign_cve.strip().upper() or None
    if cve and not any(v.cve_id == cve for d in ctx.city.devices for v in d.vulns):
        raise ToolArgError(f"no device carries {cve[:20]}")
    content = {
        "entry_points": entry,
        "target_category": a.target_category or None,
        "pivot_shared_firmware": a.pivot_shared_firmware,
        "campaign_cve": cve,
    }
    digest = hashlib.sha256(tools.dumps(content).encode()).hexdigest()[:8]
    try:
        return Strategy(id=f"s-{digest}", **content)
    except ValidationError as exc:
        raise ToolArgError(f"strategy: {exc.errors()[0]['msg']}") from None


def describe(strategy: Strategy) -> str:
    parts = [f"entry {', '.join(strategy.entry_points)}" if strategy.entry_points else "any exposed entry"]
    if strategy.target_category:
        parts.append(f"→ {strategy.target_category.value}")
    if strategy.pivot_shared_firmware:
        parts.append("firmware pivot")
    if strategy.campaign_cve:
        parts.append(f"campaign {strategy.campaign_cve}")
    return " · ".join(parts)


# --------------------------------------------------------------------------- scoring


def concat_losses(*parts: ScenarioLosses) -> ScenarioLosses:
    """Stack scenario sets for the same city (rows appended in order)."""
    first = parts[0]
    if any(p.device_ids != first.device_ids for p in parts):
        raise ValueError("scenario sets cover different devices")
    return ScenarioLosses(
        city_id=first.city_id,
        seed=first.seed,
        device_ids=first.device_ids,
        device_loss=np.concatenate([p.device_loss for p in parts]),
        compromised=np.concatenate([p.compromised for p in parts]),
        campaign_cve=tuple(c for p in parts for c in p.campaign_cve),
    )


def score_strategy(ctx: RunContext, strategy: Strategy) -> Probe:
    """CVaR of the plan under review on probe scenarios, before and after adding this
    strategy's attack scenarios (same seed: common random numbers)."""
    plan = ctx.candidate
    if plan is None:
        raise ToolArgError("no plan under review")
    base = ctx.redteam_baselines.get(plan.id)
    if base is None:
        base = ctx.engine.controlled(
            ctx.city, plan.choices, n_scenarios=ctx.n_scenarios, seed=ctx.redteam_seed
        )
        ctx.redteam_baselines[plan.id] = base
        ctx.redteam_sim_calls += 1
    attack = ctx.engine.controlled(
        ctx.city, plan.choices, n_scenarios=ctx.n_scenarios, seed=ctx.redteam_seed, strategy=strategy
    )
    ctx.redteam_sim_calls += 1
    alpha = ctx.budget.alpha
    before = ctx.engine.cvar(base.total, alpha)
    after = ctx.engine.cvar(np.concatenate([base.total, attack.total]), alpha)
    # A zero baseline makes the ratio undefined; any new loss then counts as +100%.
    increase = (after - before) / before if before > 0 else (1.0 if after > 0 else 0.0)
    return Probe(
        strategy_id=strategy.id,
        cvar_before=round(before, 4),
        cvar_after_attack=round(after, 4),
        increase_pct=round(increase, 4),
        hole=increase > HOLE_THRESHOLD,
        sim_calls=ctx.redteam_sim_calls,
    )


# --------------------------------------------------------------------------- proposals


def _context(ctx: RunContext, plan_view: dict[str, Any], history: list[dict[str, Any]]) -> str:
    corridor = {d.id for d in ctx.city.devices if CORRIDOR_TAG in d.tags}
    choices = ctx.candidate.choices if ctx.candidate else {}
    devices = []
    for d in ctx.city.devices:
        entry_like = d.exposed or d.category == Category.EV_CHARGER
        # Plain graph reachability: in the simulator a control (segment included) scales a
        # device's odds and spread, it does not remove edges, so a segmented gateway is still a path.
        reaches = bool(corridor & ctx.engine.bfs_reach(ctx.graphs, [d.id])) if entry_like else None
        devices.append(
            {
                "id": d.id,
                "category": d.category.value,
                "zone": d.zone,
                "firmware_family": d.firmware.split("/")[0],
                "exposed": d.exposed,
                "control": choices[d.id].value if d.id in choices else None,
                "cves": sorted(v.cve_id for v in d.vulns),
                "kev_cves": sorted(v.cve_id for v in d.vulns if v.kev),
                "on_ambulance_corridor": d.id in corridor,
                "reaches_corridor": reaches,
            }
        )
    return tools.dumps({"plan_under_review": plan_view, "devices": devices, "previous_probes": history})


def propose_strategies(ctx: RunContext, history: list[dict[str, Any]]) -> list[Strategy]:
    """Strong tier proposes up to ``MAX_STRATEGIES``; each is validated, unknown ids are
    dropped with a REJECT note, duplicates are removed."""
    view = tools.call(ctx, AgentName.REDTEAM, "list_controls", {})
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": _context(ctx, view.result | {"tool_call_id": view.id}, history)},
    ]
    response = ctx.llm.chat("redteam.propose", messages, tier="strong", json_output=True)
    try:
        raw = response.json().get("strategies")
    except LLMOutputError:
        raw = None
    if not isinstance(raw, list):
        ctx.event(AgentName.REDTEAM, EventKind.REJECT, "Red-Team answer was not a list of strategies", {})
        return []
    strategies: dict[str, Strategy] = {}
    for item in raw[:MAX_STRATEGIES]:
        try:
            strategy = strategy_from_args(ctx, item if isinstance(item, dict) else {"_": item})
        except ToolArgError as exc:
            ctx.event(AgentName.REDTEAM, EventKind.REJECT, f"Dropped a proposed strategy: {exc}", {})
            continue
        strategies.setdefault(strategy.id, strategy)
    chosen = list(strategies.values())
    ctx.event(
        AgentName.REDTEAM,
        EventKind.DECISION,
        f"Red-Team will try {tools.count(len(chosen), 'strategy')} against {view.result['plan_id']}",
        {"strategies": [s.model_dump() | {"label": describe(s)} for s in chosen]},
        tool_call_id=view.id,
        usage=response.usage,
    )
    return chosen


# --------------------------------------------------------------------------- loop


def replan(ctx: RunContext, strategies: list[Strategy]) -> bool:
    """Add each hole's attack scenarios (uncontrolled, training seed) to the training set and
    re-solve; the new CVaR plan becomes the candidate. Returns whether the plan changed."""
    old = ctx.candidate
    extra = [
        ctx.engine.simulate(ctx.city, n_scenarios=ctx.n_scenarios, seed=ctx.engine.train_seed, strategy=s)
        for s in strategies
    ]
    ctx.set_train(concat_losses(ctx.train_losses, *extra))
    record = tools.call(
        ctx,
        AgentName.PLANNER,
        "optimize",
        {"budget_inr": ctx.budget.inr, "downtime_h": ctx.budget.downtime_h},
    )
    stamp(ctx, record)
    new = ctx.plans[record.result["plan_id"]]
    ctx.candidate = new
    changed = len({d for d, _ in set(new.choices.items()) ^ set(old.choices.items() if old else ())})
    added = sum(e.n_scenarios for e in extra)
    outcome = (
        f"{old.id if old else '—'} → {new.id} ({changed} device{'' if changed == 1 else 's'} changed)"
        if changed
        else f"the optimiser kept {new.id}"
    )
    ctx.event(
        AgentName.PLANNER,
        EventKind.DECISION,
        f"Replanned on {added} added attack scenarios: {outcome}",
        {"plan": new.model_dump(mode="json"), "strategies": [s.id for s in strategies]},
        tool_call_id=record.id,
    )
    return changed > 0


def run_redteam(ctx: RunContext) -> RedTeamOutcome:
    """Up to ``MAX_ROUNDS`` of propose -> probe (-> replan on holes). Every probe is a
    ``simulate_strategy`` tool call; every hole is a HOLE event."""
    history: list[dict[str, Any]] = []
    found: list[Hole] = []
    for round_no in range(1, MAX_ROUNDS + 1):
        holes: list[tuple[Strategy, Probe]] = []
        strategies = propose_strategies(ctx, history)
        for strategy in strategies:
            record = tools.call(ctx, AgentName.REDTEAM, "simulate_strategy", strategy_args(strategy))
            probe = Probe.model_validate(record.result)
            history.append(
                {"round": round_no, "strategy": strategy_args(strategy), "hole": probe.hole}
                | probe.model_dump(include={"cvar_before", "cvar_after_attack", "increase_pct"})
            )
            if probe.hole:
                holes.append((strategy, probe))
                ctx.event(
                    AgentName.REDTEAM,
                    EventKind.HOLE,
                    f"Hole: {describe(strategy)} raises CVaR95 {probe.cvar_before:.2f} → "
                    f"{probe.cvar_after_attack:.2f} ({probe.increase_pct:+.1%})",
                    {"strategy": strategy.model_dump(), "probe": probe.model_dump()},
                    tool_call_id=record.id,
                )
        found += [p.to_hole() for _, p in holes]
        if not holes:
            after = " after replan" if round_no > 1 else ""
            tried = tools.count(len(strategies), "strategy")
            ctx.event(
                AgentName.REDTEAM,
                EventKind.DECISION,
                f"Round {round_no}: no hole above {HOLE_THRESHOLD:.0%} in {tried}{after}",
                {"round": round_no, "sim_calls": ctx.redteam_sim_calls},
            )
            return RedTeamOutcome(rounds=round_no, holes_found=found)
        if round_no == MAX_ROUNDS:
            why = f"after {MAX_ROUNDS} rounds"
        elif not replan(ctx, [s for s, _ in holes]):
            # Same plan, same seeds: another round would only repeat these results.
            why = "the replan kept the same plan, so the budget cannot close them"
        else:
            continue
        residual = [p.to_hole() for _, p in holes]
        ctx.event(
            AgentName.REDTEAM,
            EventKind.DECISION,
            f"{tools.count(len(residual), 'hole')} {'remains' if len(residual) == 1 else 'remain'}: {why}; "
            "flagged for the approver",
            {"residual": [h.model_dump() for h in residual], "sim_calls": ctx.redteam_sim_calls},
        )
        return RedTeamOutcome(rounds=round_no, holes_found=found, residual=residual)
    raise AssertionError("unreachable")  # pragma: no cover


def random_search(ctx: RunContext, budget_calls: int, seed: int = 0) -> list[Probe]:
    """Baseline for the Red-Team: random strategies from the same menu, scored the same way."""
    rng = random.Random(seed)
    devices = ctx.city.devices
    entries: list[list[str]] = [
        [],
        *([d.id] for d in devices if d.exposed or d.category == Category.EV_CHARGER),
    ]
    targets = ["", *(c.value for c in Category)]
    cves = ["", *sorted({v.cve_id for d in devices for v in d.vulns})]
    probes = []
    for _ in range(budget_calls):
        args = {
            "entry_points": rng.choice(entries),
            "target_category": rng.choice(targets),
            "pivot_shared_firmware": rng.random() < 0.5,
            "campaign_cve": rng.choice(cves),
        }
        probes.append(score_strategy(ctx, strategy_from_args(ctx, args)))
    return probes


def calls_to_first_hole(probes: list[Probe]) -> int | None:
    """Simulator calls spent when the first hole was found (None if none was)."""
    return next((p.sim_calls for p in probes if p.hole), None)
