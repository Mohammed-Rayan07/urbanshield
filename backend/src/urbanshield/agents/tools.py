"""Toolbox: the only way an agent touches the world. Owner: C.

``Toolbox.call``:
1. checks the per-agent allowlist (``guard.allowlist``) and emits a REJECT event if refused,
2. validates the arguments with a flat Pydantic model,
3. runs a deterministic function over the ``Engine``,
4. stores a ``ToolResult`` under a sequential, run-scoped id (``tc-001`` …) for provenance and
   the Auditor,
5. emits a TOOL_CALL event.

Tool results are compact JSON summaries (never matrices) because they are fed back to the
model. Tool ids are sequential and results carry no timestamps, so identical runs produce
identical prompts and replay exactly.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from urbanshield.agents.engine import Engine
from urbanshield.agents.llm import LLM
from urbanshield.guard.allowlist import ALLOWLIST, ToolNotAllowed, authorize
from urbanshield.schemas import (
    CVE_PATTERN,
    AgentEvent,
    AgentName,
    Budget,
    Category,
    City,
    Constraint,
    ControlKind,
    EventKind,
    LLMUsage,
    Objective,
    Plan,
    ScenarioLosses,
    Solver,
    ToolResult,
)

CORRIDOR_TAG = "ambulance_corridor"
DEFAULT_ALPHA = 0.95


class ToolArgError(ValueError):
    """The arguments for a tool call did not validate."""


def dumps(value: Any) -> str:
    """Canonical JSON for prompts: sorted keys, no whitespace, so identical runs send identical bytes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# --------------------------------------------------------------------------- run state


@dataclass
class RunContext:
    """Everything one incident run shares. Not thread-safe; one run = one worker thread."""

    run_id: str
    city: City
    engine: Engine
    llm: LLM
    emit: Callable[[AgentEvent], None]
    budget: Budget
    n_scenarios: int = 1000
    applied: dict[str, ControlKind] = field(default_factory=dict)
    constraints: list[Constraint] = field(default_factory=list)
    plans: dict[str, Plan] = field(default_factory=dict)
    candidate: Plan | None = None
    results: dict[str, ToolResult] = field(default_factory=dict)
    untrusted: dict[str, str] = field(default_factory=dict)  # sha256 -> raw advisory text
    redteam_seed: int = 3  # probe scenarios: neither the training nor the test seed
    redteam_sim_calls: int = 0  # simulator calls spent by the Red-Team (outcome-verification metric)
    redteam_baselines: dict[str, ScenarioLosses] = field(default_factory=dict)  # plan id -> scenarios
    _tool_seq: itertools.count = field(default_factory=lambda: itertools.count(1))
    _event_seq: itertools.count = field(default_factory=lambda: itertools.count(1))
    _graphs: Any = None
    _train: ScenarioLosses | None = None

    def next_tool_id(self) -> str:
        return f"tc-{next(self._tool_seq):03d}"

    def event(
        self,
        agent: AgentName,
        kind: EventKind,
        summary: str,
        payload: dict[str, Any] | None = None,
        tool_call_id: str | None = None,
        usage: LLMUsage | None = None,
    ) -> AgentEvent:
        event = AgentEvent(
            id=f"{self.run_id}:ev-{next(self._event_seq):03d}",
            city_id=self.city.id,
            run_id=self.run_id,
            agent=agent,
            kind=kind,
            summary=summary[:280],
            payload=payload or {},
            tool_call_id=tool_call_id,
            usage=usage,
        )
        self.emit(event)
        return event

    @property
    def graphs(self) -> Any:
        if self._graphs is None:
            self._graphs = self.engine.build_graphs(self.city)
        return self._graphs

    @property
    def train_losses(self) -> ScenarioLosses:
        """Uncontrolled training scenarios the optimiser plans on (cached per run)."""
        if self._train is None:
            self._train = self.engine.simulate(
                self.city, n_scenarios=self.n_scenarios, seed=self.engine.train_seed
            )
        return self._train

    def set_train(self, losses: ScenarioLosses) -> None:
        """Replace the training scenarios (the Red-Team's replan adds attack scenarios)."""
        self._train = losses


# --------------------------------------------------------------------------- argument models


class Args(BaseModel):
    """Flat argument schemas only (no nesting, no unions): some providers accept a JSON-Schema subset."""

    model_config = ConfigDict(extra="forbid")


class NoArgs(Args):
    pass


class TextRef(Args):
    text_sha256: str = Field(description="SHA-256 of the quarantined text")


class AdvisoryArgs(Args):
    cve_id: str = Field(pattern=CVE_PATTERN)
    vendor: str = Field(max_length=64)
    product: str = Field(max_length=64)
    firmware_family: str = Field(max_length=64)
    affected_below: str = Field(max_length=32)
    cvss: float = Field(ge=0, le=10)


class BfsArgs(Args):
    sources: list[str] = Field(description="Device ids the attacker starts from")
    respect_controls: bool = Field(default=True, description="Treat segmented devices as blocked")


class DeviceArg(Args):
    device_id: str


class QueryArgs(Args):
    category: str = Field(default="", description="signal | meter | streetlight | ev_charger, or empty")
    zone: str = Field(default="")
    firmware_family: str = Field(default="", description="e.g. 'lumenos'")
    exposed_only: bool = False


class BudgetArgs(Args):
    budget_inr: int = Field(gt=0)
    downtime_h: float = Field(gt=0)


class PlanDiffArgs(Args):
    plan_a: str
    plan_b: str


class StrategyArgs(Args):
    entry_points: list[str] = Field(
        default_factory=list, description="Device ids; empty = any exposed device"
    )
    target_category: str = Field(
        default="", description="signal | meter | streetlight | ev_charger, or empty"
    )
    pivot_shared_firmware: bool = False
    campaign_cve: str = Field(default="", description="Force a campaign on this CVE, or empty")


# --------------------------------------------------------------------------- tool functions


def _summary(ctx: RunContext, losses: ScenarioLosses) -> dict[str, Any]:
    total = losses.total
    corridor = [i for i, d in enumerate(ctx.city.devices) if CORRIDOR_TAG in d.tags]
    p_corridor = float(losses.compromised[:, corridor].any(axis=1).mean()) if corridor else 0.0
    share = losses.device_loss.sum(axis=0)
    top = sorted(zip(losses.device_ids, share, strict=True), key=lambda kv: -kv[1])[:5]
    denom = float(share.sum()) or 1.0
    return {
        "cvar95": round(ctx.engine.cvar(total, DEFAULT_ALPHA), 4),
        "mean_loss": round(float(total.mean()), 4),
        "p_corridor_compromised": round(p_corridor, 4),
        "top_loss_devices": [{"device_id": d, "share": round(float(s) / denom, 3)} for d, s in top],
    }


def _device_brief(device: Any) -> dict[str, Any]:
    return {
        "id": device.id,
        "name": device.name,
        "category": device.category.value,
        "zone": device.zone,
        "firmware": device.firmware,
        "exposed": device.exposed,
        "criticality": device.criticality,
        "max_cvss": max((v.cvss for v in device.vulns), default=0.0),
        "tags": device.tags,
    }


def plan_brief(plan: Plan) -> dict[str, Any]:
    out: dict[str, Any] = {
        "objective": plan.objective.value,
        "cost_inr": plan.cost_inr,
        "downtime_h": plan.downtime_h,
        "solver": plan.solver.value,
        "n_controls": len(plan.choices),
    }
    if plan.metrics:
        out |= {
            "cvar": round(plan.metrics.cvar, 4),
            "mean_loss": round(plan.metrics.mean_loss, 4),
            "max_cascade": plan.metrics.max_cascade,
        }
    return out


def _blocked(ctx: RunContext) -> list[str]:
    return [d for d, kind in ctx.applied.items() if kind == ControlKind.SEGMENT]


def _t_quarantine_extract(ctx: RunContext, a: TextRef) -> dict[str, Any]:
    from urbanshield.guard.quarantine import quarantine_extract

    if a.text_sha256 not in ctx.untrusted:
        raise ToolArgError("no quarantined text with that sha256 in this run")
    advisory = quarantine_extract(ctx.untrusted[a.text_sha256], ctx.llm)
    return {"advisory": advisory.model_dump()}


def _t_cross_check(ctx: RunContext, a: AdvisoryArgs) -> dict[str, Any]:
    from urbanshield.guard.quarantine import cross_check
    from urbanshield.schemas import Advisory

    advisory = Advisory(**a.model_dump(), source_sha256="0" * 64)
    return {"discrepancies": cross_check(advisory, ctx.engine.feed_record)}


def _t_match_inventory(ctx: RunContext, a: AdvisoryArgs) -> dict[str, Any]:
    from urbanshield.agents.sentinel import match_inventory
    from urbanshield.schemas import Advisory

    matches = match_inventory(ctx.city, Advisory(**a.model_dump(), source_sha256="0" * 64))
    return {"matches": [m.model_dump() for m in matches], "count": len(matches)}


def _t_bfs_reach(ctx: RunContext, a: BfsArgs) -> dict[str, Any]:
    _require_devices(ctx, a.sources)
    blocked = _blocked(ctx) if a.respect_controls else []
    reached = sorted(ctx.engine.bfs_reach(ctx.graphs, a.sources, blocked=blocked))
    corridor = [d for d in reached if CORRIDOR_TAG in ctx.city.device(d).tags]
    return {"reached": reached, "count": len(reached), "corridor_reached": corridor}


def _t_blast_radius(ctx: RunContext, a: DeviceArg) -> dict[str, Any]:
    _require_devices(ctx, [a.device_id])
    lost = ctx.engine.blast_radius(ctx.graphs, a.device_id)
    critical = [d for d in lost if ctx.city.device(d).criticality >= 0.9]
    return {"device_id": a.device_id, "lost": lost, "critical_lost": critical}


def _t_simulate(ctx: RunContext, a: NoArgs) -> dict[str, Any]:
    # The run's scenario count and the test seed, so this CVaR is the same number the
    # evaluator reports for the same controls (no knob for the model to turn).
    losses = ctx.engine.controlled(
        ctx.city, ctx.applied, n_scenarios=ctx.n_scenarios, seed=ctx.engine.test_seed
    )
    return {"controls_applied": len(ctx.applied)} | _summary(ctx, losses)


def _t_query_devices(ctx: RunContext, a: QueryArgs) -> dict[str, Any]:
    found = [
        d
        for d in ctx.city.devices
        if (not a.category or d.category.value == a.category)
        and (not a.zone or d.zone.lower() == a.zone.lower())
        and (not a.firmware_family or d.firmware.split("/")[0].lower() == a.firmware_family.lower())
        and (not a.exposed_only or d.exposed)
    ]
    return {"count": len(found), "devices": [_device_brief(d) for d in found[:25]]}


def _t_compare(ctx: RunContext, a: BudgetArgs) -> dict[str, Any]:
    budget = Budget(inr=a.budget_inr, downtime_h=a.downtime_h, alpha=ctx.budget.alpha)
    plans = ctx.engine.compare(ctx.city, budget, list(ctx.constraints), n_scenarios=ctx.n_scenarios)
    for plan in plans:
        ctx.plans[plan.id] = plan
    cvar_plan = next(p for p in plans if p.objective.value == "cvar")
    cvss_plan = next(p for p in plans if p.objective.value == "cvss")
    # Shape documented in guard/auditor.py: claims compare plan "a" (baseline) with "b" (ours).
    return {"a": cvss_plan.id, "b": cvar_plan.id, "plans": {p.id: plan_brief(p) for p in plans}}


def _t_optimize(ctx: RunContext, a: BudgetArgs) -> dict[str, Any]:
    budget = Budget(inr=a.budget_inr, downtime_h=a.downtime_h, alpha=ctx.budget.alpha)
    plan = ctx.engine.solve_cvar(ctx.city, ctx.train_losses, budget, list(ctx.constraints))
    plan = plan.model_copy(update={"metrics": ctx.engine.evaluate_plan(ctx.city, plan, ctx.budget.alpha)})
    ctx.plans[plan.id] = plan
    return {"plan_id": plan.id, "plans": {plan.id: plan_brief(plan)}}


def _t_plan_diff(ctx: RunContext, a: PlanDiffArgs) -> dict[str, Any]:
    pa, pb = _plan(ctx, a.plan_a), _plan(ctx, a.plan_b)
    devices = sorted(set(pa.choices) | set(pb.choices))
    changed = [
        {"device_id": d, "a": pa.choices.get(d), "b": pb.choices.get(d)}
        for d in devices
        if pa.choices.get(d) != pb.choices.get(d)
    ]
    return {"plan_a": pa.id, "plan_b": pb.id, "changed": changed, "n_changed": len(changed)}


def _t_list_controls(ctx: RunContext, a: NoArgs) -> dict[str, Any]:
    plan = ctx.candidate
    if plan is None:
        return {"plan_id": None, "choices": {}}
    unprotected_exposed = [d.id for d in ctx.city.devices if d.exposed and d.id not in plan.choices]
    return {
        "plan_id": plan.id,
        "choices": {d: k.value for d, k in sorted(plan.choices.items())},
        "unprotected_exposed": unprotected_exposed,
    }


def _t_evaluate_applied(ctx: RunContext, a: NoArgs) -> dict[str, Any]:
    """Re-simulate the twin with exactly the controls applied so far (B's held-out evaluator)."""
    options = {(d.id, o.kind): o for d in ctx.city.devices for o in d.controls}
    choices = dict(sorted(ctx.applied.items()))
    plan = Plan(
        id=f"applied-{len(choices)}",
        city_id=ctx.city.id,
        objective=Objective.CVAR,
        choices=choices,
        cost_inr=sum(options[(d, k)].cost_inr for d, k in choices.items()),
        downtime_h=sum(options[(d, k)].downtime_h for d, k in choices.items()),
        solver=Solver.RANKING,
        solve_ms=0,
    )
    m = ctx.engine.evaluate_plan(ctx.city, plan, ctx.budget.alpha, n_scenarios=ctx.n_scenarios)
    return {
        "controls_applied": len(choices),
        "cvar": round(m.cvar, 4),
        "mean_loss": round(m.mean_loss, 4),
        "max_cascade": m.max_cascade,
        "ci_low": round(m.ci_low, 4),
        "ci_high": round(m.ci_high, 4),
    }


def _t_simulate_strategy(ctx: RunContext, a: StrategyArgs) -> dict[str, Any]:
    from urbanshield.agents.redteam import score_strategy, strategy_from_args

    strategy = strategy_from_args(ctx, a.model_dump())
    return score_strategy(ctx, strategy).model_dump()


def _require_devices(ctx: RunContext, ids: list[str]) -> None:
    known = {d.id for d in ctx.city.devices}
    unknown = [d for d in ids if d not in known]
    if unknown:
        raise ToolArgError(f"unknown device ids: {', '.join(unknown[:5])}")


def _plan(ctx: RunContext, plan_id: str) -> Plan:
    if plan_id not in ctx.plans:
        raise ToolArgError(f"unknown plan {plan_id!r}")
    return ctx.plans[plan_id]


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    args: type[Args]
    fn: Callable[[RunContext, Any], dict[str, Any]]


TOOLS: dict[str, Tool] = {
    t.name: t
    for t in (
        Tool(
            "quarantine_extract",
            "Reduce quarantined advisory text to a typed advisory.",
            TextRef,
            _t_quarantine_extract,
        ),
        Tool(
            "cross_check",
            "Compare an advisory with the pinned vulnerability feed.",
            AdvisoryArgs,
            _t_cross_check,
        ),
        Tool("match_inventory", "Devices affected by an advisory.", AdvisoryArgs, _t_match_inventory),
        Tool("bfs_reach", "Devices an attacker can reach from the given sources.", BfsArgs, _t_bfs_reach),
        Tool(
            "blast_radius",
            "Services lost if this device is lost (dependency closure).",
            DeviceArg,
            _t_blast_radius,
        ),
        Tool(
            "simulate",
            "Monte Carlo attack simulation with the controls applied so far.",
            NoArgs,
            _t_simulate,
        ),
        Tool(
            "query_devices",
            "Find devices by category, zone, firmware family or exposure.",
            QueryArgs,
            _t_query_devices,
        ),
        Tool(
            "compare",
            "Every planning objective under the same budget, scored on held-out scenarios.",
            BudgetArgs,
            _t_compare,
        ),
        Tool(
            "optimize",
            "CVaR-optimal remediation plan under the budget and current constraints.",
            BudgetArgs,
            _t_optimize,
        ),
        Tool(
            "plan_diff", "Devices whose chosen control differs between two plans.", PlanDiffArgs, _t_plan_diff
        ),
        Tool(
            "list_controls",
            "Controls in the plan under review and exposed devices it leaves unprotected.",
            NoArgs,
            _t_list_controls,
        ),
        Tool(
            "simulate_strategy",
            "Attack the plan under review with one strategy; reports the CVaR increase.",
            StrategyArgs,
            _t_simulate_strategy,
        ),
        Tool(
            "evaluate_applied",
            "Re-simulate the twin with the controls applied so far (held-out scenarios).",
            NoArgs,
            _t_evaluate_applied,
        ),
    )
}


def _schema(model: type[Args]) -> dict[str, Any]:
    schema = model.model_json_schema()
    schema.pop("title", None)
    for prop in schema.get("properties", {}).values():
        prop.pop("title", None)
    schema.setdefault("properties", {})
    return schema


def openai_tool_specs(agent: AgentName) -> list[dict[str, Any]]:
    """Function-calling specs for exactly the tools ``agent`` may call (sorted, so prompts are stable)."""
    return [
        {
            "type": "function",
            "function": {"name": t.name, "description": t.description, "parameters": _schema(t.args)},
        }
        for name in sorted(ALLOWLIST.get(agent, ()))
        if (t := TOOLS.get(name)) is not None
    ]


def call(ctx: RunContext, agent: AgentName, tool: str, arguments: dict[str, Any]) -> ToolResult:
    """Authorise, validate, run and record one tool call. Raises ``ToolNotAllowed`` / ``ToolArgError``."""
    try:
        authorize(agent, tool)
    except ToolNotAllowed:
        ctx.event(
            agent, EventKind.REJECT, f"Blocked: {agent.value} is not allowed to call {tool}", {"tool": tool}
        )
        raise
    spec = TOOLS.get(tool)
    if spec is None:
        raise ToolArgError(f"unknown tool {tool!r}")
    try:
        args = spec.args.model_validate(arguments)
    except ValidationError as exc:
        raise ToolArgError(f"{tool}: {exc.errors()[0]['msg']}") from exc
    result = spec.fn(ctx, args)
    record = ToolResult(id=ctx.next_tool_id(), tool=tool, agent=agent, args=args.model_dump(), result=result)
    ctx.results[record.id] = record
    ctx.event(
        agent, EventKind.TOOL_CALL, _describe(tool, args, result), {"tool": tool}, tool_call_id=record.id
    )
    return record


def _describe(tool: str, args: Args, result: dict[str, Any]) -> str:
    match tool:
        case "match_inventory":
            return f"match_inventory → {result['count']} devices affected"
        case "bfs_reach":
            corridor = len(result["corridor_reached"])
            return f"bfs_reach → {result['count']} reachable, {corridor} on the ambulance corridor"
        case "blast_radius":
            return f"blast_radius({result['device_id']}) → {len(result['lost'])} services lost"
        case "simulate":
            hit = result["p_corridor_compromised"]
            return f"simulate → CVaR95 {result['cvar95']:.2f}, corridor hit in {hit:.0%} of scenarios"
        case "compare":
            return f"compare → {len(result['plans'])} plans under the same budget"
        case "optimize":
            return f"optimize → {result['plan_id']}"
        case "simulate_strategy":
            verdict = "HOLE" if result["hole"] else "held"
            return (
                f"simulate_strategy({result['strategy_id']}) → CVaR {result['increase_pct']:+.1%} ({verdict})"
            )
        case "evaluate_applied":
            return (
                f"evaluate_applied → CVaR95 {result['cvar']:.2f} with {result['controls_applied']} controls"
            )
        case "quarantine_extract":
            return (
                f"quarantine_extract → typed advisory {result['advisory']['cve_id']} (no free text passed on)"
            )
        case "list_controls":
            n = len(result.get("unprotected_exposed", []))
            return f"list_controls({result['plan_id']}) → {n} exposed devices without a control"
        case "cross_check":
            n = len(result["discrepancies"])
            return "cross_check vs pinned feed → consistent" if n == 0 else f"cross_check → {n} discrepancies"
        case _:
            return tool


__all__ = ["TOOLS", "Category", "RunContext", "ToolArgError", "call", "openai_tool_specs"]
