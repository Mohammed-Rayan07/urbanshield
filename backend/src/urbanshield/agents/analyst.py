"""Analyst agent: how bad is it, and do we replan, contain or monitor? Owner: C.

The model chooses which read-only tools to call and makes the call; code builds the
``Assessment`` from the tool results it cites. Citations that are not this agent's results in
this run are rejected, and any number the decision needs but the model did not cite is
computed by a tool call made by code, never taken from the model.
"""

from __future__ import annotations

from typing import Any

from urbanshield.agents import tools
from urbanshield.agents.loop import run_tool_loop
from urbanshield.agents.tools import CORRIDOR_TAG, RunContext
from urbanshield.schemas import AgentName, Assessment, EventKind, Match, ToolResult

RECOMMENDATIONS = ("replan", "contain", "monitor")
SAFE_DEFAULT = "replan"  # when in doubt, re-plan and let a human approve; never silently monitor

SYSTEM = """You are the Analyst agent of UrbanShield, which protects a simulated city's connected devices.

A new vulnerability has been matched to some devices. Investigate with your tools, then decide:
- "replan": an attack can spread to critical services (for example it reaches the ambulance-corridor
  signals, or losing the device takes dependent services down); the remediation plan must be re-optimised.
- "contain": the risk stays on the affected devices; isolate them without a full re-plan.
- "monitor": there is no meaningful risk.

How to work:
1. blast_radius for each affected device: the services lost if that device is lost.
2. bfs_reach from the affected devices: where an attacker can move next.
3. simulate once: the city-wide worst-case loss with the controls applied so far.

Never compute or state numbers yourself; the tools do. Cite the tool_call_id of every result your
decision rests on. When you have the results, reply with one JSON object and nothing else:
{"recommendation": "replan" | "contain" | "monitor", "tool_call_ids": ["tc-..."]}"""


def _user_prompt(ctx: RunContext, affected: list[str], cve_id: str) -> str:
    devices = [ctx.city.device(d) for d in affected]
    facts = {
        "cve_id": cve_id,
        "affected": [
            {
                "device_id": d.id,
                "category": d.category.value,
                "zone": d.zone,
                "firmware": d.firmware,
                "exposed": d.exposed,
                "on_ambulance_corridor": CORRIDOR_TAG in d.tags,
            }
            for d in devices
        ],
    }
    return "Matched devices (from the inventory):\n" + tools.dumps(facts)


def _citations(ctx: RunContext, final: dict[str, Any]) -> list[str]:
    """The model's citations that are this Analyst's results in this run; REJECT the rest."""
    raw = final.get("tool_call_ids")
    cited = [str(i) for i in raw] if isinstance(raw, list) else []
    own = [i for i in dict.fromkeys(cited) if i in ctx.results and ctx.results[i].agent == AgentName.ANALYST]
    bad = [i for i in dict.fromkeys(cited) if i not in own]
    if bad:
        ctx.event(
            AgentName.ANALYST,
            EventKind.REJECT,
            f"Citation rejected: {', '.join(bad[:5])[:120]} is not an Analyst result in this run",
            {"rejected_citations": bad[:20]},
        )
    return own


def assess(ctx: RunContext, matches: list[Match]) -> Assessment:
    """Investigate with BFS, blast radius and simulation tools; the LLM decides the
    recommendation, the numbers come from the tool results it cites."""
    affected = sorted({m.device_id for m in matches})
    cve_id = matches[0].cve_id if matches else "unknown"
    final, usage = run_tool_loop(
        ctx,
        AgentName.ANALYST,
        "analyst.step",
        SYSTEM,
        _user_prompt(ctx, affected, cve_id),
        default={"recommendation": SAFE_DEFAULT, "tool_call_ids": []},
    )
    recommendation = final.get("recommendation")
    if recommendation not in RECOMMENDATIONS:
        ctx.event(
            AgentName.ANALYST,
            EventKind.REJECT,
            f"Invalid recommendation {str(recommendation)[:40]!r}; using {SAFE_DEFAULT!r}",
            {"valid": list(RECOMMENDATIONS)},
        )
        recommendation = SAFE_DEFAULT

    cited = _citations(ctx, final)
    results = [ctx.results[i] for i in cited]
    if not any(r.tool == "simulate" for r in results):
        results.append(tools.call(ctx, AgentName.ANALYST, "simulate", {"n_scenarios": ctx.n_scenarios}))
    covered = {r.result["device_id"] for r in results if r.tool == "blast_radius"}
    results += [
        tools.call(ctx, AgentName.ANALYST, "blast_radius", {"device_id": d})
        for d in affected
        if d not in covered
    ]

    simulation: ToolResult = [r for r in results if r.tool == "simulate"][-1]
    lost = sorted({d for r in results if r.tool == "blast_radius" for d in r.result["lost"]})
    corridor = sorted({d for r in results if r.tool == "bfs_reach" for d in r.result["corridor_reached"]})
    assessment = Assessment(
        affected=affected,
        blast_radius=lost,
        cvar_before=simulation.result["cvar95"],
        recommendation=recommendation,
        tool_call_ids=[r.id for r in results],
    )
    reach = f", corridor reachable ({len(corridor)} signals)" if corridor else ""
    ctx.event(
        AgentName.ANALYST,
        EventKind.DECISION,
        f"Recommend {recommendation}: {len(affected)} affected, {len(lost)} dependent services at risk, "
        f"CVaR95 {assessment.cvar_before:.2f}{reach}",
        {"assessment": assessment.model_dump(), "corridor_reached": corridor},
        tool_call_id=simulation.id,
        usage=usage,
    )
    return assessment
