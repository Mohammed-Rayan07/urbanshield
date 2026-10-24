"""Toolbox (authorise -> validate -> run -> record) and the agent tool loop. Owner: C."""

from __future__ import annotations

import json

import pytest

from fakes import ScriptedLLM, SpyLLM, make_ctx, reply
from urbanshield.agents import tools
from urbanshield.agents.loop import run_tool_loop
from urbanshield.guard.allowlist import ALLOWLIST, ToolNotAllowed
from urbanshield.schemas import AgentName, EventKind


def test_disallowed_tool_is_refused_with_a_reject_event(tiny_city) -> None:
    events = []
    ctx = make_ctx(tiny_city, emit=events.append)
    with pytest.raises(ToolNotAllowed):
        tools.call(ctx, AgentName.REDTEAM, "optimize", {"budget_inr": 1, "downtime_h": 1})
    assert events[-1].kind == EventKind.REJECT and events[-1].agent == AgentName.REDTEAM
    assert ctx.results == {}


@pytest.mark.parametrize(
    "args",
    [{"sources": ["d-001"], "bogus": 1}, {"sources": "d-001x"}, {"sources": ["d-999"]}, {}],
)
def test_arguments_are_validated(tiny_city, args) -> None:
    ctx = make_ctx(tiny_city)
    with pytest.raises(tools.ToolArgError):
        tools.call(ctx, AgentName.ANALYST, "bfs_reach", args)
    assert ctx.results == {}


def test_tool_ids_are_sequential_and_results_stored(tiny_city) -> None:
    events = []
    ctx = make_ctx(tiny_city, emit=events.append)
    a = tools.call(ctx, AgentName.ANALYST, "bfs_reach", {"sources": ["d-001"]})
    b = tools.call(ctx, AgentName.ANALYST, "blast_radius", {"device_id": "d-004"})
    assert (a.id, b.id) == ("tc-001", "tc-002")
    assert ctx.results == {"tc-001": a, "tc-002": b}
    assert a.result["reached"] == ["d-001", "d-002", "d-003", "d-004", "d-005"]
    assert a.result["corridor_reached"] == ["d-004", "d-005"]
    assert b.result["lost"] == ["d-005"]
    assert [e.tool_call_id for e in events if e.kind == EventKind.TOOL_CALL] == ["tc-001", "tc-002"]


@pytest.mark.parametrize(
    "agent", [AgentName.SENTINEL, AgentName.ANALYST, AgentName.PLANNER, AgentName.REDTEAM]
)
def test_tool_specs_are_allowlisted_flat_and_stable(agent) -> None:
    specs = tools.openai_tool_specs(agent)
    names = [s["function"]["name"] for s in specs]
    assert names == sorted(names) and set(names) <= ALLOWLIST[agent]
    flat = json.dumps(specs)
    assert "$ref" not in flat and "$defs" not in flat and "anyOf" not in flat
    assert specs == tools.openai_tool_specs(agent)


def test_redteam_has_no_write_or_planning_tools() -> None:
    names = {s["function"]["name"] for s in tools.openai_tool_specs(AgentName.REDTEAM)}
    assert names == {"bfs_reach", "list_controls", "simulate_strategy"}


def test_loop_feeds_tool_errors_back_and_recovers(tiny_city) -> None:
    events = []
    script = {
        "analyst.step": [
            reply(
                calls=[("optimize", {"budget_inr": 1, "downtime_h": 1}), ("bfs_reach", {"sources": ["d-9"]})]
            ),
            reply(calls=[("bfs_reach", {"sources": ["d-001"]})]),
            reply({"recommendation": "contain", "tool_call_ids": ["tc-001"]}),
        ]
    }
    spy = SpyLLM(ScriptedLLM(script))
    ctx = make_ctx(tiny_city, llm=spy, emit=events.append)
    final, usage = run_tool_loop(ctx, AgentName.ANALYST, "analyst.step", "system", "user")
    assert final == {"recommendation": "contain", "tool_call_ids": ["tc-001"]}
    assert usage.prompt_tokens == 30 and usage.completion_tokens == 15
    assert any(e.kind == EventKind.REJECT for e in events)
    errors = [json.loads(m["content"]) for m in spy.requests[1]["messages"] if m["role"] == "tool"]
    assert len(errors) == 2 and all("error" in e for e in errors)
    ok = [json.loads(m["content"]) for m in spy.requests[2]["messages"] if m["role"] == "tool"][-1]
    assert ok["tool_call_id"] == "tc-001" and ok["tool"] == "bfs_reach"
    assert spy.requests[0]["tools"] == tools.openai_tool_specs(AgentName.ANALYST)


def test_loop_stops_at_max_steps_with_an_error_event(tiny_city) -> None:
    events = []
    script = {"analyst.step": [reply(calls=[("bfs_reach", {"sources": ["d-001"]})]) for _ in range(10)]}
    ctx = make_ctx(tiny_city, llm=ScriptedLLM(script), emit=events.append)
    final, _ = run_tool_loop(ctx, AgentName.ANALYST, "analyst.step", "s", "u", max_steps=3, default={"x": 1})
    assert final == {"x": 1}
    assert events[-1].kind == EventKind.ERROR and len(ctx.results) == 3


def test_loop_asks_again_after_non_json_answer(tiny_city) -> None:
    script = {"analyst.step": [reply("I think we should replan."), reply({"recommendation": "replan"})]}
    spy = SpyLLM(ScriptedLLM(script))
    final, _ = run_tool_loop(make_ctx(tiny_city, llm=spy), AgentName.ANALYST, "analyst.step", "s", "u")
    assert final == {"recommendation": "replan"}
    assert "JSON" in spy.requests[1]["messages"][-1]["content"]
