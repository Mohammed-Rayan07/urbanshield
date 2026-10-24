"""Analyst and Planner: decisions by the model, numbers from cited tool results. Owner: C."""

from __future__ import annotations

import pytest

from fakes import TEST_ADVISORIES, ScriptedLLM, SpyLLM, make_ctx, reply
from urbanshield.agents.analyst import assess
from urbanshield.agents.planner import parse_constraints, run_planner
from urbanshield.agents.sentinel import run_sentinel
from urbanshield.guard.quarantine import load_presets, sha256_text
from urbanshield.schemas import AgentName, ConstraintKind, EventKind

PRESETS = {p["id"]: p["text"] for p in load_presets(TEST_ADVISORIES)}


def _sentinel(ctx, preset="normal_01_lumenos"):
    result = run_sentinel(ctx, PRESETS[preset])
    assert result is not None
    return result


# ---------------------------------------------------------------- analyst


def test_assessment_numbers_come_from_cited_results(tiny_city) -> None:
    events = []
    ctx = make_ctx(tiny_city, emit=events.append)
    a = assess(ctx, _sentinel(ctx).matches)
    assert a.affected == ["d-001", "d-002"]
    assert a.recommendation == "replan"  # the lumenos chain reaches the corridor via the gateway
    assert set(a.tool_call_ids) <= set(ctx.results)
    sims = [ctx.results[i] for i in a.tool_call_ids if ctx.results[i].tool == "simulate"]
    assert len(sims) == 1 and a.cvar_before == sims[0].result["cvar95"]
    lost = {
        d
        for i in a.tool_call_ids
        if ctx.results[i].tool == "blast_radius"
        for d in ctx.results[i].result["lost"]
    }
    assert a.blast_radius == sorted(lost)
    decision = events[-1]
    assert decision.agent == AgentName.ANALYST and decision.kind == EventKind.DECISION
    assert decision.payload["assessment"] == a.model_dump()


def test_invented_citations_are_rejected_and_numbers_still_come_from_tools(tiny_city) -> None:
    events = []
    script = {"analyst.step": [reply({"recommendation": "contain", "tool_call_ids": ["tc-999", "tc-001"]})]}
    ctx = make_ctx(tiny_city, llm=ScriptedLLM(script), emit=events.append)
    a = assess(ctx, _sentinel(ctx).matches)
    assert "tc-999" not in a.tool_call_ids
    assert "tc-001" not in a.tool_call_ids  # exists, but it is the Sentinel's, not the Analyst's
    rejects = [e for e in events if e.kind == EventKind.REJECT]
    assert rejects and "tc-999" in rejects[0].summary
    sim = next(ctx.results[i] for i in a.tool_call_ids if ctx.results[i].tool == "simulate")
    assert a.cvar_before == sim.result["cvar95"] and a.recommendation == "contain"


def test_citations_about_unaffected_devices_do_not_inflate_the_blast_radius(tiny_city) -> None:
    script = {
        "analyst.step": [
            reply(calls=[("blast_radius", {"device_id": "d-004"})]),  # d-005 depends on d-004
            reply({"recommendation": "replan", "tool_call_ids": ["tc-004"]}),
        ]
    }
    ctx = make_ctx(tiny_city, llm=ScriptedLLM(script))
    a = assess(ctx, _sentinel(ctx).matches)
    assert ctx.results["tc-004"].result["lost"] == ["d-005"]
    assert a.blast_radius == []  # d-001/d-002 take nothing down with them


def test_invalid_recommendation_falls_back_to_replan(tiny_city) -> None:
    events = []
    script = {"analyst.step": [reply({"recommendation": "ignore it", "tool_call_ids": []})]}
    ctx = make_ctx(tiny_city, llm=ScriptedLLM(script), emit=events.append)
    a = assess(ctx, _sentinel(ctx).matches)
    assert a.recommendation == "replan"
    assert any(e.kind == EventKind.REJECT and "recommendation" in e.summary for e in events)


# ---------------------------------------------------------------- planner: constraints


def _rows(ctx, text):
    return [(c.kind, c.params) for c in parse_constraints(ctx, text)]


def test_constraint_text_becomes_validated_rows(tiny_city) -> None:
    events = []
    ctx = make_ctx(tiny_city, emit=events.append)
    text = "Z1 festival this weekend, no streetlight downtime. Must fix d-006. No segmentation."
    rows = parse_constraints(ctx, text)
    assert {(c.kind, tuple(c.params.items())) for c in rows} == {
        (ConstraintKind.NO_DOWNTIME_ZONE, (("zone", "Z1"),)),
        (ConstraintKind.MUST_FIX, (("device_id", "d-006"),)),
        (ConstraintKind.FORBID_CONTROL, (("kind", "segment"),)),
    }
    assert all(c.source_sha256 == sha256_text(text) for c in rows)
    assert sum(e.kind == EventKind.DECISION for e in events) == 3


@pytest.mark.parametrize(
    ("text", "valid"),
    [
        ("Zone 9 festival, no downtime in Zone 9", ["Z1", "Z2", "Z3"]),
        ("must fix d-042", ["d-001", "d-002", "d-003", "d-004", "d-005", "d-006"]),
    ],
)
def test_unknown_zones_and_devices_are_rejected_not_guessed(tiny_city, text, valid) -> None:
    events = []
    ctx = make_ctx(tiny_city, emit=events.append)
    assert parse_constraints(ctx, text) == []
    [reject] = [e for e in events if e.kind == EventKind.REJECT]
    assert reject.agent == AgentName.PLANNER and reject.payload["valid"] == valid


def test_budget_and_downtime_phrases_set_the_budget(tiny_city) -> None:
    ctx = make_ctx(tiny_city)
    assert parse_constraints(ctx, "Budget ₹1.5 lakh and at most 6 hours of downtime.") == []
    assert (ctx.budget.inr, ctx.budget.downtime_h) == (150_000, 6.0)


def test_unparseable_constraint_output_rejects_everything(tiny_city) -> None:
    events = []
    script = {"planner.constraints": [reply("sure, no downtime anywhere!")]}
    ctx = make_ctx(tiny_city, llm=ScriptedLLM(script), emit=events.append)
    assert parse_constraints(ctx, "no downtime in Z1") == []
    assert events[-1].kind == EventKind.REJECT


def test_malformed_rows_are_rejected_individually(tiny_city) -> None:
    rows = [
        {"kind": "no_downtime_zone", "params": {"zone": "z2"}},  # case-normalised to Z2
        {"kind": "teleport", "params": {}},
        {"kind": "forbid_control", "params": {"kind": "nuke"}},
        {"kind": "budget", "params": {"inr": -5}},
        {"kind": "downtime", "params": {"hours": float("inf")}},
        {"kind": "budget", "params": {"inr": 0.5}},
    ]
    events = []
    ctx = make_ctx(
        tiny_city,
        llm=ScriptedLLM({"planner.constraints": [reply({"constraints": rows})]}),
        emit=events.append,
    )
    assert _rows(ctx, "anything") == [(ConstraintKind.NO_DOWNTIME_ZONE, {"zone": "Z2"})]
    assert sum(e.kind == EventKind.REJECT for e in events) == 5


# ---------------------------------------------------------------- planner: plan + claims


def test_planner_proposes_the_cvar_plan_with_audited_claims(tiny_city) -> None:
    events = []
    ctx = make_ctx(tiny_city, emit=events.append)
    plan = run_planner(ctx, "Z1 festival, no streetlight downtime")
    assert plan is not None and plan.objective.value == "cvar" and ctx.candidate == plan
    compare = ctx.results[plan.tool_call_id]
    assert compare.tool == "compare" and compare.result["b"] == plan.id
    z1 = {d.id for d in tiny_city.devices if d.zone == "Z1"}
    options = {(d.id, o.kind): o for d in tiny_city.devices for o in d.controls}
    assert all(options[(d, k)].downtime_h == 0 for d, k in plan.choices.items() if d in z1)
    audit = next(e for e in events if e.agent == AgentName.AUDITOR and e.kind == EventKind.DECISION)
    assert audit.payload["accepted"] and audit.payload["rejected"] == []
    assert all(ctx.plans[p].tool_call_id == compare.id for p in compare.result["plans"])


def test_claims_citing_unknown_tool_calls_are_rejected(tiny_city) -> None:
    events = []
    script = {
        "planner.claims": [
            reply(
                {
                    "claims": [
                        {
                            "metric": "cvar",
                            "plan_a": 1.0,
                            "plan_b": 0.5,
                            "delta": -0.5,
                            "tool_call_id": "tc-404",
                        }
                    ]
                }
            )
        ]
    }
    ctx = make_ctx(tiny_city, llm=ScriptedLLM(script), emit=events.append)
    run_planner(ctx, None)
    audit = next(e for e in events if e.agent == AgentName.AUDITOR and e.kind == EventKind.DECISION)
    assert audit.payload["accepted"] == [] and "tc-404" in audit.payload["rejected"][0]["reason"]
    assert any(e.agent == AgentName.AUDITOR and e.kind == EventKind.REJECT for e in events)


def test_malformed_claims_count_as_rejections(tiny_city) -> None:
    events = []
    script = {"planner.claims": [reply({"claims": [{"metric": "cvar", "plan_a": "forty"}, "nope"]})]}
    ctx = make_ctx(tiny_city, llm=ScriptedLLM(script), emit=events.append)
    run_planner(ctx, None)
    audit = next(e for e in events if e.agent == AgentName.AUDITOR and e.kind == EventKind.DECISION)
    assert len(audit.payload["rejected"]) == 2 and audit.payload["rejection_rate"] == 1.0


def test_later_agents_never_see_the_raw_advisory(tiny_city) -> None:
    spy = SpyLLM(ScriptedLLM({}))
    ctx = make_ctx(tiny_city, llm=spy)
    text = PRESETS["poisoned_01_ignore_previous"]
    assess(ctx, _sentinel(ctx, "poisoned_01_ignore_previous").matches)
    run_planner(ctx, "Z1 festival, no streetlight downtime")
    later = [r for r in spy.requests if r["task"] != "sentinel.extract"]
    assert {r["task"] for r in later} >= {"analyst.step", "planner.constraints", "planner.claims"}
    blob = str([r["messages"] for r in later])
    assert text not in blob and "ignore previous" not in blob.lower() and "LSB-2025-07" not in blob
