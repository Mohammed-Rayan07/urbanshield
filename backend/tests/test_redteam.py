"""Red-Team: strategies against the plan under review, holes, replan. Owner: C."""

from __future__ import annotations

from dataclasses import replace

import numpy as np
import pytest

from fakes import ScriptedLLM, cvar, make_ctx, reply
from urbanshield.agents import redteam, tools
from urbanshield.agents.planner import run_planner
from urbanshield.agents.redteam import (
    HOLE_THRESHOLD,
    concat_losses,
    propose_strategies,
    random_search,
    run_redteam,
    score_strategy,
    strategy_from_args,
)
from urbanshield.schemas import AgentName, Budget, EventKind, ScenarioLosses, Strategy


def _planned(tiny_city, **kwargs):
    events = []
    ctx = make_ctx(tiny_city, emit=events.append, **kwargs)
    run_planner(ctx, None)
    return ctx, events


def _losses(totals: list[float], n_devices: int = 6) -> ScenarioLosses:
    loss = np.zeros((len(totals), n_devices))
    loss[:, 0] = totals
    return ScenarioLosses(
        city_id="tiny",
        seed=0,
        device_ids=tuple(f"d-00{i}" for i in range(1, n_devices + 1)),
        device_loss=loss,
        compromised=loss > 0,
        campaign_cve=(None,) * len(totals),
    )


# ---------------------------------------------------------------- strategies


def test_strategy_from_args_validates_and_normalises(tiny_city) -> None:
    ctx = make_ctx(tiny_city)
    s = strategy_from_args(ctx, {"entry_points": ["d-001"], "target_category": "signal", "campaign_cve": ""})
    assert s.entry_points == ["d-001"] and s.target_category.value == "signal" and s.campaign_cve is None
    again = strategy_from_args(ctx, {"target_category": "signal", "entry_points": ["d-001"]})
    assert s.id == again.id and s.id.startswith("s-")
    assert strategy_from_args(ctx, {"pivot_shared_firmware": True}).id != s.id


@pytest.mark.parametrize(
    "args",
    [
        {"entry_points": ["d-999"]},
        {"target_category": "toaster"},
        {"campaign_cve": "CVE-2099-0001"},  # no device carries it
        {"campaign_cve": "not-a-cve"},
    ],
)
def test_bad_strategies_are_refused(tiny_city, args) -> None:
    with pytest.raises(tools.ToolArgError):
        strategy_from_args(make_ctx(tiny_city), args)


# ---------------------------------------------------------------- scoring


@pytest.mark.parametrize(("attack_loss", "hole"), [(10.48, False), (10.52, True)])
def test_hole_only_above_threshold(tiny_city, attack_loss, hole) -> None:
    # 20 baseline scenarios at 10.0 -> CVaR95 = 10.0. Adding 20 attack scenarios, two of them
    # at ``attack_loss``, makes the tail (2 of 40) average ``attack_loss``: +4.8% vs +5.2%.
    def simulate(city, n_scenarios=20, seed=0, controls=None, strategy=None, campaign_rate=0.2):
        if strategy is None:
            return _losses([10.0] * 20)
        return _losses([attack_loss] * 2 + [1.0] * 18)

    ctx, _ = _planned(tiny_city)
    ctx.engine = replace(ctx.engine, simulate=simulate)
    probe = score_strategy(ctx, Strategy(id="s-x"))
    assert probe.cvar_before == pytest.approx(10.0)
    assert probe.cvar_after_attack == pytest.approx(attack_loss)
    assert probe.increase_pct == pytest.approx(attack_loss / 10.0 - 1)
    assert probe.hole is hole and (probe.increase_pct > HOLE_THRESHOLD) is hole


def test_scoring_needs_a_plan_under_review(tiny_city) -> None:
    with pytest.raises(tools.ToolArgError):
        score_strategy(make_ctx(tiny_city), Strategy(id="s-x"))


def test_simulator_calls_are_counted(tiny_city) -> None:
    ctx, _ = _planned(tiny_city)
    a = tools.call(ctx, AgentName.REDTEAM, "simulate_strategy", {"entry_points": ["d-001"]})
    b = tools.call(ctx, AgentName.REDTEAM, "simulate_strategy", {"pivot_shared_firmware": True})
    assert (a.result["sim_calls"], b.result["sim_calls"]) == (2, 3)  # baseline once, then one per attack
    assert set(a.result) == {
        "strategy_id",
        "cvar_before",
        "cvar_after_attack",
        "increase_pct",
        "hole",
        "sim_calls",
    }


def test_concat_losses_appends_scenarios() -> None:
    both = concat_losses(_losses([1.0, 2.0]), _losses([3.0]))
    assert both.n_scenarios == 3 and both.total.tolist() == [1.0, 2.0, 3.0]
    with pytest.raises(ValueError):
        concat_losses(_losses([1.0]), _losses([1.0], n_devices=5))


# ---------------------------------------------------------------- proposals


def test_mock_proposals_are_valid_and_deterministic(tiny_city) -> None:
    ctx, events = _planned(tiny_city)
    first = propose_strategies(ctx, [])
    again = propose_strategies(_planned(tiny_city)[0], [])
    assert 1 <= len(first) <= redteam.MAX_STRATEGIES and first == again
    assert len({s.id for s in first}) == len(first)
    assert any(e.tool_call_id and ctx.results[e.tool_call_id].tool == "list_controls" for e in events)


def test_unknown_ids_in_proposals_are_dropped_with_a_note(tiny_city) -> None:
    proposals = {
        "strategies": [
            {"entry_points": ["d-404"], "target_category": "signal"},
            {"pivot_shared_firmware": True},
            {"campaign_cve": "CVE-2099-0001"},
        ]
    }
    ctx, events = _planned(tiny_city, llm=ScriptedLLM({"redteam.propose": [reply(proposals)]}))
    strategies = propose_strategies(ctx, [])
    assert [s.pivot_shared_firmware for s in strategies] == [True]
    notes = [e for e in events if e.agent == AgentName.REDTEAM and e.kind == EventKind.REJECT]
    assert len(notes) == 2


# ---------------------------------------------------------------- loop + replan


def _linear_cvar(losses: ScenarioLosses, ctx, choices) -> float:
    keep = np.ones(len(ctx.city.devices))
    for i, d in enumerate(ctx.city.devices):
        if d.id in choices:
            option = next(o for o in d.controls if o.kind == choices[d.id])
            keep[i] = option.exploit_mult * option.spread_mult
    return cvar(losses.device_loss @ keep, ctx.budget.alpha)


def test_redteam_finds_holes_and_replan_never_increases_training_cvar(tiny_city) -> None:
    ctx, events = _planned(tiny_city)
    before = ctx.candidate
    outcome = run_redteam(ctx)
    probes = [ctx.results[e.tool_call_id] for e in events if e.kind == EventKind.TOOL_CALL]
    assert any(p.tool == "simulate_strategy" for p in probes)
    holes = [e for e in events if e.kind == EventKind.HOLE]
    assert len(holes) == len(outcome.holes_found)
    assert all(ctx.results[e.tool_call_id].result["increase_pct"] > HOLE_THRESHOLD for e in holes)
    assert outcome.rounds in (1, 2)
    if outcome.holes_found:
        after = ctx.candidate
        assert after.tool_call_id and ctx.results[after.tool_call_id].tool == "optimize"
        train = ctx.train_losses
        assert train.n_scenarios > ctx.n_scenarios  # augmented with the attack scenarios
        assert _linear_cvar(train, ctx, after.choices) <= _linear_cvar(train, ctx, before.choices) + 1e-9
    assert events[-1].agent == AgentName.REDTEAM and events[-1].kind == EventKind.DECISION


def test_replan_then_clean_second_round(tiny_city) -> None:
    script = {
        "redteam.propose": [
            reply({"strategies": [{"pivot_shared_firmware": True}]}),
            reply({"strategies": []}),
        ]
    }
    ctx, events = _planned(tiny_city, llm=ScriptedLLM(script), budget=Budget(inr=20_000, downtime_h=8))
    before = ctx.candidate
    outcome = run_redteam(ctx)
    assert outcome.rounds == 2 and len(outcome.holes_found) == 1 and outcome.residual == []
    assert ctx.candidate != before
    assert events[-1].summary.endswith("after replan")


def test_unchanged_replan_stops_early_with_residual_holes(tiny_city) -> None:
    ctx, events = _planned(tiny_city)
    outcome = run_redteam(ctx)
    assert outcome.rounds == 1 and outcome.residual and outcome.residual == outcome.holes_found
    assert "budget cannot close" in events[-1].summary


def test_no_hole_means_no_replan(tiny_city) -> None:
    ctx, events = _planned(tiny_city, llm=ScriptedLLM({"redteam.propose": [reply({"strategies": []})]}))
    candidate = ctx.candidate
    outcome = run_redteam(ctx)
    assert outcome.holes_found == [] and outcome.rounds == 1 and ctx.candidate == candidate
    assert "no hole" in events[-1].summary


def test_random_search_is_seeded_and_bounded(tiny_city) -> None:
    ctx, _ = _planned(tiny_city)
    a = random_search(ctx, budget_calls=4, seed=7)
    b = random_search(_planned(tiny_city)[0], budget_calls=4, seed=7)
    assert [p.strategy_id for p in a] == [p.strategy_id for p in b]
    assert len(a) <= 4 and all(p.sim_calls <= 5 for p in a)
