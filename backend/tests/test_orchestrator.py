"""A full incident on the fake engine: event sequence, approvals, determinism, quarantine. Owner: C."""

from __future__ import annotations

import threading
from dataclasses import replace

import pytest

from fakes import TEST_ADVISORIES, ScriptedLLM, SpyLLM, make_ctx, reply
from urbanshield.agents.mock import MockLLM
from urbanshield.agents.orchestrator import ApprovalDecision, ApprovalGate, run_incident
from urbanshield.guard.quarantine import load_presets
from urbanshield.schemas import AgentName, Autonomy, EventKind

PRESETS = {p["id"]: p["text"] for p in load_presets(TEST_ADVISORIES)}
FESTIVAL = "Z1 festival this weekend, no streetlight downtime"


class Always:
    """Approvals that answer immediately (or never, with ``approve=None``)."""

    def __init__(self, approve: bool | None) -> None:
        self.approve = approve
        self.asked: list[dict] = []

    def ask(self, request: dict, timeout_s: float, announce) -> ApprovalDecision | None:
        announce()
        self.asked.append(request)
        if self.approve is None:
            return None
        return ApprovalDecision(plan_id=request["plan_id"], approve=self.approve, role="approver")


def _run(tiny_city, approvals, text=PRESETS["normal_01_lumenos"], llm=None, constraints=FESTIVAL):
    events = []
    ctx = make_ctx(tiny_city, emit=events.append, llm=llm)
    run_incident(ctx, text, constraints, approvals, timeout_s=0.05)
    return ctx, events


def _autonomy(city, device_id, kind):
    return next(o.autonomy for o in city.device(device_id).controls if o.kind == kind)


def _in_order(events, expected) -> bool:
    it = iter((e.agent, e.kind) for e in events)
    return all(step in it for step in expected)


def test_full_incident_emits_the_expected_sequence(tiny_city) -> None:
    ctx, events = _run(tiny_city, Always(True))
    A, K = AgentName, EventKind
    assert _in_order(
        events,
        [
            (A.SYSTEM, K.OBSERVE),
            (A.SENTINEL, K.OBSERVE),
            (A.SENTINEL, K.DECISION),
            (A.ANALYST, K.TOOL_CALL),
            (A.ANALYST, K.DECISION),
            (A.PLANNER, K.DECISION),  # constraint row
            (A.PLANNER, K.TOOL_CALL),  # compare
            (A.AUDITOR, K.DECISION),
            (A.PLANNER, K.DECISION),  # candidate
            (A.REDTEAM, K.TOOL_CALL),
            (A.REDTEAM, K.DECISION),
            (A.SYSTEM, K.APPLY),  # auto-applied by policy
            (A.SYSTEM, K.DECISION),  # approval request
            (A.HUMAN, K.APPROVAL),
            (A.SYSTEM, K.APPLY),  # approved controls
            (A.SYSTEM, K.APPLY),  # re-simulated
            (A.SYSTEM, K.DECISION),  # run complete
        ],
    ), [(e.agent.value, e.kind.value, e.summary) for e in events]
    assert ctx.applied == dict(ctx.candidate.choices)
    verify = events[-2]
    assert verify.kind == EventKind.APPLY and "Re-simulated" in verify.summary
    before, after = verify.payload["before"], verify.payload["after"]
    assert after["cvar"] <= before["cvar"]
    assert ctx.results[verify.tool_call_id].tool == "evaluate_applied"
    assert len({e.id for e in events}) == len(events)


def test_rejection_keeps_only_auto_applied_controls(tiny_city) -> None:
    ctx, events = _run(tiny_city, Always(False))
    auto = {d: k for d, k in ctx.candidate.choices.items() if _autonomy(tiny_city, d, k) == Autonomy.AUTO}
    assert ctx.applied == auto
    assert any(e.agent == AgentName.HUMAN and e.kind == EventKind.REJECT for e in events)


def test_approval_timeout_applies_nothing_that_needs_approval(tiny_city) -> None:
    ctx, events = _run(tiny_city, Always(None))
    assert all(_autonomy(tiny_city, d, k) == Autonomy.AUTO for d, k in ctx.applied.items())
    assert any("timed out" in e.summary and "nothing" in e.summary for e in events)


def test_feed_discrepancy_needs_approval_before_anything_runs(tiny_city) -> None:
    approvals = Always(False)
    ctx, events = _run(tiny_city, approvals, text=PRESETS["wrong_01_cvss_downgrade"])
    assert approvals.asked[0]["kind"] == "advisory"
    assert ctx.applied == {} and not any(e.agent == AgentName.ANALYST for e in events)


def test_approved_discrepancy_continues(tiny_city) -> None:
    approvals = Always(True)
    _, events = _run(tiny_city, approvals, text=PRESETS["wrong_01_cvss_downgrade"])
    assert [r["kind"] for r in approvals.asked] == ["advisory", "plan"]
    assert any(e.agent == AgentName.ANALYST for e in events)


def test_monitor_stops_after_the_analyst(tiny_city) -> None:
    script = {"analyst.step": [reply({"recommendation": "monitor", "tool_call_ids": []})]}
    ctx, events = _run(tiny_city, Always(True), llm=ScriptedLLM(script))
    assert ctx.candidate is None and ctx.applied == {}
    assert not any(e.agent == AgentName.PLANNER for e in events)


def test_contain_makes_affected_devices_must_fix(tiny_city) -> None:
    script = {"analyst.step": [reply({"recommendation": "contain", "tool_call_ids": []})]}
    ctx, _ = _run(tiny_city, Always(True), llm=ScriptedLLM(script), constraints=None)
    assert {"d-001", "d-002"} <= set(ctx.candidate.choices)


def test_contain_that_cannot_be_satisfied_keeps_the_compared_plan(tiny_city) -> None:
    script = {"analyst.step": [reply({"recommendation": "contain", "tool_call_ids": []})]}
    text = FESTIVAL + ". No credential rotation."
    ctx, events = _run(tiny_city, Always(True), llm=ScriptedLLM(script), constraints=text)
    assert any("keeping the city-wide plan" in e.summary for e in events)
    assert not any(c.kind.value == "must_fix" for c in ctx.constraints)
    assert events[-1].summary.startswith("Run complete")


def test_unextractable_advisory_stops_cleanly(tiny_city) -> None:
    ctx, events = _run(tiny_city, Always(True), text="lights are flickering")
    assert ctx.applied == {} and events[-1].agent == AgentName.SYSTEM
    assert any(e.kind == EventKind.ERROR for e in events)


def test_a_crash_becomes_an_error_event_not_silence(tiny_city) -> None:
    def broken(*args, **kwargs):
        raise RuntimeError("solver exploded")

    events = []
    ctx = make_ctx(tiny_city, emit=events.append)
    ctx.engine = replace(ctx.engine, compare=broken)
    run_incident(ctx, PRESETS["normal_01_lumenos"], None, Always(True), timeout_s=0.05)
    assert events[-1].kind == EventKind.ERROR and "RuntimeError" in events[-1].summary
    assert ctx.applied == {}


def test_raw_advisory_reaches_only_the_quarantined_extractor(tiny_city) -> None:
    spy = SpyLLM(MockLLM())
    text = PRESETS["poisoned_02_role_override"]
    _run(tiny_city, Always(True), text=text, llm=spy)
    tasks = {r["task"] for r in spy.requests}
    assert {"sentinel.extract", "analyst.step", "planner.claims", "redteam.propose"} <= tasks
    for request in spy.requests:
        blob = str(request["messages"])
        if request["task"] == "sentinel.extract":
            assert "administrator rights" in blob and request["tools"] is None
        else:
            assert "administrator rights" not in blob and "SYSTEM PROMPT UPDATE" not in blob
            assert "VSA-24-011" not in blob


def test_identical_runs_send_identical_llm_requests(tiny_city) -> None:
    transcripts = []
    for run_id in ("run-a", "run-b"):
        spy = SpyLLM(MockLLM())
        ctx = make_ctx(tiny_city, llm=spy, run_id=run_id)
        run_incident(ctx, PRESETS["normal_01_lumenos"], FESTIVAL, Always(True), timeout_s=0.05)
        transcripts.append(spy.transcript())
    assert transcripts[0] == transcripts[1]
    assert "run-a" not in transcripts[0]


def test_gate_hands_a_decision_across_threads() -> None:
    gate = ApprovalGate()
    request = {"plan_id": "plan-x", "kind": "plan"}
    result = {}
    worker = threading.Thread(
        target=lambda: result.setdefault("d", gate.ask(request, timeout_s=5, announce=lambda: None))
    )
    worker.start()
    for _ in range(500):
        if gate.pending:
            break
        threading.Event().wait(0.01)
    assert gate.pending == request
    assert not gate.submit("plan-other", True, "approver")
    assert gate.submit("plan-x", True, "approver")
    worker.join(5)
    assert result["d"] == ApprovalDecision("plan-x", True, "approver") and gate.pending is None


def test_gate_accepts_an_answer_given_the_moment_it_is_announced() -> None:
    gate = ApprovalGate()
    accepted = []
    decision = gate.ask(
        {"plan_id": "plan-x", "kind": "plan"},
        5,
        lambda: accepted.append(gate.submit("plan-x", True, "approver")),
    )
    assert accepted == [True] and decision == ApprovalDecision("plan-x", True, "approver")


def test_gate_times_out() -> None:
    assert ApprovalGate().ask({"plan_id": "p", "kind": "plan"}, 0.01, lambda: None) is None


@pytest.mark.parametrize("approve", [True, False])
def test_gate_refuses_when_nothing_is_pending(approve) -> None:
    assert not ApprovalGate().submit("plan-x", approve, "approver")
