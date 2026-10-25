"""Event loop that runs one incident end to end. Owner: C.

    advisory text ──► Sentinel ──► Analyst ──► Planner ◄──► Red-Team (≤2 rounds)
                                                   │
                                     autonomy policy / human approval
                                                   │
                                     apply in twin ──► re-simulate (verify) ──► audit

Plain synchronous code: every step emits ``AgentEvent`` objects through ``ctx.emit`` (the API
streams them over SSE and appends each one to the audit log) and the API runs it in a worker
thread. Human decisions arrive through an ``Approvals`` object; waiting is bounded, and a
timeout applies nothing that needs approval.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from urbanshield.agents import tools
from urbanshield.agents.analyst import assess
from urbanshield.agents.llm import ReplayMiss
from urbanshield.agents.planner import inr, run_planner, stamp
from urbanshield.agents.redteam import run_redteam
from urbanshield.agents.sentinel import SentinelResult, run_sentinel
from urbanshield.agents.tools import RunContext
from urbanshield.schemas import AgentName, Autonomy, Constraint, ConstraintKind, ControlKind, EventKind

log = logging.getLogger("urbanshield.orchestrator")

APPROVAL_TIMEOUT_S = 600.0


@dataclass(frozen=True)
class ApprovalDecision:
    plan_id: str
    approve: bool
    role: str


class Approvals(Protocol):
    def ask(
        self, request: dict[str, Any], timeout_s: float, announce: Callable[[], None]
    ) -> ApprovalDecision | None:
        """Open ``request``, then call ``announce`` (which tells the human), then block until a
        decision (None on timeout). Opening first means an instant answer is never refused."""
        ...


class ApprovalGate:
    """One pending approval at a time, handed between the API thread and the run's worker."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._decided = threading.Event()
        self._pending: dict[str, Any] | None = None
        self._decision: ApprovalDecision | None = None

    @property
    def pending(self) -> dict[str, Any] | None:
        with self._lock:
            return self._pending

    def ask(
        self, request: dict[str, Any], timeout_s: float, announce: Callable[[], None]
    ) -> ApprovalDecision | None:
        with self._lock:
            self._pending, self._decision = dict(request), None
            self._decided.clear()
        try:
            announce()
        except BaseException:
            with self._lock:
                self._pending = None
            raise
        self._decided.wait(timeout_s)
        with self._lock:
            decision, self._pending = self._decision, None
        return decision

    def submit(self, plan_id: str, approve: bool, role: str) -> bool:
        """Record a decision for the pending request; False if none is pending for ``plan_id``."""
        with self._lock:
            if self._pending is None or self._pending["plan_id"] != plan_id or self._decided.is_set():
                return False
            self._decision = ApprovalDecision(plan_id=plan_id, approve=approve, role=role)
            self._decided.set()
            return True


class _Stop(Exception):
    """End the run early (the reason has already been emitted)."""


def _human(
    ctx: RunContext, approvals: Approvals, request: dict[str, Any], timeout_s: float, ask: str
) -> bool:
    """Emit the approval request, wait, record the human's answer. True only on approval."""

    def announce() -> None:
        ctx.event(AgentName.SYSTEM, EventKind.DECISION, ask, {"approval": request})

    decision = approvals.ask(request, timeout_s, announce)
    if decision is None:
        ctx.event(
            AgentName.SYSTEM,
            EventKind.ERROR,
            f"Approval timed out after {timeout_s:g} s; nothing that needs approval was applied",
            {"approval": request},
        )
        return False
    verb = "Approved" if decision.approve else "Rejected"
    ctx.event(
        AgentName.HUMAN,
        EventKind.APPROVAL if decision.approve else EventKind.REJECT,
        f"{verb} {decision.plan_id} (role: {decision.role})",
        {"plan_id": decision.plan_id, "role": decision.role, "kind": request["kind"]},
    )
    return decision.approve


def _option(ctx: RunContext, device_id: str, kind: ControlKind) -> Any:
    return next(o for o in ctx.city.device(device_id).controls if o.kind == kind)


def _allowed_options(ctx: RunContext, device_id: str) -> list[Any]:
    """The device's options that the current constraint rows still allow."""
    device = ctx.city.device(device_id)
    rows = ctx.constraints
    forbidden = {str(c.params.get("kind")) for c in rows if c.kind == ConstraintKind.FORBID_CONTROL}
    quiet = {str(c.params.get("zone")) for c in rows if c.kind == ConstraintKind.NO_DOWNTIME_ZONE}
    return [
        o
        for o in device.controls
        if o.kind.value not in forbidden and not (device.zone in quiet and o.downtime_h > 0)
    ]


def _keep_plan(ctx: RunContext, affected: list[str], why: str) -> None:
    ctx.event(
        AgentName.SYSTEM,
        EventKind.OBSERVE,
        f"Contain: {why}; keeping the city-wide plan",
        {"affected": affected},
    )


def _contain(ctx: RunContext, affected: list[str]) -> None:
    """``contain``: re-solve the CVaR plan so every affected device gets a control. The rows go
    to the CVaR optimiser only (the audited comparison stays unconstrained by them), and only
    if the cheapest allowed controls fit the budget and the downtime window; otherwise, or if the
    solver still finds the rows infeasible, the compared plan stands."""
    allowed = [_allowed_options(ctx, d) for d in affected]
    cheapest = [min(opts, key=lambda o: o.cost_inr) for opts in allowed if opts]
    fits = (
        len(cheapest) == len(affected)
        and sum(o.cost_inr for o in cheapest) <= ctx.budget.inr
        and sum(min(o.downtime_h for o in opts) for opts in allowed) <= ctx.budget.downtime_h
    )
    if not fits:
        _keep_plan(ctx, affected, "the affected devices cannot all be covered within budget and constraints")
        return
    before = list(ctx.constraints)
    rows = [Constraint(kind=ConstraintKind.MUST_FIX, params={"device_id": d}) for d in affected]
    ctx.constraints.extend(r for r in rows if r not in ctx.constraints)
    args = {"budget_inr": ctx.budget.inr, "downtime_h": ctx.budget.downtime_h}
    try:
        record = tools.call(ctx, AgentName.PLANNER, "optimize", args)
    except Exception as exc:  # an infeasible combination: say so and keep the audited plan
        log.warning("contain re-solve failed: %s", exc)
        ctx.constraints[:] = before
        _keep_plan(ctx, affected, f"the optimiser could not satisfy the rows ({type(exc).__name__})")
        return
    stamp(ctx, record)
    ctx.candidate = ctx.plans[record.result["plan_id"]]
    ctx.event(
        AgentName.PLANNER,
        EventKind.DECISION,
        f"Contain: re-solved so the {len(affected)} affected devices get a control → {ctx.candidate.id}",
        {"must_fix": affected, "plan": ctx.candidate.model_dump(mode="json")},
        tool_call_id=record.id,
    )


def _gate_advisory(ctx: RunContext, sentinel: SentinelResult, approvals: Approvals, timeout_s: float) -> None:
    request = {
        "kind": "advisory",
        "plan_id": f"advisory-{sentinel.advisory.source_sha256[:12]}",
        "discrepancies": sentinel.discrepancies,
    }
    ask = (
        f"Approval needed: the advisory disagrees with the pinned feed ({len(sentinel.discrepancies)} fields)"
    )
    if not _human(ctx, approvals, request, timeout_s, ask):
        _finish(ctx, "Stopped: the advisory was not approved; nothing was planned or applied")
        raise _Stop


def _apply(ctx: RunContext, approvals: Approvals, timeout_s: float, residual: list[dict[str, Any]]) -> None:
    """Autonomy policy: AUTO controls apply at once, the rest wait for an approver; then verify."""
    plan = ctx.candidate
    assert plan is not None
    before = tools.call(ctx, AgentName.SYSTEM, "evaluate_applied", {})
    auto = {d: k for d, k in plan.choices.items() if _option(ctx, d, k).autonomy == Autonomy.AUTO}
    manual = {d: k for d, k in plan.choices.items() if d not in auto}
    if auto:
        ctx.applied.update(auto)
        ctx.event(
            AgentName.SYSTEM,
            EventKind.APPLY,
            f"Auto-applied {len(auto)} low-risk controls (policy: auto, no downtime)",
            {"controls": {d: k.value for d, k in sorted(auto.items())}, "plan_id": plan.id},
        )
    if manual:
        cost = sum(_option(ctx, d, k).cost_inr for d, k in manual.items())
        downtime = sum(_option(ctx, d, k).downtime_h for d, k in manual.items())
        request = {
            "kind": "plan",
            "plan_id": plan.id,
            "controls": {d: k.value for d, k in sorted(manual.items())},
            "cost_inr": cost,
            "downtime_h": downtime,
            "residual_holes": residual,
        }
        ask = f"Approval needed: {tools.count(len(manual), 'control')} with downtime in {plan.id} "
        ask += f"({inr(cost)}, {downtime:g} h)"
        if _human(ctx, approvals, request, timeout_s, ask):
            ctx.applied.update(manual)
            ctx.event(
                AgentName.SYSTEM,
                EventKind.APPLY,
                f"Applied {len(manual)} approved controls in the twin",
                {"controls": request["controls"], "plan_id": plan.id},
            )
    if ctx.enforce is not None and ctx.applied:
        _enforce(ctx, plan.id)
    after = tools.call(ctx, AgentName.SYSTEM, "evaluate_applied", {})
    b, a = before.result, after.result
    ctx.event(
        AgentName.SYSTEM,
        EventKind.APPLY,
        f"Re-simulated: CVaR95 {b['cvar']:.2f} → {a['cvar']:.2f}, {a['controls_applied']} controls in place",
        {"before": b, "after": a, "before_tool_call_id": before.id, "plan_id": plan.id},
        tool_call_id=after.id,
    )


def _enforce(ctx: RunContext, plan_id: str) -> None:
    """Compile what was applied into signed policy and install it at the Enforcer; report the corridor
    paths before and after. A refused policy is an ERROR event: the twin is planned, nothing enforced."""
    assert ctx.enforce is not None
    try:
        report = ctx.enforce(plan_id, dict(ctx.applied))
    except ValueError as exc:  # PolicyRejected
        ctx.event(AgentName.SYSTEM, EventKind.ERROR, f"Enforcer refused the policy: {exc}"[:280], {})
        return
    before, after = report["corridor_before"]["status"], report["corridor_after"]["status"]
    ctx.event(
        AgentName.SYSTEM,
        EventKind.APPLY,
        f"Enforced signed policy v{report['version']} ({tools.count(report['rules'], 'rule')}, "
        f"{report['apply_ms']:g} ms): corridor paths {before} → {after}",
        {"enforcement": report, "plan_id": plan_id},
    )


def _finish(ctx: RunContext, summary: str, payload: dict[str, Any] | None = None) -> None:
    ctx.event(AgentName.SYSTEM, EventKind.DECISION, summary, payload or {})


def run_incident(
    ctx: RunContext,
    advisory_text: str,
    constraints_text: str | None,
    approvals: Approvals,
    timeout_s: float = APPROVAL_TIMEOUT_S,
) -> None:
    """Run the full loop, emitting events as they happen. Never raises: a failure becomes an
    ERROR event (and is logged), so a run cannot end silently."""
    try:
        ctx.event(AgentName.SYSTEM, EventKind.OBSERVE, f"Incident started (LLM mode: {ctx.llm.mode})", {})
        sentinel = run_sentinel(ctx, advisory_text)
        if sentinel is None:
            return _finish(ctx, "Stopped: the advisory could not be read; nothing was planned or applied")
        if sentinel.decision == "needs_approval":
            _gate_advisory(ctx, sentinel, approvals, timeout_s)
        if not sentinel.matches:
            return _finish(ctx, "Monitor: no device is affected; nothing to plan")

        assessment = assess(ctx, sentinel.matches)
        if assessment.recommendation == "monitor":
            return _finish(ctx, "Monitor: the Analyst found no meaningful risk; nothing to plan")
        run_planner(ctx, constraints_text)
        if assessment.recommendation == "contain":
            _contain(ctx, assessment.affected)
        outcome = run_redteam(ctx)
        _apply(ctx, approvals, timeout_s, [h.model_dump() for h in outcome.residual])
        _finish(
            ctx,
            f"Run complete: {tools.count(len(ctx.applied), 'control')} in place, "
            f"{tools.count(len(outcome.holes_found), 'hole')} found",
            {"applied": {d: k.value for d, k in sorted(ctx.applied.items())}, "plan_id": ctx.candidate.id},
        )
    except _Stop:
        return
    except ReplayMiss as exc:
        ctx.event(AgentName.SYSTEM, EventKind.ERROR, f"Replay miss: {exc}"[:280], {})
    except Exception as exc:
        log.exception("run %s failed", ctx.run_id)
        ctx.event(
            AgentName.SYSTEM,
            EventKind.ERROR,
            f"Run failed ({type(exc).__name__}); nothing more was applied",
            {},
        )
