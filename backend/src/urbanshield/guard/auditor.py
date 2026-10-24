"""The Auditor: deterministic code that checks every number an agent states. Owner: S.

An agent never writes a number in prose. It emits ``Claim`` objects; each must cite a
``tool_call_id`` whose stored result contains ``metric`` for both plans, and the
values must match (relative tolerance 1e-6). ``delta`` must equal ``plan_b - plan_a``.
Anything else is rejected with a reason, and the rejection rate is shown in the UI.

Tool results store per-plan metrics as::

    {"plans": {"<plan_id>": {"cvar": 12.3, "mean_loss": 4.5, ...}}, "a": "<plan_id>", "b": "<plan_id>"}
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field

from urbanshield.schemas import DEFAULT_ALPHA, Claim, ToolResult

REL_TOL = 1e-6
ABS_TOL = 1e-9  # so a true delta of 0 survives float error

_LABELS = {
    "cvar": f"Worst-case loss (CVaR {DEFAULT_ALPHA:.0%})",
    "mean_loss": "Expected loss",
    "max_cascade": "Largest cascade",
}


@dataclass(frozen=True)
class Rejection:
    claim: Claim
    reason: str


@dataclass(frozen=True)
class AuditVerdict:
    accepted: list[Claim] = field(default_factory=list)
    rejected: list[Rejection] = field(default_factory=list)

    @property
    def rejection_rate(self) -> float:
        total = len(self.accepted) + len(self.rejected)
        return len(self.rejected) / total if total else 0.0


def check_claims(claims: list[Claim], tool_results: Mapping[str, ToolResult]) -> AuditVerdict:
    """Accept a claim only if its cited tool result records ``metric`` for both plans with
    the same values and ``delta == plan_b - plan_a``; reject everything else with a reason."""
    accepted: list[Claim] = []
    rejected: list[Rejection] = []
    for claim in claims:
        reason = _reject_reason(claim, tool_results)
        if reason is None:
            accepted.append(claim)
        else:
            rejected.append(Rejection(claim=claim, reason=reason))
    return AuditVerdict(accepted=accepted, rejected=rejected)


def _reject_reason(claim: Claim, tool_results: Mapping[str, ToolResult]) -> str | None:
    """Short human reason a claim is ungrounded, or None if it checks out."""
    tool_result = tool_results.get(claim.tool_call_id)
    if tool_result is None:
        return f"no tool call {claim.tool_call_id}"
    stored = tool_result.result
    plans = stored.get("plans")
    if not isinstance(plans, Mapping):
        return f"{claim.tool_call_id} records no plan metrics"
    for side, value in (("a", claim.plan_a), ("b", claim.plan_b)):
        plan_id = stored.get(side)
        metrics = plans.get(plan_id) if isinstance(plan_id, str) else None
        if not isinstance(metrics, Mapping):
            return f"{claim.tool_call_id} records no plan {side}"
        recorded = metrics.get(claim.metric)
        if isinstance(recorded, bool) or not isinstance(recorded, int | float):
            return f"{claim.metric} not recorded for {plan_id}"
        if not _close(value, recorded):
            return f"plan_{side} {_fmt(value)} ≠ recorded {_fmt(recorded)}"
    if not _close(claim.delta, claim.plan_b - claim.plan_a):
        return "delta ≠ plan_b − plan_a"
    return None


def _close(x: float, y: float) -> bool:
    return math.isclose(x, y, rel_tol=REL_TOL, abs_tol=ABS_TOL)


def _fmt(x: float) -> str:
    """One decimal when that is exact, otherwise enough digits to show the difference."""
    return f"{x:.1f}" if math.isclose(x, round(x, 1), abs_tol=ABS_TOL) else f"{x:.6g}"


def render(claim: Claim) -> str:
    """Templated sentence for an accepted claim, e.g.
    'Worst-case loss (CVaR 95%) falls from 41.2 to 27.9 (-32.3%).'"""
    label = _LABELS.get(claim.metric, claim.metric)
    if _close(claim.delta, 0.0):
        return f"{label} is unchanged at {_fmt(claim.plan_a)}."
    verb = "falls" if claim.delta < 0 else "rises"
    sentence = f"{label} {verb} from {_fmt(claim.plan_a)} to {_fmt(claim.plan_b)}"
    if claim.plan_a == 0:
        return f"{sentence}."
    pct = claim.delta / abs(claim.plan_a) * 100
    return f"{sentence} ({'−' if pct < 0 else '+'}{abs(pct):.1f}%)."
