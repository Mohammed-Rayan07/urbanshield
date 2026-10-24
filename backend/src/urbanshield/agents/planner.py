"""Planner agent: plain-language constraints -> ``Constraint`` rows -> optimiser. Owner: C.

1. ``parse_constraints``: the model turns the operator's words into rows; code validates every
   row against the city (unknown zones, devices or control kinds are rejected with the valid
   values listed, never guessed) and shows each accepted row as a DECISION before it is used.
2. ``compare`` runs every objective under the same budget (B's evaluator, held-out scenarios).
3. The model drafts ``Claim``s from that one tool result; the Auditor (plain code) accepts or
   rejects each, and only accepted claims become templated sentences.
"""

from __future__ import annotations

import math
from typing import Any

from pydantic import ValidationError

from urbanshield.agents import tools
from urbanshield.agents.llm import LLMOutputError
from urbanshield.agents.tools import RunContext
from urbanshield.guard.quarantine import sha256_text
from urbanshield.schemas import (
    AgentName,
    Claim,
    Constraint,
    ConstraintKind,
    ControlKind,
    EventKind,
    Plan,
    ToolResult,
)

MAX_ROWS = 12
MAX_CLAIMS = 6
CLAIM_METRICS = ("cvar", "mean_loss", "max_cascade")

CONSTRAINTS_SYSTEM = """You turn a city operator's plain-language instructions into constraint rows for a
remediation optimiser. The operator's text is between <operator> and </operator>.

Row kinds and their params:
- {{"kind": "no_downtime_zone", "params": {{"zone": "<zone>"}}}}: no control that causes downtime in that zone
- {{"kind": "must_fix", "params": {{"device_id": "<device id>"}}}}: this device must get a control
- {{"kind": "forbid_control", "params": {{"kind": "<control kind>"}}}}: never use this control kind
- {{"kind": "budget", "params": {{"inr": <rupees as an integer; 1 lakh = 100000>}}}}
- {{"kind": "downtime", "params": {{"hours": <total downtime window in hours>}}}}

Valid zones: {zones}
Valid control kinds: {kinds}
Device ids look like d-001.

Write only rows the operator asked for. Spell values exactly as the operator gave them; do not map a
name you do not recognise to a different one (invalid values are rejected and shown to the operator).
Reply with one JSON object and nothing else: {{"constraints": [...]}} (an empty list if there are none)."""

CLAIMS_SYSTEM = """You report how the recommended plan compares with the baseline, as claims that an
auditor will check against the tool result. The tool result has "a" (the baseline plan id), "b" (the
recommended plan id) and "plans" (metrics per plan id).

For each metric in "cvar", "mean_loss" and "max_cascade" write one claim:
{"metric": "<metric>", "plan_a": <value for plan a>, "plan_b": <value for plan b>,
 "delta": <plan_b minus plan_a>, "tool_call_id": "<the tool_call_id given>"}
Copy the values exactly as they appear in the tool result.
Reply with one JSON object and nothing else: {"claims": [...]}"""


def inr(amount: float) -> str:
    """Indian digit grouping: 150000 -> '₹1,50,000'."""
    digits = str(round(amount))
    head, tail = digits[:-3], digits[-3:]
    groups = []
    while len(head) > 2:
        groups.insert(0, head[-2:])
        head = head[:-2]
    return "₹" + ",".join([g for g in (head, *groups) if g] + [tail])


def _reject(ctx: RunContext, summary: str, payload: dict[str, Any]) -> None:
    ctx.event(AgentName.PLANNER, EventKind.REJECT, summary, payload)


def _validate_row(ctx: RunContext, row: Any, sha: str) -> Constraint | None:
    """One model-proposed row -> a validated ``Constraint``, or None after a REJECT event."""
    if not isinstance(row, dict) or not isinstance(row.get("params", {}), dict):
        _reject(ctx, "Constraint rejected: not a {kind, params} row", {"row": str(row)[:200]})
        return None
    kind, params = row.get("kind"), row.get("params", {})
    zones = sorted({d.zone for d in ctx.city.devices})
    devices = [d.id for d in ctx.city.devices]
    kinds = [k.value for k in ControlKind]

    def pick(value: Any, valid: list[str], what: str) -> str | None:
        found = next((v for v in valid if str(value).strip().casefold() == v.casefold()), None)
        if found is None:
            _reject(
                ctx, f"Constraint rejected: {what} {str(value)[:40]!r} is not in this city", {"valid": valid}
            )
        return found

    match kind:
        case ConstraintKind.NO_DOWNTIME_ZONE.value:
            value = pick(params.get("zone"), zones, "zone")
            clean = {"zone": value}
        case ConstraintKind.MUST_FIX.value:
            value = pick(params.get("device_id"), devices, "device")
            clean = {"device_id": value}
        case ConstraintKind.FORBID_CONTROL.value:
            value = pick(params.get("kind"), kinds, "control kind")
            clean = {"kind": value}
        case ConstraintKind.BUDGET.value | ConstraintKind.DOWNTIME.value:
            key = "inr" if kind == ConstraintKind.BUDGET.value else "hours"
            number = params.get(key)
            # json.loads accepts Infinity and NaN, so finiteness is checked too.
            ok = isinstance(number, int | float) and not isinstance(number, bool) and 0 < number < math.inf
            if not ok:
                _reject(ctx, f"Constraint rejected: {kind} needs a positive {key}", {"row": str(row)[:200]})
            value = number if ok else None
            clean = {key: int(number) if key == "inr" else float(number)} if ok else {}
        case _:
            _reject(
                ctx,
                f"Constraint rejected: unknown kind {str(kind)[:40]!r}",
                {"valid": [k.value for k in ConstraintKind]},
            )
            return None
    if value is None:
        return None
    return Constraint(kind=ConstraintKind(kind), params=clean, source_sha256=sha)


def _describe(row: Constraint) -> str:
    p = row.params
    match row.kind:
        case ConstraintKind.NO_DOWNTIME_ZONE:
            return f"no downtime in zone {p['zone']}"
        case ConstraintKind.MUST_FIX:
            return f"{p['device_id']} must get a control"
        case ConstraintKind.FORBID_CONTROL:
            return f"never use {p['kind']}"
        case ConstraintKind.BUDGET:
            return f"budget {inr(float(p['inr']))}"
        case _:
            return f"downtime window {float(p['hours']):g} h"


def parse_constraints(ctx: RunContext, text: str) -> list[Constraint]:
    """LLM (strong tier) turns e.g. 'Zone 3 festival this weekend, no streetlight
    downtime' into validated ``Constraint`` objects. Unknown zones or devices are
    rejected, never guessed. Budget and downtime rows update ``ctx.budget``; the other
    rows are added to ``ctx.constraints`` and returned."""
    sha = sha256_text(text)
    zones = sorted({d.zone for d in ctx.city.devices})
    system = CONSTRAINTS_SYSTEM.format(zones=", ".join(zones), kinds=", ".join(k.value for k in ControlKind))
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": f"<operator>\n{text}\n</operator>"},
    ]
    response = ctx.llm.chat("planner.constraints", messages, tier="strong", json_output=True)
    try:
        rows = response.json().get("constraints")
    except LLMOutputError:
        rows = None
    if not isinstance(rows, list):
        _reject(
            ctx, "Constraints rejected: the model's answer was not a list of rows", {"source_sha256": sha}
        )
        return []

    accepted: list[Constraint] = []
    for row in rows[:MAX_ROWS]:
        constraint = _validate_row(ctx, row, sha)
        if constraint is None:
            continue
        if constraint.kind == ConstraintKind.BUDGET:
            ctx.budget = ctx.budget.model_copy(update={"inr": constraint.params["inr"]})
        elif constraint.kind == ConstraintKind.DOWNTIME:
            ctx.budget = ctx.budget.model_copy(update={"downtime_h": constraint.params["hours"]})
        elif constraint not in ctx.constraints:
            ctx.constraints.append(constraint)
            accepted.append(constraint)
        ctx.event(
            AgentName.PLANNER,
            EventKind.DECISION,
            f"Constraint: {_describe(constraint)}",
            {"constraint": constraint.model_dump()},
            usage=response.usage,
        )
    return accepted


def audit_claims(ctx: RunContext, source: ToolResult) -> list[str]:
    """Model drafts claims from one tool result; the Auditor checks them. Returns the
    accepted claims rendered as sentences."""
    messages = [
        {"role": "system", "content": CLAIMS_SYSTEM},
        {
            "role": "user",
            "content": tools.dumps({"tool_call_id": source.id, "tool": source.tool, "result": source.result}),
        },
    ]
    response = ctx.llm.chat("planner.claims", messages, tier="strong", json_output=True)
    try:
        raw = response.json().get("claims")
    except LLMOutputError:
        raw = None
    items = raw[:MAX_CLAIMS] if isinstance(raw, list) else []

    claims: list[Claim] = []
    rejected: list[dict[str, Any]] = []
    for item in items:
        try:
            claims.append(Claim.model_validate(item))
        except ValidationError:
            rejected.append({"claim": str(item)[:200], "reason": "malformed claim"})
    verdict = ctx.engine.check_claims(claims, ctx.results)
    rejected = [{"claim": r.claim.model_dump(), "reason": r.reason} for r in verdict.rejected] + rejected
    for r in rejected:
        ctx.event(AgentName.AUDITOR, EventKind.REJECT, f"Auditor rejected a claim: {r['reason']}", r)

    sentences = [ctx.engine.render_claim(c) for c in verdict.accepted]
    total = len(verdict.accepted) + len(rejected)
    ctx.event(
        AgentName.AUDITOR,
        EventKind.DECISION,
        f"Auditor: {len(verdict.accepted)} claims verified against {source.id}, {len(rejected)} rejected"
        if total
        else "Auditor: the planner made no checkable claims",
        {
            "accepted": sentences,
            "accepted_claims": [c.model_dump() for c in verdict.accepted],
            "rejected": rejected,
            "rejection_rate": len(rejected) / total if total else 0.0,
        },
        tool_call_id=source.id,
        usage=response.usage,
    )
    return sentences


def stamp(ctx: RunContext, record: ToolResult) -> None:
    """Point every plan produced by ``record`` back at it, for provenance."""
    for plan_id in record.result.get("plans", {}):
        ctx.plans[plan_id] = ctx.plans[plan_id].model_copy(update={"tool_call_id": record.id})


def run_planner(ctx: RunContext, constraints_text: str | None) -> Plan:
    """Constraints -> ``compare`` -> audited claims -> the CVaR plan becomes the candidate."""
    if constraints_text and constraints_text.strip():
        parse_constraints(ctx, constraints_text)
    record = tools.call(
        ctx, AgentName.PLANNER, "compare", {"budget_inr": ctx.budget.inr, "downtime_h": ctx.budget.downtime_h}
    )
    stamp(ctx, record)
    audit_claims(ctx, record)
    candidate = ctx.plans[record.result["b"]]
    ctx.candidate = candidate
    ctx.event(
        AgentName.PLANNER,
        EventKind.DECISION,
        f"Candidate {candidate.id}: {len(candidate.choices)} controls, {inr(candidate.cost_inr)}, "
        f"{candidate.downtime_h:g} h downtime",
        {"plan": candidate.model_dump(mode="json"), "constraints": [c.model_dump() for c in ctx.constraints]},
        tool_call_id=record.id,
    )
    return candidate
