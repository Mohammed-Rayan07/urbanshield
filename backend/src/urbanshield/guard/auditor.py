"""The Auditor: deterministic code that checks every number an agent states. Owner: A (after h6).

An agent never writes a number in prose. It emits ``Claim`` objects; each must cite a
``tool_call_id`` whose stored result contains ``metric`` for both plans, and the
values must match (relative tolerance 1e-6). ``delta`` must equal ``plan_b - plan_a``.
Anything else is rejected with a reason, and the rejection rate is shown in the UI.

Tool results store per-plan metrics as::

    {"plans": {"<plan_id>": {"cvar": 12.3, "mean_loss": 4.5, ...}}, "a": "<plan_id>", "b": "<plan_id>"}
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from urbanshield.schemas import Claim, ToolResult


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
    raise NotImplementedError


def render(claim: Claim) -> str:
    """Templated sentence for an accepted claim, e.g.
    'Worst-case loss (CVaR 95%) falls from 41.2 to 27.9 (-32.3%).'"""
    raise NotImplementedError
