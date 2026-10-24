"""Event loop that runs one incident end to end. Owner: C.

    advisory text ──► Sentinel ──► Analyst ──► Planner ◄──► Red-Team (≤2 rounds)
                                                   │
                                     autonomy policy / human approval
                                                   │
                                     apply in twin ──► re-simulate (verify) ──► audit

Every step emits ``AgentEvent`` objects to the run's queue (streamed to the UI over
SSE) and appends them to the audit log.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from urbanshield.schemas import AgentEvent, Constraint


async def run_incident(
    city_id: str,
    advisory_text: str,
    constraints_text: str | None = None,
    extra_constraints: list[Constraint] | None = None,
) -> AsyncIterator[AgentEvent]:
    """Run the full loop, yielding events as they happen."""
    raise NotImplementedError
    yield  # pragma: no cover  (makes this an async generator)
