"""FastAPI app. Run with ``uv run uvicorn urbanshield.api.main:app --reload``.

Every route is keyed by ``city_id`` so the service stays stateless and multi-city.
Until the live pipeline lands, routes serve the demo fixtures; the shapes do not change.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from urbanshield import __version__
from urbanshield.api import fixtures
from urbanshield.config import get_settings
from urbanshield.guard import quarantine
from urbanshield.schemas import (
    Advisory,
    AgentEvent,
    AgentName,
    AuditEntry,
    City,
    EventKind,
    Plan,
    ToolResult,
    VerifyResult,
)

settings = get_settings()

app = FastAPI(
    title="UrbanShield API",
    version=__version__,
    description="Tail-risk-aware cyber resilience planning for connected city infrastructure.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Role"],
)


class IncidentRequest(BaseModel):
    advisory_text: str = Field(min_length=1, max_length=20_000)
    constraints_text: str | None = Field(default=None, max_length=2_000)


class IncidentStarted(BaseModel):
    run_id: str


def _city_or_404(city_id: str) -> City:
    city = fixtures.demo_city()
    if city.id != city_id:
        raise HTTPException(status_code=404, detail=f"unknown city {city_id!r}")
    return city


@app.get("/api/health")
def health() -> dict[str, str]:
    # ``data`` stays "placeholder" until the routes are backed by the real pipeline; the UI
    # shows a banner so placeholder numbers can never end up in a screenshot or the video.
    return {"status": "ok", "version": __version__, "llm_mode": settings.llm_mode, "data": "placeholder"}


@app.get("/api/cities/{city_id}", response_model=City)
def get_city(city_id: str) -> City:
    return _city_or_404(city_id)


@app.get("/api/cities/{city_id}/plans", response_model=list[Plan])
def get_plans(city_id: str) -> list[Plan]:
    _city_or_404(city_id)
    return list(fixtures.demo_plans())


@app.post("/api/cities/{city_id}/incidents", response_model=IncidentStarted, status_code=202)
def start_incident(city_id: str, body: IncidentRequest) -> IncidentStarted:
    _city_or_404(city_id)
    return IncidentStarted(run_id="run-placeholder")


@app.get("/api/runs/{run_id}/events")
async def stream_events(run_id: str) -> StreamingResponse:
    """Server-Sent Events: one ``AgentEvent`` JSON per ``data:`` line, then ``event: done``."""

    async def gen() -> AsyncIterator[str]:
        for event in fixtures.demo_events():
            yield f"data: {event.model_dump_json()}\n\n"
            await asyncio.sleep(0.6)
        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


class ApprovalRequest(BaseModel):
    plan_id: str
    approve: bool = True


class QuarantinePreviewRequest(BaseModel):
    advisory_text: str = Field(min_length=1, max_length=20_000)


class QuarantinePreview(BaseModel):
    """What the planner would receive for this text. ``advisory`` is the only thing
    that ever leaves quarantine; the raw text never does."""

    source_sha256: str
    flagged_spans: list[tuple[int, int]]
    advisory: Advisory | None
    discrepancies: list[str]
    error: str | None = None


@app.post("/api/runs/{run_id}/approvals", response_model=AgentEvent)
def approve(run_id: str, body: ApprovalRequest) -> AgentEvent:
    return AgentEvent(
        id=f"ev-approval-{body.plan_id}",
        city_id=fixtures.demo_city().id,
        run_id=run_id,
        agent=AgentName.HUMAN,
        kind=EventKind.APPROVAL if body.approve else EventKind.REJECT,
        summary=f"{'Approved' if body.approve else 'Rejected'} {body.plan_id}",
    )


@app.get("/api/tool-results/{tool_call_id}", response_model=ToolResult)
def get_tool_result(tool_call_id: str) -> ToolResult:
    """Provenance: the inputs and output behind any number on screen."""
    event = next((e for e in fixtures.demo_events() if e.tool_call_id == tool_call_id), None)
    plan = next((p for p in fixtures.demo_plans() if p.tool_call_id == tool_call_id), None)
    if event is None and plan is None:
        raise HTTPException(status_code=404, detail=f"unknown tool call {tool_call_id!r}")
    return ToolResult(
        id=tool_call_id,
        tool="optimize" if plan else event.summary.split(" ", 1)[0],
        agent=AgentName.PLANNER if plan else event.agent,
        args={"placeholder": True},
        result=plan.model_dump(mode="json") if plan else {"summary": event.summary},
        ts=event.ts if event else fixtures.demo_events()[0].ts,
    )


@app.post("/api/quarantine/preview", response_model=QuarantinePreview)
def quarantine_preview(body: QuarantinePreviewRequest) -> QuarantinePreview:
    return QuarantinePreview(
        source_sha256=quarantine.sha256_text(body.advisory_text),
        flagged_spans=quarantine.flag_spans(body.advisory_text),
        advisory=None,
        discrepancies=[],
        error="extractor not implemented yet",
    )


@app.get("/api/audit/entries", response_model=list[AuditEntry])
def audit_entries() -> list[AuditEntry]:
    return []


@app.get("/api/audit/verify", response_model=VerifyResult)
def verify_audit() -> VerifyResult:
    return VerifyResult(ok=True, entries=len(fixtures.demo_events()))
