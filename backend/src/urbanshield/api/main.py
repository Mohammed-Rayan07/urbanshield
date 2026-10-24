"""FastAPI app. Run with ``uv run uvicorn urbanshield.api.main:app --reload``.

Every route is keyed by ``city_id`` so the service stays stateless and multi-city.
``create_app`` serves the demo fixtures (``data: "placeholder"``) until the engine's modules
are implemented, then the live pipeline (``data: "live"``); the route shapes do not change.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from urbanshield import __version__
from urbanshield.agents.engine import Engine, default_engine, engine_ready
from urbanshield.agents.llm import LLM, ReplayMiss, get_llm
from urbanshield.api import fixtures
from urbanshield.config import Settings, get_settings
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

log = logging.getLogger("urbanshield.api")


class IncidentRequest(BaseModel):
    advisory_text: str = Field(min_length=1, max_length=20_000)
    constraints_text: str | None = Field(default=None, max_length=2_000)


class IncidentStarted(BaseModel):
    run_id: str


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


class AdvisoryPreset(BaseModel):
    id: str
    kind: str
    title: str
    text: str


def create_app(
    engine: Engine | None = None,
    settings: Settings | None = None,
    *,
    live: bool | None = None,
    llm: LLM | None = None,
) -> FastAPI:
    """Build the API. ``live=None`` decides from ``engine_ready``; tests pin it explicitly."""
    settings = settings or get_settings()
    engine = engine or default_engine()
    llm = llm or get_llm(settings)
    is_live = engine_ready(engine) if live is None else live

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

    def city_or_404(city_id: str) -> City:
        city = fixtures.demo_city()
        if city.id != city_id:
            raise HTTPException(status_code=404, detail=f"unknown city {city_id!r}")
        return city

    @app.get("/api/health")
    def health() -> dict[str, str | bool]:
        # ``data`` stays "placeholder" until the routes are backed by the real pipeline; the UI
        # shows a banner so placeholder numbers can never end up in a screenshot or the video.
        return {
            "status": "ok",
            "version": __version__,
            "llm_mode": settings.llm_mode,
            "data": "live" if is_live else "placeholder",
            "engine_ready": is_live,
        }

    @app.get("/api/cities/{city_id}", response_model=City)
    def get_city(city_id: str) -> City:
        return city_or_404(city_id)

    @app.get("/api/cities/{city_id}/plans", response_model=list[Plan])
    def get_plans(city_id: str) -> list[Plan]:
        city_or_404(city_id)
        return list(fixtures.demo_plans())

    @app.post("/api/cities/{city_id}/incidents", response_model=IncidentStarted, status_code=202)
    def start_incident(city_id: str, body: IncidentRequest) -> IncidentStarted:
        city_or_404(city_id)
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

    @app.get("/api/advisories", response_model=list[AdvisoryPreset])
    def advisory_presets() -> list[AdvisoryPreset]:
        """Curated Judge Mode advisories: normal, poisoned and valid-but-wrong."""
        return [
            AdvisoryPreset(**{k: p[k] for k in ("id", "kind", "title", "text")})
            for p in quarantine.load_presets()
        ]

    @app.post("/api/quarantine/preview", response_model=QuarantinePreview)
    def quarantine_preview(body: QuarantinePreviewRequest) -> QuarantinePreview:
        """Run the real quarantine on pasted text: the typed advisory and the feed cross-check.
        Works without the city or optimiser, so Judge Mode is real as early as possible."""
        text = body.advisory_text
        advisory: Advisory | None = None
        discrepancies: list[str] = []
        error: str | None = None
        try:
            advisory = quarantine.quarantine_extract(text, llm)
        except ValueError as exc:
            error = f"rejected: {exc}"
        except ReplayMiss:
            error = "replay mode has no recording for this text"
        except Exception as exc:  # provider outage etc.: report it, never pretend it passed
            log.exception("quarantine extractor failed")
            error = f"extractor unavailable ({type(exc).__name__})"
        if advisory is not None:
            discrepancies = quarantine.cross_check(advisory, engine.feed_record)
        return QuarantinePreview(
            source_sha256=quarantine.sha256_text(text),
            flagged_spans=quarantine.flag_spans(text),
            advisory=advisory,
            discrepancies=discrepancies,
            error=error,
        )

    @app.get("/api/audit/entries", response_model=list[AuditEntry])
    def audit_entries() -> list[AuditEntry]:
        return []

    @app.get("/api/audit/verify", response_model=VerifyResult)
    def verify_audit() -> VerifyResult:
        return VerifyResult(ok=True, entries=len(fixtures.demo_events()))

    return app


app = create_app()
