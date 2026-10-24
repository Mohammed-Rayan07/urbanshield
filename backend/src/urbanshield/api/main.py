"""FastAPI app. Run with ``uv run uvicorn urbanshield.api.main:app --reload``.

Every route is keyed by ``city_id`` so the service stays stateless and multi-city.
``create_app`` serves the demo fixtures (``data: "placeholder"``) until the engine's modules
are implemented, then the live pipeline (``data: "live"``); the route shapes do not change.

Runs execute in a worker thread (the pipeline is CPU-bound); their events are streamed over
SSE and every one is appended to the hash-chained, signed audit log before it is shown.
Approvals need the ``X-Role: approver`` header: demo RBAC, not real authentication.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import closing
from typing import Annotated, Any

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from urbanshield import __version__
from urbanshield.agents.engine import Engine, default_engine, engine_ready
from urbanshield.agents.llm import LLM, ReplayMiss, get_llm
from urbanshield.agents.orchestrator import run_incident
from urbanshield.agents.tools import RunContext, plan_brief
from urbanshield.api import fixtures
from urbanshield.api.runs import RunRegistry, RunState
from urbanshield.config import Settings, get_settings
from urbanshield.guard import quarantine
from urbanshield.guard.audit_log import AuditLog
from urbanshield.schemas import (
    Advisory,
    AgentEvent,
    AgentName,
    AuditEntry,
    Budget,
    City,
    EventKind,
    Plan,
    ToolResult,
    VerifyResult,
)

log = logging.getLogger("urbanshield.api")

APPROVER = "approver"
PLANS_TOOL_ID = "tc-plans"
PREVIEW_CONCURRENCY = 2  # each preview is one LLM call; bound the spend and the threadpool
MAX_AUDIT_PAGE = 5000


class IncidentRequest(BaseModel):
    advisory_text: str = Field(min_length=1, max_length=20_000)
    constraints_text: str | None = Field(default=None, max_length=2_000)


class IncidentStarted(BaseModel):
    run_id: str


class ApprovalRequest(BaseModel):
    plan_id: str = Field(min_length=1, max_length=128)
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


class TamperRequest(BaseModel):
    seq: int = Field(ge=0)


class AuditHead:
    """The highest audit head this process has published. A later head that is lower, or
    has a different hash at the published seq, means rows were cut from the end of the log:
    the one edit a hash chain alone cannot see."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.seq: int | None = None
        self.hash: str | None = None

    def publish(self, seq: int, digest: str) -> None:
        with self._lock:
            if self.seq is None or seq > self.seq:
                self.seq, self.hash = seq, digest

    def check(self, audit: AuditLog) -> str | None:
        """Why the stored log contradicts the published head, or None."""
        with self._lock:
            seq, digest = self.seq, self.hash
        if seq is None:
            return None
        at = audit.entries(after_seq=seq - 1, limit=1)
        if not at or at[0].seq != seq or at[0].hash != digest:
            return "log shorter than previously published head"
        return None


def _open_audit(settings: Settings) -> tuple[AuditLog | None, str]:
    """The audit log, or None and the reason it is unavailable (shown in /api/health)."""
    if not settings.signing_key_hex:
        log.warning(
            "AUDIT_SIGNING_KEY is not set: using an ephemeral key; signatures will not verify after a restart"
        )
    try:
        settings.db_path.parent.mkdir(parents=True, exist_ok=True)
        return AuditLog(settings.db_path, signing_key_hex=settings.signing_key_hex), "ok"
    except ValueError:
        return None, "unavailable: AUDIT_SIGNING_KEY must be 64 hex characters"
    except (sqlite3.Error, OSError) as exc:
        log.exception("audit log unavailable")
        return None, f"unavailable: {type(exc).__name__}"


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
    audit, audit_status = _open_audit(settings)
    head = AuditHead()
    runs = RunRegistry()
    budget = Budget(inr=settings.budget_inr, downtime_h=settings.downtime_h)
    city_cache: dict[str, City] = {}
    plans_cache: dict[str, Any] = {}
    cache_lock = threading.RLock()  # first requests may race; generation and compare run once
    previews = threading.BoundedSemaphore(PREVIEW_CONCURRENCY)

    app = FastAPI(
        title="UrbanShield API",
        version=__version__,
        description="Tail-risk-aware cyber resilience planning for connected city infrastructure.",
    )
    app.state.runs = runs
    app.state.audit = audit
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-Role"],
    )

    # ------------------------------------------------------------------ helpers

    def the_city() -> City:
        if not is_live:
            return fixtures.demo_city()
        with cache_lock:
            if "city" not in city_cache:
                city_cache["city"] = engine.generate_city(seed=settings.city_seed)
            return city_cache["city"]

    def city_or_404(city_id: str) -> City:
        city = the_city()
        if city.id != city_id:
            raise HTTPException(status_code=404, detail=f"unknown city {city_id!r}")
        return city

    def live_plans() -> tuple[list[Plan], ToolResult]:
        """``compare`` under the demo budget, computed once and recorded for provenance."""
        with cache_lock:
            if "plans" not in plans_cache:
                city = the_city()
                plans = engine.compare(city, budget, [], n_scenarios=settings.n_scenarios)
                cvar_plan = next(p for p in plans if p.objective.value == "cvar")
                cvss_plan = next(p for p in plans if p.objective.value == "cvss")
                record = ToolResult(
                    id=PLANS_TOOL_ID,
                    tool="compare",
                    agent=AgentName.PLANNER,
                    args={"budget_inr": budget.inr, "downtime_h": budget.downtime_h},
                    result={
                        "a": cvss_plan.id,
                        "b": cvar_plan.id,
                        "plans": {p.id: plan_brief(p) for p in plans},
                    },
                )
                plans_cache["plans"] = [p.model_copy(update={"tool_call_id": record.id}) for p in plans]
                plans_cache["record"] = record
            return plans_cache["plans"], plans_cache["record"]

    def require_audit() -> AuditLog:
        if audit is None:
            raise HTTPException(status_code=503, detail=f"audit log {audit_status}")
        return audit

    def emitter(state: RunState) -> Callable[[AgentEvent], None]:
        """Audit first, then show. An event that cannot be audited stops the run (fail closed)."""
        failed = threading.Event()

        def emit(event: AgentEvent) -> None:
            if failed.is_set():
                state.push(event)
                return
            if event.kind == EventKind.APPLY and audit is not None and (last := audit.head()) is not None:
                head.publish(last.seq, last.hash)
                tip = {"seq": last.seq, "hash": last.hash}
                event = event.model_copy(update={"payload": event.payload | {"audit_head": tip}})
            try:
                require_audit().append(event)
            except (HTTPException, sqlite3.Error, OSError) as exc:
                failed.set()
                log.exception("audit append failed for run %s", state.run_id)
                state.push(event)
                raise RuntimeError("audit log unavailable; the run was stopped") from exc
            state.push(event)

        return emit

    def run_in_background(state: RunState, body: IncidentRequest) -> None:
        def work() -> None:
            try:
                run_incident(
                    state.ctx,
                    body.advisory_text,
                    body.constraints_text,
                    state.gate,
                    timeout_s=settings.approval_timeout_s,
                )
            finally:
                state.finish()

        try:
            threading.Thread(target=work, name=f"run-{state.run_id}", daemon=True).start()
        except RuntimeError as exc:  # could not start a thread: free the slot, tell the caller
            state.finish()
            raise HTTPException(status_code=503, detail="could not start the run; try again") from exc

    # ------------------------------------------------------------------ routes

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
            "audit_key": "fixed" if settings.signing_key_hex else "ephemeral",
            "audit": audit_status,
        }

    @app.get("/api/cities/{city_id}", response_model=City)
    def get_city(city_id: str) -> City:
        return city_or_404(city_id)

    @app.get("/api/cities/{city_id}/plans", response_model=list[Plan])
    def get_plans(city_id: str) -> list[Plan]:
        city_or_404(city_id)
        return live_plans()[0] if is_live else list(fixtures.demo_plans())

    @app.post(
        "/api/cities/{city_id}/incidents",
        response_model=IncidentStarted,
        status_code=202,
        responses={
            404: {"description": "Unknown city"},
            429: {"description": "Too many incidents running (see Retry-After)"},
            503: {"description": "Audit log unavailable, or the run could not start"},
        },
    )
    def start_incident(city_id: str, body: IncidentRequest) -> IncidentStarted:
        city = city_or_404(city_id)
        if not is_live:
            return IncidentStarted(run_id="run-placeholder")
        require_audit()
        state = RunState(run_id=f"run-{uuid.uuid4().hex[:12]}", city_id=city.id)
        state.ctx = RunContext(
            run_id=state.run_id,
            city=city,
            engine=engine,
            llm=llm,
            emit=emitter(state),
            budget=budget,
            n_scenarios=settings.n_scenarios,
        )
        if not runs.add(state):
            raise HTTPException(
                status_code=429,
                detail="too many incidents running; try again shortly",
                headers={"Retry-After": "30"},
            )
        run_in_background(state, body)
        return IncidentStarted(run_id=state.run_id)

    @app.get(
        "/api/runs/{run_id}/events",
        response_class=StreamingResponse,
        responses={
            200: {"content": {"text/event-stream": {}}, "description": "AgentEvent JSON per data: line"},
            404: {"description": "Unknown run"},
        },
    )
    async def stream_events(run_id: str) -> StreamingResponse:
        """Server-Sent Events: one ``AgentEvent`` JSON per ``data:`` line, then ``event: done``.
        Reconnecting replays the run from its first event."""
        if not is_live:

            async def placeholder() -> AsyncIterator[str]:
                for event in fixtures.demo_events():
                    yield f"data: {event.model_dump_json()}\n\n"
                    await asyncio.sleep(0.6)
                yield "event: done\ndata: {}\n\n"

            return StreamingResponse(placeholder(), media_type="text/event-stream")
        state = runs.get(run_id)
        if state is None:
            raise HTTPException(status_code=404, detail=f"unknown run {run_id!r}")

        async def follow() -> AsyncIterator[str]:
            async for event in state.follow():
                yield ": keep-alive\n\n" if event is None else f"data: {event.model_dump_json()}\n\n"
            yield "event: done\ndata: {}\n\n"

        return StreamingResponse(
            follow(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"}
        )

    @app.post(
        "/api/runs/{run_id}/approvals",
        response_model=AgentEvent,
        responses={
            403: {"description": "Missing X-Role: approver"},
            404: {"description": "Unknown run"},
            409: {"description": "No pending approval for this plan_id"},
            504: {"description": "Decision recorded but not yet acknowledged; do not retry"},
        },
    )
    async def approve(
        run_id: str, body: ApprovalRequest, x_role: Annotated[str | None, Header()] = None
    ) -> AgentEvent:
        """Answer the run's pending approval. Needs ``X-Role: approver`` (demo RBAC)."""
        if x_role != APPROVER:
            raise HTTPException(status_code=403, detail="approvals need the approver role (X-Role: approver)")
        if not is_live:
            return AgentEvent(
                id=f"ev-approval-{body.plan_id}",
                city_id=fixtures.demo_city().id,
                run_id=run_id,
                agent=AgentName.HUMAN,
                kind=EventKind.APPROVAL if body.approve else EventKind.REJECT,
                summary=f"{'Approved' if body.approve else 'Rejected'} {body.plan_id}",
                payload={"role": APPROVER},
            )
        state = runs.get(run_id)
        if state is None:
            raise HTTPException(status_code=404, detail=f"unknown run {run_id!r}")
        seen = state.count()
        if not state.gate.submit(body.plan_id, body.approve, APPROVER):
            raise HTTPException(status_code=409, detail=f"no pending approval for {body.plan_id!r}")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:  # the worker records the decision as an event
            recent, _ = state.since(seen)
            event = next(
                (
                    e
                    for e in recent
                    if e.agent == AgentName.HUMAN and e.payload.get("plan_id") == body.plan_id
                ),
                None,
            )
            if event is not None:
                return event
            await asyncio.sleep(0.02)
        raise HTTPException(
            status_code=504,
            detail="decision recorded; the timeline will show it shortly (do not resubmit)",
        )

    @app.get("/api/runs/{run_id}/tool-results/{tool_call_id}", response_model=ToolResult)
    def get_run_tool_result(run_id: str, tool_call_id: str) -> ToolResult:
        """Provenance for a number in a run's timeline (tool ids restart in every run)."""
        state = runs.get(run_id) if is_live else None
        record = state.ctx.results.get(tool_call_id) if state and state.ctx else None
        if record is None:
            raise HTTPException(status_code=404, detail=f"unknown tool call {tool_call_id!r} in {run_id!r}")
        return record

    @app.get("/api/tool-results/{tool_call_id}", response_model=ToolResult)
    def get_tool_result(tool_call_id: str) -> ToolResult:
        """Provenance for the precomputed ``/plans`` comparison."""
        if is_live:
            _, record = live_plans()
            if tool_call_id != record.id:
                raise HTTPException(status_code=404, detail=f"unknown tool call {tool_call_id!r}")
            return record
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
        fields = ("id", "kind", "title", "text")
        return [AdvisoryPreset(**{k: p[k] for k in fields}) for p in quarantine.load_presets()]

    @app.post(
        "/api/quarantine/preview",
        response_model=QuarantinePreview,
        responses={429: {"description": "Too many previews in flight (each is an LLM call)"}},
    )
    def quarantine_preview(body: QuarantinePreviewRequest) -> QuarantinePreview:
        """Run the real quarantine on pasted text: the typed advisory and the feed cross-check.
        Works without the city or optimiser, so Judge Mode is real as early as possible."""
        if not previews.acquire(blocking=False):
            raise HTTPException(
                status_code=429, detail="previews are busy; try again", headers={"Retry-After": "5"}
            )
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
        finally:
            previews.release()
        if advisory is not None:
            discrepancies = quarantine.cross_check(advisory, engine.feed_record)
        return QuarantinePreview(
            source_sha256=quarantine.sha256_text(text),
            flagged_spans=quarantine.flag_spans(text),
            advisory=advisory,
            discrepancies=discrepancies,
            error=error,
        )

    @app.get(
        "/api/audit/entries",
        response_model=list[AuditEntry],
        responses={503: {"description": "Audit log unavailable"}},
    )
    def audit_entries(
        after_seq: Annotated[int, Query(ge=-1)] = -1,
        limit: Annotated[int, Query(ge=1, le=MAX_AUDIT_PAGE)] = MAX_AUDIT_PAGE,
    ) -> list[AuditEntry]:
        """Entries in ``seq`` order; page with ``after_seq`` (the last seq you have)."""
        return require_audit().entries(after_seq=after_seq, limit=limit)

    @app.get("/api/audit/key")
    def audit_key() -> dict[str, str]:
        """Public Ed25519 key: anyone can check the signatures with it."""
        return {"verify_key_hex": require_audit().verify_key_hex}

    @app.get("/api/audit/verify", response_model=VerifyResult)
    def verify_audit() -> VerifyResult:
        """Re-check every hash and signature, and that the log still reaches the highest head
        this server has published (tail truncation)."""
        log_ = require_audit()
        result = log_.verify()
        tip = log_.head()
        current = {"head_seq": tip.seq if tip else None, "head_hash": tip.hash if tip else None}
        if result.ok and (reason := head.check(log_)) is not None:
            return VerifyResult(ok=False, entries=result.entries, reason=reason, truncated=True, **current)
        if result.ok and tip is not None:
            head.publish(tip.seq, tip.hash)
        return result.model_copy(update=current)

    if settings.allow_demo_tamper:

        @app.post("/api/audit/tamper")
        def tamper(body: TamperRequest) -> dict[str, int]:
            """Judge Mode only (ALLOW_DEMO_TAMPER=1): edit one stored event so Verify chain breaks there."""
            require_audit()
            with closing(sqlite3.connect(settings.db_path)) as conn, conn:
                row = conn.execute("SELECT event_json FROM audit_log WHERE seq = ?", (body.seq,)).fetchone()
                if row is None:
                    raise HTTPException(status_code=404, detail=f"no audit entry {body.seq}")
                event = json.loads(row[0])
                event["summary"] = f"{event.get('summary', '')} [edited]"[:280]
                conn.execute(
                    "UPDATE audit_log SET event_json = ? WHERE seq = ?",
                    (json.dumps(event, sort_keys=True, separators=(",", ":")), body.seq),
                )
            return {"tampered_seq": body.seq}

    return app


def __getattr__(name: str) -> FastAPI:
    """``urbanshield.api.main:app`` for uvicorn, built on first access rather than at import, so
    importing ``create_app`` (tests, scripts) never opens the default database or reads ``.env``."""
    if name != "app":
        raise AttributeError(name)
    if "app" not in _APP:
        _APP["app"] = create_app()
    return _APP["app"]


_APP: dict[str, FastAPI] = {}
