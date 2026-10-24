"""Live-mode API on the fake engine: runs, SSE replay, approvals (demo RBAC), provenance,
audit key / verify / truncation, tamper route gating, fail-closed audit. Owner: C."""

from __future__ import annotations

import json
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from fakes import fake_engine, settings_for
from urbanshield.api.main import create_app
from urbanshield.guard.quarantine import load_presets
from urbanshield.schemas import AgentEvent

PRESETS = {p["id"]: p["text"] for p in load_presets()}
INCIDENT = {
    "advisory_text": PRESETS["normal_01_lumenos"],
    "constraints_text": "Z1 festival, no streetlight downtime",
}
APPROVER = {"X-Role": "approver"}


def _client(tiny_city, tmp_path, **overrides) -> TestClient:
    settings = settings_for(tmp_path, **overrides)
    return TestClient(create_app(fake_engine(tiny_city), settings, live=True))


@pytest.fixture
def client(tiny_city, tmp_path) -> TestClient:
    return _client(tiny_city, tmp_path)


def _events(client: TestClient, run_id: str) -> list[AgentEvent]:
    with client.stream("GET", f"/api/runs/{run_id}/events") as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        lines = [line for line in r.iter_lines() if line.startswith(("data: ", "event: "))]
    assert lines[-2:] == ["event: done", "data: {}"]
    return [AgentEvent.model_validate_json(line[6:]) for line in lines[:-2]]


def _wait_pending(client: TestClient, run_id: str, timeout: float = 20.0) -> dict:
    state = client.app.state.runs.get(run_id)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if state.gate.pending:
            return state.gate.pending
        assert not state.done, [e.summary for e in state.events]
        time.sleep(0.02)
    raise AssertionError("no approval was requested")


def _start(client: TestClient, body: dict = INCIDENT) -> str:
    r = client.post("/api/cities/tiny/incidents", json=body)
    assert r.status_code == 202, r.text
    return r.json()["run_id"]


def test_health_reports_live_fields(client) -> None:
    body = client.get("/api/health").json()
    assert body | {"version": "x"} == {
        "status": "ok",
        "version": "x",
        "llm_mode": "mock",
        "data": "live",
        "engine_ready": True,
        "audit_key": "fixed",
        "audit": "ok",
    }


def test_ephemeral_key_is_reported(tiny_city, tmp_path) -> None:
    assert (
        _client(tiny_city, tmp_path, signing_key_hex=None).get("/api/health").json()["audit_key"]
        == "ephemeral"
    )


def test_live_city_plans_and_provenance(client) -> None:
    assert client.get("/api/cities/tiny").json()["id"] == "tiny"
    assert client.get("/api/cities/mangaluru-demo").status_code == 404
    plans = client.get("/api/cities/tiny/plans").json()
    assert plans[0]["objective"] == "cvar" and all(p["metrics"] for p in plans)
    record = client.get(f"/api/tool-results/{plans[0]['tool_call_id']}").json()
    assert record["tool"] == "compare" and plans[0]["id"] in record["result"]["plans"]
    assert client.get("/api/tool-results/tc-001").status_code == 404


def test_full_run_with_approval_over_http(client) -> None:
    run_id = _start(client)
    pending = _wait_pending(client, run_id)
    assert pending["kind"] == "plan"
    denied = client.post(f"/api/runs/{run_id}/approvals", json={"plan_id": pending["plan_id"]})
    assert denied.status_code == 403
    wrong = client.post(f"/api/runs/{run_id}/approvals", json={"plan_id": "plan-nope"}, headers=APPROVER)
    assert wrong.status_code == 409
    ok = client.post(f"/api/runs/{run_id}/approvals", json={"plan_id": pending["plan_id"]}, headers=APPROVER)
    assert (
        ok.status_code == 200
        and ok.json()["kind"] == "approval"
        and ok.json()["payload"]["role"] == "approver"
    )

    events = _events(client, run_id)
    assert events[-1].summary.startswith("Run complete")
    assert [e.id for e in events] == [e.id for e in _events(client, run_id)]  # reconnect replays all
    verify = next(e for e in events if e.summary.startswith("Re-simulated"))
    assert verify.payload["audit_head"]["seq"] >= 0

    tc = verify.tool_call_id
    record = client.get(f"/api/runs/{run_id}/tool-results/{tc}").json()
    assert record["tool"] == "evaluate_applied"
    assert client.get(f"/api/runs/{run_id}/tool-results/tc-999").status_code == 404
    assert client.get(f"/api/runs/run-nope/tool-results/{tc}").status_code == 404

    entries = client.get("/api/audit/entries").json()
    assert [e["event_id"] for e in entries] == [e.id for e in events]
    result = client.get("/api/audit/verify").json()
    assert result["ok"] and result["entries"] == len(events) and result["head_seq"] == len(events) - 1
    assert len(client.get("/api/audit/key").json()["verify_key_hex"]) == 64


def test_approval_timeout_applies_nothing_that_needs_approval(tiny_city, tmp_path) -> None:
    client = _client(tiny_city, tmp_path, approval_timeout_s=0.2)
    events = _events(client, _start(client))
    assert any("timed out" in e.summary for e in events)
    applied = [e for e in events if e.kind.value == "apply" and e.summary.startswith("Applied")]
    assert applied == []


def test_rejection_over_http(client) -> None:
    run_id = _start(client)
    pending = _wait_pending(client, run_id)
    r = client.post(
        f"/api/runs/{run_id}/approvals",
        json={"plan_id": pending["plan_id"], "approve": False},
        headers=APPROVER,
    )
    assert r.json()["kind"] == "reject"
    assert not any(e.summary.startswith("Applied") for e in _events(client, run_id))


def test_runs_waiting_on_an_approver_do_not_hold_a_slot(client) -> None:
    parked = []
    for _ in range(3):  # max_active is 2; each run parks on its approval before the next starts
        parked.append(_start(client))
        _wait_pending(client, parked[-1])
    assert _start(client)  # a fourth still starts: parked runs are not "computing"
    for run_id in parked:
        pending = client.app.state.runs.get(run_id).gate.pending
        client.post(f"/api/runs/{run_id}/approvals", json={"plan_id": pending["plan_id"]}, headers=APPROVER)


def test_busy_server_answers_429_with_retry_after(client) -> None:
    runs = client.app.state.runs
    runs.max_active = 0
    r = client.post("/api/cities/tiny/incidents", json=INCIDENT)
    assert r.status_code == 429 and r.headers["retry-after"] == "30"


def test_audit_entries_page_and_head(tiny_city, tmp_path) -> None:
    client = _client(tiny_city, tmp_path, approval_timeout_s=0.1)
    events = _events(client, _start(client))
    first = client.get("/api/audit/entries", params={"limit": 3}).json()
    rest = client.get("/api/audit/entries", params={"after_seq": first[-1]["seq"]}).json()
    assert [e["seq"] for e in first + rest] == list(range(len(events)))
    assert client.get("/api/audit/entries", params={"limit": 0}).status_code == 422
    assert client.app.state.audit.head().seq == len(events) - 1


def test_importing_the_module_does_not_build_the_default_app() -> None:
    import urbanshield.api.main as main

    assert "app" not in vars(main)  # built lazily on first access (uvicorn), not at import


def test_unknown_run_is_404(client) -> None:
    assert client.get("/api/runs/run-nope/events").status_code == 404
    assert (
        client.post("/api/runs/run-nope/approvals", json={"plan_id": "x"}, headers=APPROVER).status_code
        == 404
    )


def test_one_byte_edit_and_tail_truncation_are_caught(tiny_city, tmp_path) -> None:
    client = _client(tiny_city, tmp_path, approval_timeout_s=0.1)
    _events(client, _start(client))
    first = client.get("/api/audit/verify").json()
    assert first["ok"] and first["head_seq"] > 3
    db = tmp_path / "test.db"
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM audit_log WHERE seq >= ?", (first["head_seq"] - 1,))
    cut = client.get("/api/audit/verify").json()
    assert (
        not cut["ok"] and cut["truncated"] and cut["reason"] == "log shorter than previously published head"
    )
    with sqlite3.connect(db) as conn:
        conn.execute(
            "UPDATE audit_log SET event_json = replace(event_json, 'Incident', 'lncident') WHERE seq = 0"
        )
    edited = client.get("/api/audit/verify").json()
    assert not edited["ok"] and edited["first_bad_seq"] == 0 and not edited["truncated"]


def test_tamper_route_exists_only_when_enabled(tiny_city, tmp_path) -> None:
    off = _client(tiny_city, tmp_path)
    assert off.post("/api/audit/tamper", json={"seq": 0}).status_code == 404
    on = _client(tiny_city, tmp_path / "on", allow_demo_tamper=True, approval_timeout_s=0.1)
    _events(on, _start(on))
    assert on.post("/api/audit/tamper", json={"seq": 2}).json() == {"tampered_seq": 2}
    result = on.get("/api/audit/verify").json()
    assert not result["ok"] and result["first_bad_seq"] == 2
    assert on.post("/api/audit/tamper", json={"seq": 9999}).status_code == 404


def test_unavailable_audit_log_refuses_incidents(tiny_city, tmp_path) -> None:
    client = _client(tiny_city, tmp_path, signing_key_hex="not-hex")
    assert client.get("/api/health").json()["audit"].startswith("unavailable")
    assert client.post("/api/cities/tiny/incidents", json=INCIDENT).status_code == 503
    assert client.get("/api/audit/verify").status_code == 503


def test_raw_advisory_never_appears_in_streamed_or_audited_events(client) -> None:
    text = PRESETS["poisoned_02_role_override"]
    run_id = _start(client, {"advisory_text": text, "constraints_text": None})
    pending = _wait_pending(client, run_id)
    client.post(f"/api/runs/{run_id}/approvals", json={"plan_id": pending["plan_id"]}, headers=APPROVER)
    blob = json.dumps([e.model_dump(mode="json") for e in _events(client, run_id)])
    assert "administrator rights" not in blob and text not in blob
