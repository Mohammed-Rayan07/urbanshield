"""Sentinel: quarantine -> cross-check -> inventory match -> decision. Owner: C."""

from __future__ import annotations

import pytest

from fakes import SpyLLM, fake_engine, make_ctx
from urbanshield.agents.mock import MockLLM
from urbanshield.agents.sentinel import match_inventory, parse_version, run_sentinel, version_below
from urbanshield.guard.quarantine import load_presets, sha256_text
from urbanshield.schemas import Advisory, AgentName, EventKind

PRESETS = {p["id"]: p for p in load_presets()}


def _adv(**overrides) -> Advisory:
    fields = {
        "cve_id": "CVE-2026-0001",
        "vendor": "Lumenos",
        "product": "SL-200",
        "firmware_family": "lumenos",
        "affected_below": "4.2.0",
        "cvss": 6.5,
        "source_sha256": "0" * 64,
    }
    return Advisory(**(fields | overrides))


@pytest.mark.parametrize(
    ("a", "b", "below"),
    [
        ("4.1.3", "4.2.0", True),
        ("4.2.0", "4.2.0", False),
        ("4.10.0", "4.9.9", False),  # numeric, not lexicographic
        ("4.2", "4.2.0", False),  # missing parts count as zero
        ("4.1", "4.1.1", True),
    ],
)
def test_version_compare_is_numeric(a, b, below) -> None:
    assert version_below(a, b) is below


def test_unparseable_version_is_none() -> None:
    assert parse_version("4.x") is None and parse_version("") is None
    assert version_below("4.x", "5.0") is False


def test_family_match_is_case_insensitive_and_sorted(tiny_city) -> None:
    matches = match_inventory(tiny_city, _adv(firmware_family="LUMENOS"))
    assert [m.device_id for m in matches] == ["d-001", "d-002"]
    assert {m.reason for m in matches} == {"firmware_family_and_version"}


def test_listed_cve_matches_even_outside_the_version_range(tiny_city) -> None:
    matches = match_inventory(tiny_city, _adv(cve_id="CVE-2025-31337", affected_below="1.0.0"))
    assert [(m.device_id, m.reason) for m in matches] == [("d-001", "cve_listed"), ("d-002", "cve_listed")]


def _kinds(events) -> list[tuple[AgentName, EventKind]]:
    return [(e.agent, e.kind) for e in events]


def test_normal_advisory_escalates_with_matches(tiny_city) -> None:
    events = []
    ctx = make_ctx(tiny_city, emit=events.append)
    text = PRESETS["normal_01_lumenos"]["text"]
    result = run_sentinel(ctx, text)
    assert result is not None and result.decision == "escalate"
    assert [m.device_id for m in result.matches] == ["d-001", "d-002"]
    assert result.discrepancies == []
    assert ctx.untrusted[sha256_text(text)] == text
    tools = [ctx.results[e.tool_call_id].tool for e in events if e.kind == EventKind.TOOL_CALL]
    assert tools == ["quarantine_extract", "cross_check", "match_inventory"]
    assert _kinds(events)[0] == (AgentName.SENTINEL, EventKind.OBSERVE)
    assert events[-1].kind == EventKind.DECISION and events[-1].payload["decision"] == "escalate"


def test_poisoned_advisory_is_flagged_and_has_no_effect(tiny_city) -> None:
    events = []
    ctx = make_ctx(tiny_city, emit=events.append)
    result = run_sentinel(ctx, PRESETS["poisoned_01_ignore_previous"]["text"])
    clean = run_sentinel(make_ctx(tiny_city), PRESETS["normal_01_lumenos"]["text"])
    assert result is not None and clean is not None
    observe = events[0]
    assert observe.kind == EventKind.OBSERVE and observe.payload["flagged_spans"]
    assert result.advisory.model_dump(exclude={"source_sha256"}) == clean.advisory.model_dump(
        exclude={"source_sha256"}
    )
    assert result.decision == "escalate"


@pytest.mark.parametrize("preset", [p for p in PRESETS if p.startswith("wrong")])
def test_valid_but_wrong_advisory_needs_approval(tiny_city, preset) -> None:
    result = run_sentinel(make_ctx(tiny_city), PRESETS[preset]["text"])
    assert result is not None and result.decision == "needs_approval" and result.discrepancies


def test_missing_feed_fails_closed(tiny_city) -> None:
    def no_feed(cve_id: str) -> dict | None:
        raise NotImplementedError

    ctx = make_ctx(tiny_city, engine=fake_engine(tiny_city, feed_record=no_feed))
    result = run_sentinel(ctx, PRESETS["normal_01_lumenos"]["text"])
    assert result is not None and result.decision == "needs_approval"


def test_unextractable_text_stops_with_an_error_event(tiny_city) -> None:
    events = []
    ctx = make_ctx(tiny_city, emit=events.append)
    assert run_sentinel(ctx, "Something is wrong with the lights, please check.") is None
    assert events[-1].kind == EventKind.ERROR and events[-1].agent == AgentName.SENTINEL


def test_no_match_and_consistent_means_monitor(tiny_city) -> None:
    text = PRESETS["normal_01_lumenos"]["text"].replace("4.2.0", "4.0.0")
    feed = {"cve_id": "CVE-2025-31337", "cvss": 6.1, "vendor": "Lumenos", "product": "SL-200"}
    city = tiny_city.model_copy(
        update={"devices": [d.model_copy(update={"vulns": []}) for d in tiny_city.devices]}
    )
    ctx = make_ctx(city, engine=fake_engine(city, feed_record=lambda _: feed))
    result = run_sentinel(ctx, text)
    assert result is not None and result.matches == [] and result.decision == "monitor"


def test_raw_text_reaches_exactly_one_llm_request(tiny_city) -> None:
    spy = SpyLLM(MockLLM())
    text = PRESETS["poisoned_02_role_override"]["text"]
    run_sentinel(make_ctx(tiny_city, llm=spy), text)
    marker = "administrator rights"
    hits = [r for r in spy.requests if marker in str(r["messages"])]
    assert len(hits) == 1 and hits[0]["task"] == "sentinel.extract" and hits[0]["tools"] is None
