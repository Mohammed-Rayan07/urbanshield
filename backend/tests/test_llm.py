"""LLM adapter: live cache-through, replay-only, JSON parsing. No network. Owner: C."""

from __future__ import annotations

import pytest

from fakes import settings_for
from urbanshield.agents.llm import CachedLLM, LLMOutputError, ReplayMiss, parse_json_object, request_key

MESSAGES = [{"role": "user", "content": "hi"}]


def _record(content: str = '{"ok": true}') -> dict:
    return {
        "task": "t",
        "model": "strong-model",
        "content": content,
        "tool_calls": [{"id": "c1", "name": "bfs_reach", "arguments": '{"sources": ["d-001"]}'}],
        "prompt_tokens": 3,
        "completion_tokens": 2,
        "latency_ms": 7,
    }


def test_replay_miss_raises_and_never_builds_a_client(tmp_path) -> None:
    llm = CachedLLM(settings_for(tmp_path), mode="replay", cache_dir=tmp_path)
    with pytest.raises(ReplayMiss):
        llm.chat("analyst.step", MESSAGES)
    assert llm._client is None


def test_live_records_then_replay_serves_the_same_answer(tmp_path, monkeypatch) -> None:
    live = CachedLLM(settings_for(tmp_path), mode="live", cache_dir=tmp_path)
    calls = []
    monkeypatch.setattr(live, "_call", lambda *a: calls.append(a) or _record())
    first = live.chat("analyst.step", MESSAGES)
    again = live.chat("analyst.step", MESSAGES)
    assert len(calls) == 1 and not first.usage.cached and again.usage.cached
    assert [p.name for p in tmp_path.iterdir()] == [
        f"{request_key('strong-model', MESSAGES, None, False)}.json"
    ]

    replay = CachedLLM(settings_for(tmp_path), mode="replay", cache_dir=tmp_path)
    served = replay.chat("analyst.step", MESSAGES)
    assert served.content == first.content and served.tool_calls == first.tool_calls
    assert served.tool_calls[0].arguments == {"sources": ["d-001"]}


def test_request_key_depends_on_everything_sent() -> None:
    base = request_key("m", MESSAGES, None, False)
    assert base == request_key("m", [dict(MESSAGES[0])], [], False)
    assert len({base, request_key("m2", MESSAGES, None, False), request_key("m", MESSAGES, None, True)}) == 3


def test_live_without_a_key_refuses_clearly(tmp_path) -> None:
    llm = CachedLLM(settings_for(tmp_path), mode="live", cache_dir=tmp_path)
    with pytest.raises(RuntimeError, match="LLM_API_KEY"):
        llm.chat("analyst.step", MESSAGES)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('{"a": 1}', {"a": 1}),
        ('```json\n{"a": {"b": 2}}\n```', {"a": {"b": 2}}),
        ('Sure! {"a": 1} Hope that helps {see}.', {"a": 1}),
        ('[1] then {"a": [1, 2]}', {"a": [1, 2]}),
    ],
)
def test_parse_json_object_finds_the_first_object(text, expected) -> None:
    assert parse_json_object(text) == expected


@pytest.mark.parametrize("text", ["", "no braces", "{broken", "[1, 2]"])
def test_parse_json_object_rejects_non_objects(text) -> None:
    with pytest.raises(LLMOutputError):
        parse_json_object(text)
