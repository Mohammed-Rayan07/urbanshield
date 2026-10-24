"""Rule-based stand-in for the LLM (``LLM_MODE=mock``). Owner: C.

Each call site (``task``) has a deterministic responder written with regexes and simple
heuristics. Mock runs need no key and no network (CI uses them) and are labelled "mock"
everywhere they are shown. They are a stand-in for the plumbing, not evidence about agents:
agent numbers in EVALS.md come from live or replayed runs only.

Responders read only what the real model would see in ``messages``, so the prompts are
exercised too. Tool-call ids are ``call_<step>_<i>``; token counts are estimated as
characters / 4; latency is 0.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from urbanshield.agents.llm import LLMResponse, Tier, ToolCallRequest
from urbanshield.schemas import LLMUsage

Responder = Callable[[list[dict[str, Any]]], tuple[str | None, list[ToolCallRequest]]]


def _text(messages: list[dict[str, Any]], role: str) -> str:
    return "\n".join(str(m.get("content") or "") for m in messages if m.get("role") == role)


def _first(pattern: str, text: str, flags: int = re.IGNORECASE | re.MULTILINE) -> str:
    match = re.search(pattern, text, flags)
    return match.group(1).strip() if match else ""


# --------------------------------------------------------------------------- sentinel.extract


def _extract(messages: list[dict[str, Any]]) -> tuple[str | None, list[ToolCallRequest]]:
    """Advisory fields by regex. The first statement of each field wins, like a careful reader."""
    text = _first(r"<advisory>\n(.*)\n</advisory>", _text(messages, "user"), re.DOTALL)
    vendor = _first(r"^\s*(?:vendor|manufacturer)\s*:\s*([^\n.,;]+)", text)
    family = (
        _first(r"firmware family\s*:\s*([a-z][\w-]*)", text)
        or _first(r"affected firmware\s*:\s*([a-z][\w-]*)", text)
        or _first(r"\b([a-z][\w-]*) firmware\b", text)
        or vendor
    )
    fields = {
        "cve_id": _first(r"\b(CVE-\d{4}-\d{4,})\b", text),
        "vendor": vendor,
        "product": _first(r"^\s*(?:product|model)\s*:\s*([^\n.,;]+)", text),
        "firmware_family": family.lower(),
        "affected_below": _first(
            r"(?:prior to|before|below|earlier than|<)\s*(?:version\s*)?v?(\d+(?:\.\d+){0,3})", text
        ),
        "cvss": _first(
            r"CVSS(?:\s*v?\d(?:\.\d)?)?(?:\s*base)?(?:\s*score)?\s*[:=]?\s*(\d{1,2}(?:\.\d)?)", text
        ),
    }
    return json.dumps(fields, sort_keys=True), []


RESPONDERS: dict[str, Responder] = {
    "sentinel.extract": _extract,
}


class MockLLM:
    """Deterministic ``LLM`` for CI and keyless runs."""

    mode = "mock"

    def chat(
        self,
        task: str,
        messages: list[dict[str, Any]],
        tier: Tier = "strong",
        tools: list[dict[str, Any]] | None = None,
        json_output: bool = False,
    ) -> LLMResponse:
        responder = RESPONDERS.get(task)
        if responder is None:
            raise ValueError(f"no mock responder for task {task!r}")
        content, calls = responder(messages)
        prompt_chars = len(json.dumps(messages, sort_keys=True)) + len(json.dumps(tools or []))
        completion_chars = len(content or "") + len(json.dumps([c.arguments for c in calls]))
        usage = LLMUsage(
            model="mock",
            prompt_tokens=prompt_chars // 4,
            completion_tokens=completion_chars // 4,
            latency_ms=0,
        )
        return LLMResponse(content=content, tool_calls=calls, usage=usage)
