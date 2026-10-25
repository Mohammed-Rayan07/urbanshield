"""Live smoke test of the configured OpenAI-compatible endpoint (run once you have a key).

    uv run python scripts/llm_check.py

Checks, against LLM_BASE_URL with LLM_MODEL_FAST / LLM_MODEL_STRONG from .env:
1. the model list, and that both configured models are in it;
2. a JSON-mode answer (and whether ``response_format`` is accepted);
3. that every agent's real tool schemas are accepted, and one full tool-call round trip;
4. latency per call, and a gentle rate-limit probe (5 sequential calls; no parallel burst,
   the free tier is small).
Calls are not cached and nothing is written. Exit code 0 only if every check passed.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

from urbanshield.agents.tools import openai_tool_specs
from urbanshield.config import get_settings
from urbanshield.schemas import AgentName


def _timed(fn: Any, **kwargs: Any) -> tuple[Any, int]:
    started = time.perf_counter()
    result = fn(**kwargs)
    return result, int((time.perf_counter() - started) * 1000)


def _main() -> int:
    settings = get_settings()
    if settings.llm_mode != "live" or not (settings.llm_base_url and settings.llm_api_key):
        print("Set LLM_MODE=live, LLM_BASE_URL and LLM_API_KEY in .env first.", file=sys.stderr)
        return 2
    from openai import APIStatusError, BadRequestError, OpenAI, RateLimitError

    client = OpenAI(base_url=settings.llm_base_url, api_key=settings.llm_api_key)
    create = client.chat.completions.create
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"[{'ok' if ok else 'FAIL'}] {name}{': ' + detail if detail else ''}")
        if not ok:
            failures.append(name)

    try:
        models = sorted(m.id for m in client.models.list())
        listed = {m.split("/")[-1] for m in models}
        for tier, model in (("fast", settings.model_fast), ("strong", settings.model_strong)):
            check(f"model list has the {tier} model", model.split("/")[-1] in listed, model)
    except APIStatusError as exc:
        check("model list", False, f"HTTP {exc.status_code}")

    messages = [{"role": "user", "content": 'Reply with {"ok": true} as a JSON object and nothing else.'}]
    try:
        reply, ms = _timed(
            create,
            model=settings.model_fast,
            messages=messages,
            temperature=0,
            response_format={"type": "json_object"},
        )
        check(
            "JSON mode (response_format accepted)",
            json.loads(reply.choices[0].message.content)["ok"],
            f"{ms} ms",
        )
    except BadRequestError:
        reply, ms = _timed(create, model=settings.model_fast, messages=messages, temperature=0)
        content = reply.choices[0].message.content or ""
        check("JSON without response_format (fallback path in llm.py)", '"ok"' in content, f"{ms} ms")

    for agent in (AgentName.SENTINEL, AgentName.ANALYST, AgentName.PLANNER, AgentName.REDTEAM):
        specs = openai_tool_specs(agent)
        try:
            _timed(create, model=settings.model_strong, messages=messages, tools=specs, temperature=0)
            check(f"tool schemas accepted ({agent.value}, {len(specs)} tools)", True)
        except BadRequestError as exc:
            check(f"tool schemas accepted ({agent.value})", False, str(exc)[:200])

    specs = openai_tool_specs(AgentName.ANALYST)
    ask = [{"role": "user", "content": "Call bfs_reach with sources ['d-001']. Do not answer in text."}]
    first, ms = _timed(create, model=settings.model_strong, messages=ask, tools=specs, temperature=0)
    calls = first.choices[0].message.tool_calls or []
    check("model requests a tool call", bool(calls) and calls[0].function.name == "bfs_reach", f"{ms} ms")
    if calls:
        call = calls[0]
        follow = [
            *ask,
            {
                "role": "assistant",
                "content": first.choices[0].message.content or "",
                "tool_calls": [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {"name": call.function.name, "arguments": call.function.arguments},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": call.id, "content": json.dumps({"reached": ["d-001", "d-002"]})},
        ]
        second, ms = _timed(create, model=settings.model_strong, messages=follow, tools=specs, temperature=0)
        check("tool result round trip", bool(second.choices[0].message.content), f"{ms} ms")

    limited = 0
    latencies = []
    for _ in range(5):
        try:
            _, ms = _timed(create, model=settings.model_fast, messages=messages, temperature=0)
            latencies.append(ms)
        except RateLimitError:
            limited += 1
            time.sleep(2)
    detail = f"{limited}/5 rate-limited; latency {min(latencies, default=0)}-{max(latencies, default=0)} ms"
    check("rate-limit probe (sequential)", limited < 5, detail)

    print(
        "\nAll checks passed." if not failures else f"\n{len(failures)} checks failed: {', '.join(failures)}"
    )
    return 0 if not failures else 1


def main() -> int:
    """Run the check and turn provider errors into a concise failure instead of a traceback."""
    from openai import APIStatusError

    try:
        return _main()
    except APIStatusError as exc:
        print(f"[FAIL] provider request: HTTP {exc.status_code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
