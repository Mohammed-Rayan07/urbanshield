"""The agent tool loop: the model asks for tools, code runs them, until a JSON answer. Owner: C.

Every requested call goes through ``tools.call`` (allowlist, validation, provenance). A refused
or invalid call is not fatal: the error goes back to the model as the tool's result so it can
correct itself. Tool messages carry the run-scoped ``tool_call_id`` the model must cite.
"""

from __future__ import annotations

from typing import Any

from urbanshield.agents import tools
from urbanshield.agents.llm import LLMOutputError, LLMResponse
from urbanshield.agents.tools import RunContext, ToolArgError
from urbanshield.agents.tools import dumps as _dumps
from urbanshield.guard.allowlist import ToolNotAllowed
from urbanshield.schemas import AgentName, EventKind, LLMUsage

MAX_CALLS_PER_STEP = 8
JSON_REMINDER = "Reply with one JSON object only, as described in the instructions."


def add_usage(total: LLMUsage | None, usage: LLMUsage) -> LLMUsage:
    """Token and latency totals across calls; ``cached`` only if every call was."""
    if total is None:
        return usage
    return LLMUsage(
        model=total.model,
        prompt_tokens=total.prompt_tokens + usage.prompt_tokens,
        completion_tokens=total.completion_tokens + usage.completion_tokens,
        latency_ms=total.latency_ms + usage.latency_ms,
        cached=total.cached and usage.cached,
    )


def _assistant_message(response: LLMResponse) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant", "content": response.content or ""}
    if response.tool_calls:
        message["tool_calls"] = [
            {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": _dumps(c.arguments)}}
            for c in response.tool_calls
        ]
    return message


def _run_call(ctx: RunContext, agent: AgentName, name: str, arguments: dict[str, Any]) -> str:
    try:
        record = tools.call(ctx, agent, name, arguments)
    except (ToolNotAllowed, ToolArgError) as exc:
        return _dumps({"tool": name, "error": str(exc)})
    return _dumps({"tool": name, "tool_call_id": record.id, "result": record.result})


def run_tool_loop(
    ctx: RunContext,
    agent: AgentName,
    task: str,
    system: str,
    user: str,
    max_steps: int = 5,
    default: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], LLMUsage | None]:
    """Drive one agent until it answers with a JSON object; return it and the summed usage.

    After ``max_steps`` model turns without an answer, emit an ERROR event and return
    ``default`` (the caller's safe choice)."""
    specs = tools.openai_tool_specs(agent)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    usage: LLMUsage | None = None
    for _ in range(max_steps):
        response = ctx.llm.chat(task, messages, tier="strong", tools=specs)
        usage = add_usage(usage, response.usage)
        messages.append(_assistant_message(response))
        if response.tool_calls:
            for call in response.tool_calls[:MAX_CALLS_PER_STEP]:
                content = _run_call(ctx, agent, call.name, call.arguments)
                messages.append({"role": "tool", "tool_call_id": call.id, "content": content})
            for call in response.tool_calls[MAX_CALLS_PER_STEP:]:
                error = _dumps({"tool": call.name, "error": f"at most {MAX_CALLS_PER_STEP} calls per turn"})
                messages.append({"role": "tool", "tool_call_id": call.id, "content": error})
            continue
        try:
            return response.json(), usage
        except LLMOutputError:
            messages.append({"role": "user", "content": JSON_REMINDER})
    ctx.event(
        agent,
        EventKind.ERROR,
        f"{agent.value} gave no answer within {max_steps} steps; using the safe default",
        {"task": task, "default": default or {}},
        usage=usage,
    )
    return dict(default or {}), usage
