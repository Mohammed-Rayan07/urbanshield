"""Provider-agnostic LLM adapter. Owner: C.

One interface, three modes (``LLM_MODE``):

- ``live``: any OpenAI-compatible Chat Completions endpoint with function calling
  (``LLM_BASE_URL`` / ``LLM_API_KEY``; e.g. Gemini's OpenAI-compatible endpoint). Every
  response is written to an on-disk cache keyed by the SHA-256 of the canonical request.
- ``replay``: serve only from that cache. A miss raises ``ReplayMiss``; it never falls back
  to anything else. The demo video and offline venue runs use this mode.
- ``mock``: deterministic rule-based responders (``agents/mock.py``). CI and keyless runs.
  Mock output is labelled as such everywhere it is shown.

Model routing: ``tier="fast"`` for extraction, ``tier="strong"`` for planning and the red team.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

from urbanshield.config import FIXTURES_DIR, Settings
from urbanshield.schemas import LLMUsage

Tier = Literal["fast", "strong"]
TRACES_DIR = FIXTURES_DIR / "traces"
MAX_RETRIES = 4


class ReplayMiss(RuntimeError):
    """Replay mode was asked for a request that was never recorded."""


class LLMOutputError(ValueError):
    """The model's output could not be parsed into what the caller asked for."""


@dataclass(frozen=True)
class ToolCallRequest:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class LLMResponse:
    content: str | None
    tool_calls: list[ToolCallRequest]
    usage: LLMUsage

    def json(self) -> dict[str, Any]:
        """Parse ``content`` as a JSON object, tolerating code fences and surrounding prose."""
        return parse_json_object(self.content or "")


class LLM(Protocol):
    mode: str

    def chat(
        self,
        task: str,
        messages: list[dict[str, Any]],
        tier: Tier = "strong",
        tools: list[dict[str, Any]] | None = None,
        json_output: bool = False,
    ) -> LLMResponse:
        """``task`` names the call site (e.g. ``"redteam.propose"``); mock mode dispatches on it."""
        ...


def parse_json_object(text: str) -> dict[str, Any]:
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        raise LLMOutputError("no JSON object in model output")
    try:
        value = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise LLMOutputError(f"invalid JSON in model output: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise LLMOutputError("model output is not a JSON object")
    return value


def request_key(
    model: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None, json_output: bool
) -> str:
    """SHA-256 of the canonical request. Identical prompts → identical key, so replays are exact."""
    canonical = json.dumps(
        {"model": model, "messages": messages, "tools": tools or [], "json": json_output},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class CachedLLM:
    """Live (cache-through) or replay (cache-only) client for an OpenAI-compatible endpoint."""

    def __init__(
        self, settings: Settings, mode: Literal["live", "replay"], cache_dir: Path = TRACES_DIR
    ) -> None:
        self.mode = mode
        self._settings = settings
        self._cache_dir = cache_dir
        self._client: Any = None

    def _model(self, tier: Tier) -> str:
        return self._settings.model_fast if tier == "fast" else self._settings.model_strong

    def _openai(self) -> Any:
        # Built lazily: the SDK refuses to construct without a key, and replay/CI have none.
        if self._client is None:
            if not (self._settings.llm_base_url and self._settings.llm_api_key):
                raise RuntimeError("LLM_MODE=live needs LLM_BASE_URL and LLM_API_KEY")
            from openai import OpenAI

            self._client = OpenAI(base_url=self._settings.llm_base_url, api_key=self._settings.llm_api_key)
        return self._client

    def chat(
        self,
        task: str,
        messages: list[dict[str, Any]],
        tier: Tier = "strong",
        tools: list[dict[str, Any]] | None = None,
        json_output: bool = False,
    ) -> LLMResponse:
        model = self._model(tier)
        key = request_key(model, messages, tools, json_output)
        path = self._cache_dir / f"{key}.json"
        if path.exists():
            return _from_record(json.loads(path.read_text(encoding="utf-8")), cached=True)
        if self.mode == "replay":
            raise ReplayMiss(
                f"no recorded response for {task} (key {key[:12]}); record it in live mode first"
            )
        record = self._call(task, model, messages, tools, json_output)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=1, ensure_ascii=False), encoding="utf-8")
        return _from_record(record, cached=False)

    def _call(
        self,
        task: str,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        json_output: bool,
    ) -> dict[str, Any]:
        from openai import APIStatusError, BadRequestError, RateLimitError

        kwargs: dict[str, Any] = {"model": model, "messages": messages, "temperature": 0}
        if tools:
            kwargs["tools"] = tools
        if json_output:
            kwargs["response_format"] = {"type": "json_object"}
        for attempt in range(MAX_RETRIES):
            started = time.perf_counter()
            try:
                response = self._openai().chat.completions.create(**kwargs)
                break
            except BadRequestError:
                # Some OpenAI-compatible providers reject response_format; the prompt already asks for JSON.
                if "response_format" not in kwargs:
                    raise
                kwargs.pop("response_format")
            except RateLimitError:
                if attempt == MAX_RETRIES - 1:
                    raise
                time.sleep(2 ** (attempt + 1))
            except APIStatusError as exc:
                if exc.status_code < 500 or attempt == MAX_RETRIES - 1:
                    raise
                time.sleep(2 ** (attempt + 1))
        else:  # pragma: no cover - loop always breaks or raises
            raise RuntimeError(f"{task}: no response after {MAX_RETRIES} attempts")
        message = response.choices[0].message
        usage = response.usage
        return {
            "task": task,
            "model": model,
            "content": message.content,
            "tool_calls": [
                {"id": c.id, "name": c.function.name, "arguments": c.function.arguments or "{}"}
                for c in (message.tool_calls or [])
            ],
            "prompt_tokens": getattr(usage, "prompt_tokens", 0) or 0,
            "completion_tokens": getattr(usage, "completion_tokens", 0) or 0,
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }


def _from_record(record: dict[str, Any], cached: bool) -> LLMResponse:
    calls = []
    for raw in record["tool_calls"]:
        try:
            arguments = (
                json.loads(raw["arguments"]) if isinstance(raw["arguments"], str) else raw["arguments"]
            )
        except json.JSONDecodeError:
            arguments = {"__invalid_json__": raw["arguments"]}
        calls.append(ToolCallRequest(id=raw["id"], name=raw["name"], arguments=arguments or {}))
    return LLMResponse(
        content=record["content"],
        tool_calls=calls,
        usage=LLMUsage(
            model=record["model"],
            prompt_tokens=record["prompt_tokens"],
            completion_tokens=record["completion_tokens"],
            latency_ms=record["latency_ms"],
            cached=cached,
        ),
    )


def get_llm(settings: Settings) -> LLM:
    """The adapter for the configured mode."""
    if settings.llm_mode == "mock":
        from urbanshield.agents.mock import MockLLM

        return MockLLM()
    return CachedLLM(settings, mode=settings.llm_mode)
