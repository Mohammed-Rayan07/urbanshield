"""Provider-agnostic LLM adapter. Owner: C.

One interface, three modes (``LLM_MODE``):

- ``live``: any OpenAI-compatible Chat Completions endpoint (``LLM_BASE_URL``,
  ``LLM_API_KEY``) with function calling. Every response is cached on disk under
  ``fixtures/traces/`` keyed by the SHA-256 of the canonical request.
- ``replay``: serve only from that cache; a cache miss is an error. The demo video and
  offline venue runs use this mode, so they are deterministic and need no network.
- ``mock``: deterministic scripted responses so the whole app and CI run with no keys.

Model routing: ``tier="fast"`` (extraction) or ``tier="strong"`` (planning, red team).
Every call returns ``LLMUsage`` so tokens and latency appear on the agent timeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from urbanshield.schemas import LLMUsage

Tier = Literal["fast", "strong"]


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


class LLM:
    def chat(
        self,
        messages: list[dict[str, Any]],
        tier: Tier = "strong",
        tools: list[dict[str, Any]] | None = None,
        response_schema: dict[str, Any] | None = None,
    ) -> LLMResponse:
        raise NotImplementedError


def get_llm() -> LLM:
    """The adapter for the configured mode."""
    raise NotImplementedError
