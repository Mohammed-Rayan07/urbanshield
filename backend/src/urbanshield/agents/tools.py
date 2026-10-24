"""Tool registry: the only way an agent touches the world. Owner: C.

Each tool is a plain function wrapped with a Pydantic argument model. ``call``:
1. checks the allowlist (``guard.allowlist.authorize``),
2. validates arguments,
3. runs the deterministic function,
4. stores a ``ToolResult`` with a fresh ``tc-…`` id (for provenance and the Auditor),
5. emits a TOOL_CALL ``AgentEvent``.
"""

from __future__ import annotations

from typing import Any

from urbanshield.schemas import AgentName, ToolResult


def openai_tool_specs(agent: AgentName) -> list[dict[str, Any]]:
    """JSON-schema tool definitions for the tools ``agent`` may call."""
    raise NotImplementedError


def call(agent: AgentName, tool: str, arguments: dict[str, Any], run_id: str) -> ToolResult:
    raise NotImplementedError
