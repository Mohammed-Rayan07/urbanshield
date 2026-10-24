"""Per-agent tool allowlists (least privilege). Owner: C.

The orchestrator calls ``authorize`` before every tool call; an agent asking for a
tool outside its list gets a REJECT event, never the tool. Only the human approval
path can apply a plan, so no agent holds a write tool on city state. ``SYSTEM`` is the
orchestrator's own code (no LLM): it may only re-simulate what has been applied.
"""

from __future__ import annotations

from types import MappingProxyType

from urbanshield.schemas import AgentName

ALLOWLIST: MappingProxyType[AgentName, frozenset[str]] = MappingProxyType(
    {
        AgentName.SENTINEL: frozenset({"quarantine_extract", "cross_check", "match_inventory"}),
        AgentName.ANALYST: frozenset({"bfs_reach", "blast_radius", "simulate", "query_devices"}),
        AgentName.PLANNER: frozenset({"parse_constraint", "optimize", "compare", "plan_diff"}),
        AgentName.REDTEAM: frozenset({"simulate_strategy", "bfs_reach", "list_controls"}),
        AgentName.SYSTEM: frozenset({"evaluate_applied"}),
    }
)


class ToolNotAllowed(PermissionError):
    def __init__(self, agent: AgentName, tool: str) -> None:
        super().__init__(f"{agent} may not call {tool}")
        self.agent = agent
        self.tool = tool


def authorize(agent: AgentName, tool: str) -> None:
    """Raise ``ToolNotAllowed`` unless ``tool`` is on ``agent``'s list."""
    if tool not in ALLOWLIST.get(agent, frozenset()):
        raise ToolNotAllowed(agent, tool)
