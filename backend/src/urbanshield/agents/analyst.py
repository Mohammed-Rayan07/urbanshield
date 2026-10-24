"""Analyst agent: how bad is it, and do we replan, contain or monitor? Owner: C."""

from __future__ import annotations

from urbanshield.schemas import Assessment, City, Match


def assess(city: City, matches: list[Match], run_id: str) -> Assessment:
    """Investigate with BFS, blast radius and simulation tools; the LLM decides the
    recommendation, the numbers come from the tool results it cites."""
    raise NotImplementedError
