"""Planner agent: plain-language constraints -> ``Constraint`` rows -> optimiser. Owner: C."""

from __future__ import annotations

from urbanshield.schemas import City, Constraint


def parse_constraints(city: City, text: str) -> list[Constraint]:
    """LLM (strong tier) turns e.g. 'Zone 3 festival this weekend, no streetlight
    downtime' into validated ``Constraint`` objects. Unknown zones or devices are
    rejected, never guessed. The UI shows the rows before they are used."""
    raise NotImplementedError
