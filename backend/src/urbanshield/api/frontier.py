"""Budget frontier: worst-case loss of each planner as the budget grows. Owner: C.

Solving eight plans per budget takes tens of seconds, so the frontier is precomputed by
``scripts/build_frontier.py`` (same ``compare`` the ``/plans`` route uses, held-out CVaR) and served
from ``fixtures/frontier.json``. The dashboard's budget slider reads it; nothing is solved on drag.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field

from urbanshield.config import FIXTURES_DIR
from urbanshield.schemas import Contract

FRONTIER_PATH = FIXTURES_DIR / "frontier.json"
FRONTIER_PLANS = ("cvar", "cvss", "bfs_centrality", "mean")


class FrontierPoint(Contract):
    budget_inr: int = Field(gt=0)
    cvar: dict[str, float] = Field(description="objective -> held-out CVaR95 of that plan")
    cost_inr: dict[str, int]
    controls: dict[str, int]


class Frontier(Contract):
    city_id: str
    downtime_h: float
    n_scenarios: int
    test_seed: int
    generated_by: str = "scripts/build_frontier.py"
    points: list[FrontierPoint]


def load_frontier(path: Path = FRONTIER_PATH) -> Frontier | None:
    """The committed frontier, or None if it has not been built yet."""
    if not path.exists():
        return None
    return Frontier.model_validate(json.loads(path.read_text(encoding="utf-8")))
