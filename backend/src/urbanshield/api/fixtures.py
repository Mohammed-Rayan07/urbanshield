"""Read demo fixtures from disk. The API serves these until the live pipeline replaces them."""

from __future__ import annotations

import json
from functools import lru_cache

from pydantic import TypeAdapter

from urbanshield.config import FIXTURES_DIR
from urbanshield.schemas import AgentEvent, City, Plan

DEMO_DIR = FIXTURES_DIR / "demo"


def _read(name: str) -> object:
    return json.loads((DEMO_DIR / name).read_text(encoding="utf-8"))


@lru_cache
def demo_city() -> City:
    return City.model_validate(_read("city.json"))


@lru_cache
def demo_plans() -> tuple[Plan, ...]:
    return tuple(TypeAdapter(list[Plan]).validate_python(_read("plans.json")))


@lru_cache
def demo_events() -> tuple[AgentEvent, ...]:
    return tuple(TypeAdapter(list[AgentEvent]).validate_python(_read("events.json")))
