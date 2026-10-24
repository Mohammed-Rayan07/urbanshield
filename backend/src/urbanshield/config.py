"""Runtime settings, read once from the environment (and `.env` in development)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BACKEND_DIR / "data"
FIXTURES_DIR = BACKEND_DIR / "fixtures"

LLMMode = Literal["live", "replay", "mock"]


@dataclass(frozen=True)
class Settings:
    llm_mode: LLMMode
    llm_base_url: str | None
    llm_api_key: str | None
    model_fast: str
    model_strong: str
    db_path: Path
    signing_key_hex: str | None
    city_seed: int
    n_scenarios: int
    cors_origins: tuple[str, ...]


@lru_cache
def get_settings() -> Settings:
    load_dotenv(BACKEND_DIR.parent / ".env")
    mode = os.getenv("LLM_MODE", "mock")
    if mode not in ("live", "replay", "mock"):
        raise ValueError(f"LLM_MODE must be live, replay or mock, got {mode!r}")
    return Settings(
        llm_mode=mode,  # type: ignore[arg-type]
        llm_base_url=os.getenv("LLM_BASE_URL") or None,
        llm_api_key=os.getenv("LLM_API_KEY") or None,
        model_fast=os.getenv("LLM_MODEL_FAST", "fast-model"),
        model_strong=os.getenv("LLM_MODEL_STRONG", "strong-model"),
        db_path=Path(os.getenv("DB_PATH", str(BACKEND_DIR / "urbanshield.db"))),
        signing_key_hex=os.getenv("AUDIT_SIGNING_KEY") or None,
        city_seed=int(os.getenv("CITY_SEED", "7")),
        n_scenarios=int(os.getenv("N_SCENARIOS", "2000")),
        cors_origins=tuple(os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")),
    )
