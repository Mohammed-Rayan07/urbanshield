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
    budget_inr: int = 150_000  # the demo budget: ₹1.5 lakh, a quarter of the original ₹6 lakh
    downtime_h: float = 24.0
    approval_timeout_s: float = 600.0
    allow_demo_tamper: bool = False  # POST /api/audit/tamper exists only when ALLOW_DEMO_TAMPER=1


def _flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes")


@lru_cache
def get_settings() -> Settings:
    load_dotenv(BACKEND_DIR.parent / ".env")
    mode = _env("LLM_MODE", "mock")
    if mode not in ("live", "replay", "mock"):
        raise ValueError(f"LLM_MODE must be live, replay or mock, got {mode!r}")
    return Settings(
        llm_mode=mode,  # type: ignore[arg-type]
        llm_base_url=_env("LLM_BASE_URL") or None,
        llm_api_key=_env("LLM_API_KEY") or None,
        model_fast=_env("LLM_MODEL_FAST", "fast-model"),
        model_strong=_env("LLM_MODEL_STRONG", "strong-model"),
        db_path=Path(_env("DB_PATH", str(BACKEND_DIR / "urbanshield.db"))),
        signing_key_hex=_env("AUDIT_SIGNING_KEY") or None,
        city_seed=int(_env("CITY_SEED", "7")),
        n_scenarios=int(_env("N_SCENARIOS", "2000")),
        cors_origins=tuple(o.strip() for o in _env("CORS_ORIGINS", "http://localhost:5173").split(",")),
        budget_inr=int(_env("BUDGET_INR", "150000")),
        downtime_h=float(_env("DOWNTIME_H", "24")),
        approval_timeout_s=float(_env("APPROVAL_TIMEOUT_S", "600")),
        allow_demo_tamper=_flag("ALLOW_DEMO_TAMPER"),
    )


def _env(name: str, default: str = "") -> str:
    """The variable, or ``default`` when it is unset *or empty* (``.env.example`` ships ``DB_PATH=``)."""
    return os.getenv(name, "").strip() or default
