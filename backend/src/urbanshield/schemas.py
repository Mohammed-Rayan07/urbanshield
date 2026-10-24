"""Data contracts shared by every module.

FROZEN: only the integrator edits this file. If you need a change, ask; do not
work around a contract locally. Every module talks to every other module through
these types, which is what lets four people build in parallel.

Conventions
- Money is integer rupees (``*_inr``). Time is hours (``*_h``) or milliseconds (``*_ms``).
- Probabilities and multipliers are floats in [0, 1].
- Timestamps are timezone-aware UTC ``datetime`` values (ISO-8601 on the wire).
- IDs are short, stable strings: devices ``d-001``, plans ``plan-<objective>-<hash>``,
  tool calls ``tc-<uuid4 hex[:12]>``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"
DEFAULT_ALPHA = 0.95


def utcnow() -> datetime:
    return datetime.now(UTC)


class Contract(BaseModel):
    """Base for every wire type: immutable, and unknown fields are rejected."""

    model_config = ConfigDict(frozen=True, extra="forbid")


# --------------------------------------------------------------------------- enums


class Category(StrEnum):
    SIGNAL = "signal"
    METER = "meter"
    STREETLIGHT = "streetlight"
    EV_CHARGER = "ev_charger"


class ControlKind(StrEnum):
    PATCH = "patch"
    SEGMENT = "segment"
    DISABLE_REMOTE = "disable_remote"
    ROTATE_CREDS = "rotate_creds"
    VIRTUAL_PATCH = "virtual_patch"


class Autonomy(StrEnum):
    AUTO = "auto"  # may be applied without a human (low risk, reversible)
    APPROVE = "approve"  # needs an approver


class EdgeKind(StrEnum):
    REACH = "reach"  # attacker can move src -> dst
    DEPENDS = "depends"  # dst's service depends on src (damage flows src -> dst)


class Objective(StrEnum):
    CVAR = "cvar"  # UrbanShield
    MEAN = "mean"  # ablation: same MILP, expected loss
    PATCH_ONLY = "patch_only"  # ablation: CVaR restricted to patches
    CVSS = "cvss"  # baseline
    CVSS_KEV_EPSS = "cvss_kev_epss"  # baseline
    LOSS_PER_INR = "loss_per_inr"  # baseline
    GREEDY_TAIL = "greedy_tail"  # baseline + solver fallback
    BFS_CENTRALITY = "bfs_centrality"  # baseline: "why not just BFS?"


class Solver(StrEnum):
    MILP = "milp"
    GREEDY = "greedy"
    RANKING = "ranking"


class AgentName(StrEnum):
    SENTINEL = "sentinel"
    ANALYST = "analyst"
    PLANNER = "planner"
    REDTEAM = "redteam"
    AUDITOR = "auditor"  # deterministic code, not an LLM
    HUMAN = "human"
    SYSTEM = "system"


class EventKind(StrEnum):
    OBSERVE = "observe"
    TOOL_CALL = "tool_call"
    DECISION = "decision"
    HOLE = "hole"
    APPROVAL = "approval"
    REJECT = "reject"
    APPLY = "apply"
    ERROR = "error"


class ConstraintKind(StrEnum):
    BUDGET = "budget"
    DOWNTIME = "downtime"
    NO_DOWNTIME_ZONE = "no_downtime_zone"
    MUST_FIX = "must_fix"
    FORBID_CONTROL = "forbid_control"


# --------------------------------------------------------------------------- city


class Vulnerability(Contract):
    cve_id: str = Field(pattern=CVE_PATTERN)
    cvss: float = Field(ge=0, le=10)
    epss: float = Field(ge=0, le=1)
    kev: bool = False


class ControlOption(Contract):
    kind: ControlKind
    cost_inr: int = Field(ge=0)
    downtime_h: float = Field(ge=0)
    exploit_mult: float = Field(ge=0, le=1, description="Multiplier on this device's exploit odds")
    spread_mult: float = Field(ge=0, le=1, description="Multiplier on damage this device passes on")
    autonomy: Autonomy = Autonomy.APPROVE


class Device(Contract):
    id: str
    name: str
    category: Category
    zone: str
    lat: float
    lon: float
    firmware: str = Field(description="family/version, e.g. 'lumenos/4.1.3'")
    vulns: list[Vulnerability] = Field(default_factory=list)
    exposed: bool = Field(description="Reachable from the internet (attack entry point)")
    criticality: float = Field(ge=0, le=1, description="Service impact if lost")
    controls: list[ControlOption] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list, description="e.g. 'ambulance_corridor'")


class Edge(Contract):
    src: str
    dst: str
    kind: EdgeKind


class City(Contract):
    id: str
    name: str
    seed: int
    devices: list[Device]
    edges: list[Edge]

    def device(self, device_id: str) -> Device:
        for d in self.devices:
            if d.id == device_id:
                return d
        raise KeyError(device_id)


# --------------------------------------------------------------------------- simulation


@dataclass(frozen=True)
class ScenarioLosses:
    """Output of the Monte Carlo simulator.

    ``device_loss[s, i]`` is the loss attributed to device ``i`` in scenario ``s``
    (its own criticality plus the cascade it caused). Summing a row gives the
    scenario's total loss under the additive model the MILP uses.
    """

    city_id: str
    seed: int
    device_ids: tuple[str, ...]
    device_loss: np.ndarray  # shape (S, N), float64, >= 0
    compromised: np.ndarray  # shape (S, N), bool
    # Length S. Set only when a campaign FIRED in that scenario (every carrier of the CVE
    # is then compromised together); None for ordinary scenarios and for campaigns whose
    # single exploit draw failed.
    campaign_cve: tuple[str | None, ...]

    @property
    def total(self) -> np.ndarray:
        """Additive total loss per scenario, shape (S,)."""
        return self.device_loss.sum(axis=1)

    @property
    def n_scenarios(self) -> int:
        return int(self.device_loss.shape[0])


# --------------------------------------------------------------------------- planning


class Constraint(Contract):
    kind: ConstraintKind
    params: dict[str, float | int | str | list[str]] = Field(default_factory=dict)
    source_sha256: str | None = Field(
        default=None, description="Hash of the natural-language text this came from, if any"
    )


class Budget(Contract):
    inr: int = Field(gt=0)
    downtime_h: float = Field(gt=0)
    alpha: float = Field(default=DEFAULT_ALPHA, gt=0, lt=1)


class PlanMetrics(Contract):
    cvar: float = Field(ge=0, description="CVaR at the plan's alpha, full simulator")
    mean_loss: float = Field(ge=0)
    max_cascade: int = Field(ge=0, description="Largest number of devices lost in one scenario")
    ci_low: float = Field(ge=0, description="Bootstrap 95% CI on cvar")
    ci_high: float = Field(ge=0)
    linear_gap: float = Field(description="(MILP-predicted cvar - simulated cvar) / simulated cvar")
    split: Literal["train", "test"] = "test"


class Plan(Contract):
    id: str
    city_id: str
    objective: Objective
    choices: dict[str, ControlKind] = Field(description="device_id -> chosen control (<=1 per device)")
    cost_inr: int = Field(ge=0)
    downtime_h: float = Field(ge=0)
    solver: Solver
    solve_ms: int = Field(ge=0)
    metrics: PlanMetrics | None = None
    tool_call_id: str | None = None


# --------------------------------------------------------------------------- agents


class Advisory(Contract):
    """The ONLY shape advisory text may take after quarantine. No free text field."""

    cve_id: str = Field(pattern=CVE_PATTERN)
    vendor: str = Field(max_length=64)
    product: str = Field(max_length=64)
    firmware_family: str = Field(max_length=64)
    affected_below: str = Field(max_length=32, description="Versions strictly below this are affected")
    cvss: float = Field(ge=0, le=10)
    source_sha256: str = Field(description="Hash of the raw text, so the original can be audited")


class Match(Contract):
    device_id: str
    cve_id: str = Field(pattern=CVE_PATTERN)
    reason: Literal["firmware_family_and_version", "cve_listed"]


class Assessment(Contract):
    affected: list[str]
    blast_radius: list[str]
    cvar_before: float = Field(ge=0)
    recommendation: Literal["replan", "contain", "monitor"]
    tool_call_ids: list[str]


class Strategy(Contract):
    id: str
    entry_points: list[str] = Field(default_factory=list, description="Device IDs; empty = any exposed")
    target_category: Category | None = None
    pivot_shared_firmware: bool = False
    campaign_cve: str | None = Field(default=None, pattern=CVE_PATTERN)


class Hole(Contract):
    strategy_id: str
    cvar_before: float = Field(ge=0)
    cvar_after_attack: float = Field(ge=0)
    increase_pct: float
    sim_calls: int = Field(ge=0, description="Simulator calls spent finding it")


class Claim(Contract):
    metric: str
    plan_a: float
    plan_b: float
    delta: float
    tool_call_id: str


class ToolResult(Contract):
    id: str
    tool: str
    agent: AgentName
    args: dict[str, Any]
    result: dict[str, Any]
    ts: datetime = Field(default_factory=utcnow)


class LLMUsage(Contract):
    model: str
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    latency_ms: int = Field(ge=0)
    cached: bool = False


class AgentEvent(Contract):
    id: str
    ts: datetime = Field(default_factory=utcnow)
    city_id: str
    run_id: str
    agent: AgentName
    kind: EventKind
    summary: str = Field(max_length=280, description="One line for the timeline")
    payload: dict[str, Any] = Field(default_factory=dict)
    tool_call_id: str | None = None
    parent_id: str | None = None
    usage: LLMUsage | None = None


class AuditEntry(Contract):
    seq: int = Field(ge=0)
    event_id: str
    payload_sha256: str
    prev_hash: str
    hash: str
    signature: str = Field(description="Ed25519 signature over `hash`, hex")


class VerifyResult(Contract):
    ok: bool
    entries: int
    first_bad_seq: int | None = None
    reason: str | None = None
    # Latest entry. The API remembers the highest head it has published; a later, shorter or
    # different head means rows were cut from the end of the log (``truncated``).
    head_seq: int | None = None
    head_hash: str | None = None
    truncated: bool = False
