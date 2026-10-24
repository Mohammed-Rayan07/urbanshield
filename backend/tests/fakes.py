"""Test-only stand-ins for the parts the agents drive but C does not own. Owner: C.

``fake_engine(city)`` binds every ``Engine`` field. City (A) and optimiser (B) functions are
small, exact versions that are good enough on ``tiny_city``: plain-Python BFS, a pinned
feed dict, a brute-force CVaR/mean solver and ranking baselines. The simulator and the
Auditor are S's real modules, so agent tests exercise the real numbers.

``SpyLLM`` wraps any LLM and records every request, for the structural-guarantee and
transcript-determinism tests.
"""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import math
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import numpy as np

from urbanshield.agents.engine import Engine
from urbanshield.agents.llm import LLMResponse, Tier, ToolCallRequest
from urbanshield.agents.mock import MockLLM
from urbanshield.agents.tools import RunContext
from urbanshield.config import Settings
from urbanshield.guard import auditor
from urbanshield.schemas import (
    Budget,
    City,
    Constraint,
    ConstraintKind,
    ControlKind,
    LLMUsage,
    Objective,
    Plan,
    PlanMetrics,
    ScenarioLosses,
    Solver,
)
from urbanshield.sim import montecarlo

# Presets written for this fake world (tiny_city + FAKE_FEED). The shipped presets in
# data/advisories are written for the real demo twin and are tested against it.
TEST_ADVISORIES = Path(__file__).parent / "data" / "advisories"

FAKE_FEED: dict[str, dict[str, Any]] = {
    "CVE-2025-31337": {
        "cve_id": "CVE-2025-31337",
        "cvss": 6.1,
        "epss": 0.4,
        "kev": True,
        "vendor": "Lumenos",
        "product": "SL-200 streetlight controller",
        "summary": "Lumenos SL-200 streetlight controllers running firmware before 4.2.0 accept "
        "unauthenticated configuration writes over the management port.",
    },
    "CVE-2024-48201": {
        "cve_id": "CVE-2024-48201",
        "cvss": 5.4,
        "epss": 0.2,
        "kev": False,
        "vendor": "Voltgrid",
        "product": "VG-50 EV charger",
        "summary": "Voltgrid VG-50 chargers before 2.1.0 expose a debug service.",
    },
    "CVE-2023-29910": {
        "cve_id": "CVE-2023-29910",
        "cvss": 4.3,
        "epss": 0.1,
        "kev": False,
        "vendor": "Trafikon",
        "product": "TS-7 traffic signal controller",
        "summary": "Trafikon TS-7 controllers below 7.3.0 never expire web console sessions.",
    },
}


def fake_feed_record(cve_id: str) -> dict | None:
    record = FAKE_FEED.get(cve_id)
    return dict(record) if record else None


# --------------------------------------------------------------------------- city (A)


@dataclass(frozen=True)
class FakeGraphs:
    reach: dict[str, set[str]]
    depends: dict[str, set[str]]


def build_graphs(city: City) -> FakeGraphs:
    reach: dict[str, set[str]] = {d.id: set() for d in city.devices}
    depends: dict[str, set[str]] = {d.id: set() for d in city.devices}
    for e in city.edges:
        (reach if e.kind.value == "reach" else depends)[e.src].add(e.dst)
    return FakeGraphs(reach=reach, depends=depends)


def _closure(adj: dict[str, set[str]], sources: Iterable[str], blocked: set[str]) -> set[str]:
    seen = {s for s in sources if s not in blocked}
    queue = deque(sorted(seen))
    while queue:
        for nxt in sorted(adj[queue.popleft()]):
            if nxt not in seen and nxt not in blocked:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def bfs_reach(graphs: FakeGraphs, sources: Iterable[str], blocked: Iterable[str] = ()) -> set[str]:
    return _closure(graphs.reach, sources, set(blocked))


def blast_radius(graphs: FakeGraphs, device_id: str) -> list[str]:
    return sorted(_closure(graphs.depends, [device_id], set()) - {device_id})


# --------------------------------------------------------------------------- optimiser (B)


def cvar(losses: np.ndarray, alpha: float) -> float:
    k = max(1, math.ceil((1 - alpha) * len(losses) - 1e-9))
    return float(np.sort(losses)[-k:].mean())


def _options(city: City, constraints: list[Constraint], patch_only: bool) -> list[list[Any]]:
    """Per device: None (no control) plus every option the constraints allow."""
    no_downtime = {str(c.params["zone"]) for c in constraints if c.kind == ConstraintKind.NO_DOWNTIME_ZONE}
    forbidden = {str(c.params["kind"]) for c in constraints if c.kind == ConstraintKind.FORBID_CONTROL}
    must = {str(c.params["device_id"]) for c in constraints if c.kind == ConstraintKind.MUST_FIX}
    out = []
    for d in city.devices:
        opts = [
            o
            for o in d.controls
            if o.kind.value not in forbidden
            and not (patch_only and o.kind != ControlKind.PATCH)
            and not (d.zone in no_downtime and o.downtime_h > 0)
        ]
        out.append(opts if d.id in must else [None, *opts])
    return out


def _plan(city: City, objective: Objective, choices: dict[str, ControlKind], solver: Solver) -> Plan:
    opts = {(d.id, o.kind): o for d in city.devices for o in d.controls}
    digest = hashlib.sha256(json.dumps(sorted((k, v.value) for k, v in choices.items())).encode()).hexdigest()
    return Plan(
        id=f"plan-{objective.value}-{digest[:8]}",
        city_id=city.id,
        objective=objective,
        choices=dict(sorted(choices.items())),
        cost_inr=sum(opts[(d, k)].cost_inr for d, k in choices.items()),
        downtime_h=sum(opts[(d, k)].downtime_h for d, k in choices.items()),
        solver=solver,
        solve_ms=0,
    )


def solve(
    city: City,
    losses: ScenarioLosses,
    budget: Budget,
    constraints: list[Constraint] | None = None,
    objective: Objective = Objective.CVAR,
    time_limit_s: float = 30.0,
) -> Plan:
    """Exhaustive search over the linear loss model (tiny cities only)."""
    constraints = constraints or []
    per_device = _options(city, constraints, patch_only=objective == Objective.PATCH_ONLY)
    best: tuple[float, float, int, dict[str, ControlKind]] | None = None
    for combo in itertools.product(*per_device):
        chosen = [(d, o) for d, o in zip(city.devices, combo, strict=True) if o is not None]
        cost = sum(o.cost_inr for _, o in chosen)
        downtime = sum(o.downtime_h for _, o in chosen)
        if cost > budget.inr or downtime > budget.downtime_h:
            continue
        keep = np.ones(len(city.devices))
        for i, o in enumerate(combo):
            if o is not None:
                keep[i] = o.exploit_mult * o.spread_mult
        total = losses.device_loss @ keep
        score = float(total.mean()) if objective == Objective.MEAN else cvar(total, budget.alpha)
        key = (round(score, 12), cost, len(chosen), {d.id: o.kind for d, o in chosen})
        if best is None or key[:3] < best[:3]:
            best = key
    assert best is not None, "no feasible plan"
    return _plan(city, objective, best[3], Solver.MILP)


def _rank_and_buy(city: City, budget: Budget, constraints: list[Constraint], objective: Objective) -> Plan:
    per_device = dict(zip((d.id for d in city.devices), _options(city, constraints, False), strict=True))
    ranked = sorted(city.devices, key=lambda d: (-max((v.cvss for v in d.vulns), default=0.0), d.id))
    choices: dict[str, ControlKind] = {}
    cost = downtime = 0.0
    for d in ranked:
        opts = sorted(
            (o for o in per_device[d.id] if o is not None), key=lambda o: o.kind != ControlKind.PATCH
        )
        for o in opts:
            if cost + o.cost_inr <= budget.inr and downtime + o.downtime_h <= budget.downtime_h:
                choices[d.id] = o.kind
                cost += o.cost_inr
                downtime += o.downtime_h
                break
    return _plan(city, objective, choices, Solver.RANKING)


@dataclass
class FakeOptimiser:
    """B's evaluate/compare on top of the real simulator. Counts calls for assertions."""

    calls: dict[str, int] = field(default_factory=lambda: {"compare": 0, "solve": 0, "evaluate": 0})

    def solve(self, *args: Any, **kwargs: Any) -> Plan:
        self.calls["solve"] += 1
        return solve(*args, **kwargs)

    def evaluate_plan(
        self, city: City, plan: Plan, alpha: float, n_scenarios: int = 400, seed: int = 2, **_: Any
    ) -> PlanMetrics:
        self.calls["evaluate"] += 1
        losses = montecarlo.simulate(city, n_scenarios, seed=seed, controls=dict(plan.choices))
        c = cvar(losses.total, alpha)
        return PlanMetrics(
            cvar=c,
            mean_loss=float(losses.total.mean()),
            max_cascade=int(losses.compromised.sum(axis=1).max()),
            ci_low=c,
            ci_high=c,
            linear_gap=0.0,
        )

    def compare(
        self, city: City, budget: Budget, constraints: list[Constraint] | None = None, n_scenarios: int = 400
    ) -> list[Plan]:
        self.calls["compare"] += 1
        constraints = constraints or []
        train = montecarlo.simulate(city, n_scenarios, seed=1)
        plans = [solve(city, train, budget, constraints, o) for o in (Objective.CVAR, Objective.MEAN)]
        plans.append(solve(city, train, budget, constraints, Objective.PATCH_ONLY))
        plans += [
            _rank_and_buy(city, budget, constraints, o)
            for o in Objective
            if o not in (Objective.CVAR, Objective.MEAN, Objective.PATCH_ONLY)
        ]
        return [
            p.model_copy(update={"metrics": self.evaluate_plan(city, p, budget.alpha, n_scenarios)})
            for p in plans
        ]


def fake_engine(
    city: City,
    feed_record: Callable[[str], dict | None] = fake_feed_record,
    optimiser: FakeOptimiser | None = None,
) -> Engine:
    opt = optimiser or FakeOptimiser()
    return Engine(
        generate_city=lambda seed=0, **_: city,
        build_graphs=build_graphs,
        bfs_reach=bfs_reach,
        blast_radius=blast_radius,
        feed_record=feed_record,
        simulate=montecarlo.simulate,
        solve=opt.solve,
        compare=opt.compare,
        evaluate_plan=opt.evaluate_plan,
        cvar=cvar,
        train_seed=1,
        test_seed=2,
        check_claims=auditor.check_claims,
        render_claim=auditor.render,
    )


def settings_for(tmp_path: Path, **overrides: Any) -> Settings:
    """Mock-mode settings with a throwaway database and a fixed signing key."""
    base = Settings(
        llm_mode="mock",
        llm_base_url=None,
        llm_api_key=None,
        model_fast="fast-model",
        model_strong="strong-model",
        db_path=tmp_path / "test.db",
        signing_key_hex="11" * 32,
        city_seed=7,
        n_scenarios=400,
        cors_origins=("http://localhost:5173",),
    )
    return replace(base, **overrides)


def make_ctx(
    city: City,
    llm: Any = None,
    engine: Engine | None = None,
    emit: Callable[[Any], None] | None = None,
    budget: Budget | None = None,
    n_scenarios: int = 400,
    run_id: str = "run-test",
) -> RunContext:
    return RunContext(
        run_id=run_id,
        city=city,
        engine=engine or fake_engine(city),
        llm=llm or MockLLM(),
        emit=emit or (lambda _: None),
        budget=budget or Budget(inr=70_000, downtime_h=8),
        n_scenarios=n_scenarios,
    )


# --------------------------------------------------------------------------- LLM spy


@dataclass
class SpyLLM:
    """Records every request (canonical JSON) before delegating."""

    inner: Any
    requests: list[dict[str, Any]] = field(default_factory=list)

    @property
    def mode(self) -> str:
        return self.inner.mode

    def chat(
        self,
        task: str,
        messages: list[dict[str, Any]],
        tier: Tier = "strong",
        tools: list[dict[str, Any]] | None = None,
        json_output: bool = False,
    ) -> LLMResponse:
        request = {
            "task": task,
            "tier": tier,
            "messages": messages,
            "tools": tools,
            "json_output": json_output,
        }
        self.requests.append(copy.deepcopy(request))  # callers keep appending to ``messages``
        return self.inner.chat(task, messages, tier=tier, tools=tools, json_output=json_output)

    def transcript(self) -> str:
        return json.dumps(self.requests, sort_keys=True, ensure_ascii=False)

    def requests_for(self, prefix: str) -> list[dict[str, Any]]:
        return [r for r in self.requests if r["task"].startswith(prefix)]


def reply(content: dict | str | None = None, calls: list[tuple[str, dict]] = ()) -> LLMResponse:
    """A canned response: JSON content and/or tool calls ``[(name, arguments), ...]``."""
    text = json.dumps(content) if isinstance(content, dict) else content
    usage = LLMUsage(model="scripted", prompt_tokens=10, completion_tokens=5, latency_ms=0)
    requests = [ToolCallRequest(id=f"call_{i}", name=n, arguments=a) for i, (n, a) in enumerate(calls)]
    return LLMResponse(content=text, tool_calls=requests, usage=usage)


@dataclass
class ScriptedLLM:
    """Answers tasks listed in ``script`` in order; everything else goes to the mock."""

    script: dict[str, list[LLMResponse]]
    mode: str = "mock"
    fallback: Any = field(default_factory=MockLLM)

    def chat(
        self,
        task: str,
        messages: list[dict[str, Any]],
        tier: Tier = "strong",
        tools: list[dict[str, Any]] | None = None,
        json_output: bool = False,
    ) -> LLMResponse:
        if self.script.get(task):
            return self.script[task].pop(0)
        return self.fallback.chat(task, messages, tier=tier, tools=tools, json_output=json_output)
