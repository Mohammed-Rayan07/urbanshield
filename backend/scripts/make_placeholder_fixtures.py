"""Write PLACEHOLDER demo fixtures so the API and UI work before the real pipeline does.

    uv run python scripts/make_placeholder_fixtures.py

Outputs ``fixtures/demo/{city,plans,events}.json``. The values are plausible but fake
(no simulation behind them). They get replaced by ``scripts/build_demo.py`` once the
real city generator, simulator and optimiser land.
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

from urbanshield.schemas import (
    AgentEvent,
    AgentName,
    Autonomy,
    Category,
    City,
    ControlKind,
    ControlOption,
    Device,
    Edge,
    EdgeKind,
    EventKind,
    LLMUsage,
    Objective,
    Plan,
    PlanMetrics,
    Solver,
    Vulnerability,
)

OUT = Path(__file__).resolve().parents[1] / "fixtures" / "demo"
CITY_ID = "mangaluru-demo"

ZONES = {  # zone -> (lat, lon) centre
    "Surathkal": (13.0108, 74.7943),
    "Panambur": (12.9419, 74.8090),
    "Kottara": (12.9050, 74.8380),
    "Hampankatta": (12.8698, 74.8430),
}
CONTROL_TEMPLATES = {
    ControlKind.PATCH: (40_000, 4.0, 0.1, 1.0, Autonomy.APPROVE),
    ControlKind.SEGMENT: (25_000, 2.0, 0.7, 0.3, Autonomy.APPROVE),
    ControlKind.DISABLE_REMOTE: (5_000, 0.0, 0.4, 1.0, Autonomy.APPROVE),
    ControlKind.ROTATE_CREDS: (2_000, 0.0, 0.6, 1.0, Autonomy.AUTO),
    ControlKind.VIRTUAL_PATCH: (15_000, 0.5, 0.3, 1.0, Autonomy.APPROVE),
}


def _controls(rng: random.Random) -> list[ControlOption]:
    kinds = [ControlKind.PATCH, *rng.sample(list(CONTROL_TEMPLATES)[1:], k=rng.randint(1, 3))]
    out = []
    for kind in kinds:
        cost, down, em, sm, auto = CONTROL_TEMPLATES[kind]
        out.append(
            ControlOption(
                kind=kind,
                cost_inr=int(cost * rng.uniform(0.7, 1.3)),
                downtime_h=down,
                exploit_mult=em,
                spread_mult=sm,
                autonomy=auto,
            )
        )
    return out


def build_city(rng: random.Random) -> City:
    devices: list[Device] = []
    edges: list[Edge] = []

    def add(category: Category, zone: str, firmware: str, vulns, exposed, crit, tags=()):
        lat0, lon0 = ZONES[zone]
        idx = len(devices) + 1
        devices.append(
            Device(
                id=f"d-{idx:03d}",
                name=f"{category.value.replace('_', ' ').title()} {zone[:3].upper()}-{idx:02d}",
                category=category,
                zone=zone,
                lat=round(lat0 + rng.uniform(-0.012, 0.012), 5),
                lon=round(lon0 + rng.uniform(-0.010, 0.010), 5),
                firmware=firmware,
                vulns=vulns,
                exposed=exposed,
                criticality=crit,
                controls=_controls(rng),
                tags=list(tags),
            )
        )
        return devices[-1].id

    shared = Vulnerability(cve_id="CVE-2025-31337", cvss=6.1, epss=0.42, kev=True)
    lights = [
        add(Category.STREETLIGHT, rng.choice(list(ZONES)), "lumenos/4.1.3", [shared], i < 2, 0.3)
        for i in range(12)
    ]
    gateway = add(
        Category.EV_CHARGER,
        "Kottara",
        "voltgrid/2.0.1",
        [Vulnerability(cve_id="CVE-2024-48201", cvss=5.4, epss=0.18)],
        False,
        0.5,
    )
    corridor = [
        add(
            Category.SIGNAL,
            zone,
            "trafikon/7.2.0",
            [Vulnerability(cve_id="CVE-2023-29910", cvss=4.3, epss=0.05)],
            False,
            0.95,
            tags=("ambulance_corridor",),
        )
        for zone in ("Surathkal", "Panambur", "Kottara", "Hampankatta", "Hampankatta")
    ]
    decoys = [
        add(
            Category.STREETLIGHT,
            "Hampankatta",
            "decorlite/1.0.0",
            [Vulnerability(cve_id=f"CVE-2025-1000{i}", cvss=9.8, epss=0.02)],
            True,
            0.1,
            tags=("decorative",),
        )
        for i in range(3)
    ]
    others = []
    while len(devices) < 50:
        cat = rng.choice([Category.METER, Category.EV_CHARGER, Category.SIGNAL])
        cvss = round(rng.uniform(3.0, 8.5), 1)
        others.append(
            add(
                cat,
                rng.choice(list(ZONES)),
                f"generic-{cat.value}/1.{rng.randint(0, 9)}",
                [
                    Vulnerability(
                        cve_id=f"CVE-2024-{20000 + len(devices)}",
                        cvss=cvss,
                        epss=round(rng.uniform(0.01, 0.3), 2),
                    )
                ],
                rng.random() < 0.15,
                round(rng.uniform(0.2, 0.8), 2),
            )
        )

    edges += [Edge(src=lights[i], dst=lights[i + 1], kind=EdgeKind.REACH) for i in range(11)]
    edges += [Edge(src=lights[5], dst=gateway, kind=EdgeKind.REACH)]
    edges += [Edge(src=gateway, dst=s, kind=EdgeKind.REACH) for s in corridor]
    edges += [Edge(src=corridor[i], dst=corridor[i + 1], kind=EdgeKind.DEPENDS) for i in range(4)]
    for d in others:
        edges.append(Edge(src=d, dst=rng.choice(others), kind=EdgeKind.REACH))
        if rng.random() < 0.3:
            edges.append(Edge(src=d, dst=rng.choice(others), kind=EdgeKind.DEPENDS))
    edges = [e for e in {(e.src, e.dst, e.kind): e for e in edges if e.src != e.dst}.values()]
    _ = decoys
    return City(id=CITY_ID, name="Mangaluru (demo twin)", seed=7, devices=devices, edges=edges)


def build_plans(city: City) -> list[Plan]:
    def plan(obj, picks, cvar, mean, cascade, solver):
        choices = {d: ControlKind.PATCH if i % 2 else ControlKind.SEGMENT for i, d in enumerate(picks)}
        return Plan(
            id=f"plan-{obj.value}",
            city_id=city.id,
            objective=obj,
            choices=choices,
            cost_inr=480_000 + 7_000 * len(picks),
            downtime_h=18.0,
            solver=solver,
            solve_ms=2_400 if solver == Solver.MILP else 12,
            metrics=PlanMetrics(
                cvar=cvar,
                mean_loss=mean,
                max_cascade=cascade,
                ci_low=cvar * 0.92,
                ci_high=cvar * 1.08,
                linear_gap=0.06,
            ),
            tool_call_id=f"tc-placeholder-{obj.value}",
        )

    ids = [d.id for d in city.devices]
    return [
        plan(Objective.CVAR, ids[5:6] + ids[12:18], 18.4, 3.1, 7, Solver.MILP),
        plan(Objective.MEAN, ids[20:28], 26.7, 2.9, 11, Solver.MILP),
        plan(Objective.CVSS, ids[17:20] + ids[30:35], 39.5, 4.4, 16, Solver.RANKING),
        plan(Objective.BFS_CENTRALITY, ids[0:8], 31.2, 3.9, 13, Solver.RANKING),
        plan(Objective.CVSS_KEV_EPSS, ids[0:3] + ids[30:34], 33.8, 3.8, 14, Solver.RANKING),
        plan(Objective.LOSS_PER_INR, ids[20:27], 27.9, 3.0, 11, Solver.RANKING),
        plan(Objective.GREEDY_TAIL, ids[5:6] + ids[12:17], 20.1, 3.2, 8, Solver.GREEDY),
        plan(Objective.PATCH_ONLY, ids[5:6] + ids[12:16], 24.6, 3.3, 9, Solver.MILP),
    ]


def build_events() -> list[AgentEvent]:
    t0 = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)
    rows = [
        (AgentName.SYSTEM, EventKind.OBSERVE, "New advisory received (sha256 3f9a…)", None),
        (
            AgentName.SENTINEL,
            EventKind.TOOL_CALL,
            "quarantine_extract → CVE-2025-31337, lumenos < 4.2.0",
            "fast",
        ),
        (AgentName.SENTINEL, EventKind.TOOL_CALL, "cross_check vs pinned feed: consistent", None),
        (AgentName.SENTINEL, EventKind.DECISION, "12 streetlights match lumenos/4.1.3 → escalate", "fast"),
        (AgentName.ANALYST, EventKind.TOOL_CALL, "blast_radius(d-006) → 5 corridor signals", None),
        (AgentName.ANALYST, EventKind.DECISION, "Campaign reaches ambulance corridor → replan", "strong"),
        (AgentName.PLANNER, EventKind.DECISION, "Constraint: no downtime in Kottara (festival)", "strong"),
        (AgentName.PLANNER, EventKind.TOOL_CALL, "optimize(cvar, ₹6,00,000, 24h) → plan-cvar", None),
        (AgentName.REDTEAM, EventKind.DECISION, "Trying 5 strategies against plan-cvar", "strong"),
        (AgentName.REDTEAM, EventKind.HOLE, "Hole: pivot via EV gateway d-013 (+9.4% CVaR)", None),
        (AgentName.PLANNER, EventKind.TOOL_CALL, "re-optimize on augmented set → plan-cvar-r1", None),
        (AgentName.REDTEAM, EventKind.DECISION, "No hole above 5% after replan", "strong"),
        (AgentName.AUDITOR, EventKind.DECISION, "6 claims accepted, 1 rejected (value mismatch)", None),
        (AgentName.SYSTEM, EventKind.APPLY, "Auto-applied 4 credential rotations (policy)", None),
        (AgentName.HUMAN, EventKind.APPROVAL, "Approver signed off segmentation of d-013", None),
        (AgentName.SYSTEM, EventKind.APPLY, "Re-simulated: CVaR 39.5 → 18.4 (−53%)", None),
    ]
    out = []
    for i, (agent, kind, summary, tier) in enumerate(rows):
        usage = (
            LLMUsage(
                model=f"{tier}-model",
                prompt_tokens=1800 if tier == "strong" else 600,
                completion_tokens=220,
                latency_ms=2100 if tier == "strong" else 650,
            )
            if tier
            else None
        )
        out.append(
            AgentEvent(
                id=f"ev-{i:03d}",
                ts=t0 + timedelta(seconds=4 * i),
                city_id=CITY_ID,
                run_id="run-placeholder",
                agent=agent,
                kind=kind,
                summary=summary,
                tool_call_id=f"tc-placeholder-{i:03d}" if kind == EventKind.TOOL_CALL else None,
                usage=usage,
            )
        )
    return out


def main() -> None:
    rng = random.Random(7)
    city = build_city(rng)
    OUT.mkdir(parents=True, exist_ok=True)

    def dump(name: str, data) -> None:
        (OUT / name).write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    dump("city.json", city.model_dump(mode="json"))
    dump("plans.json", [p.model_dump(mode="json") for p in build_plans(city)])
    dump("events.json", [e.model_dump(mode="json") for e in build_events()])
    print(f"wrote placeholder fixtures to {OUT}")


if __name__ == "__main__":
    main()
