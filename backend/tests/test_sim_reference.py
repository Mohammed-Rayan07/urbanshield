"""Differential test for the simulator. Owner: S.

A naive reference walks each scenario with plain Python sets and queues, reading the same
uniforms as ``simulate()`` (``montecarlo._draw``). On random small cities, with random
controls, Red-Team strategies and campaign rates, the vectorised simulator must agree with it
exactly: same compromised sets, same per-device losses, same fired campaigns.
"""

from __future__ import annotations

import math
from collections import deque

import numpy as np

from urbanshield.schemas import (
    Category,
    City,
    ControlKind,
    ControlOption,
    Device,
    Edge,
    EdgeKind,
    Strategy,
    Vulnerability,
)
from urbanshield.sim import montecarlo as mc

N_CITIES = 300
N_SCENARIOS = 60


def _bfs(adj: dict[int, set[int]], starts: list[int]) -> set[int]:
    seen, queue = set(starts), deque(starts)
    while queue:
        for j in adj[queue.popleft()]:
            if j not in seen:
                seen.add(j)
                queue.append(j)
    return seen


def _reference(city: City, n_scen: int, seed: int, controls, strategy, rate):
    """One scenario at a time, straight from the model in docs/ASSUMPTIONS.md."""
    devs = city.devices
    n = len(devs)
    ids = [d.id for d in devs]
    draws = mc._draw(np.random.default_rng(seed), n_scen, n)
    em, sm = [1.0] * n, [1.0] * n
    for i, d in enumerate(devs):
        if d.id in controls:
            opt = next(c for c in d.controls if c.kind == controls[d.id])
            em[i], sm[i] = opt.exploit_mult, opt.spread_mult
    p = [(1 - math.prod(1 - v.epss for v in d.vulns)) * em[i] for i, d in enumerate(devs)]
    reach: dict[int, set[int]] = {i: set() for i in range(n)}
    deps: dict[int, set[int]] = {i: set() for i in range(n)}
    for e in city.edges:
        (reach if e.kind == EdgeKind.REACH else deps)[ids.index(e.src)].add(ids.index(e.dst))

    if strategy and strategy.entry_points:
        w = [1.0 if d.id in strategy.entry_points else 0.0 for d in devs]
    else:
        w = [1.0 if d.exposed else 0.0 for d in devs]
    if strategy and strategy.target_category:
        for i in range(n):
            if any(devs[j].category == strategy.target_category for j in _bfs(reach, [i])):
                w[i] *= mc.TARGET_ENTRY_WEIGHT

    carriers: dict[str, set[int]] = {}
    epss: dict[str, float] = {}
    for i, d in enumerate(devs):
        for v in d.vulns:
            carriers.setdefault(v.cve_id, set()).add(i)
            epss[v.cve_id] = max(epss.get(v.cve_id, 0.0), v.epss)
    if strategy and strategy.campaign_cve:
        cves = [strategy.campaign_cve] if strategy.campaign_cve in carriers else []
    else:
        cves = sorted(carriers)
    cw = [epss[c] * len(carriers[c]) for c in cves]

    family = [d.firmware.split("/")[0] for d in devs]
    pivot = bool(strategy and strategy.pivot_shared_firmware)
    crit = [d.criticality for d in devs]
    per_dev = [crit[i] + sm[i] * sum(crit[j] for j in _bfs(deps, [i]) - {i}) for i in range(n)]

    comp = np.zeros((n_scen, n), dtype=bool)
    fired_out: list[str | None] = []
    for s in range(n_scen):
        u = draws.exploit[s]
        fired = None
        if cves and sum(cw) > 0 and draws.is_campaign[s] < rate:
            cum, k = 0.0, len(cves) - 1
            for idx, wt in enumerate(cw):
                cum += wt / sum(cw)
                if draws.campaign_pick[s] < cum:
                    k = idx
                    break
            if draws.campaign_fire[s] < epss[cves[k]]:
                fired = cves[k]
        if fired:
            seeds = {i for i in carriers[fired] if draws.campaign_fire[s] < epss[fired] * em[i]}
        else:
            cand = [i for i in range(n) if w[i] > 0]
            ranked = sorted(cand, key=lambda i: (-(math.log1p(-draws.entry_key[s, i]) / w[i]), i))
            seeds = {i for i in ranked[: min(draws.entry_count[s], len(cand))] if u[i] < p[i]}
        lost, queue = set(seeds), deque(seeds)
        while queue:
            i = queue.popleft()
            pivots = {j for j in range(n) if pivot and family[j] == family[i] and u[j] < em[j]}
            for j in (reach[i] | pivots) - lost:
                if j in pivots or u[j] < p[j]:
                    lost.add(j)
                    queue.append(j)
        comp[s, list(lost)] = True
        fired_out.append(fired)
    return comp, comp * np.array(per_dev)[None, :], tuple(fired_out)


def _random_city(rng: np.random.Generator, n: int) -> City:
    opts = [
        ControlOption(kind=ControlKind.PATCH, cost_inr=1, downtime_h=1, exploit_mult=0.1, spread_mult=1.0),
        ControlOption(kind=ControlKind.SEGMENT, cost_inr=1, downtime_h=1, exploit_mult=0.7, spread_mult=0.3),
        ControlOption(
            kind=ControlKind.ROTATE_CREDS, cost_inr=1, downtime_h=0, exploit_mult=0.0, spread_mult=0.5
        ),
    ]
    cves = [
        Vulnerability(cve_id=f"CVE-2024-{1000 + k}", cvss=5, epss=float(rng.choice([0, rng.random()])))
        for k in range(6)
    ]
    devs = [
        Device(
            id=f"d-{i:03d}",
            name="x",
            category=list(Category)[rng.integers(4)],
            zone="Z",
            lat=0,
            lon=0,
            firmware=f"f{rng.integers(3)}/1",
            vulns=list(rng.choice(cves, rng.integers(0, 3), replace=False)),
            exposed=bool(rng.random() < 0.3),
            criticality=float(rng.random()),
            controls=opts,
        )
        for i in range(n)
    ]
    edges = [
        Edge(src=devs[a].id, dst=devs[b].id, kind=kind)
        for kind, m in ((EdgeKind.REACH, 2 * n), (EdgeKind.DEPENDS, n // 2))
        for a, b in rng.integers(0, n, size=(m, 2))
    ]
    return City(id="r", name="r", seed=0, devices=devs, edges=edges)


def _random_case(rng: np.random.Generator):
    n = int(rng.integers(1, 12))
    city = _random_city(rng, n)
    ids = [d.id for d in city.devices]
    kinds = [ControlKind.PATCH, ControlKind.SEGMENT, ControlKind.ROTATE_CREDS]
    controls = {i: kinds[rng.integers(3)] for i in ids if rng.random() < 0.3}
    strategy = None
    if rng.random() < 0.7:
        strategy = Strategy(
            id="s",
            entry_points=list(rng.choice(ids, rng.integers(0, min(3, n) + 1), replace=False)),
            target_category=[None, *Category][rng.integers(5)],
            pivot_shared_firmware=bool(rng.random() < 0.5),
            campaign_cve=[None, "CVE-2024-1000", "CVE-2024-1003", "CVE-2099-0001"][rng.integers(4)],
        )
    rate = float(rng.choice([0.0, 0.2, 0.7, 1.0]))
    return city, controls, strategy, rate


def test_simulate_matches_naive_reference() -> None:
    rng = np.random.default_rng(123)
    for trial in range(N_CITIES):
        city, controls, strategy, rate = _random_case(rng)
        out = mc.simulate(
            city, N_SCENARIOS, seed=trial, controls=controls, strategy=strategy, campaign_rate=rate
        )
        comp, loss, fired = _reference(city, N_SCENARIOS, trial, controls, strategy, rate)
        assert np.array_equal(out.compromised, comp), f"compromised differs, trial {trial}"
        np.testing.assert_allclose(out.device_loss, loss, rtol=0, atol=1e-12, err_msg=f"trial {trial}")
        assert out.campaign_cve == fired, f"fired campaigns differ, trial {trial}"
