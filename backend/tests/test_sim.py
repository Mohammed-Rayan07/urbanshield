"""Monte Carlo simulator. Owner: A."""

from __future__ import annotations

import time

import numpy as np

from urbanshield.schemas import ControlKind, Strategy
from urbanshield.sim.montecarlo import simulate


def test_shapes_and_bounds(tiny_city) -> None:
    out = simulate(tiny_city, n_scenarios=500, seed=1)
    assert out.device_loss.shape == out.compromised.shape == (500, 6)
    assert out.device_ids == tuple(d.id for d in tiny_city.devices)
    assert len(out.campaign_cve) == 500
    assert (out.device_loss >= 0).all()
    assert out.total.max() > 0


def test_deterministic_for_seed(tiny_city) -> None:
    a = simulate(tiny_city, n_scenarios=300, seed=3)
    b = simulate(tiny_city, n_scenarios=300, seed=3)
    assert np.array_equal(a.device_loss, b.device_loss)


def test_controls_reduce_loss(tiny_city) -> None:
    base = simulate(tiny_city, n_scenarios=2000, seed=4)
    fixed = simulate(
        tiny_city,
        n_scenarios=2000,
        seed=4,
        controls={"d-001": ControlKind.PATCH, "d-003": ControlKind.SEGMENT},
    )
    assert fixed.total.mean() < base.total.mean()


def test_campaigns_are_correlated(tiny_city) -> None:
    out = simulate(tiny_city, n_scenarios=2000, seed=5, campaign_rate=0.5)
    rows = [s for s, cve in enumerate(out.campaign_cve) if cve == "CVE-2025-31337"]
    assert rows, "the shared CVE should drive some campaign scenarios"
    carriers = [
        i for i, d in enumerate(tiny_city.devices) if any(v.cve_id == "CVE-2025-31337" for v in d.vulns)
    ]
    together = out.compromised[np.ix_(rows, carriers)].all(axis=1).mean()
    assert together > 0.9


def test_strategy_restricts_entry(tiny_city) -> None:
    out = simulate(
        tiny_city,
        n_scenarios=500,
        seed=6,
        campaign_rate=0.0,
        strategy=Strategy(id="s1", entry_points=["d-006"]),
    )
    reachable = {"d-006"}
    for i, dev in enumerate(tiny_city.devices):
        if dev.id not in reachable:
            assert not out.compromised[:, i].any()


def test_fast_enough() -> None:
    from urbanshield.city.generator import generate_city

    city = generate_city(seed=7)
    t = time.perf_counter()
    simulate(city, n_scenarios=2000, seed=0)
    assert time.perf_counter() - t < 2.0
