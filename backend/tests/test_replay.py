"""The dashboard replay: one scenario, hop by hop, identical across plans."""

from __future__ import annotations

import numpy as np
import pytest

from urbanshield.city.generator import generate_city
from urbanshield.sim.montecarlo import fall_hops, simulate

S = 400


@pytest.fixture(scope="module")
def city():
    return generate_city(seed=7)


@pytest.fixture(scope="module")
def some_controls(city):
    return {d.id: d.controls[0].kind for d in city.devices[::3]}


@pytest.mark.parametrize("use_controls", [False, True])
def test_fall_hops_match_simulate(city, some_controls, use_controls):
    controls = some_controls if use_controls else None
    run = simulate(city, n_scenarios=S, seed=5, controls=controls)
    lost = np.flatnonzero(run.compromised.any(axis=1))
    assert len(lost) > 0
    for s in [*lost[:25], 0, S - 1]:
        hops = fall_hops(city, int(s), n_scenarios=S, seed=5, controls=controls)
        assert np.array_equal(hops >= 0, run.compromised[s])


def test_fall_hops_are_a_spread_order(city):
    run = simulate(city, n_scenarios=S, seed=5)
    s = int(np.argmax(run.compromised.sum(axis=1)))
    hops = fall_hops(city, s, n_scenarios=S, seed=5)
    index = {d.id: i for i, d in enumerate(city.devices)}
    sources: dict[int, list[int]] = {}
    for e in city.edges:
        if e.kind.value == "reach":
            sources.setdefault(index[e.dst], []).append(index[e.src])
    for i in np.flatnonzero(hops > 0):
        assert any(hops[j] == hops[i] - 1 for j in sources.get(i, [])), "each hop follows a REACH edge"


def test_controls_never_add_losses(city, some_controls):
    run = simulate(city, n_scenarios=S, seed=5)
    s = int(np.argmax(run.compromised.sum(axis=1)))
    bare = fall_hops(city, s, n_scenarios=S, seed=5) >= 0
    guarded = fall_hops(city, s, n_scenarios=S, seed=5, controls=some_controls) >= 0
    assert not (guarded & ~bare).any()


def test_fall_hops_rejects_bad_scenario(city):
    with pytest.raises(ValueError):
        fall_hops(city, S, n_scenarios=S)
