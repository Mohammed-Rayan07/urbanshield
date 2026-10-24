"""Contracts and placeholder fixtures stay valid. Owner: integrator."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from urbanshield.api import fixtures
from urbanshield.schemas import Category, Device, Plan, Vulnerability


def test_vulnerability_rejects_bad_cve_id() -> None:
    with pytest.raises(ValidationError):
        Vulnerability(cve_id="cve-1", cvss=5, epss=0.1)


def test_contracts_are_frozen_and_strict() -> None:
    v = Vulnerability(cve_id="CVE-2024-0001", cvss=5, epss=0.1)
    with pytest.raises(ValidationError):
        v.cvss = 9  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Device(
            id="x",
            name="x",
            category=Category.METER,
            zone="z",
            lat=0,
            lon=0,
            firmware="f",
            exposed=False,
            criticality=0.5,
            surprise=1,
        )  # type: ignore[call-arg]


def test_demo_fixtures_validate() -> None:
    city = fixtures.demo_city()
    plans = fixtures.demo_plans()
    events = fixtures.demo_events()
    ids = {d.id for d in city.devices}
    assert len(city.devices) >= 40
    assert all(e.src in ids and e.dst in ids for e in city.edges)
    assert all(isinstance(p, Plan) and set(p.choices) <= ids for p in plans)
    assert events and events[0].ts <= events[-1].ts
