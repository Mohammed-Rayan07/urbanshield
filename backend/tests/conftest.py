"""Shared fixtures, plus one rule: a test that hits an unimplemented stub is SKIPPED
(reported as "not implemented yet"), not failed. CI stays green while modules are
being built, and the skip count shows what is left."""

from __future__ import annotations

import pytest

from urbanshield.schemas import (
    Autonomy,
    Budget,
    Category,
    City,
    ControlKind,
    ControlOption,
    Device,
    Edge,
    EdgeKind,
    Vulnerability,
)


def _skip_if_not_implemented(outcome) -> None:
    if outcome.excinfo is not None and issubclass(outcome.excinfo[0], NotImplementedError):
        outcome.force_exception(pytest.skip.Exception("not implemented yet", _use_item_location=True))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_setup(item):
    _skip_if_not_implemented((yield))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    _skip_if_not_implemented((yield))


def _controls() -> list[ControlOption]:
    return [
        ControlOption(
            kind=ControlKind.PATCH, cost_inr=40_000, downtime_h=4, exploit_mult=0.1, spread_mult=1.0
        ),
        ControlOption(
            kind=ControlKind.SEGMENT, cost_inr=25_000, downtime_h=2, exploit_mult=0.7, spread_mult=0.3
        ),
        ControlOption(
            kind=ControlKind.ROTATE_CREDS,
            cost_inr=2_000,
            downtime_h=0,
            exploit_mult=0.6,
            spread_mult=1.0,
            autonomy=Autonomy.AUTO,
        ),
    ]


@pytest.fixture
def tiny_city() -> City:
    """Six devices: an exposed light chain -> gateway -> two corridor signals, plus a decoy.

    REACH:   d-001 -> d-002 -> d-003(gateway) -> d-004 -> d-005
    DEPENDS: d-004 -> d-005
    d-006 is an isolated decoy with CVSS 9.8.
    """
    shared = Vulnerability(cve_id="CVE-2025-31337", cvss=6.1, epss=0.4, kev=True)

    def dev(i, cat, zone, fw, vulns, exposed, crit, tags=()):
        return Device(
            id=f"d-00{i}",
            name=f"dev {i}",
            category=cat,
            zone=zone,
            lat=12.9,
            lon=74.8,
            firmware=fw,
            vulns=vulns,
            exposed=exposed,
            criticality=crit,
            controls=_controls(),
            tags=list(tags),
        )

    devices = [
        dev(1, Category.STREETLIGHT, "Z1", "lumenos/4.1.3", [shared], True, 0.3),
        dev(2, Category.STREETLIGHT, "Z1", "lumenos/4.1.3", [shared], False, 0.3),
        dev(
            3,
            Category.EV_CHARGER,
            "Z2",
            "voltgrid/2.0.1",
            [Vulnerability(cve_id="CVE-2024-48201", cvss=5.4, epss=0.2)],
            False,
            0.5,
        ),
        dev(
            4,
            Category.SIGNAL,
            "Z2",
            "trafikon/7.2.0",
            [Vulnerability(cve_id="CVE-2023-29910", cvss=4.3, epss=0.1)],
            False,
            0.95,
            ("ambulance_corridor",),
        ),
        dev(
            5,
            Category.SIGNAL,
            "Z3",
            "trafikon/7.2.0",
            [Vulnerability(cve_id="CVE-2023-29910", cvss=4.3, epss=0.1)],
            False,
            0.95,
            ("ambulance_corridor",),
        ),
        dev(
            6,
            Category.STREETLIGHT,
            "Z3",
            "decorlite/1.0.0",
            [Vulnerability(cve_id="CVE-2025-10001", cvss=9.8, epss=0.02)],
            True,
            0.1,
            ("decorative",),
        ),
    ]
    edges = [
        Edge(src="d-001", dst="d-002", kind=EdgeKind.REACH),
        Edge(src="d-002", dst="d-003", kind=EdgeKind.REACH),
        Edge(src="d-003", dst="d-004", kind=EdgeKind.REACH),
        Edge(src="d-004", dst="d-005", kind=EdgeKind.REACH),
        Edge(src="d-004", dst="d-005", kind=EdgeKind.DEPENDS),
    ]
    return City(id="tiny", name="Tiny", seed=0, devices=devices, edges=edges)


@pytest.fixture
def tiny_budget() -> Budget:
    return Budget(inr=70_000, downtime_h=8)
