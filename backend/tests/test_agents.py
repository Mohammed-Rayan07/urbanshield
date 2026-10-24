"""Agent building blocks. Owner: C."""

from __future__ import annotations

from urbanshield.agents.sentinel import match_inventory
from urbanshield.schemas import Advisory


def test_match_inventory_by_family_and_version(tiny_city) -> None:
    adv = Advisory(
        cve_id="CVE-2026-0001",
        vendor="Lumenos",
        product="SL-200",
        firmware_family="lumenos",
        affected_below="4.2.0",
        cvss=6.5,
        source_sha256="0" * 64,
    )
    matches = match_inventory(tiny_city, adv)
    assert {m.device_id for m in matches} == {"d-001", "d-002"}


def test_version_outside_range_does_not_match(tiny_city) -> None:
    adv = Advisory(
        cve_id="CVE-2026-0001",
        vendor="Lumenos",
        product="SL-200",
        firmware_family="lumenos",
        affected_below="4.1.0",
        cvss=6.5,
        source_sha256="0" * 64,
    )
    assert match_inventory(tiny_city, adv) == []
