"""Sentinel agent: advisory -> quarantined ``Advisory`` -> matched devices. Owner: C."""

from __future__ import annotations

from urbanshield.schemas import Advisory, City, Match


def match_inventory(city: City, advisory: Advisory) -> list[Match]:
    """Deterministic matcher: same firmware family and version below ``affected_below``,
    or the CVE already listed on the device."""
    raise NotImplementedError
