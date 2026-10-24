"""City generator, graphs and feeds. Owner: A."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from urbanshield.city.feeds import FeedIntegrityError, load_feed, sha256_file
from urbanshield.city.generator import MANGALURU_BBOX, generate_city
from urbanshield.city.graphs import bfs_reach, blast_radius, build_graphs, reach_centrality
from urbanshield.schemas import Autonomy, Category, ControlKind

# ---------------------------------------------------------------- generator


@pytest.fixture(scope="module")
def city():
    return generate_city(seed=7)


def test_generator_is_deterministic(city) -> None:
    assert generate_city(seed=7) == city
    assert generate_city(seed=8) != city


def test_ids_and_coordinates(city) -> None:
    ids = [d.id for d in city.devices]
    assert len(ids) == len(set(ids)) == 50
    assert all(i.startswith("d-") for i in ids)
    lat0, lon0, lat1, lon1 = MANGALURU_BBOX
    assert all(lat0 <= d.lat <= lat1 and lon0 <= d.lon <= lon1 for d in city.devices)
    assert {e.src for e in city.edges} | {e.dst for e in city.edges} <= set(ids)


def test_shared_firmware_family(city) -> None:
    lights = [d for d in city.devices if d.category == Category.STREETLIGHT]
    family = Counter(d.firmware.rsplit(".", 1)[0] for d in lights).most_common(1)[0]
    assert family[1] >= 10
    members = [d for d in lights if d.firmware.startswith(family[0])]
    shared = set.intersection(*({v.cve_id for v in d.vulns} for d in members))
    assert shared, "family members must share a CVE"
    cvss = {v.cvss for d in members for v in d.vulns if v.cve_id in shared}
    assert all(5.0 <= c < 7.0 for c in cvss), "the shared CVE is medium severity"
    assert any(d.exposed for d in members)


def test_ambulance_corridor_reachable_from_family(city) -> None:
    corridor = [d for d in city.devices if "ambulance_corridor" in d.tags]
    assert len(corridor) >= 4
    assert all(d.category == Category.SIGNAL and d.criticality >= 0.9 for d in corridor)
    g = build_graphs(city)
    exposed_lights = [d.id for d in city.devices if d.category == Category.STREETLIGHT and d.exposed]
    reached = bfs_reach(g, exposed_lights)
    assert any(d.id in reached for d in corridor)


def test_decoys_exist(city) -> None:
    depends_src = {e.src for e in city.edges if e.kind == "depends"}
    decoys = [
        d
        for d in city.devices
        if max((v.cvss for v in d.vulns), default=0) >= 9.0
        and d.criticality <= 0.2
        and d.id not in depends_src
    ]
    assert len(decoys) >= 3


def test_control_options(city) -> None:
    for d in city.devices:
        assert 2 <= len(d.controls) <= 5
        assert len({c.kind for c in d.controls}) == len(d.controls)
        for c in d.controls:
            if c.kind == ControlKind.ROTATE_CREDS:
                assert c.autonomy == Autonomy.AUTO
            if c.downtime_h > 0:
                assert c.autonomy == Autonomy.APPROVE


# ---------------------------------------------------------------- graphs


def test_bfs_reach(tiny_city) -> None:
    g = build_graphs(tiny_city)
    assert bfs_reach(g, ["d-001"]) == {"d-001", "d-002", "d-003", "d-004", "d-005"}
    assert bfs_reach(g, ["d-001"], blocked=["d-003"]) == {"d-001", "d-002"}
    assert bfs_reach(g, ["d-006"]) == {"d-006"}


def test_blast_radius_and_centrality(tiny_city) -> None:
    g = build_graphs(tiny_city)
    assert blast_radius(g, "d-004") == ["d-005"]
    assert blast_radius(g, "d-006") == []
    c = reach_centrality(g)
    assert c["d-001"] > c["d-004"] > c["d-005"]


# ---------------------------------------------------------------- feeds


def _write_feed(tmp_path: Path) -> tuple[Path, Path]:
    feed = tmp_path / "feed.json"
    feed.write_text(
        json.dumps(
            {
                "generated": "2026-10-24",
                "sources": ["test"],
                "records": [
                    {
                        "cve_id": "CVE-2025-31337",
                        "cvss": 6.1,
                        "epss": 0.42,
                        "kev": True,
                        "vendor": "Lumenos",
                        "product": "SL-200",
                        "summary": "test",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    pin = tmp_path / "feed.sha256"
    pin.write_text(sha256_file(feed), encoding="utf-8")
    return feed, pin


def test_feed_loads_when_hash_matches(tmp_path) -> None:
    feed, pin = _write_feed(tmp_path)
    vulns = load_feed(feed, pin)
    assert vulns["CVE-2025-31337"].kev is True


def test_tampered_feed_is_refused(tmp_path) -> None:
    feed, pin = _write_feed(tmp_path)
    feed.write_text(feed.read_text(encoding="utf-8").replace("6.1", "1.0"), encoding="utf-8")
    with pytest.raises(FeedIntegrityError):
        load_feed(feed, pin)


# ---------------------------------------------------------------- demo story and hardening


def test_decoys_are_fully_isolated(city) -> None:
    decoys = {d.id for d in city.devices if "decorative" in d.tags}
    assert decoys
    assert not [e for e in city.edges if e.src in decoys or e.dst in decoys]


def test_shared_cve_is_unique_to_the_family(city) -> None:
    family = [d for d in city.devices if d.firmware.startswith("lumenos/4.1")]
    (shared,) = {v.cve_id for v in family[0].vulns}
    carriers = {d.id for d in city.devices if any(v.cve_id == shared for v in d.vulns)}
    assert carriers == {d.id for d in family}
    assert len({v.cve_id for d in city.devices for v in d.vulns}) >= 15, "real CVE diversity"


def test_gateways_are_the_only_way_from_the_family_to_the_corridor(city) -> None:
    g = build_graphs(city)
    family = [d.id for d in city.devices if d.firmware.startswith("lumenos/4.1")]
    corridor = {d.id for d in city.devices if "ambulance_corridor" in d.tags}
    gateways = [d.id for d in city.devices if "gateway" in d.tags]
    assert corridor & bfs_reach(g, family)
    assert not corridor & bfs_reach(g, family, blocked=gateways), "segmenting gateways must cut the path"


def test_decoy_cve_is_critical_but_unlikely(city) -> None:
    decoy = next(d for d in city.devices if "decorative" in d.tags).vulns[0]
    family = next(d for d in city.devices if d.firmware.startswith("lumenos/4.1")).vulns[0]
    assert decoy.cvss >= 9.0 > family.cvss
    assert decoy.epss < family.epss, "the CVSS-first trap: higher score, lower real-world likelihood"


def test_feed_without_a_needed_band_raises() -> None:
    from urbanshield.schemas import Vulnerability

    only_low = {"CVE-2024-0001": Vulnerability(cve_id="CVE-2024-0001", cvss=4.1, epss=0.1)}
    with pytest.raises(ValueError, match="family"):
        generate_city(feed=only_low)


def test_unknown_device_ids_raise(tiny_city) -> None:
    g = build_graphs(tiny_city)
    with pytest.raises(KeyError):
        bfs_reach(g, ["d-999"])
    with pytest.raises(KeyError):
        blast_radius(g, "d-999")


def test_feed_record_fails_closed_without_pin(tmp_path) -> None:
    from urbanshield.city.feeds import feed_record

    feed, pin = _write_feed(tmp_path)
    assert feed_record("CVE-2025-31337", feed, pin)["vendor"] == "Lumenos"
    assert feed_record("CVE-2099-0001", feed, pin) is None
    pin.unlink()
    with pytest.raises(FeedIntegrityError):
        feed_record("CVE-2025-31337", feed, pin)


def test_feed_record_refuses_tampered_or_missing_feed(tmp_path) -> None:
    from urbanshield.city.feeds import feed_record

    feed, pin = _write_feed(tmp_path)
    feed.write_text(feed.read_text(encoding="utf-8").replace("6.1", "1.0"), encoding="utf-8")
    with pytest.raises(FeedIntegrityError):
        feed_record("CVE-2025-31337", feed, pin)
    feed.unlink()
    with pytest.raises(FeedIntegrityError):
        feed_record("CVE-2025-31337", feed, pin)


def test_duplicate_records_are_refused(tmp_path) -> None:
    feed, pin = _write_feed(tmp_path)
    payload = json.loads(feed.read_text(encoding="utf-8"))
    payload["records"] *= 2
    feed.write_text(json.dumps(payload), encoding="utf-8")
    pin.write_text(sha256_file(feed), encoding="utf-8")
    with pytest.raises(FeedIntegrityError, match="duplicate"):
        load_feed(feed, pin)


def test_committed_snapshot_matches_code_pin() -> None:
    assert len(load_feed()) == 40


@pytest.mark.slow
def test_scales_to_5000_devices() -> None:
    import time

    t = time.perf_counter()
    big = generate_city(seed=1, n_devices=5000)
    centrality = reach_centrality(build_graphs(big))
    assert len(big.devices) == len(centrality) == 5000
    assert time.perf_counter() - t < 10
