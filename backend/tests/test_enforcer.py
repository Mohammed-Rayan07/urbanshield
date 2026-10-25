"""Enforcer and corridor interlock: signed policy, deny by default, verified effect, safe commands."""

from __future__ import annotations

import pytest

from urbanshield.city.generator import generate_city
from urbanshield.guard.enforcer import Enforcer, PolicyRejected, PolicySigner, compile_policy
from urbanshield.guard.interlock import CORRIDOR_TAG, MAX_HOLD_S, CorridorInterlock, SignalCommand
from urbanshield.schemas import ControlKind, EdgeKind


@pytest.fixture(scope="module")
def city():
    return generate_city(seed=7)


@pytest.fixture
def signer():
    return PolicySigner()


@pytest.fixture
def enforcer(city, signer):
    return Enforcer(city=city, verify_key=signer.verify_key)


def _gateways(city):
    return [d.id for d in city.devices if "gateway" in d.tags]


def _corridor(city):
    return [d.id for d in city.devices if CORRIDOR_TAG in d.tags]


def test_corridor_is_reachable_before_any_policy(enforcer):
    paths = enforcer.corridor_paths()
    assert paths.status == "open" and paths.unfiltered


def test_segmenting_every_gateway_closes_the_corridor(city, signer, enforcer):
    choices = {g: ControlKind.SEGMENT for g in _gateways(city)}
    report = enforcer.apply(signer.sign(compile_policy(city, "plan-x", choices, version=1)))
    assert report["version"] == 1 and report["rules"] > 0
    assert enforcer.corridor_paths().status == "closed"
    gateways = set(_gateways(city))
    edges = [(e.src, e.dst) for e in city.edges if e.kind == EdgeKind.REACH]
    assert not any(enforcer.allows_flow(s, d) for s, d in edges if {s, d} & gateways)


def test_virtual_patch_filters_but_does_not_cut_the_flow(city, signer, enforcer):
    choices = {g: ControlKind.VIRTUAL_PATCH for g in _gateways(city)}
    enforcer.apply(signer.sign(compile_policy(city, "plan-x", choices, version=1)))
    paths = enforcer.corridor_paths()
    assert paths.reachable and paths.status in ("filtered", "open")


def test_deny_by_default_for_flows_not_in_the_twin(city, enforcer):
    reach = {(e.src, e.dst) for e in city.edges if e.kind == EdgeKind.REACH}
    ids = [d.id for d in city.devices]
    missing = next((a, b) for a in ids for b in ids if a != b and (a, b) not in reach)
    assert not enforcer.allows_flow(*missing)


def test_bad_signature_is_refused(city, enforcer):
    forged = PolicySigner().sign(compile_policy(city, "plan-x", {}, version=1))
    with pytest.raises(PolicyRejected, match="signature"):
        enforcer.apply(forged)
    assert enforcer.version == 0
    assert enforcer.status().decisions[0].rule == "signature"


def test_tampered_policy_is_refused(city, signer, enforcer):
    signed = signer.sign(compile_policy(city, "plan-x", {_gateways(city)[0]: ControlKind.SEGMENT}, version=1))
    edited = signed.model_copy(update={"policy": signed.policy.model_copy(update={"rules": []})})
    with pytest.raises(PolicyRejected, match="signature"):
        enforcer.apply(edited)


def test_rollback_and_replay_are_refused(city, signer, enforcer):
    v2 = signer.sign(compile_policy(city, "plan-b", {}, version=2))
    enforcer.apply(v2)
    with pytest.raises(PolicyRejected, match="rollback"):
        enforcer.apply(signer.sign(compile_policy(city, "plan-a", {}, version=1)))
    with pytest.raises(PolicyRejected, match="rollback"):
        enforcer.apply(v2)


def test_other_city_policy_is_refused(city, signer, enforcer):
    policy = compile_policy(city, "plan-x", {}, version=1).model_copy(update={"city_id": "elsewhere"})
    with pytest.raises(PolicyRejected, match="another city"):
        enforcer.apply(signer.sign(policy))


def test_policy_compilation_is_deterministic(city):
    choices = {g: ControlKind.SEGMENT for g in _gateways(city)}
    reordered = dict(reversed(list(choices.items())))
    a = compile_policy(city, "p", choices, 1).model_copy(update={"issued_at": "t"})
    b = compile_policy(city, "p", reordered, 1).model_copy(update={"issued_at": "t"})
    assert a.sha256 == b.sha256


def test_rotate_creds_bumps_the_credential_epoch(city, signer, enforcer):
    d = city.devices[0].id
    enforcer.apply(signer.sign(compile_policy(city, "p", {d: ControlKind.ROTATE_CREDS}, version=1)))
    assert enforcer.credential_epoch(d) == 1


def test_closed_management_refuses_remote_commands(city, signer, enforcer):
    signal = _corridor(city)[0]
    enforcer.apply(signer.sign(compile_policy(city, "p", {signal: ControlKind.DISABLE_REMOTE}, version=1)))
    verdict = enforcer.admit(SignalCommand(device_id=signal, phase="ns_green"))
    assert not verdict.allowed and verdict.rule == "management_closed"
    assert enforcer.admit(SignalCommand(device_id=signal, phase="ns_green", remote=False)).allowed


def test_admit_reports_latency(city, enforcer):
    v = enforcer.admit(SignalCommand(device_id=_corridor(city)[0], phase="ns_green"))
    assert v.allowed and v.latency_us >= 0


# --------------------------------------------------------------------------- interlock


def test_conflicting_greens_are_always_vetoed():
    lock = CorridorInterlock(["c1"])
    for remote in (True, False):
        v = lock.check(SignalCommand(device_id="x", phase="both_green", remote=remote))
        assert not v.allowed and v.rule == "conflicting_greens"


def test_long_remote_hold_on_the_corridor_is_vetoed_but_local_is_allowed():
    lock = CorridorInterlock(["c1"])
    long_hold = SignalCommand(device_id="c1", phase="all_red", hold_s=MAX_HOLD_S + 1)
    assert lock.check(long_hold).rule == "corridor_hold"
    assert lock.phases["c1"] == "green_wave"  # a veto changes nothing
    assert lock.check(long_hold.model_copy(update={"remote": False})).allowed


def test_only_one_corridor_signal_may_leave_the_green_wave():
    lock = CorridorInterlock(["c1", "c2", "c3"])
    assert lock.check(SignalCommand(device_id="c1", phase="all_red", hold_s=30)).allowed
    v = lock.check(SignalCommand(device_id="c2", phase="flash"))
    assert not v.allowed and v.rule == "corridor_continuity" and "c1" in v.reason
    assert lock.check(SignalCommand(device_id="c1", phase="green_wave")).allowed
    assert lock.check(SignalCommand(device_id="c2", phase="flash")).allowed


def test_signals_off_the_corridor_are_not_constrained_by_corridor_rules():
    lock = CorridorInterlock(["c1"])
    assert lock.check(SignalCommand(device_id="x", phase="all_red", hold_s=3600)).allowed
