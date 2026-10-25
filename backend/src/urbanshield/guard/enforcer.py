"""Enforcer: an approved plan becomes signed policy, applied at a deny-by-default gateway. Owner: C.

Planning decides *which* controls; this module makes them concrete and checks they took effect.

1. ``compile_policy`` turns the plan's (device, control) choices into rules over the twin:
   ``segment`` denies every REACH flow into and out of the device, ``disable_remote`` denies inbound
   flows (its management endpoint is closed), ``rotate_creds`` bumps the device's credential epoch,
   ``patch`` schedules the fixed firmware and ``virtual_patch`` installs a filter for the device's CVEs.
   ``patch`` and ``virtual_patch`` harden the device itself; the flow stays, but it is filtered.
2. ``PolicySigner`` signs the canonical policy with the **control-plane** Ed25519 key. It is a separate
   key from the audit log's: the gateway only holds the verify key, so a stolen gateway cannot mint policy.
3. ``Enforcer.apply`` refuses a bad signature, another city's policy, or a version that is not newer
   than the one in force (no rollback or replay of old policy), then installs the rules.
4. ``Enforcer.corridor_paths`` verifies the effect on the flow table itself: can an internet-exposed
   device still reach an ambulance-corridor signal, and is every remaining route filtered?
5. Every signal command passes ``Enforcer.admit``: closed management endpoints refuse remote commands,
   and the corridor interlock (``guard/interlock.py``) vetoes unsafe ones even when they are authenticated.

There is no API to push policy: only an incident run's apply step compiles and signs it, covering the
controls actually applied (low-risk, no-downtime ones auto-apply; anything with downtime needs an approver).
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import Field

from urbanshield.guard.interlock import CORRIDOR_TAG, CorridorInterlock, SignalCommand, Verdict
from urbanshield.schemas import City, Contract, ControlKind, EdgeKind

RuleAction = Literal["deny_flow", "close_management", "rotate_credentials", "schedule_firmware", "filter_cve"]
HARDENING = ("schedule_firmware", "filter_cve")


class PolicyRule(Contract):
    id: str
    action: RuleAction
    device_id: str
    control: ControlKind
    src: str | None = None  # deny_flow only
    dst: str | None = None
    cves: list[str] = Field(default_factory=list)  # filter_cve / schedule_firmware


class Policy(Contract):
    city_id: str
    plan_id: str
    version: int = Field(ge=1)
    issued_at: str
    rules: list[PolicyRule]

    def canonical(self) -> bytes:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()


class SignedPolicy(Contract):
    policy: Policy
    signature: str  # hex Ed25519 over policy.canonical()
    key_id: str  # first 16 hex of the verify key


class PolicyRejected(ValueError):
    """The gateway refused a policy (signature, city or version)."""


def compile_policy(city: City, plan_id: str, choices: dict[str, ControlKind], version: int) -> Policy:
    """Concrete, deterministic rules for the chosen controls (sorted, so the same plan signs the same)."""
    reach = sorted((e.src, e.dst) for e in city.edges if e.kind == EdgeKind.REACH)
    rules: list[PolicyRule] = []

    def add(action: RuleAction, device_id: str, kind: ControlKind, **kw: Any) -> None:
        rules.append(
            PolicyRule(id=f"r-{len(rules) + 1:03d}", action=action, device_id=device_id, control=kind, **kw)
        )

    for device_id, kind in sorted(choices.items()):
        cves = sorted(v.cve_id for v in city.device(device_id).vulns)
        match ControlKind(kind):
            case ControlKind.SEGMENT:
                for s, d in reach:
                    if device_id in (s, d):
                        add("deny_flow", device_id, kind, src=s, dst=d)
            case ControlKind.DISABLE_REMOTE:
                add("close_management", device_id, kind)
                for s, d in reach:
                    if d == device_id:
                        add("deny_flow", device_id, kind, src=s, dst=d)
            case ControlKind.ROTATE_CREDS:
                add("rotate_credentials", device_id, kind)
            case ControlKind.PATCH:
                add("schedule_firmware", device_id, kind, cves=cves)
            case ControlKind.VIRTUAL_PATCH:
                add("filter_cve", device_id, kind, cves=cves)
    return Policy(
        city_id=city.id,
        plan_id=plan_id,
        version=version,
        issued_at=datetime.now(UTC).isoformat(timespec="seconds"),
        rules=rules,
    )


def key_id(key: VerifyKey) -> str:
    return key.encode().hex()[:16]


class PolicySigner:
    """Holds the control-plane signing key; lives with the planner's apply step, never at the gateway."""

    def __init__(self, signing_key_hex: str | None = None) -> None:
        self._key = SigningKey(bytes.fromhex(signing_key_hex)) if signing_key_hex else SigningKey.generate()

    @property
    def verify_key(self) -> VerifyKey:
        return self._key.verify_key

    def sign(self, policy: Policy) -> SignedPolicy:
        signature = self._key.sign(policy.canonical()).signature.hex()
        return SignedPolicy(policy=policy, signature=signature, key_id=key_id(self.verify_key))


class EnforcerDecision(Contract):
    ts: str
    kind: Literal["policy", "command"]
    allowed: bool
    summary: str
    rule: str | None = None


class CorridorPaths(Contract):
    """Can an internet-exposed device still reach an ambulance-corridor signal over allowed flows?"""

    entry_points: int
    corridor: int
    reachable: list[str] = Field(description="Corridor signals reachable over allowed flows")
    unfiltered: list[str] = Field(description="Reachable over routes with no patched or filtered device")
    status: Literal["open", "filtered", "closed"]


class EnforcerStatus(Contract):
    city_id: str
    version: int
    plan_id: str | None
    policy_sha256: str | None
    key_id: str
    rules: dict[str, int]
    flows_allowed: int
    flows_total: int
    corridor: CorridorPaths
    decisions: list[EnforcerDecision]


@dataclass
class Enforcer:
    """The policy enforcement point for one city. Holds only the verify key."""

    city: City
    verify_key: VerifyKey
    version: int = 0
    signed: SignedPolicy | None = None
    interlock: CorridorInterlock = field(init=False)
    _flows: frozenset[tuple[str, str]] = field(init=False)
    _denied: set[tuple[str | None, str | None]] = field(default_factory=set)
    _closed: set[str] = field(default_factory=set)
    _hardened: set[str] = field(default_factory=set)
    _credential_epoch: dict[str, int] = field(default_factory=dict)
    _decisions: deque[EnforcerDecision] = field(default_factory=lambda: deque(maxlen=50))

    def __post_init__(self) -> None:
        self._flows = frozenset((e.src, e.dst) for e in self.city.edges if e.kind == EdgeKind.REACH)
        self.interlock = CorridorInterlock([d.id for d in self.city.devices if CORRIDOR_TAG in d.tags])

    # ------------------------------------------------------------------ policy

    def apply(self, signed: SignedPolicy) -> dict[str, Any]:
        """Verify and install ``signed``; raises ``PolicyRejected`` (and records why)."""
        t0 = time.perf_counter()
        policy = signed.policy
        try:
            self.verify_key.verify(policy.canonical(), bytes.fromhex(signed.signature))
        except (BadSignatureError, ValueError):
            self._reject(f"Refused policy v{policy.version}: bad signature", "signature")
        if policy.city_id != self.city.id:
            self._reject(f"Refused policy for another city ({policy.city_id[:40]})", "city")
        if policy.version <= self.version:
            self._reject(
                f"Refused policy v{policy.version}: v{self.version} is in force (no rollback)", "version"
            )

        rules = policy.rules
        self._denied = {(r.src, r.dst) for r in rules if r.action == "deny_flow"}
        self._closed = {r.device_id for r in rules if r.action == "close_management"}
        self._hardened = {r.device_id for r in rules if r.action in HARDENING}
        for r in rules:
            if r.action == "rotate_credentials":
                self._credential_epoch[r.device_id] = self._credential_epoch.get(r.device_id, 0) + 1
        self.version, self.signed = policy.version, signed
        apply_ms = round((time.perf_counter() - t0) * 1000, 3)
        self._record("policy", True, f"Installed signed policy v{policy.version} ({len(rules)} rules)")
        return {"version": policy.version, "rules": len(rules), "apply_ms": apply_ms}

    def _reject(self, summary: str, rule: str) -> None:
        self._record("policy", False, summary, rule)
        raise PolicyRejected(summary)

    # ------------------------------------------------------------------ data plane

    def allows_flow(self, src: str, dst: str) -> bool:
        """Deny by default: only twin REACH flows that the policy in force does not deny."""
        return (src, dst) in self._flows and (src, dst) not in self._denied

    def credential_epoch(self, device_id: str) -> int:
        return self._credential_epoch.get(device_id, 0)

    def corridor_paths(self) -> CorridorPaths:
        entries = [d.id for d in self.city.devices if d.exposed]
        corridor = {d.id for d in self.city.devices if CORRIDOR_TAG in d.tags}
        reachable = self._reach(entries, through_hardened=True) & corridor
        open_entries = [e for e in entries if e not in self._hardened]
        unfiltered = self._reach(open_entries, through_hardened=False) & corridor
        status = "open" if unfiltered else "filtered" if reachable else "closed"
        return CorridorPaths(
            entry_points=len(entries),
            corridor=len(corridor),
            reachable=sorted(reachable),
            unfiltered=sorted(unfiltered),
            status=status,
        )

    def _reach(self, sources: list[str], through_hardened: bool) -> set[str]:
        out: dict[str, list[str]] = {}
        for s, d in self._flows:
            if self.allows_flow(s, d) and (through_hardened or d not in self._hardened):
                out.setdefault(s, []).append(d)
        seen, queue = set(sources), deque(sources)
        while queue:
            for nxt in out.get(queue.popleft(), []):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        return seen

    # ------------------------------------------------------------------ commands

    def admit(self, command: SignalCommand) -> Verdict:
        """Every signal command passes here: closed management first, then the corridor interlock."""
        t0 = time.perf_counter()
        if command.remote and command.device_id in self._closed:
            reason = f"{command.device_id}: remote management is closed by policy v{self.version}"
            verdict = Verdict(allowed=False, rule="management_closed", reason=reason)
        else:
            verdict = self.interlock.check(command)
        verdict = verdict.model_copy(update={"latency_us": round((time.perf_counter() - t0) * 1e6, 1)})
        word = "Allowed" if verdict.allowed else "Vetoed"
        self._record(
            "command", verdict.allowed, f"{word} {command.describe()}: {verdict.reason}", verdict.rule
        )
        return verdict

    # ------------------------------------------------------------------ status

    def _record(
        self, kind: Literal["policy", "command"], allowed: bool, summary: str, rule: str | None = None
    ) -> None:
        ts = datetime.now(UTC).isoformat(timespec="milliseconds")
        decision = EnforcerDecision(ts=ts, kind=kind, allowed=allowed, summary=summary[:280], rule=rule)
        self._decisions.appendleft(decision)

    def status(self) -> EnforcerStatus:
        policy = self.signed.policy if self.signed else None
        counts: dict[str, int] = {}
        for r in policy.rules if policy else []:
            counts[r.action] = counts.get(r.action, 0) + 1
        return EnforcerStatus(
            city_id=self.city.id,
            version=self.version,
            plan_id=policy.plan_id if policy else None,
            policy_sha256=policy.sha256 if policy else None,
            key_id=key_id(self.verify_key),
            rules=counts,
            flows_allowed=sum(self.allows_flow(s, d) for s, d in self._flows),
            flows_total=len(self._flows),
            corridor=self.corridor_paths(),
            decisions=list(self._decisions),
        )
