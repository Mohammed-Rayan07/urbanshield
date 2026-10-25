"""Corridor safety interlock: plain-code rules every signal command must pass. Owner: C.

Defence in depth, not a new idea for one junction: real cabinets have hardware conflict monitors
that refuse conflicting greens. What a per-cabinet monitor cannot see is the **corridor**: this
interlock sits in the network command path and keeps the whole ambulance corridor passable, and it
judges the command itself, so a request with valid credentials is still refused when it is unsafe.

Rules (deterministic, no LLM):

- ``conflicting_greens``: no signal may show green to crossing directions.
- ``corridor_hold``: a remote command may not hold a corridor signal on all-red or flash for longer
  than ``MAX_HOLD_S`` (a local operator at the cabinet may, e.g. after a crash).
- ``corridor_continuity``: at most ``MAX_DISRUPTED`` corridor signal may be off the green wave
  (all-red or flash) at a time, whoever asks, so one request cannot close the corridor.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from urbanshield.schemas import Contract

CORRIDOR_TAG = "ambulance_corridor"
MAX_HOLD_S = 90
MAX_DISRUPTED = 1

Phase = Literal["green_wave", "ns_green", "ew_green", "all_red", "flash", "both_green"]
DISRUPTIVE: frozenset[str] = frozenset({"all_red", "flash"})


class SignalCommand(Contract):
    device_id: str
    phase: Phase
    hold_s: int = Field(default=0, ge=0, le=86_400)
    remote: bool = True  # False = an operator at the cabinet

    def describe(self) -> str:
        hold = f" for {self.hold_s} s" if self.hold_s else ""
        where = "remote" if self.remote else "local"
        return f"{self.phase}{hold} on {self.device_id} ({where})"


class Verdict(Contract):
    allowed: bool
    rule: str | None = None
    reason: str
    latency_us: float = 0.0


class CorridorInterlock:
    """Keeps the corridor's signal phases and judges each command against the rules above."""

    def __init__(self, corridor: list[str]) -> None:
        self.corridor = frozenset(corridor)
        self.phases: dict[str, str] = {d: "green_wave" for d in sorted(corridor)}

    def check(self, command: SignalCommand) -> Verdict:
        """Allowed commands update the corridor's state; vetoed ones change nothing."""
        d, phase = command.device_id, command.phase
        if phase == "both_green":
            return Verdict(
                allowed=False, rule="conflicting_greens", reason="crossing directions would both be green"
            )
        if d in self.corridor and phase in DISRUPTIVE:
            if command.remote and command.hold_s > MAX_HOLD_S:
                reason = (
                    f"remote hold of {command.hold_s} s on an ambulance-corridor signal (max {MAX_HOLD_S} s)"
                )
                return Verdict(allowed=False, rule="corridor_hold", reason=reason)
            disrupted = [x for x, p in self.phases.items() if p in DISRUPTIVE and x != d]
            if len(disrupted) >= MAX_DISRUPTED:
                reason = f"{', '.join(disrupted)} already off the green wave; the corridor must stay passable"
                return Verdict(allowed=False, rule="corridor_continuity", reason=reason)
        if d in self.corridor:
            self.phases[d] = phase
        return Verdict(allowed=True, reason="passes every corridor safety rule")
