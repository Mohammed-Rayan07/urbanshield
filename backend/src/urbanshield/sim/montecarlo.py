"""Monte Carlo attack simulator. Owner: S.

Model (keep it this simple; it is documented in docs/ASSUMPTIONS.md):

- Exploit odds of device i: ``p_i = 1 - prod(1 - epss_v)`` over its vulns, times
  ``exploit_mult`` of its chosen control (1.0 if none).
- Each scenario draws entry points among exposed devices, then spreads over REACH
  edges: a reachable device is compromised with probability ``p_i``.
- **Campaign scenarios** (a fraction ``campaign_rate`` of S): pick one CVE and make a
  single exploit draw with that CVE's odds. If it succeeds, every device carrying it is
  compromised *together* and ``campaign_cve[s]`` records the CVE; if it fails, the
  scenario proceeds as an ordinary one with ``campaign_cve[s] = None``. Real attacks
  are not independent coin flips.
- **Common random numbers:** draw all uniforms for a seed *first* (independent of
  controls), then compare them against the controlled odds ``p * exploit_mult``. Applying
  a control must never shift the random stream, so plans are compared on identical
  attacks and differences between plans are not noise.
- Damage: a lost device costs its ``criticality``; loss then cascades over DEPENDS
  edges, scaled by the source's ``spread_mult``. ``device_loss[s, i]`` attributes the
  device's own loss plus the cascade it caused to device i.
- Must be vectorised over scenarios (NumPy arrays of shape (S, N)); no Python loop
  per scenario. 2,000 scenarios x 50 devices should run in well under a second.
"""

from __future__ import annotations

from urbanshield.schemas import City, ControlKind, ScenarioLosses, Strategy


def simulate(
    city: City,
    n_scenarios: int = 2000,
    seed: int = 0,
    controls: dict[str, ControlKind] | None = None,
    strategy: Strategy | None = None,
    campaign_rate: float = 0.2,
) -> ScenarioLosses:
    """Run the simulation.

    ``controls`` applies chosen controls (device_id -> kind) using that device's
    ``ControlOption`` multipliers. ``strategy`` restricts the attacker (entry points,
    target category, shared-firmware pivot, forced campaign CVE) for the Red-Team.
    Same inputs and seed -> identical output.
    """
    raise NotImplementedError
