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

from dataclasses import dataclass

import numpy as np
from scipy import sparse
from scipy.sparse import csgraph

from urbanshield.schemas import City, ControlKind, EdgeKind, ScenarioLosses, Strategy

MAX_ENTRY_POINTS = 3
TARGET_ENTRY_WEIGHT = 4.0  # entry bias toward devices that can reach the strategy's target category


@dataclass(frozen=True)
class _Draws:
    """Every uniform a run uses, drawn up front so controls never shift the stream."""

    exploit: np.ndarray  # (S, N) compared against controlled per-device odds
    entry_key: np.ndarray  # (S, N) ranks candidate entry points
    entry_count: np.ndarray  # (S,) number of entry points, 1..MAX_ENTRY_POINTS
    is_campaign: np.ndarray  # (S,) compared against campaign_rate
    campaign_pick: np.ndarray  # (S,) chooses the campaign CVE
    campaign_fire: np.ndarray  # (S,) the single campaign exploit draw


def _draw(rng: np.random.Generator, s: int, n: int) -> _Draws:
    return _Draws(
        exploit=rng.random((s, n)),
        entry_key=rng.random((s, n)),
        entry_count=rng.integers(1, MAX_ENTRY_POINTS + 1, size=s),
        is_campaign=rng.random(s),
        campaign_pick=rng.random(s),
        campaign_fire=rng.random(s),
    )


def _adjacency(city: City, index: dict[str, int], kind: EdgeKind) -> sparse.csr_matrix:
    """Sparse src -> dst matrix of one edge kind (duplicates collapse to 1)."""
    pairs = [(index[e.src], index[e.dst]) for e in city.edges if e.kind == kind]
    n = len(index)
    if not pairs:
        return sparse.csr_matrix((n, n))
    src, dst = np.array(pairs).T
    adj = sparse.csr_matrix((np.ones(len(pairs)), (src, dst)), shape=(n, n))
    adj.data[:] = 1.0
    return adj


def _multipliers(city: City, controls: dict[str, ControlKind] | None) -> tuple[np.ndarray, np.ndarray]:
    """Per-device ``exploit_mult`` and ``spread_mult`` of the chosen controls (1.0 if none)."""
    controls = controls or {}
    unknown = sorted(set(controls) - {d.id for d in city.devices})
    if unknown:
        raise ValueError(f"controls name unknown devices: {', '.join(unknown)}")
    n = len(city.devices)
    exploit_mult, spread_mult = np.ones(n), np.ones(n)
    for i, dev in enumerate(city.devices):
        kind = controls.get(dev.id)
        if kind is None:
            continue
        option = next((c for c in dev.controls if c.kind == kind), None)
        if option is None:
            raise ValueError(f"{dev.id} has no {kind} control option")
        exploit_mult[i], spread_mult[i] = option.exploit_mult, option.spread_mult
    return exploit_mult, spread_mult


def _base_odds(city: City) -> np.ndarray:
    """``p_i = 1 - prod(1 - epss_v)`` over each device's vulns."""
    return np.array([1.0 - np.prod([1.0 - v.epss for v in d.vulns]) for d in city.devices])


def _cascade_reach(crit: np.ndarray, depends: sparse.csr_matrix) -> np.ndarray:
    """Sum of criticality over each device's DEPENDS descendants (itself excluded)."""
    out = np.zeros(len(crit))
    for i in np.flatnonzero(np.diff(depends.indptr)):
        order = csgraph.breadth_first_order(depends, i, directed=True, return_predecessors=False)
        out[i] = crit[order[1:]].sum()
    return out


def _entry_candidates(
    city: City, index: dict[str, int], strategy: Strategy | None, reach: sparse.csr_matrix
) -> np.ndarray:
    """Entry weight per device: 0 = never an entry point."""
    if strategy is not None and strategy.entry_points:
        unknown = sorted(set(strategy.entry_points) - set(index))
        if unknown:
            raise ValueError(f"strategy {strategy.id} names unknown entry points: {', '.join(unknown)}")
        weight = np.zeros(len(city.devices))
        weight[[index[d] for d in strategy.entry_points]] = 1.0
    else:
        weight = np.array([1.0 if d.exposed else 0.0 for d in city.devices])
    if strategy is not None and strategy.target_category is not None:
        targets = np.array([d.category == strategy.target_category for d in city.devices])
        weight = np.where(_can_reach(reach, targets), weight * TARGET_ENTRY_WEIGHT, weight)
    return weight


def _can_reach(reach: sparse.csr_matrix, targets: np.ndarray) -> np.ndarray:
    """Devices with a REACH path to any target (a target reaches itself): one reverse BFS
    from a virtual node wired to every target."""
    n = reach.shape[0]
    if not targets.any():
        return np.zeros(n, dtype=bool)
    k = int(targets.sum())
    hub = sparse.csr_matrix((np.ones(k), (np.flatnonzero(targets), np.full(k, n))), shape=(n + 1, n + 1))
    graph = sparse.bmat([[reach, None], [None, sparse.csr_matrix((1, 1))]]).tocsr() + hub
    order = csgraph.breadth_first_order(graph.T.tocsr(), n, directed=True, return_predecessors=False)
    found = np.zeros(n + 1, dtype=bool)
    found[order] = True
    return found[:n]


def _pick_entries(weight: np.ndarray, draws: _Draws) -> np.ndarray:
    """Weighted sampling without replacement (Efraimidis-Spirakis keys), vectorised over S."""
    s, n = draws.entry_key.shape
    if not weight.any():
        return np.zeros((s, n), dtype=bool)
    # log(1 - u) is finite for u in [0, 1), so no candidate can tie with the -inf of a non-candidate.
    keys = np.where(weight > 0, np.log1p(-draws.entry_key) / np.where(weight > 0, weight, 1.0), -np.inf)
    rank = np.argsort(np.argsort(-keys, axis=1, kind="stable"), axis=1, kind="stable")
    count = np.minimum(draws.entry_count, int((weight > 0).sum()))
    return rank < count[:, None]


def _campaigns(
    city: City,
    draws: _Draws,
    exploit_mult: np.ndarray,
    campaign_rate: float,
    strategy: Strategy | None,
) -> tuple[np.ndarray, tuple[str | None, ...]]:
    """Campaign seeds (S, N) and the CVE of every campaign that fired."""
    s, n = draws.exploit.shape
    carriers: dict[str, np.ndarray] = {}
    epss: dict[str, float] = {}
    for i, dev in enumerate(city.devices):
        for v in dev.vulns:
            carriers.setdefault(v.cve_id, np.zeros(n, dtype=bool))[i] = True
            epss[v.cve_id] = max(epss.get(v.cve_id, 0.0), v.epss)
    if strategy is not None and strategy.campaign_cve is not None:
        cves = [strategy.campaign_cve] if strategy.campaign_cve in carriers else []
    else:
        cves = sorted(carriers)
    seeds = np.zeros((s, n), dtype=bool)
    weight = np.array([epss[c] * carriers[c].sum() for c in cves])
    if not cves or weight.sum() <= 0:
        return seeds, (None,) * s

    pick = np.searchsorted(np.cumsum(weight) / weight.sum(), draws.campaign_pick, side="right")
    pick = np.minimum(pick, len(cves) - 1)
    # Whether a campaign fires uses the uncontrolled odds, so controls never turn a campaign
    # scenario into an ordinary one; each carrier then falls if the same draw beats its own
    # controlled odds (all carriers fall together when none is controlled).
    odds = np.array([epss[c] for c in cves])[pick]
    fired = (draws.is_campaign < campaign_rate) & (draws.campaign_fire < odds)
    carrier_mask = np.stack([carriers[c] for c in cves])[pick]  # (S, N)
    beats = draws.campaign_fire[:, None] < odds[:, None] * exploit_mult[None, :]
    seeds = fired[:, None] & carrier_mask & beats
    return seeds, tuple(cves[k] if f else None for k, f in zip(pick, fired, strict=True))


def _firmware_family(city: City) -> sparse.csr_matrix:
    """Sparse N x N matrix linking devices of the same firmware family (``family/version``)."""
    families = [d.firmware.split("/")[0] for d in city.devices]
    _, fam = np.unique(families, return_inverse=True)
    member = sparse.csr_matrix((np.ones(len(fam)), (np.arange(len(fam)), fam)))
    return (member @ member.T).tocsr()


def _spread(
    seeds: np.ndarray,
    can_fall: np.ndarray,
    reach: sparse.csr_matrix,
    family: sparse.csr_matrix | None,
    pivot_ok: np.ndarray,
) -> np.ndarray:
    """Hop-by-hop REACH spread from ``seeds``; one sparse mat-mul of the frontier per hop.

    ``can_fall[s, i]``: device i falls in scenario s when the attacker reaches it (its exploit
    draw beat its controlled odds). Each device has one draw per scenario, so a device that
    resists once resists for the whole scenario. With ``family``, one lost member of a
    firmware family takes down every member whose ``pivot_ok`` draw passes.
    """
    compromised = seeds.copy()
    rows, cols = np.nonzero(seeds)
    for _ in range(seeds.shape[1]):
        if family is not None:
            rows, cols = _hop(rows, cols, family, pivot_ok, compromised, keep=True)
        rows, cols = _hop(rows, cols, reach, can_fall, compromised, keep=False)
        if not len(rows):
            break
    return compromised


def _hop(
    rows: np.ndarray,
    cols: np.ndarray,
    adj: sparse.csr_matrix,
    allowed: np.ndarray,
    compromised: np.ndarray,
    keep: bool,
) -> tuple[np.ndarray, np.ndarray]:
    """One sparse frontier step: (scenario, device) pairs newly reached over ``adj`` that the
    ``allowed`` draws let fall. Updates ``compromised`` in place and returns the new frontier
    (plus the old one when ``keep``). Work scales with the frontier, not with S x N."""
    s, n = compromised.shape
    frontier = sparse.csr_matrix((np.ones(len(rows)), (rows, cols)), shape=(s, n))
    hit_rows, hit_cols = (frontier @ adj).nonzero()
    new = allowed[hit_rows, hit_cols] & ~compromised[hit_rows, hit_cols]
    hit_rows, hit_cols = hit_rows[new], hit_cols[new]
    compromised[hit_rows, hit_cols] = True
    if keep:
        return np.concatenate([rows, hit_rows]), np.concatenate([cols, hit_cols])
    return hit_rows, hit_cols


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
    n = len(city.devices)
    index = {d.id: i for i, d in enumerate(city.devices)}
    draws = _draw(np.random.default_rng(seed), n_scenarios, n)

    reach = _adjacency(city, index, EdgeKind.REACH)
    depends = _adjacency(city, index, EdgeKind.DEPENDS)
    exploit_mult, spread_mult = _multipliers(city, controls)
    can_fall = draws.exploit < (_base_odds(city) * exploit_mult)[None, :]

    entries = _pick_entries(_entry_candidates(city, index, strategy, reach), draws) & can_fall
    campaign_seeds, campaign_cve = _campaigns(city, draws, exploit_mult, campaign_rate, strategy)
    fired = np.array([c is not None for c in campaign_cve], dtype=bool)
    seeds = np.where(fired[:, None], campaign_seeds, entries)

    pivot = strategy is not None and strategy.pivot_shared_firmware
    family = _firmware_family(city) if pivot else None
    compromised = _spread(seeds, can_fall, reach, family, draws.exploit < exploit_mult[None, :])

    crit = np.array([d.criticality for d in city.devices])
    per_device = crit + spread_mult * _cascade_reach(crit, depends)
    device_loss = compromised * per_device[None, :]

    return ScenarioLosses(
        city_id=city.id,
        seed=seed,
        device_ids=tuple(index),
        device_loss=device_loss.astype(np.float64),
        compromised=compromised,
        campaign_cve=campaign_cve,
    )
