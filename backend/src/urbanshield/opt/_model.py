"""Shared planner plumbing: constraint parsing, the option table and plan ids. Owner: B.

Every planner (MILP, greedy, baselines) reads the operator's constraints through
``allowed_options`` and builds plans with ``plan_id``, so they can never disagree about
what is allowed.

The option table holds, for every allowed (device, control) pair, the per-scenario loss
that control removes (``saved``, shape S x M). Two models fill it:

- **calibrated** (the default whenever ``losses`` are a plain simulator run): one
  common-random-numbers re-simulation per option, ``saved[:, j] = L_base - L_with_j``.
  This captures what a control does to *other* devices (a segmented gateway stops the
  spread through it), which the per-device formula below cannot see.
- **linear** (synthetic or Red-Team losses, or cities too big to re-simulate):
  ``saved[:, j] = device_loss[:, i] * (1 - exploit_mult * spread_mult)``.

Either way the planner treats savings as additive across controls; every plan is then
re-scored in the full simulator on held-out scenarios (``evaluate.py``).
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from dataclasses import dataclass

import numpy as np

from urbanshield.schemas import (
    Budget,
    City,
    Constraint,
    ConstraintKind,
    ControlKind,
    ControlOption,
    Objective,
    ScenarioLosses,
)

# Above this many options a calibration (one simulation each) costs more than it is worth.
CALIBRATE_MAX_OPTIONS = 600
_CACHE_SIZE = 8
_calibrated: OrderedDict[str, np.ndarray] = OrderedDict()


def plan_id(objective: Objective, choices: dict[str, ControlKind]) -> str:
    """``plan-<objective>-<8 hex of the sorted choices>``: equal plans get equal ids."""
    canonical = ",".join(f"{d}:{ControlKind(k).value}" for d, k in sorted(choices.items()))
    return f"plan-{Objective(objective).value}-{hashlib.sha256(canonical.encode()).hexdigest()[:8]}"


def _kind(value: object) -> str:
    return value.value if isinstance(value, ControlKind) else str(value)


def must_fix(constraints: list[Constraint]) -> list[str]:
    """Device ids that must get a control, in constraint order, without duplicates."""
    ids = [str(c.params["device_id"]) for c in constraints if c.kind == ConstraintKind.MUST_FIX]
    return list(dict.fromkeys(ids))


def effective_budget(budget: Budget, constraints: list[Constraint]) -> Budget:
    """``budget`` tightened by any BUDGET / DOWNTIME constraint (the smaller limit wins)."""
    inr, downtime = budget.inr, budget.downtime_h
    for c in constraints:
        if c.kind == ConstraintKind.BUDGET and "inr" in c.params:
            inr = min(inr, int(float(c.params["inr"])))  # type: ignore[arg-type]
        elif c.kind == ConstraintKind.DOWNTIME and "downtime_h" in c.params:
            downtime = min(downtime, float(c.params["downtime_h"]))  # type: ignore[arg-type]
    return budget.model_copy(update={"inr": max(inr, 0), "downtime_h": max(downtime, 0.0)})


def allowed_options(
    city: City, constraints: list[Constraint], patch_only: bool = False
) -> dict[str, list[ControlOption]]:
    """Each device's controls that the constraints allow, in the device's listed order."""
    no_downtime = {str(c.params["zone"]) for c in constraints if c.kind == ConstraintKind.NO_DOWNTIME_ZONE}
    forbidden = {_kind(c.params["kind"]) for c in constraints if c.kind == ConstraintKind.FORBID_CONTROL}
    return {
        d.id: [
            o
            for o in d.controls
            if not (patch_only and o.kind != ControlKind.PATCH)
            and o.kind.value not in forbidden
            and not (d.zone in no_downtime and o.downtime_h > 0)
        ]
        for d in city.devices
    }


@dataclass(frozen=True)
class OptionTable:
    keys: list[tuple[str, ControlKind]]  # (device_id, kind) per column
    device: np.ndarray  # (M,) index into city.devices
    cost: np.ndarray  # (M,) INR
    downtime: np.ndarray  # (M,) hours
    saved: np.ndarray  # (S, M) loss removed per scenario, >= 0
    base: np.ndarray  # (S,) loss with no controls
    calibrated: bool

    @property
    def size(self) -> int:
        return len(self.keys)


def _base_matches_simulator(city: City, losses: ScenarioLosses) -> bool:
    """True if ``losses`` is exactly ``simulate(city, S, losses.seed)`` (no controls, no
    strategy, default campaign rate): only then is re-simulating an option comparable."""
    from urbanshield.sim.montecarlo import simulate

    if losses.city_id != city.id or losses.device_ids != tuple(d.id for d in city.devices):
        return False
    probe = simulate(city, n_scenarios=losses.n_scenarios, seed=losses.seed)
    return np.array_equal(probe.device_loss, losses.device_loss)


def _calibrated_saved(city: City, losses: ScenarioLosses) -> np.ndarray:
    """``L_base - L_with_option`` for every listed option of every device (S x all options),
    cached per (city, seed, S) because ``compare`` asks for it once per planner."""
    from urbanshield.sim.montecarlo import simulate

    digest = hashlib.sha256(city.model_dump_json().encode())
    digest.update(f"|{losses.seed}|{losses.n_scenarios}".encode())
    key = digest.hexdigest()
    if key in _calibrated:
        _calibrated.move_to_end(key)
        return _calibrated[key]
    base = losses.total
    columns = [
        base - simulate(city, n_scenarios=losses.n_scenarios, seed=losses.seed, controls={d.id: o.kind}).total
        for d in city.devices
        for o in d.controls
    ]
    # Common random numbers: a control can only shrink the set of lost devices, so the
    # saving is never negative; the clip only absorbs float noise.
    saved = np.clip(np.column_stack(columns), 0.0, None) if columns else np.zeros((len(base), 0))
    _calibrated[key] = saved
    while len(_calibrated) > _CACHE_SIZE:
        _calibrated.popitem(last=False)
    return saved


def option_table(
    city: City,
    losses: ScenarioLosses,
    constraints: list[Constraint],
    patch_only: bool = False,
    calibrate: bool = True,
) -> OptionTable:
    """The allowed options as aligned arrays (see the module docstring for ``saved``)."""
    allowed = allowed_options(city, constraints, patch_only)
    column = {d: i for i, d in enumerate(losses.device_ids)}
    n_all = sum(len(d.controls) for d in city.devices)
    use_sim = calibrate and n_all <= CALIBRATE_MAX_OPTIONS and _base_matches_simulator(city, losses)
    full = _calibrated_saved(city, losses) if use_sim else None

    keys, device, cost, downtime, cols = [], [], [], [], []
    position = 0  # column of this option in ``full`` (all listed options, device order)
    for i, d in enumerate(city.devices):
        ok = {o.kind for o in allowed[d.id]}
        for o in d.controls:
            if o.kind in ok:
                keys.append((d.id, o.kind))
                device.append(i)
                cost.append(o.cost_inr)
                downtime.append(o.downtime_h)
                if full is not None:
                    cols.append(full[:, position])
                elif d.id in column:
                    cols.append(losses.device_loss[:, column[d.id]] * (1.0 - o.exploit_mult * o.spread_mult))
                else:
                    cols.append(np.zeros(losses.n_scenarios))
            position += 1
    saved = np.column_stack(cols) if cols else np.zeros((losses.n_scenarios, 0))
    return OptionTable(
        keys=keys,
        device=np.array(device, dtype=np.int64),
        cost=np.array(cost, dtype=float),
        downtime=np.array(downtime, dtype=float),
        saved=saved,
        base=losses.total,
        calibrated=full is not None,
    )
