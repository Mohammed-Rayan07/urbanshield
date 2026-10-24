"""Helpers every planner shares. Owner: B.

Linear loss model used by the MILP (a stated simplification, checked against the
full simulator in ``evaluate.py``)::

    L_s(x) = sum_i  device_loss[s, i] * (1 - sum_k r_ik * x_ik)
    r_ik   = 1 - exploit_mult_ik * spread_mult_ik      # fraction of device i's loss removed

Feasibility rules every plan must satisfy (tests check all planners):
- at most one control per device, and only a control listed in that device's options;
- total ``cost_inr`` <= budget.inr and total ``downtime_h`` <= budget.downtime_h;
- every ``Constraint`` honoured (NO_DOWNTIME_ZONE: no control with downtime > 0 on a
  device in that zone; MUST_FIX: device gets some control; FORBID_CONTROL: kind unused).
"""

from __future__ import annotations

import math

import numpy as np

from urbanshield.schemas import Budget, City, Constraint, ConstraintKind, ControlKind, Plan


def tail_size(n_scenarios: int, alpha: float) -> int:
    """Number of scenarios in the CVaR tail. The ``- 1e-9`` guards float error:
    ``(1 - 0.95) * 100`` is ``5.000000000000004``, which must count as 5, not 6."""
    return max(1, math.ceil((1 - alpha) * n_scenarios - 1e-9))


def cvar(losses: np.ndarray, alpha: float) -> float:
    """Empirical CVaR: mean of the worst ``tail_size(S, alpha)`` scenario losses.
    Use ``tail_size`` everywhere (including the MILP's 1/((1-alpha)S) term) so the
    optimiser and the evaluator measure the same thing."""
    arr = np.asarray(losses, dtype=float)
    if arr.size == 0:
        return 0.0
    k = tail_size(arr.size, alpha)
    if k >= arr.size:
        return float(np.mean(arr))
    partitioned = np.partition(arr, arr.size - k)
    return float(np.mean(partitioned[-k:]))


def reduction(city: City, device_id: str, kind: ControlKind) -> float:
    """``r_ik`` for one device/control pair."""
    device = city.device(device_id)
    for opt in device.controls:
        if opt.kind == kind:
            return float(1.0 - opt.exploit_mult * opt.spread_mult)
    raise KeyError(f"Device {device_id} has no control of kind {kind}")


def is_feasible(
    city: City,
    plan: Plan,
    budget: Budget,
    constraints: list[Constraint] | None = None,
) -> bool:
    """True if ``plan`` satisfies every rule in the module docstring."""
    total_cost = 0
    total_downtime = 0.0

    # Cache device lookup
    device_map = {d.id: d for d in city.devices}

    for dev_id, kind in plan.choices.items():
        dev = device_map.get(dev_id)
        if dev is None:
            return False
        opt = next((c for c in dev.controls if c.kind == kind), None)
        if opt is None:
            return False
        total_cost += opt.cost_inr
        total_downtime += opt.downtime_h

    if total_cost > budget.inr or total_downtime > budget.downtime_h:
        return False
    if plan.cost_inr > budget.inr or plan.downtime_h > budget.downtime_h:
        return False

    for c in constraints or []:
        if c.kind == ConstraintKind.NO_DOWNTIME_ZONE:
            zone = c.params.get("zone")
            for dev_id, kind in plan.choices.items():
                dev = device_map[dev_id]
                if dev.zone == zone:
                    opt = next(opt for opt in dev.controls if opt.kind == kind)
                    if opt.downtime_h > 0:
                        return False
        elif c.kind == ConstraintKind.MUST_FIX:
            must_dev = c.params.get("device_id")
            if must_dev and must_dev not in plan.choices:
                return False
        elif c.kind == ConstraintKind.FORBID_CONTROL:
            forbidden = c.params.get("kind")
            if forbidden:
                forbidden_str = forbidden.value if hasattr(forbidden, "value") else str(forbidden)
                for kind in plan.choices.values():
                    kind_str = kind.value if hasattr(kind, "value") else str(kind)
                    if kind_str == forbidden_str:
                        return False
        elif c.kind == ConstraintKind.BUDGET:
            max_inr = c.params.get("inr")
            if max_inr is not None and total_cost > float(max_inr):
                return False
        elif c.kind == ConstraintKind.DOWNTIME:
            max_dt = c.params.get("downtime_h")
            if max_dt is not None and total_downtime > float(max_dt):
                return False

    return True
