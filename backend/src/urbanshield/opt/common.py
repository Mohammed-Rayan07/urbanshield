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

import numpy as np

from urbanshield.schemas import Budget, City, Constraint, ControlKind, Plan


def cvar(losses: np.ndarray, alpha: float) -> float:
    """Empirical CVaR: mean of the worst ``ceil((1 - alpha) * S)`` scenario losses."""
    raise NotImplementedError


def reduction(city: City, device_id: str, kind: ControlKind) -> float:
    """``r_ik`` for one device/control pair."""
    raise NotImplementedError


def is_feasible(city: City, plan: Plan, budget: Budget, constraints: list[Constraint]) -> bool:
    """True if ``plan`` satisfies every rule in the module docstring."""
    raise NotImplementedError
