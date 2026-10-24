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

from urbanshield.schemas import Budget, City, Constraint, ControlKind, Plan


def tail_size(n_scenarios: int, alpha: float) -> int:
    """Number of scenarios in the CVaR tail. The ``- 1e-9`` guards float error:
    ``(1 - 0.95) * 100`` is ``5.000000000000004``, which must count as 5, not 6."""
    return max(1, math.ceil((1 - alpha) * n_scenarios - 1e-9))


def cvar(losses: np.ndarray, alpha: float) -> float:
    """Empirical CVaR: mean of the worst ``tail_size(S, alpha)`` scenario losses.
    Use ``tail_size`` everywhere (including the MILP's 1/((1-alpha)S) term) so the
    optimiser and the evaluator measure the same thing."""
    raise NotImplementedError


def reduction(city: City, device_id: str, kind: ControlKind) -> float:
    """``r_ik`` for one device/control pair."""
    raise NotImplementedError


def is_feasible(city: City, plan: Plan, budget: Budget, constraints: list[Constraint]) -> bool:
    """True if ``plan`` satisfies every rule in the module docstring."""
    raise NotImplementedError
