"""Scalability benchmark: simulator, CVaR MILP and greedy at 50 / 500 / 5,000 devices. Owner: B.

    uv run --with matplotlib python scripts/bench.py            # print the table
    uv run --with matplotlib python scripts/bench.py --write    # also docs/bench.png + EVALS.md §5

matplotlib is a one-off script dependency (``--with``), not a project dependency.
Both planners are scored on the same option table (``_model.option_table``) they optimise,
so the gap column compares solver quality, not models.
"""

from __future__ import annotations

import argparse
import time

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from urbanshield.agents.evidence import replace_section
from urbanshield.city.generator import generate_city
from urbanshield.config import BACKEND_DIR
from urbanshield.opt._model import CALIBRATE_MAX_OPTIONS, option_table
from urbanshield.opt.common import cvar
from urbanshield.opt.cvar import solve
from urbanshield.opt.greedy import greedy_tail
from urbanshield.schemas import Budget, City, Plan, ScenarioLosses
from urbanshield.sim.montecarlo import simulate

DOCS = BACKEND_DIR.parent / "docs"
SIZES = (50, 500, 5000)
N_SCENARIOS = 1000
TIME_LIMIT_S = 30.0


def _model_cvar(city: City, losses: ScenarioLosses, plan: Plan, alpha: float) -> float:
    table = option_table(city, losses, [])
    column = {key: j for j, key in enumerate(table.keys)}
    picked = [column[(d, k)] for d, k in plan.choices.items()]
    return cvar(table.base - table.saved[:, picked].sum(axis=1), alpha)


def _timed(fn):
    started = time.perf_counter()
    value = fn()
    return value, time.perf_counter() - started


def run() -> tuple[list[dict], str]:
    rows = []
    for n in SIZES:
        city = generate_city(seed=42, n_devices=n)
        budget = Budget(inr=12_000 * n, downtime_h=0.5 * n)  # scales with the city: ~₹6 lakh / 24 h at 50
        losses, t_sim = _timed(lambda c=city: simulate(c, n_scenarios=N_SCENARIOS, seed=1))
        greedy, t_greedy = _timed(lambda c=city, sl=losses, b=budget: greedy_tail(c, sl, b))
        milp, t_milp = _timed(lambda c=city, sl=losses, b=budget: solve(c, sl, b, time_limit_s=TIME_LIMIT_S))
        c_milp = _model_cvar(city, losses, milp, budget.alpha)
        c_greedy = _model_cvar(city, losses, greedy, budget.alpha)
        row = {
            "n": n,
            "options": option_table(city, losses, []).size,
            "sim": t_sim,
            "milp": t_milp,
            "greedy": t_greedy,
            "solver": milp.solver.value,
            "c_milp": c_milp,
            "c_greedy": c_greedy,
            "gap": 100.0 * (c_greedy - c_milp) / c_milp if c_milp > 0 else 0.0,
        }
        rows.append(row)
        print(row, flush=True)

    lines = [
        f"| Devices | Options | Sim (S={N_SCENARIOS:,}) | MILP | MILP result | Greedy | MILP CVaR | "
        "Greedy CVaR | Greedy vs MILP |",
        "|---:|---:|---:|---:|---|---:|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(
            f"| {r['n']:,} | {r['options']:,} | {r['sim']:.2f} s | {r['milp']:.2f} s | `{r['solver']}` | "
            f"{r['greedy']:.2f} s | {r['c_milp']:.2f} | {r['c_greedy']:.2f} | {r['gap']:+.2f}% |"
        )
    lines += [
        "",
        f"MILP: HiGHS with a {TIME_LIMIT_S:g} s limit; a time-limited incumbent is kept (`milp`) only if it "
        "beats the greedy plan, otherwise the greedy plan is returned (`greedy`). Below "
        f"{CALIBRATE_MAX_OPTIONS:,} options both planners first calibrate the option savings (one "
        "simulation per option), which is most of their time at 50 devices; larger cities use the "
        "linear savings model. Budget scales with city size (₹12,000 and 0.5 h per device).",
        "",
        "![Scalability benchmark](bench.png)",
    ]
    return rows, "\n".join(lines)


def plot(rows: list[dict]) -> None:
    n = [r["n"] for r in rows]
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=150)
    for key, label, marker in (
        ("sim", f"Monte Carlo simulator (S={N_SCENARIOS:,})", "o"),
        ("greedy", "Greedy tail heuristic", "s"),
        ("milp", f"CVaR MILP (HiGHS, {TIME_LIMIT_S:g} s limit)", "^"),
    ):
        ax.plot(n, [r[key] for r in rows], marker=marker, linewidth=1.8, label=label)
    ax.set(xscale="log", yscale="log", xlabel="Devices in the city", ylabel="Seconds (log scale)")
    ax.set_title("UrbanShield scalability")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(DOCS / "bench.png")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--write", action="store_true", help="write docs/bench.png and EVALS.md section 5")
    args = parser.parse_args()
    rows, table = run()
    print(table)
    if args.write:
        plot(rows)
        replace_section(DOCS / "EVALS.md", 5, table)
        print(f"wrote {DOCS / 'bench.png'} and EVALS.md section 5")


if __name__ == "__main__":
    main()
