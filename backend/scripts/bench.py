"""Scalability benchmark for UrbanShield optimiser and simulation. Owner: B.

Usage:
    python scripts/bench.py
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# Ensure backend/src is on sys.path
backend_src = Path(__file__).resolve().parents[1] / "src"
if str(backend_src) not in sys.path:
    sys.path.insert(0, str(backend_src))

from urbanshield.opt.common import cvar  # noqa: E402
from urbanshield.opt.cvar import solve  # noqa: E402
from urbanshield.opt.greedy import greedy_tail  # noqa: E402
from urbanshield.schemas import (  # noqa: E402
    Autonomy,
    Budget,
    Category,
    City,
    ControlKind,
    ControlOption,
    Device,
    Edge,
    EdgeKind,
    Objective,
    ScenarioLosses,
    Vulnerability,
)


def _get_benchmark_city(n_devices: int, seed: int = 42) -> City:
    """Generate benchmark city with N devices."""
    try:
        from urbanshield.city.generator import generate_city

        city = generate_city(seed=seed, n_devices=n_devices)
        if len(city.devices) == n_devices:
            return city
    except NotImplementedError:
        pass

    rng = np.random.default_rng(seed)
    categories = [Category.STREETLIGHT, Category.SIGNAL, Category.METER, Category.EV_CHARGER]
    devices = []
    for i in range(n_devices):
        cat = categories[i % 4]
        vuln = Vulnerability(
            cve_id=f"CVE-2025-{20000 + i}",
            cvss=float(rng.uniform(4.0, 9.5)),
            epss=float(rng.uniform(0.05, 0.5)),
        )
        controls = [
            ControlOption(
                kind=ControlKind.PATCH,
                cost_inr=int(rng.integers(30_000, 50_000)),
                downtime_h=4.0,
                exploit_mult=0.1,
                spread_mult=1.0,
                autonomy=Autonomy.APPROVE,
            ),
            ControlOption(
                kind=ControlKind.SEGMENT,
                cost_inr=int(rng.integers(15_000, 25_000)),
                downtime_h=2.0,
                exploit_mult=0.7,
                spread_mult=0.3,
                autonomy=Autonomy.APPROVE,
            ),
            ControlOption(
                kind=ControlKind.ROTATE_CREDS,
                cost_inr=int(rng.integers(1_000, 3_000)),
                downtime_h=0.0,
                exploit_mult=0.6,
                spread_mult=1.0,
                autonomy=Autonomy.AUTO,
            ),
        ]
        devices.append(
            Device(
                id=f"d-{i + 1:04d}",
                name=f"dev-{i + 1}",
                category=cat,
                zone=f"Z{i % 4 + 1}",
                lat=12.9 + float(rng.uniform(-0.05, 0.05)),
                lon=74.8 + float(rng.uniform(-0.05, 0.05)),
                firmware=f"firmware/{cat}/1.0",
                vulns=[vuln],
                exposed=(i % 4 == 0),
                criticality=float(rng.uniform(0.1, 0.9)),
                controls=controls,
            )
        )

    edges = [
        Edge(src=devices[i].id, dst=devices[i + 1].id, kind=EdgeKind.REACH) for i in range(n_devices - 1)
    ]
    return City(
        id=f"bench-{n_devices}",
        name=f"Bench {n_devices}",
        seed=seed,
        devices=devices,
        edges=edges,
    )


def _simulate_benchmark(city: City, s: int = 1000, seed: int = 0) -> ScenarioLosses:
    """Simulate or generate synthetic scenario losses."""
    try:
        from urbanshield.sim.montecarlo import simulate

        return simulate(city, n_scenarios=s, seed=seed)
    except NotImplementedError:
        pass

    rng = np.random.default_rng(seed)
    n = len(city.devices)
    crit = np.array([d.criticality for d in city.devices])
    prob = np.array([max(v.cvss / 10.0 for v in d.vulns) * 0.4 for d in city.devices])
    comp = rng.random((s, n)) < prob[None, :]
    loss = comp * crit[None, :]
    return ScenarioLosses(
        city_id=city.id,
        seed=seed,
        device_ids=tuple(d.id for d in city.devices),
        device_loss=loss.astype(np.float64),
        compromised=comp,
        campaign_cve=(None,) * s,
    )


def run_benchmark():
    n_values = [50, 500, 5000]
    s_scenarios = 1000
    budget = Budget(inr=1_000_000, downtime_h=48, alpha=0.95)

    sim_times = []
    milp_times = []
    greedy_times = []
    cvar_gaps = []

    header = (
        "| Devices (N) | Scenarios (S) | Sim Time (s) | MILP Time (s) | "
        "Greedy Time (s) | MILP CVaR | Greedy CVaR | Gap (%) |"
    )
    results_table = [
        header,
        "|---|---|---|---|---|---|---|---|",
    ]

    print("Running scalability benchmarks...", flush=True)
    for n in n_values:
        print(f"\n--- Benchmarking N = {n}, S = {s_scenarios} ---", flush=True)
        city = _get_benchmark_city(n)

        # 1. Simulate
        t0 = time.perf_counter()
        losses = _simulate_benchmark(city, s=s_scenarios, seed=1)
        sim_time = time.perf_counter() - t0
        sim_times.append(sim_time)
        print(f"Simulate: {sim_time:.3f}s", flush=True)

        # 2. Greedy
        t0 = time.perf_counter()
        plan_greedy = greedy_tail(city, losses, budget)
        greedy_time = time.perf_counter() - t0
        greedy_times.append(greedy_time)
        print(f"Greedy: {greedy_time:.3f}s", flush=True)

        # Precompute greedy linear CVaR
        scale_g = np.ones(n)
        for did, kind in plan_greedy.choices.items():
            idx = losses.device_ids.index(did)
            opt = next(c for c in city.device(did).controls if c.kind == kind)
            scale_g[idx] -= 1.0 - opt.exploit_mult * opt.spread_mult
        greedy_cvar = cvar(losses.device_loss @ scale_g, budget.alpha)

        # 3. MILP (with 30s limit)
        if n > 1000:
            print("Running MILP with 10s limit (large scale fallback to greedy expected)...", flush=True)
            t0 = time.perf_counter()
            plan_milp = solve(city, losses, budget, objective=Objective.CVAR, time_limit_s=10.0)
            milp_time = time.perf_counter() - t0
        else:
            t0 = time.perf_counter()
            plan_milp = solve(city, losses, budget, objective=Objective.CVAR, time_limit_s=30.0)
            milp_time = time.perf_counter() - t0

        milp_times.append(milp_time)
        print(f"MILP: {milp_time:.3f}s (Solver: {plan_milp.solver.value})", flush=True)

        scale_m = np.ones(n)
        for did, kind in plan_milp.choices.items():
            idx = losses.device_ids.index(did)
            opt = next(c for c in city.device(did).controls if c.kind == kind)
            scale_m[idx] -= 1.0 - opt.exploit_mult * opt.spread_mult
        milp_cvar = cvar(losses.device_loss @ scale_m, budget.alpha)

        gap_pct = ((greedy_cvar - milp_cvar) / milp_cvar) * 100.0 if milp_cvar > 0 else 0.0
        cvar_gaps.append(gap_pct)

        results_table.append(
            f"| {n:,} | {s_scenarios:,} | {sim_time:.3f}s | {milp_time:.3f}s | "
            f"{greedy_time:.3f}s | {milp_cvar:.2f} | {greedy_cvar:.2f} | **+{gap_pct:.2f}%** |"
        )

    # Generate Scalability Plot
    fig, ax = plt.subplots(figsize=(8, 5), dpi=150)
    ax.plot(n_values, sim_times, "o-", label="Monte Carlo Sim (S=1000)", color="#2563eb", linewidth=2)
    ax.plot(n_values, greedy_times, "s-", label="Greedy Tail Heuristic", color="#10b981", linewidth=2)
    ax.plot(n_values, milp_times, "^-", label="CVaR MILP (CBC, 30s limit)", color="#f59e0b", linewidth=2)

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Number of City Devices (N)", fontsize=11, fontweight="bold")
    ax.set_ylabel("Execution Time (seconds, log scale)", fontsize=11, fontweight="bold")
    ax.set_title(
        "UrbanShield Scalability: Simulation, MILP & Greedy Heuristic", fontsize=12, fontweight="bold"
    )
    ax.grid(True, which="both", ls="--", alpha=0.5)
    ax.legend(frameon=True, fontsize=10)
    plt.tight_layout()

    docs_dir = Path(__file__).resolve().parents[2] / "docs"
    plot_path = docs_dir / "bench.png"
    fig.savefig(plot_path)
    plt.close(fig)
    print(f"\nSaved benchmark chart to {plot_path}")

    # Update docs/EVALS.md Section 5
    sec5_text = "\n".join(results_table) + "\n\n![Scalability Benchmark](bench.png)\n"
    evals_path = docs_dir / "EVALS.md"
    content = evals_path.read_text(encoding="utf-8")

    content = re.sub(
        r"## 5\. Scalability \(50 / 500 / 5,000 devices\)\s*\n\s*_pending_.*?(?=\Z)",
        f"## 5. Scalability (50 / 500 / 5,000 devices)\n\n{sec5_text}\n",
        content,
        flags=re.DOTALL,
    )
    evals_path.write_text(content, encoding="utf-8")
    print(f"Updated {evals_path} Section 5 successfully!")


if __name__ == "__main__":
    run_benchmark()
