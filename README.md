# UrbanShield

**Tail-risk-aware cyber resilience planning for the connected infrastructure of future cities.**

[![CI](https://github.com/Mohammed-Rayan07/urbanshield/actions/workflows/ci.yml/badge.svg)](https://github.com/Mohammed-Rayan07/urbanshield/actions/workflows/ci.yml)
· ChronoForge 2026, NITK Surathkal · Cybersecurity track · Team **Merge Conflict**

> 🎥 **Demo video:** _link added at submission_ · 📐 [Architecture](docs/ARCHITECTURE.md) · 📊 [Evaluation](docs/EVALS.md) · 📄 [Assumptions](docs/ASSUMPTIONS.md)

---

## The problem

Cities are wiring up traffic signals, streetlights, smart meters and EV chargers faster than they can secure them. A scanner hands a small municipal team hundreds of findings sorted by CVSS. It does not say **which ten to fix with the money available**, and it knows nothing about what a device does or what depends on it. A medium-severity bug in firmware shared by a dozen streetlights, one hop from the ambulance-corridor signals, matters more than a critical bug in a decorative light. Cities don't fear the average year; they fear **the bad year**.

## What UrbanShield does

Given a device inventory and a fixed budget in rupees, UrbanShield simulates how attacks spread through the city, then picks the set of fixes that **minimises worst-case (CVaR 95%) loss**, not average loss. When a new advisory arrives, four agents re-assess, re-plan, **attack their own plan**, and explain what changed. A human approves anything with downtime.

| | |
|---|---|
| **Agents decide, tools compute** | Every number comes from a deterministic tool (BFS, Monte Carlo simulator, CVaR MILP). Agents choose *what* to compute. |
| **Red-Team agent** | After a plan is chosen, an attacker agent searches for strategies that break *that* plan. Holes force a re-plan. |
| **The checker is not an LLM** | An Auditor in plain code rejects any claim that doesn't match a recorded tool result. |
| **Prompt-injection quarantine** | Advisory text is reduced to a typed record before any planning agent sees it, then cross-checked against a pinned feed. |
| **Tamper-evident** | Every agent action goes to a SHA-256 hash chain with Ed25519 signatures. |
| **Honest numbers** | Plans are scored on held-out scenarios with bootstrap CIs, against CVSS-first, BFS-only and mean-loss baselines under the same budget. |

## Why agents, and not just BFS?

Reachability *is* BFS, and the agents call it as a tool; there's even a BFS-only baseline in the results. What a graph search can't do is decide which devices a messy vendor bulletin affects, turn "festival in Zone 3, no streetlight downtime" into an optimiser constraint, or adapt an attack to the plan that was just chosen. That is what the agents do, under allowlists, with every decision logged.

## Quick start

```bash
# backend (Python 3.12, uv)
cd backend && uv sync && uv run uvicorn urbanshield.api.main:app --reload --port 8000
# frontend (Node 24), in a second terminal
cd frontend && npm ci && npm run dev        # http://localhost:5173
```

Or everything in Docker, offline replay mode: `docker compose up --build` → <http://localhost:8080>.

No API key is needed: `LLM_MODE=mock` (default) runs deterministic agents, `replay` serves recorded agent traces. See [`.env.example`](.env.example) for live mode with any OpenAI-compatible endpoint.

## Repository layout

```
backend/src/urbanshield/
  schemas.py   data contracts shared by every module
  city/        city twin on Mangaluru streets, attack + dependency graphs, pinned CVE/KEV/EPSS feed
  sim/         vectorised Monte Carlo with correlated campaigns
  opt/         CVaR MILP (PuLP/CBC), baselines, ablations, held-out evaluation
  agents/      Sentinel, Analyst, Planner, Red-Team, orchestrator, provider-agnostic LLM adapter
  guard/       quarantine, tool allowlists, Auditor, hash-chained audit log
  api/         FastAPI + Server-Sent Events
frontend/      React + Vite + Tailwind + Leaflet + Recharts
docs/          architecture, assumptions, evaluation, demo script, team manuals
```

## Tests

```bash
cd backend && uv run pytest        # property tests: feasibility, CVaR maths, hash-chain tamper detection, …
```

## Scope and ethics

Everything runs against a **simulated** city. UrbanShield does not scan, probe or exploit real systems; attacks are probabilities on a graph and there is no exploit code. Vendor names are fictional; CVE, KEV and EPSS records are real public data used to seed vulnerability profiles. A person approves any plan before it is marked as applied.

## Team

Prabhav Ravi (lead) · Anubhav Chatterjee · Mohammad Rayan · Sai Varun Tej K — [MIT licence](LICENSE)
