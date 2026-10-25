# UrbanShield

**A cyber resilience control plane for a simulated connected city.** UrbanShield models how attacks can
spread through city infrastructure, compares hardening plans under a fixed budget, and demonstrates how
signed policy and a corridor safety interlock can constrain commands in the simulated environment.

[![CI](https://github.com/Mohammed-Rayan07/urbanshield/actions/workflows/ci.yml/badge.svg)](https://github.com/Mohammed-Rayan07/urbanshield/actions/workflows/ci.yml)

ChronoForge 2026 · NITK Surathkal · Cybersecurity track · Team **Merge Conflict**

- [Architecture](docs/ARCHITECTURE.md)
- [Evaluation results and methodology](docs/EVALS.md)
- [Assumptions and data sources](docs/ASSUMPTIONS.md)
- [Demo script](docs/DEMO_SCRIPT.md)

## What it does

UrbanShield uses a synthetic 50-device Mangaluru city twin. Its workflow is:

1. **Assess an advisory.** Untrusted bulletin text is screened and reduced to typed fields. The extracted
   fields are checked against the pinned vulnerability feed and city inventory.
2. **Plan within constraints.** Deterministic graph, simulation, and optimisation tools measure reachability
   and tail loss. The planner compares remediation choices against the supplied budget and downtime limits.
3. **Challenge the plan.** The Red-Team agent proposes simulated attack strategies against the candidate plan;
   a material increase in simulated CVaR can trigger another planning round.
4. **Approve and enforce.** Low-risk controls follow the autonomy policy; other controls wait for approval.
   The simulated Enforcer verifies signed policy and applies it to the twin. The corridor interlock checks
   commands using deterministic safety rules.
5. **Verify and audit.** The plan is re-evaluated in simulation. Events, policy decisions, and interlock
   verdicts are written to a signed, hash-chained audit log.

**Agents propose; deterministic tools calculate; code validates; an operator approves higher-impact work.**
The LLM is not in the enforcement or safety-interlock path.

## Evaluation

The latest checked-in results in [docs/EVALS.md](docs/EVALS.md) compare plans on 2,000 held-out simulator
scenarios using the same ₹1,50,000 budget and 24-hour downtime limit. The measured CVaR95 values are:

| Plan | Held-out CVaR95 |
|---|---:|
| CVaR optimiser | 6.34 |
| CVSS-first ranking | 17.12 |
| BFS centrality ranking | 15.11 |
| Mean-loss optimiser | 7.78 |

These are simulated losses for this synthetic city and scenario distribution, not measured real-world incident
rates. Sensitivity and scalability results, including their methods and caveats, are in [docs/EVALS.md](docs/EVALS.md).
The Red-Team-vs-random and prompt-injection evaluation sections are still pending evidence; no results are
claimed for them.

## Quick start

Requirements: Python 3.12 with `uv`, and Node.js with npm.

```powershell
# Terminal 1: backend
cd backend
uv sync
uv run uvicorn urbanshield.api.main:app --reload --port 8000

# Terminal 2: frontend
cd frontend
npm ci
npm run dev
```

Open <http://localhost:5173>. The API docs are at <http://localhost:8000/docs>.

For Docker, copy `.env.example` to `.env` and run:

```powershell
docker compose up --build
```

The compose configuration defaults to `LLM_MODE=replay`. Replay is cache-only and fails with a replay miss
when a matching response has not been recorded. The checked-in trace directory currently has no recorded
LLM responses, so use `LLM_MODE=mock` for an offline startup until traces are recorded. Mock mode uses
deterministic scripted responders and is labelled as mock in the application.

## LLM modes and guardrails

The app supports `mock`, `live`, and `replay` modes. To use a live OpenAI-compatible Chat Completions
endpoint, set `LLM_MODE`, `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL_FAST`, and `LLM_MODEL_STRONG` in the
local `.env` file. Never commit `.env` or put a key in source code. For Gemini, consult Google's current
[model list](https://ai.google.dev/gemini-api/docs/models) and configure its OpenAI-compatible endpoint.
Provider quotas and billing apply. Run the smoke check before using a live model:

```powershell
cd backend
uv run python scripts/llm_check.py
```

UrbanShield does not train or fine-tune a model. Its guardrails are implemented in the application workflow:
untrusted advisory text is quarantined, only validated typed fields move to later agents, each agent has an
allowlist of tools, tool arguments are validated, and the Auditor checks claims against recorded tool results.
The LLM cannot apply controls, sign policy, or override the deterministic interlock.

Live mode records model responses in `backend/fixtures/traces` for offline replay. Record the required
workflows before relying on replay; an absent trace is an error and never falls back to mock. The live
Red-Team-vs-random and injection-suite evidence has not yet been recorded.

## Application workspaces

The frontend includes Story Mode, Overview, Risk Intelligence, Response & Mitigation, Devices, Judge Mode,
and Audit Log. It shows a two-plan replay using shared simulator random draws, a precomputed budget frontier,
the simulated attack console, approval flow, advisory quarantine, and audit verification. Values presented
as measurements come from backend results; the city and attacks themselves remain simulated.

## API overview

| Route | Purpose |
|---|---|
| `GET /api/health` | Engine readiness, data mode, LLM mode, and audit-key status |
| `GET /api/cities/{id}` | City twin and inventory |
| `GET /api/cities/{id}/plans` · `/risk` | Compared plans and held-out risk summaries |
| `GET /api/cities/{id}/replay` | Same scenario replayed under the compared plans |
| `GET /api/cities/{id}/frontier` | Precomputed held-out loss across budget levels |
| `GET /api/cities/{id}/enforcer` | Simulated policy and recent enforcement decisions |
| `POST /api/cities/{id}/enforcer/commands` | Evaluate a simulated command through policy and interlock |
| `POST /api/cities/{id}/incidents` | Start an incident workflow |
| `GET /api/runs/{run}/events` | Stream incident events over Server-Sent Events |
| `POST /api/runs/{run}/approvals` | Approve or reject a pending plan (`X-Role: approver`) |
| `GET /api/audit/entries` · `/key` · `/verify` | Read and verify the signed audit chain |

## Repository layout

```text
backend/src/urbanshield/
  city/       city twin, attack and dependency graphs, vulnerability feed
  sim/        vectorised Monte Carlo simulation and scenario replay
  opt/        CVaR optimisation, baselines, and evaluation
  agents/     LLM adapter, Sentinel, Analyst, Planner, Red-Team, orchestration
  guard/      quarantine, tool allowlists, Auditor, audit log, Enforcer, interlock
  api/        FastAPI routes, SSE runs, replay, risk, and budget frontier
backend/scripts/  evaluation, benchmark, trace recording, and smoke-check scripts
frontend/         React, Vite, Tailwind, and Leaflet application
docs/             architecture, assumptions, evaluations, demo materials, and manuals
```

## Checks

```powershell
cd backend
uv run pytest
uv run ruff check .
uv run ruff format --check .

cd ../frontend
npm run lint
npm run build
```

## Limitations and safety

- All devices, vulnerabilities in the twin, attacks, enforcement, and mitigation outcomes are simulated.
  UrbanShield does not scan, probe, exploit, or configure real infrastructure.
- The Enforcer models policy changes over the twin; it does not install network rules on real equipment.
- The interlock is an illustrative deterministic rule set. A deployment would require an approved signal
  timing plan, validated hardware interfaces, and operational safety review.
- Approval uses a demo role header, not production authentication. Run state and demo signing configuration
  are process-local; a restart resets in-memory state.
- An ephemeral audit signing key is used when `AUDIT_SIGNING_KEY` is unset. Persist a secret key securely if
  audit verification must survive restarts; never commit it.
- Replay mode needs recorded traces for the exact prompts. Current checked-in traces are empty, and the
  live evidence sections of `docs/EVALS.md` remain pending.

## Team and license

Prabhav Ravi · Anubhav Chatterjee · Mohammad Rayan · Sai Varun Tej K — [MIT License](LICENSE)
