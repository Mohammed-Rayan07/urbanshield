# UrbanShield — Final 24-Hour Build Plan
**Team Merge Conflict · ChronoForge 2026 (NITK Surathkal) · Track: Cybersecurity · Theme: Cities of the Future**

> Senior's guidance: **minimalism, scalability, security** — no exotic tech.
> Rule: the final build must be "based on the proposal submitted during screening". Everything here **deepens** the proposal; nothing pivots.
> Judging: Problem Relevance · Innovation · Technical Implementation · Functionality · Impact · **Scalability** · **UX** · Track Alignment; Cyber track adds *threat analysis, defensive effectiveness, technical rigor, responsible implementation*; agentic projects add *autonomy, tool integration, planning, reliability, **outcome verification***.

---

## 0. One-paragraph strategy

Most teams will ship a glossy dashboard wrapped around a chatbot, with numbers nobody can check. We win by being the opposite: **every number is traceable, the AI is attacked by our own red-team agent, the security claims fail live when a judge tries to break them, and it runs on a real map of Mangaluru.** Agents make the judgement calls; deterministic tools (BFS, simulator, CVaR optimiser) produce every number; a non-LLM auditor checks the AI's output.

---

## 1. The "why agents, isn't this just BFS?" answer (say this in the first 30 seconds)

> "Reachability **is** BFS, and our agents call it as a tool. We even include a **BFS-only baseline**, and here's how much worse it is at the same budget. What BFS can't do is read a vendor bulletin saying *'SL-200 series, firmware before 4.2'* and decide which of our devices that means. It can't turn *'festival in Zone 3 this weekend, no streetlight downtime'* into an optimiser constraint. And it can't ask *'given the plan we just picked, where would a smart attacker go now?'*. That's our Red-Team agent. Agents decide; tools compute; a non-AI auditor checks; a human approves."

| Job | Deterministic tool | Agent |
|---|---|---|
| Who can reach whom | BFS on reachability graph | — |
| How damage spreads | cascade on dependency graph | — |
| Best fixes under budget | CVaR MILP (SciPy/HiGHS) | — |
| Messy advisory text → affected devices | ✗ (aliases, version ranges) | **Sentinel** |
| Compromise alert → real? blast radius? contain what? | ✗ | **Analyst** |
| Plain-language ops constraints → MILP rows | ✗ | **Planner** |
| Attack the *chosen* plan adaptively | ✗ (a fixed search has no strategy) | **Red-Team** |
| Is every number in the explanation real? | **Auditor** (plain code, not an LLM) | — |

**New baseline added specifically for this question:** `bfs_centrality`, which spends the budget on the devices that reach the most other devices. It sits in the results table next to CVSS-first, so the judge's question is answered with a number.

---

## 2. How we stand out from generic "Claude-Code-built" projects

| Generic hackathon AI project | UrbanShield |
|---|---|
| LLM produces the answers | LLM **never produces a number**: tools compute, agents decide, the Auditor rejects ungrounded claims (rejection rate shown live) |
| "Trust me" metrics | **Click any number → provenance drawer**: tool name, inputs, tool-call ID, timestamp, audit-chain hash |
| Happy-path demo | **Judge Mode**: a judge pastes their own malicious advisory or edits the audit log, and the system catches it live |
| Cherry-picked result | Results on **held-out scenarios with bootstrap CIs** + ablations + one **honest case where we don't win** |
| LangChain/CrewAI boilerplate | A ~200-line hand-written orchestrator with **explicit per-agent tool allowlists**: small, auditable, explainable in 1 minute |
| Abstract "smart city" | A **real map of Mangaluru/Surathkal** (OpenStreetMap + Leaflet); the ambulance corridor runs along NH-66 to a city hospital; budgets in ₹ |
| Full autonomy or none | An **autonomy policy** per control type: low-risk fixes (credential rotation) auto-apply with rollback; anything with downtime needs human approval |
| "Works on my machine" | `docker compose up` / `make demo`, fixed seeds, **replay mode** if the LLM API fails, fallback video |

Data is synthetic devices placed on real streets, seeded with real CVE / CISA-KEV / EPSS records. We never impersonate a real vendor or city department; vendor names are fictional.

---

## 3. Architecture (minimal on purpose)

```
 React + Vite + Tailwind  ──  Map (Leaflet/OSM) · Plans · Agents/Audit  ── (REST + SSE)
                                         │
 FastAPI  (stateless; every route keyed by city_id; roles: viewer / operator / approver)
   ├─ Orchestrator: event queue (SQLite table) → Sentinel → Analyst → Planner ⇄ Red-Team
   │                 → Approval gate (autonomy policy) → apply in twin → re-simulate (verify)
   ├─ Guardrails: quarantined extractor · per-agent tool allowlist · Pydantic at every boundary
   │              · Auditor (claims ↔ tool-call IDs) · hash-chained, Ed25519-signed audit log
   ├─ Tools (pure, deterministic, unit-tested): city_gen · bfs_reach · cascade · simulate (NumPy, vectorised)
   │              · cvar_milp · greedy_tail · baselines · plan_diff · match_inventory
   ├─ LLM adapter: live (any OpenAI-compatible endpoint) | replay (recorded traces) | mock (no key)
   └─ SQLite: devices, edges, scenarios, plans, events, audit_log
```

**Stack (unchanged from proposal, trimmed):** Python 3.12, NumPy, SciPy sparse, NetworkX (graph build only), SciPy (HiGHS MILP), FastAPI, Pydantic v2, SQLite, PyNaCl, OpenAI Python SDK (pointed at any compatible endpoint) · React (Vite), Tailwind, Leaflet, Recharts. **No LangChain, no Kafka, no Kubernetes, no vector DB.**

**Models:** a fast model for Sentinel extraction, a strong model for Planner/Red-Team, set in `.env`. OmniRush tokens power the team's *coding agents*; the app's runtime agents need one OpenAI-compatible key for live recording, and run in `mock`/`replay` otherwise.

### 3.1 Agents: inputs, tools, decision, guardrail

| Agent | Tools (allowlist) | Decision it owns | Output schema | Guardrail |
|---|---|---|---|---|
| **Sentinel** | `quarantine_extract`, `match_inventory`, `emit_event` | Which devices does this advisory/alert affect? Escalate? | `Advisory`, `Match[]` | Raw text only reaches a sandboxed extractor that can emit **only** the `Advisory` schema (dual-LLM / quarantine pattern) |
| **Analyst** | `bfs_reach`, `blast_radius`, `simulate`, `query_devices` | How bad is it? Replan or contain? | `Assessment` | Read-only tools |
| **Planner** | `parse_constraint`, `cvar_optimize`, `run_baselines`, `plan_diff` | Which constraints apply; which plan to propose | `Constraint[]`, `PlanProposal` | Constraints shown to the human as rows before use; solver picks the numbers |
| **Red-Team** | `simulate_strategy`, `bfs_reach`, `list_controls` | Which attack strategies to try against *this* plan | `Strategy[]`, `Hole?` | **No write tools**; strategy menu is parameterised (entry points, target category, firmware pivot, campaign CVE) |
| **Auditor** (code) | — | Accept/reject each claim | `Claim{metric, a, b, delta, tool_call_id}` | Value must equal the stored tool result exactly |

**Red-Team loop:** plan P → Red-Team proposes ≤5 strategies → each strategy generates a batch of scenarios → those are added to the evaluation set and P's CVaR95 is recomputed. A **hole** means *adding the strategy's scenarios raises P's CVaR95 by more than 5%* (not "some scenario exceeds CVaR"; tail scenarios always do). On a hole, the Planner re-solves on the augmented set (max 2 rounds). The UI shows **CVaR before attack → after attack → after replan**.

**Why the Red-Team isn't just enumeration (the follow-up question):** we measure **simulator calls needed to find a hole: Red-Team vs random sampling of the same strategy menu at the same call budget**. That is our outcome-verification number. Run this by h16; if the agent doesn't beat random, find out before the judges do and fix the prompt/menu, or present it honestly.

### 3.2 Demo flows

**Flow A, live autonomy (~75 s):**
1. A new advisory arrives (real CVE ID) → Sentinel matches 11 streetlight controllers sharing firmware `4.1.x`.
2. Analyst: the campaign cascade reaches the NH-66 ambulance-corridor signals (lights up red on the map).
3. Operator types *"Zone 3 festival this weekend, no streetlight downtime"* → Planner shows the constraint row → CVaR plan.
4. Red-Team tries 5 strategies and finds a pivot via an EV-charger gateway → **hole** → replan.
5. Credential rotations auto-apply (policy); segmentation needs approval → approver clicks → re-simulation verifies the worst-case drop → audit entry.

**Flow B, Judge Mode security (~45 s):**
1. "Paste your own advisory" → the screen shows **exactly what the planner receives**: a typed `Advisory` diff, nothing else. Frame it as a *structural* guarantee ("whatever you paste, this is all the planner can see"), **not** as detection. Two more layers: the extracted fields are **cross-checked against the pinned NVD/KEV record for that CVE ID** (a mismatch is flagged and the match needs approval), and **no `Advisory` field can change device or plan state** (it can only trigger re-scoring). Default to a curated set of attacks; pre-test 20+ injection variants, including ones that try to produce a *valid but wrong* advisory, before allowing free typing.
2. "Tamper with the log": edit one row → **Verify chain** turns red at that exact entry.
3. The Auditor counter shows a rejected LLM claim with the reason (value mismatch with the tool call).

---

## 4. Security (the tool is secure, not just about security)

| Threat (STRIDE-ish) | Control | Live? |
|---|---|---|
| Prompt injection via advisories | Quarantined extractor → schema-only output; downstream agents never see free text; extracted fields cross-checked against the pinned feed record; schema fields cannot mutate state | ✅ B1 |
| LLM hallucinated numbers | Claims cite tool-call IDs; deterministic Auditor; rejection rate logged | ✅ B3 |
| Excessive agency | Per-agent allowlists; Red-Team read-only; only the approval gate can "apply" | ✅ allowlist panel |
| Unauthorised change | Roles (viewer/operator/approver); autonomy policy; rollback for auto-applied fixes | ✅ A5 |
| Repudiation / tampering | SHA-256 chain + Ed25519 signatures; `/audit/verify` | ✅ B2 |
| Poisoned data feed | Feed snapshot SHA-256 pinned and checked on load | — |
| Input abuse | Pydantic validation, size limits, simple rate limit | — |
| Secrets | `.env` only, never sent to the frontend; `.env.example` committed | — |
| Responsible use | Simulated city only; no scanning or exploit code; attacks are probabilities on a graph | README + slide |

Map these against the **OWASP Top 10 for LLM Applications** on one slide (LLM01 injection, LLM06 excessive agency, LLM09 misinformation, …). Judges recognise that list.

---

## 5. Scalability (with evidence, not adjectives)

- **Vectorised simulator**: scenarios × devices as NumPy arrays; sparse adjacency; no per-scenario Python loops.
- **Optimiser**: scenario cap (sample-average approximation), greedy warm-start, **automatic MILP → greedy-tail handoff** past a size or time threshold; the UI says which solver ran and the measured gap.
- **`bench.py` chart (slide)**: runtime and CVaR gap at **50 / 500 / 5,000 devices**.
- **Service**: stateless API, `city_id` on every route (multi-city/multi-tenant), SQLite → Postgres is a connection-string change, the event table → Redis/Kafka later. **Say it, don't build it.**
- **Onboarding**: CSV/JSON inventory import using the same schema, so a real city's asset register drops in.

---

## 6. UX: three screens, one idea per screen

1. **City** (map): devices on Mangaluru streets, coloured by category, sized by criticality, red halo = at risk, the ambulance corridor highlighted. Clicking a device shows CVEs, firmware, controls and dependencies.
2. **Plans**: same ₹ budget, three plans side by side (**CVSS-first · BFS-only · UrbanShield**). Loss histogram with the tail shaded, one headline number with its CI, and "what flipped" diff chips. Full baseline + ablation table under a fold.
3. **Agents**: live SSE timeline (agent → tool call → decision), approval buttons, Auditor counter, audit log with **Verify chain**, Judge Mode panel.

Design: dark, one accent colour, Inter / JetBrains Mono for numbers, generous spacing, no gradients. Every number is clickable for provenance. Built with the `frontend-design` / `ui-ux-pro-max` skills.

---

## 7. Cut list (visible minimalism)

- ✂ alpha 0.90/0.99 (0.95 only) · ✂ random-cities stretch (replaced by the benchmark) · ✂ flood sensors (4 categories)
- ✂ LLM-written explanation (templated sentences filled from verified fields)
- ✂ LangChain/CrewAI, Kafka, K8s, microservices, OAuth provider
- ✂ ATT&CK-for-ICS / IEC 62443 mapping (future-work slide)
- Dashboard shows 3 plans; the full 5 baselines + 2 ablations live in one table.

---

## 8. Contracts: freeze in hour 0 (`backend/app/schemas.py`)

```
Device        id, name, category{signal|meter|streetlight|ev_charger}, zone, lat, lon, firmware,
              cves[], exposed, criticality(0-1), epss, kev(bool), controls[ControlOption]
ControlOption kind{patch|segment|disable_remote|rotate_creds|virtual_patch}, cost_inr, downtime_h,
              exploit_mult, spread_mult, autonomy{auto|approve}
Edge          src, dst, kind{reach|depends}
Scenario      id, seed, campaign_cve?, entry_points[], device_loss[]   (stored as .npy matrix)
Constraint    kind{budget|downtime|no_downtime_zone|must_fix|forbid_control}, params, source_sha256
Plan          id, objective{cvar|mean|cvss|cvss_kev_epss|loss_per_inr|greedy_tail|bfs_centrality|patch_only},
              choices{device_id: kind}, cost_inr, downtime_h, cvar95, mean_loss, max_cascade,
              ci95[lo,hi], solver{milp|greedy}, solve_ms, tool_call_id
AgentEvent    id, ts(ISO-8601 UTC), city_id, agent, kind{observe|tool_call|decision|hole|approval|reject},
              payload, tool_call_id?, parent_id?
AuditEntry    seq, event_id, payload_sha256, prev_hash, hash, sig_ed25519
Claim         metric, plan_a, plan_b, delta, tool_call_id
```

---

## 9. Repo layout

```
Chronoforge/
├─ PLAN.md · README.md · ARCHITECTURE.md · ASSUMPTIONS.md · .env.example · docker-compose.yml · Makefile
├─ backend/app/{main.py, schemas.py, db.py}
│   ├─ city/    generator, graphs, Mangaluru coordinates, CVE seeding
│   ├─ sim/     vectorised Monte Carlo, campaigns, cascade
│   ├─ opt/     cvar_milp, greedy_tail, baselines (incl. bfs_centrality), ablations, eval (held-out + bootstrap)
│   ├─ agents/  orchestrator, sentinel, analyst, planner, redteam, llm_adapter (live|replay), policy
│   └─ guard/   quarantine, allowlists, auditor, audit_log
├─ backend/data/  kev_epss_snapshot.json + .sha256, advisories/ (incl. poisoned), traces/ (replay)
├─ backend/tests/ · backend/bench.py
└─ frontend/  Vite + React + Tailwind + Leaflet + Recharts
```

---

## 10. Team split (4 parallel tracks; nobody waits)

| Person | Track | Must-have by |
|---|---|---|
| **A** (Prabhav) | City generator on the Mangaluru map, graphs, CVE/KEV/EPSS feed, ASSUMPTIONS | generator **h4** |
| **S** (Anubhav) | Vectorised simulator + campaigns, audit log, Auditor | `simulate()` **h6** |
| **B** (Sai Varun) | CVaR MILP, 5 baselines (incl. BFS), 2 ablations, held-out eval + CIs, greedy fallback, `bench.py` | CVaR beats CVSS-first **h10** |
| **C (Rayan, integrator)** | Orchestrator, 4 agents, quarantine, allowlists, autonomy policy, LLM adapter, API, contracts, reviews | thin loop on mocks **h8**, real tools **h14** |
| **D** (Rayan) | 3 screens, SSE, provenance drawer, Judge Mode, README/ARCHITECTURE, slides, video | static on fixtures **h8**, live **h16** |

A commits `fixtures/city.json` and `fixtures/losses.npy` by **h2** (fake values are fine) so B, C and D never block on A.

**C is the critical path.** After h6, **A takes the Auditor and the hash-chained audit log** (deterministic code, independent of the agents), so C only owns the orchestrator, the agents, quarantine and allowlists.

---

## 11. Timeline

| Hours | Work | Gate |
|---|---|---|
| 0-1 | Repo, schemas frozen, fixtures, `.env.example`, roles agreed | |
| 1-6 | A: city + sim · B: patch-only MILP · C: orchestrator on mocks · D: UI shell + map | |
| 6-10 | A: campaigns · B: baselines + CVaR · C: Sentinel + quarantine + Analyst · D: City + Plans screens | **h10 CP1: CVaR beats CVSS-first & BFS-only on screen** |
| 10-14 | A+B: multi-control + ablations · C: Planner constraints + Red-Team loop · D: Agents screen + SSE | |
| 14-16 | C: audit log, approval gate, autonomy policy · B: held-out eval + CIs · D: provenance drawer | **h16 CP2: Flow A end-to-end live → record replay trace** |
| 16-19 | C: Judge Mode (injection, tamper) · B: `bench.py` chart · D: polish · A: ASSUMPTIONS.md | |
| 19-21 | **Feature freeze.** `ecc:security-reviewer`, `/code-review`, `webapp-testing` e2e on Flow A/B, fixes | |
| 21-23 | README, ARCHITECTURE diagram, slides, **record fallback video**, 2× rehearsal + Q&A drill | |
| 23-24 | Submit; buffer | |

**Fallbacks:** behind at CP1 → patch-only controls, keep the agents. Behind at CP2 → 1 Red-Team round with a fixed menu, NL constraints become a dropdown.

**Drop order if time runs short (drop the first item first):** provenance drawer → autonomy policy (static badge) → free-paste Judge Mode (curated attacks only) → Mangaluru map (fall back to a force graph) → extra control types. **Never drop:** CVaR vs CVSS/BFS on held-out data, the Red-Team hole→replan, injection quarantine, the tamper-evident log.

---

## 12. Reliability

- Live/replay adapter (one env flag) · fixed seeds, so numbers are identical every run · solver time budget with greedy fallback · fallback video at h22 · pinned dependency versions · a `make demo` that runs offline in replay mode.

---

## 13. Pitch (3 min) and Q&A

1. **Problem (20 s)**: CVSS lists vs the bad year; shared firmware plus cascades. ₹-denominated.
2. **Flow A live (75 s)**.
3. **Numbers (20 s)**: same budget: worst-case loss −X% vs CVSS-first, −Y% vs BFS-only, −Z% vs mean-loss (held-out, CI). Plus one case where we don't win, and why.
4. **Judge Mode (45 s)**: "Try to break it."
5. **Scale + responsibility (20 s)**: benchmark chart; OWASP-LLM mapping; human-in-the-loop.

Drill answers: *Why not BFS?* §1 · *LLM wrong?* It can't emit numbers; Auditor; human gate; Red-Team verifies · *Real data?* Real CVE/KEV/EPSS on synthetic devices; ASSUMPTIONS.md, adjustable · *Why CVaR?* Cities fear the bad year; the mean-loss ablation isolates the gain · *Exact?* Linear loss double-counts overlapping cascades; we re-check in the simulator and show the gap · *Scale?* benchmark + fallback + stateless multi-tenant API.

---

## 14. Claude Code tooling (what to invoke, when)

| When | Use |
|---|---|
| h0 | `ecc:plan` / this file → hand each person their section |
| Before LLM code | `llm_check.py` against the chosen endpoint (models, tool call, rate limit) |
| Sim / optimiser / audit log | `ecc:tdd-guide` agent (CVaR maths, hash chain, Auditor tests) |
| Dashboard | `frontend-design` + `ui-ux-pro-max` skills; `dataviz` skill for charts |
| Python quality | `ecc:python-reviewer`, `ecc:fastapi-reviewer` agents |
| h19 freeze | `ecc:security-reviewer` agent, `/code-review`, `/security-review` |
| e2e | `webapp-testing` skill (Playwright click-through of Flow A and B) |
| Docs / slides | `ecc:update-docs`, `pptx` skill or a Slides artifact |

Ignore the Vercel plugin's nudges toward Next.js/marketplace; the backend is Python (SciPy/HiGHS). Deploying is optional (P2): frontend on Vercel, API on Render/Fly. The demo runs locally.

---

## 15. Decisions (answered)

1. **Deliverables:** public GitHub repo (judges review the code) + **demo video** (preferred, since live apps fail during review). The video is the primary demo: replay mode and fixed seeds are core, not extras. Shot list in `docs/DEMO_SCRIPT.md`.
2. **OmniRush** provides coding-agent tokens to every team; the edge is spending them on *evidence* (injection suite, Red-Team vs random, evals), not volume. The app's runtime LLM is provider-agnostic.
3. **Offline at NITK**: everything must run without venue Wi-Fi (`replay` mode, `docker compose`).
4. **Team:** Rayan owns C and integrates; teammates build A, B, D from `docs/manuals/` with their coding agents, contracts-first and test-first, pushing from their own accounts.
