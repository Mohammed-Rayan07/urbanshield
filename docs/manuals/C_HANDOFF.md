# Part C handoff: agents, guardrails, API

**New owner:** Anubhav (`anubhav10cs`) · **Integrator / reviewer / dashboard:** Rayan · **Branch:** `c/agents`

You are taking over Part C of UrbanShield mid-build. Part C is the heart of the project: it's what the judges
will ask about first ("why agents, isn't this just BFS?") and what the demo video shows. Read this whole file
before writing code. Then read, in this order: `AGENTS.md`, `docs/PLAN.md` (strategy; sections 1–5 matter
most), `docs/ARCHITECTURE.md`, `docs/manuals/C_agents.md`, `backend/src/urbanshield/schemas.py`.

---

## 0. Context in 60 seconds

- **Hackathon:** ChronoForge 2026 (NITK Surathkal), 24 hours, Cybersecurity track, theme "Cities of the Future".
  Judged on problem relevance, innovation, technical implementation, functionality, impact, **scalability**,
  UX and track alignment. Agentic projects are also judged on **autonomy, tool use, planning, reliability and
  outcome verification**. Cyber projects are judged on **threat analysis, defensive effectiveness, rigour and
  responsible implementation**.
- **Deliverables:** the GitHub repo (reviewers read the code) plus a **demo video**, which is the primary
  demo. Everything must run offline in `replay` mode with identical numbers on every run.
- **Senior's guidance:** minimalism, scalability, security. No exotic tech.
- **The product:** a city twin of 50 IoT devices on Mangaluru streets. A Monte Carlo attack simulator (yours,
  Part S). A CVaR optimiser that spends a fixed ₹ budget to minimise *worst-case* loss (B). Four agents that
  react to a new advisory by re-assessing, re-planning, **attacking their own plan** and explaining it, with a
  human approving anything that causes downtime.
- **Core principle:** *agents decide, tools compute, a non-LLM Auditor checks, a human approves.* The LLM
  never produces a number.

| Part | Owner | Status |
|---|---|---|
| A: city, graphs, feed | Prabhav | in progress |
| B: optimiser, evals, bench | Sai Varun | in progress |
| S: simulator, audit log, Auditor | you | **done**: open the PR; Rayan has reviewed it (24 passed, lint clean) |
| **C: agents, guardrails, API** | **you (from now)** | about 30% done, see §2 |
| D: dashboard + video | Rayan | in progress |

---

## 1. First 15 minutes

1. Open the S PR: `gh pr create --base main --head s/sim-audit --fill`. Rayan merges it.
2. **Add your differential test** (naive reference vs `simulate()`, exact match on 300 random cities) as a
   *new* file, `backend/tests/test_sim_reference.py`, in the same PR. Approved. Mark it `@pytest.mark.slow`
   if it takes more than about 3 s.
3. `git fetch; git switch c/agents; git rebase origin/main` (after S merges).
4. In your Claude Code, stop the ecc GateGuard hook from blocking every new file by creating
   `.claude/settings.local.json` (gitignored):
   `{"env": {"GATEGUARD_EXEMPT_GLOBS": "**"}}`, then restart the session. Destructive-command checks stay on.
5. Get a **Gemini API key** (free tier) from Google AI Studio and put it in `.env` (never commit `.env`):
   ```
   LLM_MODE=live
   LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/
   LLM_API_KEY=<key>
   LLM_MODEL_FAST=<current Flash model id from ai.google.dev/gemini-api/docs/models>
   LLM_MODEL_STRONG=<current Pro or Flash model id>
   AUDIT_SIGNING_KEY=<generate once, see §4.1>
   ```

---

## 2. What's already on `c/agents`

| File | State | Notes |
|---|---|---|
| `agents/engine.py` | **done** | `Engine` dataclass: the only seam between agents and A/S/B modules. `default_engine()` binds the real modules lazily; `engine_ready()` is True once they're all implemented (only `NotImplementedError` counts as not-ready; other errors propagate). Tests inject fakes. |
| `agents/llm.py` | **done** (untested) | `chat(task, messages, tier, tools, json_output)`. `CachedLLM` handles live (cache-through) and replay (cache-only; a miss raises `ReplayMiss`). The OpenAI SDK client is built lazily, only in live mode. 429/5xx use bounded exponential backoff. A 400 caused by `response_format` is retried without it. Cache key = SHA-256 of the canonical request. `get_llm(settings)` imports `agents/mock.py` (**not written yet**). |
| `agents/tools.py` | **done in shape, has dangling refs** | `RunContext` holds per-run state, sequential `tc-001` tool ids, `ctx.event()` emits `AgentEvent`s, and caches graphs and train losses. There are 12 tools with **flat** Pydantic arg models. `openai_tool_specs(agent)` exposes only allowed tools. `call()` does authorise (emitting a REJECT event when refused) → validate → run → store `ToolResult` → emit TOOL_CALL. |
| `guard/allowlist.py` | done | Per-agent allowlists; Red-Team is read-only. |
| `guard/quarantine.py` | partial | `sha256_text` and `flag_spans` are done; `quarantine_extract` and `cross_check` are stubs. |
| `agents/sentinel.py`, `analyst.py`, `planner.py`, `redteam.py`, `orchestrator.py` | stubs | You write these. |
| `api/main.py` | fixture-backed | Serves placeholder demo data; `/api/health` says `data: "placeholder"` and the UI shows a yellow banner. |

**Dangling references in `tools.py` you must resolve.** They were planned but not written yet; change the
stub signatures to match:
- `quarantine_extract(raw_text, llm) -> Advisory`. The stub has only `raw_text`; add `llm: LLM`.
- `cross_check(advisory, feed_lookup) -> list[str]`. Add the lookup param (pass `engine.feed_record`).
- `redteam.strategy_from_args(ctx, args_dict) -> Strategy` and `redteam.score_strategy(ctx, strategy) -> Hole-like
  result` with keys `strategy_id`, `cvar_before`, `cvar_after_attack`, `increase_pct`, `hole`, `sim_calls`.
- `api.ts` / `types.ts` will need the run-scoped provenance route (§3.6). Tell Rayan before you change them,
  because his dashboard uses them.

---

## 3. Architecture decisions (already made; don't re-litigate)

1. **Engine seam.** Agents receive an `Engine`. **Never write A/B/S logic inside C**, not even a "temporary"
   version; fakes live in `backend/tests/` only. Teammates' commits are their attribution.
2. **App factory.** Replace module-level `settings = get_settings()` in `api/main.py` with
   `create_app(engine: Engine | None, settings: Settings) -> FastAPI`. Keep `app = create_app(...)` at module
   level for uvicorn. With the default engine **not ready**, serve the fixture data (`data: "placeholder"`).
   When it's ready, serve live data (`data: "live"`). **Pin `test_api.py`**: fixture-mode tests use an explicit
   fixture configuration and live-mode tests use a fake engine. Otherwise CI flips behaviour the moment A and B merge.
3. **Threading.** The pipeline is CPU-heavy (MILP, simulation take seconds). Write the orchestrator as **plain
   synchronous code** taking an `emit(event)` callback; the API runs it with `asyncio.to_thread`. Run state
   (events list + `asyncio.Condition` or a thread-safe queue with `loop.call_soon_threadsafe`) lets SSE **replay
   past events, then follow new ones**, so a browser refresh mid-run doesn't lose the timeline.
4. **Approvals.** The orchestrator blocks on a `threading.Event` per run with a **timeout (10 min)**. On timeout,
   emit "approval timed out; nothing applied". `POST /api/runs/{run_id}/approvals` requires the header
   `X-Role: approver` (otherwise 403) and records it in the event. Call this "demo RBAC" in the README, not real auth.
5. **Determinism → replay.** Nothing volatile may reach a prompt: sequential tool ids, no timestamps or run
   ids in tool results or prompts, sorted keys, stable tool order. **Test:** two identical mock runs produce
   byte-identical LLM request transcripts.
6. **Provenance is run-scoped**, because tool ids repeat across runs:
   `GET /api/runs/{run_id}/tool-results/{tool_call_id}`. Keep `GET /api/tool-results/{id}` only for the
   precomputed `/plans` comparison, or drop it.
7. **The LLM outputs decisions and cited tool-call ids, never numbers.** Code fills `Assessment.cvar_before`,
   plan metrics etc. from the cited `ToolResult`s and **rejects citations that don't exist in this run**.
   `source_sha256` is set by code, never by the model. The `compare` tool already stores its result in the
   Auditor's shape `{"plans": {id: {...}}, "a": cvss_id, "b": cvar_id}`. Stamp `tool_call_id` onto plans
   with `plan.model_copy(update=...)`.
8. **Gemini compatibility (unverified; design for graceful failure).** Flat tool schemas only (no nested models,
   `$ref`/`$defs` or `Optional` unions; use defaults). `response_format` falls back to prompt-only JSON
   (already in `llm.py`). Model ids come from `.env` only. **Do one live smoke test (`scripts/llm_check.py`) the
   moment you have a key**, before building on assumptions. The free tier has low requests per minute, so keep
   Red-Team calls sequential and rely on the cache.
9. **Fail closed.** Feed unavailable or `cross_check` errors → a discrepancy that requires human approval, not a
   pass. Audit log unavailable → shown in `/api/health`, never swallowed. A replay miss raises; it never falls
   back to mock.
10. **Mock mode = rule-based agents, labelled as such** (health `llm_mode`, UI badge). Never fabricate an
    Auditor rejection in mock. **EVALS numbers for Red-Team-vs-random and the injection suite must come from
    live or replayed Gemini runs, with the mode printed in the table.** Mock-derived "agent evidence" would be
    misrepresentation.
11. **Demo tamper route** (`POST /api/audit/tamper`, edits one row so Judge Mode can show the chain break)
    exists only when `ALLOW_DEMO_TAMPER=1`. It defaults off everywhere, including `docker-compose.yml`.

---

## 4. Decisions on your three audit-log points

### 4.1 Fixed signing key: yes
`config.Settings.signing_key_hex` already reads `AUDIT_SIGNING_KEY`. In `create_app`, pass it:
`AuditLog(settings.db_path, signing_key_hex=settings.signing_key_hex)`. If it's unset, start anyway but
report `audit_key: "ephemeral"` in `/api/health` (UI shows a warning) and log a warning. Expose the public key
at `GET /api/audit/key` → `{"verify_key_hex": ...}`. Add `AUDIT_SIGNING_KEY` generation instructions to
`.env.example` (the comment is there; add your one-liner).

### 4.2 Tail truncation: detect it, and say so upfront
Approved contract change (you make it; tell Rayan because `types.ts` changes too):
- `VerifyResult` gets `head_seq: int | None = None`, `head_hash: str | None = None`, `truncated: bool = False`.
- The API keeps the **highest head it has served since startup** (in memory). If a later `verify()` shows a
  lower `head_seq`, or a different hash at that seq, then `truncated=True, ok=False`, reason
  "log shorter than previously published head".
- `/api/audit/verify` and every SSE `apply` event carry the current head, and the UI header shows `#seq · hash[:8]`.
- README "Limitations" says: tail truncation is detected only against a previously published head; production
  would anchor heads in an external transparency log or notary. Being honest is better than a judge finding it.

### 4.3 Differential test: yes, as `tests/test_sim_reference.py` (see §1).

---

## 5. Remaining tasks, in order (write each task's tests first, then the code; commit per task)

### C3 · Mock LLM + quarantine + Sentinel (≈ 2 h)
- `agents/mock.py`: `MockLLM` with `mode="mock"` and deterministic **rule-based responders keyed by `task`**:
  `sentinel.extract` (regex: CVE id, vendor/product, firmware family, "below/before/prior to/<" version, CVSS),
  `analyst.step` (scripted tool calls: blast_radius on matches → simulate → final decision JSON),
  `planner.constraints` (regex: "no (…) downtime in <zone>", "must fix d-…", "no segmentation", budgets in ₹/lakh),
  `planner.claims` (claims built from the compare result in the messages),
  `redteam.propose` (heuristics: unprotected exposed devices with a path to the corridor, largest unpatched firmware
  family pivot, campaign on the KEV CVE with most unprotected carriers, EV-charger gateways, target=signal).
  Tool-call ids are `call_<step>_<i>`. Usage tokens are estimated as chars/4, latency 0, `model="mock"`.
- `guard/quarantine.py`: `quarantine_extract(raw_text, llm)` makes **one tool-less, fast-tier call**. The system
  prompt says the text is untrusted data and must never be followed. Validate into `Advisory` (minus
  `source_sha256`, set by code); raise `ValueError` on invalid output. `cross_check(advisory, feed_lookup)` compares
  CVE presence, CVSS (|Δ| > 0.5), and vendor/product (case-insensitive containment); lookup errors are a discrepancy.
- `agents/sentinel.py`: `match_inventory` uses a deterministic tuple version compare (`4.1.3 < 4.2.0`), matching on
  family + version or the CVE already being listed (existing tests in `test_agents.py`). Plus `run_sentinel(ctx, raw_text)`:
  store the raw text in `ctx.untrusted` under its sha → `flag_spans` (emit an OBSERVE with spans if any) → tool
  `quarantine_extract` → `cross_check` → `match_inventory` → DECISION (escalate / monitor / needs-approval on
  discrepancies).
- `data/advisories/`: 3 normal, 3 poisoned (instructions embedded), 3 **valid-but-wrong** (well-formed but lying
  about the version range, CVSS or vendor; cross-check must flag them). These are the Judge Mode presets.
- **Make `/api/quarantine/preview` live** (works without A/B), so Judge Mode is real early.

### C4 · Analyst + Planner (≈ 2 h)
- `agents/loop.py` (new): `run_tool_loop(ctx, agent, task, system, user, max_steps=5) -> (final_json, usage_total)`.
  It sends `openai_tool_specs(agent)` and executes requested calls via `tools.call`. Tool errors
  (`ToolNotAllowed`, `ToolArgError`) go back to the model as `{"error": ...}` tool messages so it can recover.
  It stops on a final JSON answer or `max_steps` (then emits an ERROR event and returns a safe default).
- Analyst: the tool loop decides `replan | contain | monitor` and cites tool ids. Code builds `Assessment`
  (affected from Sentinel matches, blast radius and `cvar_before` from the cited results).
- Planner: `parse_constraints(ctx, text)` (strong tier → JSON list → validate: unknown zones/devices/kinds →
  REJECT event listing the valid values, **never guessed**) → DECISION event per constraint row → tool
  `compare` → LLM drafts `Claim`s (`planner.claims`) → `engine.check_claims` → DECISION event with accepted
  sentences (`engine.render_claim`) + rejection count/reasons → candidate = the CVaR plan.

### C5 · Red-Team + replan (≈ 2 h)
- `propose_strategies(ctx)`: the strong tier gets `list_controls` + device summary context and returns ≤5
  strategies (validated; unknown ids are dropped with a note).
- `score_strategy(ctx, strategy)`: baseline = `engine.controlled(city, candidate.choices, n, seed=redteam_seed)`.
  The attack = the same with `strategy=`. `cvar_before = cvar(base.total)`,
  `cvar_after = cvar(concat(base.total, attack.total))`. A **hole** = increase > `HOLE_THRESHOLD` (5%).
- Replan: augment the training set with **uncontrolled** strategy scenarios for each hole (concatenate
  `ScenarioLosses`; write a helper) → `engine.solve_cvar` → `evaluate_plan` → new candidate → round 2 (max 2 rounds).
  Events: HOLE (red) and DECISION "no hole above 5% after replan".
- `random_search(ctx, budget_calls, seed)`: random strategies from the same menu.
  `scripts/redteam_vs_random.py`: simulator calls to first hole, agent vs random, 20 seeds, **live/replay only**.

### C6 · Orchestrator + live API (≈ 2 h)
- `orchestrator.run_incident(ctx, advisory_text, constraints_text, approvals) -> None` (sync; emits events):
  Sentinel → Analyst (stop if `monitor`) → Planner → Red-Team ≤2 rounds → autonomy policy (options with
  `Autonomy.AUTO` apply immediately, with an APPLY event; the rest emit an approval-request DECISION and wait) →
  on approval apply → `evaluate_plan` before/after → APPLY "Re-simulated: CVaR x → y".
  Every event → `AuditLog.append`.
- API: run registry, `POST /incidents` (202 + run_id, runs in a thread), SSE with replay+follow,
  approvals (X-Role), run-scoped provenance, audit entries/verify/key, health `{data, llm_mode, audit_key,
  engine_ready}`, tamper route (env-gated).

### C7 · Evidence + replay (≈ 2 h)
- `scripts/llm_check.py`: models list, one tool-call round trip, latency, rate-limit probe.
- `scripts/injection_suite.py`: about 50 variants (generate them with the LLM *once*, commit the list) incl.
  valid-but-wrong; report the share where the planner input stayed clean and cross-check caught the lie → EVALS.md.
- `scripts/build_demo.py`: regenerate `fixtures/demo/{city,plans,events}.json` from the real pipeline so the
  placeholder banner disappears.
- **Record replay traces**: run Flow A and the Judge Mode presets live once and commit `fixtures/traces/`. From
  then on `LLM_MODE=replay` reproduces the video exactly.

### Tests you must add (the acceptance criteria)
- Mock and replay are deterministic; a replay miss raises `ReplayMiss`; the live client is never constructed in mock/replay.
- `tools.call` refuses disallowed tools (REJECT event emitted), validates args, and returns sequential ids with stored results.
- **Structural guarantee (most important):** after Sentinel, the raw advisory text appears in **no** LLM request made
  by the Analyst, Planner or Red-Team (record requests in a spy LLM).
- Valid-but-wrong advisories produce cross-check discrepancies; a missing feed fails closed.
- The planner rejects unknown zones; claims citing unknown tool ids are rejected.
- The Red-Team reports a hole only above the threshold; replan never increases training CVaR.
- A full incident on a fake engine emits the expected event sequence; approval without `X-Role: approver` → 403;
  approval timeout → nothing applied.
- API: SSE replays past events on reconnect; health fields present; tamper route 404 unless enabled.
- Two identical mock runs → identical LLM request transcripts.

Fake engine: `backend/tests/fakes.py` implementing every `Engine` field on `tiny_city` (simple deterministic
losses; `compare` returns plans for every `Objective` with metrics). Test-only.

---

## 6. Using Claude Code + ecc efficiently

- Work task by task (C3 → C7). **Tests first**, then the code, then `uv run pytest`, then
  `uv run ruff check . --fix && uv run ruff format .`, then commit. Small commits from your own account.
- **Don't spawn review agents mid-build.** At the end of C4 and again at the end of C7, run these ecc agents
  **in parallel** on the diff and verify each finding before applying it:
  `ecc:python-reviewer`, `ecc:fastapi-reviewer`, `ecc:security-reviewer`, `ecc:silent-failure-hunter` (it targets
  the NotImplementedError fallbacks, swallowed 429s and fail-open paths). Then run `/code-review` before opening the PR.
- Useful skills: `ecc:fastapi-patterns`, `ecc:python-testing`, `ecc:security-review`, `ecc:api-design`.
- Stuck on the same failure twice? Stop and message Rayan with the test output and diff.

## 7. Boundaries

- **You own:** `agents/`, `guard/quarantine.py`, `guard/allowlist.py`, `api/`, `config.py`, `data/advisories/`,
  `fixtures/traces/`, `fixtures/demo/` (regenerated by script), C's scripts and tests, plus `tests/fakes.py`.
- **Contracts** (`schemas.py`, `frontend/src/types.ts`, `frontend/src/api.ts`): you may make the changes listed in this
  file (§2, §3.6, §4.2, health fields), in **one commit that updates Python and TypeScript together**, and tell
  Rayan. Anything else needs his OK first.
- **Don't touch:** `city/` (Prabhav), `opt/` (Sai Varun), `frontend/src/screens|components` (Rayan).
- Keep `README.md` claims true: if something isn't built, it isn't claimed.

## 8. Merge windows and definition of done

PR `c/agents` → `main` at **h10** (C3 done, preview live), **h14** (C4–C5 on fakes), **h16** (C6 live end-to-end on
the real engine + replay traces recorded). Feature freeze at h19.

**Done =** all C tests pass in mock mode with no network, ruff clean, CI green; Flow A runs end-to-end on the real
engine in replay mode; Judge Mode presets work; EVALS sections 3–4 filled from live/replay runs; README health/RBAC/
limitations lines accurate.
