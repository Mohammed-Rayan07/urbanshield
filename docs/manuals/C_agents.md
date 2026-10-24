# Manual C — Agents, guardrails, API (Rayan, integrator)

**Owner:** Rayan · **Branch:** `c/agents` · **Tests:** `tests/test_agents.py`, `tests/test_api.py`, guard tests for quarantine/allowlist, plus new agent tests you add.

## You own

```
backend/src/urbanshield/agents/      llm.py, tools.py, sentinel.py, analyst.py, planner.py, redteam.py, orchestrator.py
backend/src/urbanshield/guard/       quarantine.py, allowlist.py
backend/src/urbanshield/api/         main.py, fixtures.py (+ store/run registry)
backend/src/urbanshield/schemas.py   (contract owner)
frontend/src/types.ts, frontend/src/api.ts   (contract owner)
backend/data/advisories/             curated advisories incl. poisoned + valid-but-wrong
backend/fixtures/traces/             recorded LLM traces for replay
backend/scripts/llm_check.py, scripts/build_demo.py, scripts/injection_suite.py, scripts/redteam_vs_random.py
```

## Runtime LLM

OmniRush gives the team coding-agent tokens; it is **not** the app's runtime API. The app's agents use
`agents/llm.py` against **any OpenAI-compatible Chat Completions endpoint with function calling**
(`LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL_FAST`, `LLM_MODEL_STRONG`). Everything also works in `mock`
(CI, no key) and `replay` (video, offline venue). Live recording uses the **Gemini free tier** via its OpenAI-compatible endpoint
(`LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/`). The free tier has low
requests-per-minute limits: run Red-Team proposals sequentially, rely on the response cache, and record
replay traces as soon as Flow A works.

## Tasks

### C1 · LLM adapter (h0–h3)
`agents/llm.py`: `openai.OpenAI(base_url=…, api_key=…)`, `chat.completions.create` with `tools` and
`response_format={"type":"json_object"}` when `response_schema` is given; on-disk cache keyed by
SHA-256 of canonical request JSON → `fixtures/traces/<hash>.json`; `replay` = cache only; `mock` =
scripted responses keyed by a `mock_key` in the first system message. Returns `LLMUsage`.
`scripts/llm_check.py`: list models, one tool-call round trip, latency, burst of 5 parallel calls.

### C2 · Tool registry + allowlist enforcement (h3–h5)
`agents/tools.py`: registry of `name → (ArgsModel, fn)`; `call()` = authorize → validate → run →
store `ToolResult` (in-memory dict + SQLite) → emit TOOL_CALL event. Tools wrap A's, S's and B's functions
(use fixtures/mocks until they merge).

### C3 · Quarantine + Sentinel (h5–h8)
`quarantine_extract` (fast tier, **no tools**, JSON-only, validated into `Advisory`), `cross_check`
against `feeds.feed_record` (A), `sentinel.match_inventory` (deterministic version compare; parse
`4.1.3` into tuples). Curate `data/advisories/`: 3 normal, 3 poisoned, 3 valid-but-wrong.

### C4 · Analyst + Planner (h8–h11)
Analyst: tool loop (≤6 steps) over bfs_reach / blast_radius / simulate → `Assessment` citing tool-call
IDs. Planner: `parse_constraints` (strong tier → `Constraint[]`, reject unknown zones/devices) → `optimize`
/ `compare` (B) → Claims → Auditor (S).

### C5 · Red-Team (h11–h14)
Strategy menu = entry points × target category × firmware pivot × campaign CVE. Strong tier proposes ≤5
with reasons; `probe` scores each (hole if CVaR rises >5% when its scenarios are added); Planner re-solves on
the augmented set; ≤2 rounds. `scripts/redteam_vs_random.py`: sim calls to first hole, agent vs random,
20 seeds → numbers for EVALS.md.

### C6 · Orchestrator + live API (h12–h16)
`run_incident` async generator; run registry `run_id → asyncio.Queue`; SSE route streams the queue;
autonomy policy (AUTO controls applied immediately with an APPLY event; others wait for
`/approvals`); after approval: apply → `evaluate_plan` → APPLY event with before/after. Every event →
audit log (S). Replace fixture-backed routes with live ones; keep response shapes.

### C7 · Evidence (h16–h19)
`scripts/injection_suite.py` (≈50 variants incl. valid-but-wrong → pass rate), record replay traces for the
video, `scripts/build_demo.py` to regenerate `fixtures/demo/*` from the real pipeline.

## Merge windows
h6, h10, h14, h16 — review PRs with the checklist in [INTEGRATOR.md](INTEGRATOR.md).
