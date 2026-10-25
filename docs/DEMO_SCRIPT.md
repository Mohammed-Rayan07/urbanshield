# Demo video: script and shot list (target 2:50, 1920×1080 or 1280×720)

Record from a **fresh backend**: the Enforcer starts at policy v0 with the corridor "open". Use a browser at 100%
zoom, full screen (F11). Record the voice-over separately if the room is noisy, then lay it over the screen
capture. Every number below is on screen when you say it — never say a number that isn't.

**Setup before each take**

1. Fresh audit log: delete `backend/urbanshield.db`. Two reasons: the tamper step in shot 8 breaks the chain on
   purpose, and without `AUDIT_SIGNING_KEY` in `.env` the server signs with a new key on every start, so a log
   from an earlier start shows "bad signature" at entry 0.
2. Start the backend with Judge Mode tampering on:
   `cd backend && ALLOW_DEMO_TAMPER=1 uv run uvicorn urbanshield.api.main:app --port 8000`
   (PowerShell: `$env:ALLOW_DEMO_TAMPER=1; uv run uvicorn urbanshield.api.main:app --port 8000`).
3. `cd frontend && npm run dev`, open `http://localhost:5173/#/overview` once and wait for both maps to load
   (warms the caches), then go to `#/story`.

---

## Part 1 — Story Mode (`#/story`, arrow keys), 0:00–1:55

| # | Time | Screen | Do | Say (roughly) |
|---|---|---|---|---|
| 1 | 0:00–0:20 | **Problem** | Nothing; let the four number cards sit | "Cities are wiring up traffic signals, meters and EV chargers faster than they can secure them. A scanner gives them a list sorted by CVSS. It never says *which ten to fix with the money they have* — and it never fixes anything. Cities don't fear the average year. They fear the bad year." |
| 2 | 0:20–0:55 | **Two cities** | → . Let the replay play; point at the corridor box turning red on the left | "Same attack, two cities. One of the worst attacks from our held-out set, with identical random draws — only the plan differs, same ₹1.5 lakh budget. Left: patched by CVSS score. It loses 23 devices and an ambulance-corridor signal. Right: UrbanShield loses one, and the corridor stays clear. And it's not a cherry-pick — the line below averages all of the worst 5%." |
| 3 | 0:55–1:25 | **Mitigate** | → . Click **Run attack** | "But a plan on paper doesn't stop anyone. So UrbanShield enforces it. This attacker holds *valid stolen credentials* and fires a kill chain at an ambulance-corridor signal: freeze it red, force conflicting greens, blind it on flash. Every command is judged at our Enforcer in microseconds — three of three blocked, each written to a signed audit log. The interlock judges the *command*, not the login." |
| 4 | 1:25–1:45 | **Proof** | → . Drag the budget slider from ₹1.5 L to ₹6 L and back | "Measured on two thousand attacks the planner never saw: sixty-three percent lower worst case than CVSS-first. A quarter of the money, half the worst case — at ₹1.5 lakh we beat CVSS-first given ₹6 lakh. It holds in five of five perturbed cities." |
| 5 | 1:45–1:55 | **Trust** | → | "And the AI proposes; deterministic code decides. Advisories are quarantined, every claim is checked against a tool result, and every action is signed." |

## Part 2 — The closed loop, live (`#/response`), 1:55–2:35

| # | Time | Do | Say (roughly) |
|---|---|---|---|
| 6 | 1:55–2:10 | Esc out of Story Mode → **Response & Mitigation**. Pick the normal *lumenos* advisory preset and run it. Let Sentinel → Analyst → Planner → Red-Team stream | "Here's the whole loop on a new advisory. Sentinel matches the affected firmware, the Analyst finds the path to the corridor, the Planner picks the budget-optimal fix, and the Red-Team attacks that plan before we trust it." |
| 7 | 2:10–2:35 | **Hold to approve**. Point at *"Enforced signed policy v1 … corridor paths open → closed"*, then the re-simulated CVaR drop | "Low-risk fixes apply automatically; anything with downtime needs a human. Once approved, the plan is compiled into signed policy and pushed to a deny-by-default gateway — and it checks itself: the attack path to the corridor goes from *open* to *closed*. Then it re-simulates to prove the risk actually dropped." |

## Part 3 — Trust, then close, 2:35–2:50

| # | Time | Do | Say (roughly) |
|---|---|---|---|
| 8 | 2:35–2:45 | **Judge Mode**: load the *poisoned* preset; then tamper one audit row and click **Verify** | "Paste a poisoned advisory: only six typed, cross-checked fields ever reach the planner. Edit one row of the audit log, and verification breaks at exactly that entry." |
| 9 | 2:45–2:50 | Back to Overview | "UrbanShield: a control plane for city infrastructure, not a dashboard. Simulated city only — no real systems touched." |

---

### If something goes wrong while recording

- Maps blank on first load → the backend is still computing the replay (a few seconds on a cold start); reload.
- Attack console says a command "could not reach the Enforcer" → the backend is down; restart it and re-run.
- The live incident is the only step that waits on the agents; if it stalls, keep the Story Mode take and cut.
- Verify already red before shot 8 → you reused a tampered database; stop, delete `backend/urbanshield.db`, restart.

### Words to avoid

"Nothing like this exists", "real exploit", "production-ready", and any ambulance delay in minutes (we don't model
it). Say "simulated city" at least once.
