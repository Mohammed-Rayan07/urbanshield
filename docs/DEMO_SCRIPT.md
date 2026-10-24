# Demo video: shot list (target 2:45, 1280×720, `LLM_MODE=replay`)

Every feature is built to be filmed. Record the voice-over separately if the room is noisy.

| # | Time | Screen | On screen | Voice-over (say roughly this) |
|---|---|---|---|---|
| 1 | 0:00–0:15 | Title card | "UrbanShield — where does the city's next rupee go?" | Cities patch by CVSS. They fear the bad year, when one shared firmware bug takes down many devices at once. |
| 2 | 0:15–0:35 | City | Map of Mangaluru; hover the lumenos streetlight family, the EV gateway, the NH-66 ambulance corridor | 50 devices on real streets. These twelve streetlights share firmware, one hop from the ambulance corridor signals. |
| 3 | 0:35–0:55 | Plans | CVSS-first vs BFS-only vs UrbanShield; headline −X% | Same ₹6 lakh budget. CVSS-first buys the critical-scored decorative lights. UrbanShield cuts worst-case loss by X%, measured on scenarios it never saw. |
| 4 | 0:55–1:45 | Agents | Inject advisory → Sentinel matches 12 → Analyst blast radius → operator types the festival constraint → Planner plan → **Red-Team finds a hole via the EV gateway** → replan → credential rotations auto-apply → approver signs segmentation → re-simulated drop | This is why it's agents and not just BFS: they read the advisory, turn the operator's words into constraints, and attack their own plan until it holds. |
| 5 | 1:45–2:05 | Provenance | Click the −X% → drawer with the tool call | No number comes from the language model. Click any number to see the tool call behind it. |
| 6 | 2:05–2:30 | Judge Mode | Paste a poisoned advisory → right side shows only typed fields; edit one audit row → Verify chain turns red at that entry | Whatever you paste, this is all the planner can see. And if anyone edits the log, the chain breaks exactly there. |
| 7 | 2:30–2:45 | Bench + close | Scalability chart; repo link | Runs from 50 to 5,000 devices; MILP hands off to a greedy solver at scale. Simulated city only, no real systems touched. |

Rough cut at h16, final at h20–h22. Keep the raw recordings.
