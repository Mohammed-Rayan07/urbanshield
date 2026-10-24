# Manual D — Dashboard and demo video

**Owner:** Rayan · **Branch:** `d/frontend` · **Checks:** `npm run lint` and `npm run build` clean; the screens work against the running API.

## Why this part matters

Judges will mostly see UrbanShield **through the demo video**, so the dashboard is the product. It must
be minimal, calm and obviously trustworthy: three screens, one idea each, every number clickable to
see where it came from.

## You own

```
frontend/src/screens/      CityScreen.tsx, PlansScreen.tsx, AgentsScreen.tsx
frontend/src/components/   anything you need (new files)
frontend/src/App.tsx       layout only
frontend/src/index.css     only to add tokens/fonts
frontend/index.html, frontend/public/
docs/DEMO_SCRIPT.md, docs/screenshots/
```

**Never touch:** `frontend/src/types.ts` (contract), `frontend/src/api.ts` (ask Rayan for new calls),
anything in `backend/` except through the C manual.

## Run it

```powershell
# terminal 1 — API (serves realistic placeholder data right now)
cd backend; uv sync; uv run uvicorn urbanshield.api.main:app --reload --port 8000
# terminal 2 — dashboard
cd frontend; npm ci; npm run dev     # open http://localhost:5173
```

All endpoints you need already exist (`src/api.ts`): `city`, `plans`, `startIncident` + `useRunEvents`
(live SSE), `approve`, `toolResult` (provenance), `quarantinePreview`, `auditEntries`, `verifyAudit`.
They return placeholder data until the backend lands (a yellow **PLACEHOLDER DATA** banner shows while
`/api/health` says `data: placeholder`); **the shapes will not change**.

## Design rules (as built)

> **Status:** built by the integrator from three reference layouts (Overview, Risk Intelligence,
> Response & Mitigation) plus Devices, Judge Mode and Audit Log. The rules below describe the result.

- Light municipal-console theme. Tokens live in the `@theme` block of `src/index.css` (`forest-*`,
  `canvas`, `surface`, `line`, `ink`, `muted`, `danger`, `high`, `warn`, `ok`, `info`); SVG code uses the
  same values from `src/lib/colors.ts`. Forest green means UrbanShield; red/orange/amber/green mean risk
  and nothing else. Device category is encoded by marker shape, never by colour. No decorative gradients.
- DM Serif Display for page titles, Inter for UI and numbers (tabular figures), JetBrains Mono for IDs
  and hashes. All three are self-hosted through `@fontsource`, so the demo works offline.
- Motion explains something (counting KPIs, staggered entrance, ripples on alert carriers, flowing
  attack paths, the hold-to-approve fill, the audit chain sweep/break) and respects `prefers-reduced-motion`.
- Basemap: Esri Light Gray Canvas / World Imagery (CARTO tiles now require an API key).
- Numbers: ₹ with Indian grouping (`toLocaleString('en-IN')`), losses to 1 decimal, percentages with sign.
- Every metric on screen is a `<Metric>` component: click → **provenance drawer** showing the tool call
  (`api.toolResult(tool_call_id)`): tool, agent, args, result JSON, timestamp.
- Loading, empty and error states for every fetch. Keyboard focus visible. Works at 1280×720 (video size).

---

## Tasks (in order)

### D1 · Shell and components (target: h3)
Fonts, header with the three tabs (exists), `components/`: `Metric` (value + label + optional CI,
clickable), `Panel`, `Badge` (category / solver / autonomy), `ProvenanceDrawer` (right-side slide-over).
**Done when:** build + lint clean, drawer opens with placeholder tool results.

### D2 · City screen — the map (target: h7)
`react-leaflet` map centred on (12.94, 74.82), zoom 12. Dark tiles:
`https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png` with attribution
`© OpenStreetMap contributors © CARTO`.
- Devices as `CircleMarker`: colour by category, radius 4–10 by criticality, red ring if `exposed`.
- REACH edges as thin dashed polylines; DEPENDS as solid; toggle each in a small legend.
- Ambulance corridor (`tags` contains `ambulance_corridor`): thicker accent line through those signals.
- Click a device → side panel: name, category, zone, firmware, CVEs (CVSS, EPSS, KEV badge), control
  options table (cost, downtime, autonomy).
- Highlight devices touched by the latest run in red (later from events; for now: a prop).
**Done when:** looks good at 1280×720.

### D3 · Plans screen (target: h10)
- Top: one sentence + big number: "Same ₹ budget: worst-case loss **−X%** vs CVSS-first" (CI in small text).
- Three cards side by side: **CVSS-first · BFS-only · UrbanShield (CVaR)** — CVaR, mean loss, max cascade,
  cost, downtime, solver badge, solve time. All `Metric`s.
- Recharts horizontal bar chart: CVaR (test set) for every plan with CI whiskers; UrbanShield in accent,
  others in muted grey.
- "What changed" chips: devices where UrbanShield's choice differs from CVSS-first (device name + control).
- Collapsible full table of all 8 plans.
**Done when:** looks good at 1280×720.

### D4 · Agents screen — the live loop (target: h14)
- Left: timeline from `useRunEvents`. Each row: time, agent badge (own colour per agent), summary,
  token/latency chip from `usage`, tool-call rows collapsible, `hole` rows red, `apply` rows green.
- Right column: **Auditor** counter (accepted / rejected, rejection rate), **Approval** card for
  pending approvals (Approve / Reject → `api.approve`), **Audit log** list with a **Verify chain** button
  (`api.verifyAudit`) that shows ✓ green or ✗ red with `first_bad_seq`.
- Top: "Inject advisory" with a dropdown of curated advisories (normal, poisoned, valid-but-wrong) and an
  optional constraint text box ("Zone 3 festival this weekend, no streetlight downtime").

### D5 · Judge Mode (target: h16)
A panel (button on the Agents screen) titled "Try to break it":
- Textarea "Paste any advisory" → `api.quarantinePreview` → two columns: *what you pasted* (with
  `flagged_spans` highlighted) and **what the planner sees** (the typed `advisory` fields only, or the
  error). Caption: "Whatever you paste, the right side is all the planning agents can ever see."
- "Tamper with the log" button explanation + Verify chain (the backend team provides the tamper action).

### D6 · Polish and video assets (target: h19)
Empty/error states, focus rings, tab order, titles; check every screen at 1280×720.
**Screenshots only now**, after Rayan regenerates the fixtures from the real pipeline (the banner must be gone):
save `docs/screenshots/{city,plans,agents}.png`. Never publish placeholder numbers.

### D7 · Demo video (h20–h22)
Follow `docs/DEMO_SCRIPT.md`. Record at 1280×720 with OBS, backend in `LLM_MODE=replay` so every run is
identical. Keep it under 3 minutes. Export MP4, upload (YouTube unlisted / Drive), put the link at the top of README.

---

## Paste-ready prompt for your agent

```text
Do task D1 from docs/manuals/D_frontend.md. Only edit files under "You own". Use the design rules
exactly (tokens from src/index.css, no new colours). Do not edit src/types.ts or src/api.ts.
When done run `npm run lint` and `npm run build` in frontend/ and show me the output.
```
Repeat D2, D3, … one at a time. After each, open http://localhost:5173 and look at it yourself.

## Definition of done
Three screens + provenance drawer + Judge Mode working against the live API; lint/build clean;
screenshots in `docs/screenshots/`; video recorded.
