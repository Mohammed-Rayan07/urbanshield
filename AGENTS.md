# Rules for coding agents working in this repo

You are helping one member of Team Merge Conflict build **one part** of UrbanShield during a 24-hour
hackathon. Read these rules first, then the manual for your part in `docs/manuals/`.

## Hard rules

1. **Stay in your lane.** Only create or edit files listed under "You own" in your manual.
2. **Never edit the contracts:** `backend/src/urbanshield/schemas.py` and `frontend/src/types.ts`.
   If a contract looks wrong or missing, stop and tell your human to ask the integrator (Rayan).
3. **Tests are the acceptance criteria.** Your module is done when its tests in `backend/tests/` pass
   (they currently skip with "not implemented yet"). Do not weaken, delete or skip a test to make it pass.
4. **Keep signatures.** Implement the stubs exactly as declared (names, parameters, return types).
   You may add private helpers (`_name`) and new private modules inside your own folders.
5. **No new dependencies** without the integrator's OK. Allowed backend libs: numpy, scipy, networkx,
   pulp, pydantic, pynacl, fastapi, openai. Frontend: react, leaflet, react-leaflet, recharts, tailwind.
6. **No secrets.** Never write API keys or tokens into files. Never commit `.env`.
7. **Deterministic.** Same inputs and seed must give identical outputs. Use `numpy.random.default_rng(seed)`
   or `random.Random(seed)`, never global random state.
8. **Simulation only.** No network scanning, no exploit code, no calls to real devices.

## Commands (run from the folder shown)

| Where | Command | What |
|---|---|---|
| `backend/` | `uv sync` | install |
| `backend/` | `uv run pytest` | all tests (`-k sim` to filter) |
| `backend/` | `uv run ruff check . --fix && uv run ruff format .` | lint + format (must be clean) |
| `backend/` | `uv run uvicorn urbanshield.api.main:app --reload --port 8000` | API |
| `frontend/` | `npm ci` / `npm run dev` / `npm run lint` / `npm run build` | install / dev server / lint / type-check + build |

## Code style

- Python 3.12, type hints everywhere, docstrings on public functions, max line 110 (ruff enforces).
- Vectorise with NumPy; no Python loop over scenarios.
- Small pure functions. No print debugging left behind. No commented-out code.
- Frontend: function components, Tailwind classes using the tokens in `src/index.css`, all network
  calls through `src/api.ts`.

## Git

Work on your branch (`a/city`, `b/optimizer`, `s/sim-audit`, `c/agents`, `d/frontend`). Commit small and often with
clear messages (`sim: vectorise campaign scenarios`). Push your branch and open a PR to `main`. CI must be green.
