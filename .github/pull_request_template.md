## What

<!-- One or two sentences. Which manual task(s) does this complete? e.g. "A3: campaign scenarios" -->

## Checklist

- [ ] Only touches paths I own (see my manual in `docs/manuals/`)
- [ ] Did not edit `backend/src/urbanshield/schemas.py` or `frontend/src/types.ts`
- [ ] `uv run pytest` passes locally; tests for my module are no longer skipped
- [ ] `uv run ruff check . && uv run ruff format --check .` clean (backend) / `npm run lint && npm run build` clean (frontend)
- [ ] No secrets, keys or `.env` committed
