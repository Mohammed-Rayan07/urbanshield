.PHONY: setup api web test lint fixtures demo

setup:        ## install backend + frontend dependencies
	cd backend && uv sync
	cd frontend && npm ci

api:          ## run the API on :8000 (auto-reload)
	cd backend && uv run uvicorn urbanshield.api.main:app --reload --port 8000

web:          ## run the dashboard on :5173 (proxies /api to :8000)
	cd frontend && npm run dev

test:         ## backend tests
	cd backend && uv run pytest

lint:         ## all linters and format checks
	cd backend && uv run ruff check . && uv run ruff format --check .
	cd frontend && npm run lint && npm run build

fixtures:     ## regenerate placeholder demo fixtures
	cd backend && uv run python scripts/make_placeholder_fixtures.py

demo:         ## full stack in Docker, offline replay mode -> http://localhost:8080
	docker compose up --build
