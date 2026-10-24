FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY . .
RUN uv sync --locked --no-dev
RUN useradd --create-home app && chown -R app /app
USER app
EXPOSE 8000
CMD ["uv", "run", "--no-dev", "uvicorn", "urbanshield.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
