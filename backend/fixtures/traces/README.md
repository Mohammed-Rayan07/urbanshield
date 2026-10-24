# Recorded LLM traces (replay mode)

Each file is one recorded response, named by the SHA-256 of the canonical request
(model, messages, tools, JSON mode). `LLM_MODE=live` writes them; `LLM_MODE=replay` serves only
these files and raises `ReplayMiss` for anything else (it never falls back to mock).

Recording (needs a key in `.env`, see `.env.example`):

1. `uv run python scripts/llm_check.py`, so the endpoint, models and tool schemas are confirmed first.
2. With `LLM_MODE=live`, run Flow A once (`scripts/build_demo.py`, or the dashboard) and each Judge Mode
   preset through the quarantine preview, then the evidence scripts.
3. Commit the new `*.json` files here. From then on `LLM_MODE=replay` reproduces the video exactly.

Keep `LLM_MODEL_FAST` / `LLM_MODEL_STRONG` unchanged between recording and replay: the model id is part
of the key. Traces hold model output only, never the API key.
