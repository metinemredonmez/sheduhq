# services/ai

Shedu AI servisi — Python, FastAPI. Yalnızca iç ağdan, Rust API'si tarafından çağrılır.

```bash
uv sync
uv run pytest
uv run ruff check
uv run uvicorn shedu_ai.main:app --host 127.0.0.1 --port 8090
```

Kurallar için [`src/shedu_ai/main.py`](src/shedu_ai/main.py) ve [docs/mimari.md](../../docs/mimari.md).
