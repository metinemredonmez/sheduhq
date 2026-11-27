# services/ai

Shedu AI servisi — Python, FastAPI. Yalnızca iç ağdan, Rust API'si tarafından çağrılır.
Veritabanına erişmez; API o isteğe ait azaltılmış veriyi gönderir.

```bash
uv sync
uv run pytest
uv run ruff check
uv run uvicorn shedu_ai.main:app --host 127.0.0.1 --port 8090
```

Uç nokta: `POST /v1/summaries/events` (olay özeti), `Authorization: Bearer <SHEDU_AI_TOKEN>`.
Başarılı yanıt özet metnini ve harcamayı (`model`, token'lar, `cost_microusd`) içerir. Hata
yanıtı `{"detail": "ai_refused" | "ai_unavailable", "usage": …}` biçimindedir; model yanıt
verdiyse harcama `usage` içindedir ve API onu maliyet defterine yazar.

| Değişken | Anlamı |
|---|---|
| `SHEDU_AI_TOKEN` | API ile paylaşılan servis token'ı (en az 32 karakter). Yoksa servis her isteğe 503 döner. |
| `SHEDU_AI_MODEL` | Varsayılan `claude-opus-5-5`. Fiyatı `pricing.py`'de olmayan modelle servis başlamaz. |
| `ANTHROPIC_API_KEY` | Model sağlayıcısının anahtarı (Anthropic SDK'sının standart değişkeni). |

API tarafı: `SHEDU_AI_URL` (loopback dışında yalnızca HTTPS), `SHEDU_AI_TOKEN`,
`SHEDU_AI_DAILY_BUDGET_USD` (varsayılan 20). Kurallar için
[`src/shedu_ai/main.py`](src/shedu_ai/main.py), [`src/shedu_ai/summary.py`](src/shedu_ai/summary.py)
ve [docs/mimari.md](../../docs/mimari.md#ai-olay-özeti).
