# services/ai

Shedu AI servisi — Python, FastAPI. Yalnızca iç ağdan, Rust API'si tarafından çağrılır.
Veritabanına erişmez; API o isteğe ait azaltılmış veriyi gönderir.

```bash
uv sync
uv run pytest
uv run ruff check
uv run uvicorn shedu_ai.main:app --host 127.0.0.1 --port 8090
```

## Kapı

`/health` dışındaki her istek, gövde okunmadan önce saf ASGI kapısından geçer
([`gate.py`](src/shedu_ai/gate.py)):

1. Servis yapılandırılmamışsa (`SHEDU_AI_TOKEN` yok) 503 `not_configured`.
2. `Authorization: Bearer <SHEDU_AI_TOKEN>` sabit zamanlı karşılaştırılır; eksik, yanlış veya
   birden çok başlık 401 `unauthorized`. Bu iki yanıt gövde hiç okunmadan döner.
3. Gövde en fazla 1 MiB. `Content-Length` sınırı aşıyorsa gövde okunmadan 413
   `payload_too_large`; başlık yoksa (chunked) veya yanlışsa akış sayılır ve sınır aşılınca
   istek uygulamaya hiç iletilmeden 413 döner.

## `POST /v1/summaries/events`

İstek (bilinmeyen alan reddedilir):

| Alan | Anlamı |
|---|---|
| `panel_name` | 1–100 karakter. Kullanıcı verisi: prompt'ta veri olarak durur. |
| `time_zone` | IANA saat dilimi (ör. `Europe/Istanbul`). |
| `period_start`, `period_end` | Saat dilimli zaman. Dönem boş olamaz, en fazla 7 gün 1 saat. |
| `events` | Dönemin en yeni olayları, en fazla 500. Her `occurred_at` `[period_start, period_end]` içinde. |
| `truncated` | Liste kısaltıldı mı (varsayılan `false`). |
| `counts` | Zorunlu. Dönemdeki görünür olayların **tamamının** SQL ile hesaplanmış sayıları: `{"total", "alarms", "armed", "disarmed", "disconnected", "power_problems"}`, her biri 0–10 000 000 tam sayı. |
| `connection` | Zorunlu, `"connected"`, `"disconnected"` veya `null` (bilinmiyor). Panelin dönem sonundaki son bilinen bağlantı durumu; dönemden önceki bir olaydan da gelebilir. |

Tutarlılık kuralları (aykırı istek 422 `invalid_request`):

- `len(events) <= counts.total`; listede bir türün olay sayısı `counts`'taki sayısını aşamaz.
- Tür sayılarının toplamı (`alarms + armed + disarmed + disconnected + power_problems`) `total`'i
  aşamaz (`connected` yalnızca `total` içinde sayılır).
- `events` boşsa `counts.total` 0 olmalı.

Kesin bilgiler koddan gelir: prompt'taki `kesin_sayilar` doğrudan `counts`'tur ve model sayıları
listeden saymaz. Liste eksikse (`truncated` veya `len(events) < counts.total`) prompt bunu açıkça
söyler. `needs_attention`: `alarms > 0`, `power_problems > 0` veya
`connection == "disconnected"`. Olay yoksa model çağrılmaz (panel hâlâ kopuksa sabit metin bunu
da söyler).

Başarılı yanıt (200): `summary`, `highlights`, `needs_attention`, `stats` (`counts`'un aynısı),
`generated`, harcama (`model`, `input_tokens`, `output_tokens`, `cost_microusd`).

### Hata sözleşmesi

200 dışındaki her yanıt:

```json
{"detail": "<kod>", "usage": {"model": "…", "input_tokens": 0, "output_tokens": 0, "cost_microusd": 0} | null, "may_be_billed": true | false}
```

- `usage` doluysa model yanıt vermiştir: API bu gerçek harcamayı maliyet defterine yazar.
- `usage` null ve `may_be_billed` false: faturalanan bir istek sağlayıcıya gitmemiştir veya
  sağlayıcı faturalamadan reddetmiştir. API sıfır yazar.
- `usage` null ve `may_be_billed` true: harcama bilinmez. API en kötü durum tahminini yazar.

| Durum | `detail` | `usage` | `may_be_billed` |
|---|---|---|---|
| 401 | `unauthorized` | null | false |
| 503 | `not_configured` | null | false |
| 413 | `payload_too_large` | null | false |
| 422 | `invalid_request` (doğrulama; istek içeriği, `loc`, `msg` yansıtılmaz) | null | false |
| 422 | `ai_refused` (model güvenlik gerekçesiyle reddetti) | dolu | true |
| 503 | `ai_unavailable`, model yanıt verdi ama yanıt kullanılamadı | dolu | true |
| 503 | `ai_unavailable`, zaman aşımı veya bağlantı hatası | null | true |
| 503 | `ai_unavailable`, sağlayıcı hata yanıtı (429, diğer 4xx, 5xx, 529) | null | false |
| 500 | `internal_error` (beklenmeyen istisna; içerik log'a yazılmaz) | null | true |
| 404 / 405 | `not_found` / `method_not_allowed` (yalnızca kimlikli istekte) | null | false |

Model istemcisi 30 saniye zaman aşımıyla ve **SDK yeniden denemesi kapalı** (`max_retries=0`)
çalışır: API her özet için tek çağrılık bütçe ayırır; tekrar gerekiyorsa kararı API verir.

## Ortam

| Değişken | Anlamı |
|---|---|
| `SHEDU_AI_TOKEN` | API ile paylaşılan servis token'ı (en az 32 karakter). Yoksa servis her isteğe 503 döner. |
| `SHEDU_AI_MODEL` | Varsayılan `claude-opus-5-5`. Fiyatı `pricing.py`'de olmayan modelle servis başlamaz. |
| `ANTHROPIC_API_KEY` | Model sağlayıcısının anahtarı (Anthropic SDK'sının standart değişkeni). |

API tarafı: `SHEDU_AI_URL` (loopback dışında yalnızca HTTPS), `SHEDU_AI_TOKEN`,
`SHEDU_AI_DAILY_BUDGET_USD` (varsayılan 20). Kurallar için
[`src/shedu_ai/main.py`](src/shedu_ai/main.py), [`src/shedu_ai/gate.py`](src/shedu_ai/gate.py),
[`src/shedu_ai/summary.py`](src/shedu_ai/summary.py) ve
[docs/mimari.md](../../docs/mimari.md#ai-olay-özeti).
