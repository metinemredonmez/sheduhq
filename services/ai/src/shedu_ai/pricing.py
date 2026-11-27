"""Model fiyatları ve çağrı maliyeti (AI-03).

Fiyatlar milyon token başına ABD doları (giriş, çıkış). Mikro-dolar maliyet, token sayısı ile
milyon token fiyatının çarpımıdır, böylece tam sayı olarak hesaplanır.

- Servis, fiyatı bu tabloda olmayan bir modelle başlamaz.
- Güvenlik reddinde sunucu tarafı yedek model devreye girebilir. Yanıttaki model tabloda yoksa en
  pahalı katmanın fiyatıyla sayılır: bütçe harcamayı eksik değil fazla sayar.
- Önbellek token'ları kullanılmıyor. Görünürlerse temkinli sayılır: yazma giriş fiyatının iki
  katı, okuma giriş fiyatıyla.

Kaynak: Anthropic fiyatları (Kasım 2026). Fiyat değişince bu tablo güncellenir.
"""

from __future__ import annotations

PRICES: dict[str, tuple[int, int]] = {
    "claude-opus-5-5": (4, 20),
    "claude-opus-5": (5, 25),
    "claude-opus-4-8": (5, 25),
}
# Rust API'deki bilinmeyen çağrı tahmini de bu fiyatı kullanır (ai.rs).
UNKNOWN_MODEL_PRICE = (10, 50)


def is_priced(model: str) -> bool:
    return model in PRICES


def cost_microusd(
    model: str,
    input_tokens: int,
    output_tokens: int,
    cache_creation_tokens: int = 0,
    cache_read_tokens: int = 0,
) -> int:
    rate_in, rate_out = PRICES.get(model, UNKNOWN_MODEL_PRICE)
    return (
        input_tokens * rate_in
        + cache_creation_tokens * rate_in * 2
        + cache_read_tokens * rate_in
        + output_tokens * rate_out
    )
