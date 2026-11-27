"""Anthropic Claude ile özet yazıcı.

- Model: varsayılan `claude-opus-5-5`; `SHEDU_AI_MODEL` ile değiştirilebilir.
- Yapılandırılmış çıktı (JSON şeması): model yalnızca `summary` ve `highlights` döndürebilir.
- Düşük çaba (effort: low) ve sınırlı `max_tokens`: özet kısa, maliyet düşük (AI-03).
- Güvenlik sınıflandırıcısı reddederse sunucu tarafında varsayılan yedek modele geçilir
  (`fallbacks: "default"`); bütün zincir reddederse `Refused`.
- Zaman aşımı 30 saniye, SDK'nın kendi yeniden denemesi kapalı; hata durumunda `Unavailable`.
  Alarm yolu AI'ya bağlı değildir: özet gelmezse yalnızca özet gösterilmez.
- Yanıt gelmeyen hatada faturalama belirsizliği `may_be_billed` ile bildirilir (AI-03): zaman
  aşımı ve bağlantı hatasında istek sağlayıcıya ulaşmış ve model çalışmış olabilir (true).
  Sağlayıcının reddettiği istek (429, 4xx) ve aşırı yük (529) model çalışmadan döner (false).
  Sunucu hatasında (diğer 5xx) model çalışmış olabilir; faturalanıp faturalanmadığı
  doğrulanamadığından temkinli davranılır (true): Rust API rezervasyonu tahminiyle kapatır.
"""

from __future__ import annotations

import logging

import anthropic

from .pricing import cost_microusd
from .summary import DRAFT_SCHEMA, Draft, Refused, Unavailable, Usage

log = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-opus-5-5"
# Rust API, sonucu bilinmeyen çağrının maliyet tahmininde bu sınırı kullanır (ai.rs).
MAX_TOKENS = 4096
FALLBACK_BETA = "server-side-fallback-2026-07-01"
CLIENT_TIMEOUT_SECONDS = 30.0


def request_params(model: str, system: str, user: str) -> dict[str, object]:
    """Messages API isteğinin parametreleri (test edilebilir, ağ yok)."""
    return {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "system": system,
        "messages": [{"role": "user", "content": user}],
        "output_config": {
            "effort": "low",
            "format": {"type": "json_schema", "schema": DRAFT_SCHEMA},
        },
        "betas": [FALLBACK_BETA],
        "fallbacks": "default",
    }


def billed_usage(response: object) -> Usage:
    """Faturalanan kullanım. Yedek model devreye girdiyse `usage.iterations` her denemeyi kendi
    modeliyle listeler; üst düzey `usage` yalnızca son denemedir."""
    usage = response.usage  # type: ignore[attr-defined]
    iterations = getattr(usage, "iterations", None) or [usage]
    model = response.model  # type: ignore[attr-defined]
    total_in = total_out = cost = 0
    for item in iterations:
        item_model = getattr(item, "model", None) or model
        tokens_in = item.input_tokens or 0
        tokens_out = item.output_tokens or 0
        total_in += tokens_in
        total_out += tokens_out
        cost += cost_microusd(
            item_model,
            tokens_in,
            tokens_out,
            getattr(item, "cache_creation_input_tokens", None) or 0,
            getattr(item, "cache_read_input_tokens", None) or 0,
        )
    return Usage(model=model, input_tokens=total_in, output_tokens=total_out, cost_microusd=cost)


class ClaudeWriter:
    def __init__(self, client: anthropic.AsyncAnthropic, model: str = DEFAULT_MODEL) -> None:
        self._client = client
        self._model = model

    @classmethod
    def from_environment(cls, model: str) -> ClaudeWriter:
        # Kimlik bilgisi SDK'nın standart sırasıyla ortamdan okunur (ANTHROPIC_API_KEY vb.).
        # SDK'nın yeniden denemesi kapalı (max_retries=0): Rust API her özet için tek çağrılık
        # bütçe rezervasyonu yapar ve harcamayı tek yanıttan yazar. SDK'nın sessiz tekrarı
        # (zaman aşımı, bağlantı, 429, 5xx) faturayı katlayabilir; zaman aşımından sonraki tekrarda
        # ilk denemenin harcaması hiç görünmez. Tekrar gerekiyorsa kararı API verir (AI-03).
        client = anthropic.AsyncAnthropic(timeout=CLIENT_TIMEOUT_SECONDS, max_retries=0)
        return cls(client, model)

    async def write(self, system: str, user: str) -> tuple[Draft, Usage]:
        try:
            response = await self._client.beta.messages.create(
                **request_params(self._model, system, user)
            )
        # Sıra önemli: APITimeoutError, APIConnectionError'ın; RateLimitError, APIStatusError'ın
        # alt sınıfıdır.
        except anthropic.APITimeoutError as error:
            # İstek gitmiş, model çalışmış olabilir; yanıt gelmediği için harcama bilinmez.
            raise Unavailable("zaman aşımı", may_be_billed=True) from error
        except anthropic.APIConnectionError as error:
            raise Unavailable("bağlantı", may_be_billed=True) from error
        except anthropic.RateLimitError as error:
            # Sağlayıcının hata yanıtı faturalanmaz.
            raise Unavailable("hız sınırı", may_be_billed=False) from error
        except anthropic.APIStatusError as error:
            log.warning("model hatası: durum %s", error.status_code)
            server_side = error.status_code >= 500 and error.status_code != 529
            raise Unavailable("model hatası", may_be_billed=server_side) from error

        # Yanıt geldiyse harcama oldu: hangi sonuç olursa olsun kullanım bildirilir.
        usage = billed_usage(response)
        if response.stop_reason == "refusal":
            category = getattr(response.stop_details, "category", None)
            log.warning("model özeti reddetti: %s", category)
            raise Refused(str(category), usage)
        if response.stop_reason == "max_tokens":
            raise Unavailable("yanıt yarım kaldı", usage)
        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            raise Unavailable("metin yok", usage)
        try:
            draft = Draft.model_validate_json(text)
        except ValueError as error:
            raise Unavailable("şemaya uymayan yanıt", usage) from error
        return draft, usage
