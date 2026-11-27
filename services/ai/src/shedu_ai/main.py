"""Shedu AI servisi.

Kurallar (bkz. docs/mimari.md):
- Bu servis kullanıcıya açık değildir; yalnızca iç ağdan, servis kimliğiyle (paylaşılan token)
  Rust API'si çağırır (ARC-04). Token yoksa veya yanlışsa istek reddedilir; servis token'sız
  yapılandırılmışsa hiçbir isteğe yanıt vermez (EXC-01).
- Veritabanına erişmez; API yalnızca o isteğe ait, azaltılmış ve tek kiracılı veriyi
  gönderir (AI-02).
- Modelin aracı yoktur; alarmı kuramaz, kapatamaz, kimseyi çağıramaz (AI-01).
- Maliyet bütçesi API'de (kullanıcı ve organizasyon başına) ve burada (olay sayısı, max_tokens,
  düşük çaba) uygulanır (AI-03).
- PIN, token, telefon numarası veya kullanıcı kimliği prompt'a girmez; olay içerikleri log'a
  yazılmaz (LOG-02).
"""

from __future__ import annotations

import hmac
import logging
import os
from dataclasses import dataclass

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from .claude import DEFAULT_MODEL, ClaudeWriter
from .pricing import is_priced
from .summary import (
    ModelError,
    Refused,
    SummaryRequest,
    SummaryResponse,
    Unavailable,
    Writer,
    summarize,
)

log = logging.getLogger(__name__)
MIN_TOKEN_LEN = 32


@dataclass(frozen=True)
class Settings:
    # İç servis kimliği; Rust API'si `Authorization: Bearer …` ile gönderir.
    service_token: str | None
    model: str = DEFAULT_MODEL

    @classmethod
    def from_environment(cls) -> Settings:
        token = os.environ.get("SHEDU_AI_TOKEN") or None
        if token is not None and len(token) < MIN_TOKEN_LEN:
            raise RuntimeError(f"SHEDU_AI_TOKEN en az {MIN_TOKEN_LEN} karakter olmalı")
        model = os.environ.get("SHEDU_AI_MODEL", DEFAULT_MODEL)
        # Maliyeti hesaplanamayan modelle başlanmaz (AI-03).
        if not is_priced(model):
            raise RuntimeError(f"{model} için fiyat tanımlı değil (pricing.py)")
        return cls(service_token=token, model=model)


def create_app(settings: Settings, writer: Writer | None) -> FastAPI:
    app = FastAPI(
        title="Shedu AI",
        version="0.2.0",
        # İç servis: dokümantasyon ve şema yayınlanmaz.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    def authorize(authorization: str | None = Header(default=None)) -> None:
        if settings.service_token is None or writer is None:
            raise HTTPException(status_code=503, detail="not_configured")
        expected = f"Bearer {settings.service_token}"
        if authorization is None or not hmac.compare_digest(
            authorization.encode(), expected.encode()
        ):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    def failure(status: int, code: str, error: ModelError) -> JSONResponse:
        # Model yanıt verdiyse harcama bildirilir; API maliyet defterine yazar (AI-03).
        usage = error.usage.model_dump() if error.usage is not None else None
        return JSONResponse(status_code=status, content={"detail": code, "usage": usage})

    @app.post(
        "/v1/summaries/events",
        dependencies=[Depends(authorize)],
        response_model=SummaryResponse,
    )
    async def event_summary(body: SummaryRequest) -> SummaryResponse | JSONResponse:
        if writer is None:  # authorize zaten engeller; tip denetimi için
            raise HTTPException(status_code=503, detail="not_configured")
        try:
            result = await summarize(body, writer)
        except Refused as error:
            return failure(422, "ai_refused", error)
        except Unavailable as error:
            return failure(503, "ai_unavailable", error)
        log.info(
            "özet: olay=%d model=%s giriş=%d çıkış=%d maliyet_µ$=%d",
            len(body.events),
            result.model,
            result.input_tokens,
            result.output_tokens,
            result.cost_microusd,
        )
        return result

    return app


def _default_app() -> FastAPI:
    settings = Settings.from_environment()
    writer = ClaudeWriter.from_environment(settings.model) if settings.service_token else None
    return create_app(settings, writer)


app = _default_app()
