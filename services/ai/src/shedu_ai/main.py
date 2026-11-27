"""Shedu AI servisi.

Kurallar (bkz. docs/mimari.md):
- Bu servis kullanıcıya açık değildir; yalnızca iç ağdan, servis kimliğiyle (paylaşılan token)
  Rust API'si çağırır (ARC-04). Kimlik doğrulama ve 1 MiB gövde sınırı, FastAPI gövdeyi okumadan
  önce saf ASGI kapısında uygulanır (`gate.py`, RES-01). Token yoksa veya yanlışsa istek gövdesi
  okunmadan reddedilir; servis token'sız yapılandırılmışsa hiçbir isteğe yanıt vermez (EXC-01).
- Veritabanına erişmez; API yalnızca o isteğe ait, azaltılmış ve tek kiracılı veriyi
  gönderir (AI-02).
- Modelin aracı yoktur; alarmı kuramaz, kapatamaz, kimseyi çağıramaz (AI-01).
- Maliyet bütçesi API'de (kullanıcı ve organizasyon başına) ve burada (olay sayısı, max_tokens,
  düşük çaba, tek deneme) uygulanır (AI-03). 200 dışındaki her yanıt
  `{"detail", "usage", "may_be_billed"}` biçimindedir; API harcamayı buna göre deftere yazar.
- PIN, token, telefon numarası veya kullanıcı kimliği prompt'a girmez; olay içerikleri log'a
  yazılmaz, doğrulama hatası istek içeriğini yanıta yansıtmaz (LOG-02).
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from http import HTTPStatus

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .claude import DEFAULT_MODEL, ClaudeWriter
from .gate import AUTHENTICATED, ServiceGate, error_content
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
_CODE = re.compile(r"[a-z_]+")


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


def _status_code(status: int) -> str:
    try:
        return HTTPStatus(status).phrase.lower().replace(" ", "_").replace("-", "_")
    except ValueError:
        return "http_error"


def create_app(settings: Settings, writer: Writer | None) -> FastAPI:
    app = FastAPI(
        title="Shedu AI",
        version="0.3.0",
        # İç servis: dokümantasyon ve şema yayınlanmaz.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    # Tek doğru kaynak: kimlik doğrulama ve gövde sınırı (ARC-04, RES-01).
    app.add_middleware(ServiceGate, token=settings.service_token, ready=writer is not None)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, error: RequestValidationError) -> JSONResponse:
        # Hata ayrıntıları (input, loc, msg) istek içeriğini taşır; yanıta ve log'a yazılmaz.
        log.info("geçersiz istek: %d hata", len(error.errors()))
        return JSONResponse(
            status_code=422, content=error_content("invalid_request", may_be_billed=False)
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, error: StarletteHTTPException) -> JSONResponse:
        # 404, 405 ve kendi kodlarımız da aynı hata sözleşmesiyle döner.
        detail = error.detail
        own = isinstance(detail, str) and _CODE.fullmatch(detail) is not None
        code = detail if own else _status_code(error.status_code)
        return JSONResponse(
            status_code=error.status_code,
            content=error_content(code, may_be_billed=False),
            headers=error.headers,
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    def failure(status: int, code: str, error: ModelError) -> JSONResponse:
        # Model yanıt verdiyse harcama bildirilir; vermediyse faturalanmış olabilir mi (AI-03).
        usage = error.usage.model_dump() if error.usage is not None else None
        log.warning("özet üretilemedi: %s (%s) may_be_billed=%s", code, error, error.may_be_billed)
        return JSONResponse(
            status_code=status,
            content=error_content(code, usage, may_be_billed=error.may_be_billed),
        )

    @app.post("/v1/summaries/events", response_model=SummaryResponse)
    async def event_summary(
        request: Request, body: SummaryRequest
    ) -> SummaryResponse | JSONResponse:
        # İkinci savunma: kapı kaldırılırsa veya atlanırsa istek işlenmez (EXC-01).
        if request.scope.get(AUTHENTICATED) is not True or writer is None:
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
