"""Servis kapısı: kimlik doğrulama ve gövde sınırı (ARC-04, RES-01, EXC-01).

Saf ASGI ara katmanıdır; FastAPI gövdeyi okuyup ayrıştırmadan önce çalışır ve bu kuralların tek
doğru kaynağıdır:
- `/health` dışındaki her HTTP isteğinde önce `Authorization: Bearer <token>` sabit zamanlı
  karşılaştırılır. Servis yapılandırılmamışsa (token veya yazıcı yok) 503 `not_configured`, token
  eksik veya yanlışsa 401 `unauthorized` döner. Bu yanıtlar gövde hiç okunmadan gönderilir.
- Gövde en fazla `MAX_BODY_BYTES` olabilir. `Content-Length` sınırı aşıyorsa gövde okunmadan 413
  `payload_too_large` döner. Başlık yoksa veya yanlışsa akış okunurken sayılır: gövde sınır kadar
  tamponlanır, sınır aşılırsa uygulamaya hiç iletilmez; aşılmazsa uygulamaya yeniden oynatılır.
- Uygulamadan kaçan beklenmeyen istisna 500 `internal_error` olur. İstisna mesajı ve izi istek
  içeriği taşıyabilir; log'a yalnızca türü ve yeri yazılır (LOG-02).

Hata yanıtlarının hepsi `{"detail": <kod>, "usage": …, "may_be_billed": …}` biçimindedir. Kapıdan
dönen hatalarda model çağrılmamıştır: `usage` null, `may_be_billed` false. Beklenmeyen istisnada
modelin çalışıp çalışmadığı bilinmez: `may_be_billed` true.
"""

from __future__ import annotations

import hmac
import json
import logging
import traceback
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 1024 * 1024
HEALTH_PATH = "/health"
# Kapıdan geçen isteğin işareti; uç nokta bunu ikinci savunma olarak denetler.
AUTHENTICATED = "shedu.service_authenticated"


def error_content(
    code: str, usage: dict[str, Any] | None = None, *, may_be_billed: bool
) -> dict[str, Any]:
    """Hata yanıtı gövdesi. `usage` doluysa API gerçek harcamayı yazar; null ve `may_be_billed`
    false ise sıfır, null ve true ise en kötü durum tahminini (AI-03)."""
    return {"detail": code, "usage": usage, "may_be_billed": may_be_billed}


class _ClientGone(Exception):
    """İstemci gövdeyi göndermeden bağlantıyı kapattı."""


class ServiceGate:
    def __init__(self, app: ASGIApp, *, token: str | None, ready: bool) -> None:
        self.app = app
        # Token veya yazıcı yoksa servis hiçbir isteğe yanıt vermez (EXC-01).
        self._expected = f"Bearer {token}".encode() if token is not None and ready else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            # WebSocket ucu yok: bağlantı kabul edilmeden kapatılır.
            await receive()
            await send({"type": "websocket.close", "code": 1008})
            return

        started = False

        async def tracked(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self._http(scope, receive, tracked)
        except Exception as error:
            _log_unexpected(error)
            if not started:
                await _reply(send, 500, error_content("internal_error", may_be_billed=True))

    async def _http(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["path"] == HEALTH_PATH:
            await self.app(scope, receive, send)
            return
        if self._expected is None:
            await _reply(send, 503, error_content("not_configured", may_be_billed=False))
            return
        if not self._authorized(scope):
            await _reply(
                send,
                401,
                error_content("unauthorized", may_be_billed=False),
                [(b"www-authenticate", b"Bearer")],
            )
            return
        too_large = error_content("payload_too_large", may_be_billed=False)
        if _declares_too_large(scope):
            await _reply(send, 413, too_large)
            return
        try:
            body = await _read_body(receive)
        except _ClientGone:
            return
        if body is None:
            await _reply(send, 413, too_large)
            return
        scope[AUTHENTICATED] = True
        await self.app(scope, _replay(body, receive), send)

    def _authorized(self, scope: Scope) -> bool:
        values = [value for name, value in scope["headers"] if name == b"authorization"]
        # Birden çok Authorization başlığı belirsizdir; reddedilir.
        if len(values) != 1 or self._expected is None:
            return False
        return hmac.compare_digest(values[0], self._expected)


def _declares_too_large(scope: Scope) -> bool:
    """`Content-Length` sınırı aşıyor mu? Başlık yoksa veya bozuksa karar akışta verilir."""
    for name, value in scope["headers"]:
        if name == b"content-length" and value.isdigit():
            digits = value.lstrip(b"0") or b"0"
            # Çok uzun sayı int'e çevrilmeden reddedilir.
            if len(digits) > 9 or int(digits) > MAX_BODY_BYTES:
                return True
    return False


async def _read_body(receive: Receive) -> bytes | None:
    """Gövdeyi en fazla `MAX_BODY_BYTES` okur; sınır aşılırsa okumayı bırakır ve None döner."""
    body = bytearray()
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            raise _ClientGone
        chunk = message.get("body", b"")
        if len(body) + len(chunk) > MAX_BODY_BYTES:
            return None
        body += chunk
        if not message.get("more_body", False):
            return bytes(body)


def _replay(body: bytes, receive: Receive) -> Receive:
    pending = True

    async def replay() -> Message:
        nonlocal pending
        if pending:
            pending = False
            return {"type": "http.request", "body": body, "more_body": False}
        # Gövde bitti; sonraki iletiler (ör. bağlantı kopması) özgün kanaldan gelir.
        return await receive()

    return replay


async def _reply(
    send: Send,
    status: int,
    content: dict[str, Any],
    headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    body = json.dumps(content, separators=(",", ":")).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                # Okunmamış gövde kalmış olabilir; bağlantı yeniden kullanılmaz.
                (b"connection", b"close"),
                *(headers or []),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _log_unexpected(error: Exception) -> None:
    frames = traceback.extract_tb(error.__traceback__)
    where = f"{frames[-1].filename.rsplit('/', 1)[-1]}:{frames[-1].lineno}" if frames else "?"
    log.error("beklenmeyen hata: %s (%s)", type(error).__name__, where)
