import asyncio
import itertools
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import pytest
from conftest import TOKEN, USAGE, FakeWriter, Refused, Unavailable, body, event
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shedu_ai.gate import MAX_BODY_BYTES
from shedu_ai.main import Settings, create_app

URL = "/v1/summaries/events"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
RAW_AUTH = (b"authorization", f"Bearer {TOKEN}".encode())
NOT_BILLED = {"usage": None, "may_be_billed": False}
VALID = json.dumps(body([event(0, "armed")])).encode()


def make_app(writer: FakeWriter | None, token: str | None = TOKEN) -> FastAPI:
    return create_app(Settings(service_token=token), writer)


def client(writer: FakeWriter | None, token: str | None = TOKEN) -> TestClient:
    return TestClient(make_app(writer, token))


# --- Ham ASGI: gövdenin okunup okunmadığını doğrudan sayar ---------------------------------


@dataclass
class Raw:
    status: int
    headers: dict[bytes, bytes]
    json: dict[str, Any]
    reads: int  # uygulamanın receive() ile aldığı gövde iletisi sayısı


def chunks(*parts: bytes) -> list[dict[str, Any]]:
    return [
        {"type": "http.request", "body": part, "more_body": i < len(parts) - 1}
        for i, part in enumerate(parts)
    ]


def endless(part: bytes) -> Iterable[dict[str, Any]]:
    return itertools.repeat({"type": "http.request", "body": part, "more_body": True})


def call(
    app: FastAPI,
    headers: list[tuple[bytes, bytes]],
    messages: Iterable[dict[str, Any]] = (),
    path: str = URL,
) -> Raw:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"content-type", b"application/json"), *headers],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8090),
    }
    sent: list[dict[str, Any]] = []
    reads = 0

    async def run() -> None:
        nonlocal reads
        source = iter(messages)
        done = asyncio.Event()

        async def receive() -> dict[str, Any]:
            nonlocal reads
            message = next(source, None)
            if message is None:
                await done.wait()
                return {"type": "http.disconnect"}
            reads += 1
            return message

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)
            if message["type"] == "http.response.body" and not message.get("more_body"):
                done.set()

        await app(scope, receive, send)

    asyncio.run(run())
    start = next(m for m in sent if m["type"] == "http.response.start")
    payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return Raw(start["status"], dict(start["headers"]), json.loads(payload), reads)


@pytest.mark.parametrize(
    ("token", "configured", "headers", "status", "code"),
    [
        (None, True, [RAW_AUTH], 503, "not_configured"),
        (TOKEN, False, [RAW_AUTH], 503, "not_configured"),
        (TOKEN, True, [], 401, "unauthorized"),
        (TOKEN, True, [(b"authorization", b"Bearer yanlis")], 401, "unauthorized"),
        (TOKEN, True, [(b"authorization", TOKEN.encode())], 401, "unauthorized"),
        (TOKEN, True, [RAW_AUTH, RAW_AUTH], 401, "unauthorized"),  # iki başlık: belirsiz
        # Kimliksiz istek çok büyük gövde bildirse de 413 değil 401 alır; gövde okunmaz.
        (
            TOKEN,
            True,
            [(b"content-length", str(50 * MAX_BODY_BYTES).encode())],
            401,
            "unauthorized",
        ),
    ],
)
def test_rejections_happen_before_the_body_is_read(
    token: str | None, configured: bool, headers: list, status: int, code: str
) -> None:
    writer = FakeWriter()
    app = make_app(writer if configured else None, token)

    # Gövde geçerli: okunsaydı istek başarılı olurdu.
    result = call(app, headers, chunks(VALID))

    assert result.status == status
    assert result.json == {"detail": code, **NOT_BILLED}
    assert result.reads == 0
    assert writer.calls == []


def test_unauthorized_response_names_the_scheme() -> None:
    result = call(make_app(FakeWriter()), [], chunks(VALID))

    assert result.headers[b"www-authenticate"] == b"Bearer"


@pytest.mark.parametrize("length", [str(MAX_BODY_BYTES + 1), "9" * 40])
def test_declared_oversize_body_is_rejected_unread(length: str) -> None:
    writer = FakeWriter()

    result = call(make_app(writer), [RAW_AUTH, (b"content-length", length.encode())], chunks(VALID))

    assert result.status == 413
    assert result.json == {"detail": "payload_too_large", **NOT_BILLED}
    assert result.reads == 0
    assert writer.calls == []


def test_stream_without_content_length_is_cut_off_at_the_limit() -> None:
    writer = FakeWriter()
    part = b" " * (64 * 1024)

    result = call(make_app(writer), [RAW_AUTH], endless(part))

    assert result.status == 413
    assert result.json == {"detail": "payload_too_large", **NOT_BILLED}
    # Sınırın biraz ötesine kadar okunur, sonra bırakılır.
    assert result.reads == MAX_BODY_BYTES // len(part) + 1
    assert writer.calls == []


def test_lying_content_length_is_counted_on_the_stream() -> None:
    writer = FakeWriter()

    result = call(
        make_app(writer),
        [RAW_AUTH, (b"content-length", b"10")],
        chunks(VALID, b" " * MAX_BODY_BYTES),
    )

    assert result.status == 413
    assert writer.calls == []


def test_body_within_the_limit_is_replayed_to_the_app() -> None:
    writer = FakeWriter()
    third = len(VALID) // 3

    result = call(
        make_app(writer),
        [RAW_AUTH],
        chunks(VALID[:third], VALID[third : 2 * third], VALID[2 * third :]),
    )

    assert result.status == 200
    assert result.json["generated"] is True
    assert len(writer.calls) == 1


def test_websocket_is_closed_without_accepting() -> None:
    sent: list[dict[str, Any]] = []

    async def run() -> None:
        async def receive() -> dict[str, Any]:
            return {"type": "websocket.connect"}

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        scope = {"type": "websocket", "path": URL, "headers": [RAW_AUTH]}
        await make_app(FakeWriter())(scope, receive, send)

    asyncio.run(run())

    assert sent == [{"type": "websocket.close", "code": 1008}]


# --- HTTP üzerinden ---------------------------------------------------------------------


def test_body_limit_boundary(writer: FakeWriter) -> None:
    api = client(writer)
    exact = VALID + b" " * (MAX_BODY_BYTES - len(VALID))
    headers = {**AUTH, "Content-Type": "application/json"}

    assert api.post(URL, content=exact, headers=headers).status_code == 200
    over = api.post(URL, content=exact + b" ", headers=headers)
    assert over.status_code == 413
    assert over.json() == {"detail": "payload_too_large", **NOT_BILLED}
    assert len(writer.calls) == 1


def test_chunked_upload_over_the_limit_is_rejected(writer: FakeWriter) -> None:
    # Üretici gövde: Content-Length yok (chunked), sınır akışta sayılır.
    def stream() -> Iterable[bytes]:
        yield VALID
        yield b" " * MAX_BODY_BYTES

    response = client(writer).post(
        URL, content=stream(), headers={**AUTH, "Content-Type": "application/json"}
    )

    assert response.status_code == 413
    assert "content-length" not in response.request.headers
    assert writer.calls == []


def test_health_needs_no_token_even_when_unconfigured() -> None:
    assert client(None, token=None).get("/health").json() == {"status": "ok"}
    assert client(FakeWriter()).get("/health").status_code == 200


def test_unknown_paths_are_gated_too(writer: FakeWriter) -> None:
    api = client(writer)

    assert api.get("/yok").status_code == 401
    missing = api.get("/yok", headers=AUTH)
    assert missing.status_code == 404
    assert missing.json() == {"detail": "not_found", **NOT_BILLED}


def test_wrong_method_uses_the_error_contract(writer: FakeWriter) -> None:
    response = client(writer).get(URL, headers=AUTH)

    assert response.status_code == 405
    assert response.json() == {"detail": "method_not_allowed", **NOT_BILLED}


def test_returns_summary_with_exact_counts(writer: FakeWriter) -> None:
    events = [event(0, "alarm", alarm_kind="intrusion"), event(5, "disarmed")]

    response = client(writer).post(URL, json=body(events), headers=AUTH)

    assert response.status_code == 200
    data = response.json()
    assert data["summary"] == "Gece bir hırsız alarmı oldu."
    assert data["needs_attention"] is True
    assert data["stats"]["alarms"] == 1
    assert data["stats"]["total"] == 2
    assert data["generated"] is True
    assert data["input_tokens"] == 120
    assert len(writer.calls) == 1


@pytest.mark.parametrize(
    ("error", "status", "expected"),
    [
        (Refused("cyber", USAGE), 422, {"detail": "ai_refused", "usage": USAGE.model_dump()}),
        (
            Unavailable("yarım", USAGE),
            503,
            {"detail": "ai_unavailable", "usage": USAGE.model_dump()},
        ),
        # Kullanım biliniyorsa harcama kesindir; bayrak ne olursa olsun true.
        (
            Unavailable("yarım", USAGE, may_be_billed=False),
            503,
            {"detail": "ai_unavailable", "usage": USAGE.model_dump()},
        ),
        (Unavailable("zaman aşımı", may_be_billed=True), 503, {"detail": "ai_unavailable"}),
        # Belirtilmezse temkinli: faturalanmış olabilir.
        (Unavailable("x"), 503, {"detail": "ai_unavailable"}),
    ],
)
def test_model_failures_report_spend_or_billing_uncertainty(
    error: Exception, status: int, expected: dict
) -> None:
    response = client(FakeWriter(error=error)).post(
        URL, json=body([event(0, "armed")]), headers=AUTH
    )

    assert response.status_code == status
    assert response.json() == {"usage": None, **expected, "may_be_billed": True}


def test_provider_error_without_spend_is_not_billed() -> None:
    writer = FakeWriter(error=Unavailable("hız sınırı", may_be_billed=False))

    response = client(writer).post(URL, json=body([event(0, "armed")]), headers=AUTH)

    assert response.status_code == 503
    assert response.json() == {"detail": "ai_unavailable", **NOT_BILLED}


def test_success_reports_cost(writer: FakeWriter) -> None:
    response = client(writer).post(URL, json=body([event(0, "armed")]), headers=AUTH)

    assert response.json()["cost_microusd"] == 1280


def test_unpriced_model_is_refused_at_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHEDU_AI_TOKEN", TOKEN)
    monkeypatch.setenv("SHEDU_AI_MODEL", "claude-bilinmeyen-1")

    with pytest.raises(RuntimeError, match="fiyat"):
        Settings.from_environment()

    monkeypatch.setenv("SHEDU_AI_MODEL", "claude-opus-5-5")
    assert Settings.from_environment().model == "claude-opus-5-5"


MARKER = "ozel-icerik-7f3a"  # istek içeriği izleyicisi


@pytest.mark.parametrize(
    "request_kwargs",
    [
        {"json": body(user_email=f"{MARKER}@ornek.com")},  # tanımsız alan
        {"json": body(panel_name=MARKER * 20)},  # çok uzun ad
        {"json": body([event(0, "armed", zone=MARKER)], counts={"total": MARKER})},
        {"content": f'{{"panel_name": "{MARKER}"'.encode()},  # bozuk JSON
        {"content": b""},
    ],
)
def test_invalid_request_does_not_reflect_input(
    writer: FakeWriter, request_kwargs: dict, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    headers = {**AUTH, "Content-Type": "application/json"}

    response = client(writer).post(URL, headers=headers, **request_kwargs)

    assert response.status_code == 422
    assert response.json() == {"detail": "invalid_request", **NOT_BILLED}
    assert MARKER not in response.text
    assert MARKER not in caplog.text
    assert writer.calls == []


def test_unexpected_error_is_internal_billable_and_not_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    writer = FakeWriter(error=RuntimeError(f"olay içeriği: {MARKER}"))

    response = client(writer).post(URL, json=body([event(0, "armed", zone=MARKER)]), headers=AUTH)

    assert response.status_code == 500
    assert response.json() == {"detail": "internal_error", "usage": None, "may_be_billed": True}
    assert MARKER not in response.text
    assert MARKER not in caplog.text
    assert "RuntimeError" in caplog.text


def test_endpoint_refuses_requests_that_bypassed_the_gate(writer: FakeWriter) -> None:
    # İkinci savunma: ara katman kaldırılırsa geçerli token'la bile işlenmez.
    app = make_app(writer)
    app.user_middleware.clear()

    response = TestClient(app).post(URL, json=body([event(0, "armed")]), headers=AUTH)

    assert response.status_code == 503
    assert response.json() == {"detail": "not_configured", **NOT_BILLED}
    assert writer.calls == []
