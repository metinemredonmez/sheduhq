"""ClaudeWriter: sahte Anthropic istemcisiyle; ağa çıkılmaz."""

import asyncio
from types import SimpleNamespace
from typing import Any

import anthropic
import httpx2
import pytest

from shedu_ai.claude import DEFAULT_MODEL, ClaudeWriter, request_params
from shedu_ai.summary import Refused, Unavailable

REQUEST = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


def message(
    text: str | None = '{"summary":"Özet.","highlights":["Bir"]}',
    stop_reason: str = "end_turn",
    stop_details: Any = None,
    iterations: list[SimpleNamespace] | None = None,
) -> SimpleNamespace:
    content = [SimpleNamespace(type="thinking", thinking="...")]
    if text is not None:
        content.append(SimpleNamespace(type="text", text=text))
    return SimpleNamespace(
        content=content,
        stop_reason=stop_reason,
        stop_details=stop_details,
        model="claude-opus-5-5",
        usage=SimpleNamespace(input_tokens=200, output_tokens=30, iterations=iterations),
    )


class FakeClient:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.kwargs: dict[str, Any] = {}
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    async def create(self, **kwargs: Any) -> Any:
        self.kwargs = kwargs
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def write(result: Any) -> tuple[Any, FakeClient]:
    fake = FakeClient(result)
    writer = ClaudeWriter(fake, DEFAULT_MODEL)  # type: ignore[arg-type]
    return asyncio.run(writer.write("sistem", "kullanıcı")), fake


def test_request_uses_structured_output_low_effort_and_fallback() -> None:
    params = request_params(DEFAULT_MODEL, "s", "u")

    assert params["model"] == "claude-opus-5-5"
    assert params["output_config"]["effort"] == "low"  # type: ignore[index]
    assert params["output_config"]["format"]["type"] == "json_schema"  # type: ignore[index]
    assert params["fallbacks"] == "default"
    assert "tools" not in params  # modelin aracı yok (AI-01)


def test_parses_the_text_block() -> None:
    (draft, usage), fake = write(message())

    assert draft.summary == "Özet."
    assert draft.highlights == ["Bir"]
    assert usage.input_tokens == 200
    assert fake.kwargs["messages"] == [{"role": "user", "content": "kullanıcı"}]


def test_cost_uses_the_price_table() -> None:
    (_, usage), _ = write(message())

    assert usage.cost_microusd == 200 * 4 + 30 * 20


def test_refusal_is_reported_with_its_spend() -> None:
    with pytest.raises(Refused) as caught:
        write(message(text=None, stop_reason="refusal", stop_details=SimpleNamespace(category="x")))

    assert caught.value.usage is not None
    assert caught.value.usage.cost_microusd == 200 * 4 + 30 * 20
    assert caught.value.may_be_billed is True


def test_fallback_attempts_are_all_billed() -> None:
    iterations = [
        SimpleNamespace(type="message", model="claude-opus-5-5", input_tokens=100, output_tokens=0),
        SimpleNamespace(
            type="fallback_message", model="claude-opus-4-8", input_tokens=100, output_tokens=50
        ),
        SimpleNamespace(
            type="fallback_message", model="claude-yeni-9", input_tokens=10, output_tokens=10
        ),
    ]

    (_, usage), _ = write(message(iterations=iterations))

    assert usage.input_tokens == 210
    assert usage.output_tokens == 60
    # Bilinmeyen model en pahalı katmandan sayılır.
    assert usage.cost_microusd == 100 * 4 + (100 * 5 + 50 * 25) + (10 * 10 + 10 * 50)


@pytest.mark.parametrize(
    "result",
    [
        message(stop_reason="max_tokens"),
        message(text=None),
        message(text="özet değil"),
        message(text='{"summary": 1}'),
    ],
)
def test_unusable_responses_are_unavailable_and_still_billed(result: Any) -> None:
    with pytest.raises(Unavailable) as caught:
        write(result)

    assert caught.value.usage is not None
    assert caught.value.may_be_billed is True


def status_error(cls: type[anthropic.APIStatusError], status: int) -> anthropic.APIStatusError:
    return cls("hata", response=httpx2.Response(status, request=REQUEST), body=None)


@pytest.mark.parametrize(
    ("error", "may_be_billed"),
    [
        # Yanıt gelmedi: istek gitmiş ve model çalışmış olabilir.
        (anthropic.APITimeoutError(request=REQUEST), True),
        (anthropic.APIConnectionError(request=REQUEST), True),
        # Sağlayıcının reddettiği istek ve aşırı yük: model çalışmadı.
        (status_error(anthropic.RateLimitError, 429), False),
        (status_error(anthropic.OverloadedError, 529), False),
        # Sunucu hatası: model çalışmış olabilir, faturalama doğrulanamaz (temkinli).
        (status_error(anthropic.InternalServerError, 500), True),
        (status_error(anthropic.InternalServerError, 503), True),
        (status_error(anthropic.BadRequestError, 400), False),
        (status_error(anthropic.AuthenticationError, 401), False),
    ],
)
def test_api_errors_are_unavailable_with_billing_uncertainty(
    error: Exception, may_be_billed: bool
) -> None:
    with pytest.raises(Unavailable) as caught:
        write(error)

    assert caught.value.usage is None
    assert caught.value.may_be_billed is may_be_billed


def test_sdk_retries_are_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ağa çıkılmaz; yalnızca istemci kurulur.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anahtari-ag-yok")

    writer = ClaudeWriter.from_environment(DEFAULT_MODEL)

    assert writer._client.max_retries == 0
    assert writer._client.timeout == 30.0
