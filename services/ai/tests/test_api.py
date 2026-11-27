import pytest
from conftest import TOKEN, USAGE, FakeWriter, Refused, Unavailable, body, event
from fastapi.testclient import TestClient

from shedu_ai.main import Settings, create_app

URL = "/v1/summaries/events"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def client(writer: FakeWriter | None, token: str | None = TOKEN) -> TestClient:
    return TestClient(create_app(Settings(service_token=token), writer))


def test_unconfigured_service_refuses_everything() -> None:
    response = client(None, token=None).post(URL, json=body(), headers=AUTH)

    assert response.status_code == 503
    assert response.json()["detail"] == "not_configured"


def test_requires_the_service_token(writer: FakeWriter) -> None:
    api = client(writer)

    assert api.post(URL, json=body()).status_code == 401
    assert api.post(URL, json=body(), headers={"Authorization": "Bearer yanlis"}).status_code == 401
    assert api.post(URL, json=body(), headers={"Authorization": TOKEN}).status_code == 401
    assert writer.calls == []


def test_returns_summary_with_exact_counts(writer: FakeWriter) -> None:
    events = [event(0, "alarm", alarm_kind="intrusion"), event(5, "disarmed")]

    response = client(writer).post(URL, json=body(events), headers=AUTH)

    assert response.status_code == 200
    data = response.json()
    assert data["summary"] == "Gece bir hırsız alarmı oldu."
    assert data["needs_attention"] is True
    assert data["stats"]["alarms"] == 1
    assert data["generated"] is True
    assert data["input_tokens"] == 120
    assert len(writer.calls) == 1


def test_refusal_and_outage_map_to_stable_codes_and_report_spend() -> None:
    events = [event(0, "armed")]

    refused = client(FakeWriter(error=Refused("cyber", USAGE))).post(
        URL, json=body(events), headers=AUTH
    )
    down = client(FakeWriter(error=Unavailable("x"))).post(URL, json=body(events), headers=AUTH)

    assert refused.status_code == 422
    assert refused.json() == {"detail": "ai_refused", "usage": USAGE.model_dump()}
    assert down.status_code == 503
    assert down.json() == {"detail": "ai_unavailable", "usage": None}


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


def test_unknown_fields_are_rejected(writer: FakeWriter) -> None:
    response = client(writer).post(URL, json=body(user_email="a@b.c"), headers=AUTH)

    assert response.status_code == 422
    assert writer.calls == []


def test_schema_is_not_published(writer: FakeWriter) -> None:
    assert client(writer).get("/openapi.json").status_code == 404
