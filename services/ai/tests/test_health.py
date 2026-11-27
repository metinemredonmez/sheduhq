from fastapi.testclient import TestClient

from shedu_ai.main import app

client = TestClient(app)


def test_health_returns_ok() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_public_docs_are_disabled() -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
