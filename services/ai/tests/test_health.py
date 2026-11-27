import pytest
from conftest import TOKEN, FakeWriter
from fastapi.testclient import TestClient

from shedu_ai.main import Settings, app, create_app

client = TestClient(app)


def test_health_returns_ok() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_and_schema_are_not_published(path: str) -> None:
    api = TestClient(create_app(Settings(service_token=TOKEN), FakeWriter()))

    # Kimliksiz istek kapıda kalır; kimlikli istek de bir şey bulamaz.
    assert api.get(path).status_code == 401
    assert api.get(path, headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 404
