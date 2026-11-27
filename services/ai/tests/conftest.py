from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from shedu_ai.summary import Draft, Refused, Unavailable, Usage

START = datetime(2026, 11, 26, 21, 0, tzinfo=UTC)
# 120 × 4 + 40 × 20 mikro-dolar.
USAGE = Usage(model="claude-opus-5-5", input_tokens=120, output_tokens=40, cost_microusd=1280)
TOKEN = "t" * 40


class FakeWriter:
    """Model yerine geçer; aldığı prompt'u saklar, verilen yanıtı veya hatayı döndürür."""

    def __init__(self, draft: Draft | None = None, error: Exception | None = None) -> None:
        self.draft = draft or Draft(summary="Gece bir hırsız alarmı oldu.", highlights=["Alarm"])
        self.error = error
        self.calls: list[tuple[str, str]] = []

    async def write(self, system: str, user: str) -> tuple[Draft, Usage]:
        self.calls.append((system, user))
        if self.error is not None:
            raise self.error
        return self.draft, USAGE


def event(minutes: int, kind: str, **extra: Any) -> dict[str, Any]:
    return {"occurred_at": (START + timedelta(minutes=minutes)).isoformat(), "kind": kind, **extra}


def body(events: list[dict[str, Any]] | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "panel_name": "Ev",
        "time_zone": "Europe/Istanbul",
        "period_start": START.isoformat(),
        "period_end": (START + timedelta(hours=24)).isoformat(),
        "events": events if events is not None else [],
        **extra,
    }


@pytest.fixture
def writer() -> FakeWriter:
    return FakeWriter()


__all__ = ["TOKEN", "USAGE", "FakeWriter", "Refused", "Unavailable", "body", "event"]
