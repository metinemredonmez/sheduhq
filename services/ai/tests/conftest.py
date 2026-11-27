from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from shedu_ai.summary import KIND_COUNTS, Draft, Refused, Unavailable, Usage

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


def counts_for(events: list[dict[str, Any]], **override: int) -> dict[str, int]:
    """Listeyle tutarlı kesin sayılar (liste dönemin tamamıysa API'nin hesaplayacağı)."""
    kinds = Counter(item["kind"] for item in events)
    counts = {field: kinds[kind] for kind, field in KIND_COUNTS.items()}
    return {"total": len(events), **counts, **override}


def body(events: list[dict[str, Any]] | None = None, **extra: Any) -> dict[str, Any]:
    events = events if events is not None else []
    return {
        "panel_name": "Ev",
        "time_zone": "Europe/Istanbul",
        "period_start": START.isoformat(),
        "period_end": (START + timedelta(hours=24)).isoformat(),
        "events": events,
        "counts": counts_for(events),
        "connection": "connected",
        **extra,
    }


@pytest.fixture
def writer() -> FakeWriter:
    return FakeWriter()


__all__ = [
    "START",
    "TOKEN",
    "USAGE",
    "FakeWriter",
    "Refused",
    "Unavailable",
    "body",
    "counts_for",
    "event",
]
