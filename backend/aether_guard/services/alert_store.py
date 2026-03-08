from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from uuid import uuid4

from aether_guard.schemas import AlertRecord, Severity


class AlertStore:
    """
    Privacy-safe in-memory alert store for early development.

    Stores only:
    - derived signals (floats)
    - risk score + severity
    - title (non-sensitive template string)

    Does NOT store:
    - raw email text
    - sender addresses
    - URLs

    Later upgrade path:
    - persist to Postgres with retention policy + aggregation.
    """

    def __init__(self, *, max_items: int = 500) -> None:
        self._items: deque[AlertRecord] = deque(maxlen=max_items)

    def add(self, *, risk_score: int, severity: Severity, title: str, signals: dict[str, float]) -> AlertRecord:
        rec = AlertRecord(
            id=str(uuid4()),
            created_at_utc=datetime.now(timezone.utc),
            risk_score=risk_score,
            severity=severity,
            title=title,
            signals=signals,
        )
        self._items.appendleft(rec)
        return rec

    def list(self, *, limit: int = 50) -> list[AlertRecord]:
        return list(self._items)[: max(0, limit)]

    def stats(self) -> dict[str, object]:
        by: dict[Severity, int] = {"low": 0, "medium": 0, "high": 0}
        for it in self._items:
            by[it.severity] += 1
        return {"total_alerts": len(self._items), "by_severity": by}


