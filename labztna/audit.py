"""Small in-memory audit sink for the local gateway lab.

Audit records intentionally contain identifiers and decisions only. Secrets,
raw requests, tokens, and payloads are never accepted by this API.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from threading import Lock
from typing import Any


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    event: str
    outcome: str
    subject: str | None = None
    resource: str | None = None
    device_id: str | None = None
    request_id: str | None = None
    detail: str | None = None


class AuditLog:
    """Bounded, thread-safe audit storage suitable for a disposable demo."""

    def __init__(self, max_events: int = 512) -> None:
        if not (1 <= max_events <= 100_000):
            raise ValueError("invalid audit log size")
        self._events: deque[AuditEvent] = deque(maxlen=max_events)
        self._lock = Lock()

    def record(
        self,
        event: str,
        outcome: str,
        *,
        subject: str | None = None,
        resource: str | None = None,
        device_id: str | None = None,
        request_id: str | None = None,
        detail: str | None = None,
    ) -> None:
        # Callers provide only bounded, non-secret labels. Truncate defensively
        # so a malformed client cannot exhaust the in-memory sink.
        item = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            event=str(event)[:64],
            outcome=str(outcome)[:32],
            subject=(str(subject)[:128] if subject is not None else None),
            resource=(str(resource)[:128] if resource is not None else None),
            device_id=(str(device_id)[:128] if device_id is not None else None),
            request_id=(str(request_id)[:128] if request_id is not None else None),
            detail=(str(detail)[:256] if detail is not None else None),
        )
        with self._lock:
            self._events.append(item)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [asdict(event) for event in self._events]

