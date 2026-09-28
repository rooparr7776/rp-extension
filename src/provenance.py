from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List


class ProvenanceLogger:
    """Collects provenance events for each request as in the paper."""

    def __init__(self):
        self.events: List[Dict[str, Any]] = []

    def log(self, request_id: Any, event_type: str, data: Dict[str, Any]) -> None:
        record = {"request_id": request_id, "event_type": event_type}
        record.update(data)
        self.events.append(record)

    def get_events_for(self, request_id: Any) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["request_id"] == request_id]

    def clear(self) -> None:
        self.events.clear()


class ProvenanceFactory:
    """Utility to build provenance events in a consistent paper-inspired format."""

    @staticmethod
    def event(request_id: Any, event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        event = {"request_id": request_id, "event_type": event_type}
        event.update(data)
        return event
