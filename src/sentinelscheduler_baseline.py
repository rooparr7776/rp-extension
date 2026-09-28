from __future__ import annotations

from typing import Any, Dict


class SentinelSchedulerBaseline:
    """Original paper algorithm: SentinelScheduler.

    This class keeps the original idle-slot scheduling and metadata-only queueing flow.
    """

    def __init__(self):
        self.app_profiles = {}
        self.idle_slots = {}
        self.queue = []

    def analyze_application(self, row: Dict[str, Any]) -> Dict[str, Any]:
        app_id = row.get("application_id")
        trust = float(row.get("application_trust", 0.5))
        level = row.get("security_level", "LOW")
        return {
            "app_id": app_id,
            "trust_score": trust,
            "security_level": level,
        }

    def process(self, row: Dict[str, Any]) -> Dict[str, Any]:
        app_id = row.get("application_id")
        app_profile = self.analyze_application(row)
        self.app_profiles[app_id] = app_profile

        if row.get("is_idle", 0) == 1:
            decision = "EXECUTE_NOW"
            provenance = "decrypted_during_idle"
            queue_status = "none"
            waiting_time = 0.0
            execution_time = 0.0
            latency = 0.0
        else:
            if row.get("security_level", "LOW") == "LOW":
                decision = "ACCESS_GRANTED"
                provenance = "metadata_sent"
                queue_status = "none"
                waiting_time = 0.0
                execution_time = 0.0
                latency = 0.0
            else:
                decision = "QUEUED"
                provenance = "queued_for_idle"
                queue_status = "queued"
                self.queue.append(row.get("request_id"))
                waiting_time = 1.0
                execution_time = 0.0
                latency = 1.0

        return {
            "request_id": row.get("request_id"),
            "decision": decision,
            "threshold": 0.0,
            "security_score": 0.0,
            "penalty": 0.0,
            "delay": 0.0,
            "queue_status": queue_status,
            "waiting_time": waiting_time,
            "execution_time": execution_time,
            "cpu_utilization": row.get("cpu_utilization", 0.0),
            "memory_utilization": row.get("memory_utilization", 0.0),
            "provenance_event": {"request_id": row.get("request_id"), "event_type": provenance},
            "latency": latency,
        }
