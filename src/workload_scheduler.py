from __future__ import annotations

from typing import Any, Dict


class WorkloadAwareScheduler:
    """Proposed extension of the paper's SentinelScheduler.

    ORIGINAL PAPER LOGIC: idle-state check -> execute crypto task OR metadata-only OR queue.
    PROPOSED EXTENSION: idle-state check + workload score + task priority/urgency + queue/defer decisions.
    """

    def __init__(self):
        self.queue = []

    def compute_workload_score(self, row: Dict[str, Any]) -> float:
        cpu = float(row.get("cpu_utilization", 0.0))
        memory = float(row.get("memory_utilization", 0.0))
        queue_length = float(row.get("queue_length", 0.0))
        score = 0.5 * cpu + 0.3 * memory + 0.2 * min(1.0, queue_length / 50.0)
        return max(0.0, min(score, 1.0))

    def compute_task_priority_score(self, row: Dict[str, Any]) -> float:
        security_level_weight = {"LOW": 0.2, "MEDIUM": 0.5, "HIGH": 0.8}.get(row.get("security_level", "LOW"), 0.2)
        priority = float(row.get("task_priority", 1)) / 5.0
        urgency = float(row.get("task_urgency", 1)) / 6.0
        trust = float(row.get("application_trust", 0.5))
        crypto_cost = float(row.get("crypto_cost", 0.2))
        score = 0.25 * priority + 0.25 * urgency + 0.20 * security_level_weight + 0.15 * trust + 0.15 * crypto_cost
        return max(0.0, min(score, 1.0))

    def process(self, row: Dict[str, Any]) -> Dict[str, Any]:
        workload = self.compute_workload_score(row)
        task_priority = self.compute_task_priority_score(row)
        is_idle = bool(row.get("is_idle", 0))

        if is_idle:
            if workload < 0.55 and task_priority >= 0.45:
                decision = "EXECUTE_NOW"
                provenance = "task_executed_in_idle"
                queue_status = "none"
                waiting_time = 0.0
                execution_time = 0.0
            else:
                decision = "DEFER"
                provenance = "workload_deferred"
                queue_status = "deferred"
                waiting_time = 0.5
                execution_time = 0.0
        else:
            if task_priority >= 0.7 or row.get("security_level", "LOW") == "HIGH":
                decision = "PRIORITIZE"
                provenance = "priority_execution"
                queue_status = "prioritized"
                waiting_time = 0.2
                execution_time = 0.0
            else:
                decision = "QUEUE"
                provenance = "queued_for_idle"
                self.queue.append(row.get("request_id"))
                queue_status = "queued"
                waiting_time = 1.5
                execution_time = 0.0

        return {
            "request_id": row.get("request_id"),
            "decision": decision,
            "threshold": workload,
            "security_score": task_priority,
            "penalty": workload,
            "delay": waiting_time,
            "queue_status": queue_status,
            "waiting_time": waiting_time,
            "execution_time": execution_time,
            "cpu_utilization": row.get("cpu_utilization", 0.0),
            "memory_utilization": row.get("memory_utilization", 0.0),
            "provenance_event": {"request_id": row.get("request_id"), "event_type": provenance},
            "latency": waiting_time,
        }
