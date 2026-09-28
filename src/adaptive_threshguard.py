from __future__ import annotations

import time
from typing import Any, Dict


class AdaptiveThreshGuard:
    """Proposed extension of the paper's ThreshGuard logic.

    ORIGINAL PAPER LOGIC: metadata -> security score -> fixed threshold -> allow/deny -> security-level processing -> bottleneck
    PROPOSED EXTENSION: metadata -> security score -> context collection -> adaptive threshold -> adaptive penalty -> allow/deny/delay -> security-level processing -> bottleneck
    """

    def __init__(self, base_threshold: float = 0.6, alpha: float = 0.9, bottleneck_timeout: float = 0.05):
        self.base_threshold = base_threshold
        self.alpha = alpha
        self.bottleneck_timeout = bottleneck_timeout
        self.lock = False

    def compute_context_factor(self, row: Dict[str, Any]) -> float:
        trust = (float(row.get("user_trust", 0.5)) + float(row.get("application_trust", 0.5)) + float(row.get("device_trust", 0.5))) / 3.0
        sensitivity = {"LOW": 0.2, "MEDIUM": 0.5, "HIGH": 0.8}.get(row.get("security_level", "LOW"), 0.2)
        violation_rate = min(1.0, float(row.get("previous_violations", 0.0)) / 20.0)
        burst = float(row.get("burst_intensity", 0.0))
        request_rate = min(1.0, float(row.get("request_rate", 0.0)) / 100.0)
        time_factor = 0.5 if int(row.get("time_of_day", 12)) in range(0, 6) else 0.25 if int(row.get("time_of_day", 12)) in range(21, 24) else 0.1
        workload = (float(row.get("cpu_utilization", 0.0)) + float(row.get("memory_utilization", 0.0))) / 2.0
        normal_activity = 1.0 - max(0.0, (1.0 - trust))
        return 0.45 * (1.0 - trust) + 0.25 * sensitivity + 0.20 * violation_rate + 0.25 * burst + 0.15 * request_rate + 0.20 * time_factor + 0.15 * workload - 0.10 * normal_activity

    def compute_adaptive_threshold(self, row: Dict[str, Any]) -> float:
        base = self.base_threshold
        context_factor = self.compute_context_factor(row)
        threshold = base * (1.0 + context_factor)
        return float(max(0.15, min(threshold, 1.0)))

    def compute_security_score(self, row: Dict[str, Any]) -> float:
        trust = (float(row.get("user_trust", 0.5)) + float(row.get("application_trust", 0.5)) + float(row.get("device_trust", 0.5))) / 3.0
        risk = 1.0 - trust
        burst = float(row.get("burst_intensity", 0.0))
        rate = float(row.get("request_rate", 0.0)) / 100.0
        violation = float(row.get("previous_violations", 0.0)) / 25.0
        sensitivity = {"LOW": 0.2, "MEDIUM": 0.5, "HIGH": 0.8}.get(row.get("security_level", "LOW"), 0.2)
        score = 0.35 * risk + 0.2 * burst + 0.2 * rate + 0.15 * violation + 0.1 * sensitivity
        return max(0.0, min(score, 1.0))

    def compute_violation(self, access_rate: float, adaptive_threshold: float) -> float:
        return max(0.0, access_rate - adaptive_threshold)

    def compute_delay(self, penalty: float, sensitivity: str) -> float:
        sensitivity_multiplier = {"LOW": 0.75, "MEDIUM": 1.0, "HIGH": 1.35}.get(sensitivity, 1.0)
        return self.alpha * sensitivity_multiplier * penalty

    def process(self, row: Dict[str, Any]) -> Dict[str, Any]:
        data_id = row.get("data_id")
        operation = row.get("operation")
        principal = row.get("user_id")
        security_score = self.compute_security_score(row)
        adaptive_threshold = self.compute_adaptive_threshold(row)
        penalty = self.compute_violation(float(row.get("request_rate", 0.0)), adaptive_threshold)
        delay = self.compute_delay(penalty, row.get("security_level", "LOW"))
        provenance = {
            "data": {"data_id": data_id, "security_level": row.get("security_level", "LOW"), "operation": operation},
            "user/application": principal,
            "operation": operation,
            "timestamp": str(row.get("timestamp")),
            "event_type": "adaptive_threshold_applied",
        }

        if security_score < adaptive_threshold:
            provenance["event_type"] = "thresh_deny"
            return {
                "request_id": row.get("request_id"),
                "decision": "ACCESS_DENIED",
                "threshold": adaptive_threshold,
                "security_score": security_score,
                "penalty": penalty,
                "delay": delay,
                "queue_status": "none",
                "waiting_time": 0.0,
                "execution_time": 0.0,
                "cpu_utilization": row.get("cpu_utilization", 0.0),
                "memory_utilization": row.get("memory_utilization", 0.0),
                "provenance_event": provenance,
            }

        security_level = row.get("security_level", "LOW")
        if security_level == "LOW":
            provenance["event_type"] = "access_ok_low"
            return {
                "request_id": row.get("request_id"),
                "decision": "ACCESS_GRANTED",
                "threshold": adaptive_threshold,
                "security_score": security_score,
                "penalty": penalty,
                "delay": delay,
                "queue_status": "none",
                "waiting_time": 0.0,
                "execution_time": 0.0,
                "cpu_utilization": row.get("cpu_utilization", 0.0),
                "memory_utilization": row.get("memory_utilization", 0.0),
                "provenance_event": provenance,
            }

        start = time.perf_counter()
        if self.lock:
            elapsed = time.perf_counter() - start
            if elapsed > self.bottleneck_timeout:
                provenance["event_type"] = "queued_bottleneck"
                return {
                    "request_id": row.get("request_id"),
                    "decision": "QUEUED",
                    "threshold": adaptive_threshold,
                    "security_score": security_score,
                    "penalty": penalty,
                    "delay": delay,
                    "queue_status": "queued",
                    "waiting_time": float(self.bottleneck_timeout),
                    "execution_time": 0.0,
                    "cpu_utilization": row.get("cpu_utilization", 0.0),
                    "memory_utilization": row.get("memory_utilization", 0.0),
                    "provenance_event": provenance,
                }

        self.lock = True
        if security_level == "MEDIUM":
            pass
        elif security_level == "HIGH":
            pass

        provenance["event_type"] = "access_ok_medium" if security_level == "MEDIUM" else "access_ok_high"
        self.lock = False
        return {
            "request_id": row.get("request_id"),
            "decision": "ACCESS_GRANTED",
            "threshold": adaptive_threshold,
            "security_score": security_score,
            "penalty": penalty,
            "delay": delay,
            "queue_status": "none",
            "waiting_time": 0.0,
            "execution_time": time.perf_counter() - start,
            "cpu_utilization": row.get("cpu_utilization", 0.0),
            "memory_utilization": row.get("memory_utilization", 0.0),
            "provenance_event": provenance,
        }
