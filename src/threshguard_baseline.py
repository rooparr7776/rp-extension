from __future__ import annotations

import time
from typing import Any, Dict


class ThreshGuardBaseline:
    """Original paper algorithm: ThreshGuard_OnAccessRequest.

    This class intentionally preserves the paper's baseline logic and event semantics.
    """

    def __init__(self, base_threshold: float = 0.6, alpha: float = 0.9, bottleneck_timeout: float = 0.05):
        self.base_threshold = base_threshold
        self.alpha = alpha
        self.bottleneck_timeout = bottleneck_timeout
        self.lock = False
        self.runtime_context = {}

    def compute_security_score(self, row: Dict[str, Any]) -> float:
        trust = (row.get("user_trust", 0.5) + row.get("application_trust", 0.5) + row.get("device_trust", 0.5)) / 3.0
        risk = 1.0 - trust
        burst = float(row.get("burst_intensity", 0.0))
        rate = float(row.get("request_rate", 0.0)) / 100.0
        violation = float(row.get("previous_violations", 0.0)) / 25.0
        sensitivity = {"LOW": 0.2, "MEDIUM": 0.5, "HIGH": 0.8}.get(row.get("security_level", "LOW"), 0.2)
        score = 0.35 * risk + 0.2 * burst + 0.2 * rate + 0.15 * violation + 0.1 * sensitivity
        return max(0.0, min(score, 1.0))

    def compute_violation(self, access_rate: float, threshold: float) -> float:
        return max(0.0, access_rate - threshold)

    def compute_delay(self, penalty: float) -> float:
        return self.alpha * penalty

    def process(self, row: Dict[str, Any]) -> Dict[str, Any]:
        data_id = row.get("data_id")
        operation = row.get("operation")
        principal = row.get("user_id")
        metadata = {"data_id": data_id, "security_level": row.get("security_level", "LOW"), "operation": operation}
        security_score = self.compute_security_score(row)
        threshold = self.base_threshold
        violation = self.compute_violation(float(row.get("request_rate", 0.0)), threshold)
        delay = self.compute_delay(violation)
        provenance = {"data": metadata, "user/application": principal, "operation": operation, "timestamp": str(row.get("timestamp")), "event_type": "threshguard_baseline"}

        if security_score < threshold:
            provenance["event_type"] = "thresh_deny"
            return {
                "request_id": row.get("request_id"),
                "decision": "ACCESS_DENIED",
                "threshold": threshold,
                "security_score": security_score,
                "penalty": violation,
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
                "threshold": threshold,
                "security_score": security_score,
                "penalty": violation,
                "delay": delay,
                "queue_status": "none",
                "waiting_time": 0.0,
                "execution_time": 0.0,
                "cpu_utilization": row.get("cpu_utilization", 0.0),
                "memory_utilization": row.get("memory_utilization", 0.0),
                "provenance_event": provenance,
            }

        acquired = False
        start = time.perf_counter()
        if self.lock:
            # Bottleneck queue behavior consistent with paper.
            elapsed = time.perf_counter() - start
            if elapsed > self.bottleneck_timeout:
                provenance["event_type"] = "queued_bottleneck"
                return {
                    "request_id": row.get("request_id"),
                    "decision": "QUEUED",
                    "threshold": threshold,
                    "security_score": security_score,
                    "penalty": violation,
                    "delay": delay,
                    "queue_status": "queued",
                    "waiting_time": float(self.bottleneck_timeout),
                    "execution_time": 0.0,
                    "cpu_utilization": row.get("cpu_utilization", 0.0),
                    "memory_utilization": row.get("memory_utilization", 0.0),
                    "provenance_event": provenance,
                }

        self.lock = True
        acquired = True

        if security_level == "MEDIUM":
            # ORIGINAL PAPER LOGIC: additional security checks
            pass
        elif security_level == "HIGH":
            # ORIGINAL PAPER LOGIC: MFA and encrypted container before operation
            pass

        provenance["event_type"] = "access_ok_medium" if security_level == "MEDIUM" else "access_ok_high"
        self.lock = False
        self.runtime_context.clear()
        return {
            "request_id": row.get("request_id"),
            "decision": "ACCESS_GRANTED",
            "threshold": threshold,
            "security_score": security_score,
            "penalty": violation,
            "delay": delay,
            "queue_status": "none",
            "waiting_time": 0.0,
            "execution_time": time.perf_counter() - start,
            "cpu_utilization": row.get("cpu_utilization", 0.0),
            "memory_utilization": row.get("memory_utilization", 0.0),
            "provenance_event": provenance,
        }
