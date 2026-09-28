from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


def generate_dataset(n_records: int = 100_000, seed: int = 42, output_path: str | None = None) -> pd.DataFrame:
    rng = np.random.default_rng(seed)

    user_count = max(500, n_records // 20)
    app_count = 150
    device_count = 300
    data_count = 4000

    request_id = np.arange(1, n_records + 1)
    timestamp = pd.date_range("2024-01-01", periods=n_records, freq="5s")
    user_id = rng.integers(1, user_count + 1, size=n_records)
    application_id = rng.integers(1, app_count + 1, size=n_records)
    device_id = rng.integers(1, device_count + 1, size=n_records)
    data_id = rng.integers(1, data_count + 1, size=n_records)

    operation_choices = np.array(["READ", "WRITE", "DELETE", "APPEND"], dtype=object)
    operation = rng.choice(operation_choices, size=n_records)

    security_level_raw = rng.random(n_records)
    security_level = np.where(
        security_level_raw < 0.55,
        "LOW",
        np.where(security_level_raw < 0.9, "MEDIUM", "HIGH"),
    )

    # Correlate trust with application profile and attack activity.
    base_user_trust = rng.normal(loc=0.72, scale=0.12, size=n_records)
    suspect_user = rng.random(n_records) < 0.18
    base_user_trust[suspect_user] = rng.normal(loc=0.38, scale=0.12, size=suspect_user.sum())
    user_trust = np.clip(base_user_trust, 0.05, 0.99)

    base_app_trust = rng.normal(loc=0.68, scale=0.16, size=n_records)
    suspicious_app = rng.random(n_records) < 0.2
    base_app_trust[suspicious_app] = rng.normal(loc=0.31, scale=0.12, size=suspicious_app.sum())
    application_trust = np.clip(base_app_trust, 0.05, 0.99)

    device_trust = np.clip(rng.normal(loc=0.75, scale=0.13, size=n_records), 0.1, 0.99)
    suspicious_device_mask = rng.random(n_records) < 0.12
    device_trust[suspicious_device_mask] = np.clip(rng.normal(loc=0.35, scale=0.13, size=suspicious_device_mask.sum()), 0.05, 0.7)

    access_frequency = np.clip(rng.normal(loc=24.0, scale=10.0, size=n_records), 1.0, 200.0)
    request_rate = np.clip(0.5 * access_frequency + rng.normal(loc=0.0, scale=8.0, size=n_records), 0.1, 250.0)

    burst_intensity = np.clip(rng.normal(loc=0.32, scale=0.18, size=n_records), 0.0, 1.0)
    burst_intensity = np.clip(burst_intensity + 0.6 * (request_rate / request_rate.max()), 0.0, 1.0)

    previous_access_count = np.clip(rng.poisson(lam=12.0, size=n_records) + (request_rate / 3.0).astype(int), 0, 180)
    previous_violations = np.clip(rng.poisson(lam=1.4, size=n_records) + (1 - user_trust) * 5 + (1 - application_trust) * 3, 0, 40)

    time_of_day = rng.integers(0, 24, size=n_records)
    is_idle = ((time_of_day >= 0) & (time_of_day <= 5)) | ((time_of_day >= 21) & (time_of_day <= 23))
    is_idle = np.where(is_idle, 1, 0)

    cpu_utilization = np.clip(rng.normal(loc=0.45, scale=0.2, size=n_records), 0.05, 0.98)
    cpu_utilization = np.clip(cpu_utilization + 0.25 * (request_rate / 200.0), 0.05, 0.98)

    memory_utilization = np.clip(rng.normal(loc=0.48, scale=0.18, size=n_records), 0.05, 0.95)
    queue_length = np.clip(rng.poisson(lam=5.0, size=n_records) + (cpu_utilization * 10).astype(int), 0, 120)

    task_priority = rng.integers(1, 5, size=n_records)
    task_urgency = rng.integers(1, 6, size=n_records)
    crypto_cost = np.clip(rng.normal(loc=0.6, scale=0.22, size=n_records), 0.05, 1.0)
    crypto_cost[security_level == "HIGH"] = np.clip(crypto_cost[security_level == "HIGH"] + 0.25, 0.05, 1.0)

    attack_logit = (
        1.2 * (1.0 - user_trust)
        + 1.8 * (1.0 - application_trust)
        + 1.3 * (1.0 - device_trust)
        + 2.0 * burst_intensity
        + 1.5 * (np.clip(previous_violations / 30.0, 0, 1))
        + 1.0 * (np.clip(request_rate / 200.0, 0, 1))
        + 0.6 * (security_level == "HIGH")
    )
    attack_probability = 1 / (1 + np.exp(-(-3.2 + attack_logit)))
    attack_label = rng.random(n_records) < attack_probability

    is_misuse = attack_label.astype(int)
    access_duration = np.clip(rng.normal(loc=20.0, scale=8.0, size=n_records) + 15 * attack_label.astype(float), 1.0, 180.0)

    df = pd.DataFrame(
        {
            "request_id": request_id,
            "timestamp": timestamp,
            "user_id": user_id,
            "application_id": application_id,
            "device_id": device_id,
            "data_id": data_id,
            "operation": operation,
            "security_level": security_level,
            "user_trust": np.round(user_trust, 4),
            "application_trust": np.round(application_trust, 4),
            "device_trust": np.round(device_trust, 4),
            "access_frequency": np.round(access_frequency, 4),
            "request_rate": np.round(request_rate, 4),
            "burst_intensity": np.round(burst_intensity, 4),
            "previous_access_count": previous_access_count,
            "previous_violations": previous_violations,
            "time_of_day": time_of_day,
            "is_idle": is_idle.astype(int),
            "cpu_utilization": np.round(cpu_utilization, 4),
            "memory_utilization": np.round(memory_utilization, 4),
            "queue_length": queue_length,
            "task_priority": task_priority,
            "task_urgency": task_urgency,
            "crypto_cost": np.round(crypto_cost, 4),
            "attack_label": is_misuse,
            "is_misuse": is_misuse,
            "access_duration": np.round(access_duration, 4),
        }
    )

    output = Path(output_path) if output_path else Path(__file__).resolve().parents[1] / "data" / "processed" / "synthetic_access_dataset.csv"
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)
    return df
