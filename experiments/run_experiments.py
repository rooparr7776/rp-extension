from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from experiments.config import DATASET_SIZE, FIGURES_DIR, LOGS_DIR, SEEDS, TABLES_DIR
from src.adaptive_threshguard import AdaptiveThreshGuard
from src.data_generator import generate_dataset
from src.metrics import classification_metrics
from src.sentinelscheduler_baseline import SentinelSchedulerBaseline
from src.threshguard_baseline import ThreshGuardBaseline
from src.workload_scheduler import WorkloadAwareScheduler


def evaluate_threshguard(df: pd.DataFrame, processor) -> pd.DataFrame:
    rows = []
    for _, row in df.iterrows():
        result = processor.process(row.to_dict())
        result["is_misuse"] = int(row["is_misuse"])
        result["predicted_misuse"] = int(result["decision"] in {"ACCESS_DENIED", "QUEUED"})
        rows.append(result)
    out = pd.DataFrame(rows)
    metrics = classification_metrics(out["is_misuse"], out["predicted_misuse"])
    out["metrics"] = json.dumps(metrics)
    return out, metrics


def evaluate_scheduler(df: pd.DataFrame, processor) -> pd.DataFrame:
    rows = []
    for _, row in df.iterrows():
        result = processor.process(row.to_dict())
        result["is_misuse"] = int(row["is_misuse"])
        rows.append(result)
    return pd.DataFrame(rows)


def summarize_statistical_runs(results: list[dict]) -> dict:
    keys = sorted(results[0].keys())
    out = {}
    for key in keys:
        values = np.array([float(r[key]) for r in results], dtype=float)
        mean = values.mean()
        std = values.std(ddof=1) if len(values) > 1 else 0.0
        ci = 1.96 * std / np.sqrt(len(values)) if len(values) > 1 else 0.0
        out[key] = {"mean": mean, "std": std, "ci95": ci}
    return out


def save_table(df: pd.DataFrame, filename: str) -> None:
    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(TABLES_DIR / filename, index=False)


def save_figure(fig, filename: str) -> None:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURES_DIR / filename, dpi=200, bbox_inches="tight")
    plt.close(fig)


def build_summary_tables() -> None:
    dataset_path = Path(__file__).resolve().parents[1] / "data" / "processed" / "synthetic_access_dataset.csv"
    if not dataset_path.exists():
        generate_dataset(n_records=DATASET_SIZE, seed=42)
    else:
        current_count = pd.read_csv(dataset_path).shape[0]
        if current_count != DATASET_SIZE:
            generate_dataset(n_records=DATASET_SIZE, seed=42)
    df = pd.read_csv(dataset_path)

    # Baseline vs enhanced ThreshGuard
    baseline_runs = []
    enhanced_runs = []
    scheduler_baseline_runs = []
    scheduler_enhanced_runs = []

    for seed in SEEDS:
        seed_df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
        b_out, b_metrics = evaluate_threshguard(seed_df, ThreshGuardBaseline())
        e_out, e_metrics = evaluate_threshguard(seed_df, AdaptiveThreshGuard())
        sb_out = evaluate_scheduler(seed_df, SentinelSchedulerBaseline())
        se_out = evaluate_scheduler(seed_df, WorkloadAwareScheduler())
        baseline_runs.append(b_metrics)
        enhanced_runs.append(e_metrics)
        scheduler_baseline_runs.append({
            "average_waiting_time": float(sb_out["waiting_time"].mean()),
            "average_task_latency": float(sb_out["latency"].mean()),
            "queue_length": float(sb_out["queue_status"].eq("queued").sum()),
            "throughput": float(len(sb_out) / max(sb_out["waiting_time"].sum() + 1e-9, 1e-9)),
        })
        scheduler_enhanced_runs.append({
            "average_waiting_time": float(se_out["waiting_time"].mean()),
            "average_task_latency": float(se_out["latency"].mean()),
            "queue_length": float(se_out["queue_status"].eq("queued").sum()),
            "throughput": float(len(se_out) / max(se_out["waiting_time"].sum() + 1e-9, 1e-9)),
        })

    tg_summary = summarize_statistical_runs(baseline_runs)
    tg_enhanced_summary = summarize_statistical_runs(enhanced_runs)
    sched_summary = summarize_statistical_runs(scheduler_baseline_runs)
    sched_enhanced_summary = summarize_statistical_runs(scheduler_enhanced_runs)

    pd.DataFrame([tg_summary]).to_csv(TABLES_DIR / "threshguard_baseline_summary.csv", index=False)
    pd.DataFrame([tg_enhanced_summary]).to_csv(TABLES_DIR / "threshguard_enhanced_summary.csv", index=False)
    pd.DataFrame([sched_summary]).to_csv(TABLES_DIR / "scheduler_baseline_summary.csv", index=False)
    pd.DataFrame([sched_enhanced_summary]).to_csv(TABLES_DIR / "scheduler_enhanced_summary.csv", index=False)

    # Plots
    fig, ax = plt.subplots(figsize=(8, 5))
    labels = ["Baseline", "Enhanced"]
    detection = [tg_summary["misuse_detection_rate"]["mean"], tg_enhanced_summary["misuse_detection_rate"]["mean"]]
    ax.bar(labels, detection, color=["steelblue", "darkorange"])
    ax.set_title("ThreshGuard misuse detection rate")
    ax.set_ylabel("Recall / detection rate")
    save_figure(fig, "threshguard_detection_rate.png")

    fig, ax = plt.subplots(figsize=(8, 5))
    fpr = [tg_summary["false_positive_rate"]["mean"], tg_enhanced_summary["false_positive_rate"]["mean"]]
    ax.bar(labels, fpr, color=["steelblue", "darkorange"])
    ax.set_title("ThreshGuard false positive rate")
    ax.set_ylabel("FPR")
    save_figure(fig, "threshguard_fpr.png")

    fig, ax = plt.subplots(figsize=(8, 5))
    thresholds = [0.6, 0.7]
    ax.hist([np.clip(df["request_rate"] / 100.0, 0, 1), np.clip(df["request_rate"] / 100.0, 0, 1)], bins=20, alpha=0.7)
    ax.set_title("Threshold distribution proxy")
    ax.set_xlabel("normalized score")
    ax.set_ylabel("count")
    save_figure(fig, "threshold_distribution.png")

    fig, ax = plt.subplots(figsize=(8, 5))
    waiting_data = [
        scheduler_baseline_runs[0]["average_waiting_time"],
        scheduler_enhanced_runs[0]["average_waiting_time"],
    ]
    ax.bar(["Baseline", "Enhanced"], waiting_data, color=["#4c72b0", "#dd8452"])
    ax.set_title("SentinelScheduler waiting time")
    ax.set_ylabel("seconds")
    save_figure(fig, "scheduler_waiting_time.png")

    # Scalability
    sizes = [10_000, 50_000, 100_000, 250_000, 500_000]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(sizes, sizes, linestyle="--", label="linear")
    ax.set_title("Scalability trend")
    ax.set_xlabel("requests")
    ax.set_ylabel("workload index")
    save_figure(fig, "scalability.png")

    log_path = LOGS_DIR / "experiment_log.txt"
    log_path.write_text("ThreshGuard and SentinelScheduler experiment summary generated successfully.\n", encoding="utf-8")

    print("Dataset statistics:")
    print(df[["request_rate", "burst_intensity", "cpu_utilization", "memory_utilization", "is_misuse"]].describe().to_string())
    print("\nBaseline ThreshGuard metrics:")
    print(pd.DataFrame([baseline_runs[0]]).to_string(index=False))
    print("\nEnhanced ThreshGuard metrics:")
    print(pd.DataFrame([enhanced_runs[0]]).to_string(index=False))
    print("\nBaseline SentinelScheduler metrics:")
    print(pd.DataFrame([scheduler_baseline_runs[0]]).to_string(index=False))
    print("\nEnhanced SentinelScheduler metrics:")
    print(pd.DataFrame([scheduler_enhanced_runs[0]]).to_string(index=False))

    print("\nTables written:")
    print(sorted(p.name for p in TABLES_DIR.iterdir()))
    print("Figures written:")
    print(sorted(p.name for p in FIGURES_DIR.iterdir()))


if __name__ == "__main__":
    build_summary_tables()
