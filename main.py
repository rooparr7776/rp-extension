from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from experiments.config import FIGURES_DIR, TABLES_DIR
from src.adaptive_threshguard import AdaptiveThreshGuard
from src.data_generator import generate_dataset
from src.metrics import classification_metrics
from src.sentinelscheduler_baseline import SentinelSchedulerBaseline
from src.threshguard_baseline import ThreshGuardBaseline
from src.workload_scheduler import WorkloadAwareScheduler


ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "data" / "processed" / "synthetic_access_dataset.csv"


def evaluate_threshguard(df: pd.DataFrame, processor):
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


def evaluate_scheduler(df: pd.DataFrame, processor):
    rows = []
    for _, row in df.iterrows():
        result = processor.process(row.to_dict())
        result["is_misuse"] = int(row["is_misuse"])
        rows.append(result)
    return pd.DataFrame(rows)


def save_outputs(df: pd.DataFrame, baseline_threshguard, enhanced_threshguard, baseline_scheduler, enhanced_scheduler):
    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    baseline_df = pd.DataFrame(baseline_threshguard)
    enhanced_df = pd.DataFrame(enhanced_threshguard)
    baseline_sched_df = pd.DataFrame(baseline_scheduler)
    enhanced_sched_df = pd.DataFrame(enhanced_scheduler)

    baseline_df.to_csv(TABLES_DIR / "baseline_threshguard_results.csv", index=False)
    enhanced_df.to_csv(TABLES_DIR / "enhanced_threshguard_results.csv", index=False)
    baseline_sched_df.to_csv(TABLES_DIR / "baseline_scheduler_results.csv", index=False)
    enhanced_sched_df.to_csv(TABLES_DIR / "enhanced_scheduler_results.csv", index=False)

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(["Baseline", "Enhanced"], [baseline_df["decision"].str.contains("DENIED|QUEUED").sum(), enhanced_df["decision"].str.contains("DENIED|QUEUED").sum()], color=["#4c72b0", "#dd8452"])
    ax.set_title("Access-control blocking decisions")
    ax.set_ylabel("count")
    fig.savefig(FIGURES_DIR / "access_control_summary.png", dpi=200, bbox_inches="tight")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(["Baseline", "Enhanced"], [baseline_sched_df["waiting_time"].mean(), enhanced_sched_df["waiting_time"].mean()], color=["#4c72b0", "#dd8452"])
    ax.set_title("Scheduler waiting time")
    ax.set_ylabel("seconds")
    fig.savefig(FIGURES_DIR / "scheduler_waiting_time.png", dpi=200, bbox_inches="tight")
    plt.close(fig)

    print("Dataset rows:", len(df))
    print("Misuse rate:", round(df["is_misuse"].mean(), 4))
    print("Baseline ThreshGuard metrics:", baseline_df.iloc[0].to_dict())
    print("Enhanced ThreshGuard metrics:", enhanced_df.iloc[0].to_dict())
    print("Baseline SentinelScheduler metrics:", baseline_sched_df.iloc[0].to_dict())
    print("Enhanced SentinelScheduler metrics:", enhanced_sched_df.iloc[0].to_dict())


def run_pipeline():
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not DATASET_PATH.exists():
        df = generate_dataset(n_records=100_000, seed=42, output_path=str(DATASET_PATH))
    else:
        df = pd.read_csv(DATASET_PATH)

    base_rows = []
    enh_rows = []
    base_sched_rows = []
    enh_sched_rows = []

    for _, row in df.iterrows():
        base_rows.append(ThreshGuardBaseline().process(row.to_dict()))
        enh_rows.append(AdaptiveThreshGuard().process(row.to_dict()))
        base_sched_rows.append(SentinelSchedulerBaseline().process(row.to_dict()))
        enh_sched_rows.append(WorkloadAwareScheduler().process(row.to_dict()))

    save_outputs(df, base_rows, enh_rows, base_sched_rows, enh_sched_rows)
    print("Project run complete.")


if __name__ == "__main__":
    run_pipeline()
