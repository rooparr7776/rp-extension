from __future__ import annotations

import numpy as np
import pandas as pd


def safe_divide(num: float, den: float) -> float:
    return num / den if den else 0.0


def classification_metrics(y_true: pd.Series, y_pred: pd.Series) -> dict:
    y_true = y_true.astype(int)
    y_pred = y_pred.astype(int)

    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())

    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    f1 = safe_divide(2 * precision * recall, precision + recall)
    false_positive_rate = safe_divide(fp, fp + tn)
    false_negative_rate = safe_divide(fn, fn + tp)
    misuse_detection_rate = recall

    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "misuse_detection_rate": misuse_detection_rate,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
    }


def summarize_numeric(df: pd.DataFrame, field: str) -> dict:
    series = df[field].replace([np.inf, -np.inf], np.nan).dropna()
    if series.empty:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0}
    return {
        "mean": float(series.mean()),
        "std": float(series.std(ddof=1)) if len(series) > 1 else 0.0,
        "min": float(series.min()),
        "max": float(series.max()),
    }


def aggregate_results(df: pd.DataFrame) -> dict:
    out = {}
    for col in ["decision_score", "threshold", "penalty", "delay", "waiting_time", "execution_time", "cpu_utilization", "memory_utilization"]:
        if col in df.columns:
            out[col] = summarize_numeric(df, col)
    return out
