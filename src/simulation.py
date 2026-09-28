from __future__ import annotations

from typing import Dict, List

import pandas as pd

from .adaptive_threshguard import AdaptiveThreshGuard
from .sentinelscheduler_baseline import SentinelSchedulerBaseline
from .threshguard_baseline import ThreshGuardBaseline
from .workload_scheduler import WorkloadAwareScheduler


def run_all_algorithms(df: pd.DataFrame) -> Dict[str, List[dict]]:
    baseline_tg = ThreshGuardBaseline()
    enhanced_tg = AdaptiveThreshGuard()
    baseline_sched = SentinelSchedulerBaseline()
    enhanced_sched = WorkloadAwareScheduler()

    results = {
        "baseline_threshguard": [],
        "enhanced_threshguard": [],
        "baseline_scheduler": [],
        "enhanced_scheduler": [],
    }

    for _, row in df.iterrows():
        results["baseline_threshguard"].append(baseline_tg.process(row))
        results["enhanced_threshguard"].append(enhanced_tg.process(row))
        results["baseline_scheduler"].append(baseline_sched.process(row))
        results["enhanced_scheduler"].append(enhanced_sched.process(row))

    return results
