# Context-Aware ThreshGuard and Workload-Aware SentinelScheduler

## 1. Original paper architecture

This project implements the two baseline algorithms described in the provided source material:

- ThreshGuard_OnAccessRequest
- SentinelScheduler

The original paper architecture is built around a security gate for access requests and an idle-slot scheduler for deferred crypto-heavy tasks. The two mechanisms are complementary: the access-control layer blocks or delays dangerous requests, while the scheduler opportunistically performs crypto operations during periods of low system activity.

## 2. Original ThreshGuard algorithm

The existing algorithm from the paper is treated as the baseline. Its structure is:

1. Retrieve metadata for the target data object.
2. Compute a security score from metadata, requester, operation, and runtime context.
3. Compare the score to the threshold for the requested operation.
4. If the score is below threshold, deny access and record a provenance event.
5. If the data is low security, allow direct access.
6. If the data is medium or high security, acquire a bottleneck lock and serialize access.
7. Apply additional checks for medium security and stronger controls for high security.
8. Release the lock, clean context, and log completion.

The paper also defines threshold violation and delay as:

- P(t) = max(0, r(t) - T)
- D_s = alpha * P(t)

where r(t) is the current access rate, T is the allowed threshold, and alpha controls delay growth.

## 3. Original SentinelScheduler algorithm

The original scheduler is also preserved as the baseline. It has three phases:

1. Application analysis and idle-slot identification.
2. Application access request handling.
3. Idle-slot task execution.

In the baseline, trust, security level, and learned idle periods determine whether a task is executed immediately, sent as metadata-only, or queued for the next idle slot. The core idea is not replaced; rather, the enhanced versions add workload-aware and context-aware decisions while preserving the original idle-slot logic.

## 4. Limitations motivating the extensions

The baseline algorithms are effective but limited in realistic runtime environments where:

- trust differs across applications and devices,
- access bursts can appear benign or malicious depending on context,
- repeated violations should influence future thresholds,
- system load affects whether a crypto task should be deferred or executed,
- priority and urgency should matter when queue pressure grows.

## 5. Proposed Context-Aware ThreshGuard

This project implements a proposed extension, not a replacement of the original paper algorithm. The extension keeps the same conceptual flow from the paper:

Existing algorithm from the paper:
metadata -> security score -> fixed threshold -> allow/deny -> security-level processing -> bottleneck

Proposed extension implemented here:
metadata -> security score -> context collection -> adaptive threshold -> adaptive penalty -> allow/deny/delay -> security-level processing -> bottleneck

The adaptive threshold is defined as:

T_adaptive = T_base * (1 + w_trust * (1 - trust) + w_device * (1 - device_trust) + w_sensitivity * sensitivity + w_history * violation_rate + w_burst * burst_intensity + w_time * time_factor) - w_safe * normal_activity

This is then used to compute the violation and delay:

P(t) = max(0, r(t) - T_adaptive)
D_s = alpha * P(t)

The original paper's bottleneck lock remains active.

## 6. Proposed Workload-Aware SentinelScheduler

The scheduler maintains the original idle-slot concept. The enhancement adds workload awareness and priority handling without removing idle-time scheduling.

The original scheduler: is the system idle? yes -> run crypto task, no -> metadata-only or queue.

The enhanced version: is the system idle? yes -> consider workload and task priority; no -> compute workload and urgency; if the task is high urgency or high-risk, allow prioritized execution; otherwise queue or defer.

## 7. Exact differences between baseline and proposed algorithms

The exact distinction in this project is:

- Baseline files are the original paper logic and keep the original semantics.
- Proposed files extend only the threshold decision and scheduling decision while preserving the rest of the paper's flow.

Baseline vs proposed:

- Baseline ThreshGuard uses a fixed threshold and fixed delay.
- Proposed ThreshGuard uses adaptive threshold + adaptive penalty based on runtime context.
- Baseline SentinelScheduler uses idle-slot checks primarily.
- Proposed SentinelScheduler adds CPU, memory, queue length, task priority, urgency, and cryptographic cost to the decision.

## 8. Synthetic dataset generation

The synthetic dataset is not a real IoT dataset. It follows the same behavioral mapping described in the paper:

- packet/flow frequency -> storage access frequency r(t)
- burst traffic -> burst read/write behavior
- session duration -> access duration
- attack label -> unauthorized or suspicious access
- connection anomalies -> suspicion/security score
- benign traffic -> normal access patterns

It contains 100,000 records and correlates trust, burst intensity, previous violations, and request rate with maliciousness.

## 9. Network-to-storage behavioral mapping

The synthetic generation deliberately mirrors the networking concepts used in the paper:

- access frequency is mapped from packet/flow frequency,
- burst intensity from burst traffic,
- access duration from session duration,
- attack labels from attack labels,
- security score from anomaly features.

## 10. Experimental methodology

The project evaluates all implementations on the same synthetic dataset. The experiments include:

- ThreshGuard baseline vs enhanced
- security levels low/medium/high
- workload settings low/medium/high
- trust settings low/medium/high
- SentinelScheduler baseline vs enhanced
- CPU and queue-load scenarios
- scalability from 10K up to 500K requests
- ablation studies
- 5 random seeds with mean, standard deviation, and 95% confidence intervals

## 11. Metrics

The implementations record:

- misuse detection rate
- false positive rate
- false negative rate
- precision
- recall
- F1
- number of denied requests
- number of queued requests
- average delay
- average response time
- average waiting time
- average task latency
- throughput
- queue length
- CPU utilization
- memory utilization
- priority task completion

## 12. Ablation study

For enhanced ThreshGuard, the project compares:

A. Original ThreshGuard
B. + trust awareness
C. + trust + sensitivity
D. + trust + sensitivity + access history
E. Full context-aware version

For enhanced SentinelScheduler, the project compares:

A. Original idle-time scheduler
B. + CPU awareness
C. + CPU + memory
D. + CPU + memory + queue
E. Full workload + priority + urgency version

## 13. Statistical validation

The experiments are run across at least 5 random seeds. Results are summarized using:

- mean
- standard deviation
- 95% confidence interval

## 14. Limitations

This is a simulation study. The synthetic dataset is intentionally designed to mirror realistic relationships but is not an empirical deployment trace. The project is intended as a reproducible comparative study of the paper's baseline algorithms and the proposed extensions.

## 15. Reproducibility

The project is organized to be repeatable:

- the same dataset is shared across all algorithms,
- random seeds are controlled,
- all runs write results to the results folder,
- figures and tables are produced automatically.

## Proposed algorithm summary

This project implements the original paper algorithm as the baseline and extends it in two targeted ways:

- Context-Aware Enhanced ThreshGuard extends threshold selection and penalty computation with trust, sensitivity, history, burst activity, time context, and workload factors.
- Workload-Aware Enhanced SentinelScheduler extends the idle-slot scheduler with workload-aware execution decisions and task priority/urgency handling.

The baseline algorithms remain available for comparison and are not replaced.
