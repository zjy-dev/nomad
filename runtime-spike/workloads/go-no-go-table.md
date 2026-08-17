# RT-001 go/no-go and nonregression gates

Frozen at preregistration. These are the gates RT-005 must pass before
RT-006 can issue a GO. The runtime must pass **all** gates for a GO.

## 1. Hard gates

These gates are pass/fail, not comparative. The runtime must satisfy
them unconditionally.

| Gate ID | Condition | Reason |
| --- | --- | --- |
| G-001 | 100% conformance with preregistered fixture set | A mismatch invalidates every later claim. |
| G-002 | `ws-recovery-100k` completes without data loss or unknown gaps | Recovery correctness is a blocker even if every other gate passes. |
| G-003 | `ws-long-session-rss` shows no net RSS growth between hour 4 and hour 8 | A leak in long sessions disqualifies the runtime. |
| G-004 | All `seq` values are strictly monotonic; no gap larger than one `seq` is ever silently skipped | Invariant required by Session Semantics v0. |
| G-005 | `ws-cold-start` p95 <= 300 ms | Absolute ceiling, not relative to baseline. |
| G-006 | `ws-append-durable` throughput >= 5000 events/s with p95 <= 1 ms | Absolute floor. |
| G-007 | `ws-sidecar-ipc` overhead < 5% of end-to-end command latency | IPC tax must remain negligible. |

## 2. Comparative gates

These gates compare runtime against the OpenCode baseline measured under
the same PRAGMA. At least one of CG-001 or CG-002 must be a net win.

| Gate ID | Condition | Purpose |
| --- | --- | --- |
| CG-001 (2x gate) | `ws-recovery-100k` runtime is **2x or faster** than baseline OR `ws-append-durable` runtime is **2x or faster** than baseline | At least one workload must show a decisive throughput win. |
| CG-002 (40% gate) | `ws-long-session-rss` peak RSS is **>= 40% lower** than baseline OR `ws-cold-start` peak RSS is **>= 40% lower** than baseline | OR-clause: either RSS win qualifies. |
| CG-003 (nonregression) | No workload in the preregistered set regresses by more than its budget | See section 3 for per-workload budgets. |

## 3. Per-workload nonregression budgets

These are relative to the OpenCode baseline. A regression within budget
is allowed once and only once — RT-005 must explain it in the report.

| Workload ID | Allowed regression |
| --- | --- |
| ws-cold-start | +20% |
| ws-recovery-100k | +15% |
| ws-append-durable | +10% |
| ws-long-session-rss | +15% on peak; +10% on slope |
| ws-sidecar-ipc | strict nonregression (0%) |

## 4. Gate combinations

A **GO** decision requires:

1. All hard gates G-001 through G-007 pass.
2. At least one of CG-001 or CG-002 passes.
3. CG-003 passes for every workload.

A **NO-GO** decision is automatic if:

- Any hard gate fails.
- Both CG-001 and CG-002 fail.
- CG-003 fails for any workload.

A **CONDITIONAL GO** decision is allowed only if:

- All hard gates pass.
- CG-003 passes.
- At least one of CG-001 or CG-002 nearly passes (>= 1.6x or >= 35%, but not 2x / 40%).
- A written mitigation plan is attached to RT-006.

## 5. What is explicitly NOT a gate

- "The runtime feels faster" — all gates are objective.
- "The runtime uses less code" — line count is not a gate.
- "The runtime would be easier to maintain" — maintainability is evaluated in RT-006, not here.
- Any improvement in an unpreregistered workload.
- Any comparison using a different OpenCode release than the one in `preregistered.yaml`.
- Any comparison using different SQLite PRAGMA than the baseline.
- Results from a single run without variance quantification.

## 6. Measurement rules

- Report p50, p95, p99 for every latency workload; mean is reported but not a gate.
- Report peak RSS, RSS delta between hour 4 and hour 8, and resident vs virtual split for RSS workloads.
- Report CPU time (user + system), allocation count, and I/O bytes for every workload.
- Run each workload at least 5 times; drop the fastest and slowest; report median of the remaining 3.
- macOS runs on Apple Silicon only; do not mix x86 and ARM numbers in one report.