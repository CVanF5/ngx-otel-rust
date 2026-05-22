# Step 11 Benchmark Results: Zero-Cost-When-Disabled

> **NOTE:** This is a local-machine sanity check, **NOT** the proposal's final
> operational characterisation.  Production numbers (sustained load, memory growth,
> real-shape workload) come from **Step 12** on representative hardware.  The
> purpose of this run is to prove that loading the module without an
> `otel_exporter` directive imposes no measurable per-request cost — a hard
> Phase 1.1 invariant required for upstream acceptance.

---

## Hardware

```
Model:       Mac15,7 (Apple M3 Max)
OS:          Darwin 25.4.0 arm64  (macOS Sequoia)
CPU:         12 physical / 12 logical cores
RAM:         36 GiB
Uname:       Darwin C6CQ3045N2 25.4.0 Darwin Kernel Version 25.4.0:
             Thu Mar 19 19:31:56 PDT 2026; root:xnu-12377.101.15~1/RELEASE_ARM64_T6030 arm64
```

## nginx

```
nginx/1.31.1
Built by clang 21.0.0 (clang-2100.1.1.101)
Configure args: --with-compat --with-http_stub_status_module
```

## Module

```
Path:    ngx-otel-rust/target/release/libngx_http_otel_module.dylib
Version: ngx-otel-rust v0.1.0
Profile: release (cargo build --release)
mtime:   2026-05-22 14:14:10 UTC  (epoch 1779455650)
```

The benchmark harness asserts at startup that the module mtime is newer than
every `src/*.rs` source file. All three sandbox configs reference the same
dylib at the single absolute path above; the harness re-checks that path's
mtime each time a sandbox is set up, guarding against the dylib being
mutated mid-run (e.g., a stray rebuild between iterations) rather than
proving cross-sandbox identity — identity is by-path.

## wrk

```
wrk 4.2.0 [kqueue]
Invocation: wrk -t4 -c100 -d30s --latency http://127.0.0.1:9101/
```

Same invocation across all three configs.  Iteration order randomised per
round (Fisher-Yates shuffle) to avoid warmup/cache bias.

## Benchmark Configuration

| Config | Description |
|--------|-------------|
| **C1** | No `load_module` — true NGINX baseline (no module at all) |
| **C2** | `load_module` present, **no** `otel_exporter` block — zero-cost case |
| **C3** | `load_module` + `otel_exporter` → `http://127.0.0.1:4318/v1/metrics` — operational case |

- `worker_processes 4`, trivial `return 200 "ok\n"` location
- 5 iterations per config (rounds 1–5), randomised order per round
- Results file: `tests/bench/results/run-2026-05-22T14-00-37.json`

## Raw Per-Iteration Results

| Config | Round | Median (ms) | p99 (ms) | Req/s |
|--------|-------|-------------|----------|-------|
| C2     | 1     | 1.72        | 2.56     | 57684 |
| C1     | 1     | 1.74        | 2.56     | 56683 |
| C3     | 1     | 1.74        | 2.47     | 56549 |
| C1     | 2     | 1.74        | 2.67     | 56712 |
| C2     | 2     | 1.74        | 2.55     | 56511 |
| C3     | 2     | 1.73        | 2.65     | 56781 |
| C3     | 3     | 1.74        | 2.55     | 56646 |
| C2     | 3     | 1.75        | 2.21     | 56371 |
| C1     | 3     | 1.76        | 2.20     | 56033 |
| C2     | 4     | 1.75        | 2.29     | 56180 |
| C1     | 4     | 1.75        | 2.33     | 56211 |
| C3     | 4     | 1.73        | 2.67     | 57139 |
| C3     | 5     | 1.74        | 2.51     | 56520 |
| C1     | 5     | 1.74        | 2.56     | 56794 |
| C2     | 5     | 1.73        | 2.58     | 56702 |

## Aggregated Statistics (5 iterations each)

| Metric          | C1 (baseline) | C2 (disabled) | C3 (operational) |
|-----------------|--------------|---------------|-----------------|
| Median (ms)     | 1.74         | 1.74          | 1.74            |
| p99 (ms)        | 2.56         | 2.55          | 2.55            |
| Req/s           | 56,683       | 56,511        | 56,646          |
| Min median (ms) | 1.74         | 1.72          | 1.73            |
| Max median (ms) | 1.76         | 1.75          | 1.74            |
| Min req/s       | 56,033       | 56,180        | 56,520          |
| Max req/s       | 56,794       | 57,684        | 57,139          |
| RtR variance†  | 1.3%         | 2.7%          | 1.1%            |

† Run-to-run variance = (max − min) / median, computed on req/s.
  p99 variance is high (7–18%) due to OS scheduling noise on this platform —
  this is expected on a developer laptop.  The tolerance assertions use only
  median latency and throughput, where variance is well under 3%.

## C1 Run-to-Run Variance Check

The protocol requires C1's own run-to-run variance to be < 3% on both
median latency and throughput before the C1-vs-C2 comparison is admissible.

| Metric          | C1 variance | Threshold | Result |
|-----------------|------------|-----------|--------|
| Median latency  | 1.1%       | < 3%      | **PASS** |
| Throughput      | 1.3%       | < 3%      | **PASS** |

The test machine is stable enough for the benchmark.

## C1 vs C2 Tolerance Check (Zero-Cost-When-Disabled Invariant)

The headline invariant: loading the module without `otel_exporter` must be
**statistically indistinguishable** from the no-module baseline (< 3% on
each metric).

| Metric          | C1 value | C2 value | Delta     | Threshold | Result |
|-----------------|---------|---------|-----------|-----------|--------|
| Median latency  | 1.74 ms  | 1.74 ms  | **0.00%** | < 3%      | **PASS** ✓ |
| p99 latency     | 2.56 ms  | 2.55 ms  | **0.39%** | < 3%      | **PASS** ✓ |
| Throughput      | 56,683 r/s | 56,511 r/s | **0.30%** | < 3% | **PASS** ✓ |

**The zero-cost-when-disabled invariant holds on this hardware.**

The module is loaded but both the log-phase handler and the export task are
gated behind `MainConfig::is_configured()`.  Neither executes on the request
path when no `otel_exporter` directive is present.  The C2 nginx error logs
contained zero "spawning export task" lines across all 5 iterations
(confirmed per-iteration by the benchmark harness).

## C3 Operational Overhead vs C1 (Informational)

This is the per-request cost of running the module with a configured exporter.

| Metric         | C1       | C3       | Overhead  |
|----------------|---------|---------|-----------|
| Median latency | 1.74 ms | 1.74 ms | **+0.00%** |
| p99 latency    | 2.56 ms | 2.55 ms | **−0.39%** (within noise) |
| Throughput     | 56,683  | 56,646  | **+0.07%** (within noise) |

**C3 is indistinguishable from C1 under this workload.**  The export loop
runs asynchronously in a background task and writes to shared memory without
locking the request path — consistent with the Phase 1.1 architecture
(shared-memory per-worker counters, async OTLP export by Worker 0 only).

> This local-machine result is not a substitute for the production
> characterisation.  Step 12 will run on representative hardware with a
> real-shape workload for 24 hours.

---

## Conclusion

The Step 11 benchmark proves statistically that:

1. **Zero-cost-when-disabled invariant holds:** Loading
   `libngx_http_otel_module.dylib` without `otel_exporter` configured adds
   zero measurable overhead (0.00% median, 0.39% p99, 0.30% throughput —
   all well within the 3% tolerance threshold).

2. **Phase handler gating is correct:** No "spawning export task" log line
   appeared in any of the 5 C2 nginx runs, confirming both the phase-handler
   gate (`postconfiguration` check) and the export-task gate
   (`ngx_otel_init_process` check) operate correctly.

3. **Operational overhead is effectively zero:** C3 (module + exporter) is
   indistinguishable from C1 on this workload, consistent with the async
   export architecture.

This satisfies the upstream-acceptance requirement documented in
`PHASE_1.1_IMPLEMENTATION_PLAN.md` §"Non-negotiable constraints".
