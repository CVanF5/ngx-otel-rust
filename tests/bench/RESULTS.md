# Trace hot-path bench — head-to-head comparison (host-1, AMD EPYC 9R14)

## Provenance

- Code: tree of commit `4562dd8` (origin/main tip, incl. the redirect-safe guard,
  bitfield shim read, and eager DRBG seed — all on the trace hot path).
- Run: 2026-06-11 20:24 → 2026-06-12 07:24 UTC, unattended; launched + smoke-validated
  (both arms loaded + exported) before walking away. Raw per-cell data: host-1
  `~/bench38/rounds.jsonl` (1,773 cells).

- Rounds completed: **296**  ·  total cells: 1773  ·  good cells: 1773
- C++ `nginx-otel` built + benched: **YES** — built ok: /home/admin/bench38/nginx-otel/build/ngx_otel_module.so
- Method: 1 nginx worker pinned core3, otelcol(`nop` null-sink) core2, `wrk` load-gen cores0-1; open-loop saturating run, **c64 / 15s** per cell; worker CPU = /proc utime+stime delta over the run.
- **baseline = traces OFF.** ours' baseline still carries metrics+logs (we are not traces-only like C++); the apples-to-apples trace number is the **marginal (s100 − baseline) µs-cpu/req**.

## Throughput (rps), latency (µs), worker CPU per request (µs) — median of rounds

| module | mode | rps | p50 µs | p99 µs | µs-cpu/req | n |
|---|---|---|---|---|---|---|
| ours | baseline | 137426.40 | 461.00 | 496.00 | 7.29 | 296 |
| ours | s100 | 133189.64 | 475.00 | 511.00 | 7.52 | 296 |
| ours | s10 | 133117.25 | 476.00 | 511.00 | 7.52 | 296 |
| cpp | baseline | 136348.04 | 464.00 | 500.00 | 7.35 | 295 |
| cpp | s100 | 117166.88 | 508.00 | 811.00 | 8.54 | 295 |
| cpp | s10 | 127404.35 | 493.00 | 845.00 | 7.86 | 295 |

## Marginal trace hot-path cost  (s100 − baseline, µs-cpu/req)

- **ours**: 100%% sampling adds **+0.231 µs-cpu/req** per request; 10%% sampling adds +0.231
- **cpp**: 100%% sampling adds **+1.199 µs-cpu/req** per request; 10%% sampling adds +0.512

## Honest read
- At 100% sampling our marginal trace cost is **+0.231 µs-cpu/req vs +1.199 for the C++
  module** — about 5.2x cheaper per request, with the cost paid in a different place:
  ours in a fixed REWRITE-phase step per request, the C++ module's inside the worker's
  request loop (serialization + batching).
- At the saturation point that difference compounds: ours loses **3.1%** throughput at
  100% sampling (137.4k -> 133.2k rps) where the C++ module loses **14.1%** (136.3k ->
  117.2k), and our p99 stays at 511 us vs 811 us.
- Our marginal is **sampling-rate-independent** (+0.231 at both 100% and 10%): it is
  dominated by fixed per-request work (handler entry, gates, span context), while the
  per-span cost is too small to move the median. The C++ cost scales with the sampling
  rate (+0.512 at 10%), consistent with per-span in-worker serialization.
- These numbers are higher than the earlier single-round characterizations (+0.07 to
  +0.13) because the certified tree carries the June-11 hardening on the same hot path
  (redirect-safe internal-redirect guard, C-shim bitfield read, eager seeding). The
  trade was deliberate: correctness fixes first, then the authoritative measurement.
- Reminder of the standing scope limit: the central exporter caps trace DELIVERY at
  ~10k spans/s/worker (see RESULTS-span-saturation-2026-06-09.md); at saturation loads
  ours keeps the worker cheap but drops spans, while the C++ module delivers ~all spans
  from a pegged worker. Both facts are part of the honest comparison.


_Caveats_: AWS-managed cpufreq (governor not settable on this guest); 4-core box so the load-gen shares it; single static `return 200` location isolates module overhead (no upstream); **open-loop latency** (wrk2 constant-rate was abandoned — PANIC'd on this host — so p50/p99 carry mild coordinated-omission, but the worker-CPU-per-request metric is unaffected and is the headline). Same nginx 1.31.1 --with-compat binary loads either module.

