# Span saturation bench — central-exporter trace-delivery ceiling

**Date:** 2026-06-09 · **Host:** host-1 (AWS c7a EPYC, 4 vCPU) · **Goal:** find where the
central `nginx: otel exporter` stops keeping up with sampled spans (the "knee"), and *why*.

## Headline

At 100 % sampling a **single worker** offers ~135 k spans/s, but the exporter **delivers a flat
~10 k spans/s** and drops the rest (~93 %) — while sitting at **2 % CPU**. The ceiling is **not**
encode/CPU, **not** the ring size, and **not** the metric interval. It is a deliberate, co-sized
**per-drain budget**:

> spans drain every **250 ms** (`SHUTDOWN_POLL_INTERVAL`); each drain reads at most
> **2 500 spans/worker** (`MAX_SPAN_RECORDS_PER_WORKER_PER_DRAIN`) and is independently bounded by
> the **256 KiB** per-worker ring (`DEFAULT_SPAN_RING_CAP` ≈ 2 500 spans). The two limiters are
> co-sized to ~2 500 → **2 500 × 4 drains/s ≈ 10 k spans/s/worker**.

The hot path stays graceful: even at 93 % drop, worker p99 is unaffected by the span machinery
(drop-on-full is cheap; no backpressure to the request). The cap is on *delivery*, not on serving.

## Provenance / honesty notes

- **Bench build:** the host-1 rsync checkout (pre-promote: `splitmix64` IDs, and — importantly —
  **predating P3**, so it does *not* export `ngx_otel.traces.dropped_records`). Delivery was
  therefore measured at the **collector** (`otelcol_receiver_accepted_spans`), not from the module.
- **Applies to shipped code:** the three limiting constants are **byte-identical** in
  `origin/main` @ `51902e6` — `SHUTDOWN_POLL_INTERVAL=250ms` (`export/mod.rs:136`),
  `MAX_SPAN_RECORDS_PER_WORKER_PER_DRAIN=2_500` (`:1581`), `DEFAULT_SPAN_RING_CAP=256*1024`
  (`shm.rs:1077`). So the ~10 k/s/worker ceiling is the **current** behaviour.
- **Drops are observable on `origin/main`** (unlike the bench build): `ngx_otel.traces.dropped_records`
  is emitted (`export/mod.rs:310`, asserted at `:2035`). An operator on shipped code *can* see the
  ~93 % drop directly; the bench measured it indirectly only because its build is pre-P3.
- **Single worker / 4 cores:** host-1's 4 vCPU mean one worker already pegs the *offered* side at
  ~135 k req/s, so multi-worker fan-in onto one exporter was **not** measured (needs a bigger host).
- 100 % sampling **confirmed**: `span_start.rs:162` (root spans → `sampled=true`) + a controlled
  2 000-sequential-request run delivered exactly **2 000** spans (no sampling loss, no drops at low rate).

## Method

- nginx: 1 worker pinned core 3, `otel_trace on` + `otel_trace_context ignore` (root spans → 100 %),
  `otel_export_protocol otlp_grpc` → local otelcol.
- otelcol-contrib 0.153.0 pinned core 2; OTLP/gRPC receiver; traces → `nop` (fast sink, isolates the
  exporter's drain/encode/send); delivered counted via `otelcol_receiver_accepted_spans` self-telemetry.
- `wrk` on cores 0–1. (`wrk2 -R` rate control **panics** on this host — known; so offered rate was
  swept via `-c`, which is worker-bound at ~135 k regardless of connections.)
- delivered/s = Δ`receiver_accepted_spans` / window; drop % = (offered − delivered)/offered.

## Results

### Load sweep (default build, `otel_metric_interval 1s`)
| conns | offered rps | delivered/s | drop % | exporter CPU % | worker p99 |
|------:|------------:|------------:|-------:|---------------:|-----------:|
| 4     | 128 787     | 9 500       | 92.6   | 2              | 37 µs      |
| 16    | 134 889     | 10 000      | 92.6   | 2              | 132 µs     |
| 64    | 136 140     | 9 750       | 92.8   | 2              | 499 µs     |
| 256   | 134 001     | 9 750       | 92.7   | 2              | 13.07 ms\* |

\* p99 at c=256 is connection-queueing on a single worker core, not span overhead.
Low-rate control: **2 000 sequential requests → 2 000 delivered (0 % drop).**

### Mechanism isolation (rebuilds, one knob at a time)
| change | delivered/s | drop % | exp CPU % | reading |
|---|---:|---:|---:|---|
| `otel_metric_interval` 2s vs 1s | 9 375 / 8 382 | ~93 | 2 | **flat** → spans drain on the 250 ms sub-cadence, *not* the metric interval |
| ring 256 KiB → **1 MiB** (4×), cap unchanged | 9 583 | 92.9 | 2 | **no change** → cap-bound, not ring-bound |
| cap 2 500 → **25 000** (10×), ring unchanged | 11 864 | 91.2 | 2 | **barely moves** → now ring-bound (256 KiB ≈ 2 500 spans) |
| **both** raised: ring 8 MiB + cap 60 000 | **0** | 100 | 39 | a ~6 MB/drain batch **exceeds the gRPC max-message size** → collector rejects → nothing delivered |

The pair is co-sized to ~2 500: raising either alone just exposes the other. Raising both far enough
hits a **third** wall — the OTLP/gRPC max message size — because the drain sends one batch per cycle.

## Answer to "how long does it need to run?"

It doesn't need a long soak. The ceiling is reached in **seconds** (steady-state within one drain
cycle) and is flat across load, connections, and time — so the bench is a **short ramp + targeted
rebuilds**, not an endurance run. Total wall-clock here was a handful of minutes per data point
(dominated by incremental rebuilds), not hours.

## Recommendations

1. **The exporter is not the bottleneck for metrics/summary-logs** (those aggregate). For **100 %-sampled
   traces it is**, at ~10 k spans/s/worker — *well below* the exporter's CPU capacity (2 %). This is a
   sizing choice, not a compute limit.
2. **To raise the trace ceiling**, change three things *together* (any one alone is wasted): the
   per-drain budget (`MAX_SPAN_RECORDS_PER_WORKER_PER_DRAIN`), the ring (`DEFAULT_SPAN_RING_CAP` — a
   future `otel_trace_ring_size` directive is already noted in `shm.rs`), **and** split the span send
   into multiple sub-max-size messages per drain (or drain spans more often than 250 ms). Without the
   send-chunking, a bigger budget just trips the gRPC message-size wall (see the last row).
3. **Honest scalability story for the architect:** cheap/default-on holds for metrics + summary-logs;
   for traces, sustained 100 % sampling is safe to **~10 k spans/s/worker** at defaults, beyond which
   spans drop **gracefully and observably** (`ngx_otel.traces.dropped_records`) without harming request
   latency. For higher trace volume: sample down, or raise the caps per (2). Aligns with the standing
   guidance that traces are per-request (non-aggregated) and don't inherit the metrics/log wins.
4. **Untested (needs a bigger host):** multi-worker fan-in onto the single exporter. With per-worker
   rings + per-worker drain budgets, aggregate delivery should scale ~N×10 k/s until the exporter's
   single-process drain CPU (2 % per worker-equivalent → large headroom) or the collector saturates —
   an extrapolation to confirm on >4 cores.
