# Exporter lifecycle safety

The `nginx: otel exporter` is a helper process spawned by the nginx master to
own all collector sockets and telemetry I/O. This document states its lifecycle
invariants as **guarantees**, each backed by implementation evidence and the C2
chaos test suite (`tests/integration/`).

---

## Invariants

### 1. Master never blocks on the exporter

The exporter is optional to nginx's request-handling liveness.

- **Workers do not hold sockets** to the collector. All collector TCP
  connections originate exclusively from the exporter PID. Workers write
  telemetry into bounded shared-memory rings (bump-and-defer) and never call
  into the exporter's event loop.
- **Shutdown is bounded.** `ngx_terminate` (SIGTERM) causes the exporter to
  exit immediately; `ngx_quit` (SIGQUIT) triggers a graceful drain bounded by
  `GRACEFUL_DRAIN_BACKSTOP` (15 s), after which the exporter force-exits
  regardless of collector reachability.
- **Socket isolation** verified by `run_chaos_kill9.sh`: workers return HTTP 200
  while the exporter is dead; `/proc/<pid>/net/tcp` shows zero `:4317/:4318`
  sockets on any worker PID.

### 2. Exporter is optional to request-handling liveness

If the exporter is dead, crashed, or in degraded mode, nginx continues to
accept and serve HTTP requests normally. Workers drop telemetry into the bounded
shm rings; once those rings fill the oldest records are silently overwritten.
No worker blocks, panics, or returns an error to the client.

- **Dead-collector shutdown** verified by `run_chaos_dead_collector.sh`: SIGQUIT
  completes within 20 s even with a permanently unreachable collector, and SIGHUP
  reload leaves workers returning HTTP 200 throughout.

### 3. Setup failure — no respawn loop

If the exporter encounters a fatal error during initialisation (channel setup,
privilege drop, or module `init_process` returning `NGX_ERROR`) it calls
`std::process::exit(2)`. nginx interprets exit code 2 as a permanent failure
and marks the slot non-respawnable (`ngx_processes[i].respawn = 0`); the
exporter slot stays silent and workers continue unaffected.

*Source:* `src/exporter/mod.rs` steps 5a and 7; `nginx/src/os/unix/ngx_process.c`
`WEXITSTATUS(status) == 2` guard.

### 4. Crash-loop → bounded backoff → clean self-disable (C1)

A recurring **runtime** crash (panic, OOM, signal mid-operation) triggers
nginx's built-in respawn (`NGX_PROCESS_RESPAWN`). The exporter defends against
fork-storm via a crash counter stored in `control_shm`:

| Count in window | Action |
|---|---|
| 1 | Continue (first start, no backoff) |
| 2–5 | Exponential backoff before init: `min(100 ms × 2^(count−1), 5 000 ms)` |
| > 5 | `NGX_LOG_ALERT` + `exit(2)` → respawn disabled, degraded mode |

The crash window is **60 s**. A long-lived healthy exporter (≥60 s without a
crash) resets the counter automatically, so a single transient crash later does
not count as a loop.

**Reload safety.** `control_shm_zone_init` zeroes `crash_count` and
`window_start_unix` on SIGHUP reload (`old_data != NULL`), so a legitimate
operator reload always starts from a clean slate and the new exporter is never
pre-emptively disabled by a stale counter.

**Self-disable alert message:**
```
otel exporter: disabled after N crashes in 60s — telemetry OFF, nginx request handling UNAFFECTED
```

- **Crash-loop containment** verified by `run_chaos_crashloop.sh`:
  exporter self-disables after `MAX_CRASH_RESTARTS = 5`, ALERT is logged,
  no further respawn observed, master remains responsive, workers return HTTP 200.

### 5. Degraded-state self-metric

When the crash counter is > 0 the export loop publishes
`ngx_otel.exporter.restarts` as an OTLP Gauge, allowing operators to detect
repeated crashes without inspecting the nginx error log.

After self-disable the metric is no longer emitted (the exporter is gone), but
`ngx_otel.traces.dropped_records` and the metric-ring fullness will rise as
telemetry backs up in the bounded shm — observable via the same scrape endpoint.

---

## Chaos test matrix

| Test script | Scenario | Assertions |
|---|---|---|
| `run_chaos_kill9.sh` | `kill -9` exporter under HTTP load | workers 200; socket isolation (Linux: `/proc`); master respawns; clean SIGQUIT |
| `run_chaos_crashloop.sh` | Repeated startup abort (test-support feature) | backoff fires; self-disable after 5; ALERT logged; master + workers unaffected |
| `run_chaos_dead_collector.sh` | SIGQUIT/SIGHUP with unreachable collector | SIGQUIT ≤ 20 s; no orphan; reload zeroes crash counter |

All three scripts pass on macOS (dev) and debian-vm (Linux, CI). Socket
isolation is verified definitively on Linux via `/proc/<pid>/net/tcp`; on macOS
the check is informational (multiple nginx instances may share the dev machine).

**TSAN gate** (commit `62f69da`, debian-vm): 0 data races on the new
`crash_count` / `window_start_unix` `AtomicU64` fields across all integration
scripts.

---

## Constants (single-homed in `src/exporter/mod.rs`)

| Constant | Value | Purpose |
|---|---|---|
| `CRASH_WINDOW_SECS` | 60 s | Rolling window for the crash counter |
| `MAX_CRASH_RESTARTS` | 5 | Restarts before self-disable |
| `CRASH_BACKOFF_BASE_MS` | 100 ms | Base of the exponential backoff |
| `CRASH_BACKOFF_CAP_MS` | 5 000 ms | Maximum single-backoff sleep |
| `GRACEFUL_DRAIN_BACKSTOP` | 15 s | Maximum drain wait on SIGQUIT |
