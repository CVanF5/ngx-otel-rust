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

## Known limitation: gen-1 exporter under `daemon on`

### What happens

With `daemon on` (the nginx production default) nginx performs a double-fork
on startup:

```
P0 (shell child)
  └─ forks master M
       └─ M spawns gen-1 exporter E1 via ngx_spawn_process()
P0 exits → M is adopted by init/systemd
           E1 is also adopted by init/systemd (PPID → 1)
```

Because E1's PPID is not M, M never receives `SIGCHLD` when E1 dies.
If E1 crashes or is killed (`kill -9`), M does not respawn it and telemetry
is silently lost until the next reload.

**Graceful stop with `nginx -s quit` is permanently blocked** once the
daemon-on startup sequence has run:

* M sends SIGQUIT to all processes in its table, including E1's PID.
* If E1 is still alive it receives SIGQUIT, runs its graceful drain, and
  exits — but SIGCHLD is delivered to init (PPID 1), not M.  M's process
  table still shows E1 as live.
* If E1 was already killed (e.g. `kill -9` before the quit) M's `kill(E1,
  SIGQUIT)` returns `ESRCH` immediately; M still does not mark E1 as done.
* Either way M enters `sigsuspend()` waiting for E1's SIGCHLD, which never
  arrives.  The master **hangs indefinitely**.

`nginx -s stop` (SIGTERM) is unaffected: it forces workers to exit without
waiting for SIGCHLD.  Use `nginx -s stop` or `kill -SIGTERM <master_pid>`
to terminate nginx cleanly when `daemon on` was used at startup.

A one-time `kill() failed` ALERT is logged at ALERT level
(`ngx_process_cycle.c:517-521`) if the SIGKILL escalation fires while E1
is already dead.  That log line is bookkeeping; the hang described above is
the real operational impact.

This is a gap in nginx's respawn model, not a bug in the module code: there is
no extension point in nginx 1.31.x that runs post-daemonize inside the
long-lived master.

### Detection

At `init_module` time the module checks whether `daemon on` is configured and
the current process has not yet daemonized (`ngx_daemonized == 0 &&
ngx_inherited == 0`).  When true it logs `NGX_LOG_ALERT`:

```
otel: daemon on — gen-1 exporter will be unsupervised after daemonize
(PPID 1; crash-respawn unavailable for this generation).
Run `nginx -s reload` once after startup to restore supervision.
See LIFECYCLE.md §"Known limitation: gen-1 exporter under daemon on".
```

The ALERT appears in `error.log` during every cold start with `daemon on` until
a reload has been performed.

### Runtime detection: heartbeat-stale ALERT (B4 follow-up 2)

The startup ALERT above warns about the *possibility*; a second, runtime
detector reports the *event* — a silent exporter death (the unsupervised gen-1
dying, an exporter wedged by `SIGSTOP`, or a crash-loop self-disable) — through
the only channel that still works when the exporter is dead: the worker error
log.

Mechanism (`src/liveness.rs`):

* The exporter stamps its monotonic clock (`ngx_current_msec`,
  `CLOCK_MONOTONIC` basis) into the control shm zone
  (`ControlShm::last_beat_msec`) every **1 s**, from a dedicated self-rearming
  `ngx_event_t` timer that is independent of drain/send progress — a stalled
  send to a blackholed collector does not delay beats.
* Workers check the beat **only on the ring-full drop path** (span or
  access-tail push returning "full" — an already-counted symptom path). There
  is no per-request check and zero added cost in healthy operation.
* The drop is the trigger, the heartbeat is the verdict: drops with a fresh
  beat are normal saturation (the exporter keeps exporting
  `*.dropped_records`) and never alert. Only a beat older than **5 s**
  (5 beat periods — derived from the beat period, not from
  `otel_metric_interval`) produces:

```
[alert] ... otel exporter heartbeat stale (no beat for >5000ms);
telemetry suspended; nginx -s reload restores
```

* The ALERT is **latched: one line per worker per exporter generation**.
  A SIGHUP reload starts a new generation (and a fresh, supervised exporter),
  which re-arms the latch.

Note: detection requires drop traffic on a ring (spans enabled or
`otel_log_export` set, plus requests that push records). A fully idle
nginx with a dead exporter stays silent until telemetry pressure appears —
by design, the check lives on the symptom path only.

### Remedy

Run `nginx -s reload` once after startup.  The reload causes the long-lived
master (which is already daemonized and owns the pidfile) to spawn a fresh
gen-2 exporter directly.  Gen-2 has PPID = master, so SIGCHLD supervision and
crash-respawn work normally for all subsequent generations.

The reload can be scripted in an init / systemd unit:

```ini
# systemd example
ExecStartPost=/usr/sbin/nginx -s reload
```

### Deferred fix (Option B)

A self-supervisor approach (exporter forks a watchdog before the double-fork
completes, or the module uses `ngx_init_cycle` hooks) was designed but deferred
as out-of-scope for this release.  The ALERT + reload remedy is sufficient for
production use.  The self-supervisor design is captured in the commit that
introduced this section.

### Test

`tests/integration/run_b4_daemon_on_gen1.sh` verifies:

| Step | Assertion |
|---|---|
| Cold start with `daemon on` | ALERT present in error.log (**regression gate**) |
| Gen-1 exporter running | PPID ≠ master (orphaned after daemonize) |
| `kill -9` gen-1 | NO respawn within 5 s (master blind to SIGCHLD) |
| `nginx -s reload` | Gen-2 exporter appears with PPID = master |
| `kill -9` gen-2 | Respawn within 5 s (supervision restored) |
| SIGQUIT | Master hangs (B4 gap — sigsuspend waiting for gen-1 SIGCHLD that never arrives); use SIGTERM for clean stop |

---

## Chaos test matrix

| Test script | Scenario | Assertions |
|---|---|---|
| `run_chaos_kill9.sh` | `kill -9` exporter under HTTP load | workers 200; socket isolation (Linux: `/proc`); master respawns; clean SIGQUIT |
| `run_chaos_crashloop.sh` | Repeated startup abort (test-support feature) | backoff fires; self-disable after 5; ALERT logged; master + workers unaffected |
| `run_chaos_dead_collector.sh` | SIGQUIT/SIGHUP with unreachable collector | SIGQUIT ≤ 20 s; no orphan; reload zeroes crash counter |
| `run_b4_daemon_on_gen1.sh` | `daemon on` gen-1 orphan + reload remedy | ALERT logged; kill-9 gen-1 → no respawn; reload → gen-2 PPID=master; kill-9 gen-2 → respawn |
| `run_b4_heartbeat_stale.sh` | Heartbeat-stale alert, both polarities | alive+saturated (drops verified) → 0 alerts; daemon-on gen-1 kill-9 → beats freeze → exactly 1 latched ALERT; reload remedy → beats resume, no false fire |

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
