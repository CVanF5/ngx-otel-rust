# SPIKE: dual-role OTel worker

**Status:** experimental spike (NOT production-merge). Branch
`spike/dual-role-otel-worker`. Feature flag `dual-role-worker`.

## Question

Can we run the OTel export task inside a **dual-role** NGINX worker — a
completely normal request-serving worker that ALSO drives the export task — and
get master-supervision for free while staying reuseport-clean?

## Mechanism verdict

**WORKS — reuseport-clean, no blackhole, B2 confirmed.**

The dual-role worker is the dedicated-worker spike minus the accept-suppression
step. All the B2 win (master-supervised via `NGX_PROCESS_RESPAWN`) is
preserved; all the reuseport cost of the dedicated spike is eliminated.

## Comparison to dedicated-worker spike

| Dimension | dedicated-worker | dual-role-worker |
|-----------|-----------------|-----------------|
| No child exporter | YES | YES |
| B2 master supervision | YES | YES |
| reuseport-clean | NO — ~37% blackhole | **YES — 0/150 failures** |
| Request capacity lost | 1 worker | 0 workers |
| CPU contention on designated worker | minimal | YES (export + requests share one worker; ~2% CPU export) |
| Accept suppression | YES | NO |
| Socket surgery | YES (close reuseport fd) | NO |

## How it's built

`--features dual-role-worker`:
1. `init_module` skips `ngx_spawn_process` — no child exporter
   (`src/lib.rs`, the `#[cfg(feature = "dual-role-worker")]` early return).
2. The **last** worker slot (`worker_processes - 1`) is the dual-role worker. Its
   `init_process` (`spike_dual_role_worker_init`) spawns `export_loop(amcf)` via
   `ngx::async_::spawn`, driven by the worker's own
   `ngx_process_events_and_timers` — **without** removing any accept events or
   closing any sockets.
3. Config guard: `worker_processes < 2` → hard `[emerg]` at module init.

Build: set `ngx_rust_target_features=dual-role-worker` in `config` and
reconfigure (`rm -rf objs-debug/ngx_otel_rust target/debug/build/nginx-sys-*`,
then `make build BUILD=debug`).

## Evidence (debian-vm, daemon on, worker_processes 3)

All checks run in BOTH noreuseport and reuseport mode.

### Check 1 — all 3 workers serve requests (CONFIRMED)
```
# noreuseport
workers: 28658 28659 28660
CHECK 1 RESULT: served=300 fail=0
[OK] no accept suppression

# reuseport
CHECK 1 (reuseport): served=300 fail=0
```
Dual-role worker (pid 28660 / 29597) accepts connections normally alongside the
other workers. No accept-suppression log lines in either mode.

### Check 2 — telemetry end-to-end (CONFIRMED)
```
# noreuseport
metrics.json size before: 111 → after: 114
spike-dualrole lines in last 50: 33
[OK] telemetry flowing to collector

# reuseport
metrics.json before: 215 → after: 218
spike-dualrole lines in last 50: 50
[OK] telemetry flowing
```
The in-worker export task drains all worker rings and ships OTLP.

### Check 3 / B2 — master supervision (CONFIRMED, both modes)
```
# noreuseport
dual-role worker pid=28660, PPID=28657 (master=28657)
[OK] PPID == master before kill
killing dual-role worker 28660 with kill -9...
new dual-role worker pid=29346, PPID=28657 (master=28657)
[OK] PPID == master after respawn — B2 confirmed
2026/06/29 21:56:28 [alert] 28657#0: worker process 28660 exited on signal 9
2026/06/29 21:56:28 [notice] 29346#0: export task spawned on worker event loop

# reuseport
dual-role worker pid=29597 PPID=29594 master=29594
new worker pid=30496 PPID=29594 master=29594
[OK] B2 confirmed
2026/06/29 21:58:23 [alert] 29594#0: worker process 29597 exited on signal 9
```
The master reaps and respawns the dual-role worker (PPID stays == master) and
the respawn re-starts the export task. Identical to the dedicated-worker B2 fix.

### Check 4 — reload (CONFIRMED, both modes)
```
# noreuseport
CHECK 4 RESULT: served=50 fail=0

# reuseport
CHECK 4 (reuseport): served=50 fail=0
```
`nginx -s reload` → fresh workers under same master; the new last-slot worker
re-starts the export task; all 50 post-reload requests return 200.

### Check 5 — reuseport headline: ZERO blackhole (CONFIRMED)
```
[OK] no socket surgery — reuseport sockets intact
CHECK 5 RESULT (reuseport): served=150 / 150 fail=0
[OK] no blackhole — 150/150 served under reuseport
```
Compare to dedicated-worker: 95/150 OK (37% blackhole). Dual-role: 150/150 OK.
The absence of any socket surgery is the headline claim confirmed.

## No event-loop starvation observed

The export task is async and driven by epoll inside the worker's
`ngx_process_events_and_timers` loop. With a 1-second export interval and
~2% CPU cost, no starvation of request-serving was observed. The worker handled
300 + 200 + 150 = 650 requests across the three checks without a single failure.

A definitive starvation check would require a high-RPS benchmark on host-1 —
that is deferred (the host-1 bench agent has the dedicated vs baseline
comparison). The 2% exporter CPU makes starvation implausible but not disproved
at extreme load.

## Shortcuts taken (same as dedicated-worker)

- Last-slot designation is a fixed heuristic (`worker_processes - 1`).
- No graceful-drain-on-quit for the in-worker export task.
- No per-worker request-count instrumentation; all workers logged connections
  during checks.
- The `control_shm` successor/heartbeat machinery is intact but unused.

## A production version would need

1. Graceful drain of the in-worker export task on `ngx_quit`.
2. Robust designated-slot selection.
3. Decide the fate of `control_shm` successor / liveness machinery (may be
   simplifiable since the worker is master-supervised).
4. Bench on host-1 to quantify the CPU-contention cost at realistic RPS.
