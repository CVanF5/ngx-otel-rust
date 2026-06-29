# SPIKE: dedicated non-accepting OTel worker

**Status:** experimental spike (NOT production-merge). Branch
`spike/dedicated-otel-worker`. Feature flag `dedicated-worker`.

## Question

Can we run the OTel export task inside a dedicated, *non-accepting* NGINX
**worker** instead of the separate `nginx: otel exporter` child process — and
does that get master-supervision for free, fixing the `daemon on` gen-1 orphan
(B2)?

## Mechanism verdict

**WORKS — with a reuseport caveat.**

- **Shared listen socket (no `reuseport`): clean.** The dedicated worker simply
  removes the accept read event from each `cycle->listening[].connection->read`
  (via `ngx_event_actions.del`, the `ngx_del_event` macro target). It never
  wakes on accept; the other workers absorb all connections on the shared fd.
  All 5 checks pass cleanly.
- **`reuseport`: blackhole.** Each worker owns its *own* listen socket and the
  kernel hashes incoming connections across the SO_REUSEPORT group. Closing the
  dedicated worker's socket (so the kernel should redistribute its share) does
  NOT cleanly redistribute already-hashed/queued connections: ~1/3 of requests
  (the closed slot's share, with `worker_processes 3`) time out. Measured:
  **95 OK / 55 timeout of 150** sequential requests. Merely *not* arming accept
  on a reuseport socket would be worse (silent blackhole of the whole slot
  share with no close). This is a real blocker for the reuseport path as
  implemented.

## How it's built

`--features dedicated-worker`:
1. `init_module` skips `ngx_spawn_process` — no child exporter
   (`src/lib.rs`, the `#[cfg(feature = "dedicated-worker")]` early return).
2. The **last** worker slot (`worker_processes - 1`) is the otel worker. Its
   `init_process` (`spike_dedicated_worker_init`) suppresses accept
   (`spike_suppress_accept`) and spawns `export_loop(amcf)` via
   `ngx::async_::spawn`, driven by the worker's own
   `ngx_process_events_and_timers`.
3. Config guard: `worker_processes < 2` → hard `[emerg]` at module init
   (would otherwise leave zero request-serving workers).

Build note: the nginx dynamic-module path compiles cargo with
`--no-default-features --features "$ngx_otel_rust_RUST_FEATURES"`. To inject the
spike feature into the `.so`, set `ngx_rust_target_features=dedicated-worker` in
`config` and reconfigure (`rm -rf objs-debug target/debug/build/nginx-sys-*`,
then `make build BUILD=debug`).

## Evidence (debian-vm, daemon on, worker_processes 3)

### Check 3 / B2 — the headline (CONFIRMED)
```
[INFO] worker pids:  13341 13342 13343  (ppid 13340 = master)
worker 2 of 3 is the dedicated otel worker; suppressing accept ...
dedicated worker 13343 PPID = 13340 (master=13340)
killing dedicated otel worker 13343
[alert] 13340#0: worker process 13343 exited on signal 9
new dedicated (last slot) worker pid = 13900  PPID = 13340
13900 ... removed accept event (slot 0); accept suppressed
```
The master reaps and respawns the dedicated worker (PPID stays = master) and the
respawn re-suppresses accept. Contrast: the current child exporter spawned from
`init_module` under `daemon on` reparents to init (PPID 1) and is NOT respawned
(the existing `[alert]` warns about exactly this). The spike removes that gap by
using a sanctioned `NGX_PROCESS_RESPAWN` worker.

### Check 1 — accept exclusion (CONFIRMED, shared-socket)
Dedicated worker logs `removed accept event (slot 0)`; all served connections
("client … closed keepalive connection") are attributed to the OTHER workers
only, never the dedicated PID.

### Check 2 — telemetry end-to-end (CONFIRMED)
`metrics.json` grows under load and carries the `spike-dedworker` service tag —
the in-worker export task drains all worker rings and ships OTLP (N→1
aggregation preserved).

### Check 4 — reload (CONFIRMED, shared-socket)
`nginx -s reload` → 3 fresh workers under the same master; the new dedicated
slot re-suppresses accept; 50/50 post-reload requests return 200.

### Check 5 — reuseport (BLOCKER)
`closed reuseport listen fd (slot 2)` then ~1/3 of requests time out
(95 OK / 55 timeout of 150). B2 respawn still works in this mode, but the
socket-close does not cleanly redistribute the slot's connection share.

## Shortcuts taken

- Last-slot designation is a fixed heuristic (`worker_processes - 1`); no
  rebinding if the operator changes worker count semantics, no CPU-affinity
  handling.
- The reload successor-announce / `successor_gen` machinery is left intact but
  unused (the worker export task does not snapshot it); a production version
  would either repurpose or remove it.
- `reuseport` bit is read via the bindgen bitfield accessor
  (`ngx_listening_t::reuseport()`), which is in the bindgen-bitfield-bug risk
  class; for a 1-bit early field it read correctly here, but a production
  version should use a C shim or close-by-fd-set rather than the bitfield.
- No graceful-drain-on-quit for the in-worker export task (the child exporter
  has an explicit drain loop; here the worker's normal shutdown path runs).
- No per-worker request-count instrumentation; accept exclusion was shown via
  log attribution + `ss`, not a counter.

## A production version would still need

1. A clean reuseport story: either (a) forbid `reuseport` with this mode, or
   (b) never create the dedicated worker's reuseport socket in the first place
   (pre-empt `ngx_event_process_init` / `ngx_clone_listening`), so no
   connections are ever hashed to it — closing after the fact is too late.
2. Graceful drain of the in-worker export task on `ngx_quit` (reuse the child
   exporter's `EXPORT_LOOP_DONE` + backstop-timer pattern).
3. Robust dedicated-slot selection + the bitfield-safe reuseport detection.
4. Decide the fate of the `control_shm` successor/heartbeat machinery (the
   worker is master-supervised, so the gen-handoff + liveness-heartbeat design
   may be simplifiable or removable).
