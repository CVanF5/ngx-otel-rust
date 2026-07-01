// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Exporter process lifecycle.
//!
//! This module provides the `nginx: otel exporter` child process, spawned by
//! master via the `init_module` hook in `src/lib.rs`. The exporter handles
//! master channel signals (QUIT / TERMINATE / REOPEN), drops privileges to the
//! configured nginx user, runs the nginx event loop, and owns the async export
//! task spawned via [`ngx::async_::spawn`].
//!
//! Workers are bump-and-defer only — no event loop work, no allocation, no
//! sockets on the cold path. The collector connection originates exclusively
//! from the exporter PID.

pub(crate) mod channel;
pub(crate) mod control_shm;

use core::ffi::c_void;
use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use ngx::core::Pool;
use ngx::http::HttpModuleMainConf;

use crate::HttpOtelModule;

/// Process-local flag set by `otel_exporter_cycle` immediately after fork.
/// Reading it is a single `Relaxed` atomic load — zero cost outside the
/// exporter process. Set once, never cleared.
pub(crate) static IS_OTEL_EXPORTER: AtomicBool = AtomicBool::new(false);

/// Default upper bound on the graceful-drain wait after `ngx_quit` before the
/// exporter force-exits. The export loop normally signals `EXPORT_LOOP_DONE`
/// within ~`SHUTDOWN_POLL_INTERVAL` (250 ms); this only caps a wedged send.
/// Overridden by `worker_shutdown_timeout` if smaller — see `effective_drain_backstop`.
const GRACEFUL_DRAIN_BACKSTOP: std::time::Duration = std::time::Duration::from_secs(15);

/// Effective drain backstop, honouring `worker_shutdown_timeout` when set
/// (0 = unset, use the default unchanged): `min(GRACEFUL_DRAIN_BACKSTOP, timeout)`.
pub(crate) fn effective_drain_backstop(
    default_backstop: std::time::Duration,
    shutdown_timeout_ms: u64,
) -> std::time::Duration {
    if shutdown_timeout_ms == 0 {
        default_backstop
    } else {
        default_backstop.min(std::time::Duration::from_millis(shutdown_timeout_ms))
    }
}

// ── Crash-loop backoff constants ─────────────────────────────────────────────

/// Rolling window for the crash counter (seconds); `pub(crate)` so
/// `control_shm` tests can cross-check the authoritative constant.
pub(crate) const CRASH_WINDOW_SECS: u64 = 60;

/// Maximum exporter restarts within `CRASH_WINDOW_SECS` before it self-disables
/// via `exit(2)` (degraded mode: workers keep serving, telemetry drops into
/// the bounded shm rings). `pub(crate)` for `control_shm` test cross-check.
pub(crate) const MAX_CRASH_RESTARTS: u64 = 5;

/// Base backoff sleep before continuing init after a crash restart; doubles
/// each restart (`BASE * 2^(count-1)`, capped at `CRASH_BACKOFF_CAP_MS`).
pub(crate) const CRASH_BACKOFF_BASE_MS: u64 = 100;

/// Maximum backoff sleep before continuing init.
pub(crate) const CRASH_BACKOFF_CAP_MS: u64 = 5_000;

/// Bounded exponential backoff (ms) for `count` = crash_count **after**
/// incrementing (1 = first start → 0; 2 = first restart → 100ms; …).
/// `min(BASE * 2^(count-1), CAP)`, overflow-safe via `saturating_mul`.
pub(crate) fn crash_backoff_ms(count: u64) -> u64 {
    if count <= 1 {
        return 0;
    }
    let shift = count.saturating_sub(1).min(31); // cap shift to prevent u64 overflow
    CRASH_BACKOFF_BASE_MS.saturating_mul(1u64 << shift).min(CRASH_BACKOFF_CAP_MS)
}

/// Process identity as seen from inside the `ngx-otel-rust` crate. Mirrors
/// `nginx-acme/src/util.rs`'s `NgxProcess` plus an `Exporter` variant,
/// distinguished from a generic helper via `IS_OTEL_EXPORTER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NgxProcess {
    Single,
    Master,
    Signaller,
    Worker(u32),
    Helper,
    /// This process is the dedicated `nginx: otel exporter` child.
    Exporter,
}

/// Returns the current process identity. Cold-path only (gating predicates),
/// never called from the request hot path.
pub(crate) fn ngx_process() -> NgxProcess {
    // SAFETY: `ngx_process` is an nginx `static mut` set during process init and
    // only read thereafter; this cold-path read runs on the single-threaded
    // event loop, so there is no data race.
    let p = unsafe { nginx_sys::ngx_process } as u32;
    match p {
        nginx_sys::NGX_PROCESS_SINGLE => NgxProcess::Single,
        nginx_sys::NGX_PROCESS_MASTER => NgxProcess::Master,
        nginx_sys::NGX_PROCESS_SIGNALLER => NgxProcess::Signaller,
        nginx_sys::NGX_PROCESS_WORKER => {
            // SAFETY: `ngx_worker` is an nginx `static mut` set once at worker
            // init; read-only here on the single-threaded worker.
            NgxProcess::Worker(unsafe { nginx_sys::ngx_worker } as u32)
        }
        nginx_sys::NGX_PROCESS_HELPER => {
            if IS_OTEL_EXPORTER.load(Ordering::Relaxed) {
                NgxProcess::Exporter
            } else {
                NgxProcess::Helper
            }
        }
        // Unknown process type — treat as generic helper to stay conservative.
        _ => NgxProcess::Helper,
    }
}

// ── Exporter cycle entry point ────────────────────────────────────────────────

/// Exporter cycle entry point — called from `ngx_spawn_process` via the
/// `ngx_spawn_proc_pt` function pointer registered in `ngx_otel_init_module`.
///
/// Sequence mirrors `ngx_cache_manager_process_cycle`
/// (`nginx/src/os/unix/ngx_process_cycle.c:1088-1136`) plus signal-handler
/// installation (needed at initial start: `init_module` fires before
/// `ngx_init_signals` in master).
///
/// # Sequencing constraints (order is load-bearing)
/// 1. `ngx_init_signals` BEFORE `sigprocmask` clears the mask.
/// 2. `close_sibling_channels` BEFORE `ngx_add_channel_event` (close
///    FDs we don't own; keep `ngx_channel` = our `channel[1]`).
/// 3. `drop_privileges_and_chdir` AFTER `ngx_add_channel_event` (safer to
///    register before dropping).
/// 4. `ngx_setproctitle` last, just before entering the loop.
///
/// # Safety
///
/// This is an FFI callback (`ngx_spawn_proc_pt`). `cycle` is guaranteed
/// non-null by nginx. All nginx-global dereferences are inside `unsafe`.
pub(crate) unsafe extern "C" fn otel_exporter_cycle(
    cycle: *mut nginx_sys::ngx_cycle_t,
    _data: *mut c_void,
) {
    // SAFETY: FFI callback invoked by nginx with a valid non-null `cycle` (fn
    // contract), running in the freshly-forked exporter process. The block sets
    // and reads nginx globals (`ngx_cycle`, `ngx_process`) and calls nginx setup
    // routines on the single-threaded event loop before any other task runs, so
    // the static-mut writes are race-free. Per-step rationale is inline below.
    unsafe {
        // 0. Update ngx_cycle to the new cycle: at fork time master's ngx_cycle
        //    still points at the previous init cycle (nginx.c:335 sets it AFTER
        //    ngx_init_cycle returns, but our hook fires during ngx_init_cycle:649).
        nginx_sys::ngx_cycle = cycle;

        // 1. Identify as exporter so ngx_process() returns Exporter, not Helper.
        nginx_sys::ngx_process = nginx_sys::NGX_PROCESS_HELPER as nginx_sys::ngx_uint_t;
        IS_OTEL_EXPORTER.store(true, Ordering::Relaxed);

        // 1.5. Crash-loop backoff: detect rapid restarts and throttle / self-disable
        //      before any risky init. The control-shm zone was mapped by nginx
        //      before fork, so the pointer is valid here.
        //
        //      Algorithm (matches the unit-tested `simulate_startup` in control_shm):
        //        a) Outside the crash window (or uninitialized): reset counter+window.
        //        b) Increment crash_count.
        //        c) count > MAX_CRASH_RESTARTS: log ALERT + exit(2) (degrade; workers
        //           keep serving, telemetry silently drops once shm rings fill).
        //        d) count > 1: sleep bounded-exponential backoff before continuing.
        //
        //      RELOAD SAFETY: `control_shm_zone_init` zeroes crash_count and
        //      window_start_unix on SIGHUP reload, so an operator reload always
        //      starts from a clean slate.
        //
        // SAFETY: `cycle` is the valid non-null cycle passed by nginx; all field reads
        // below are through shared references to Atomic types, which are safe.
        //
        // test_crash_count: captured here, consumed by the test-support crash hook
        // at step 10 (None if the control-shm pointer is unavailable).
        #[cfg(feature = "test-support")]
        let mut test_crash_count: Option<u64> = None;
        if let Some(amcf) = crate::HttpOtelModule::main_conf(&*cycle) {
            if let Some(ctrl_ptr) = amcf.control_shm_ptr_mut() {
                let ctrl = &*ctrl_ptr;
                let now = crate::util::now_unix_secs();
                let window = ctrl.window_start_unix.load(Ordering::Acquire);

                if window == 0 || now.saturating_sub(window) > CRASH_WINDOW_SECS {
                    ctrl.crash_count.store(0, Ordering::Relaxed);
                    ctrl.window_start_unix.store(now, Ordering::Release);
                }

                let count = ctrl.crash_count.fetch_add(1, Ordering::AcqRel) + 1;

                if count > MAX_CRASH_RESTARTS {
                    alert!(
                        (*cycle).log,
                        "otel exporter: disabled after {} crashes in {}s \
                         — telemetry OFF, nginx request handling UNAFFECTED",
                        count,
                        CRASH_WINDOW_SECS,
                    );
                    // exit(2) instructs nginx NOT to respawn this helper
                    // (same mechanism as the channel-event setup failure at step 7).
                    std::process::exit(2);
                }

                if count > 1 {
                    let backoff_ms = crash_backoff_ms(count);
                    warn!(
                        (*cycle).log,
                        "otel exporter: crash #{} in window, backing off {}ms before init",
                        count,
                        backoff_ms,
                    );
                    std::thread::sleep(std::time::Duration::from_millis(backoff_ms));

                    // Publish so the self-metric is visible on the first export tick
                    // (count - 1 = prior crashes in window).
                    crate::drain::EXPORTER_RESTARTS.store(count - 1, Ordering::Relaxed);
                }

                #[cfg(feature = "test-support")]
                {
                    test_crash_count = Some(count);
                }
            }
        }

        // 2. Install signal handlers. Idempotent on the SIGHUP path (already
        //    installed in master); REQUIRED at initial start because
        //    init_module fires before ngx_init_signals in master (nginx.c:293
        //    vs :345), so the forked child inherits SIG_DFL.
        let _ = nginx_sys::ngx_init_signals((*cycle).log);

        // 2a. Drop privileges and chdir, matching ngx_worker_process_init
        //     (setgid/setuid :799-851, chdir :872-879) BEFORE sigprocmask, the
        //     module init_process fan-out, and ngx_add_channel_event — so
        //     steps 5a/6/7 and the export-task spawn all run UNPRIVILEGED,
        //     same least-privilege ordering as nginx workers. No-op when not
        //     started as root (geteuid() != 0).
        drop_privileges_and_chdir(cycle);

        // 3. Clear the blocked-signal mask inherited from master.
        //    See ngx_worker_process_init:881-886.
        let mut empty: libc::sigset_t = mem::zeroed();
        libc::sigemptyset(&raw mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &raw const empty, ptr::null_mut());

        // 4. We don't accept connections. Close the listening sockets.
        nginx_sys::ngx_close_listening_sockets(cycle);

        // 5. Modest connection pool — same as cache_manager (line :1105).
        (*cycle).connection_n = 512;

        // 5a. Call each module's init_process before ngx_add_channel_event —
        //     the event module's init_process allocates
        //     cycle->connections/read_events/write_events (mirrors
        //     ngx_worker_process_init:891-898). Our own init_process returns
        //     early on NGX_PROCESS_HELPER (never spawns the export task here);
        //     fanning out to all modules mirrors nginx's own worker init,
        //     which relies on each module self-gating on ngx_process.
        let mut i = 0usize;
        let modules: *mut *mut nginx_sys::ngx_module_t = (*cycle).modules;
        while !(*modules.add(i)).is_null() {
            let m: *mut nginx_sys::ngx_module_t = *modules.add(i);
            if let Some(init_process_fn) = (*m).init_process {
                let rc = init_process_fn(cycle);
                if rc == nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t {
                    emerg!(
                        (*cycle).log,
                        "otel exporter: module[{}] init_process returned NGX_ERROR",
                        i
                    );
                    std::process::exit(2);
                }
            }
            i += 1;
        }

        // 6. Close sibling channel FDs and our own channel[0] (the master
        //    end). Mirrors ngx_worker_process_init:900-923.
        close_sibling_channels(cycle);

        // 7. Register our channel event handler on ngx_channel (our
        //    `channel[1]`). This is how master sends QUIT/TERMINATE/REOPEN
        //    commands to us.
        // Use NGX_RS_READ_EVENT (ngx-rust wrapper.h helper) rather than
        // nginx_sys::NGX_READ_EVENT directly — the latter is a parenthesised
        // compound #define on Linux epoll and bindgen does not lift it.
        // See ngx-rust commit on wrapper.h for the rationale.
        let rc = nginx_sys::ngx_add_channel_event(
            cycle,
            nginx_sys::ngx_channel as nginx_sys::ngx_fd_t,
            nginx_sys::NGX_RS_READ_EVENT as nginx_sys::ngx_int_t,
            Some(channel::otel_exporter_channel_handler),
        );
        if rc == nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t {
            // Fatal: if we can't receive channel commands, master can't signal
            // us to quit. exit(2) disables respawn so we don't loop forever.
            emerg!((*cycle).log, "otel exporter: ngx_add_channel_event failed; aborting");
            std::process::exit(2);
        }

        // 8. (Privileges were already dropped + chdir done at step 2a, matching
        //    ngx_worker_process_init's early drop — see the note there. Steps
        //    5a/6/7 above therefore ran unprivileged.)

        // 9. No accept mutex — exporter doesn't accept HTTP connections.
        nginx_sys::ngx_use_accept_mutex = 0;

        // 10. Set the process title visible in `ps`. Do this last so that
        //     "otel exporter" in ps is the signal that the exporter is
        //     fully initialised.
        nginx_sys::ngx_setproctitle(c"otel exporter".as_ptr().cast_mut());

        // ── Test-support crash hook (after setproctitle) ──────────────────────
        // Fires AFTER step 10 so "nginx: otel exporter" is already visible in
        // `ps` when abort() happens; by now the master has entered its event
        // loop with SIGCHLD installed (timing safe). Enabled only with
        // `--features test-support`; zero code in production.
        // search: NGX_OTEL_CRASH_ON_STARTUP
        #[cfg(feature = "test-support")]
        if let Some(tcc) = test_crash_count {
            if std::env::var_os("NGX_OTEL_CRASH_ON_STARTUP").is_some() {
                // For crash #1, the longer sleep also gives the master time to
                // enter ngx_master_process_cycle + sigsuspend (deterministic
                // SIGCHLD delivery even on slow CI hosts).
                let sleep_ms: u64 = if tcc == 1 { 500 } else { 300 };
                std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                warn!(
                    (*cycle).log,
                    "otel exporter: [test-support] NGX_OTEL_CRASH_ON_STARTUP set \
                     — calling abort() to simulate crash #{} (proctitle set)",
                    tcc,
                );
                // SAFETY: `abort()` is always safe to call; it terminates the
                // process immediately. nginx's SIGCHLD handler will see a
                // non-clean exit and respawn the exporter (NGX_PROCESS_RESPAWN).
                libc::abort();
            }
        }

        // 11. Spawn the async export task, pinned on the exporter's pool for
        //     the process lifetime. Reads the shm rings workers write via
        //     fork-shared pages.
        let amcf =
            HttpOtelModule::main_conf(&*cycle).expect("exporter cycle: missing otel main conf");
        let task = ngx::async_::spawn(crate::drain::export_loop(amcf));
        let pool = Pool::from_ngx_pool((*cycle).pool);
        // `Pool::allocate` returns null (and has already dropped the Task) on
        // alloc/cleanup-registration failure. Dropping the Task cancels the
        // export future, but the heartbeat timer below keeps stamping
        // `last_beat_msec` — workers would see a "live" exporter exporting
        // nothing. Refuse that silent-failure state: abort so the master's
        // crash-respawn restarts the exporter cleanly.
        if pool.allocate(task).is_null() {
            emerg!(
                (*cycle).log,
                "otel exporter: failed to pin export task on the cycle pool \
                 (out of memory) — aborting so the master respawns the exporter"
            );
            // SAFETY: `abort()` is always safe to call; it terminates the
            // process immediately.  The export task was already dropped by the
            // failed `allocate`, and the heartbeat timer has not been armed yet
            // (set up below), so no live state outlives this call.
            libc::abort();
        }

        // 11.5. Dedicated liveness heartbeat timer: a self-rearming
        //     `ngx_event_t` stamps `ngx_current_msec` into
        //     `ControlShm::last_beat_msec` every `HEARTBEAT_PERIOD_MS`. Workers
        //     read it on their ring-full drop path to distinguish a
        //     saturated-but-alive exporter from a silent one.
        //
        //     INDEPENDENCE FROM DRAIN/SEND PROGRESS (hard requirement): this
        //     timer fires from the same `ngx_process_events_and_timers` call
        //     (step 12) that drives the export task's async sends over
        //     non-blocking IO (NgxExecutor, no block_on; wakes deferred via
        //     ngx_post_event, never re-polled synchronously) — a
        //     blackholed-collector send only parks its future, so beats
        //     continue regardless. Allocated from the cycle pool (stable
        //     address, process lifetime); the timer dies with the process.
        if let Some(ctrl_ptr) = amcf.control_shm_ptr_mut() {
            let hb_ev =
                nginx_sys::ngx_pcalloc((*cycle).pool, mem::size_of::<nginx_sys::ngx_event_t>())
                    as *mut nginx_sys::ngx_event_t;
            if hb_ev.is_null() {
                // Non-fatal: telemetry export still works; only the worker-side
                // stale detection is unavailable (workers see last_beat == 0 or
                // the pre-fork value and apply startup grace).
                warn!(
                    (*cycle).log,
                    "otel exporter: heartbeat timer allocation failed; \
                     liveness stale-detection disabled for this generation"
                );
            } else {
                (*hb_ev).handler = Some(heartbeat_timer_handler);
                (*hb_ev).data = ctrl_ptr.cast::<c_void>();
                (*hb_ev).log = (*cycle).log;
                // First beat immediately: workers must see liveness from the
                // moment the exporter is up, not one period later.
                (*ctrl_ptr)
                    .last_beat_msec
                    .store(nginx_sys::ngx_current_msec as u64, Ordering::Release);
                // SAFETY (ngx_add_timer): hb_ev is a valid, zeroed, pool-pinned
                // ngx_event_t; ngx_current_msec and ngx_event_timer_rbtree are
                // initialised before any process cycle runs.
                nginx_sys::ngx_add_timer(
                    hb_ev,
                    crate::liveness::HEARTBEAT_PERIOD_MS as nginx_sys::ngx_msec_t,
                );
            }
        }

        // Copy the Copy-typed mutable statics into locals first: formatting
        // them directly would create shared refs to a `static mut` (static_mut_refs).
        let pid = nginx_sys::ngx_pid;
        let parent = nginx_sys::ngx_parent;
        notice!(
            (*cycle).log,
            "otel exporter: cycle entered, pid={}, parent={}, endpoint={}",
            pid,
            parent,
            amcf.exporter.endpoint
        );

        // 12. Main event loop. Polls ngx_terminate / ngx_quit / ngx_reopen
        //     exactly as ngx_cache_manager_process_cycle does.
        //     On ngx_quit: wait for the export task's graceful drain to complete
        //     (signalled via EXPORT_LOOP_DONE) before exiting.
        loop {
            if nginx_sys::ngx_terminate != 0 {
                notice!((*cycle).log, "otel exporter: ngx_terminate, exit");
                std::process::exit(0);
            }
            if nginx_sys::ngx_quit != 0 {
                // Drive the event loop until the export task's graceful drain
                // sets EXPORT_LOOP_DONE or the backstop deadline is reached.
                // The exporter is not subject to ngx_event_no_timers_left, so
                // cancelable sleep timers fire normally and the export loop
                // detects ngx_quit within SHUTDOWN_POLL_INTERVAL (250 ms).
                //
                // Ring-drain ownership on reload uses successor_gen abdication
                // (not a time-based dedup, which races on log/span ring
                // `pop_into`): the master bumps successor_gen before forking
                // the new exporter; the old one checks it here and skips ring
                // pops when a successor is present. See graceful_drain in
                // export/mod.rs for the abdication logic.
                //
                // `ngx_process_events_and_timers` BLOCKS on epoll/kqueue, so
                // the backstop timer (fires at GRACEFUL_DRAIN_BACKSTOP ms) is
                // required to guarantee the call always returns by the
                // deadline — without it, an early export_loop abort (bad
                // endpoint) leaves no active fds/timers and the block would
                // never return, hanging `nginx -s quit`. The noop handler just
                // returns, letting the `now() < drain_deadline` check re-run.
                //
                // SAFETY (mem::zeroed): `ngx_event_t` is a C POD struct; an
                // all-zero bit-pattern is a valid initial state for an unarmed
                // event (same pattern as ngx-rust/src/async_/sleep.rs
                // TimerEvent::new).  We are inside the outer `unsafe {}` at
                // the top of otel_exporter_cycle.
                let mut backstop_ev: nginx_sys::ngx_event_t = core::mem::zeroed();
                backstop_ev.handler = Some(noop_timer_handler);
                // SAFETY ((*cycle).log): cycle is the valid non-null cycle
                // pointer established by the outer SAFETY contract.
                backstop_ev.log = (*cycle).log;
                // backstop_ev is NOT moved while armed — stays on the call
                // stack until del_timer below completes.
                // SAFETY: cycle is the valid non-null cycle pointer established by
                // the outer SAFETY contract; conf_ctx indexing uses the same pattern
                // as lib.rs:232-234 and drop_privileges_and_chdir.
                let shutdown_timeout_ms: u64 = {
                    let core_idx = nginx_sys::ngx_core_module.index;
                    let raw_conf: *mut *mut *mut core::ffi::c_void =
                        *(*cycle).conf_ctx.add(core_idx);
                    let ccf: *const nginx_sys::ngx_core_conf_t = raw_conf.cast();
                    if ccf.is_null() {
                        0
                    } else {
                        (*ccf).shutdown_timeout as u64
                    }
                };
                let drain_cap =
                    effective_drain_backstop(GRACEFUL_DRAIN_BACKSTOP, shutdown_timeout_ms);
                let backstop_ms = drain_cap.as_millis() as nginx_sys::ngx_msec_t;
                // SAFETY (ngx_add_timer): backstop_ev is a valid non-null
                // ngx_event_t on the stack; ngx_current_msec and
                // ngx_event_timer_rbtree are initialised by nginx before any
                // process cycle runs.
                nginx_sys::ngx_add_timer(&raw mut backstop_ev, backstop_ms);

                let drain_deadline = std::time::Instant::now() + drain_cap;
                while !crate::drain::EXPORT_LOOP_DONE.load(Ordering::Acquire)
                    && std::time::Instant::now() < drain_deadline
                {
                    nginx_sys::ngx_process_events_and_timers(cycle);
                }

                // Cancel the backstop timer if it hasn't fired yet (clean drain).
                if backstop_ev.timer_set() != 0 {
                    // SAFETY (ngx_del_timer): backstop_ev is still live on the
                    // stack; timer_set() being non-zero confirms it is still in
                    // the rbtree.
                    nginx_sys::ngx_del_timer(&raw mut backstop_ev);
                }
                let drained = crate::drain::EXPORT_LOOP_DONE.load(Ordering::Relaxed);
                notice!((*cycle).log, "otel exporter: ngx_quit, drain_done={}, exit", drained);
                std::process::exit(0);
            }
            if nginx_sys::ngx_reopen != 0 {
                nginx_sys::ngx_reopen = 0;
                nginx_sys::ngx_reopen_files(cycle, -1i32 as nginx_sys::ngx_uid_t);
                notice!((*cycle).log, "otel exporter: reopening logs");
            }
            nginx_sys::ngx_process_events_and_timers(cycle);
        }
    }
}

// ── Lifecycle helpers ─────────────────────────────────────────────────────────

/// No-op nginx event handler used as the backstop timer callback in the
/// drain-wait loop (`otel_exporter_cycle`).
///
/// When the backstop timer fires, nginx's event expire loop calls this
/// handler.  Nothing needs to happen here — merely returning causes
/// `ngx_process_events_and_timers` to return, allowing the while condition
/// (`now() < drain_deadline`) to be re-evaluated and the loop to exit.
///
/// # Safety
///
/// FFI callback invoked by nginx's timer infrastructure with a valid (possibly
/// null-data) `ngx_event_t`.  The handler accesses nothing through `ev`.
unsafe extern "C" fn noop_timer_handler(_ev: *mut nginx_sys::ngx_event_t) {}

/// Liveness heartbeat timer handler (exporter process).
///
/// Stamps the exporter's `ngx_current_msec` (monotonic, `CLOCK_MONOTONIC`
/// basis — same basis workers compare against) into
/// `ControlShm::last_beat_msec`, then re-arms itself for
/// [`crate::liveness::HEARTBEAT_PERIOD_MS`].  Runs entirely on the exporter's
/// single-threaded event loop; one Release store + one rbtree insertion per
/// period.  Independent of drain/send progress by construction — see the
/// registration comment in `otel_exporter_cycle` step 11.5.
///
/// # Safety
///
/// FFI callback invoked by nginx's timer expiry with the pool-pinned event
/// registered in `otel_exporter_cycle`; `ev.data` is the live `ControlShm`
/// pointer for the mapped control zone (process lifetime).
unsafe extern "C" fn heartbeat_timer_handler(ev: *mut nginx_sys::ngx_event_t) {
    // SAFETY: `ev` is the valid pool-pinned event (fn contract); `data` was set
    // to the live ControlShm pointer at registration; `last_beat_msec` is an
    // AtomicU64, so the cross-process store is well-defined. `ngx_current_msec`
    // is updated by this process's own single-threaded event loop.
    unsafe {
        let ctrl = (*ev).data as *const crate::exporter::control_shm::ControlShm;
        if !ctrl.is_null() {
            (*ctrl).last_beat_msec.store(nginx_sys::ngx_current_msec as u64, Ordering::Release);
        }
        // Re-arm unconditionally: beating while draining on ngx_quit is
        // correct (the exporter IS alive); the timer dies with the process.
        nginx_sys::ngx_add_timer(ev, crate::liveness::HEARTBEAT_PERIOD_MS as nginx_sys::ngx_msec_t);
    }
}

/// Close sibling process channel FDs that this process should not own.
///
/// Transcribed from `ngx_worker_process_init:900-923`
/// (`nginx/src/os/unix/ngx_process_cycle.c`). Iterates
/// `ngx_processes[0..ngx_last_process]` and closes `channel[1]` for every
/// slot that is not ours, then closes our own `channel[0]` (the master end —
/// we only need `channel[1]` which nginx sets as `ngx_channel` before fork).
///
/// # Safety
///
/// Accesses nginx globals `ngx_processes`, `ngx_last_process`,
/// `ngx_process_slot`. Called exclusively from `otel_exporter_cycle` while
/// still in the single-thread forked child before any event loop is running.
unsafe fn close_sibling_channels(cycle: *mut nginx_sys::ngx_cycle_t) {
    let last = nginx_sys::ngx_last_process as usize;
    let slot = nginx_sys::ngx_process_slot as usize;

    for n in 0..last {
        if n == slot {
            continue; // skip our own slot
        }
        let pid = nginx_sys::ngx_processes[n].pid;
        if pid == -1 {
            continue; // empty slot
        }
        let ch1 = nginx_sys::ngx_processes[n].channel[1];
        if ch1 == -1 {
            continue; // no write end to close
        }
        if libc::close(ch1) == -1 {
            alert!(
                (*cycle).log,
                "otel exporter: close() channel[1] for slot {} (pid={}) failed",
                n,
                pid
            );
        }
    }

    // Close our own channel[0] (the master's write end). We keep channel[1]
    // (ngx_channel) — that's the fd we registered for channel events.
    let ch0 = nginx_sys::ngx_processes[slot].channel[0];
    if ch0 != -1 && libc::close(ch0) == -1 {
        alert!((*cycle).log, "otel exporter: close() channel[0] for our slot failed");
    }
}

/// Drop privileges to the configured nginx user and chdir to the working
/// directory.
///
/// Order: `setgid` → `initgroups` → `setuid` → `chdir`, mirroring
/// `ngx_worker_process_init:799-879`. Skipped when `geteuid() != 0` (same
/// guard as the C source at :799) — on macOS dev machines this branch always
/// skips since the exporter isn't running as root.
///
/// Omits the `NGX_HAVE_CAPABILITIES` + `transparent` branch (no transparent
/// proxying here) and `prctl(PR_SET_DUMPABLE)` (coredump nice-to-have, not
/// correctness-required); add either if requirements change.
///
/// # Safety
///
/// Accesses `ngx_core_module` and dereferences `cycle->conf_ctx`. Called
/// exclusively from `otel_exporter_cycle` in the forked child.
unsafe fn drop_privileges_and_chdir(cycle: *mut nginx_sys::ngx_cycle_t) {
    // Resolve ngx_core_conf_t via ngx_get_conf(cycle->conf_ctx, ngx_core_module)
    // (same pattern as config.rs::register_shm_zone:292-305). conf_ctx is
    // *mut *mut *mut *mut c_void; indexing by core_module.index gives the
    // *mut *mut *mut c_void that points to ngx_core_conf_t.
    let core_idx = nginx_sys::ngx_core_module.index;
    // Safety: conf_ctx is a valid array of pointers set by nginx at startup.
    let raw_conf: *mut *mut *mut c_void = *(*cycle).conf_ctx.add(core_idx);
    let ccf: *const nginx_sys::ngx_core_conf_t = raw_conf.cast();
    if ccf.is_null() {
        return;
    }

    // Only drop privileges when running as root — same guard as
    // ngx_worker_process_init:799.  On macOS dev machines geteuid() != 0 so
    // this branch is skipped; the exporter runs as the current user (not root).
    if libc::geteuid() != 0 {
        return;
    }

    // setgid MUST come before setuid (once setuid drops, setgid is locked).
    if libc::setgid((*ccf).group as libc::gid_t) == -1 {
        emerg!((*cycle).log, "otel exporter: setgid({}) failed", (*ccf).group);
        // Fatal: exit(2) disables respawn — privilege-drop failure is
        // unrecoverable (ngx_process.c:551-557).
        std::process::exit(2);
    }

    // initgroups failure is non-fatal (mirrors nginx worker behaviour).
    // libc::initgroups takes c_int on macOS/BSD but gid_t (u32) on Linux —
    // see libc 0.2 platform shims. Cast through a per-platform alias so the
    // call compiles cleanly on both arms.
    #[cfg(target_os = "linux")]
    let initgroups_gid = (*ccf).group as libc::gid_t;
    #[cfg(not(target_os = "linux"))]
    let initgroups_gid = (*ccf).group as libc::c_int;
    if libc::initgroups((*ccf).username, initgroups_gid) == -1 {
        alert!((*cycle).log, "otel exporter: initgroups() failed (non-fatal)");
    }

    if libc::setuid((*ccf).user as libc::uid_t) == -1 {
        emerg!((*cycle).log, "otel exporter: setuid({}) failed", (*ccf).user);
        std::process::exit(2);
    }

    if (*ccf).working_directory.len > 0 && libc::chdir((*ccf).working_directory.data.cast()) == -1 {
        alert!((*cycle).log, "otel exporter: chdir() failed");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;
    use std::sync::{Mutex, OnceLock};

    // Serialises tests that mutate nginx global state (`ngx_process`,
    // `ngx_worker`, `IS_OTEL_EXPORTER`). Tests run in parallel by default; a
    // shared mutex prevents concurrent writes from producing spurious failures.
    static GLOBAL_STATE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn global_state_lock() -> &'static Mutex<()> {
        GLOBAL_STATE_LOCK.get_or_init(|| Mutex::new(()))
    }

    /// With `IS_OTEL_EXPORTER = false` and `ngx_process = HELPER`,
    /// `ngx_process()` must return `NgxProcess::Helper`.
    #[test]
    fn ngx_process_returns_helper_when_not_exporter() {
        let _guard = global_state_lock().lock().unwrap();
        IS_OTEL_EXPORTER.store(false, Ordering::SeqCst);
        // SAFETY: `global_state_lock` serialises all nginx process-global
        // mutation across tests; single-threaded test, reset before asserting.
        unsafe {
            nginx_sys::ngx_process = nginx_sys::NGX_PROCESS_HELPER as nginx_sys::ngx_uint_t;
        }
        let result = ngx_process();
        // Reset before the assert so state is clean even if it panics.
        // SAFETY: see above.
        unsafe {
            nginx_sys::ngx_process = nginx_sys::NGX_PROCESS_SINGLE as nginx_sys::ngx_uint_t;
        }
        assert_eq!(result, NgxProcess::Helper);
    }

    /// With `IS_OTEL_EXPORTER = true` and `ngx_process = HELPER`,
    /// `ngx_process()` must return `NgxProcess::Exporter`.
    #[test]
    fn ngx_process_returns_exporter_when_flag_set() {
        let _guard = global_state_lock().lock().unwrap();
        IS_OTEL_EXPORTER.store(false, Ordering::SeqCst); // reset first
                                                         // SAFETY: `global_state_lock` serialises all nginx process-global
                                                         // mutation across tests; single-threaded test, reset before asserting.
        unsafe {
            nginx_sys::ngx_process = nginx_sys::NGX_PROCESS_HELPER as nginx_sys::ngx_uint_t;
        }
        IS_OTEL_EXPORTER.store(true, Ordering::SeqCst);
        let result = ngx_process();
        IS_OTEL_EXPORTER.store(false, Ordering::SeqCst);
        // SAFETY: see above.
        unsafe {
            nginx_sys::ngx_process = nginx_sys::NGX_PROCESS_SINGLE as nginx_sys::ngx_uint_t;
        }
        assert_eq!(result, NgxProcess::Exporter);
    }

    /// With `ngx_process = WORKER` and `ngx_worker = 0`,
    /// `ngx_process()` must return `NgxProcess::Worker(0)`.
    #[test]
    fn ngx_process_returns_worker_zero() {
        let _guard = global_state_lock().lock().unwrap();
        IS_OTEL_EXPORTER.store(false, Ordering::SeqCst);
        // SAFETY: `global_state_lock` serialises all nginx process-global
        // mutation across tests; single-threaded test, reset before asserting.
        unsafe {
            nginx_sys::ngx_process = nginx_sys::NGX_PROCESS_WORKER as nginx_sys::ngx_uint_t;
            nginx_sys::ngx_worker = 0;
        }
        let result = ngx_process();
        // SAFETY: see above.
        unsafe {
            nginx_sys::ngx_process = nginx_sys::NGX_PROCESS_SINGLE as nginx_sys::ngx_uint_t;
        }
        assert_eq!(result, NgxProcess::Worker(0));
    }

    // ── Direct tests of the REAL `crash_backoff_ms()` function ───────────────
    // Call the production function, not a simulation — guards against the
    // "duplicate-logic" masking pattern (control_shm's `simulate_startup`
    // re-implements the formula locally; a silent drift there wouldn't be
    // caught without this cross-check).

    /// count = 0: first start (pre-increment value), no backoff expected.
    #[test]
    fn backoff_count_zero_is_no_backoff() {
        assert_eq!(crash_backoff_ms(0), 0, "count=0 must return 0ms");
    }

    /// count = 1: first start (post-increment value), no backoff expected.
    #[test]
    fn backoff_count_one_is_no_backoff() {
        assert_eq!(crash_backoff_ms(1), 0, "count=1 must return 0ms (first start)");
    }

    /// count = 2: first restart.  Formula: BASE * 2^(count-1) = 100 * 2^1 = 200ms.
    #[test]
    fn backoff_count_two_is_200ms() {
        assert_eq!(crash_backoff_ms(2), 200, "count=2 must return 200ms");
    }

    /// count = 3: second restart.  Formula: 100 * 2^2 = 400ms.
    #[test]
    fn backoff_count_three_is_400ms() {
        assert_eq!(crash_backoff_ms(3), 400, "count=3 must return 400ms");
    }

    /// count = 4: third restart.  Formula: 100 * 2^3 = 800ms.
    #[test]
    fn backoff_count_four_is_800ms() {
        assert_eq!(crash_backoff_ms(4), 800, "count=4 must return 800ms");
    }

    /// count = 5: fourth restart (last before self-disable in the default config).
    /// Formula: 100 * 2^4 = 1600ms.
    #[test]
    fn backoff_count_five_is_1600ms() {
        assert_eq!(crash_backoff_ms(5), 1_600, "count=5 must return 1600ms");
    }

    /// count = MAX_CRASH_RESTARTS (5) — the give-up boundary; the exporter's
    /// exit(2) branch fires at count > MAX_CRASH_RESTARTS, so this is the last
    /// count that still produces a backoff. `crash_backoff_ms` itself has no
    /// knowledge of that threshold — just returns the capped formula.
    #[test]
    fn backoff_at_max_crash_restarts_boundary() {
        let at_boundary = crash_backoff_ms(MAX_CRASH_RESTARTS);
        assert_eq!(at_boundary, 1_600, "backoff at MAX_CRASH_RESTARTS must be 1600ms");
    }

    /// count > MAX_CRASH_RESTARTS: backoff formula still computes (the give-up
    /// branch in `otel_exporter_cycle` exits BEFORE calling `crash_backoff_ms`,
    /// but the function itself should be total and cap at CRASH_BACKOFF_CAP_MS).
    #[test]
    fn backoff_exceeding_max_restarts_caps_at_5000ms() {
        // count=6: 100 * 2^5 = 3200ms (still under 5000ms cap).
        assert_eq!(crash_backoff_ms(6), 3_200, "count=6 must return 3200ms");

        // count=7: 100 * 2^6 = 6400ms → capped at 5000ms.
        assert_eq!(crash_backoff_ms(7), CRASH_BACKOFF_CAP_MS, "count=7 must return cap (5000ms)");

        // Large count: must not overflow or panic; must equal the cap.
        assert_eq!(
            crash_backoff_ms(100),
            CRASH_BACKOFF_CAP_MS,
            "large count must return cap (5000ms)"
        );
    }

    /// Overflow safety: count = u64::MAX must not panic; the shift is capped at 31.
    #[test]
    fn backoff_u64_max_does_not_overflow() {
        let result = crash_backoff_ms(u64::MAX);
        assert_eq!(
            result, CRASH_BACKOFF_CAP_MS,
            "u64::MAX count must return cap (5000ms), not overflow"
        );
    }

    // ── N3: effective_drain_backstop ──────────────────────────────────────────

    /// N3: timeout = 0 (nginx default) → use the module default, unchanged.
    ///
    /// Mutation evidence (executed, both halves recorded in commit):
    /// change `min` to `max` in `effective_drain_backstop` →
    /// the `timeout=5000` test returns `15s` instead of `5s` → FAILS.
    #[test]
    fn n3_drain_backstop_zero_timeout_returns_default() {
        let default = std::time::Duration::from_secs(15);
        assert_eq!(
            effective_drain_backstop(default, 0),
            default,
            "timeout=0 (unset) must return the default backstop"
        );
    }

    #[test]
    fn n3_drain_backstop_shorter_timeout_is_honoured() {
        let default = std::time::Duration::from_secs(15);
        assert_eq!(
            effective_drain_backstop(default, 5_000),
            std::time::Duration::from_secs(5),
            "timeout=5000ms is shorter than 15s and must be used"
        );
    }

    #[test]
    fn n3_drain_backstop_longer_timeout_is_capped_at_default() {
        let default = std::time::Duration::from_secs(15);
        assert_eq!(
            effective_drain_backstop(default, 60_000),
            default,
            "timeout=60s is longer than 15s and must be capped at the default"
        );
    }
}
