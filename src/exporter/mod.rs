// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Exporter process lifecycle — Phase 1.3.2.
//!
//! This module provides the `nginx: otel exporter` child process, spawned by
//! master via the `init_module` hook in `src/lib.rs`. The exporter handles
//! master channel signals (QUIT / TERMINATE / REOPEN), drops privileges to the
//! configured nginx user, runs the nginx event loop, and now (Phase 1.3.2)
//! owns the async export task spawned via [`ngx::async_::spawn`].
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
///
/// Reading this flag is a single `Relaxed` atomic load — zero cost in
/// non-exporter processes (the load is only on the cold path inside
/// `ngx_process()`). The flag is set once and never cleared.
pub(crate) static IS_OTEL_EXPORTER: AtomicBool = AtomicBool::new(false);

/// Process identity as seen from inside the `ngx-otel-rust` crate.
///
/// Mirrors [`nginx-acme/src/util.rs`](../../../nginx-acme/src/util.rs)
/// `NgxProcess` but adds the `Exporter` variant that distinguishes the
/// dedicated `nginx: otel exporter` child from a generic helper. The
/// distinction is tracked via the process-local `IS_OTEL_EXPORTER` flag.
///
/// See `PHASE_1_3_RESEARCH.md` §3.5 for the design rationale.
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

/// Returns the current process identity.
///
/// Reads the nginx global `ngx_process` and, for the `NGX_PROCESS_HELPER`
/// case, the process-local `IS_OTEL_EXPORTER` flag. This is a cold-path
/// helper — it is only called from gating predicates, never from the
/// request hot path.
pub(crate) fn ngx_process() -> NgxProcess {
    let p = unsafe { nginx_sys::ngx_process } as u32;
    match p {
        nginx_sys::NGX_PROCESS_SINGLE => NgxProcess::Single,
        nginx_sys::NGX_PROCESS_MASTER => NgxProcess::Master,
        nginx_sys::NGX_PROCESS_SIGNALLER => NgxProcess::Signaller,
        nginx_sys::NGX_PROCESS_WORKER => {
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
/// (`nginx/src/os/unix/ngx_process_cycle.c:1088-1136`) with the addition of
/// signal-handler installation (needed at initial start because `init_module`
/// fires before `ngx_init_signals` in master — see §2.8 of the research doc).
///
/// # Sequencing constraints (order is load-bearing)
/// 1. `ngx_init_signals` BEFORE `sigprocmask` clears the mask.
/// 2. `close_sibling_channels` BEFORE `ngx_add_channel_event` (close
///    FDs we don't own; keep `ngx_channel` = our channel[1]).
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
    unsafe {
        // 0. Update ngx_cycle to point to the new cycle. At the time of fork,
        //    the master's ngx_cycle still points to the previous init cycle
        //    (nginx.c:335 sets it AFTER ngx_init_cycle returns, but our hook
        //    fires during ngx_init_cycle:649). Updating it here ensures that
        //    ngx_get_connection (and friends) read the correct connection_n.
        nginx_sys::ngx_cycle = cycle;

        // 1. Identify as exporter: set the nginx process-type global and our
        //    own process-local flag. This lets ngx_process() return Exporter
        //    rather than Helper for this process.
        nginx_sys::ngx_process = nginx_sys::NGX_PROCESS_HELPER as nginx_sys::ngx_uint_t;
        IS_OTEL_EXPORTER.store(true, Ordering::Relaxed);

        // 2. Install signal handlers. This call is idempotent on the SIGHUP
        //    path (signals are already installed in master). It is REQUIRED at
        //    initial start: init_module fires before ngx_init_signals in master
        //    (nginx.c:293 vs :345), so the forked child inherits SIG_DFL.
        //    See PHASE_1_3_RESEARCH.md §2.8.
        let _ = nginx_sys::ngx_init_signals((*cycle).log);

        // 3. Clear the blocked-signal mask inherited from master.
        //    See ngx_worker_process_init:881-886.
        let mut empty: libc::sigset_t = mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, ptr::null_mut());

        // 4. We don't accept connections. Close the listening sockets.
        nginx_sys::ngx_close_listening_sockets(cycle);

        // 5. Modest connection pool — same as cache_manager (line :1105).
        (*cycle).connection_n = 512;

        // 5a. Initialise the event system: call each module's init_process.
        //     This must happen before ngx_add_channel_event because the event
        //     module's init_process allocates cycle->connections/read_events/
        //     write_events. Mirrors ngx_worker_process_init:891-898.
        //
        //     Our own module's init_process (ngx_otel_init_process) is safe:
        //     it returns early because ngx_process = NGX_PROCESS_HELPER (not
        //     WORKER or SINGLE), so it never spawns the export task here.
        let mut i = 0usize;
        let modules: *mut *mut nginx_sys::ngx_module_t = (*cycle).modules;
        while !(*modules.add(i)).is_null() {
            let m: *mut nginx_sys::ngx_module_t = *modules.add(i);
            if let Some(init_process_fn) = (*m).init_process {
                let rc = init_process_fn(cycle);
                if rc == nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t {
                    ngx::ngx_log_error!(
                        nginx_sys::NGX_LOG_EMERG, (*cycle).log,
                        "otel exporter: module[{}] init_process returned NGX_ERROR", i
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
        //    channel[1]). This is how master sends QUIT/TERMINATE/REOPEN
        //    commands to us. See PHASE_1_3_RESEARCH.md §2.4, §3.4.
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
            ngx::ngx_log_error!(
                nginx_sys::NGX_LOG_EMERG, (*cycle).log,
                "otel exporter: ngx_add_channel_event failed; aborting"
            );
            std::process::exit(2);
        }

        // 8. Drop privileges and chdir — parity with worker_process_init.
        //    Must happen AFTER channel registration (see sequencing above).
        drop_privileges_and_chdir(cycle);

        // 9. No accept mutex — exporter doesn't accept HTTP connections.
        nginx_sys::ngx_use_accept_mutex = 0;

        // 10. Set the process title visible in `ps`. Do this last so that
        //     "otel exporter" in ps is the signal that the exporter is
        //     fully initialised.
        nginx_sys::ngx_setproctitle(c"otel exporter".as_ptr().cast_mut());

        // 11. Spawn the async export task. The task lives for the process
        //     lifetime; allocating it on the exporter's pool keeps it pinned
        //     until the cycle tears down. The task reads the shm rings written
        //     by workers via fork-shared pages (PHASE_1_3_RESEARCH.md §4.1).
        //     Sub-item 2 (Phase 1.3.2): this is the new owner of the export loop.
        let amcf = HttpOtelModule::main_conf(&mut *cycle)
            .expect("exporter cycle: missing otel main conf");
        let task = ngx::async_::spawn(crate::export::export_loop(amcf));
        let pool = Pool::from_ngx_pool((*cycle).pool);
        let _ = pool.allocate(task);

        ngx::ngx_log_error!(
            nginx_sys::NGX_LOG_NOTICE, (*cycle).log,
            "otel exporter: cycle entered, pid={}, parent={}, endpoint={}",
            nginx_sys::ngx_pid, nginx_sys::ngx_parent, amcf.exporter.endpoint
        );

        // 12. Main event loop. Polls ngx_terminate / ngx_quit / ngx_reopen
        //     exactly as ngx_cache_manager_process_cycle does.
        //     On ngx_quit: wait for the export task's graceful drain to complete
        //     (signalled via EXPORT_LOOP_DONE) before exiting.
        loop {
            if nginx_sys::ngx_terminate != 0 {
                ngx::ngx_log_error!(
                    nginx_sys::NGX_LOG_NOTICE, (*cycle).log,
                    "otel exporter: ngx_terminate, exit"
                );
                std::process::exit(0);
            }
            if nginx_sys::ngx_quit != 0 {
                // Keep driving the event loop until the export task completes
                // its graceful drain and sets EXPORT_LOOP_DONE, or until a
                // hard deadline is reached.
                //
                // §6.3 RESOLVED: the exporter is not a worker and is not subject
                // to ngx_event_no_timers_left. Cancelable sleep timers fire
                // normally, so the export loop detects ngx_quit within at most
                // SHUTDOWN_POLL_INTERVAL (250 ms) and runs graceful_drain.
                //
                // Q2 RESOLVED — option (a): on SIGHUP the old exporter races
                // workers. Dedup via time_unix_nano (cumulative-counter model).
                // Phase 2 (logs) reopens this when log-drain semantics force
                // ordered handoff.
                let drain_deadline = std::time::Instant::now()
                    + std::time::Duration::from_secs(15);
                while !crate::export::EXPORT_LOOP_DONE.load(Ordering::Acquire)
                    && std::time::Instant::now() < drain_deadline
                {
                    nginx_sys::ngx_process_events_and_timers(cycle);
                }
                let drained = crate::export::EXPORT_LOOP_DONE.load(Ordering::Relaxed);
                ngx::ngx_log_error!(
                    nginx_sys::NGX_LOG_NOTICE, (*cycle).log,
                    "otel exporter: ngx_quit, drain_done={}, exit",
                    drained
                );
                std::process::exit(0);
            }
            if nginx_sys::ngx_reopen != 0 {
                nginx_sys::ngx_reopen = 0;
                nginx_sys::ngx_reopen_files(cycle, -1i32 as nginx_sys::ngx_uid_t);
                ngx::ngx_log_error!(
                    nginx_sys::NGX_LOG_NOTICE, (*cycle).log,
                    "otel exporter: reopening logs"
                );
            }
            nginx_sys::ngx_process_events_and_timers(cycle);
        }
    }
}

// ── Lifecycle helpers ─────────────────────────────────────────────────────────

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
            ngx::ngx_log_error!(
                nginx_sys::NGX_LOG_ALERT, (*cycle).log,
                "otel exporter: close() channel[1] for slot {} (pid={}) failed",
                n, pid
            );
        }
    }

    // Close our own channel[0] (the master's write end). We keep channel[1]
    // (ngx_channel) — that's the fd we registered for channel events.
    let ch0 = nginx_sys::ngx_processes[slot].channel[0];
    if ch0 != -1 {
        if libc::close(ch0) == -1 {
            ngx::ngx_log_error!(
                nginx_sys::NGX_LOG_ALERT, (*cycle).log,
                "otel exporter: close() channel[0] for our slot failed"
            );
        }
    }
}

/// Drop privileges to the configured nginx user and chdir to the working
/// directory.
///
/// Implements the Q5-RESOLVED drop-privileges specification from
/// `PHASE_1_3_RESEARCH.md`: `setgid` → `initgroups` → `setuid`, then
/// `chdir`. Mirrors `ngx_worker_process_init:799-879`.
///
/// Skipped when `geteuid() != 0` (not running as root), mirroring the same
/// guard in the C source (`ngx_worker_process_init:799`). On macOS developer
/// machines this branch is always taken (user is not root); the exporter then
/// runs as the developer's current user, which is not root — the privilege
/// drop invariant is satisfied.
///
/// The `NGX_HAVE_CAPABILITIES` + `transparent` branch is intentionally
/// omitted: the exporter does not proxy with transparent addresses.
/// `TODO(phase-N):` if future requirements change, add it here.
///
/// `prctl(PR_SET_DUMPABLE)` is also omitted (nice-to-have for coredumps;
/// not required for correctness — can be added later).
///
/// # Safety
///
/// Accesses `ngx_core_module` and dereferences `cycle->conf_ctx`. Called
/// exclusively from `otel_exporter_cycle` in the forked child.
unsafe fn drop_privileges_and_chdir(cycle: *mut nginx_sys::ngx_cycle_t) {
    // Resolve ngx_core_conf_t via ngx_get_conf(cycle->conf_ctx, ngx_core_module).
    // Same pattern as config.rs::register_shm_zone:292-305.
    //
    // conf_ctx is *mut *mut *mut *mut c_void; indexing by core_module.index
    // gives the *mut *mut *mut c_void that points to ngx_core_conf_t.
    let core_idx = nginx_sys::ngx_core_module.index as usize;
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
        ngx::ngx_log_error!(
            nginx_sys::NGX_LOG_EMERG, (*cycle).log,
            "otel exporter: setgid({}) failed", (*ccf).group
        );
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
        ngx::ngx_log_error!(
            nginx_sys::NGX_LOG_ALERT, (*cycle).log,
            "otel exporter: initgroups() failed (non-fatal)"
        );
    }

    // TODO(phase-N): skip NGX_HAVE_CAPABILITIES + transparent branch.
    // The exporter does not proxy with transparent addresses today.

    if libc::setuid((*ccf).user as libc::uid_t) == -1 {
        ngx::ngx_log_error!(
            nginx_sys::NGX_LOG_EMERG, (*cycle).log,
            "otel exporter: setuid({}) failed", (*ccf).user
        );
        std::process::exit(2);
    }

    // TODO(phase-N): skip prctl(PR_SET_DUMPABLE) reset. Nice-to-have for
    // coredumps after setuid; not required for correctness. Add here if
    // production diagnostics demand it.

    if (*ccf).working_directory.len > 0 {
        if libc::chdir((*ccf).working_directory.data.cast()) == -1 {
            ngx::ngx_log_error!(
                nginx_sys::NGX_LOG_ALERT, (*cycle).log,
                "otel exporter: chdir() failed"
            );
            std::process::exit(2);
        }
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
        unsafe {
            nginx_sys::ngx_process = nginx_sys::NGX_PROCESS_HELPER as nginx_sys::ngx_uint_t;
        }
        let result = ngx_process();
        // Reset globals before the assert so the state is clean even if the
        // assert panics and unwinds past the mutex guard.
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
        unsafe {
            nginx_sys::ngx_process = nginx_sys::NGX_PROCESS_HELPER as nginx_sys::ngx_uint_t;
        }
        IS_OTEL_EXPORTER.store(true, Ordering::SeqCst);
        let result = ngx_process();
        // Reset globals and flag before the assert.
        IS_OTEL_EXPORTER.store(false, Ordering::SeqCst);
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
        unsafe {
            nginx_sys::ngx_process = nginx_sys::NGX_PROCESS_WORKER as nginx_sys::ngx_uint_t;
            nginx_sys::ngx_worker = 0;
        }
        let result = ngx_process();
        // Reset globals before the assert.
        unsafe {
            nginx_sys::ngx_process = nginx_sys::NGX_PROCESS_SINGLE as nginx_sys::ngx_uint_t;
        }
        assert_eq!(result, NgxProcess::Worker(0));
    }
}
