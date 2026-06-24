// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! # Zero-cost-when-disabled invariant
//!
//! Loading this module without an `otel_exporter { endpoint ... }` directive
//! MUST impose zero per-request overhead.  The invariant is maintained at
//! exactly two gating points — both checked against
//! `config::MainConfig::is_configured()`:
//!
//! 1. **Log-phase handler gate** (`src/lib.rs` — `postconfiguration`):
//!    `add_phase_handler` is called **only** when `amcf.is_configured()` is
//!    true.  If the exporter is not configured the phase handler is never
//!    registered and no per-request code runs.
//!    See `HttpOtelModule::postconfiguration` — the `if amcf.is_configured()`
//!    block surrounding the `add_phase_handler` call.
//!
//! 2. **Export-task gate** (`src/lib.rs` — `ngx_otel_init_process`):
//!    The async export loop is spawned **only** when `amcf.is_configured()` is
//!    true.  If the exporter is not configured the process hook returns early
//!    with no allocation, no task spawn, and no background activity.
//!    See `ngx_otel_init_process` — the `if !amcf.is_configured()` early
//!    return that precedes any `ngx::async_::spawn` or `Pool::allocate` call.
//!
//! **Invariant contract:**
//! - No per-request allocation on the disabled path.
//! - No per-request locking on the disabled path.
//! - No background tasks on the disabled path.
//!
//! This is the load-bearing claim for upstream acceptance: a module that is
//! loaded but unconfigured must be indistinguishable from one that is not
//! loaded at all.

#![no_std]
// Doc-comment hygiene: every intra-doc link (`[`Type`]`) must resolve, so a
// broken reference fails the `cargo doc` build instead of silently shipping a
// dead link to docs.rs.  Enforced via `make doc-check`
// (RUSTDOCFLAGS="-D warnings" cargo doc) — `cargo clippy` does not run rustdoc
// lints.  Bare URLs are warned so they get wrapped in `<...>` for rendering.
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(rustdoc::bare_urls)]
// Require a 64-bit target: the shm rings use monotonically-increasing u64
// byte offsets cast to `usize` on every push/pop, and stub_status treats
// `ngx_atomic_t` (c_ulong) as `u64`. Both assumptions break silently on
// 32-bit targets (usize truncation after 4 GiB; c_ulong == u32 != u64).
// Enforced below by the compile_error! guard. The cfg rejects ALL non-64-bit
// targets (16-bit, 32-bit, or any exotic width), not merely the 32-bit case,
// since the u64 assumptions only hold on a 64-bit pointer/atomic width.
#[cfg(not(target_pointer_width = "64"))]
compile_error!(
    "ngx-otel-rust requires a 64-bit target: 64-bit atomics are assumed \
     throughout (shm rings, stub_status)."
);

// Pull all `std` macros (format!, vec!, assert!, etc.) into global scope.
// The crate is no_std but links to std, so this is safe — it only affects
// name resolution, not the binary.  Required because generated tonic client
// stubs use bare `format!` which is not in scope in a no_std crate.
#[macro_use]
extern crate std;

use core::ptr;

use nginx_sys::{
    ngx_conf_t, ngx_core_conf_t, ngx_cycle_t, ngx_http_module_t, ngx_int_t, ngx_module_t,
    ngx_uint_t, NGX_HTTP_MODULE,
};
use ngx::core::Status;
use ngx::http::{add_phase_handler, HttpModule, HttpModuleLocationConf, HttpModuleMainConf};
// Pool is only needed for the test-support gRPC smoke harnesses in init_process.
#[cfg(any(test, feature = "test-support"))]
use ngx::core::Pool;

pub mod cert_table;
mod config;
pub mod data_model;
mod drain;
pub mod encoder;
pub(crate) mod exporter;
pub(crate) mod liveness;
pub(crate) mod logs;
mod metric_source;
pub(crate) mod processor;
pub(crate) mod shim;
mod shm;
pub(crate) mod traces;
pub mod transport;
pub(crate) mod util;

use config::NGX_HTTP_OTEL_COMMANDS;

#[derive(Debug)]
pub(crate) struct HttpOtelModule;

static NGX_HTTP_OTEL_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(HttpOtelModule::preconfiguration),
    postconfiguration: Some(HttpOtelModule::postconfiguration),
    create_main_conf: Some(HttpOtelModule::create_main_conf),
    init_main_conf: Some(HttpOtelModule::init_main_conf),
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: Some(HttpOtelModule::create_loc_conf),
    merge_loc_conf: Some(HttpOtelModule::merge_loc_conf),
};

#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_otel_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), no_mangle)]
pub static mut ngx_http_otel_module: ngx_module_t = ngx_module_t {
    ctx: ptr::addr_of!(NGX_HTTP_OTEL_MODULE_CTX).cast_mut().cast(),
    // SAFETY: indexing `[0]` of the static `mut NGX_HTTP_OTEL_COMMANDS` array via
    // `addr_of_mut!` only forms a pointer to its first element — it never reads or
    // writes the static, so there is no data race even though it is a `static mut`.
    // The array is a fixed-size const-initialised command table, so element 0 exists.
    commands: unsafe { ptr::addr_of_mut!(NGX_HTTP_OTEL_COMMANDS[0]) },
    type_: NGX_HTTP_MODULE as ngx_uint_t,

    init_master: None,
    init_module: Some(ngx_otel_init_module),
    init_process: Some(ngx_otel_init_process),
    init_thread: None,
    exit_thread: None,
    exit_process: Some(ngx_otel_exit_process),
    exit_master: None,

    ..ngx_module_t::default()
};

// SAFETY: the `MainConf` associated type matches the `create_main_conf` /
// `init_main_conf` hooks in `NGX_HTTP_OTEL_MODULE_CTX`, which allocate and
// initialise a `config::MainConfig` in this module's main-conf slot. The trait
// contract — that `MainConf` is the exact type nginx stores at our module's
// `ctx_index` — therefore holds, so the downcast in `main_conf()` is valid.
unsafe impl HttpModuleMainConf for HttpOtelModule {
    type MainConf = config::MainConfig;
}

// SAFETY: the `LocationConf` associated type matches the `create_loc_conf` /
// `merge_loc_conf` hooks wired in `NGX_HTTP_OTEL_MODULE_CTX`, which allocate
// and default-initialize a `metric_source::location_conf::LocationConf` in this
// module's loc-conf slot.  The trait contract — exact type at `ctx_index` —
// holds, so the downcast in `location_conf()` / `location_conf_mut()` is valid.
unsafe impl HttpModuleLocationConf for HttpOtelModule {
    type LocationConf = metric_source::location_conf::LocationConf;
}

// ── Shared exporter spawn helper ─────────────────────────────────────────────

/// Spawn the `nginx: otel exporter` process from the given cycle.
///
/// `is_reload` = true for SIGHUP reload (uses `NGX_PROCESS_JUST_RESPAWN`),
/// false for initial start (uses `NGX_PROCESS_RESPAWN`).
fn spawn_exporter_for_cycle(
    cycle: *mut nginx_sys::ngx_cycle_t,
    is_reload: bool,
) -> nginx_sys::ngx_int_t {
    // SAFETY: `cycle` is the cycle pointer nginx passes into `init_module`, which
    // is always non-null and valid for the duration of the hook; this hook runs
    // only in the single master/single process, so there is no concurrent aliasing
    // of the cycle through this `&mut`.
    let cycle_ref = unsafe { &mut *cycle };

    let respawn_flag: nginx_sys::ngx_int_t = if is_reload {
        // JUST_RESPAWN: new exporter is skipped on master's first signal
        // fan-out so old+new coexist during the ~100ms overlap window.
        nginx_sys::NGX_PROCESS_JUST_RESPAWN as nginx_sys::ngx_int_t
    } else {
        // RESPAWN: master auto-respawns the exporter on crash.
        nginx_sys::NGX_PROCESS_RESPAWN as nginx_sys::ngx_int_t
    };

    // SAFETY: `cycle` is valid (see above); `otel_exporter_cycle` is our own
    // `extern "C"` process entry point with a matching signature; the name is a
    // 'static NUL-terminated C string and `respawn_flag` is a valid NGX_PROCESS_*
    // constant. `ngx_spawn_process` is only ever called here from the master.
    let pid = unsafe {
        nginx_sys::ngx_spawn_process(
            cycle,
            Some(exporter::otel_exporter_cycle),
            core::ptr::null_mut(),
            c"otel exporter".as_ptr().cast_mut(),
            respawn_flag,
        )
    };

    if pid == nginx_sys::NGX_INVALID_PID as nginx_sys::ngx_pid_t {
        ngx::ngx_log_error!(
            nginx_sys::NGX_LOG_ERR,
            cycle_ref.log,
            "otel: failed to spawn exporter process"
        );
        return Status::NGX_ERROR.into();
    }

    ngx::ngx_log_error!(
        nginx_sys::NGX_LOG_NOTICE,
        cycle_ref.log,
        "otel: spawned exporter process, pid={}, reload={}",
        pid,
        is_reload
    );
    Status::NGX_OK.into()
}

// ── Zone-sizing validation ──────────────────────────────────────────────────

/// Detect the pre-daemon context where the first-generation exporter will be
/// orphaned.
///
/// Returns `true` when ALL of:
///   - `ccf->daemon == 1` (the `daemon on` directive — default)
///   - `ngx_daemonized == 0` (we have NOT yet forked the daemon master;
///     nginx sets this flag in `main()` AFTER `ngx_daemon()` returns —
///     `nginx/src/core/nginx.c` line 354; at `init_module` time it is still 0)
///   - `ngx_inherited == 0` (not a USR2 binary-upgrade child, where nginx
///     sets `ngx_daemonized = 1` unconditionally — `nginx/src/core/nginx.c`
///     line 358)
///
/// When this function returns `true`, `ngx_spawn_process` is about to fork E
/// from the pre-daemon P0.  After `ngx_daemon()` forks the long-lived master M
/// and P0 exits, E's PPID reparents to 1 (init).  M inherits the
/// `ngx_processes[]` entry but `waitpid(-1, WNOHANG)` in M's SIGCHLD handler
/// (`ngx_process_get_status` in `ngx_process.c`) never reaps E — only E's
/// REAL parent (init, PID 1) receives SIGCHLD when E exits.
/// Consequence: crash-respawn and the backoff loop are inoperative for the
/// gen-1 exporter under `daemon on`.
///
/// # Safety
/// `cycle` must be a valid non-null `ngx_cycle_t` pointer.
unsafe fn is_pre_daemon_initial_start(cycle: *const nginx_sys::ngx_cycle_t) -> bool {
    // Check ccf->daemon first (cheapest).
    // SAFETY: caller guarantees `cycle` is valid and non-null.
    let cycle_ref = unsafe { &*cycle };
    let core_idx = nginx_sys::ngx_core_module.index;
    // SAFETY: conf_ctx is initialised by nginx; indexing by core_idx is in-bounds.
    let raw_conf: *mut *mut *mut core::ffi::c_void = unsafe { *cycle_ref.conf_ctx.add(core_idx) };
    let core_conf = raw_conf.cast::<ngx_core_conf_t>();
    if core_conf.is_null() {
        return false;
    }
    // SAFETY: core_conf is non-null and valid at init_module time.
    let daemon_flag = unsafe { (*core_conf).daemon };
    if daemon_flag == 0 {
        return false; // daemon off — no double-fork
    }
    // SAFETY: `ngx_daemonized` and `ngx_inherited` are nginx globals written
    // by `main()` before re-entering `init_module` on SIGHUP, and never mutated
    // concurrently.  The plain reads are race-free at init_module time.
    let daemonized = unsafe { nginx_sys::ngx_daemonized };
    // SAFETY: same as ngx_daemonized above — process-lifetime global, read-only here.
    let inherited = unsafe { nginx_sys::ngx_inherited };
    daemonized == 0 && inherited == 0
}

/// Read the final `worker_processes` from the fully-parsed nginx cycle.
///
/// Called from `ngx_otel_init_module` (post-parse, so the value is final)
/// and from `check_zone_sizing` to detect the directive-ordering mismatch
/// where `worker_processes` exceeds the capacity reserved at zone registration.
///
/// # Safety
/// `cycle` must be a valid non-null `ngx_cycle_t` pointer.
unsafe fn worker_processes_from_cycle(cycle: *const nginx_sys::ngx_cycle_t) -> Option<usize> {
    // SAFETY: caller guarantees `cycle` is valid.
    let cycle_ref = unsafe { &*cycle };
    let core_idx = nginx_sys::ngx_core_module.index;
    // SAFETY: conf_ctx is initialised by nginx; indexing by core_idx is in-bounds.
    let raw_conf: *mut *mut *mut core::ffi::c_void = unsafe { *cycle_ref.conf_ctx.add(core_idx) };
    let core_conf = raw_conf.cast::<ngx_core_conf_t>();
    if core_conf.is_null() {
        return None;
    }
    // SAFETY: core_conf is non-null; struct is valid at init_module time.
    let wp = unsafe { (*core_conf).worker_processes };
    // NGX_CONF_UNSET = -1; after a full parse the value is either set or the
    // nginx default (1).  Treat anything < 1 as unknown = None.
    if wp < 1 {
        None
    } else {
        Some(wp as usize)
    }
}

/// Zone-sizing validation at init_module time.
///
/// Computes the RESERVED capacity (from each zone's registered size) and
/// compares it against the ACTUAL (post-parse, final) `worker_processes`.
///
/// - Normal case: actual_workers ≤ reserved → `amcf.n_active_workers` is set
///   and the exporter uses it to drain only active slots.
/// - Residual error case: actual_workers > reserved — this happens when an
///   explicit large count appears after `http{}` on a box where ncpu < count.
///   The operator gets a clear error and nginx refuses to start/reload.
///
/// Zones are sized for `max(ngx_ncpu, actual_workers)` at parse time,
/// so the typical `worker_processes N;` after `http{}` succeeds as long as
/// N ≤ ncpu.
///
/// `nginx -t` skips `init_module` (ngx_test_config is set, caller returns
/// early), so this check does not apply during config-test runs.
///
/// # Safety
/// `cycle` and `amcf` must be valid non-null pointers.
unsafe fn check_zone_sizing(
    cycle: *mut nginx_sys::ngx_cycle_t,
    amcf: &crate::config::MainConfig,
) -> Result<(), ()> {
    use core::sync::atomic::Ordering;

    // SAFETY: `cycle` is valid per the `unsafe fn` contract.
    let actual_workers = unsafe { worker_processes_from_cycle(cycle) }.unwrap_or(1);

    // Helper: derive the reserved capacity from the registered zone size.
    let reserved_metrics = |zone_ptr: *mut nginx_sys::ngx_shm_zone_t| -> usize {
        if zone_ptr.is_null() {
            return usize::MAX; // not registered — no constraint
        }
        // SAFETY: zone_ptr non-null; shm.size is immutable after registration.
        let size = unsafe { (*zone_ptr).shm.size };
        crate::shm::n_workers_from_zone_size(size)
    };
    let reserved_logs = |zone_ptr: *mut nginx_sys::ngx_shm_zone_t, cap: usize| -> usize {
        if zone_ptr.is_null() {
            return usize::MAX;
        }
        // SAFETY: zone_ptr is non-null per the guard above; shm.size is written
        // at zone registration and immutable thereafter.
        let size = unsafe { (*zone_ptr).shm.size };
        let avail = size.saturating_sub(crate::shm::data_offset());
        let slot = crate::shm::logs_slot_size(cap);
        avail.checked_div(slot).unwrap_or(usize::MAX)
    };
    let reserved_spans = |zone_ptr: *mut nginx_sys::ngx_shm_zone_t, cap: usize| -> usize {
        if zone_ptr.is_null() {
            return usize::MAX;
        }
        // SAFETY: zone_ptr is non-null per the guard above; shm.size is written
        // at zone registration and immutable thereafter.
        let size = unsafe { (*zone_ptr).shm.size };
        let avail = size.saturating_sub(crate::shm::data_offset());
        let slot = crate::shm::spans_slot_size(cap);
        avail.checked_div(slot).unwrap_or(usize::MAX)
    };

    let logs_cap = amcf.log_ring_cap();
    let spans_cap = crate::shm::DEFAULT_SPAN_RING_CAP;

    let res_metrics = reserved_metrics(amcf.shm_zone);
    let res_logs = reserved_logs(amcf.logs_shm_zone, logs_cap);
    let res_spans = reserved_spans(amcf.spans_shm_zone, spans_cap);

    // The minimum reserved capacity across all registered zones.
    let min_reserved = res_metrics.min(res_logs).min(res_spans);

    if actual_workers <= min_reserved {
        // All zones have sufficient capacity.  Record the active count so the
        // exporter drains only active slots (not reserved-but-inactive ones).
        // SAFETY: amcf is valid per the `unsafe fn` contract.
        amcf.n_active_workers.store(actual_workers, Ordering::Relaxed);
        return Ok(());
    }

    // actual_workers > reserved — the residual error case.
    // This happens when an explicit large count (e.g. `worker_processes 64`)
    // appears AFTER `http{}` on a box where ncpu (= reserved capacity) < 64.
    // Refuse to start so the operator gets a clear message.
    //
    // SAFETY: `cycle` is valid; `.log` is non-null.
    let log = unsafe { (*cycle).log };
    ngx::ngx_log_error!(
        nginx_sys::NGX_LOG_EMERG,
        log,
        "otel: shm zones were reserved for {} worker slots (ngx_ncpu at parse time) \
         but worker_processes={}; move the worker_processes directive BEFORE the \
         http{{}} block, or reduce it to ≤ {}, and reload",
        min_reserved,
        actual_workers,
        min_reserved
    );
    Err(())
}

// ── init_module callback ──────────────────────────────────────────────────────

/// Called by nginx from `ngx_init_modules` (via `ngx_init_cycle`) — once at
/// initial start and again on each SIGHUP reload.
///
/// Forks the `nginx: otel exporter` child process from master, gated on
/// `MainConfig::is_configured()`. Uses `NGX_PROCESS_RESPAWN` for initial
/// start (auto-respawn on crash) and `NGX_PROCESS_JUST_RESPAWN` for SIGHUP
/// reloads (skipped on the first signal fan-out so old+new exporter coexist
/// briefly — same pattern as `ngx_start_cache_manager_processes`).
///
/// Note on `daemon on` vs `daemon off`: nginx's `init_master` hook is defined
/// in the module API but is NOT called by nginx 1.31.x. All exporter spawning
/// is therefore done here for both modes. The USR2 integration test uses
/// `daemon off` and launches nginx from a subshell that exits immediately, so
/// nginx gets reparented to init (getppid()==1) before the USR2 signal, which
/// allows nginx to honour it. With `daemon off` the exporter is a direct child
/// of the master (no double-fork), so SIGCHLD and graceful-quit work correctly.
///
/// The exporter runs as a dedicated child process so that async I/O (tokio) is
/// fully isolated from nginx's event loop; process separation means a tokio
/// panic or network-stack freeze cannot stall nginx worker request handling.
extern "C" fn ngx_otel_init_module(cycle: *mut nginx_sys::ngx_cycle_t) -> nginx_sys::ngx_int_t {
    // SAFETY: `ngx_process` is a nginx global written once by the master before
    // any module init hook runs and thereafter read-only within a process, so this
    // plain read of the `static mut` cannot race.
    let process = unsafe { nginx_sys::ngx_process } as u32;
    if process != nginx_sys::NGX_PROCESS_MASTER && process != nginx_sys::NGX_PROCESS_SINGLE {
        return Status::NGX_OK.into();
    }

    // Don't spawn an exporter during `nginx -t` (config-test mode).
    // SAFETY: `ngx_test_config` is a nginx global set from the command line before
    // module init and not mutated afterwards, so this read of the `static mut` is
    // race-free.
    if unsafe { nginx_sys::ngx_test_config } != 0 {
        return Status::NGX_OK.into();
    }

    // SAFETY: `cycle` is the non-null, valid cycle nginx passes to `init_module`;
    // this hook runs only in the master/single process so the `&mut` does not alias.
    let cycle_ref = unsafe { &mut *cycle };
    let Some(amcf) = HttpOtelModule::main_conf(cycle_ref) else {
        return Status::NGX_OK.into();
    };
    if !amcf.is_configured() {
        return Status::NGX_OK.into();
    }

    // Fail-fast: verify every shm zone was sized for the actual
    // worker_processes count.  Catches the directive ordering where
    // `worker_processes N;` appears after `http{}` — postconfiguration sees
    // NGX_CONF_UNSET and sizes for 1, then workers 1..N-1 would write past the
    // zone end.  We refuse to start with a clear error instead.
    //
    // SAFETY: `cycle` is valid (verified above); `amcf` is the main conf for
    // this cycle.
    if unsafe { check_zone_sizing(cycle, amcf) }.is_err() {
        return Status::NGX_ERROR.into();
    }

    // Detect SIGHUP reload vs initial start via old_cycle->conf_ctx.
    // See existing comment above for the IMPORTANT note about ngx_is_init_cycle.
    // SAFETY: `cycle` is valid (above). `old_cycle` is a pointer nginx initialises
    // for every cycle (null on first start, the prior cycle on SIGHUP); both it and
    // its `conf_ctx` are null-checked before any further deref, so no invalid read.
    let is_reload = unsafe {
        let old = (*cycle).old_cycle;
        !old.is_null() && !(*old).conf_ctx.is_null()
    };

    // On reload, announce the successor BEFORE forking the new exporter.
    // This runs in the master process, sequentially before `ngx_spawn_process`
    // is called.  The channel message (NGX_CMD_QUIT) sent to the old exporter
    // by the master AFTER this point provides the happens-before ordering: by
    // the time the old exporter's channel handler fires and sets ngx_quit, the
    // Release store below is already visible.
    //
    // Old exporter snapshot: `my_gen` captured at startup.
    // `current_gen > my_gen` → reload → abdicate ring pops (new exporter owns).
    // `current_gen == my_gen` → pure shutdown → full drain (sole consumer).
    //
    // The increment MUST happen before the fork below, not after: the new
    // exporter reads `successor_gen` once at startup (`export_loop`'s `my_gen`
    // snapshot) and the fork() in `ngx_spawn_process` is the happens-before
    // edge that makes this store visible to that child read.  Incrementing
    // after the fork would race the child's snapshot.  Because the increment
    // therefore precedes the (fallible) spawn, a failed fork would otherwise
    // leave `successor_gen` permanently bumped with NO new exporter present:
    // the OLD exporter — still the sole live consumer — would then observe
    // `current_gen > my_gen`, latch `periodic_abdicated = true` forever, and
    // stop popping the log/span rings (rings fill → permanent telemetry loss
    // after a failed reload).  We roll the increment back on the spawn-error
    // path below to keep `successor_gen` consistent with the set of live
    // exporters: incremented iff a successor was actually forked.
    let mut announced_successor_ctrl: *const exporter::control_shm::ControlShm = core::ptr::null();
    if is_reload {
        if let Some(ctrl_ptr) = amcf.control_shm_ptr_mut() {
            // SAFETY: `control_shm_ptr_mut()` returns Some only when the zone is
            // registered and mapped; this code runs in the master process only
            // (guarded above), so there is no concurrent write — the old exporter
            // only reads this field after it receives NGX_CMD_QUIT (via channel),
            // which is sent after this function returns.
            let ctrl = unsafe { &*ctrl_ptr };
            ctrl.announce_successor();
            announced_successor_ctrl = ctrl_ptr;
        }
    }

    // Warn when the first-generation exporter will be orphaned after daemonize.
    //
    // nginx/src/core/nginx.c call order:
    //   line 293: ngx_init_cycle() → ngx_init_modules() → this callback
    //   line 350: ngx_daemon() — forks M, P0 exits → exporter PPID becomes 1
    //   line 354: ngx_daemonized = 1 — set AFTER daemon fork, in M only
    //
    // When is_pre_daemon_initial_start() returns true we are in P0 (the
    // pre-daemon spawner that will exit).  After ngx_spawn_process(E) below:
    //   - E is a child of P0; after ngx_daemon P0 exits; E's PPID → 1 (init).
    //   - M inherits E's ngx_processes[] entry, but SIGCHLD from E goes to
    //     init → ngx_process_get_status's waitpid(-1) in M never reaps E →
    //     crash-respawn is dead for this generation.
    // No fix in this loop iteration — the self-supervising wrapper (Option B)
    // is designed and deferred post-review (LIFECYCLE.md §"Known limitation").
    //
    // SAFETY: `cycle` is valid (verified above).
    if !is_reload && unsafe { is_pre_daemon_initial_start(cycle) } {
        ngx::ngx_log_error!(
            nginx_sys::NGX_LOG_ALERT,
            cycle_ref.log,
            "otel: daemon on — gen-1 exporter will be unsupervised after daemonize \
             (PPID 1; crash-respawn unavailable for this generation). \
             Run `nginx -s reload` once after startup to restore supervision. \
             See LIFECYCLE.md §\"Known limitation: gen-1 exporter under daemon on\"."
        );
    }

    // Spawn the exporter for both initial start and SIGHUP reload.
    let spawn_status = spawn_exporter_for_cycle(cycle, is_reload);

    // Roll back the successor announcement if the fork failed (NGX_INVALID_PID
    // from RLIMIT_NPROC / ENOMEM).  No successor exists, so the old exporter
    // must remain the sole consumer and keep draining the rings; leaving
    // `successor_gen` bumped would latch its `periodic_abdicated` permanently
    // (see the increment comment above).  This is a single Release decrement,
    // mirroring the increment; the master is the sole writer of this field, so
    // the round-trip leaves the counter at its pre-reload value.
    let ok: nginx_sys::ngx_int_t = Status::NGX_OK.into();
    if spawn_status != ok && !announced_successor_ctrl.is_null() {
        // SAFETY: `announced_successor_ctrl` is non-null only when set from a
        // valid `control_shm_ptr_mut()` above; same single-master-writer
        // invariant as the increment.
        let ctrl = unsafe { &*announced_successor_ctrl };
        ctrl.rollback_successor();
    }

    spawn_status
}

impl HttpModule for HttpOtelModule {
    fn module() -> &'static ngx_module_t {
        // SAFETY: `ngx_http_otel_module` is a `static mut` with process lifetime,
        // const-initialised above. After config load nginx treats the module
        // descriptor as read-only, and we only hand out a shared `&` to it, so the
        // resulting `'static` reference does not alias any live `&mut`.
        unsafe { &*::core::ptr::addr_of!(ngx_http_otel_module) }
    }

    /// Register `$otel_trace_id` and `$otel_parent_sampled` nginx variables.
    ///
    /// Both are marked `NGX_HTTP_VAR_NOCACHEABLE` — they are populated at
    /// REWRITE time from the `SpanCtx` request context and may differ from
    /// request to request.
    ///
    /// # Safety
    /// nginx calls this with a valid non-null `ngx_conf_t` during single-threaded
    /// config parsing.
    unsafe extern "C" fn preconfiguration(cf: *mut ngx_conf_t) -> nginx_sys::ngx_int_t {
        let flags = nginx_sys::NGX_HTTP_VAR_NOCACHEABLE as nginx_sys::ngx_uint_t;

        // $otel_trace_id — 32-char lowercase hex trace ID from SpanCtx.
        let mut name_trace_id: nginx_sys::ngx_str_t = ngx::ngx_string!("otel_trace_id");
        // SAFETY: `cf` is the valid non-null parse context; `name_trace_id` is a local
        // ngx_str_t with the variable name, valid for this call (nginx copies it into
        // the variable hash table during parsing); `flags` is a valid VAR_ bitfield.
        let var_trace_id =
            unsafe { nginx_sys::ngx_http_add_variable(cf, &raw mut name_trace_id, flags) };
        if var_trace_id.is_null() {
            return nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t;
        }
        // SAFETY: `var_trace_id` is the non-null `ngx_http_variable_t*` returned
        // by `ngx_http_add_variable`; writing its `get_handler` is sound (it lives
        // in the http main conf variable hash, valid for the cycle).
        unsafe { (*var_trace_id).get_handler = Some(otel_var_get_trace_id) };

        // $otel_span_id — 16-char lowercase hex span ID from SpanCtx.
        let mut name_span_id: nginx_sys::ngx_str_t = ngx::ngx_string!("otel_span_id");
        // SAFETY: same contract as the `name_trace_id` call above — `cf` valid,
        // `name_span_id` is a local ngx_str_t valid for this call.
        let var_span_id =
            unsafe { nginx_sys::ngx_http_add_variable(cf, &raw mut name_span_id, flags) };
        if var_span_id.is_null() {
            return nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t;
        }
        // SAFETY: `var_span_id` is the non-null `ngx_http_variable_t*` returned by
        // `ngx_http_add_variable`; writing its `get_handler` is sound (same conf pool).
        unsafe { (*var_span_id).get_handler = Some(otel_var_get_span_id) };

        // $otel_parent_id — 16-char lowercase hex parent span ID from SpanCtx.
        let mut name_parent_id: nginx_sys::ngx_str_t = ngx::ngx_string!("otel_parent_id");
        // SAFETY: same contract as the `name_trace_id` call above — `cf` valid,
        // `name_parent_id` is a local ngx_str_t valid for this call.
        let var_parent_id =
            unsafe { nginx_sys::ngx_http_add_variable(cf, &raw mut name_parent_id, flags) };
        if var_parent_id.is_null() {
            return nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t;
        }
        // SAFETY: `var_parent_id` is the non-null `ngx_http_variable_t*` returned by
        // `ngx_http_add_variable`; writing its `get_handler` is sound (same conf pool).
        unsafe { (*var_parent_id).get_handler = Some(otel_var_get_parent_id) };

        // $otel_parent_sampled — "1" if the W3C sampled bit is set, else "0".
        let mut name_sampled: nginx_sys::ngx_str_t = ngx::ngx_string!("otel_parent_sampled");
        // SAFETY: same contract as the `name_trace_id` call above — `cf` valid,
        // `name_sampled` is a local ngx_str_t valid for this call.
        let var_sampled =
            unsafe { nginx_sys::ngx_http_add_variable(cf, &raw mut name_sampled, flags) };
        if var_sampled.is_null() {
            return nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t;
        }
        // SAFETY: `var_sampled` is the non-null `ngx_http_variable_t*` returned by
        // `ngx_http_add_variable`; writing its `get_handler` is sound (same conf pool).
        unsafe { (*var_sampled).get_handler = Some(otel_var_get_parent_sampled) };

        nginx_sys::NGX_OK as nginx_sys::ngx_int_t
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> nginx_sys::ngx_int_t {
        // SAFETY: nginx calls `postconfiguration` with a non-null, valid `ngx_conf_t`
        // during single-threaded config parsing, so this exclusive borrow is the only
        // live reference to the conf for the duration of the call.
        let cf_ref = unsafe { &mut *cf };
        let amcf = HttpOtelModule::main_conf_mut(cf_ref).expect("otel main conf");
        let module_ptr = ::core::ptr::addr_of_mut!(ngx_http_otel_module);

        if let Err(e) = amcf.postconfiguration(cf, module_ptr) {
            return e.into();
        }

        // Register the REWRITE-phase span-start handler when configured.
        // The handler checks `amcf.is_configured()` itself on every request (zero
        // cost when unconfigured), but registration is also gated here so the
        // handler is not even in the phase chain when the module is unconfigured.
        if amcf.is_configured()
            && add_phase_handler::<metric_source::span_start::SpanStartHandler>(cf_ref).is_err()
        {
            return Status::NGX_ERROR.into();
        }

        // Register the log-phase handler only when the exporter is configured.
        if amcf.is_configured()
            && add_phase_handler::<metric_source::instrumented::LogPhaseHandler>(cf_ref).is_err()
        {
            return Status::NGX_ERROR.into();
        }

        Status::NGX_OK.into()
    }
}

// ── Variable get-handlers ($otel_trace_id, $otel_parent_sampled) ────────────

/// Tiny helper: encode `src` bytes as lowercase hex into `dst`.
///
/// Caller must ensure `dst.len() == src.len() * 2`.
fn hex_encode_into(src: &[u8], dst: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in src.iter().enumerate() {
        dst[i * 2] = HEX[(b >> 4) as usize];
        dst[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
}

/// nginx variable get-handler for `$otel_trace_id`.
///
/// Returns the W3C trace ID (32 lowercase hex chars) from the request's
/// `SpanCtx`.  Returns empty (not_found) when no `SpanCtx` is present
/// (i.e. the location has tracing disabled or the REWRITE handler has not
/// yet run).
///
/// # Safety
/// nginx calls this with a valid non-null `ngx_http_request_t*` and a valid
/// `ngx_variable_value_t*` during variable evaluation.
unsafe extern "C" fn otel_var_get_trace_id(
    r: *mut nginx_sys::ngx_http_request_t,
    v: *mut nginx_sys::ngx_variable_value_t,
    _data: usize,
) -> nginx_sys::ngx_int_t {
    use crate::traces::ctx::SpanCtx;

    // SAFETY: `r` is the non-null `ngx_http_request_t*` nginx passes to variable
    // get-handlers; `Request::from_ngx_http_request` reinterprets it as the
    // ngx-rust request wrapper (same repr) and yields a valid `&mut Request`.
    let request = unsafe { ngx::http::Request::from_ngx_http_request(r) };
    // SAFETY: `ngx_http_otel_module` is a `static` module descriptor valid for
    // the full process lifetime; `addr_of!` yields a valid pointer.
    let module = unsafe { &*::core::ptr::addr_of!(ngx_http_otel_module) };
    // Recover the SpanCtx from the pool-cleanup anchor when the module-ctx
    // slot was cleared by an internal redirect (recovery walks only on NULL slot
    // + r->internal/filter_finalize; otherwise this is a single pointer load).
    let ctx: Option<&SpanCtx> = match request.get_module_ctx::<SpanCtx>(module) {
        Some(c) => Some(c),
        // SAFETY: `r` is the live request pointer nginx passed; `module` is the
        // process-lifetime descriptor; the recovered pointer (if non-null) is a
        // pool-anchored SpanCtx valid for the request lifetime.
        None => unsafe {
            crate::traces::ctx::recover_span_ctx(r, module, ::core::ptr::null_mut()).as_ref()
        },
    };

    // SAFETY: `v` is the non-null `ngx_variable_value_t*` nginx supplies.
    let vv = unsafe { &mut *v };
    match ctx {
        Some(span_ctx) => {
            // SAFETY: `r` is valid; `(*r).pool` is the per-request pool.
            let pool = unsafe { (*r).pool };
            // SAFETY: `pool` is a valid nginx pool pointer; `ngx_pcalloc` returns
            // a pointer to pool memory valid for the request lifetime (or null).
            let buf = unsafe { nginx_sys::ngx_pcalloc(pool, 32) } as *mut u8;
            if buf.is_null() {
                vv.set_not_found(1);
                return nginx_sys::NGX_OK as nginx_sys::ngx_int_t;
            }
            // SAFETY: `buf` is a valid 32-byte pool allocation.
            let s = unsafe { core::slice::from_raw_parts_mut(buf, 32) };
            hex_encode_into(&span_ctx.trace_id, s);
            vv.set_valid(1);
            vv.set_no_cacheable(1);
            vv.set_not_found(0);
            vv.set_len(32);
            vv.data = buf;
        }
        None => {
            vv.set_not_found(1);
        }
    }
    nginx_sys::NGX_OK as nginx_sys::ngx_int_t
}

/// nginx variable get-handler for `$otel_span_id`.
///
/// Returns the span ID of the current request's span as 16 lowercase hex
/// characters.  Empty (not_found) when no `SpanCtx` is present.
///
/// # Safety
/// nginx calls this with a valid non-null `ngx_http_request_t*` and a valid
/// `ngx_variable_value_t*` during variable evaluation.
unsafe extern "C" fn otel_var_get_span_id(
    r: *mut nginx_sys::ngx_http_request_t,
    v: *mut nginx_sys::ngx_variable_value_t,
    _data: usize,
) -> nginx_sys::ngx_int_t {
    use crate::traces::ctx::SpanCtx;

    // SAFETY: `r` is the non-null `ngx_http_request_t*` nginx passes to variable
    // get-handlers; `Request::from_ngx_http_request` reinterprets it as the
    // ngx-rust request wrapper (same repr) and yields a valid `&mut Request`.
    let request = unsafe { ngx::http::Request::from_ngx_http_request(r) };
    // SAFETY: `ngx_http_otel_module` is a `static` module descriptor valid for
    // the full process lifetime; `addr_of!` yields a valid pointer.
    let module = unsafe { &*::core::ptr::addr_of!(ngx_http_otel_module) };
    let ctx: Option<&SpanCtx> = match request.get_module_ctx::<SpanCtx>(module) {
        Some(c) => Some(c),
        // SAFETY: `r` is the live request pointer nginx passed; `module` is the
        // process-lifetime descriptor; the recovered pointer (if non-null) is a
        // pool-anchored SpanCtx valid for the request lifetime.
        None => unsafe {
            crate::traces::ctx::recover_span_ctx(r, module, ::core::ptr::null_mut()).as_ref()
        },
    };

    // SAFETY: `v` is the non-null `ngx_variable_value_t*` nginx supplies.
    let vv = unsafe { &mut *v };
    match ctx {
        Some(span_ctx) => {
            // SAFETY: `r` is valid; `(*r).pool` is the per-request pool.
            let pool = unsafe { (*r).pool };
            // SAFETY: `pool` is a valid nginx pool pointer; 16 bytes for the hex string.
            let buf = unsafe { nginx_sys::ngx_pcalloc(pool, 16) } as *mut u8;
            if buf.is_null() {
                vv.set_not_found(1);
                return nginx_sys::NGX_OK as nginx_sys::ngx_int_t;
            }
            // SAFETY: `buf` is a valid 16-byte pool allocation.
            let s = unsafe { core::slice::from_raw_parts_mut(buf, 16) };
            hex_encode_into(&span_ctx.span_id, s);
            vv.set_valid(1);
            vv.set_no_cacheable(1);
            vv.set_not_found(0);
            vv.set_len(16);
            vv.data = buf;
        }
        None => {
            vv.set_not_found(1);
        }
    }
    nginx_sys::NGX_OK as nginx_sys::ngx_int_t
}

/// nginx variable get-handler for `$otel_parent_id`.
///
/// Returns the parent span ID from the request's `SpanCtx` as 16 lowercase hex
/// characters.  Returns the all-zeros string `"0000000000000000"` when the span
/// has no parent (root span).  Empty (not_found) when no `SpanCtx` is present.
///
/// # Safety
/// nginx calls this with a valid non-null `ngx_http_request_t*` and a valid
/// `ngx_variable_value_t*` during variable evaluation.
unsafe extern "C" fn otel_var_get_parent_id(
    r: *mut nginx_sys::ngx_http_request_t,
    v: *mut nginx_sys::ngx_variable_value_t,
    _data: usize,
) -> nginx_sys::ngx_int_t {
    use crate::traces::ctx::SpanCtx;

    // SAFETY: `r` is the non-null `ngx_http_request_t*` nginx passes to variable
    // get-handlers; `Request::from_ngx_http_request` reinterprets it as the
    // ngx-rust request wrapper (same repr) and yields a valid `&mut Request`.
    let request = unsafe { ngx::http::Request::from_ngx_http_request(r) };
    // SAFETY: `ngx_http_otel_module` is a `static` module descriptor valid for
    // the full process lifetime; `addr_of!` yields a valid pointer.
    let module = unsafe { &*::core::ptr::addr_of!(ngx_http_otel_module) };
    let ctx: Option<&SpanCtx> = match request.get_module_ctx::<SpanCtx>(module) {
        Some(c) => Some(c),
        // SAFETY: `r` is the live request pointer nginx passed; `module` is the
        // process-lifetime descriptor; the recovered pointer (if non-null) is a
        // pool-anchored SpanCtx valid for the request lifetime.
        None => unsafe {
            crate::traces::ctx::recover_span_ctx(r, module, ::core::ptr::null_mut()).as_ref()
        },
    };

    // SAFETY: `v` is the non-null `ngx_variable_value_t*` nginx supplies.
    let vv = unsafe { &mut *v };
    match ctx {
        Some(span_ctx) => {
            // SAFETY: `r` is valid; `(*r).pool` is the per-request pool.
            let pool = unsafe { (*r).pool };
            // SAFETY: `pool` is a valid nginx pool pointer; 16 bytes for the hex string.
            let buf = unsafe { nginx_sys::ngx_pcalloc(pool, 16) } as *mut u8;
            if buf.is_null() {
                vv.set_not_found(1);
                return nginx_sys::NGX_OK as nginx_sys::ngx_int_t;
            }
            // SAFETY: `buf` is a valid 16-byte pool allocation.
            let s = unsafe { core::slice::from_raw_parts_mut(buf, 16) };
            hex_encode_into(&span_ctx.parent_span_id, s);
            vv.set_valid(1);
            vv.set_no_cacheable(1);
            vv.set_not_found(0);
            vv.set_len(16);
            vv.data = buf;
        }
        None => {
            vv.set_not_found(1);
        }
    }
    nginx_sys::NGX_OK as nginx_sys::ngx_int_t
}

/// nginx variable get-handler for `$otel_parent_sampled`.
///
/// Returns `"1"` if the W3C sampled bit (bit 0 of `flags`) is set in the
/// request's `SpanCtx`; `"0"` if unsampled.  Empty (not_found) when no
/// `SpanCtx` is present.
///
/// # Safety
/// nginx calls this with a valid non-null `ngx_http_request_t*` and
/// `ngx_variable_value_t*`.
unsafe extern "C" fn otel_var_get_parent_sampled(
    r: *mut nginx_sys::ngx_http_request_t,
    v: *mut nginx_sys::ngx_variable_value_t,
    _data: usize,
) -> nginx_sys::ngx_int_t {
    use crate::traces::ctx::SpanCtx;

    // SAFETY: `r` is the non-null `ngx_http_request_t*` nginx passes to variable
    // get-handlers; same contract as `otel_var_get_trace_id`.
    let request = unsafe { ngx::http::Request::from_ngx_http_request(r) };
    // SAFETY: `ngx_http_otel_module` is a `static` module descriptor valid for
    // the full process lifetime; `addr_of!` yields a valid pointer.
    let module = unsafe { &*::core::ptr::addr_of!(ngx_http_otel_module) };
    // Recover the SpanCtx from the pool-cleanup anchor when the module-ctx
    // slot was cleared by an internal redirect (see otel_var_get_trace_id).
    let ctx: Option<&SpanCtx> = match request.get_module_ctx::<SpanCtx>(module) {
        Some(c) => Some(c),
        // SAFETY: `r` is the live request pointer nginx passed; `module` is the
        // process-lifetime descriptor; the recovered pointer (if non-null) is a
        // pool-anchored SpanCtx valid for the request lifetime.
        None => unsafe {
            crate::traces::ctx::recover_span_ctx(r, module, ::core::ptr::null_mut()).as_ref()
        },
    };

    // SAFETY: `v` is the non-null `ngx_variable_value_t*` nginx supplies.
    let vv = unsafe { &mut *v };
    // Static byte strings: "1" and "0".  Using `b'1'` / `b'0'` stored in
    // `static` so the pointer outlives the handler call (no pool alloc needed).
    static ONE: u8 = b'1';
    static ZERO: u8 = b'0';
    match ctx {
        Some(span_ctx) => {
            let is_sampled = (span_ctx.flags & 0x01) != 0;
            let byte_ptr =
                if is_sampled { &raw const ONE as *mut u8 } else { &raw const ZERO as *mut u8 };
            vv.set_valid(1);
            vv.set_no_cacheable(1);
            vv.set_not_found(0);
            vv.set_len(1);
            vv.data = byte_ptr;
        }
        None => {
            vv.set_not_found(1);
        }
    }
    nginx_sys::NGX_OK as nginx_sys::ngx_int_t
}

// ── init_process callback ─────────────────────────────────────────────────────

/// Called by NGINX once per worker process after the process has forked.
///
/// Workers do not own the export task; the `nginx: otel exporter` process
/// (spawned in `ngx_otel_init_module`) owns it.  This callback stays registered
/// so each worker can initialise its per-worker log ring writer.
///
/// The `#[cfg(any(test, feature = "test-support"))]` gRPC smoke harnesses
/// remain on Worker 0 for the gRPC integration tests. They do
/// not run in production builds (no allocation, no task spawn).
extern "C" fn ngx_otel_init_process(cycle: *mut ngx_cycle_t) -> ngx_int_t {
    // ── Wire error-writer shm pointers ──────────────────────────────────────
    //
    // Gate: Worker only + logs shm mapped.  Exporter and master contexts must
    // fall through to core error_log; the process-role guard in
    // ngx_otel_error_writer enforces this at call time; the null pointers here
    // are the belt to that suspenders.
    {
        // SAFETY: `cycle` is the non-null, valid cycle nginx passes into
        // `init_process`; the worker is single-threaded at this point so the `&mut`
        // is the sole live reference to the cycle.
        let cycle_ref = unsafe { &mut *cycle };
        if let Some(amcf) = HttpOtelModule::main_conf(cycle_ref) {
            if amcf.error_log_enabled {
                // Process-role gate: Worker only (not master/exporter/config-load).
                if matches!(crate::exporter::ngx_process(), crate::exporter::NgxProcess::Worker(_))
                {
                    // SAFETY: `ngx_worker` is this worker's id, set by the master
                    // before the fork and read-only thereafter, so the `static mut`
                    // read is race-free.
                    let worker_id = unsafe { nginx_sys::ngx_worker };
                    let cap = amcf.log_ring_cap();

                    if let Some(logs_base) = amcf.logs_shm_base() {
                        // SAFETY: `logs_base` is the start of the logs shm zone (from
                        // `logs_shm_base()`), `worker_id < worker_count`, and `cap`
                        // is the configured ring capacity — exactly the contract
                        // `logs_coalesce_table` requires to index this worker's slot.
                        let coalesce_table =
                            unsafe { crate::shm::logs_coalesce_table(logs_base, worker_id, cap) };
                        // SAFETY: same zone/worker_id/cap contract as above; yields a
                        // pointer to this worker's error-ring header within the zone.
                        let error_ring_ptr =
                            unsafe { crate::shm::logs_error_ring_ptr(logs_base, worker_id, cap) };

                        // Error-rate counters live in the metrics shm (WorkerSlots).
                        let error_rate_ptr = amcf.shm_base().map(|metrics_base| {
                            // SAFETY: `metrics_base` is the metrics shm zone start
                            // (from `shm_base()`) and `worker_id` is in range, so this
                            // returns a valid pointer to this worker's `WorkerSlots`.
                            let ws = unsafe { crate::shm::worker_slots(metrics_base, worker_id) };
                            // SAFETY: `ws` is the valid `WorkerSlots` pointer just
                            // obtained; `error_rate_counters` is an inline array field
                            // of that struct, so `.as_ptr()` is in-bounds and aligned.
                            unsafe {
                                (*ws).error_rate_counters.as_ptr()
                                    as *mut core::sync::atomic::AtomicU64
                            }
                        });

                        // SAFETY: all pointers passed are valid for this worker —
                        // `cycle` is the valid cycle, `logs_shm_zone` the registered
                        // zone, and `coalesce_table` / `error_ring_ptr` /
                        // `error_rate_ptr` point into shm slots owned by this worker
                        // (null error-rate falls back via `unwrap_or(null)`, which the
                        // writer treats as "no rate counter"). Called once per worker.
                        unsafe {
                            crate::logs::error_writer::wire_error_writer_state(
                                cycle as *const _,
                                amcf.logs_shm_zone,
                                coalesce_table,
                                error_ring_ptr,
                                error_rate_ptr.unwrap_or(core::ptr::null_mut()),
                                amcf.error_log_coalesce,
                            );
                        }
                    }
                }
            }
        }
    }

    // ── Eager, fallible trace-DRBG seed (off the request path) ───────────────
    //
    // Seed this worker's ChaCha20 trace-ID DRBG here, at worker init, so the
    // single `getrandom(2)` syscall happens off the per-request hot path.  On a
    // persistent OS-RNG failure (e.g. seccomp denying getrandom) we MUST NOT
    // panic — a panic in the `extern "C"` REWRITE handler aborts the worker and
    // every respawn re-aborts on its first traced request (a crash loop).
    // Instead `eager_seed_drbg()` sets a worker-local tracing-disabled flag and
    // returns Err; we log ONE `NGX_LOG_EMERG` line and keep serving traffic
    // (span-start treats the flag as unsampled — no spans, no weak IDs).  Run
    // in worker processes only; master/exporter never trace.
    if matches!(crate::exporter::ngx_process(), crate::exporter::NgxProcess::Worker(_)) {
        if let Err(e) = crate::traces::ctx::eager_seed_drbg() {
            // SAFETY: `cycle` is the non-null, valid cycle nginx passes into
            // `init_process`; `(*cycle).log` is the worker's log handle, copied
            // out (not retained).  The EMERG line is emitted at most once per
            // worker because `eager_seed_drbg` is called exactly once here.
            let log = unsafe { (*cycle).log };
            ngx::ngx_log_error!(
                nginx_sys::NGX_LOG_EMERG,
                log,
                "otel: trace-ID DRBG seeding failed ({e}); OS RNG unavailable — \
                 tracing DISABLED for this worker (traffic unaffected, no spans emitted)"
            );
        }
    }

    // ── In-worker unary gRPC viability harness ──────────────────────────────
    //
    // Only compiled when the `test-support` feature is enabled.  When set,
    // and the `otel_grpc_smoke_endpoint` directive carries a non-empty value,
    // fire one unary OTLP/gRPC export from Worker 0 via
    // `NgxExecutor` + `SendRequestService` + `NgxConnIo` — the real
    // production stack — to verify viability on the nginx event loop under
    // `--with-debug`.  Result is logged at NOTICE; the integration test in
    // `tests/integration/run_grpc_smoke.sh` greps for the success line.
    #[cfg(any(test, feature = "test-support"))]
    {
        // SAFETY: `ngx_process` is set by the master before the fork and read-only
        // afterwards, so this `static mut` read cannot race.
        let process_type = unsafe { nginx_sys::ngx_process } as u32;
        // SAFETY: `ngx_worker` is set by the master before the fork and read-only
        // afterwards, so this `static mut` read cannot race.
        let worker_num = unsafe { nginx_sys::ngx_worker };
        // SAFETY: `cycle` is the non-null, valid cycle nginx passes to init_process;
        // `log` is a plain pointer field we only copy out, not dereference here.
        let log = unsafe { (*cycle).log };
        let is_designated = matches!(
            (process_type, worker_num as u32),
            (nginx_sys::NGX_PROCESS_WORKER, 0) | (nginx_sys::NGX_PROCESS_SINGLE, _)
        );
        if is_designated {
            // SAFETY: `cycle` is the valid cycle from init_process; the worker is
            // single-threaded here so this `&mut` is the only live cycle reference.
            let cycle_ref = unsafe { &mut *cycle };
            if let Some(amcf) = HttpOtelModule::main_conf(cycle_ref) {
                // SAFETY: `cycle` is valid; `(*cycle).pool` is the worker's
                // process-lifetime pool created by nginx, the contract
                // `Pool::from_ngx_pool` requires.
                let pool = unsafe { Pool::from_ngx_pool((*cycle).pool) };
                // `log` is shared by all three harnesses; guard it once.
                let Some(log_nn) = core::ptr::NonNull::new(log) else {
                    ngx::ngx_log_error!(
                        nginx_sys::NGX_LOG_ERR,
                        log,
                        "otel grpc smoke harness: null log pointer; skipping"
                    );
                    return Status::NGX_OK.into();
                };

                // In-worker unary OTLP/gRPC viability harness.
                run_grpc_smoke_harness(
                    GrpcSmokeSpec {
                        endpoint_bytes: amcf.grpc_smoke_endpoint.as_bytes(),
                        not_utf8_msg:
                            "grpc smoke: otel_grpc_smoke_endpoint is not valid UTF-8; skipping",
                        firing_prefix: "grpc smoke: firing one unary OTLP/gRPC export",
                        alloc_fail_msg: "grpc smoke: pool allocation for smoke task failed",
                    },
                    &pool,
                    log_nn,
                    |endpoint_owned, log_nn| async move {
                        let result = crate::transport::grpc::smoke::fire_one_grpc_export(
                            &endpoint_owned,
                            log_nn,
                        )
                        .await;
                        let log_ptr = log_nn.as_ptr();
                        match result {
                            Ok(()) => {
                                // This exact line is what `run_grpc_smoke.sh` asserts on.
                                ngx::ngx_log_error!(
                                    nginx_sys::NGX_LOG_NOTICE,
                                    log_ptr,
                                    "grpc smoke: export complete"
                                );
                            }
                            Err(e) => {
                                ngx::ngx_log_error!(
                                    nginx_sys::NGX_LOG_ERR,
                                    log_ptr,
                                    "grpc smoke: export failed: {}",
                                    e
                                );
                            }
                        }
                    },
                );

                // Bidi gRPC viability harness (Echo.BidiEcho).
                run_grpc_smoke_harness(
                    GrpcSmokeSpec {
                        endpoint_bytes: amcf.bidi_smoke_endpoint.as_bytes(),
                        not_utf8_msg:
                            "bidi smoke: otel_grpc_bidi_smoke_endpoint is not valid UTF-8; skipping",
                        firing_prefix: "bidi smoke: firing one bidi stream",
                        alloc_fail_msg: "bidi smoke: pool allocation for bidi task failed",
                    },
                    &pool,
                    log_nn,
                    |endpoint_owned, log_nn| async move {
                        let result = crate::transport::grpc::smoke::fire_one_bidi_stream(
                            &endpoint_owned,
                            log_nn,
                        )
                        .await;
                        let log_ptr = log_nn.as_ptr();
                        match result {
                            Ok(()) => {
                                // fire_one_bidi_stream already logs the
                                // "bidi complete" line at NOTICE inside the
                                // function.  No additional log needed here.
                            }
                            Err(e) => {
                                // This exact pattern is what run_grpc_bidi_smoke.sh
                                // asserts must appear zero times.
                                ngx::ngx_log_error!(
                                    nginx_sys::NGX_LOG_ERR,
                                    log_ptr,
                                    "bidi smoke: bidi failed: {}",
                                    e
                                );
                            }
                        }
                    },
                );

                // Bidi backpressure overload harness.
                run_grpc_smoke_harness(
                    GrpcSmokeSpec {
                        endpoint_bytes: amcf.bidi_overload_endpoint.as_bytes(),
                        not_utf8_msg:
                            "bidi overload: otel_grpc_bidi_overload_endpoint is not valid UTF-8; skipping",
                        firing_prefix: "bidi overload: queueing overload task",
                        alloc_fail_msg: "bidi overload: pool allocation for overload task failed",
                    },
                    &pool,
                    log_nn,
                    |endpoint_owned, log_nn| async move {
                        let result = crate::transport::grpc::smoke::fire_bidi_overload(
                            &endpoint_owned,
                            log_nn,
                        )
                        .await;
                        let log_ptr = log_nn.as_ptr();
                        match result {
                            Ok(()) => {
                                // fire_bidi_overload logs the summary line at NOTICE
                                // internally.  No additional log needed here.
                            }
                            Err(e) => {
                                ngx::ngx_log_error!(
                                    nginx_sys::NGX_LOG_ERR,
                                    log_ptr,
                                    "bidi overload: failed: {}",
                                    e
                                );
                            }
                        }
                    },
                )
            }
        }
    }

    Status::NGX_OK.into()
}

/// Descriptor for one `#[cfg(test-support)]` gRPC smoke harness (see
/// [`run_grpc_smoke_harness`]). Message fields are logged verbatim so the
/// integration scripts keep matching their expected lines.
#[cfg(any(test, feature = "test-support"))]
struct GrpcSmokeSpec<'a> {
    /// Raw bytes of the configured endpoint directive; empty disables the harness.
    endpoint_bytes: &'a [u8],
    /// Logged at ERR when the endpoint is not valid UTF-8.
    not_utf8_msg: &'a str,
    /// Logged at NOTICE before spawning, as `"{firing_prefix} (endpoint=<ep>)"`.
    firing_prefix: &'a str,
    /// Logged at ERR if the spawned task cannot be pool-allocated.
    alloc_fail_msg: &'a str,
}

/// Shared scaffold for the three gRPC smoke harnesses on the
/// designated worker: skip when the endpoint is unset, decode it, log the
/// firing line, spawn `make_future` on the nginx event loop, and account a
/// pool-allocation failure. The harness-specific task body — including the
/// exact log lines the integration scripts assert on — is supplied by
/// `make_future`. Never compiled into production builds.
#[cfg(any(test, feature = "test-support"))]
fn run_grpc_smoke_harness<Fut>(
    spec: GrpcSmokeSpec<'_>,
    pool: &ngx::core::Pool,
    log_nn: core::ptr::NonNull<nginx_sys::ngx_log_t>,
    make_future: impl FnOnce(std::string::String, core::ptr::NonNull<nginx_sys::ngx_log_t>) -> Fut,
) where
    Fut: core::future::Future<Output = ()> + 'static,
{
    if spec.endpoint_bytes.is_empty() {
        return;
    }
    let log = log_nn.as_ptr();
    let Ok(endpoint_str) = core::str::from_utf8(spec.endpoint_bytes) else {
        ngx::ngx_log_error!(nginx_sys::NGX_LOG_ERR, log, "{}", spec.not_utf8_msg);
        return;
    };
    let endpoint_owned = std::string::String::from(endpoint_str);
    let firing = std::format!("{} (endpoint={})", spec.firing_prefix, endpoint_owned);
    ngx::ngx_log_error!(nginx_sys::NGX_LOG_NOTICE, log, "{}", firing);
    let task = ngx::async_::spawn(make_future(endpoint_owned, log_nn));
    if pool.allocate(task).is_null() {
        ngx::ngx_log_error!(nginx_sys::NGX_LOG_ERR, log, "{}", spec.alloc_fail_msg);
    }
}

// ── exit_process callback ─────────────────────────────────────────────────────

/// Called by NGINX when the worker process is exiting (SIGQUIT, SIGHUP-induced
/// shutdown, or natural exit).
///
/// Workers do not own the export state, so there is no
/// worker-side exit flush. The exporter's `graceful_drain` (called on its
/// `ngx_quit` path) is the sole final-flush path for both transports.
///
/// The callback stays registered so it can drain the worker's local log buffer
/// into the shared ring before exit, ensuring the exporter picks up the tail
/// records.
unsafe extern "C" fn ngx_otel_exit_process(cycle: *mut ngx_cycle_t) {
    // Set the cleanup flag on our error-log writer node so that any
    // late emissions after this point are dropped instead of touching the ring.
    // The ring itself is in shm; the exporter drains it on its next tick.
    //
    // This mirrors `ngx_syslog_cleanup`: stop producer emissions before the
    // cycle tears down the log chain.
    if !cycle.is_null() {
        // SAFETY: `cycle` is non-null (just checked) and is the valid cycle nginx
        // passes to `exit_process`; `set_cleanup_flag` only reads our writer node
        // reachable from the cycle and sets an atomic flag, with no aliasing concern
        // as the worker is single-threaded during teardown.
        unsafe {
            crate::logs::error_writer::set_cleanup_flag(cycle as *const _);
        }
    }
}

// ── otel_status_endpoint content handler ─────────────────────────────────────

/// Content handler for `otel_status_endpoint;`.
///
/// Returns the current `control_shm.version` as a decimal plain-text response.
/// Registered by `cmd_set_otel_status_endpoint` when `otel_status_endpoint;`
/// appears in a location block in test-support builds.
///
/// **Gated on `#[cfg(any(test, feature = "test-support"))]`.** Production
/// builds do not carry this handler or the directive that triggers it. Verified
/// by `grep -q "otel_status_endpoint" objs-release/ngx_http_otel_module.so`.
#[cfg(any(test, feature = "test-support"))]
pub(crate) unsafe extern "C" fn otel_status_content_handler(
    r: *mut nginx_sys::ngx_http_request_t,
) -> nginx_sys::ngx_int_t {
    use core::sync::atomic::Ordering;
    use ngx::core::{Buffer, Pool};
    use ngx::http::HttpModuleMainConf as _;

    // Read control_shm fields via the request's module conf.
    // ngx_http_request_t implements HttpModuleConfExt, so main_conf() works directly.
    // SAFETY: nginx invokes a content handler with a non-null, valid request `r`;
    // `as_ref()` additionally null-checks, yielding a shared borrow valid for the
    // handler's duration.
    let amcf_opt = unsafe { r.as_ref() }.and_then(HttpOtelModule::main_conf);
    let (version, last_beat_msec, successor_gen) = amcf_opt
        .and_then(|amcf| amcf.control_shm_ptr())
        // SAFETY: `ctrl` is the control-shm pointer returned by `control_shm_ptr()`,
        // which points to a live `ControlShm` in the mapped zone; all fields are
        // atomics read with relaxed loads, so cross-process access is sound.
        .map(|ctrl| unsafe {
            (
                (*ctrl).version.load(Ordering::Relaxed),
                (*ctrl).last_beat_msec.load(Ordering::Relaxed),
                (*ctrl).successor_gen.load(Ordering::Relaxed),
            )
        })
        .unwrap_or((0, 0, 0));

    // Test-support introspection: ring drop counters summed across workers
    // (drop evidence for the heartbeat-stale polarity tests) plus the
    // worker-local monotonic clock for staleness cross-checks.
    let mut access_dropped: u64 = 0;
    let mut error_dropped: u64 = 0;
    let mut spans_dropped: u64 = 0;
    if let Some(amcf) = amcf_opt {
        let n_workers = amcf.shm_n_workers();
        if let Some(logs_base) = amcf.logs_shm_base() {
            let cap = amcf.log_ring_cap();
            for w in 0..n_workers {
                // SAFETY: `logs_base` is the mapped logs-zone data start; the zone
                // was sized for ≥ `shm_n_workers()` slots at registration with this
                // `cap`, so both ring views are in-bounds.
                unsafe {
                    access_dropped += crate::shm::logs_access_ring(logs_base, w, cap).drop_count();
                    error_dropped += crate::shm::logs_error_ring(logs_base, w, cap).drop_count();
                }
            }
        }
        if let Some(spans_base) = amcf.spans_shm_base() {
            for w in 0..n_workers {
                // SAFETY: the spans zone is registered with the same reserved
                // worker count as the metrics zone (`n_workers_to_reserve`), so
                // `w < shm_n_workers()` slots are in-bounds at the default cap.
                unsafe {
                    spans_dropped +=
                        crate::shm::spans_ring(spans_base, w, crate::shm::DEFAULT_SPAN_RING_CAP)
                            .drop_count();
                }
            }
        }
    }
    // SAFETY: `ngx_current_msec` is an nginx global updated by this worker's own
    // single-threaded event loop (standard cached-time access).
    let now_msec = unsafe { nginx_sys::ngx_current_msec } as u64;

    // Line 1 stays the bare version (existing heartbeat test contract);
    // key=value lines follow.
    let body = std::format!(
        "{}\nlast_beat_msec={}\nnow_msec={}\nsuccessor_gen={}\nspans_dropped={}\naccess_dropped={}\nerror_dropped={}\n",
        version, last_beat_msec, now_msec, successor_gen, spans_dropped, access_dropped, error_dropped
    );
    let body_len = body.len();

    // Set response headers.
    // SAFETY: `r` is the valid request; `headers_out` is an inline field, and the
    // request is processed single-threaded so this exclusive borrow does not alias.
    let headers_out = unsafe { &mut (*r).headers_out };
    headers_out.status = 200;
    headers_out.content_length_n = body_len as nginx_sys::off_t;
    // Content-Type: text/plain (static string; pointer valid for process lifetime).
    static CONTENT_TYPE_BYTES: &[u8] = b"text/plain";
    headers_out.content_type.len = CONTENT_TYPE_BYTES.len();
    headers_out.content_type.data = CONTENT_TYPE_BYTES.as_ptr() as *mut _;
    headers_out.content_type_len = CONTENT_TYPE_BYTES.len();

    // Send response header.
    // SAFETY: `r` is the valid request; `ngx_http_send_header` is the nginx API for
    // emitting the response header line and is sound to call with a live request.
    let rc = unsafe { nginx_sys::ngx_http_send_header(r) };
    if rc == nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t {
        return rc;
    }
    // HEAD requests need no body.
    // SAFETY: `r` is the valid request; `header_only` lives after `uri_changes`
    // in `ngx_http_request_t`, so the bindgen accessor reads 2 bits low — route
    // through the C shim, which reads nginx's own layout.
    if unsafe { crate::shim::r_header_only(r) } != 0 {
        return nginx_sys::NGX_OK as nginx_sys::ngx_int_t;
    }

    // Allocate body buffer from request pool.
    // SAFETY: `r` is the valid request; `(*r).pool` is its request-scoped pool, the
    // contract `Pool::from_ngx_pool` requires.
    let pool = unsafe { Pool::from_ngx_pool((*r).pool) };
    let Some(mut buf) = pool.create_buffer_from_str(&body) else {
        return nginx_sys::NGX_HTTP_INTERNAL_SERVER_ERROR as nginx_sys::ngx_int_t;
    };
    buf.set_last_buf(true);
    buf.set_last_in_chain(true);

    // Wrap in an output chain and send.
    let chain_ptr = pool.calloc_type::<nginx_sys::ngx_chain_t>();
    if chain_ptr.is_null() {
        return nginx_sys::NGX_HTTP_INTERNAL_SERVER_ERROR as nginx_sys::ngx_int_t;
    }
    // SAFETY: `chain_ptr` is a freshly pool-allocated, zeroed `ngx_chain_t` (null-
    // checked above), so writing its `buf`/`next` fields is in-bounds; `buf` outlives
    // the call as it is allocated from the same request pool.
    unsafe {
        (*chain_ptr).buf = buf.as_ngx_buf_mut();
        (*chain_ptr).next = core::ptr::null_mut();
    }
    // SAFETY: `r` is the valid request and `chain_ptr` is a valid single-link output
    // chain just constructed; `ngx_http_output_filter` consumes it via the nginx
    // filter chain.
    unsafe { nginx_sys::ngx_http_output_filter(r, chain_ptr) }
}

/// Test-only stubs for nginx symbols referenced (but never called) in our code.
/// On macOS, flat-namespace dynamic linking resolves all external symbols at
/// process startup; without these stubs the test binary won't start.
#[cfg(test)]
mod nginx_test_stubs {
    use core::ffi::{c_char, c_void};
    use nginx_sys::{ngx_command_t, ngx_conf_t, ngx_module_t};

    // Built-in slot handlers used as function pointers in the commands table.
    #[no_mangle]
    pub extern "C" fn ngx_conf_set_flag_slot(
        _cf: *mut ngx_conf_t,
        _cmd: *mut ngx_command_t,
        _conf: *mut c_void,
    ) -> *mut c_char {
        core::ptr::null_mut()
    }

    #[no_mangle]
    pub extern "C" fn ngx_conf_set_str_slot(
        _cf: *mut ngx_conf_t,
        _cmd: *mut ngx_command_t,
        _conf: *mut c_void,
    ) -> *mut c_char {
        core::ptr::null_mut()
    }

    // nginx global module descriptor accessed to read ctx_index.
    #[no_mangle]
    pub static mut ngx_core_module: ngx_module_t = ngx_module_t::default();

    // nginx shared-memory API.
    #[no_mangle]
    pub unsafe extern "C" fn ngx_shared_memory_add(
        _cf: *mut ngx_conf_t,
        _name: *mut nginx_sys::ngx_str_t,
        _size: usize,
        _tag: *mut c_void,
    ) -> *mut nginx_sys::ngx_shm_zone_t {
        core::ptr::null_mut()
    }

    // nginx request-path globals accessed by the log-phase handler.
    #[no_mangle]
    pub static mut ngx_worker: nginx_sys::ngx_uint_t = 0;

    #[no_mangle]
    pub static mut ngx_current_msec: nginx_sys::ngx_msec_t = 0;

    // `ngx_cached_time` is a `*mut ngx_time_t`; `ngx_timeofday()` dereferences
    // it. The log-phase handler's request-duration calc calls `ngx_timeofday()`
    // (since the metrics-correctness fix `9e2138e`), so this data symbol must be
    // stubbed too — otherwise macOS dyld aborts loading the debug
    // `cargo test --lib` binary on the unresolved `_ngx_cached_time`. Points at
    // a zeroed `ngx_time_t` (sec = msec = 0 → duration clamps to 0 in tests).
    // SAFETY: `ngx_time_t` is a plain `#[repr(C)]` struct of integer fields, for
    // which the all-zero bit pattern is a valid inhabitant; this stub is only ever
    // read (sec = msec = 0) by tests, never written.
    static mut STUB_CACHED_TIME: nginx_sys::ngx_time_t = unsafe { core::mem::zeroed() };

    #[no_mangle]
    pub static mut ngx_cached_time: *mut nginx_sys::ngx_time_t =
        core::ptr::addr_of_mut!(STUB_CACHED_TIME);

    // nginx process-type globals accessed by ngx_otel_init_process.
    #[no_mangle]
    pub static mut ngx_process: nginx_sys::ngx_uint_t =
        nginx_sys::NGX_PROCESS_SINGLE as nginx_sys::ngx_uint_t;

    // nginx shutdown flags accessed by the export loop and the channel handler.
    #[no_mangle]
    pub static mut ngx_terminate: core::ffi::c_int = 0;

    #[no_mangle]
    pub static mut ngx_quit: core::ffi::c_int = 0;

    #[no_mangle]
    pub static mut ngx_reopen: core::ffi::c_int = 0;

    #[no_mangle]
    pub static mut ngx_exiting: nginx_sys::ngx_uint_t = 0;

    // nginx process identity globals used by the exporter cycle and
    // init_module.  These are data symbols resolved eagerly by dyld on macOS;
    // they must be stubbed even if the code paths that access them are never
    // exercised in unit tests.
    #[no_mangle]
    pub static mut ngx_pid: nginx_sys::ngx_pid_t = 0;

    #[no_mangle]
    pub static mut ngx_parent: nginx_sys::ngx_pid_t = 0;

    #[no_mangle]
    pub static mut ngx_test_config: nginx_sys::ngx_uint_t = 0;

    // `is_pre_daemon_initial_start` reads these two globals to
    // decide whether the orphaned-exporter warning should fire.  Unit tests never
    // exercise init_module, but the symbols must exist in the flat namespace on
    // macOS (dyld resolves all data symbols eagerly at load time).
    // Stub values: 0 = "not yet daemonized, not an inherited binary-upgrade
    // child" — the safe initial state; the actual value is irrelevant because no
    // unit test drives the init_module path.
    #[no_mangle]
    pub static mut ngx_daemonized: nginx_sys::ngx_uint_t = 0;

    #[no_mangle]
    pub static mut ngx_inherited: nginx_sys::ngx_uint_t = 0;

    // shm zone capacity uses ngx_ncpu as a headroom multiplier at parse
    // time (src/config.rs).  macOS flat-namespace requires the symbol to exist
    // at load time; 0 is a safe sentinel (config parsing is never driven in
    // unit tests — pool alloc returns null before any zone-sizing call).
    #[no_mangle]
    pub static mut ngx_ncpu: nginx_sys::ngx_int_t = 0;

    // Exporter cycle helpers: accept-mutex flag, channel fd, process table.
    #[no_mangle]
    pub static mut ngx_use_accept_mutex: nginx_sys::ngx_uint_t = 0;

    // ngx_channel is the per-process channel[1] fd set by ngx_spawn_process.
    #[no_mangle]
    pub static mut ngx_channel: nginx_sys::ngx_socket_t = -1;

    // Process table used by close_sibling_channels.
    #[no_mangle]
    pub static mut ngx_last_process: nginx_sys::ngx_int_t = 0;

    #[no_mangle]
    pub static mut ngx_process_slot: nginx_sys::ngx_int_t = 0;

    // ngx_processes array — zeroed; pid = 0, channel = [0,0] in the stub.
    // close_sibling_channels iterates 0..ngx_last_process (=0), so it never
    // touches this array in tests.
    #[no_mangle]
    // SAFETY: `ngx_process_t` is a `#[repr(C)]` POD struct (pids, fds, raw pointers,
    // bitflags) whose all-zero bit pattern is valid (null pointers, zero fds); the
    // stub array is only iterated 0..ngx_last_process (=0) in tests, so never read.
    pub static mut ngx_processes: [nginx_sys::ngx_process_t; 1024] = unsafe { core::mem::zeroed() };

    // nginx global cycle pointer (used by ngx::log::ngx_cycle_log).
    #[no_mangle]
    pub static mut ngx_cycle: *mut nginx_sys::ngx_cycle_t = core::ptr::null_mut();

    // ngx_stat_* are *mut ngx_atomic_t (= *mut c_ulong).
    // Each stub is a static zero and the pointer variable points at it so
    // the load!() macro in stub_status.rs can dereference safely.
    static mut STUB_STAT_ZERO: core::ffi::c_ulong = 0;

    macro_rules! stat_ptr_stub {
        ($name:ident) => {
            #[no_mangle]
            pub static mut $name: *mut nginx_sys::ngx_atomic_t =
                core::ptr::addr_of_mut!(STUB_STAT_ZERO);
        };
    }

    stat_ptr_stub!(ngx_stat_accepted);
    stat_ptr_stub!(ngx_stat_handled);
    stat_ptr_stub!(ngx_stat_requests);
    stat_ptr_stub!(ngx_stat_active);
    stat_ptr_stub!(ngx_stat_reading);
    stat_ptr_stub!(ngx_stat_writing);
    stat_ptr_stub!(ngx_stat_waiting);

    // nginx http core module descriptor (used by NgxHttpCoreModule::main_conf_mut).
    #[no_mangle]
    pub static mut ngx_http_core_module: ngx_module_t = ngx_module_t::default();

    // nginx array API used by register_log_handler.
    #[no_mangle]
    pub unsafe extern "C" fn ngx_array_push(_a: *mut nginx_sys::ngx_array_t) -> *mut c_void {
        core::ptr::null_mut()
    }

    // nginx connection / pool API used by NgxConnIo / NgxPool (transport layer).
    // These are never actually called in unit tests but must exist in the flat
    // namespace on macOS so the test binary can start.

    #[no_mangle]
    pub unsafe extern "C" fn ngx_event_get_peer(
        _pc: *mut nginx_sys::ngx_peer_connection_t,
        _data: *mut c_void,
    ) -> nginx_sys::ngx_int_t {
        nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_event_connect_peer(
        _pc: *mut nginx_sys::ngx_peer_connection_t,
    ) -> nginx_sys::ngx_int_t {
        nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_close_connection(_c: *mut nginx_sys::ngx_connection_t) {}

    #[no_mangle]
    pub unsafe extern "C" fn ngx_create_pool(
        _size: usize,
        _log: *mut nginx_sys::ngx_log_t,
    ) -> *mut nginx_sys::ngx_pool_t {
        core::ptr::null_mut()
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_destroy_pool(_pool: *mut nginx_sys::ngx_pool_t) {}

    #[no_mangle]
    pub unsafe extern "C" fn ngx_palloc(
        _pool: *mut nginx_sys::ngx_pool_t,
        _size: usize,
    ) -> *mut c_void {
        core::ptr::null_mut()
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_handle_read_event(
        _rev: *mut nginx_sys::ngx_event_t,
        _flags: nginx_sys::ngx_uint_t,
    ) -> nginx_sys::ngx_int_t {
        nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_handle_write_event(
        _wev: *mut nginx_sys::ngx_event_t,
        _lowat: usize,
    ) -> nginx_sys::ngx_int_t {
        nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t
    }

    // nginx rbtree API (used by timer internals in ngx_add_timer / ngx_del_timer).
    #[no_mangle]
    pub unsafe extern "C" fn ngx_rbtree_insert(
        _tree: *mut nginx_sys::ngx_rbtree_t,
        _node: *mut nginx_sys::ngx_rbtree_node_t,
    ) {
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_rbtree_delete(
        _tree: *mut nginx_sys::ngx_rbtree_t,
        _node: *mut nginx_sys::ngx_rbtree_node_t,
    ) {
    }

    // nginx event timer rbtree (global static used by ngx_add_timer / ngx_del_timer).
    #[no_mangle]
    pub static mut ngx_event_timer_rbtree: nginx_sys::ngx_rbtree_t = nginx_sys::ngx_rbtree_t {
        root: core::ptr::null_mut(),
        sentinel: core::ptr::null_mut(),
        insert: None,
    };

    // nginx http module descriptor (used by ngx core internally).
    #[no_mangle]
    pub static mut ngx_http_module: nginx_sys::ngx_module_t = nginx_sys::ngx_module_t::default();

    // nginx upstream module descriptor — `config.rs` reads `ctx_index` from it
    // to locate the upstream main config. macOS flat-namespace resolves the
    // reference eagerly even if tests never exercise that code path.
    // ctx_index = 0 is safe for unit tests that never call upstream helpers.
    #[no_mangle]
    pub static mut ngx_http_upstream_module: nginx_sys::ngx_module_t =
        nginx_sys::ngx_module_t::default();

    // `ngx_cycle` is already stubbed at line ~733 above — no duplicate needed.

    // ── Stubs for the otel_status_endpoint content handler ───────────────────
    //
    // Referenced in the #[cfg(any(test, feature = "test-support"))] content
    // handler. Never called in unit tests but must exist for macOS flat-namespace
    // linker and Linux ELF test binary linkage.

    #[no_mangle]
    pub unsafe extern "C" fn ngx_http_send_header(
        _r: *mut nginx_sys::ngx_http_request_t,
    ) -> nginx_sys::ngx_int_t {
        nginx_sys::NGX_OK as nginx_sys::ngx_int_t
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_http_output_filter(
        _r: *mut nginx_sys::ngx_http_request_t,
        _chain: *mut nginx_sys::ngx_chain_t,
    ) -> nginx_sys::ngx_int_t {
        nginx_sys::NGX_OK as nginx_sys::ngx_int_t
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_create_temp_buf(
        _pool: *mut nginx_sys::ngx_pool_t,
        _size: usize,
    ) -> *mut nginx_sys::ngx_buf_t {
        core::ptr::null_mut()
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_pcalloc(
        _pool: *mut nginx_sys::ngx_pool_t,
        _size: usize,
    ) -> *mut core::ffi::c_void {
        core::ptr::null_mut()
    }

    // nginx posted-events queue (used by event loop).
    #[no_mangle]
    pub static mut ngx_posted_next_events: nginx_sys::ngx_queue_t =
        nginx_sys::ngx_queue_t { prev: core::ptr::null_mut(), next: core::ptr::null_mut() };

    // nginx pool cleanup API (used by ngx::core::Pool).
    #[no_mangle]
    pub unsafe extern "C" fn ngx_pool_cleanup_add(
        _p: *mut nginx_sys::ngx_pool_t,
        _size: usize,
    ) -> *mut nginx_sys::ngx_pool_cleanup_t {
        core::ptr::null_mut()
    }

    // nginx log API (used by ngx_log_error! macro).
    // Defined as non-variadic stub — the symbol only needs to exist for macOS
    // flat-namespace lookup; unit tests never exercise real log output.
    #[no_mangle]
    pub unsafe extern "C" fn ngx_log_error_core(
        _level: nginx_sys::ngx_uint_t,
        _log: *mut nginx_sys::ngx_log_t,
        _err: core::ffi::c_int,
        _fmt: *const core::ffi::c_char,
    ) {
    }

    // nginx config log (used internally by config parsing, never called in tests).
    #[no_mangle]
    pub unsafe extern "C" fn ngx_conf_log_error(
        _level: nginx_sys::ngx_uint_t,
        _cf: *mut nginx_sys::ngx_conf_t,
        _err: core::ffi::c_int,
        _fmt: *const core::ffi::c_char,
    ) {
    }

    // nginx config parse (used internally, never called in unit tests).
    #[no_mangle]
    pub unsafe extern "C" fn ngx_conf_parse(
        _cf: *mut nginx_sys::ngx_conf_t,
        _filename: *mut nginx_sys::ngx_str_t,
    ) -> *mut core::ffi::c_char {
        core::ptr::null_mut()
    }

    // ── Stubs for the exporter cycle / channel handler ───────────────────────
    //
    // On macOS, flat-namespace dynamic linking resolves these at runtime.
    // On Linux (ELF), all referenced symbols must be resolved at link time
    // even for the test binary.  These stubs are never called by unit tests;
    // they only need to exist so the linker is satisfied.

    #[no_mangle]
    pub unsafe extern "C" fn ngx_spawn_process(
        _cycle: *mut nginx_sys::ngx_cycle_t,
        _proc_: nginx_sys::ngx_spawn_proc_pt,
        _data: *mut c_void,
        _name: *mut core::ffi::c_char,
        _respawn: nginx_sys::ngx_int_t,
    ) -> nginx_sys::ngx_pid_t {
        -1
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_init_signals(
        _log: *mut nginx_sys::ngx_log_t,
    ) -> nginx_sys::ngx_int_t {
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_read_channel(
        _s: nginx_sys::ngx_socket_t,
        _ch: *mut nginx_sys::ngx_channel_t,
        _size: usize,
        _log: *mut nginx_sys::ngx_log_t,
    ) -> nginx_sys::ngx_int_t {
        nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_add_channel_event(
        _cycle: *mut nginx_sys::ngx_cycle_t,
        _fd: nginx_sys::ngx_fd_t,
        _event: nginx_sys::ngx_int_t,
        _handler: nginx_sys::ngx_event_handler_pt,
    ) -> nginx_sys::ngx_int_t {
        nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_setproctitle(_title: *mut core::ffi::c_char) {}

    #[no_mangle]
    pub unsafe extern "C" fn ngx_process_events_and_timers(_cycle: *mut nginx_sys::ngx_cycle_t) {}

    #[no_mangle]
    pub unsafe extern "C" fn ngx_reopen_files(
        _cycle: *mut nginx_sys::ngx_cycle_t,
        _user: nginx_sys::ngx_uid_t,
    ) {
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_close_listening_sockets(_cycle: *mut nginx_sys::ngx_cycle_t) {}

    #[no_mangle]
    pub unsafe extern "C" fn ngx_close_channel(
        _fd: *mut nginx_sys::ngx_fd_t,
        _log: *mut nginx_sys::ngx_log_t,
    ) {
    }

    // ── transport_dns stubs (Items 1–3: resolver + inet helpers) ─────────────
    //
    // On macOS flat-namespace linking these are resolved at runtime from the
    // nginx binary.  On Linux ELF test binaries every referenced symbol must
    // exist at link time — these no-op stubs satisfy the linker.  Unit tests
    // never call the DNS resolution code path (pool alloc returns null, so
    // OwnedNgxPool::new → Err before any resolver call).

    #[no_mangle]
    pub unsafe extern "C" fn ngx_inet_set_port(_sa: *mut libc::sockaddr, _port: libc::c_ushort) {}

    #[no_mangle]
    pub unsafe extern "C" fn ngx_resolve_start(
        _r: *mut nginx_sys::ngx_resolver_t,
        _temp: *mut nginx_sys::ngx_resolver_ctx_t,
    ) -> *mut nginx_sys::ngx_resolver_ctx_t {
        core::ptr::null_mut()
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_resolve_name(
        _ctx: *mut nginx_sys::ngx_resolver_ctx_t,
    ) -> nginx_sys::ngx_int_t {
        nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_resolve_name_done(_ctx: *mut nginx_sys::ngx_resolver_ctx_t) {}

    // nginx pool allocator (ngx::core::Pool as Allocator, used by the resolver
    // Vec<ngx_addr_t, Pool> return type).
    #[no_mangle]
    pub unsafe extern "C" fn ngx_pnalloc(
        _pool: *mut nginx_sys::ngx_pool_t,
        _size: usize,
    ) -> *mut c_void {
        core::ptr::null_mut()
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_pmemalign(
        _pool: *mut nginx_sys::ngx_pool_t,
        _size: usize,
        _alignment: usize,
    ) -> *mut c_void {
        core::ptr::null_mut()
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_pfree(
        _pool: *mut nginx_sys::ngx_pool_t,
        _p: *mut c_void,
    ) -> nginx_sys::ngx_int_t {
        nginx_sys::NGX_OK as nginx_sys::ngx_int_t
    }

    // ── Stubs for trace directives + variable registration ───────────────────
    //
    // These functions are called during config parsing (otel_trace / otel_span_name
    // complex value compilation) and by the preconfiguration variable registration
    // hook.  On macOS flat-namespace linking they must exist at startup; on Linux
    // they must exist at link time.  Unit tests never drive config parsing, so
    // these stubs are never actually called.

    #[no_mangle]
    pub unsafe extern "C" fn ngx_http_add_variable(
        _cf: *mut nginx_sys::ngx_conf_t,
        _name: *mut nginx_sys::ngx_str_t,
        _flags: nginx_sys::ngx_uint_t,
    ) -> *mut nginx_sys::ngx_http_variable_t {
        core::ptr::null_mut()
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_http_compile_complex_value(
        _ccv: *mut nginx_sys::ngx_http_compile_complex_value_t,
    ) -> nginx_sys::ngx_int_t {
        nginx_sys::NGX_OK as nginx_sys::ngx_int_t
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_http_complex_value(
        _r: *mut nginx_sys::ngx_http_request_t,
        _val: *mut nginx_sys::ngx_http_complex_value_t,
        _value: *mut nginx_sys::ngx_str_t,
    ) -> nginx_sys::ngx_int_t {
        nginx_sys::NGX_OK as nginx_sys::ngx_int_t
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_list_push(_l: *mut nginx_sys::ngx_list_t) -> *mut c_void {
        core::ptr::null_mut()
    }

    // ── Stubs for the span-attribute peer/port lookup (instrumented.rs) ───────
    //
    // The log-phase span builder reads the realip-aware peer via two request
    // variables (`ngx_http_get_variable` + the `ngx_hash_strlow` that hashes the
    // variable name) and materialises the local sockaddr with
    // `ngx_connection_local_sockaddr`.  On macOS flat-namespace linking these
    // resolve from the loaded nginx binary; on a Linux ELF test binary every
    // referenced symbol must exist at link time.  Unit tests build SpanRecords
    // from synthetic requests and never drive this branch, so these stubs are
    // never actually called — they only need to exist for the linker.

    #[no_mangle]
    pub unsafe extern "C" fn ngx_hash_strlow(
        _dst: *mut core::ffi::c_uchar,
        _src: *mut core::ffi::c_uchar,
        _n: usize,
    ) -> nginx_sys::ngx_uint_t {
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_http_get_variable(
        _r: *mut nginx_sys::ngx_http_request_t,
        _name: *mut nginx_sys::ngx_str_t,
        _key: nginx_sys::ngx_uint_t,
    ) -> *mut nginx_sys::ngx_http_variable_value_t {
        core::ptr::null_mut()
    }

    #[no_mangle]
    pub unsafe extern "C" fn ngx_connection_local_sockaddr(
        _c: *mut nginx_sys::ngx_connection_t,
        _s: *mut nginx_sys::ngx_str_t,
        _port: nginx_sys::ngx_uint_t,
    ) -> nginx_sys::ngx_int_t {
        nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t
    }
}

#[cfg(test)]
mod tests {
    use super::hex_encode_into;

    /// `hex_encode_into` encodes an 8-byte span ID to 16 lowercase hex chars.
    ///
    /// This is the core logic shared by `$otel_span_id` and `$otel_parent_id`
    /// (both encode 8 bytes to 16 hex chars).
    ///
    /// Mutation evidence: swap `>> 4` with `& 0x0f` in `hex_encode_into` →
    /// the nibbles are reversed and the expected strings don't match.
    #[test]
    fn hex_encode_span_id_8bytes() {
        // Span ID: 8 bytes → 16 lowercase hex chars.
        let span_id: [u8; 8] = [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7];
        let mut out = [0u8; 16];
        hex_encode_into(&span_id, &mut out);
        assert_eq!(
            &out, b"00f067aa0ba902b7",
            "span_id hex encoding must be 16 lowercase hex chars"
        );
    }

    /// All-zero span ID (root span / no parent) encodes to 16 zeros.
    ///
    /// `$otel_parent_id` emits this string for root spans.
    ///
    /// Mutation evidence: replace the HEX lookup with uppercase → output
    /// becomes `"0000000000000000"` (same) but any non-zero value would
    /// uppercase → subsequent `hex_encode_mixed_nibbles` assertion fails.
    #[test]
    fn hex_encode_all_zeros_span_id() {
        let zero_id: [u8; 8] = [0u8; 8];
        let mut out = [0u8; 16];
        hex_encode_into(&zero_id, &mut out);
        assert_eq!(&out, b"0000000000000000", "all-zero span_id must encode to 16 zeros");
    }

    /// Mixed-nibble value exercises every hex digit path in `hex_encode_into`.
    #[test]
    fn hex_encode_mixed_nibbles() {
        // 0x0123456789abcdef covers nibbles 0-9 + a-f.
        let id: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let mut out = [0u8; 16];
        hex_encode_into(&id, &mut out);
        assert_eq!(&out, b"0123456789abcdef", "nibble encoding must cover all hex digits 0-9 a-f");
    }

    /// The 16-byte trace ID also encodes correctly (32 hex chars).
    /// `$otel_trace_id` uses the same `hex_encode_into`; this guards regression.
    ///
    /// Mutation evidence: change the output length from 32 to 30 in
    /// `hex_encode_into` → `from_utf8` still passes but the content differs.
    #[test]
    fn hex_encode_trace_id_16bytes() {
        let trace_id: [u8; 16] = [
            0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
            0x47, 0x36,
        ];
        let mut out = [0u8; 32];
        hex_encode_into(&trace_id, &mut out);
        assert_eq!(
            &out, b"4bf92f3577b34da6a3ce929d0e0e4736",
            "trace_id hex encoding must be 32 lowercase hex chars"
        );
    }
}
