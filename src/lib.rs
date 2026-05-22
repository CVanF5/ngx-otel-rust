// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! # Zero-cost-when-disabled invariant
//!
//! Loading this module without an `otel_exporter { endpoint ... }` directive
//! MUST impose zero per-request overhead.  The invariant is maintained at
//! exactly two gating points — both checked against
//! [`config::MainConfig::is_configured()`]:
//!
//! 1. **Log-phase handler gate** (`src/lib.rs` — `postconfiguration`):
//!    `add_phase_handler` is called **only** when `amcf.is_configured()` is
//!    true.  If the exporter is not configured the phase handler is never
//!    registered and no per-request code runs.
//!    See: [`HttpOtelModule::postconfiguration`] (the `if amcf.is_configured()`
//!    block, currently around line 83).
//!
//! 2. **Export-task gate** (`src/lib.rs` — `ngx_otel_init_process`):
//!    The async export loop is spawned **only** when `amcf.is_configured()` is
//!    true.  If the exporter is not configured the process hook returns early
//!    with no allocation, no task spawn, and no background activity.
//!    See: [`ngx_otel_init_process`] (the `if !amcf.is_configured()` early
//!    return, currently around line 133).
//!
//! **Invariant contract:**
//! - No per-request allocation on the disabled path.
//! - No per-request locking on the disabled path.
//! - No background tasks on the disabled path.
//!
//! This is the load-bearing claim for upstream acceptance; see
//! `PHASE_1.1_IMPLEMENTATION_PLAN.md` §"Non-negotiable constraints" and
//! the upstream proposal §2.  Step 11 contains the benchmark harness that
//! proves this claim statistically.

#![no_std]
extern crate std;

use core::ptr;

use nginx_sys::{
    ngx_conf_t, ngx_cycle_t, ngx_http_module_t, ngx_int_t, ngx_module_t, ngx_uint_t,
    NGX_HTTP_MODULE,
};
use ngx::core::{Pool, Status};
use ngx::http::{HttpModule, HttpModuleMainConf, add_phase_handler};

mod config;
pub mod data_model;
pub mod encoder;
mod export;
mod metric_source;
mod shm;
pub mod transport;

use config::NGX_HTTP_OTEL_COMMANDS;

#[derive(Debug)]
pub(crate) struct HttpOtelModule;

static NGX_HTTP_OTEL_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: None,
    postconfiguration: Some(HttpOtelModule::postconfiguration),
    create_main_conf: Some(HttpOtelModule::create_main_conf),
    init_main_conf: Some(HttpOtelModule::init_main_conf),
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: None,
    merge_loc_conf: None,
};

#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_otel_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), no_mangle)]
pub static mut ngx_http_otel_module: ngx_module_t = ngx_module_t {
    ctx: ptr::addr_of!(NGX_HTTP_OTEL_MODULE_CTX).cast_mut().cast(),
    commands: unsafe { ptr::addr_of_mut!(NGX_HTTP_OTEL_COMMANDS[0]) },
    type_: NGX_HTTP_MODULE as ngx_uint_t,

    init_master: None,
    init_module: None,
    init_process: Some(ngx_otel_init_process),
    init_thread: None,
    exit_thread: None,
    exit_process: Some(ngx_otel_exit_process),
    exit_master: None,

    ..ngx_module_t::default()
};

unsafe impl HttpModuleMainConf for HttpOtelModule {
    type MainConf = config::MainConfig;
}

impl HttpModule for HttpOtelModule {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_otel_module) }
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> nginx_sys::ngx_int_t {
        let cf_ref = unsafe { &mut *cf };
        let amcf = HttpOtelModule::main_conf_mut(cf_ref).expect("otel main conf");
        let module_ptr = ::core::ptr::addr_of_mut!(ngx_http_otel_module);

        if let Err(e) = amcf.postconfiguration(cf, module_ptr) {
            return e.into();
        }

        // Step 6: register log-phase handler only when exporter is configured.
        if amcf.is_configured() {
            if add_phase_handler::<metric_source::instrumented::LogPhaseHandler>(cf_ref)
                .is_err()
            {
                return Status::NGX_ERROR.into();
            }
        }

        Status::NGX_OK.into()
    }
}

// ── init_process callback ─────────────────────────────────────────────────────

/// Called by NGINX once per worker process after the process has forked.
///
/// Only Worker 0 (or single-process mode) bootstraps the export task.
/// All other workers log a debug line and return immediately.
///
/// Item 5 verification: grep `error.log` for "spawning export task" — exactly
/// one match must appear across all workers.
extern "C" fn ngx_otel_init_process(cycle: *mut ngx_cycle_t) -> ngx_int_t {
    // Determine the calling process type and worker index.
    let process_type = unsafe { nginx_sys::ngx_process } as u32;
    let worker_num = unsafe { nginx_sys::ngx_worker };
    let log = unsafe { (*cycle).log };

    // Worker 0 and single-process mode spawn the export task.
    // All other workers return early.
    let is_designated = matches!(
        (process_type, worker_num as u32),
        (nginx_sys::NGX_PROCESS_WORKER, 0) | (nginx_sys::NGX_PROCESS_SINGLE, _)
    );

    if !is_designated {
        ngx::ngx_log_error!(
            nginx_sys::NGX_LOG_DEBUG,
            log,
            "otel init_process: worker {}, no export task",
            worker_num
        );
        return Status::NGX_OK.into();
    }

    // Retrieve the main HTTP config for this cycle.
    let cycle_ref = unsafe { &mut *cycle };
    let Some(amcf) = HttpOtelModule::main_conf(cycle_ref) else {
        return Status::NGX_OK.into();
    };

    if !amcf.is_configured() {
        ngx::ngx_log_error!(
            nginx_sys::NGX_LOG_DEBUG,
            log,
            "otel init_process: not configured, no export task"
        );
        return Status::NGX_OK.into();
    }

    // Item 5: this exact string is grepped by the integration test.
    ngx::ngx_log_error!(
        nginx_sys::NGX_LOG_NOTICE,
        log,
        "otel init_process: worker 0 spawning export task (endpoint={})",
        amcf.exporter.endpoint
    );

    // Spawn the export loop on the NGINX event loop.
    let task = ngx::async_::spawn(export::export_loop(amcf));

    // Move the task handle into the cycle pool so it is dropped (and the
    // task is cancelled) when the cycle is destroyed at worker exit.
    let pool = unsafe { Pool::from_ngx_pool((*cycle).pool) };
    if pool.allocate(task).is_null() {
        ngx::ngx_log_error!(
            nginx_sys::NGX_LOG_ERR,
            log,
            "otel init_process: pool allocation for export task failed"
        );
        return Status::NGX_ERROR.into();
    }

    Status::NGX_OK.into()
}

// ── exit_process callback ─────────────────────────────────────────────────────

/// Called by NGINX when the worker process is exiting (SIGQUIT, SIGHUP-induced
/// shutdown, or natural exit).
///
/// Performs a synchronous final flush via [`export::exit_process_flush`] to
/// close the Phase 1.1 graceful-drain limitation: the async drain in
/// `graceful_drain` may not fire when SIGQUIT arrives while the export loop is
/// between intervals (asleep on a cancelable timer).  This callback fires
/// unconditionally and sends one final batch via the sync HTTP client before
/// the worker exits.
///
/// Only runs for Worker 0 or single-process mode — the designated worker that
/// holds the export state.  Other workers return immediately.
unsafe extern "C" fn ngx_otel_exit_process(cycle: *mut ngx_cycle_t) {
    let process_type = unsafe { nginx_sys::ngx_process } as u32;
    let worker_num = unsafe { nginx_sys::ngx_worker };

    let is_designated = matches!(
        (process_type, worker_num as u32),
        (nginx_sys::NGX_PROCESS_WORKER, 0) | (nginx_sys::NGX_PROCESS_SINGLE, _)
    );

    if !is_designated {
        return;
    }

    // Retrieve the main HTTP config for this cycle.
    let cycle_ref = unsafe { &mut *cycle };
    let Some(amcf) = HttpOtelModule::main_conf(cycle_ref) else {
        return;
    };

    if !amcf.is_configured() {
        return;
    }

    export::exit_process_flush(amcf);
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

    // nginx process-type globals accessed by ngx_otel_init_process.
    #[no_mangle]
    pub static mut ngx_process: nginx_sys::ngx_uint_t = nginx_sys::NGX_PROCESS_SINGLE as nginx_sys::ngx_uint_t;

    // nginx shutdown flags accessed by the export loop.
    #[no_mangle]
    pub static mut ngx_terminate: core::ffi::c_int = 0;

    #[no_mangle]
    pub static mut ngx_exiting: nginx_sys::ngx_uint_t = 0;

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
                unsafe { core::ptr::addr_of_mut!(STUB_STAT_ZERO) };
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
    pub unsafe extern "C" fn ngx_array_push(
        _a: *mut nginx_sys::ngx_array_t,
    ) -> *mut c_void {
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
    pub static mut ngx_event_timer_rbtree: nginx_sys::ngx_rbtree_t =
        nginx_sys::ngx_rbtree_t {
            root: core::ptr::null_mut(),
            sentinel: core::ptr::null_mut(),
            insert: None,
        };

    // nginx http module descriptor (used by ngx core internally).
    #[no_mangle]
    pub static mut ngx_http_module: nginx_sys::ngx_module_t = nginx_sys::ngx_module_t::default();

    // nginx posted-events queue (used by event loop).
    #[no_mangle]
    pub static mut ngx_posted_next_events: nginx_sys::ngx_queue_t =
        nginx_sys::ngx_queue_t {
            prev: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
        };

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
}
