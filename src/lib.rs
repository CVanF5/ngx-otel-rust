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
//!    See [`HttpOtelModule::postconfiguration`] — the `if amcf.is_configured()`
//!    block surrounding the `add_phase_handler` call.
//!
//! 2. **Export-task gate** (`src/lib.rs` — `ngx_otel_init_process`):
//!    The async export loop is spawned **only** when `amcf.is_configured()` is
//!    true.  If the exporter is not configured the process hook returns early
//!    with no allocation, no task spawn, and no background activity.
//!    See [`ngx_otel_init_process`] — the `if !amcf.is_configured()` early
//!    return that precedes any `ngx::async_::spawn` or `Pool::allocate` call.
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
// Pull all `std` macros (format!, vec!, assert!, etc.) into global scope.
// The crate is no_std but links to std, so this is safe — it only affects
// name resolution, not the binary.  Required because generated tonic client
// stubs use bare `format!` which is not in scope in a no_std crate.
#[macro_use]
extern crate std;

use core::ptr;

use nginx_sys::{
    ngx_conf_t, ngx_cycle_t, ngx_http_module_t, ngx_int_t, ngx_module_t, ngx_uint_t,
    NGX_HTTP_MODULE,
};
use ngx::core::Status;
use ngx::http::{add_phase_handler, HttpModule, HttpModuleMainConf};
// Pool is only needed for the test-support gRPC smoke harnesses in init_process.
#[cfg(any(test, feature = "test-support"))]
use ngx::core::Pool;

mod config;
pub mod data_model;
pub mod encoder;
mod export;
pub(crate) mod exporter;
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
    init_module: Some(ngx_otel_init_module),
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
/// Timing note: at initial start this fires *before* `ngx_init_signals` in
/// the master, so the forked child inherits SIG_DFL handlers. The child calls
/// `nginx_sys::ngx_init_signals` immediately after fork to fix this.
/// On SIGHUP this hook fires inside `ngx_master_process_cycle` where signals
/// are already installed — the child inherits them correctly.
///
/// See `PHASE_1_3_RESEARCH.md` §2.7–2.9, §5.2 and Q4 for design decisions.
extern "C" fn ngx_otel_init_module(cycle: *mut nginx_sys::ngx_cycle_t) -> nginx_sys::ngx_int_t {
    // Fork only when running in master-process mode. Two call sites:
    //
    // 1. Initial start: ngx_process = NGX_PROCESS_SINGLE at this point
    //    (nginx.c:339 sets MASTER *after* ngx_init_cycle returns; our hook
    //    fires during ngx_init_cycle:649). Allow SINGLE here.
    //
    // 2. SIGHUP reload: ngx_process = NGX_PROCESS_MASTER. Allow MASTER.
    //
    // Skip all worker/helper/signaller contexts (they should never call
    // ngx_init_cycle, but the check is cheap and defensive).
    //
    // Note: unlike cache_manager (spawned from ngx_master_process_cycle
    // where MASTER is already set), we use init_module which fires earlier.
    let process = unsafe { nginx_sys::ngx_process } as u32;
    if process != nginx_sys::NGX_PROCESS_MASTER && process != nginx_sys::NGX_PROCESS_SINGLE {
        return Status::NGX_OK.into();
    }

    // Don't spawn an exporter during `nginx -t` (config-test mode). In test
    // mode ngx_init_cycle is called just for syntax validation; spawning a
    // child here would leak it as an orphan when the master exits after the
    // test.
    if unsafe { nginx_sys::ngx_test_config } != 0 {
        return Status::NGX_OK.into();
    }

    let cycle_ref = unsafe { &mut *cycle };
    let Some(amcf) = HttpOtelModule::main_conf(cycle_ref) else {
        return Status::NGX_OK.into();
    };
    if !amcf.is_configured() {
        // Zero-cost gate: module loaded but no otel_exporter block → no fork,
        // no proctitle child, no background activity.
        return Status::NGX_OK.into();
    }

    // Detect SIGHUP reload via old_cycle->conf_ctx: the cycle passed to
    // ngx_init_cycle is NULL only at very first start (it's the zero-initialized
    // init_cycle struct; conf_ctx == NULL marks it). On SIGHUP, old_cycle is the
    // fully-initialized current cycle (conf_ctx != NULL).
    //
    // IMPORTANT: Checking `old_cycle != NULL` alone is WRONG. At initial start,
    // ngx_init_cycle is called as ngx_init_cycle(&init_cycle) where
    // init_cycle is zeroed, so new_cycle->old_cycle = &init_cycle (NOT null).
    // The distinguishing factor is conf_ctx: NULL in the zero-init cycle,
    // non-NULL in a fully-configured running cycle.
    // See nginx/src/core/ngx_cycle.c and the ngx_is_init_cycle() macro.
    let is_reload = unsafe {
        let old = (*cycle).old_cycle;
        !old.is_null() && !(*old).conf_ctx.is_null()
    };
    let respawn_flag: nginx_sys::ngx_int_t = if is_reload {
        // JUST_RESPAWN: new exporter is skipped on master's first signal
        // fan-out so old+new coexist during the ~100ms overlap window.
        // The old exporter receives NGX_CMD_QUIT via ngx_signal_worker_processes
        // and exits after its graceful drain.
        nginx_sys::NGX_PROCESS_JUST_RESPAWN as nginx_sys::ngx_int_t
    } else {
        // RESPAWN: master auto-respawns on crash (ngx_reap_children:593-616).
        nginx_sys::NGX_PROCESS_RESPAWN as nginx_sys::ngx_int_t
    };

    // Q4 RESOLVED: pass NULL as `data`. The exporter cycle resolves MainConfig
    // from `cycle` via HttpOtelModule::main_conf(cycle) — same path the current
    // export_loop uses. Mirrors cache_manager which uses `data` only for the
    // small ngx_cache_manager_ctx_t dispatch struct, never for config.
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
        if amcf.is_configured()
            && add_phase_handler::<metric_source::instrumented::LogPhaseHandler>(cf_ref).is_err()
        {
            return Status::NGX_ERROR.into();
        }

        Status::NGX_OK.into()
    }
}

// ── init_process callback ─────────────────────────────────────────────────────

/// Called by NGINX once per worker process after the process has forked.
///
/// Phase 1.3.2: workers are no longer the owner of the export task.
/// The `nginx: otel exporter` process (spawned in `ngx_otel_init_module`)
/// owns the export task starting from Phase 1.3.2.2.
///
/// Q3 RESOLVED: callback kept registered (not `None`) for Phase 2.
/// Phase 2 (logs) will populate this with per-worker LogProducer
/// initialisation — one ring writer per worker.
///
/// The `#[cfg(any(test, feature = "test-support"))]` gRPC smoke harnesses
/// remain on Worker 0 for the Phase 1.2 gRPC integration tests. They do
/// not run in production builds (no allocation, no task spawn).
extern "C" fn ngx_otel_init_process(_cycle: *mut ngx_cycle_t) -> ngx_int_t {
    // Q3 RESOLVED: callback kept registered (not None) for Phase 2.
    // Phase 1.3: the exporter owns the export task. Workers do
    // nothing here. Phase 2 (logs) will populate this with
    // per-worker LogProducer initialisation (one ring writer per
    // worker).
    //
    // Existing #[cfg(test-support)] smoke harnesses still run on
    // Worker(0) for the gRPC bidi tests. Their cfg-gating means
    // production builds are completely empty here.

    // ── Phase 1.2 Item 1: in-worker gRPC viability harness ──────────────────
    //
    // Only compiled when the `test-support` feature is enabled.  When set,
    // and the `otel_grpc_smoke_endpoint` directive carries a non-empty value,
    // fire one unary OTLP/gRPC export from Worker 0 via
    // `NgxExecutor` + `SendRequestService` + `NgxConnIo` — the real Phase 1.2
    // production stack — to verify viability on the nginx event loop under
    // `--with-debug`.  Result is logged at NOTICE; the integration test in
    // `tests/integration/run_grpc_smoke.sh` greps for the success line.
    #[cfg(any(test, feature = "test-support"))]
    {
        let cycle = _cycle;
        let process_type = unsafe { nginx_sys::ngx_process } as u32;
        let worker_num = unsafe { nginx_sys::ngx_worker };
        let log = unsafe { (*cycle).log };
        let is_designated = matches!(
            (process_type, worker_num as u32),
            (nginx_sys::NGX_PROCESS_WORKER, 0) | (nginx_sys::NGX_PROCESS_SINGLE, _)
        );
        if is_designated {
            let cycle_ref = unsafe { &mut *cycle };
            if let Some(amcf) = HttpOtelModule::main_conf(cycle_ref) {
                let pool = unsafe { Pool::from_ngx_pool((*cycle).pool) };

                if !amcf.grpc_smoke_endpoint.is_empty() {
                    let endpoint_bytes = amcf.grpc_smoke_endpoint.as_bytes();
                    if let Ok(endpoint_str) = core::str::from_utf8(endpoint_bytes) {
                        let endpoint_owned = std::string::String::from(endpoint_str);
                        let Some(log_nn) = core::ptr::NonNull::new(log) else {
                            ngx::ngx_log_error!(
                                nginx_sys::NGX_LOG_ERR,
                                log,
                                "grpc smoke: null log pointer; skipping"
                            );
                            return Status::NGX_OK.into();
                        };

                        ngx::ngx_log_error!(
                            nginx_sys::NGX_LOG_NOTICE,
                            log,
                            "grpc smoke: firing one unary OTLP/gRPC export (endpoint={})",
                            endpoint_owned
                        );

                        let smoke_task = ngx::async_::spawn(async move {
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
                        });

                        if pool.allocate(smoke_task).is_null() {
                            ngx::ngx_log_error!(
                                nginx_sys::NGX_LOG_ERR,
                                log,
                                "grpc smoke: pool allocation for smoke task failed"
                            );
                            // Non-fatal.
                        }
                    } else {
                        ngx::ngx_log_error!(
                            nginx_sys::NGX_LOG_ERR,
                            log,
                            "grpc smoke: otel_grpc_smoke_endpoint is not valid UTF-8; skipping"
                        );
                    }
                }

                // ── Phase 1.2 Item 2: bidi gRPC viability harness ───────────────────
                //
                // Only compiled when the `test-support` feature is enabled.  When set,
                // and the `otel_grpc_bidi_smoke_endpoint` directive carries a non-empty
                // value, fire one bidi `Echo.BidiEcho` call from Worker 0 via the same
                // `NgxExecutor` + `SendRequestService` + `NgxConnIo` stack as Item 1,
                // against the stand-alone `examples/bidi_echo_server` process.  Proves
                // the send-half and receive-half are independently pollable without
                // deadlock or livelock on the nginx event loop.  Result is logged at
                // NOTICE; the integration test in `run_grpc_bidi_smoke.sh` greps for
                // the success line.
                if !amcf.bidi_smoke_endpoint.is_empty() {
                    let endpoint_bytes = amcf.bidi_smoke_endpoint.as_bytes();
                    if let Ok(endpoint_str) = core::str::from_utf8(endpoint_bytes) {
                        let endpoint_owned = std::string::String::from(endpoint_str);
                        let Some(log_nn) = core::ptr::NonNull::new(log) else {
                            ngx::ngx_log_error!(
                                nginx_sys::NGX_LOG_ERR,
                                log,
                                "bidi smoke: null log pointer; skipping"
                            );
                            return Status::NGX_OK.into();
                        };

                        ngx::ngx_log_error!(
                            nginx_sys::NGX_LOG_NOTICE,
                            log,
                            "bidi smoke: firing one bidi stream (endpoint={})",
                            endpoint_owned
                        );

                        let bidi_task = ngx::async_::spawn(async move {
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
                        });

                        if pool.allocate(bidi_task).is_null() {
                            ngx::ngx_log_error!(
                                nginx_sys::NGX_LOG_ERR,
                                log,
                                "bidi smoke: pool allocation for bidi task failed"
                            );
                            // Non-fatal: the task is already running.
                        }
                    } else {
                        ngx::ngx_log_error!(
                            nginx_sys::NGX_LOG_ERR,
                            log,
                            "bidi smoke: otel_grpc_bidi_smoke_endpoint is not valid UTF-8; skipping"
                        );
                    }
                }

                // ── Phase 1.2 Item 3: bidi backpressure overload ─────────────────────
                //
                // Only compiled when the `test-support` feature is enabled.  When set,
                // and the `otel_grpc_bidi_overload_endpoint` directive carries a non-empty
                // value, fire a sustained bidi overload from Worker 0 against the echo
                // server to exercise the give-up / backpressure path.  Increments the
                // `BIDI_BACKPRESSURE_DROPS` counter for each send that exceeded the
                // give-up deadline.  Result is logged at NOTICE; the integration test in
                // `run_grpc_bidi_overload.sh` greps for the summary line and asserts
                // dropped > 0 and received > 0.
                if !amcf.bidi_overload_endpoint.is_empty() {
                    let endpoint_bytes = amcf.bidi_overload_endpoint.as_bytes();
                    if let Ok(endpoint_str) = core::str::from_utf8(endpoint_bytes) {
                        let endpoint_owned = std::string::String::from(endpoint_str);
                        let Some(log_nn) = core::ptr::NonNull::new(log) else {
                            ngx::ngx_log_error!(
                                nginx_sys::NGX_LOG_ERR,
                                log,
                                "bidi overload: null log pointer; skipping"
                            );
                            return Status::NGX_OK.into();
                        };

                        ngx::ngx_log_error!(
                            nginx_sys::NGX_LOG_NOTICE,
                            log,
                            "bidi overload: queueing overload task (endpoint={})",
                            endpoint_owned
                        );

                        let overload_task = ngx::async_::spawn(async move {
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
                        });

                        if pool.allocate(overload_task).is_null() {
                            ngx::ngx_log_error!(
                                nginx_sys::NGX_LOG_ERR,
                                log,
                                "bidi overload: pool allocation for overload task failed"
                            );
                            // Non-fatal: the task is already running.
                        }
                    } else {
                        ngx::ngx_log_error!(
                            nginx_sys::NGX_LOG_ERR,
                            log,
                            "bidi overload: otel_grpc_bidi_overload_endpoint is not valid UTF-8; skipping"
                        );
                    }
                }
            }
        }
    }

    Status::NGX_OK.into()
}

// ── exit_process callback ─────────────────────────────────────────────────────

/// Called by NGINX when the worker process is exiting (SIGQUIT, SIGHUP-induced
/// shutdown, or natural exit).
///
/// Phase 1.3.2: workers no longer own the export state. The sync
/// `exit_process_flush` call has been removed. The exporter's graceful_drain
/// (called on its `ngx_quit` path) handles the final flush.
///
/// Q3 RESOLVED: callback kept registered (not `None`) for Phase 2.
/// Phase 2 (logs) will populate this with producer-side final flush —
/// drain the worker's local log buffer into the shared ring before exit
/// so the exporter picks up the tail records.
unsafe extern "C" fn ngx_otel_exit_process(_cycle: *mut ngx_cycle_t) {
    // Q3 RESOLVED: callback kept registered (not None) for Phase 2.
    // Phase 1.3: the exporter's cycle owns the final drain.
    // Phase 2 (logs) will populate this with producer-side final
    // flush — drain the worker's local log buffer into the shared
    // ring before exit so the exporter picks up the tail records.
}

// ── otel_status_endpoint content handler ─────────────────────────────────────

/// Content handler for `otel_status_endpoint;` (Phase 1.3.3 Sub-item 3).
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

    // Read control_shm version via the request's module conf (one Relaxed load).
    // ngx_http_request_t implements HttpModuleConfExt, so main_conf() works directly.
    let version = unsafe { r.as_ref() }
        .and_then(HttpOtelModule::main_conf)
        .and_then(|amcf| amcf.control_shm_ptr())
        .map(|ctrl| unsafe { (*ctrl).version.load(Ordering::Relaxed) })
        .unwrap_or(0);

    // Format as "version\n".
    let body = std::format!("{}\n", version);
    let body_len = body.len();

    // Set response headers.
    let headers_out = unsafe { &mut (*r).headers_out };
    headers_out.status = 200;
    headers_out.content_length_n = body_len as nginx_sys::off_t;
    // Content-Type: text/plain (static string; pointer valid for process lifetime).
    static CONTENT_TYPE_BYTES: &[u8] = b"text/plain";
    headers_out.content_type.len = CONTENT_TYPE_BYTES.len();
    headers_out.content_type.data = CONTENT_TYPE_BYTES.as_ptr() as *mut _;
    headers_out.content_type_len = CONTENT_TYPE_BYTES.len();

    // Send response header.
    let rc = unsafe { nginx_sys::ngx_http_send_header(r) };
    if rc == nginx_sys::NGX_ERROR as nginx_sys::ngx_int_t {
        return rc;
    }
    // HEAD requests need no body.
    if unsafe { (*r).header_only() } != 0 {
        return nginx_sys::NGX_OK as nginx_sys::ngx_int_t;
    }

    // Allocate body buffer from request pool.
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
    unsafe {
        (*chain_ptr).buf = buf.as_ngx_buf_mut();
        (*chain_ptr).next = core::ptr::null_mut();
    }
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

    // ── Phase 1.3.3 stubs — otel_status_endpoint content handler ─────────────
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

    // ── Phase 1.3.1 stubs — exporter cycle / channel handler ─────────────────
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
}
