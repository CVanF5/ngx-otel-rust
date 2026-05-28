// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Exporter process lifecycle — Phase 1.3.1.
//!
//! This module provides the `nginx: otel exporter` child process, spawned by
//! master via the `init_module` hook in `src/lib.rs`. The exporter runs the
//! export loop (Phase 1.3.2), handles master channel signals
//! (QUIT / TERMINATE / REOPEN), and drops privileges to the configured nginx
//! user.
//!
//! Sub-item 1 (this file, initial pass): `NgxProcess::Exporter` helper +
//! `IS_OTEL_EXPORTER` flag. Sub-items 2–5 add the channel handler, the
//! `init_module` callback, the full cycle body, and the crash-respawn test.

use core::sync::atomic::{AtomicBool, Ordering};

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
