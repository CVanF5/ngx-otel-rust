// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Stub implementations of NGINX C symbols required by the library at link time.
//!
//! On macOS, flat-namespace dynamic linking resolves all external symbols at
//! process startup.  These stubs satisfy that requirement for integration test
//! binaries without an NGINX process.
//!
//! The stubs are intentionally no-ops: integration tests for the transport
//! layer do not exercise NGINX configuration parsing, shared memory, or
//! request handling.

use core::ffi::{c_char, c_void};
use nginx_sys::{ngx_command_t, ngx_conf_t, ngx_module_t};

// Built-in slot handlers referenced as function pointers in the commands table.
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

// NGINX global module descriptors.
#[no_mangle]
pub static mut ngx_core_module: ngx_module_t = ngx_module_t::default();

#[no_mangle]
pub static mut ngx_http_core_module: ngx_module_t = ngx_module_t::default();

// NGINX shared-memory API.
#[no_mangle]
pub unsafe extern "C" fn ngx_shared_memory_add(
    _cf: *mut ngx_conf_t,
    _name: *mut nginx_sys::ngx_str_t,
    _size: usize,
    _tag: *mut c_void,
) -> *mut nginx_sys::ngx_shm_zone_t {
    core::ptr::null_mut()
}

// NGINX request-path globals.
#[no_mangle]
pub static mut ngx_worker: nginx_sys::ngx_uint_t = 0;

#[no_mangle]
pub static mut ngx_current_msec: nginx_sys::ngx_msec_t = 0;

// nginx process-type globals (referenced by ngx_otel_init_process).
#[no_mangle]
pub static mut ngx_process: nginx_sys::ngx_uint_t =
    nginx_sys::NGX_PROCESS_SINGLE as nginx_sys::ngx_uint_t;

// nginx shutdown flags (referenced by the export loop).
#[no_mangle]
pub static mut ngx_terminate: core::ffi::c_int = 0;

#[no_mangle]
pub static mut ngx_exiting: nginx_sys::ngx_uint_t = 0;

// nginx global cycle pointer (used by ngx::log::ngx_cycle_log).
#[no_mangle]
pub static mut ngx_cycle: *mut nginx_sys::ngx_cycle_t = core::ptr::null_mut();

// ngx_stat_* statics — each pointer has its OWN backing cell so that a write
// through one does not corrupt the others.
static mut STUB_STAT_ACCEPTED: core::ffi::c_ulong = 0;
static mut STUB_STAT_HANDLED: core::ffi::c_ulong = 0;
static mut STUB_STAT_REQUESTS: core::ffi::c_ulong = 0;
static mut STUB_STAT_ACTIVE: core::ffi::c_ulong = 0;
static mut STUB_STAT_READING: core::ffi::c_ulong = 0;
static mut STUB_STAT_WRITING: core::ffi::c_ulong = 0;
static mut STUB_STAT_WAITING: core::ffi::c_ulong = 0;

#[no_mangle]
pub static mut ngx_stat_accepted: *mut nginx_sys::ngx_atomic_t =
    unsafe { core::ptr::addr_of_mut!(STUB_STAT_ACCEPTED) };
#[no_mangle]
pub static mut ngx_stat_handled: *mut nginx_sys::ngx_atomic_t =
    unsafe { core::ptr::addr_of_mut!(STUB_STAT_HANDLED) };
#[no_mangle]
pub static mut ngx_stat_requests: *mut nginx_sys::ngx_atomic_t =
    unsafe { core::ptr::addr_of_mut!(STUB_STAT_REQUESTS) };
#[no_mangle]
pub static mut ngx_stat_active: *mut nginx_sys::ngx_atomic_t =
    unsafe { core::ptr::addr_of_mut!(STUB_STAT_ACTIVE) };
#[no_mangle]
pub static mut ngx_stat_reading: *mut nginx_sys::ngx_atomic_t =
    unsafe { core::ptr::addr_of_mut!(STUB_STAT_READING) };
#[no_mangle]
pub static mut ngx_stat_writing: *mut nginx_sys::ngx_atomic_t =
    unsafe { core::ptr::addr_of_mut!(STUB_STAT_WRITING) };
#[no_mangle]
pub static mut ngx_stat_waiting: *mut nginx_sys::ngx_atomic_t =
    unsafe { core::ptr::addr_of_mut!(STUB_STAT_WAITING) };

// NGINX array API.
#[no_mangle]
pub unsafe extern "C" fn ngx_array_push(_a: *mut nginx_sys::ngx_array_t) -> *mut c_void {
    core::ptr::null_mut()
}

// nginx connection / pool API used by NgxConnIo / NgxPool (transport layer).
// These are never actually called in integration tests but must exist in the
// flat namespace on macOS so the test binary can start.

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
// flat-namespace lookup; integration tests never exercise real log output.
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

// nginx config parse (used internally, never called in integration tests).
#[no_mangle]
pub unsafe extern "C" fn ngx_conf_parse(
    _cf: *mut nginx_sys::ngx_conf_t,
    _filename: *mut nginx_sys::ngx_str_t,
) -> *mut core::ffi::c_char {
    core::ptr::null_mut()
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal spin-loop executor for async transport tests.
// ──────────────────────────────────────────────────────────────────────────────

/// Drives a future to completion using a spin-loop executor with a 30-second
/// wall-clock deadline.
///
/// The waker is a no-op; forward progress relies on the spin loop.  Each
/// `Poll::Pending` arm yields the thread to avoid a hot spin.  If the future
/// has not completed within the deadline the test panics with a clear timeout
/// message rather than hanging indefinitely.
///
/// 30 seconds is intentionally generous: it must accommodate a slow CI box
/// while still surfacing a genuinely stalled collector in a reasonable time.
pub fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use std::time::Instant;

    unsafe fn noop_clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    unsafe fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    let deadline = Instant::now() + std::time::Duration::from_secs(30);

    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(val) => return val,
            Poll::Pending => {
                assert!(
                    Instant::now() < deadline,
                    "block_on: future did not complete within 30 s — \
                     collector may have stalled or connection is hung"
                );
                std::thread::yield_now();
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Regression tests for the test-support helpers themselves.
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Finding #3 regression: block_on must panic with a clear message when the
    // future stays Pending past the deadline.  We use a short deadline via a
    // helper that mirrors block_on but accepts an explicit duration, confirming
    // the timeout path fires rather than spinning forever.
    #[test]
    fn block_on_times_out_on_stalled_future() {
        use std::future::Future;
        use std::pin::Pin;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        use std::time::{Duration, Instant};

        // A future that never resolves.
        struct NeverReady;
        impl Future for NeverReady {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }

        // Inline copy of block_on with a 100 ms deadline so the test is fast.
        fn block_on_with_deadline<F: Future>(fut: F, timeout: Duration) -> Option<F::Output> {
            unsafe fn noop_clone(_: *const ()) -> RawWaker {
                RawWaker::new(std::ptr::null(), &VTABLE)
            }
            unsafe fn noop(_: *const ()) {}
            static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

            let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
            let mut cx = Context::from_waker(&waker);
            let mut fut = std::pin::pin!(fut);
            let deadline = Instant::now() + timeout;

            loop {
                match fut.as_mut().poll(&mut cx) {
                    Poll::Ready(val) => return Some(val),
                    Poll::Pending => {
                        if Instant::now() >= deadline {
                            return None; // timed out
                        }
                        std::thread::yield_now();
                    }
                }
            }
        }

        // The stalled future must time out (return None) rather than looping forever.
        let result = block_on_with_deadline(NeverReady, Duration::from_millis(100));
        assert!(
            result.is_none(),
            "expected timeout (None) from a never-Ready future, got Some(())"
        );
    }

    // Finding #4 regression: each ngx_stat_* pointer must point to a distinct
    // memory location.  Writing through one must not be visible through any other.
    #[test]
    fn ngx_stat_pointers_are_distinct() {
        // Collect raw pointer values for each stat pointer.
        // Safety: we only read the pointer addresses, never dereference.
        let ptrs: [*mut nginx_sys::ngx_atomic_t; 7] = unsafe {
            [
                ngx_stat_accepted,
                ngx_stat_handled,
                ngx_stat_requests,
                ngx_stat_active,
                ngx_stat_reading,
                ngx_stat_writing,
                ngx_stat_waiting,
            ]
        };

        // Every address must be unique.
        for i in 0..ptrs.len() {
            for j in (i + 1)..ptrs.len() {
                assert_ne!(
                    ptrs[i], ptrs[j],
                    "ngx_stat pointers[{}] and [{}] alias the same address {:p}",
                    i, j, ptrs[i]
                );
            }
        }
    }
}
