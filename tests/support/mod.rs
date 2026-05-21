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

// ngx_stat_* statics — each is a *mut ngx_atomic_t pointing at a zero value.
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

// NGINX array API.
#[no_mangle]
pub unsafe extern "C" fn ngx_array_push(
    _a: *mut nginx_sys::ngx_array_t,
) -> *mut c_void {
    core::ptr::null_mut()
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal spin-loop executor for async transport tests.
// ──────────────────────────────────────────────────────────────────────────────

/// Drives a future to completion using a spin-loop executor.
///
/// Works because `HyperHttpTransport` uses blocking I/O — both `poll_read`
/// and `poll_write` always return `Poll::Ready` — so the future never
/// returns `Poll::Pending`.
pub fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    unsafe fn noop_clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    unsafe fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);

    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(val) => return val,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}
