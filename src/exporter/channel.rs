// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Rust-side channel event handler for the `nginx: otel exporter` process.
//!
//! Ports the QUIT / TERMINATE / REOPEN arms of the static C
//! `ngx_channel_handler` (`nginx/src/os/unix/ngx_process_cycle.c:1000-1085`)
//! to Rust. The OPEN_CHANNEL / CLOSE_CHANNEL sibling-tracking arms are
//! intentionally omitted — the exporter does not peer with workers via
//! channels; it communicates only with master.
//!
//! The handler is registered via `nginx_sys::ngx_add_channel_event` in
//! `otel_exporter_cycle` (Sub-item 4 / `src/exporter/mod.rs`).
//!
//! See `PHASE_1_3_RESEARCH.md` §3.4 and §8 Q1 for the design rationale.
//! Bindings for `ngx_channel_t`, `ngx_read_channel`, and
//! `ngx_add_channel_event` come from `nginx_sys::*` via the pre-flight
//! `ngx-rust/nginx-sys/build/wrapper.h` `#include <ngx_channel.h>` commit.

use core::mem;

use nginx_sys::{
    ngx_channel_t, ngx_connection_t, ngx_event_t, ngx_int_t, ngx_quit, ngx_read_channel,
    ngx_reopen, ngx_terminate, NGX_AGAIN, NGX_CMD_QUIT, NGX_CMD_REOPEN, NGX_CMD_TERMINATE,
    NGX_ERROR,
};

/// Channel event handler registered on the exporter's `ngx_channel` fd.
///
/// Called by nginx's event loop when the master writes a command byte to the
/// exporter's channel end. Drains the channel in a loop until `NGX_AGAIN`
/// (no more data) or `NGX_ERROR` (channel closed / read error).
///
/// On `NGX_ERROR`: does NOT close the connection — the cycle loop will see
/// the next signal flag and exit cleanly. This mirrors the approach taken in
/// `ngx_cache_manager_process_cycle` where the channel can be lost without
/// killing the process.
///
/// # Safety
///
/// This is an FFI callback; all pointer dereferences are inside `unsafe`
/// blocks. The `ev` pointer is guaranteed non-null by nginx's event dispatch.
pub unsafe extern "C" fn otel_exporter_channel_handler(ev: *mut ngx_event_t) {
    // SAFETY: nginx's event dispatch passes a valid non-null `ev` (fn contract);
    // `ev.data` is the channel connection pointer stored at registration.
    let c: *mut ngx_connection_t = unsafe { (*ev).data.cast() };
    loop {
        // SAFETY: `ngx_channel_t` is a plain C POD struct, so an all-zero bit
        // pattern is a valid initial value.
        let mut ch: ngx_channel_t = unsafe { mem::zeroed() };
        // SAFETY: `c` is the valid channel connection (from `ev.data`) with an
        // open fd; `&mut ch` is a buffer of exactly `size_of::<ngx_channel_t>()`
        // bytes; `(*ev).log` is the event's log. Plain FFI read into `ch`.
        let n: ngx_int_t = unsafe {
            ngx_read_channel((*c).fd, &mut ch as *mut _, mem::size_of::<ngx_channel_t>(), (*ev).log)
        };

        if n == NGX_AGAIN as ngx_int_t {
            // Channel drained — no more commands pending.
            return;
        }
        if n == NGX_ERROR as ngx_int_t {
            // Channel closed by master or read error. Don't close the
            // connection here — the cycle loop will exit on the next signal
            // flag set by the master (SIGTERM/SIGQUIT). Caller's event_t
            // stays registered.
            return;
        }

        // Dispatch on the command byte. We handle only the QUIT / TERMINATE /
        // REOPEN arms. The OPEN_CHANNEL / CLOSE_CHANNEL sibling-tracking arms
        // are skipped — the exporter doesn't peer with workers via channels.
        match ch.command as u32 {
            // SAFETY: set nginx's global graceful-quit flag. The exporter runs
            // single-threaded on the nginx event loop, so writing this static is
            // race-free and is the documented signal-delivery mechanism.
            NGX_CMD_QUIT => unsafe { ngx_quit = 1 },
            // SAFETY: as above — nginx's global fast-shutdown flag.
            NGX_CMD_TERMINATE => unsafe { ngx_terminate = 1 },
            // SAFETY: as above — nginx's global log-reopen flag.
            NGX_CMD_REOPEN => unsafe { ngx_reopen = 1 },
            _ => {} // OPEN_CHANNEL / CLOSE_CHANNEL — ignored
        }
    }
}
