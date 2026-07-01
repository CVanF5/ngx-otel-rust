// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Rust-side channel event handler for the `nginx: otel exporter` process.
//!
//! Ports the QUIT / TERMINATE / REOPEN arms of the static C
//! `ngx_channel_handler` (`nginx/src/os/unix/ngx_process_cycle.c:1000-1085`);
//! OPEN_CHANNEL / CLOSE_CHANNEL are omitted as the exporter only talks to
//! master, never peers with workers via channels. Registered via
//! `nginx_sys::ngx_add_channel_event` in `otel_exporter_cycle`.

use core::mem;

use nginx_sys::{
    ngx_channel_t, ngx_close_connection, ngx_connection_t, ngx_event_t, ngx_int_t, ngx_quit,
    ngx_read_channel, ngx_reopen, ngx_terminate, NGX_AGAIN, NGX_CMD_QUIT, NGX_CMD_REOPEN,
    NGX_CMD_TERMINATE, NGX_ERROR,
};

/// Channel event handler registered on the exporter's `ngx_channel` fd.
///
/// Drains the channel in a loop until `NGX_AGAIN` (no more data) or
/// `NGX_ERROR` (channel closed / read error, e.g. `kill -9` master).
///
/// On `NGX_ERROR`, closing `c` is required: leaving the EOF-firing fd
/// registered on the level-triggered event queue would spin the exporter at
/// 100% CPU (re-fires every loop tick), and `kill -9` never sends a signal to
/// fall back on.
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
            ngx_read_channel((*c).fd, &raw mut ch, mem::size_of::<ngx_channel_t>(), (*ev).log)
        };

        if n == NGX_AGAIN as ngx_int_t {
            // Channel drained — no more commands pending.
            return;
        }
        if n == NGX_ERROR as ngx_int_t {
            // Channel EOF/error (master gone): mirror ngx_channel_handler
            // (ngx_process_cycle.c:1022-1029) — deregister + close the fd so
            // the level-triggered EOF stops re-firing, then request exit
            // since master will never send SIGTERM/SIGQUIT for us.
            //
            // SAFETY: `c` is the valid channel connection obtained from
            // `ev.data` at the top of this handler; it has not been freed
            // because we only reach this path on the first NGX_ERROR
            // (subsequent calls are prevented because we close `c` here and
            // the fd is removed from the event interest set).
            unsafe { ngx_close_connection(c) };
            // SAFETY: ngx_terminate is nginx's global fast-shutdown
            // sig_atomic_t; the exporter runs single-threaded on the nginx
            // event loop, so writing it here is race-free.
            unsafe { ngx_terminate = 1 };
            return;
        }

        // Dispatch on the command byte; only QUIT / TERMINATE / REOPEN are handled.
        match ch.command as u32 {
            // SAFETY: set nginx's global graceful-quit flag. The exporter runs
            // single-threaded on the nginx event loop, so writing this static is
            // race-free and is the documented signal-delivery mechanism.
            NGX_CMD_QUIT => unsafe { ngx_quit = 1 },
            // SAFETY: as above — nginx's global fast-shutdown flag.
            NGX_CMD_TERMINATE => unsafe { ngx_terminate = 1 },
            // SAFETY: as above — nginx's global log-reopen flag.
            NGX_CMD_REOPEN => unsafe { ngx_reopen = 1 },
            _ => {
                // OPEN_CHANNEL / CLOSE_CHANNEL / future commands: not acted on.
                // NGX_CMD_OPEN_CHANNEL can carry a received fd in `ch.fd` (via
                // SCM_RIGHTS); close it here rather than silently leaking it
                // toward RLIMIT_NOFILE.
                if ch.fd >= 0 {
                    // SAFETY: `ch.fd` is an fd just received by `ngx_read_channel`
                    // (>= 0 checked); closing it is sound and the exporter never
                    // uses sibling-channel fds.
                    unsafe { libc::close(ch.fd) };
                }
            }
        }
    }
}
