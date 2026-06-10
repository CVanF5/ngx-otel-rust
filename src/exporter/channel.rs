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
    ngx_channel_t, ngx_close_connection, ngx_connection_t, ngx_event_t, ngx_int_t, ngx_quit,
    ngx_read_channel, ngx_reopen, ngx_terminate, NGX_AGAIN, NGX_CMD_QUIT, NGX_CMD_REOPEN,
    NGX_CMD_TERMINATE, NGX_ERROR,
};

/// Channel event handler registered on the exporter's `ngx_channel` fd.
///
/// Called by nginx's event loop when the master writes a command byte to the
/// exporter's channel end. Drains the channel in a loop until `NGX_AGAIN`
/// (no more data) or `NGX_ERROR` (channel closed / read error).
///
/// On `NGX_ERROR` (master channel EOF or read error — e.g. `kill -9` master):
/// closes the connection via `ngx_close_connection` (deregisters the
/// level-triggered fd from epoll/kqueue AND closes the socket; mirrors
/// `ngx_channel_handler` at `nginx/src/os/unix/ngx_process_cycle.c:1022-1029`)
/// and sets `ngx_terminate = 1` so the cycle loop exits immediately.
///
/// **B2 fix:** the pre-fix code returned here without closing `c`, leaving the
/// EOF-firing fd still registered on the level-triggered event queue → every
/// subsequent `ngx_process_events_and_timers` call woke immediately and
/// re-fired the handler → exporter at 100% CPU until manual SIGKILL.  With
/// `kill -9` the master never sends SIGTERM/SIGQUIT, so the "cycle loop will
/// exit on the next signal" assumption was wrong for that path.
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
            // Channel EOF or read error: master has closed its end (e.g.
            // master killed with SIGKILL) or the channel fd is broken.
            //
            // B2 fix — mirror ngx_channel_handler
            // (ngx_process_cycle.c:1022-1029):
            //   1. ngx_close_connection(c) — deregisters `c` from
            //      epoll/kqueue (calling ngx_del_conn internally with
            //      NGX_CLOSE_EVENT) and closes the underlying socket fd.
            //      This stops the level-triggered EOF from re-firing every
            //      event loop tick (the 100% CPU symptom).
            //   2. ngx_terminate = 1 — the cycle loop sees this and calls
            //      std::process::exit(0) on the next check.  Without this,
            //      the exporter would idle indefinitely as an orphan (master
            //      is dead and will never send SIGTERM/SIGQUIT).
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
