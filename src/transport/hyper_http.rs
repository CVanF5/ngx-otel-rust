// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Hyper HTTP/1.1 transport for OTLP/HTTP protobuf export.
//!
//! # IO model
//!
//! Two IO adapter types are provided:
//!
//! - **`SpinIo`** (wrapping `SpinTcpIo` / `SpinUnixIo`) — non-blocking OS
//!   streams that return `Poll::Pending + wake_by_ref()` on `WouldBlock`.
//!   Safe only inside the spin-loop test executor.
//!   **Never use in a NGINX worker process** — they would busy-spin the event
//!   loop thread.
//!
//! - **`NgxConnIo`** — wraps an `ngx_peer_connection_t` and implements
//!   `hyper::rt::{Read, Write}` by storing the `Waker` and returning
//!   `Poll::Pending` *without* re-arming.  The NGINX C event handlers
//!   (`ngx_otel_conn_read_handler` / `ngx_otel_conn_write_handler`) call
//!   `Waker::wake()` when the kernel signals readiness via kqueue/epoll.
//!   This is the correct integration — no busy-spinning, no blocking.
//!
//! # Architecture
//!
//! `HyperHttpTransport<C: Connector>` is generic over the connector:
//! - Tests use `HyperHttpTransport<SpinConnector>` via `::new()`.
//! - Step 9's export loop uses `HyperHttpTransport<NgxConnector>` via
//!   `::with_ngx_log()`.
//!
//! # Precedent
//!
//! `NgxConnIo` is a direct port of the pattern in
//! `nginx-acme/src/net/peer_conn.rs`:
//! - `connect_peer` ← `PeerConnection::connect_peer`
//! - `poll_connect`  ← `PeerConnection::poll_connect`
//! - `poll_read`     ← `impl hyper::rt::Read for PeerConnection`
//! - `poll_write`    ← `impl hyper::rt::Write for PeerConnection`
//! - event handlers  ← `ngx_peer_conn_read_handler` / `ngx_peer_conn_write_handler`

use core::future;
use core::future::Future;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::boxed::Box;
use std::io;
#[cfg(any(test, feature = "test-support"))]
use std::io::{Read, Write};
#[cfg(any(test, feature = "test-support"))]
use std::net::TcpStream;
#[cfg(any(test, feature = "test-support"))]
use std::os::unix::net::UnixStream;
use std::string::ToString;
#[cfg(any(test, feature = "test-support"))]
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Request;
use nginx_sys::{
    ngx_connection_t, ngx_create_pool, ngx_destroy_pool, ngx_event_connect_peer,
    ngx_event_get_peer, ngx_event_t, ngx_handle_read_event, ngx_handle_write_event, ngx_int_t,
    ngx_log_t, ngx_palloc, ngx_peer_connection_t, NGX_AGAIN, NGX_DEFAULT_POOL_SIZE, NGX_ERROR,
    NGX_OK,
};
use ngx::core::Pool;

use super::TransportError;

// ──────────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────────

/// Default read timeout in milliseconds for `NgxConnIo`, passed to
/// `ngx_add_timer`.  This is a backstop; NGINX timer fires `wake()` via
/// the event handler, not a blocking timeout.
const DEFAULT_READ_TIMEOUT_MS: nginx_sys::ngx_msec_t = 60_000;

/// Wall-clock limit for `SpinTcpIo` / `SpinUnixIo` (test only).
#[cfg(any(test, feature = "test-support"))]
const SPIN_IO_TIMEOUT: Duration = Duration::from_secs(10);

// ──────────────────────────────────────────────────────────────────────────────
// Parsed endpoint
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) enum ParsedEndpoint {
    Http { host: std::string::String, port: u16, path: std::string::String },
    Unix { socket_path: std::string::String, http_path: std::string::String },
}

impl ParsedEndpoint {
    pub(crate) fn parse(input: &str) -> Result<Self, TransportError> {
        if let Some(rest) = input.strip_prefix("http://") {
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], std::string::String::from(&rest[i..])),
                None => (rest, std::string::String::from("/")),
            };
            let (host, port) = parse_authority(authority, 80);
            Ok(ParsedEndpoint::Http { host: std::string::String::from(host), port, path })
        } else if input.starts_with("https://") {
            Err(TransportError::TlsConfig {
                cause: std::string::String::from(
                    "HTTPS transport not yet implemented; use http:// or unix:",
                ),
            })
        } else if let Some(rest) = input.strip_prefix("unix:///") {
            Ok(ParsedEndpoint::Unix {
                socket_path: std::format!("/{}", rest),
                http_path: std::string::String::from("/v1/metrics"),
            })
        } else if let Some(rest) = input.strip_prefix("unix://") {
            Ok(ParsedEndpoint::Unix {
                socket_path: std::string::String::from(rest),
                http_path: std::string::String::from("/v1/metrics"),
            })
        } else if let Some(rest) = input.strip_prefix("unix:") {
            Ok(ParsedEndpoint::Unix {
                socket_path: std::string::String::from(rest),
                http_path: std::string::String::from("/v1/metrics"),
            })
        } else {
            Err(TransportError::InvalidEndpoint {
                input: std::string::String::from(input),
                reason: "endpoint must start with http://, https://, or unix:",
            })
        }
    }

    fn authority(&self) -> std::string::String {
        match self {
            ParsedEndpoint::Http { host, port, .. } => {
                if *port == 80 {
                    host.clone()
                } else {
                    std::format!("{}:{}", host, port)
                }
            }
            ParsedEndpoint::Unix { .. } => std::string::String::from("localhost"),
        }
    }

    fn http_path(&self) -> &str {
        match self {
            ParsedEndpoint::Http { path, .. } => path,
            ParsedEndpoint::Unix { http_path, .. } => http_path,
        }
    }
}

fn parse_authority(authority: &str, default_port: u16) -> (&str, u16) {
    match authority.rfind(':') {
        Some(idx) => {
            let port = authority[idx + 1..].parse().unwrap_or(default_port);
            (&authority[..idx], port)
        }
        None => (authority, default_port),
    }
}

/// Strip IPv6 bracket notation from a host string.
///
/// `ParsedEndpoint::parse` stores the bracket form as found in the URL
/// (e.g. `"[::1]"` from `http://[::1]:4317/`).  Any caller that needs to
/// pass the host to `IpAddr::parse` or `(host, port).to_socket_addrs()` must
/// strip the brackets first.  Both the async and sync connect paths use this
/// shared helper so the two can't drift.
///
/// Returns `host` unchanged when no brackets are present.
pub(crate) fn strip_v6_brackets(host: &str) -> &str {
    if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// OwnedNgxPool — owning wrapper for ngx_pool_t
// (Ported from nginx-acme/src/util.rs `OwnedPool`)
// ──────────────────────────────────────────────────────────────────────────────

/// Owning wrapper for an nginx memory pool.  Calls `ngx_destroy_pool` on drop.
struct OwnedNgxPool(Pool);

impl OwnedNgxPool {
    fn new(size: usize, log: core::ptr::NonNull<ngx_log_t>) -> Result<Self, TransportError> {
        // SAFETY: plain FFI into nginx's pool allocator. `log` is a valid
        // `ngx_log_t` (the caller holds a `NonNull`, kept alive for the
        // exporter's lifetime); `size` is a byte count. The returned pointer is
        // null-checked below before being wrapped.
        let pool = unsafe { ngx_create_pool(size, log.as_ptr()) };
        if pool.is_null() {
            return Err(TransportError::Connection {
                cause: std::string::String::from("ngx_create_pool failed"),
            });
        }
        // SAFETY: `pool` is non-null here (checked above) and was just returned
        // by `ngx_create_pool`, so it satisfies `from_ngx_pool`'s contract of a
        // valid, live `ngx_pool_t`. `OwnedNgxPool` takes sole ownership and
        // frees it via `ngx_destroy_pool` in `Drop`.
        Ok(Self(unsafe { Pool::from_ngx_pool(pool) }))
    }
}

impl Deref for OwnedNgxPool {
    type Target = Pool;
    fn deref(&self) -> &Pool {
        &self.0
    }
}

impl DerefMut for OwnedNgxPool {
    fn deref_mut(&mut self) -> &mut Pool {
        &mut self.0
    }
}

impl Drop for OwnedNgxPool {
    fn drop(&mut self) {
        // SAFETY: `self.0` was constructed in `new` from a live pool and this
        // wrapper has sole ownership of it, so the pointer is still valid and
        // unfreed. `Drop` runs exactly once, so the pool is destroyed once.
        unsafe { ngx_destroy_pool(self.0.as_ptr()) };
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// NgxConnIo — production IO using nginx event machinery
// (Pattern ported line-by-line from nginx-acme/src/net/peer_conn.rs)
// ──────────────────────────────────────────────────────────────────────────────

/// Wraps an `ngx_peer_connection_t` for use as hyper's async IO.
///
/// **Waking contract:**
/// - `poll_read` / `poll_write` return `Poll::Pending` **without** calling
///   `wake_by_ref()`.  They store the `Waker` in `rev` / `wev`.
/// - `ngx_otel_conn_read_handler` / `ngx_otel_conn_write_handler` (C-level
///   event callbacks registered on the connection's read/write events) call
///   `Waker::wake()` when the fd is ready, rescheduling the async task without
///   busy-spinning.
///
/// **Stability requirement:**
/// Once `connect_peer` has stored `self` in `c.data`, `NgxConnIo` must not
/// move.  Always use it behind a `Pin<Box<NgxConnIo>>`.
pub struct NgxConnIo {
    pool: OwnedNgxPool,
    pc: ngx_peer_connection_t,
    rev: Option<Waker>,
    wev: Option<Waker>,
}

// SAFETY: Only used from NGINX's single-threaded worker event loop.
unsafe impl Send for NgxConnIo {}

impl NgxConnIo {
    /// Create a new (unconnected) `NgxConnIo`.
    fn new(log: core::ptr::NonNull<ngx_log_t>) -> Result<Self, TransportError> {
        let pool = OwnedNgxPool::new(NGX_DEFAULT_POOL_SIZE as usize, log)?;

        // SAFETY: `ngx_peer_connection_t` is a `#[repr(C)]` plain-old-data
        // struct of integers, pointers and bitfields; an all-zero bit pattern is
        // a valid initial value (null pointers, cleared flags) — the same state
        // nginx itself expects before `ngx_event_connect_peer`.
        let mut pc: ngx_peer_connection_t = unsafe { core::mem::zeroed() };
        pc.get = Some(ngx_event_get_peer);
        pc.log = log.as_ptr();

        Ok(Self { pool, pc, rev: None, wev: None })
    }

    /// Calls `ngx_event_connect_peer`, then sets `c.data` and installs
    /// our event handlers so the C callbacks can reach `self`.
    ///
    /// Must be called from behind a `Pin<&mut Self>` to ensure `self` doesn't
    /// move between this call and the time the C handler fires.
    fn connect_peer(self: Pin<&mut Self>) -> ngx_int_t {
        // NgxConnIo: Unpin, so get_mut() is safe.
        let this = self.get_mut();
        // SAFETY: `&mut this.pc` is a valid, uniquely-borrowed
        // `ngx_peer_connection_t` initialised in `new` (with `get` and `log`
        // set). `ngx_event_connect_peer` is the nginx FFI that allocates the
        // connection and stores it in `pc.connection`; called on the worker's
        // event-loop thread as the contract requires.
        let rc = unsafe { ngx_event_connect_peer(&raw mut this.pc) };

        // NGX_ERROR = -1, NGX_BUSY = -3, NGX_DECLINED = -4
        if rc == NGX_ERROR as ngx_int_t || rc == -3 || rc == -4 {
            return rc;
        }

        // rc is NGX_OK (0) or NGX_AGAIN (-2): connection is allocated.
        let c: *mut ngx_connection_t = this.pc.connection;
        // SAFETY: `rc` was NGX_OK/NGX_AGAIN, so `ngx_event_connect_peer`
        // allocated and populated `pc.connection`; `c` is therefore a valid,
        // live `ngx_connection_t` (plus its `read`/`write`/`log` sub-objects)
        // owned by nginx for the connection's lifetime. `this` is pinned, so the
        // `&mut NgxConnIo` stored in `c.data` stays valid until the connection
        // closes; the pool we assign outlives the connection (owned by `this`).
        unsafe {
            // Store self so C handlers can wake the right task.
            (*c).data = (this as *mut NgxConnIo).cast();

            // Assign our pool if the connection has none.
            if (*c).pool.is_null() {
                (*c).pool = this.pool.as_ptr();
            }

            (*(*c).log).connection = (*c).number;
            (*(*c).read).handler = Some(ngx_otel_conn_read_handler);
            (*(*c).write).handler = Some(ngx_otel_conn_write_handler);
        }

        rc
    }

    /// Async drive for the connection-establishment state machine.
    fn poll_connect(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        // If already connected, check for timeout or other errors.
        if !self.pc.connection.is_null() {
            let c = self.pc.connection;
            // SAFETY: `c` is non-null here (checked above), so it is a live
            // `ngx_connection_t` from a prior `connect_peer`; its `read`/`write`
            // fields point to nginx-owned `ngx_event_t`s valid for the
            // connection's lifetime. We read the `timedout` bitfield and (on
            // timeout) hand `c` back to `ngx_close_connection`, or re-install our
            // handlers on the still-open connection.
            let rv = unsafe {
                if (*(*c).read).timedout() != 0 || (*(*c).write).timedout() != 0 {
                    nginx_sys::ngx_close_connection(c);
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    (*(*c).read).handler = Some(ngx_otel_conn_read_handler);
                    (*(*c).write).handler = Some(ngx_otel_conn_write_handler);
                    Ok(())
                }
            };
            return Poll::Ready(rv);
        }

        let rc = self.as_mut().connect_peer();

        match rc {
            0 /* NGX_OK */ => Poll::Ready(Ok(())),
            -2 /* NGX_AGAIN */ => {
                // Non-blocking connect in progress; arm a timeout and store the
                // waker.  C handler fires wake() on connect completion.
                let this = self.get_mut();
                if !this.pc.connection.is_null() {
                    // SAFETY: `pc.connection` is non-null here (checked), so it
                    // is a live nginx connection whose `read` event pointer is
                    // valid; `ngx_add_timer` is the nginx FFI for arming that
                    // event's timer with a millisecond delay.
                    unsafe {
                        nginx_sys::ngx_add_timer((*this.pc.connection).read, DEFAULT_READ_TIMEOUT_MS);
                    }
                    // SAFETY: same non-null, live connection; reading its `log`
                    // pointer field for the debug log below.
                    let log = unsafe { (*this.pc.connection).log };
                    ngx::ngx_log_debug!(
                        log,
                        "NgxConnIo::poll_connect NGX_AGAIN: storing rev+wev wakers"
                    );
                }
                this.rev = Some(cx.waker().clone());
                this.wev = Some(cx.waker().clone());
                Poll::Pending
            }
            _ => Poll::Ready(Err(io::ErrorKind::ConnectionRefused.into())),
        }
    }

    fn close(&mut self) {
        if !self.pc.connection.is_null() {
            // SAFETY: `pc.connection` is non-null (checked), so it is a live
            // nginx connection from `connect_peer`; `ngx_close_connection` is
            // the matching nginx FFI to release it. We immediately null the
            // field so a later `close`/`Drop` cannot double-free.
            unsafe { nginx_sys::ngx_close_connection(self.pc.connection) };
            self.pc.connection = core::ptr::null_mut();
        }
    }
}

impl hyper::rt::Read for NgxConnIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if self.pc.connection.is_null() {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }

        let c = self.pc.connection;
        // SAFETY: `c` is non-null here (checked above), a live nginx connection;
        // its `read` field points to the nginx-owned `ngx_event_t` valid for the
        // connection's lifetime.
        let rev: *mut ngx_event_t = unsafe { (*c).read };

        // SAFETY: `rev` is the connection's live read event (just read from `c`);
        // `timedout` is a bitfield accessor on it.
        if unsafe { (*rev).timedout() } != 0 {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }

        // Call the NGINX recv function pointer (fills MaybeUninit bytes).
        // SAFETY: hyper guarantees `buf`'s uninitialised region is a valid,
        // writable `[MaybeUninit<u8>]` for this call; `as_mut` exposes it.
        let uninit: &mut [MaybeUninit<u8>] = unsafe { buf.as_mut() };
        // SAFETY: a connected nginx connection always has `recv` set (the event
        // layer installs it on connect), so `unwrap_unchecked` is sound; we pass
        // `c` plus the `uninit` slice's pointer/len, an in-bounds writable
        // buffer, matching the `ngx_recv_pt` contract.
        let n: isize = unsafe {
            ((*c).recv.unwrap_unchecked())(c, uninit.as_mut_ptr().cast::<u8>(), uninit.len())
        };

        if n == NGX_ERROR as isize {
            return Poll::Ready(Err(io::Error::last_os_error()));
        }

        // Re-arm the read event so epoll/kqueue monitors the fd again.
        // SAFETY: `rev` is the connection's live read event; `ngx_handle_read_event`
        // is the nginx FFI that re-registers it with the event mechanism (flags 0).
        if unsafe { ngx_handle_read_event(rev, 0) } != NGX_OK as ngx_int_t {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }

        // Timer management (mirror of nginx-acme's PeerConnection).
        // SAFETY: `rev` is the connection's live read event; we read its
        // `active`/`timer_set` bitfields and call the matching nginx timer FFI
        // (`ngx_add_timer`/`ngx_del_timer`) on it.
        unsafe {
            if (*rev).active() != 0 {
                nginx_sys::ngx_add_timer(rev, DEFAULT_READ_TIMEOUT_MS);
            } else if (*rev).timer_set() != 0 {
                nginx_sys::ngx_del_timer(rev);
            }
        }

        if n == NGX_AGAIN as isize {
            // No data yet — store waker; C handler fires wake() on readiness.
            // NO wake_by_ref(): that would busy-spin the NGINX worker thread.
            //
            // The debug line below logs `prev_was_some` because — with multiple
            // task contexts polling the same `NgxConnIo` (e.g., hyper's h2 client
            // spawning a `ConnTask` driver via `NgxExecutor`) — overwriting a
            // previously-stored waker silently loses a wakeup for the other task.
            // The Phase 1.2 Item 1 investigation (`INVESTIGATION_h2_wake_stall.md`)
            // used this exact log to rule out H1 (waker-overwrite race); the
            // actual root cause turned out to be a deadlock during `_conn` drop
            // (h2's `Streams::drop` calls `Waker::wake()` while holding its
            // internal mutex, which ngx-rust's old `schedule()` would resolve
            // by synchronously re-polling — see the corresponding ngx-rust
            // patch on the `ngx-otel-rust-deadlock-fix` branch).
            // SAFETY: `c` is the live nginx connection from this poll; reading
            // its `log` pointer field for the debug log below.
            let log = unsafe { (*c).log };
            let this = self.get_mut();
            let prev_was_some = this.rev.is_some();
            this.rev = Some(cx.waker().clone());
            ngx::ngx_log_debug!(
                log,
                "NgxConnIo::poll_read storing rev waker (prev_was_some={})",
                prev_was_some
            );
            return Poll::Pending;
        }

        if n > 0 {
            // SAFETY: `recv` returned `n > 0` bytes, and it wrote them into the
            // front of the `uninit` region exposed from `buf`; those `n` bytes
            // are now initialised, so advancing the cursor by `n` is sound and
            // `n <= uninit.len()` (recv never returns more than requested).
            unsafe { buf.advance(n as usize) };
        }
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for NgxConnIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.pc.connection.is_null() {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }

        let c = self.pc.connection;
        // SAFETY: `c` is non-null (checked above), a live nginx connection. A
        // connected connection always has `send` installed by the event layer,
        // so `unwrap_unchecked` is sound; `ngx_send_pt` only reads `buf.len()`
        // bytes from the pointer (the `cast_mut` is for the C signature), and
        // `buf` is a valid initialised slice for the duration of the call.
        let n: isize =
            unsafe { ((*c).send.unwrap_unchecked())(c, buf.as_ptr().cast_mut(), buf.len()) };

        if n == NGX_AGAIN as isize {
            // Store waker; C handler fires wake() when fd is write-ready.
            // SAFETY: `c` is the live nginx connection from this poll; reading
            // its `log` pointer field for the debug log below.
            let log = unsafe { (*c).log };
            let this = self.get_mut();
            let prev_was_some = this.wev.is_some();
            this.wev = Some(cx.waker().clone());
            ngx::ngx_log_debug!(
                log,
                "NgxConnIo::poll_write storing wev waker (prev_was_some={})",
                prev_was_some
            );
            return Poll::Pending;
        }

        if n > 0 {
            return Poll::Ready(Ok(n as usize));
        }

        Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.get_mut().close();
        Poll::Ready(Ok(()))
    }
}

impl Drop for NgxConnIo {
    fn drop(&mut self) {
        self.close();
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// C event handlers for NgxConnIo
// (Ported from nginx-acme/src/net/peer_conn.rs)
// ──────────────────────────────────────────────────────────────────────────────

/// NGINX calls this when the connection fd is read-ready.
/// We wake the stored read-waker so the async task is rescheduled.
unsafe extern "C" fn ngx_otel_conn_read_handler(ev: *mut ngx_event_t) {
    // SAFETY: nginx invokes this handler with a valid `ngx_event_t` whose `data`
    // is the owning `ngx_connection_t` (nginx's own convention); the reference
    // does not outlive the call.
    let c: *mut ngx_connection_t = unsafe { (*ev).data.cast() };
    // SAFETY: `c` is the live nginx connection; `connect_peer` stored our
    // pinned `&mut NgxConnIo` in `c.data`, which stays valid until the
    // connection (and thus this `NgxConnIo`) is dropped.
    let this: *mut NgxConnIo = unsafe { (*c).data.cast() };
    // SAFETY: `this` is that valid, pinned `NgxConnIo`; taking the stored read
    // waker is a plain field access on it, single-threaded on the worker.
    let waker_opt = unsafe { (*this).rev.take() };
    let rev_was_some = waker_opt.is_some();
    // SAFETY: `c` is the live connection; reading its `log` pointer field.
    let log = unsafe { (*c).log };
    ngx::ngx_log_debug!(log, "ngx_otel_conn_read_handler: rev_was_some={}", rev_was_some);
    if let Some(waker) = waker_opt {
        waker.wake();
    }
}

/// NGINX calls this when the connection fd is write-ready.
/// We wake the stored write-waker so the async task is rescheduled.
unsafe extern "C" fn ngx_otel_conn_write_handler(ev: *mut ngx_event_t) {
    // SAFETY: nginx invokes this handler with a valid `ngx_event_t` whose `data`
    // is the owning `ngx_connection_t`; the reference does not outlive the call.
    let c: *mut ngx_connection_t = unsafe { (*ev).data.cast() };
    // SAFETY: `c` is the live nginx connection; `connect_peer` stored our pinned
    // `&mut NgxConnIo` in `c.data`, valid until the connection is dropped.
    let this: *mut NgxConnIo = unsafe { (*c).data.cast() };
    // SAFETY: `this` is that valid, pinned `NgxConnIo`; taking the stored write
    // waker is a plain field access, single-threaded on the worker.
    let waker_opt = unsafe { (*this).wev.take() };
    let wev_was_some = waker_opt.is_some();
    // SAFETY: `c` is the live connection; reading its `log` pointer field.
    let log = unsafe { (*c).log };
    ngx::ngx_log_debug!(log, "ngx_otel_conn_write_handler: wev_was_some={}", wev_was_some);
    if let Some(waker) = waker_opt {
        waker.wake();
    } else {
        // No pending write-waker: just re-arm (mirrors nginx-acme).
        // SAFETY: `ev` is the valid write `ngx_event_t` nginx handed us;
        // `ngx_handle_write_event` is the nginx FFI to re-register it (flags 0).
        let _ = unsafe { ngx_handle_write_event(ev, 0) };
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SpinTcpIo / SpinUnixIo / SpinIo — TEST-ONLY adapters
//
// These wrap non-blocking OS streams.  On WouldBlock they call
// cx.waker().wake_by_ref(), which is safe only inside the spin-loop executor
// (tests/support/mod.rs).  In a NGINX worker process this would busy-spin
// the event loop thread — do not use there.
//
// Gated behind `#[cfg(any(test, feature = "test-support"))]` so that
// production builds (`cargo build --release`) cannot accidentally reference
// these types.
// ──────────────────────────────────────────────────────────────────────────────

/// Non-blocking TcpStream adapter.  TEST-ONLY — see module doc.
#[cfg(any(test, feature = "test-support"))]
pub struct SpinTcpIo(TcpStream);

#[cfg(any(test, feature = "test-support"))]
impl SpinTcpIo {
    /// Wrap an already-opened non-blocking `TcpStream`.
    pub fn new(stream: TcpStream) -> Self {
        Self(stream)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl hyper::rt::Read for SpinTcpIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // SAFETY: hyper guarantees `buf`'s uninitialised region is a valid,
        // writable `[MaybeUninit<u8>]` for this call.
        let uninit = unsafe { buf.as_mut() };
        let len = uninit.len();
        if len == 0 {
            return Poll::Ready(Ok(()));
        }
        // SAFETY: `uninit` is a valid writable region of `len` `MaybeUninit<u8>`;
        // reinterpreting it as `&mut [u8]` of the same len/ptr is sound for
        // passing to `Read::read`, which only writes (never reads) the bytes.
        let slice =
            unsafe { core::slice::from_raw_parts_mut(uninit.as_mut_ptr().cast::<u8>(), len) };
        match self.0.read(slice) {
            Ok(n) => {
                // SAFETY: `read` initialised the first `n <= len` bytes of the
                // region, so advancing the cursor by `n` is sound.
                unsafe { buf.advance(n) };
                Poll::Ready(Ok(()))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref(); // safe only in spin-loop executor
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl hyper::rt::Write for SpinTcpIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.0.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.get_mut().0.flush())
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.get_mut().0.shutdown(std::net::Shutdown::Write))
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Unpin for SpinTcpIo {}

/// Non-blocking UnixStream adapter.  TEST-ONLY — see module doc.
#[cfg(any(test, feature = "test-support"))]
pub struct SpinUnixIo(UnixStream);

#[cfg(any(test, feature = "test-support"))]
impl hyper::rt::Read for SpinUnixIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // SAFETY: hyper guarantees `buf`'s uninitialised region is a valid,
        // writable `[MaybeUninit<u8>]` for this call.
        let uninit = unsafe { buf.as_mut() };
        let len = uninit.len();
        if len == 0 {
            return Poll::Ready(Ok(()));
        }
        // SAFETY: `uninit` is a valid writable region of `len` `MaybeUninit<u8>`;
        // reinterpreting it as `&mut [u8]` of the same len/ptr is sound for
        // passing to `Read::read`, which only writes (never reads) the bytes.
        let slice =
            unsafe { core::slice::from_raw_parts_mut(uninit.as_mut_ptr().cast::<u8>(), len) };
        match self.0.read(slice) {
            Ok(n) => {
                // SAFETY: `read` initialised the first `n <= len` bytes of the
                // region, so advancing the cursor by `n` is sound.
                unsafe { buf.advance(n) };
                Poll::Ready(Ok(()))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl hyper::rt::Write for SpinUnixIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.0.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.get_mut().0.flush())
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.get_mut().0.shutdown(std::net::Shutdown::Write))
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Unpin for SpinUnixIo {}

/// Enum combining TCP and Unix spin-wait adapters.  Returned by
/// [`SpinConnector`] so one `connect()` can handle both endpoint types.
#[cfg(any(test, feature = "test-support"))]
pub enum SpinIo {
    Tcp(SpinTcpIo),
    Unix(SpinUnixIo),
}

#[cfg(any(test, feature = "test-support"))]
impl hyper::rt::Read for SpinIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            SpinIo::Tcp(t) => Pin::new(t).poll_read(cx, buf),
            SpinIo::Unix(u) => Pin::new(u).poll_read(cx, buf),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl hyper::rt::Write for SpinIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            SpinIo::Tcp(t) => Pin::new(t).poll_write(cx, buf),
            SpinIo::Unix(u) => Pin::new(u).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            SpinIo::Tcp(t) => Pin::new(t).poll_flush(cx),
            SpinIo::Unix(u) => Pin::new(u).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            SpinIo::Tcp(t) => Pin::new(t).poll_shutdown(cx),
            SpinIo::Unix(u) => Pin::new(u).poll_shutdown(cx),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Unpin for SpinIo {}

// ──────────────────────────────────────────────────────────────────────────────
// Connector trait
// ──────────────────────────────────────────────────────────────────────────────

/// Provides a fresh IO connection to the configured endpoint.
///
/// Tests inject [`SpinConnector`]; Step 9's export loop uses
/// [`NgxConnector`].
#[allow(async_fn_in_trait)]
pub(crate) trait Connector: Send {
    /// The IO type produced by this connector.
    type Io: hyper::rt::Read + hyper::rt::Write + Unpin + 'static;

    /// Open a new connection to `endpoint`.
    async fn connect(&self, endpoint: &ParsedEndpoint) -> Result<Self::Io, TransportError>;
}

// ──────────────────────────────────────────────────────────────────────────────
// SpinConnector — test connector
// ──────────────────────────────────────────────────────────────────────────────

/// Test-only connector.  Opens non-blocking OS streams and returns a
/// [`SpinIo`] wrapper that busy-wakes on `WouldBlock`.
///
/// **Do not use in a NGINX worker process.**
#[cfg(any(test, feature = "test-support"))]
pub struct SpinConnector;

#[cfg(any(test, feature = "test-support"))]
impl Connector for SpinConnector {
    type Io = SpinIo;

    async fn connect(&self, endpoint: &ParsedEndpoint) -> Result<SpinIo, TransportError> {
        match endpoint {
            ParsedEndpoint::Http { host, port, .. } => {
                let addr = std::format!("{}:{}", host, port);
                let stream = TcpStream::connect(&addr)
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_nonblocking(true)
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_read_timeout(Some(SPIN_IO_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_write_timeout(Some(SPIN_IO_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                Ok(SpinIo::Tcp(SpinTcpIo(stream)))
            }
            ParsedEndpoint::Unix { socket_path, .. } => {
                let stream = UnixStream::connect(socket_path)
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_nonblocking(true)
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_read_timeout(Some(SPIN_IO_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_write_timeout(Some(SPIN_IO_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                Ok(SpinIo::Unix(SpinUnixIo(stream)))
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// NgxConnector — production connector
// ──────────────────────────────────────────────────────────────────────────────

/// Production connector.  Uses `ngx_event_connect_peer` to open a TCP
/// connection via NGINX's event machinery.  Requires a running NGINX event loop.
///
/// Supports:
/// - Literal IPv4 and IPv6 addresses (Item 2).
/// - DNS-name endpoints via nginx's async resolver (Item 3).  The resolver
///   pointer is stored at config-parse time (Item 1) and driven by the
///   exporter's nginx event loop.  Addresses are tried sequentially.
pub struct NgxConnector {
    log: core::ptr::NonNull<ngx_log_t>,
    /// Nginx resolver from `MainConfig::resolver`, wired at config-parse time.
    /// `None` for literal-IP and unix: endpoints (no resolver needed).
    resolver: Option<core::ptr::NonNull<nginx_sys::ngx_resolver_t>>,
    /// Resolver timeout in milliseconds (from `clcf->resolver_timeout`).
    resolver_timeout: nginx_sys::ngx_msec_t,
}

impl NgxConnector {
    /// Create a connector without a resolver (literal-IP or unix: endpoints).
    pub fn new(log: core::ptr::NonNull<ngx_log_t>) -> Self {
        Self { log, resolver: None, resolver_timeout: 0 }
    }

    /// Create a connector with an nginx resolver for DNS-name endpoints.
    ///
    /// `resolver` is `NonNull<ngx_resolver_t>` stored at postconfiguration time
    /// (see `MainConfig::resolver`).  `timeout` is milliseconds.
    pub fn with_resolver(
        log: core::ptr::NonNull<ngx_log_t>,
        resolver: Option<core::ptr::NonNull<nginx_sys::ngx_resolver_t>>,
        timeout: nginx_sys::ngx_msec_t,
    ) -> Self {
        Self { log, resolver, resolver_timeout: timeout }
    }
}

// SAFETY: Only used from a single NGINX worker thread.
unsafe impl Send for NgxConnector {}

impl Connector for NgxConnector {
    type Io = Pin<Box<NgxConnIo>>;

    async fn connect(
        &self,
        endpoint: &ParsedEndpoint,
    ) -> Result<Pin<Box<NgxConnIo>>, TransportError> {
        match endpoint {
            ParsedEndpoint::Http { host, port, .. } => {
                let mut io = Box::pin(NgxConnIo::new(self.log)?);

                // Strip IPv6 bracket notation ("[::1]" → "::1") before parsing.
                // `ParsedEndpoint::parse` stores the bracket form for IPv6 URLs
                // such as `http://[::1]:4317/`, so we must strip here.
                // Uses the shared `strip_v6_brackets` helper so the sync path
                // (sync_http.rs) can't drift from this logic.
                let host_str = strip_v6_brackets(host.as_str());

                // Branch on address family.  DNS names fall through to the
                // error arm below; resolution is wired in Item 3 (transport_dns).
                let (sockaddr_ptr, socklen) = match host_str.parse::<std::net::IpAddr>() {
                    Ok(std::net::IpAddr::V4(v4)) => (
                        build_ipv4_sockaddr(&io.pool, v4, *port)?,
                        core::mem::size_of::<libc::sockaddr_in>() as nginx_sys::socklen_t,
                    ),
                    Ok(std::net::IpAddr::V6(v6)) => (
                        // ⚠️ socklen MUST match the family — sockaddr_in6 (28)
                        // ≠ sockaddr_in (16); mismatch corrupts the connect.
                        build_ipv6_sockaddr(&io.pool, v6, *port)?,
                        core::mem::size_of::<libc::sockaddr_in6>() as nginx_sys::socklen_t,
                    ),
                    Err(_) => {
                        // DNS name — resolve using the nginx async resolver.
                        return self.connect_dns(host, host_str, *port).await;
                    }
                };

                // Build and install pc.name.  REQUIRED under `--with-debug`:
                // `ngx_event_connect_peer` logs `"connect to %V, fd:%d #%uA"`
                // via `ngx_log_debug3` (ngx_event_connect.c:206) which
                // dereferences `pc->name` as `ngx_str_t *`.  With NGX_DEBUG
                // undefined the macro expands to nothing (ngx_log.h:221) so
                // a NULL `pc.name` is harmless; with `--with-debug` it
                // expands to an active log call (`ngx_log.h:185-187`) and the
                // NULL deref crashes the worker.  See nginx-acme's
                // `PeerConnection::connect` for the precedent.
                let name_ptr = build_pc_name(&io.pool, host, *port)?;
                {
                    let this = io.as_mut().get_mut();
                    this.pc.sockaddr = sockaddr_ptr;
                    this.pc.socklen = socklen;
                    this.pc.name = name_ptr;
                }

                future::poll_fn(|cx| io.as_mut().poll_connect(cx))
                    .await
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;

                Ok(io)
            }
            ParsedEndpoint::Unix { .. } => Err(TransportError::Connection {
                cause: std::string::String::from(
                    "Unix sockets not supported for NgxConnIo in Phase 1.1",
                ),
            }),
        }
    }
}

impl NgxConnector {
    /// Resolve `host` via the nginx async resolver and connect to the first
    /// reachable address.
    ///
    /// Addresses are tried **sequentially** (no happy-eyeballs).  Returns on
    /// the first successful connect, or the last error if all addresses fail.
    ///
    /// # Lifecycle note
    /// The `resolve_pool` holding the resolved `ngx_addr_t` list lives for the
    /// duration of this function.  After a successful connect the sockaddr
    /// pointer has already been consumed by `ngx_event_connect_peer` (the
    /// kernel copies the address at `connect(2)` time), so dropping the pool
    /// on return is safe.
    ///
    /// # STOP-AND-ASK if:
    /// - The resolver returns a UAF/panic (would surface as a crash here).
    /// - `ngx_inet_set_port` corrupts the address on a non-v4/v6 family.
    ///
    /// These are the resolver-lifetime / UAF concerns from the loop doc.
    async fn connect_dns(
        &self,
        host: &str,     // original host string (may have brackets for v6)
        host_str: &str, // bracket-stripped host string
        port: u16,
    ) -> Result<Pin<Box<NgxConnIo>>, TransportError> {
        use ngx::async_::resolver::Resolver;

        let resolver_nn = self.resolver.ok_or_else(|| TransportError::Connection {
            cause: std::format!(
                "DNS endpoint '{}' requires nginx's resolver directive; \
                 add 'resolver <nameserver>;' to the http block",
                host_str
            ),
        })?;

        let resolver = Resolver::from_resolver(resolver_nn, self.resolver_timeout);

        // Build a scratch pool for the resolved address list.  Dropped after
        // all connect attempts; the sockaddr data is only needed until
        // ngx_event_connect_peer returns.
        let resolve_pool = OwnedNgxPool::new(NGX_DEFAULT_POOL_SIZE as usize, self.log)?;

        // Build ngx_str_t from the host string.  The data pointer is borrowed
        // for the duration of the resolve_name call only; the ngx_resolver_ctx_t
        // copies it before the first await point returns.
        //
        // Safety: cast *const u8 → *mut u8 — nginx reads the name bytes but
        // never writes to them.
        let host_ngx_str =
            nginx_sys::ngx_str_t { len: host_str.len(), data: host_str.as_ptr() as *mut u8 };

        let addrs = resolver.resolve_name(&host_ngx_str, &resolve_pool).await.map_err(|e| {
            TransportError::Connection { cause: std::format!("DNS resolve '{}': {}", host_str, e) }
        })?;

        if addrs.is_empty() {
            return Err(TransportError::Connection {
                cause: std::format!("DNS resolve '{}': no addresses returned", host_str),
            });
        }

        // Try addresses in order; return on first successful connect.
        // Each attempt uses a fresh NgxConnIo (failed connects close the fd).
        let mut last_err = std::string::String::from("no addresses");
        for addr in addrs.iter() {
            // Set the destination port on the resolved sockaddr.
            // ngx_inet_set_port takes port in HOST byte order and calls htons()
            // internally (nginx/src/core/ngx_inet.c:1436).
            // SAFETY: `addr` is one of the `ngx_addr_t`s the resolver wrote into
            // `resolve_pool`, so `addr.sockaddr` is a valid, live sockaddr (v4 or
            // v6 family, as the resolver set) for the pool's lifetime;
            // `ngx_inet_set_port` is the nginx FFI that sets the port field for
            // whichever family that sockaddr carries.
            unsafe {
                nginx_sys::ngx_inet_set_port(addr.sockaddr, port as nginx_sys::in_port_t);
            }

            let mut io = Box::pin(NgxConnIo::new(self.log)?);
            // Build pc.name before the mutable borrow of io (borrow-split).
            let name_ptr = build_pc_name(&io.pool, host, port)?;
            {
                let this = io.as_mut().get_mut();
                // Install the ready sockaddr/socklen from the resolved addr.
                // The plan: "each ngx_addr_t already carries a ready
                // sockaddr + socklen + family — install it directly into pc"
                // (TRANSPORT_DNS_DUALSTACK_PLAN.md Step 3).
                this.pc.sockaddr = addr.sockaddr;
                this.pc.socklen = addr.socklen;
                // pc.name for debug logging under --with-debug.
                this.pc.name = name_ptr;
            }

            match future::poll_fn(|cx| io.as_mut().poll_connect(cx)).await {
                Ok(()) => return Ok(io),
                Err(e) => {
                    last_err = e.to_string();
                    // io is dropped here, closing the failed connection fd.
                }
            }
        }

        Err(TransportError::Connection { cause: last_err })
    }
}

/// Allocate an `ngx_str_t` ("host:port") in `pool` for `pc.name`.
///
/// Required by `ngx_event_connect_peer`, which logs the peer name via
/// `ngx_log_debug3(...,"connect to %V, fd:%d #%uA", pc->name, ...)`
/// (`nginx/src/event/ngx_event_connect.c:206`).  The `%V` formatter
/// dereferences `pc->name` as `ngx_str_t *`.  Under release nginx the
/// `ngx_log_debug3` macro expands to nothing (`ngx_log.h:221`) so a NULL
/// `pc.name` is harmless; under `--with-debug` (NGX_DEBUG=1) the macro
/// expands to an active log call (`ngx_log.h:185-187`) and the NULL
/// dereference crashes the worker on every connect attempt.
///
/// Symptom before this fix: workers SIGSEGV at every `otel_metric_interval`
/// tick under debug builds, immediately after the `"stream socket %d"`
/// debug line in `ngx_event_connect.c:43` and before the `"connect to %V"`
/// line in `ngx_event_connect.c:206` ever appears.
///
/// Both the byte buffer and the `ngx_str_t` struct are allocated in the
/// connection's pool, so they live exactly as long as the `NgxConnIo` that
/// owns them.  `Drop for OwnedNgxPool` calls `ngx_destroy_pool` — no leak.
///
/// Mirrors the precedent in `nginx-acme/src/net/peer_conn.rs:170-180`.
fn build_pc_name(
    pool: &Pool,
    host: &str,
    port: u16,
) -> Result<*mut nginx_sys::ngx_str_t, TransportError> {
    let s = std::format!("{}:{}", host, port);
    let bytes = s.as_bytes();
    let len = bytes.len();

    // SAFETY: `pool` is a valid, live `ngx_pool_t` (borrowed from the caller's
    // `NgxConnIo`); `ngx_palloc` returns `len` bytes from it. Null-checked below.
    let data_ptr = unsafe { ngx_palloc(pool.as_ptr(), len) } as *mut u8;
    if data_ptr.is_null() {
        return Err(TransportError::Connection {
            cause: std::string::String::from("pool alloc for pc.name data failed"),
        });
    }
    // SAFETY: `data_ptr` points to a fresh, non-null `len`-byte pool allocation;
    // `bytes` is a `len`-byte source slice. The two regions don't overlap (one is
    // the format-string buffer, the other a fresh pool block), so the copy of
    // exactly `len` bytes stays in-bounds of both.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), data_ptr, len) };

    // SAFETY: same valid pool; `ngx_palloc` returns space for one `ngx_str_t`.
    // Null-checked below.
    let name_ptr =
        unsafe { ngx_palloc(pool.as_ptr(), core::mem::size_of::<nginx_sys::ngx_str_t>()) }
            as *mut nginx_sys::ngx_str_t;
    if name_ptr.is_null() {
        return Err(TransportError::Connection {
            cause: std::string::String::from("pool alloc for pc.name struct failed"),
        });
    }
    // SAFETY: `name_ptr` is a fresh, non-null, suitably-sized/aligned pool
    // allocation for an `ngx_str_t`; writing its `len`/`data` fields initialises
    // it. `data_ptr` (its new `data`) lives in the same pool, so the two share a
    // lifetime.
    unsafe {
        (*name_ptr).len = len;
        (*name_ptr).data = data_ptr;
    }
    Ok(name_ptr)
}

/// Allocate a `sockaddr_in` in `pool` for the given IPv4 address and port.
///
/// The returned pointer is stable for the pool's lifetime.  The socklen
/// for this address family is `size_of::<sockaddr_in>()` = 16; the caller
/// is responsible for setting `pc.socklen` to this value.
///
/// Uses `from_ne_bytes` (not `from_be_bytes`) on `v4.octets()`:
/// `octets()` returns bytes in network (big-endian) order; reinterpreting
/// them as native-endian preserves the wire layout so the kernel sees the
/// correct address regardless of host byte order.
fn build_ipv4_sockaddr(
    pool: &Pool,
    v4: std::net::Ipv4Addr,
    port: u16,
) -> Result<*mut nginx_sys::sockaddr, TransportError> {
    let size = core::mem::size_of::<libc::sockaddr_in>();
    // SAFETY: `pool` is a valid, live `ngx_pool_t`; `ngx_palloc` returns
    // `size_of::<sockaddr_in>()` bytes from it, enough for one `sockaddr_in`.
    // Pool allocations are pointer-aligned, satisfying the struct's alignment.
    // Null-checked below.
    let ptr = unsafe { ngx_palloc(pool.as_ptr(), size) } as *mut libc::sockaddr_in;

    if ptr.is_null() {
        return Err(TransportError::Connection {
            cause: std::string::String::from("pool alloc for sockaddr_in failed"),
        });
    }

    // SAFETY: `ptr` is a fresh, non-null, correctly-sized/aligned allocation for
    // one `sockaddr_in`. `write_bytes(_, 0, 1)` zero-initialises it (a valid
    // all-zero POD state), then `&mut *ptr` is the only reference to it while we
    // set the family/port/addr fields.
    unsafe {
        core::ptr::write_bytes(ptr, 0u8, 1);
        let sa = &mut *ptr;
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = port.to_be();
        sa.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
    }

    Ok(ptr.cast::<nginx_sys::sockaddr>())
}

/// Allocate a `sockaddr_in6` in `pool` for the given IPv6 address and port.
///
/// The returned pointer is stable for the pool's lifetime.  The socklen
/// for this address family is `size_of::<sockaddr_in6>()` = 28; the caller
/// **must** set `pc.socklen` to this value — a mismatch with the family
/// corrupts the connect call.
///
/// `sin6_flowinfo` and `sin6_scope_id` are zeroed (collector endpoints are
/// global addresses; link-local scope-id handling is out of scope).
///
/// Precedent: `nginx-acme/src/net/peer_conn.rs:547` (`AF_INET6` branch).
fn build_ipv6_sockaddr(
    pool: &Pool,
    v6: std::net::Ipv6Addr,
    port: u16,
) -> Result<*mut nginx_sys::sockaddr, TransportError> {
    let size = core::mem::size_of::<libc::sockaddr_in6>();
    // SAFETY: `pool` is a valid, live `ngx_pool_t`; `ngx_palloc` returns
    // `size_of::<sockaddr_in6>()` bytes from it, enough for one `sockaddr_in6`.
    // Pool allocations are pointer-aligned, satisfying the struct's alignment.
    // Null-checked below.
    let ptr = unsafe { ngx_palloc(pool.as_ptr(), size) } as *mut libc::sockaddr_in6;

    if ptr.is_null() {
        return Err(TransportError::Connection {
            cause: std::string::String::from("pool alloc for sockaddr_in6 failed"),
        });
    }

    // SAFETY: `ptr` is a fresh, non-null, correctly-sized/aligned allocation for
    // one `sockaddr_in6`. `write_bytes(_, 0, 1)` zero-initialises it (valid
    // all-zero POD, also zeroing `sin6_flowinfo`/`sin6_scope_id`), then `&mut
    // *ptr` is the only reference while we set family/port/addr.
    unsafe {
        core::ptr::write_bytes(ptr, 0u8, 1);
        let sa = &mut *ptr;
        sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sa.sin6_port = port.to_be();
        // sin6_flowinfo = 0 (already zeroed above).
        // sin6_addr.s6_addr is a [u8; 16] in network byte order — octets()
        // already returns bytes in network order, so no byte-order conversion.
        sa.sin6_addr.s6_addr = v6.octets();
        // sin6_scope_id = 0 (global; link-local scope-id out of scope).
    }

    Ok(ptr.cast::<nginx_sys::sockaddr>())
}

// ──────────────────────────────────────────────────────────────────────────────
// HyperHttpTransport<C> — generic transport
// ──────────────────────────────────────────────────────────────────────────────

/// HTTP/1.1 OTLP transport, generic over the IO connector.
///
/// - Tests: `HyperHttpTransport<SpinConnector>` via [`HyperHttpTransport::new`].
/// - Step 9: `HyperHttpTransport<NgxConnector>` via
///   [`HyperHttpTransport::with_ngx_log`].
pub struct HyperHttpTransport<C> {
    endpoint: ParsedEndpoint,
    headers: std::vec::Vec<(std::string::String, std::string::String)>,
    connector: C,
}

// Manual Debug so we don't require C: Debug on the struct itself.
impl<C: core::fmt::Debug> core::fmt::Debug for HyperHttpTransport<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HyperHttpTransport")
            .field("endpoint", &self.endpoint)
            .field("connector", &self.connector)
            .finish()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl core::fmt::Debug for SpinConnector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SpinConnector")
    }
}

impl core::fmt::Debug for NgxConnector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NgxConnector").finish_non_exhaustive()
    }
}

#[allow(private_bounds)] // Connector is pub(crate); with_connector is only called within this crate.
impl<C: Connector> HyperHttpTransport<C> {
    /// Generic constructor — used by the type-specific constructors below.
    pub fn with_connector(
        endpoint_str: &str,
        headers: std::vec::Vec<(std::string::String, std::string::String)>,
        connector: C,
    ) -> Result<Self, TransportError> {
        let endpoint = ParsedEndpoint::parse(endpoint_str)?;
        Ok(Self { endpoint, headers, connector })
    }
}

/// Test constructor — uses [`SpinConnector`].
///
/// **Do not call from a NGINX worker process.**
#[cfg(any(test, feature = "test-support"))]
impl HyperHttpTransport<SpinConnector> {
    pub fn new(
        endpoint_str: &str,
        headers: std::vec::Vec<(std::string::String, std::string::String)>,
    ) -> Result<Self, TransportError> {
        Self::with_connector(endpoint_str, headers, SpinConnector)
    }
}

/// Production constructor — uses [`NgxConnector`] with proper event
/// integration.  Requires a running NGINX event loop (exporter process).
impl HyperHttpTransport<NgxConnector> {
    pub fn with_ngx_log(
        endpoint_str: &str,
        headers: std::vec::Vec<(std::string::String, std::string::String)>,
        log: core::ptr::NonNull<ngx_log_t>,
        resolver: Option<core::ptr::NonNull<nginx_sys::ngx_resolver_t>>,
        resolver_timeout: nginx_sys::ngx_msec_t,
    ) -> Result<Self, TransportError> {
        Self::with_connector(
            endpoint_str,
            headers,
            NgxConnector::with_resolver(log, resolver, resolver_timeout),
        )
    }
}

#[allow(private_bounds)]
impl<C: Connector> HyperHttpTransport<C> {
    /// Send a batch of OTLP/HTTP protobuf metrics to the configured endpoint.
    ///
    /// Maintains no cached connection across calls; a failure leaves nothing to
    /// clean up so the next call simply reconnects.
    pub async fn send(&mut self, bytes: std::vec::Vec<u8>) -> Result<(), TransportError> {
        let io = self.connector.connect(&self.endpoint).await?;
        let authority = self.endpoint.authority();
        let http_path = std::string::String::from(self.endpoint.http_path());
        http_post(io, &authority, &http_path, &self.headers, bytes).await
    }

    /// POST `bytes` to an explicit `path`, overriding the endpoint's default path.
    ///
    /// Used by the export loop to send logs to `/v1/logs` on the same host as
    /// the metrics endpoint (which uses `/v1/metrics`).  Everything else (host,
    /// port, TLS, headers) comes from the existing configured endpoint.
    ///
    /// Kept separate from `send` so the logs path can target its own endpoint
    /// path without disturbing the metrics call.
    pub async fn send_to_path(
        &mut self,
        path: &str,
        bytes: std::vec::Vec<u8>,
    ) -> Result<(), TransportError> {
        let io = self.connector.connect(&self.endpoint).await?;
        let authority = self.endpoint.authority();
        http_post(io, &authority, path, &self.headers, bytes).await
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Core HTTP/1.1 POST via hyper
// ──────────────────────────────────────────────────────────────────────────────

/// POST `body` to `http_path` via hyper's HTTP/1.1 client.
///
/// The IO driver (`conn`) and the response future are co-driven in a single
/// `poll_fn` so both share the same waker context.  With `NgxConnIo`:
/// - `conn.poll()` internally calls `NgxConnIo::poll_read` / `poll_write`,
///   which store the waker and return `Pending` on `NGX_AGAIN`.
/// - The C event handler wakes the task; the `poll_fn` is re-polled; progress
///   is made — no busy-spin, no blocking.
async fn http_post<IO>(
    io: IO,
    authority: &str,
    http_path: &str,
    extra_headers: &[(std::string::String, std::string::String)],
    body: std::vec::Vec<u8>,
) -> Result<(), TransportError>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
{
    let body_len = body.len();
    let full_body = Full::new(Bytes::from(body));

    let mut builder = Request::builder().method("POST").uri(http_path);
    {
        let hdrs = builder.headers_mut().ok_or_else(|| TransportError::Connection {
            cause: std::string::String::from("request builder already consumed"),
        })?;
        hdrs.insert(
            hyper::header::HOST,
            authority.parse().map_err(|_| TransportError::Connection {
                cause: std::format!("invalid Host value: {}", authority),
            })?,
        );
        hdrs.insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/x-protobuf"),
        );
        hdrs.insert(hyper::header::CONTENT_LENGTH, hyper::header::HeaderValue::from(body_len));
        hdrs.insert(hyper::header::CONNECTION, hyper::header::HeaderValue::from_static("close"));
        for (k, v) in extra_headers {
            if let (Ok(name), Ok(val)) =
                (k.parse::<hyper::header::HeaderName>(), v.parse::<hyper::header::HeaderValue>())
            {
                hdrs.insert(name, val);
            }
        }
    }
    let req =
        builder.body(full_body).map_err(|e| TransportError::Connection { cause: e.to_string() })?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake::<IO, Full<Bytes>>(io)
        .await
        .map_err(|e| TransportError::Connection { cause: e.to_string() })?;

    let resp_fut = sender.send_request(req);

    let mut conn = core::pin::pin!(conn);
    let mut resp_fut = core::pin::pin!(resp_fut);

    let resp = future::poll_fn(|cx| {
        // Drive the connection task alongside the response future.  If the
        // connection terminates with an error (TLS reset, peer RST, EOF) surface
        // it instead of leaving resp_fut Pending until the read timeout fires.
        if let Poll::Ready(Err(e)) = conn.as_mut().poll(cx) {
            return Poll::Ready(Err(e));
        }
        resp_fut.as_mut().poll(cx)
    })
    .await
    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;

    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(TransportError::HttpStatus {
            code: status.as_u16(),
            message: std::string::String::from(status.canonical_reason().unwrap_or("unknown")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Item 2: IPv6 sockaddr + dual-stack literal branch ─────────────────────

    /// socklen_t values for the two address families must match the plan spec
    /// (sockaddr_in = 16, sockaddr_in6 = 28) and must agree with libc's sizes.
    /// A mismatch here would corrupt ngx_event_connect_peer's socklen check.
    #[test]
    fn socklen_sizes_match_expected_values() {
        assert_eq!(
            core::mem::size_of::<libc::sockaddr_in>(),
            16,
            "sockaddr_in must be 16 bytes (IPv4 socklen)"
        );
        assert_eq!(
            core::mem::size_of::<libc::sockaddr_in6>(),
            28,
            "sockaddr_in6 must be 28 bytes (IPv6 socklen)"
        );
    }

    /// An IPv4 sockaddr built from known octets must have the correct family,
    /// port in network byte order, and address bytes in network byte order.
    ///
    /// This mirrors what `build_ipv4_sockaddr` does; we verify the struct layout
    /// directly (without a pool, which is stubbed to null in unit-test mode).
    #[test]
    fn ipv4_sockaddr_layout_correct() {
        let v4: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
        let port: u16 = 4317;

        // Reproduce the layout build_ipv4_sockaddr would produce.
        // SAFETY: `sockaddr_in` is a POD struct of integers; an all-zero bit
        // pattern is a valid, fully-initialised value to start from.
        let mut sa: libc::sockaddr_in = unsafe { core::mem::zeroed() };
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = port.to_be();
        sa.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());

        assert_eq!(sa.sin_family as libc::c_int, libc::AF_INET, "family must be AF_INET");
        assert_eq!(sa.sin_port, port.to_be(), "port must be in network byte order");
        // Address bytes in network order: 127.0.0.1 → [127, 0, 0, 1].
        // from_ne_bytes on [127,0,0,1] gives 0x0100007f on little-endian;
        // the kernel reads it byte-by-byte → 127.0.0.1. Verify the s_addr
        // bytes round-trip through to_ne_bytes back to octets.
        assert_eq!(sa.sin_addr.s_addr.to_ne_bytes(), v4.octets());
    }

    /// An IPv6 sockaddr built from known octets must have the correct family,
    /// port in network byte order, address bytes in network byte order,
    /// and zeroed flowinfo / scope_id.
    ///
    /// This mirrors what `build_ipv6_sockaddr` does.
    #[test]
    fn ipv6_sockaddr_layout_correct() {
        let v6: std::net::Ipv6Addr = "::1".parse().unwrap();
        let port: u16 = 4317;

        // SAFETY: `sockaddr_in6` is a POD struct of integers; an all-zero bit
        // pattern is a valid, fully-initialised value to start from.
        let mut sa: libc::sockaddr_in6 = unsafe { core::mem::zeroed() };
        sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sa.sin6_port = port.to_be();
        sa.sin6_addr.s6_addr = v6.octets();
        // sin6_flowinfo and sin6_scope_id remain 0 (zeroed above).

        assert_eq!(sa.sin6_family as libc::c_int, libc::AF_INET6, "family must be AF_INET6");
        assert_eq!(sa.sin6_port, port.to_be(), "port must be in network byte order");
        // ::1 → all-zero except last byte = 1.
        let expected: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(sa.sin6_addr.s6_addr, expected, "IPv6 address bytes must be in network order");
        assert_eq!(sa.sin6_flowinfo, 0, "flowinfo must be 0");
        assert_eq!(sa.sin6_scope_id, 0, "scope_id must be 0 (global addresses)");
    }

    /// `ParsedEndpoint::parse` with a bracketed IPv6 URL stores the host with
    /// brackets.  `NgxConnector::connect` strips them before parsing as IpAddr.
    #[test]
    fn parsed_endpoint_ipv6_bracket_form_preserved() {
        let ep = ParsedEndpoint::parse("http://[::1]:4317/v1/metrics").unwrap();
        match ep {
            ParsedEndpoint::Http { host, port, .. } => {
                assert_eq!(host, "[::1]", "host must retain brackets from URL");
                assert_eq!(port, 4317, "port must be parsed correctly");
                // Simulate the bracket-stripping in NgxConnector::connect.
                let host_str = if host.starts_with('[') && host.ends_with(']') {
                    host[1..host.len() - 1].to_string()
                } else {
                    host.clone()
                };
                let ip: std::net::IpAddr = host_str.parse().unwrap();
                assert!(ip.is_ipv6(), "stripped host must parse as IPv6");
            }
            _ => panic!("expected Http endpoint"),
        }
    }

    /// A literal IPv6 endpoint's socklen must be 28 (sockaddr_in6).
    /// A literal IPv4 endpoint's socklen must be 16 (sockaddr_in).
    /// These are the values NgxConnector::connect must install into pc.socklen.
    #[test]
    fn socklen_is_family_matched() {
        // IPv4 → 16
        let v4_socklen = core::mem::size_of::<libc::sockaddr_in>() as nginx_sys::socklen_t;
        assert_eq!(v4_socklen, 16, "IPv4 pc.socklen must be 16");

        // IPv6 → 28
        let v6_socklen = core::mem::size_of::<libc::sockaddr_in6>() as nginx_sys::socklen_t;
        assert_eq!(v6_socklen, 28, "IPv6 pc.socklen must be 28");

        // Confirm they differ (the key invariant — mismatch corrupts connect).
        assert_ne!(v4_socklen, v6_socklen, "IPv4 and IPv6 socklens must differ");
    }

    // ── strip_v6_brackets shared helper ──────────────────────────────────────

    /// `strip_v6_brackets` removes surrounding `[` `]` from an IPv6 host string
    /// and leaves non-bracketed strings unchanged.
    #[test]
    fn strip_v6_brackets_removes_brackets_from_ipv6_literal() {
        assert_eq!(strip_v6_brackets("[::1]"), "::1");
        assert_eq!(strip_v6_brackets("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(strip_v6_brackets("[::ffff:127.0.0.1]"), "::ffff:127.0.0.1");
    }

    /// `strip_v6_brackets` is a no-op for IPv4 literals and DNS names.
    #[test]
    fn strip_v6_brackets_is_noop_for_non_bracketed_hosts() {
        assert_eq!(strip_v6_brackets("127.0.0.1"), "127.0.0.1");
        assert_eq!(strip_v6_brackets("otel-collector.example.com"), "otel-collector.example.com");
        assert_eq!(strip_v6_brackets("::1"), "::1"); // already unbracketed
    }
}
