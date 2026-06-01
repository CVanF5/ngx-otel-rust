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
use crate::transport::Transport;

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

// ──────────────────────────────────────────────────────────────────────────────
// OwnedNgxPool — owning wrapper for ngx_pool_t
// (Ported from nginx-acme/src/util.rs `OwnedPool`)
// ──────────────────────────────────────────────────────────────────────────────

/// Owning wrapper for an nginx memory pool.  Calls `ngx_destroy_pool` on drop.
struct OwnedNgxPool(Pool);

impl OwnedNgxPool {
    fn new(size: usize, log: core::ptr::NonNull<ngx_log_t>) -> Result<Self, TransportError> {
        let pool = unsafe { ngx_create_pool(size, log.as_ptr()) };
        if pool.is_null() {
            return Err(TransportError::Connection {
                cause: std::string::String::from("ngx_create_pool failed"),
            });
        }
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
        let rc = unsafe { ngx_event_connect_peer(&mut this.pc) };

        // NGX_ERROR = -1, NGX_BUSY = -3, NGX_DECLINED = -4
        if rc == NGX_ERROR as ngx_int_t || rc == -3 || rc == -4 {
            return rc;
        }

        // rc is NGX_OK (0) or NGX_AGAIN (-2): connection is allocated.
        let c: *mut ngx_connection_t = this.pc.connection;
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
                    unsafe {
                        nginx_sys::ngx_add_timer((*this.pc.connection).read, DEFAULT_READ_TIMEOUT_MS);
                    }
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
        let rev: *mut ngx_event_t = unsafe { (*c).read };

        if unsafe { (*rev).timedout() } != 0 {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }

        // Call the NGINX recv function pointer (fills MaybeUninit bytes).
        let uninit: &mut [MaybeUninit<u8>] = unsafe { buf.as_mut() };
        let n: isize = unsafe {
            ((*c).recv.unwrap_unchecked())(c, uninit.as_mut_ptr().cast::<u8>(), uninit.len())
        };

        if n == NGX_ERROR as isize {
            return Poll::Ready(Err(io::Error::last_os_error()));
        }

        // Re-arm the read event so epoll/kqueue monitors the fd again.
        if unsafe { ngx_handle_read_event(rev, 0) } != NGX_OK as ngx_int_t {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }

        // Timer management (mirror of nginx-acme's PeerConnection).
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
        let n: isize =
            unsafe { ((*c).send.unwrap_unchecked())(c, buf.as_ptr().cast_mut(), buf.len()) };

        if n == NGX_AGAIN as isize {
            // Store waker; C handler fires wake() when fd is write-ready.
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
    let c: *mut ngx_connection_t = unsafe { (*ev).data.cast() };
    let this: *mut NgxConnIo = unsafe { (*c).data.cast() };
    let waker_opt = unsafe { (*this).rev.take() };
    let rev_was_some = waker_opt.is_some();
    let log = unsafe { (*c).log };
    ngx::ngx_log_debug!(log, "ngx_otel_conn_read_handler: rev_was_some={}", rev_was_some);
    if let Some(waker) = waker_opt {
        waker.wake();
    }
}

/// NGINX calls this when the connection fd is write-ready.
/// We wake the stored write-waker so the async task is rescheduled.
unsafe extern "C" fn ngx_otel_conn_write_handler(ev: *mut ngx_event_t) {
    let c: *mut ngx_connection_t = unsafe { (*ev).data.cast() };
    let this: *mut NgxConnIo = unsafe { (*c).data.cast() };
    let waker_opt = unsafe { (*this).wev.take() };
    let wev_was_some = waker_opt.is_some();
    let log = unsafe { (*c).log };
    ngx::ngx_log_debug!(log, "ngx_otel_conn_write_handler: wev_was_some={}", wev_was_some);
    if let Some(waker) = waker_opt {
        waker.wake();
    } else {
        // No pending write-waker: just re-arm (mirrors nginx-acme).
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
        let uninit = unsafe { buf.as_mut() };
        let len = uninit.len();
        if len == 0 {
            return Poll::Ready(Ok(()));
        }
        let slice =
            unsafe { core::slice::from_raw_parts_mut(uninit.as_mut_ptr().cast::<u8>(), len) };
        match self.0.read(slice) {
            Ok(n) => {
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
        let uninit = unsafe { buf.as_mut() };
        let len = uninit.len();
        if len == 0 {
            return Poll::Ready(Ok(()));
        }
        let slice =
            unsafe { core::slice::from_raw_parts_mut(uninit.as_mut_ptr().cast::<u8>(), len) };
        match self.0.read(slice) {
            Ok(n) => {
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
/// connection via NGINX's event machinery.  Requires a running NGINX worker.
///
/// Phase 1.1 limitations:
/// - Only IPv4 addresses (not hostnames).  DNS via `ngx::async_::resolver`
///   is Phase 1.2.
/// - Only TCP; Unix socket support for `NgxConnIo` is Phase 1.2.
pub struct NgxConnector {
    log: core::ptr::NonNull<ngx_log_t>,
}

impl NgxConnector {
    /// Create a connector with the given NGINX log handle.
    pub fn new(log: core::ptr::NonNull<ngx_log_t>) -> Self {
        Self { log }
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

                // Build and install the sockaddr into pc before connecting.
                let sockaddr_ptr = build_ipv4_sockaddr(&io.pool, host, *port)?;

                // Build and install pc.name.  REQUIRED under `--with-debug`:
                // `ngx_event_connect_peer` logs `"connect to %V, fd:%d #%uA"`
                // via `ngx_log_debug3` (ngx_event_connect.c:206) which
                // dereferences `pc->name` as `ngx_str_t *`.  With NGX_DEBUG
                // undefined the macro expands to nothing (ngx_log.h:221) so
                // a NULL `pc.name` is harmless; with `--with-debug` it
                // expands to an active call (ngx_log.h:185-187) and the NULL
                // deref crashes the worker.  See nginx-acme's
                // `PeerConnection::connect` for the precedent.
                let name_ptr = build_pc_name(&io.pool, host, *port)?;
                {
                    let this = io.as_mut().get_mut();
                    this.pc.sockaddr = sockaddr_ptr;
                    this.pc.socklen =
                        core::mem::size_of::<libc::sockaddr_in>() as nginx_sys::socklen_t;
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

    let data_ptr = unsafe { ngx_palloc(pool.as_ptr(), len) } as *mut u8;
    if data_ptr.is_null() {
        return Err(TransportError::Connection {
            cause: std::string::String::from("pool alloc for pc.name data failed"),
        });
    }
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), data_ptr, len) };

    let name_ptr =
        unsafe { ngx_palloc(pool.as_ptr(), core::mem::size_of::<nginx_sys::ngx_str_t>()) }
            as *mut nginx_sys::ngx_str_t;
    if name_ptr.is_null() {
        return Err(TransportError::Connection {
            cause: std::string::String::from("pool alloc for pc.name struct failed"),
        });
    }
    unsafe {
        (*name_ptr).len = len;
        (*name_ptr).data = data_ptr;
    }
    Ok(name_ptr)
}

/// Allocate a `sockaddr_in` in `pool` for the given host:port.
/// Returns a stable pointer valid for the pool's lifetime.
fn build_ipv4_sockaddr(
    pool: &Pool,
    host: &str,
    port: u16,
) -> Result<*mut nginx_sys::sockaddr, TransportError> {
    use std::net::IpAddr;

    let ip: IpAddr = host.parse().map_err(|_| TransportError::InvalidEndpoint {
        input: std::string::String::from(host),
        reason: "only IPv4 addresses supported in Phase 1.1; DNS is Phase 1.2",
    })?;

    let IpAddr::V4(v4) = ip else {
        return Err(TransportError::InvalidEndpoint {
            input: std::string::String::from(host),
            reason: "IPv6 not yet supported in Phase 1.1",
        });
    };

    let size = core::mem::size_of::<libc::sockaddr_in>();
    let ptr = unsafe { ngx_palloc(pool.as_ptr(), size) } as *mut libc::sockaddr_in;

    if ptr.is_null() {
        return Err(TransportError::Connection {
            cause: std::string::String::from("pool alloc for sockaddr_in failed"),
        });
    }

    unsafe {
        core::ptr::write_bytes(ptr, 0u8, 1);
        let sa = &mut *ptr;
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = port.to_be();
        // v4.octets() gives the four address bytes in network (big-endian) order.
        // `from_ne_bytes` reinterprets those bytes in the machine's native order
        // so that when the u32 is later read byte-by-byte by the kernel it sees
        // the original network-order bytes — i.e. 127.0.0.1 stays 127.0.0.1.
        // Using `from_be_bytes` would produce the WRONG layout on little-endian
        // hosts (the bytes would be reversed, mapping 127.0.0.1 → 1.0.0.127).
        sa.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
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
/// integration.  Requires a running NGINX worker.
impl HyperHttpTransport<NgxConnector> {
    pub fn with_ngx_log(
        endpoint_str: &str,
        headers: std::vec::Vec<(std::string::String, std::string::String)>,
        log: core::ptr::NonNull<ngx_log_t>,
    ) -> Result<Self, TransportError> {
        Self::with_connector(endpoint_str, headers, NgxConnector::new(log))
    }
}

impl<C: Connector> Transport for HyperHttpTransport<C> {
    async fn send(&mut self, bytes: std::vec::Vec<u8>) -> Result<(), TransportError> {
        let io = self.connector.connect(&self.endpoint).await?;
        let authority = self.endpoint.authority();
        let http_path = std::string::String::from(self.endpoint.http_path());
        http_post(io, &authority, &http_path, &self.headers, bytes).await
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
            "application/x-protobuf".parse().expect("static value"),
        );
        hdrs.insert(
            hyper::header::CONTENT_LENGTH,
            body_len.to_string().parse().expect("numeric string"),
        );
        hdrs.insert(hyper::header::CONNECTION, "close".parse().expect("static value"));
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
        let _ = conn.as_mut().poll(cx);
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
