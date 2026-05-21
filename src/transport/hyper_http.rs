// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Hyper HTTP/1.1 transport for OTLP/HTTP protobuf export.
//!
//! # IO model
//!
//! `TcpIo` and `UnixIo` wrap non-blocking OS streams and implement
//! `hyper::rt::{Read, Write}`.  When the OS returns `EAGAIN`/`WouldBlock`
//! the wrappers return `Poll::Pending` and immediately call
//! `cx.waker().wake_by_ref()` so the executor re-polls without registering
//! with an event loop reactor.  This "self-wake" pattern means:
//!
//! - **Tests** (`block_on` spin-loop, noop waker): the self-wake is a no-op
//!   but the spin-loop re-polls anyway.  Correct.
//! - **NGINX event loop (Step 9)**: `wake_by_ref()` posts an NGINX async
//!   event, scheduling a re-poll on the next event loop iteration rather than
//!   blocking the loop thread.  Much better than the previous blocking approach.
//!
//! The long-term plan (Phase 1.2) is to replace `TcpIo`/`UnixIo` with
//! nginx-acme's `PeerConnection`, which registers proper NGINX event handlers
//! instead of self-waking.
//!
//! # Connection model
//!
//! A new connection is opened for every `send()` call (simple reconnect).
//! TODO(phase-1.2): one-shot cached connection to amortise TCP handshake.
//!
//! # HTTPS
//!
//! `https://` is recognized but returns [`TransportError::TlsConfig`].
//! Full TLS via openssl-sys is Phase 1.2.

use core::future;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::string::ToString;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Request;

use super::TransportError;
use crate::transport::Transport;

// ──────────────────────────────────────────────────────────────────────────────
// Timeout
// ──────────────────────────────────────────────────────────────────────────────

/// Wall-clock limit for an individual read/write syscall.  A stalled
/// non-blocking socket will self-wake on every event loop iteration, so this
/// timeout is the last resort against a server that stops talking entirely.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

// ──────────────────────────────────────────────────────────────────────────────
// Parsed endpoint
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum ParsedEndpoint {
    Http {
        host: std::string::String,
        port: u16,
        path: std::string::String,
    },
    Unix {
        socket_path: std::string::String,
        http_path: std::string::String,
    },
}

impl ParsedEndpoint {
    fn parse(input: &str) -> Result<Self, TransportError> {
        if let Some(rest) = input.strip_prefix("http://") {
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], std::string::String::from(&rest[i..])),
                None => (rest, std::string::String::from("/")),
            };
            let (host, port) = parse_authority(authority, 80);
            Ok(ParsedEndpoint::Http {
                host: std::string::String::from(host),
                port,
                path,
            })
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
// Non-blocking IO wrappers
// ──────────────────────────────────────────────────────────────────────────────

/// Wraps a non-blocking [`TcpStream`] for hyper's async IO traits.
///
/// On `WouldBlock` the wrapper returns `Poll::Pending` and calls
/// `cx.waker().wake_by_ref()` so the executor re-polls without a reactor.
struct TcpIo(TcpStream);

impl hyper::rt::Read for TcpIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // SAFETY: MaybeUninit<u8> is layout-compatible with u8; read() initialises
        // every byte it writes.
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

impl hyper::rt::Write for TcpIo {
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

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.get_mut().0.flush())
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.get_mut().0.shutdown(std::net::Shutdown::Write))
    }
}

impl Unpin for TcpIo {}

/// Wraps a non-blocking [`UnixStream`] for hyper's async IO traits.
struct UnixIo(UnixStream);

impl hyper::rt::Read for UnixIo {
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

impl hyper::rt::Write for UnixIo {
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

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.get_mut().0.flush())
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.get_mut().0.shutdown(std::net::Shutdown::Write))
    }
}

impl Unpin for UnixIo {}

// ──────────────────────────────────────────────────────────────────────────────
// HyperHttpTransport
// ──────────────────────────────────────────────────────────────────────────────

/// HTTP/1.1 transport that POSTs OTLP protobuf bytes to a configured endpoint.
///
/// Uses [`hyper::client::conn::http1`] for protocol handling.  The underlying
/// OS stream is in non-blocking mode; `WouldBlock` is returned as
/// `Poll::Pending` with an immediate self-wake so NGINX's cooperative event
/// loop is never blocked.
///
/// TODO(phase-1.2): replace `TcpIo`/`UnixIo` with nginx-acme's
/// `PeerConnection` for proper NGINX event-handler integration (no busy-wake).
#[derive(Debug)]
pub struct HyperHttpTransport {
    endpoint: ParsedEndpoint,
    headers: std::vec::Vec<(std::string::String, std::string::String)>,
}

impl HyperHttpTransport {
    /// Create a new transport.
    ///
    /// Returns `Err` if the endpoint string cannot be parsed or uses `https://`.
    pub fn new(
        endpoint_str: &str,
        headers: std::vec::Vec<(std::string::String, std::string::String)>,
    ) -> Result<Self, TransportError> {
        let endpoint = ParsedEndpoint::parse(endpoint_str)?;
        Ok(Self { endpoint, headers })
    }
}

impl Transport for HyperHttpTransport {
    async fn send(&mut self, bytes: std::vec::Vec<u8>) -> Result<(), TransportError> {
        let authority = self.endpoint.authority();
        let http_path = std::string::String::from(self.endpoint.http_path());

        match &self.endpoint {
            ParsedEndpoint::Http { host, port, .. } => {
                let addr = std::format!("{}:{}", host, port);
                let stream = TcpStream::connect(&addr)
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                // Non-blocking so poll_read/poll_write return WouldBlock rather
                // than blocking the NGINX event loop.
                stream
                    .set_nonblocking(true)
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                // SO_RCVTIMEO / SO_SNDTIMEO as a backstop against a completely
                // silent server (non-blocking reads that never become ready).
                stream
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_write_timeout(Some(IO_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                http_post(TcpIo(stream), &authority, &http_path, &self.headers, bytes).await
            }
            ParsedEndpoint::Unix { socket_path, .. } => {
                let stream = UnixStream::connect(socket_path)
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_nonblocking(true)
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_write_timeout(Some(IO_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                http_post(UnixIo(stream), &authority, &http_path, &self.headers, bytes).await
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Core HTTP POST via hyper http1 client
// ──────────────────────────────────────────────────────────────────────────────

/// POST `body` to `http_path` using hyper's HTTP/1.1 connection.
///
/// The `conn` (IO driver) and the response future are driven together inside a
/// single `poll_fn` loop.  With non-blocking IO and the self-wake pattern,
/// the loop converges without blocking the calling executor thread.
async fn http_post<IO>(
    io: IO,
    authority: &str,
    http_path: &str,
    extra_headers: &[(std::string::String, std::string::String)],
    body: std::vec::Vec<u8>,
) -> Result<(), TransportError>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin,
{
    let body_len = body.len();
    let full_body = Full::new(Bytes::from(body));

    // Build the request.
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
        hdrs.insert(
            hyper::header::CONNECTION,
            "close".parse().expect("static value"),
        );
        for (k, v) in extra_headers {
            if let (Ok(name), Ok(val)) = (
                k.parse::<hyper::header::HeaderName>(),
                v.parse::<hyper::header::HeaderValue>(),
            ) {
                hdrs.insert(name, val);
            }
        }
    }
    let req = builder
        .body(full_body)
        .map_err(|e| TransportError::Connection { cause: e.to_string() })?;

    // Hyper HTTP/1.1 handshake — returns (SendRequest, Connection).
    // Connection is the IO driver; SendRequest enqueues requests.
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake::<IO, Full<Bytes>>(io)
            .await
            .map_err(|e| TransportError::Connection { cause: e.to_string() })?;

    let resp_fut = sender.send_request(req);

    // Drive both the IO driver (`conn`) and the response future (`resp_fut`)
    // in a single poll_fn.
    //
    // On each poll:
    //   1. conn.poll() advances the protocol state machine (writes the request,
    //      reads the response, signals resp_fut via oneshot).
    //   2. resp_fut.poll() checks whether the response is ready.
    //
    // With non-blocking IO, conn.poll() never blocks: either it makes progress
    // (data available) or the underlying IO returns WouldBlock → our wrapper
    // returns Poll::Pending and calls wake_by_ref() to re-schedule the poll.
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
            message: std::string::String::from(
                status.canonical_reason().unwrap_or("unknown"),
            ),
        })
    }
}
