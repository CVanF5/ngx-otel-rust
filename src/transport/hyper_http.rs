// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Hyper HTTP/1.1 transport for OTLP/HTTP protobuf export.
//!
//! `HyperHttpTransport` wraps blocking TCP/Unix-socket I/O in hyper's
//! async-IO traits so that the HTTP/1 client can operate without a Tokio
//! reactor.  Both `poll_read` and `poll_write` call through to blocking OS
//! operations and always return `Poll::Ready` — they never return
//! `Poll::Pending`.  This makes the transport usable from:
//!
//! - A simple spin-loop executor (`block_on`) in integration tests.
//! - NGINX's single-threaded async event loop (Step 9), where brief I/O
//!   blocking during the 10-second export window is acceptable.
//!
//! ## Connection model
//!
//! A new TCP / Unix-socket connection is created for every `send()` call.
//! No persistent connection pool is maintained in Phase 1.1; a simple
//! reconnect on each call is sufficient.
//! TODO(phase-1.2): add a one-shot cached connection to avoid the TCP
//! handshake overhead on every export interval.
//!
//! ## HTTPS
//!
//! `https://` endpoints are recognized but return [`TransportError::TlsConfig`]
//! immediately. Full TLS support (via openssl-sys) is deferred to Phase 1.2.

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
// I/O timeouts
// ──────────────────────────────────────────────────────────────────────────────

/// Maximum time to wait for data from the server.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time to spend sending data to the server.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

// ──────────────────────────────────────────────────────────────────────────────
// Parsed endpoint
// ──────────────────────────────────────────────────────────────────────────────

/// Parsed form of the `endpoint` directive value.
#[derive(Debug, Clone)]
enum ParsedEndpoint {
    /// Plain TCP: `http://host:port/path`
    Http {
        host: std::string::String,
        port: u16,
        path: std::string::String,
    },
    /// Unix domain socket: `unix:/path/to/sock` or `unix:///path/to/sock`
    Unix {
        /// Filesystem path to the socket file.
        socket_path: std::string::String,
        /// HTTP request path (defaults to `/v1/metrics`).
        http_path: std::string::String,
    },
}

impl ParsedEndpoint {
    fn parse(input: &str) -> Result<Self, TransportError> {
        if let Some(rest) = input.strip_prefix("http://") {
            // Split authority from path at the first '/'.
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
            // HTTPS is recognized but not yet implemented in Phase 1.1.
            Err(TransportError::TlsConfig {
                cause: std::string::String::from(
                    "HTTPS transport is not yet implemented in Phase 1.1; \
                     use an http:// or unix: endpoint",
                ),
            })
        } else if let Some(rest) = input.strip_prefix("unix:///") {
            // OTel convention: unix:///abs/path  → socket at /abs/path
            Ok(ParsedEndpoint::Unix {
                socket_path: std::format!("/{}", rest),
                http_path: std::string::String::from("/v1/metrics"),
            })
        } else if let Some(rest) = input.strip_prefix("unix://") {
            // unix://rel/path  → socket at rel/path
            Ok(ParsedEndpoint::Unix {
                socket_path: std::string::String::from(rest),
                http_path: std::string::String::from("/v1/metrics"),
            })
        } else if let Some(rest) = input.strip_prefix("unix:") {
            // unix:/abs/path or unix:rel/path
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

    /// Returns the value for the `Host` HTTP header.
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

    /// Returns the HTTP request path (e.g. `/v1/metrics`).
    fn http_path(&self) -> &str {
        match self {
            ParsedEndpoint::Http { path, .. } => path,
            ParsedEndpoint::Unix { http_path, .. } => http_path,
        }
    }
}

/// Parse `host[:port]` returning `(host_str, port)`.
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
// Blocking TCP wrapper (implements hyper::rt::{Read,Write})
// ──────────────────────────────────────────────────────────────────────────────

/// Wraps a blocking [`TcpStream`] for use as a hyper IO object.
///
/// Both `poll_read` and `poll_write` call blocking OS operations and always
/// return `Poll::Ready` — they never park the task with `Poll::Pending`.
struct TcpIo(TcpStream);

impl hyper::rt::Read for TcpIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // SAFETY: We treat the MaybeUninit<u8> slice as &mut [u8] because we
        // use it only as the destination for a `Read::read()` call, which
        // initialises the bytes it writes.  MaybeUninit<u8> is layout-
        // compatible with u8.
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
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl hyper::rt::Write for TcpIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Poll::Ready(self.0.write(buf))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.0.flush())
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.0.shutdown(std::net::Shutdown::Write))
    }
}

impl Unpin for TcpIo {}

// ──────────────────────────────────────────────────────────────────────────────
// Blocking Unix-socket wrapper (implements hyper::rt::{Read,Write})
// ──────────────────────────────────────────────────────────────────────────────

/// Wraps a blocking [`UnixStream`] for use as a hyper IO object.
struct UnixIo(UnixStream);

impl hyper::rt::Read for UnixIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
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
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl hyper::rt::Write for UnixIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Poll::Ready(self.0.write(buf))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.0.flush())
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.0.shutdown(std::net::Shutdown::Write))
    }
}

impl Unpin for UnixIo {}

// ──────────────────────────────────────────────────────────────────────────────
// HyperHttpTransport
// ──────────────────────────────────────────────────────────────────────────────

/// HTTP/1.1 transport that POSTs OTLP protobuf bytes to a configured endpoint.
///
/// Supports `http://` (plain TCP) and `unix:` (Unix domain socket) endpoints.
/// `https://` recognition is in place but returns [`TransportError::TlsConfig`]
/// until Phase 1.2 adds full TLS support.
///
/// # Connection model
/// A fresh connection is opened on every [`send`](Transport::send) call.
/// If the connection fails, an error is returned and the next call will try
/// again — simple reconnect, no backoff.
pub struct HyperHttpTransport {
    endpoint: ParsedEndpoint,
    /// Extra HTTP headers from `otel_exporter_header` directives.
    headers: std::vec::Vec<(std::string::String, std::string::String)>,
}

impl HyperHttpTransport {
    /// Create a new transport from a raw endpoint string and optional headers.
    ///
    /// Returns `Err(TransportError::InvalidEndpoint)` if `endpoint_str` cannot
    /// be parsed.
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
                stream
                    .set_read_timeout(Some(READ_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_write_timeout(Some(WRITE_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                let io = TcpIo(stream);
                http_send(io, &authority, &http_path, &self.headers, bytes).await
            }
            ParsedEndpoint::Unix { socket_path, .. } => {
                let stream = UnixStream::connect(socket_path)
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_read_timeout(Some(READ_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_write_timeout(Some(WRITE_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                let io = UnixIo(stream);
                http_send(io, &authority, &http_path, &self.headers, bytes).await
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Core send logic
// ──────────────────────────────────────────────────────────────────────────────

/// POST `body` bytes to `http_path` using the provided IO object.
///
/// Drives both the hyper [`Connection`](hyper::client::conn::http1::Connection)
/// (IO driver) and the [`send_request`](hyper::client::conn::http1::SendRequest::send_request)
/// future together in a single `poll_fn` loop.  Because the underlying IO
/// always returns `Poll::Ready`, the loop makes progress on every iteration
/// and terminates once the response status line has been received.
async fn http_send<IO>(
    io: IO,
    authority: &str,
    http_path: &str,
    extra_headers: &[(std::string::String, std::string::String)],
    body: std::vec::Vec<u8>,
) -> Result<(), TransportError>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let body_len = body.len();
    let full_body = Full::new(Bytes::from(body));

    // Build the HTTP request.
    let mut builder = Request::builder().method("POST").uri(http_path);

    {
        let headers = builder.headers_mut().ok_or_else(|| TransportError::Connection {
            cause: std::string::String::from("failed to access request builder headers"),
        })?;
        headers.insert(
            hyper::header::HOST,
            authority.parse().map_err(|_| TransportError::Connection {
                cause: std::format!("invalid Host header value: {}", authority),
            })?,
        );
        headers.insert(
            hyper::header::CONTENT_TYPE,
            "application/x-protobuf"
                .parse()
                .expect("static header value is valid"),
        );
        headers.insert(
            hyper::header::CONTENT_LENGTH,
            body_len
                .to_string()
                .parse()
                .expect("numeric string is a valid header value"),
        );
        // Signal to the server that we will close after this request.
        headers.insert(
            hyper::header::CONNECTION,
            "close".parse().expect("static header value is valid"),
        );
        // Append caller-supplied headers (otel_exporter_header directives).
        for (k, v) in extra_headers {
            if let (Ok(name), Ok(value)) = (
                k.parse::<hyper::header::HeaderName>(),
                v.parse::<hyper::header::HeaderValue>(),
            ) {
                headers.insert(name, value);
            }
        }
    }

    let req = builder
        .body(full_body)
        .map_err(|e| TransportError::Connection { cause: e.to_string() })?;

    // Hyper http1 handshake — establishes the connection state machine.
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake::<IO, Full<Bytes>>(io)
            .await
            .map_err(|e| TransportError::Connection { cause: e.to_string() })?;

    // Drive both the connection IO driver (`conn`) and the response future
    // (`resp_fut`) in a single poll_fn.  With blocking IO every poll_read /
    // poll_write returns Poll::Ready immediately, so no waker registration
    // is needed and the futures make progress on every poll.
    let mut conn = core::pin::pin!(conn);
    let resp_fut = sender.send_request(req);
    let mut resp_fut = core::pin::pin!(resp_fut);

    let resp = core::future::poll_fn(|cx| {
        // Advance the connection IO state machine (writes request, reads response).
        let _ = conn.as_mut().poll(cx);
        // Check whether a complete response is available.
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
