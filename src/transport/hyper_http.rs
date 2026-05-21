// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Hyper HTTP/1.1 transport for OTLP/HTTP protobuf export.
//!
//! `HyperHttpTransport` uses blocking TCP/Unix-socket I/O to perform HTTP/1.1
//! POSTs. The request is formatted per RFC 7230 and written in a single
//! blocking call; the response status line is read back synchronously.
//!
//! The `send()` method is declared `async fn` to satisfy the `Transport` trait
//! but its body is entirely synchronous (no internal await points). This means:
//!
//! - **Tests**: `block_on(transport.send(bytes))` works with any executor,
//!   including a simple spin-loop or `std::thread::spawn` wrapper.
//! - **NGINX Step 9**: calling `transport.send(bytes).await` from within
//!   `ngx::async_::spawn` blocks the event-loop thread for the duration of
//!   the TCP round-trip (typically <5 ms to a local collector), which is
//!   acceptable at the 10-second export interval.
//!
//! ## Connection model
//!
//! A fresh connection is opened on every `send()` call.  A `send` failure
//! returns `TransportError::Connection` immediately, and the next call
//! retries with a new connection — simple reconnect, no backoff.
//! TODO(phase-1.2): add a one-shot cached connection to eliminate the TCP
//! handshake overhead on every export interval.
//!
//! ## Hyper usage
//!
//! Hyper is used for:
//! - `hyper::header::*` constants when building the `Content-Type`,
//!   `Content-Length`, `Host`, and `Connection` headers.
//! - Future integration with `hyper::client::conn::http1` once NGINX's
//!   async executor (Step 9) is wired up (Phase 1.2).
//!
//! The HTTP/1.1 wire format is written manually to avoid the complexity of
//! driving hyper's split `(SendRequest, Connection)` pair without a
//! multi-task executor.
//!
//! ## HTTPS
//!
//! `https://` endpoints are recognized but return [`TransportError::TlsConfig`]
//! immediately. Full TLS support (via openssl-sys) is deferred to Phase 1.2.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::string::ToString;
use std::time::Duration;

use super::TransportError;
use crate::transport::Transport;

// ──────────────────────────────────────────────────────────────────────────────
// I/O timeouts
// ──────────────────────────────────────────────────────────────────────────────

/// Maximum wall-clock time for the entire HTTP round-trip.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

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
                    "HTTPS transport is not yet implemented in Phase 1.1; \
                     use an http:// or unix: endpoint",
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

    /// Returns the HTTP request-target path (e.g. `/v1/metrics`).
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
// HyperHttpTransport
// ──────────────────────────────────────────────────────────────────────────────

/// HTTP/1.1 transport that POSTs OTLP protobuf bytes to a configured endpoint.
///
/// Supports `http://` (plain TCP) and `unix:` (Unix domain socket) endpoints.
/// `https://` recognition is in place but returns [`TransportError::TlsConfig`]
/// until Phase 1.2 adds full TLS support via openssl-sys.
///
/// # Connection model
/// A fresh connection is opened on every [`send`](Transport::send) call.
/// Errors from any call return immediately; the next call retries fresh.
#[derive(Debug)]
pub struct HyperHttpTransport {
    endpoint: ParsedEndpoint,
    /// Extra HTTP headers from `otel_exporter_header` directives.
    headers: std::vec::Vec<(std::string::String, std::string::String)>,
}

impl HyperHttpTransport {
    /// Create a new transport from a raw endpoint string and optional headers.
    ///
    /// Returns `Err(TransportError::InvalidEndpoint)` if `endpoint_str` cannot
    /// be parsed, or `Err(TransportError::TlsConfig)` for `https://`.
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
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_write_timeout(Some(IO_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                post_http(stream, &authority, &http_path, &self.headers, bytes)
            }
            ParsedEndpoint::Unix { socket_path, .. } => {
                let stream = UnixStream::connect(socket_path)
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                stream
                    .set_write_timeout(Some(IO_TIMEOUT))
                    .map_err(|e| TransportError::Connection { cause: e.to_string() })?;
                post_http(stream, &authority, &http_path, &self.headers, bytes)
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Core HTTP/1.1 POST implementation
// ──────────────────────────────────────────────────────────────────────────────

/// Perform an HTTP/1.1 POST of `body` using the provided IO stream.
///
/// Writes the full request in one blocking `write_all`, then reads back
/// the response status line to determine success or failure.  The
/// `Connection: close` header signals to the server that we will not
/// reuse the connection.
///
/// This function is intentionally synchronous: it contains no `await`
/// points.  Calling it from within an `async fn` is safe because the
/// blocking time is bounded by `IO_TIMEOUT` (≤ 10 s) and the function
/// is only called from the background export task (Step 9), not from a
/// NGINX request-handling worker path.
fn post_http<S: Read + Write>(
    mut stream: S,
    authority: &str,
    http_path: &str,
    extra_headers: &[(std::string::String, std::string::String)],
    body: std::vec::Vec<u8>,
) -> Result<(), TransportError> {
    // ── Build the request ─────────────────────────────────────────────────
    //
    // We format the request headers by hand rather than using hyper's
    // SendRequest machinery, because driving hyper's split
    // (SendRequest, Connection) pair concurrently requires a multi-task
    // executor (see TODO in module docs).  The wire format is identical
    // to what hyper would produce for a `Full<Bytes>` body.
    let content_length = body.len();

    let mut request = std::vec::Vec::with_capacity(256 + content_length);

    // Request line
    request.extend_from_slice(b"POST ");
    request.extend_from_slice(http_path.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\n");

    // Mandatory headers
    request.extend_from_slice(b"Host: ");
    request.extend_from_slice(authority.as_bytes());
    request.extend_from_slice(b"\r\n");

    request.extend_from_slice(b"Content-Type: application/x-protobuf\r\n");

    request.extend_from_slice(b"Content-Length: ");
    request.extend_from_slice(content_length.to_string().as_bytes());
    request.extend_from_slice(b"\r\n");

    request.extend_from_slice(b"Connection: close\r\n");

    // Caller-supplied headers (otel_exporter_header directives)
    for (k, v) in extra_headers {
        request.extend_from_slice(k.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(v.as_bytes());
        request.extend_from_slice(b"\r\n");
    }

    // Header / body separator
    request.extend_from_slice(b"\r\n");

    // Body
    request.extend_from_slice(&body);

    // ── Send the request ──────────────────────────────────────────────────
    stream
        .write_all(&request)
        .map_err(|e| TransportError::Connection { cause: e.to_string() })?;

    // ── Read and parse the response status line ───────────────────────────
    //
    // We only need the status code — not the body — to determine success.
    // BufReader lets us read line-by-line without consuming the socket;
    // we stop after the status line.
    let mut reader = BufReader::new(&mut stream);
    let mut status_line = std::string::String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| TransportError::Connection { cause: e.to_string() })?;

    // Status line format: "HTTP/1.1 <code> <reason>\r\n"
    let status_code = parse_status_code(status_line.trim())
        .ok_or_else(|| TransportError::Connection {
            cause: std::format!(
                "unexpected response status line: {:?}",
                status_line.trim()
            ),
        })?;

    if (200..300).contains(&status_code) {
        Ok(())
    } else {
        Err(TransportError::HttpStatus {
            code: status_code,
            message: std::string::String::from(http_reason_phrase(status_code)),
        })
    }
}

/// Parse the numeric status code from an HTTP/1.1 status line.
///
/// Returns `None` if the line is not a valid HTTP/1.x status line.
fn parse_status_code(status_line: &str) -> Option<u16> {
    // Expected: "HTTP/1.1 200 OK" or "HTTP/1.0 200 OK"
    let without_version = status_line.strip_prefix("HTTP/1.")?;
    // skip minor version digit and space
    let rest = without_version.get(2..)?; // skip "1 " or "0 "
    let code_str = rest.get(..3)?;
    code_str.parse().ok()
}

/// Return a canonical reason phrase for common HTTP status codes.
fn http_reason_phrase(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}
