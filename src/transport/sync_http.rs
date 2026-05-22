// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Synchronous HTTP/1.1 POST client for use in `exit_process` callbacks.
//!
//! Provides a minimal blocking HTTP/1.1 POST using [`std::net::TcpStream`]
//! with 500 ms connect/write/read budgets.  It is designed for use **outside
//! the NGINX async event loop** — specifically in the `exit_process` module
//! callback where the event loop is no longer running and
//! `HyperHttpTransport` cannot be used.
//!
//! Does **not** depend on hyper or any other non-std crate.
//!
//! Only plain TCP endpoints (`http://`) are supported; `unix://` and
//! `https://` return [`SyncSendError::UnsupportedScheme`].

use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::time::Duration;

use super::hyper_http::ParsedEndpoint;

/// Maximum wall-clock time allowed for each phase of the sync send.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const WRITE_TIMEOUT: Duration = Duration::from_millis(500);
const READ_TIMEOUT: Duration = Duration::from_millis(500);

// ── Error type ────────────────────────────────────────────────────────────────

/// Error variants for [`sync_post`].
///
/// Each variant wraps the underlying [`std::io::Error`] so the caller can log
/// the error kind (including [`std::io::ErrorKind::TimedOut`] for timeouts)
/// and the OS error code.
#[derive(Debug)]
pub enum SyncSendError {
    /// TCP connection failed.  Includes timeout when the connect budget
    /// (`CONNECT_TIMEOUT`) expires before the three-way handshake completes.
    Connect(std::io::Error),
    /// Writing the HTTP request failed.  Includes timeout when the write
    /// budget (`WRITE_TIMEOUT`) expires.
    Write(std::io::Error),
    /// Reading the HTTP response failed.  Includes timeout when the read
    /// budget (`READ_TIMEOUT`) expires.
    Read(std::io::Error),
    /// The configured endpoint uses a scheme (`unix://` or `https://`) that
    /// requires non-blocking or TLS I/O; the sync TCP client cannot serve it.
    UnsupportedScheme,
}

impl SyncSendError {
    /// Returns `true` if this error was caused by a deadline expiry at any
    /// phase (connect, write, or read).
    pub fn is_timeout(&self) -> bool {
        match self {
            SyncSendError::Connect(e) | SyncSendError::Write(e) | SyncSendError::Read(e) => {
                e.kind() == std::io::ErrorKind::TimedOut
            }
            SyncSendError::UnsupportedScheme => false,
        }
    }
}

impl core::fmt::Display for SyncSendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SyncSendError::Connect(e) => write!(f, "connect: {}", e),
            SyncSendError::Write(e) => write!(f, "write: {}", e),
            SyncSendError::Read(e) => write!(f, "read: {}", e),
            SyncSendError::UnsupportedScheme => write!(
                f,
                "endpoint scheme unsupported by sync client \
                 (unix:// and https:// require the async transport)"
            ),
        }
    }
}

// ── Main function ─────────────────────────────────────────────────────────────

/// POST `body` as `application/x-protobuf` to `endpoint_str`.
///
/// Uses a blocking [`std::net::TcpStream`] with:
/// - 500 ms connect timeout
/// - 500 ms write timeout
/// - 500 ms read timeout
///
/// `extra_headers` is appended after the built-in `Content-Type` and
/// `Content-Length` headers (e.g. `Authorization`).
///
/// The response is read into a 512-byte buffer to let the server know the
/// request was received; the status code is not inspected.  The connection
/// is closed after the read.
///
/// # Errors
/// Returns `SyncSendError` on connection failure, write failure, or read
/// failure (including timeouts).  Unix socket and HTTPS endpoints return
/// `SyncSendError::UnsupportedScheme`.
pub fn sync_post(
    endpoint_str: &str,
    extra_headers: &[(std::string::String, std::string::String)],
    body: &[u8],
) -> Result<(), SyncSendError> {
    // Parse the endpoint — reuses the same parser as HyperHttpTransport so
    // the two transports interpret the configuration string identically.
    let endpoint = ParsedEndpoint::parse(endpoint_str)
        .map_err(|_| SyncSendError::UnsupportedScheme)?;

    let (host, port, path) = match &endpoint {
        ParsedEndpoint::Http { host, port, path } => (host.as_str(), *port, path.as_str()),
        // Unix sockets need UnixStream; HTTPS needs TLS — both are out of scope
        // for the sync client.  The exit_process path logs UnsupportedScheme and
        // skips the flush gracefully.
        ParsedEndpoint::Unix { .. } => return Err(SyncSendError::UnsupportedScheme),
    };

    // Resolve the address.  DNS is blocking; that is acceptable here because
    // exit_process runs outside the NGINX async event loop.
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(SyncSendError::Connect)?
        .next()
        .ok_or_else(|| {
            SyncSendError::Connect(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "no addresses resolved for endpoint host",
            ))
        })?;

    // Connect with a hard deadline so a refused or unreachable collector
    // does not stall worker exit beyond the 500 ms budget.
    let mut stream = std::net::TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(SyncSendError::Connect)?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(SyncSendError::Write)?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(SyncSendError::Read)?;

    // Build the HTTP/1.1 request.
    let authority = if port == 80 {
        std::string::String::from(host)
    } else {
        std::format!("{}:{}", host, port)
    };

    let mut request = std::format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n",
        path,
        authority,
        body.len()
    )
    .into_bytes();

    for (k, v) in extra_headers {
        request.extend_from_slice(std::format!("{}: {}\r\n", k, v).as_bytes());
    }
    // End of headers.
    request.extend_from_slice(b"\r\n");
    // Body.
    request.extend_from_slice(body);

    // One write: headers + body together.
    stream.write_all(&request).map_err(SyncSendError::Write)?;

    // One read: enough to receive the response status line.  We do not parse
    // the status code — the collector either got it or it didn't.
    let mut buf = [0u8; 512];
    stream.read(&mut buf).map_err(SyncSendError::Read)?;

    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Spin up a minimal TCP server, send an OTLP POST through `sync_post`,
    /// and assert the raw request bytes match the expected HTTP/1.1 shape:
    ///   - request line: `POST /v1/metrics HTTP/1.1\r\n`
    ///   - `Content-Type: application/x-protobuf\r\n`
    ///   - `Content-Length: <body_len>\r\n`
    #[test]
    fn sync_post_sends_correct_http_request() {
        // Bind on an OS-assigned ephemeral port.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        // Server thread: accept one connection, read the request, reply 200 OK.
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut buf = std::vec![0u8; 8192];
            let n = conn.read(&mut buf).expect("read request");
            buf.truncate(n);
            conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .expect("write response");
            buf
        });

        let body = b"\x00\x01\x02\x03protobuf-payload";
        let endpoint = std::format!("http://127.0.0.1:{}/v1/metrics", port);
        let result = sync_post(&endpoint, &[], body);
        let request_bytes = server.join().expect("server thread panicked");

        assert!(result.is_ok(), "sync_post must succeed: {:?}", result.err());

        let raw = std::string::String::from_utf8_lossy(&request_bytes);
        assert!(
            raw.starts_with("POST /v1/metrics HTTP/1.1\r\n"),
            "request line mismatch; got: {:?}",
            raw.get(..60.min(raw.len())).unwrap_or(&raw)
        );
        assert!(
            raw.contains("Content-Type: application/x-protobuf\r\n"),
            "Content-Type header missing; raw request: {:?}",
            raw.get(..200.min(raw.len())).unwrap_or(&raw)
        );
        let expected_cl = std::format!("Content-Length: {}\r\n", body.len());
        assert!(
            raw.contains(expected_cl.as_str()),
            "Content-Length header missing or wrong; expected {:?}",
            expected_cl
        );
    }
}
