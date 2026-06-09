// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Synchronous HTTP/1.1 POST client for use in `exit_process` callbacks.
//!
//! Provides a minimal blocking HTTP/1.1 POST over either
//! [`std::net::TcpStream`] or [`std::os::unix::net::UnixStream`] with
//! 500 ms connect/write/read budgets.  It is designed for use **outside the
//! NGINX async event loop** — specifically in the `exit_process` module
//! callback where the event loop is no longer running and
//! `HyperHttpTransport` cannot be used.
//!
//! Does **not** depend on hyper or any other non-std crate.
//!
//! Plain TCP (`http://`) and Unix socket (`unix:`) endpoints are supported;
//! `https://` returns [`SyncSendError::UnsupportedScheme`] because TLS is
//! deferred to Phase 1.2.

use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::os::unix::net::UnixStream;
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
    /// The configured endpoint uses a scheme (`https://`) that requires TLS;
    /// the sync client does not implement TLS (deferred to Phase 1.2).
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
                 (https:// requires TLS, deferred to Phase 1.2)"
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
/// failure (including timeouts).  HTTPS endpoints return
/// `SyncSendError::UnsupportedScheme` (TLS deferred to Phase 1.2).
pub fn sync_post(
    endpoint_str: &str,
    extra_headers: &[(std::string::String, std::string::String)],
    body: &[u8],
) -> Result<(), SyncSendError> {
    // Parse the endpoint — reuses the same parser as HyperHttpTransport so
    // the two transports interpret the configuration string identically.
    let endpoint =
        ParsedEndpoint::parse(endpoint_str).map_err(|_| SyncSendError::UnsupportedScheme)?;

    match endpoint {
        ParsedEndpoint::Http { host, port, path } => {
            // Build the HTTP/1.1 request using host:port as the authority,
            // matching HyperHttpTransport's behaviour for TCP endpoints.
            let authority = if port == 80 {
                std::string::String::from(&host)
            } else {
                std::format!("{}:{}", host, port)
            };
            let request = build_http_request(&authority, &path, extra_headers, body);

            // Resolve all addresses.  DNS is blocking; that is acceptable here
            // because exit_process runs outside the NGINX async event loop.
            // Collecting into a Vec lets us iterate multiple addresses
            // (e.g. both A and AAAA) without holding the iterator across an
            // error-handling branch.
            //
            // Strip IPv6 bracket notation before resolution.
            // `ParsedEndpoint::parse` stores `"[::1]"` for `http://[::1]:PORT/`;
            // `to_socket_addrs` rejects the bracketed form.  The async path uses
            // the same `strip_v6_brackets` helper (hyper_http.rs).
            let bare_host = crate::transport::hyper_http::strip_v6_brackets(host.as_str());
            let addrs: std::vec::Vec<_> =
                (bare_host, port).to_socket_addrs().map_err(SyncSendError::Connect)?.collect();
            if addrs.is_empty() {
                return Err(SyncSendError::Connect(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "no addresses resolved for endpoint host",
                )));
            }

            // Try each resolved address in order until one connects.
            // Each attempt gets its own CONNECT_TIMEOUT budget (500 ms) so
            // the total is bounded by `n_addresses × 500 ms`.  This is
            // acceptable in exit_process (blocking is fine there); the outer
            // backstop is worker_shutdown_timeout.  Sequential iteration is
            // intentional — no happy-eyeballs (same policy as the async path).
            let mut stream =
                connect_first_reachable(&addrs, CONNECT_TIMEOUT).map_err(SyncSendError::Connect)?;
            stream.set_write_timeout(Some(WRITE_TIMEOUT)).map_err(SyncSendError::Write)?;
            stream.set_read_timeout(Some(READ_TIMEOUT)).map_err(SyncSendError::Read)?;

            send_request_and_read_response(&mut stream, &request)
        }
        ParsedEndpoint::Unix { socket_path, http_path } => {
            // Unix-socket endpoints use "localhost" as the Host header, matching
            // HyperHttpTransport::authority() for the Unix variant.
            let request = build_http_request("localhost", &http_path, extra_headers, body);

            // UnixStream::connect has no built-in timeout.  In the typical
            // /run/otel.sock deployment shape this is fine:
            //   - server present: local connect is sub-millisecond
            //   - server absent: fails fast with ECONNREFUSED, ENOENT, or
            //     EACCES on the socket inode
            //   - peer wedged after connect: bounded by the 500 ms write/read
            //     timeouts set below
            //
            // The one edge case left uncovered is a socket file sitting on a
            // hung NFS/9P/FUSE mount — there the kernel-side connect() can
            // stall beyond 500 ms.  Such a deployment shape is exotic for a
            // local collector unix socket; if it does occur, the worker's
            // configured `worker_shutdown_timeout` is the outer backstop.
            let mut stream = UnixStream::connect(&socket_path).map_err(SyncSendError::Connect)?;
            stream.set_write_timeout(Some(WRITE_TIMEOUT)).map_err(SyncSendError::Write)?;
            stream.set_read_timeout(Some(READ_TIMEOUT)).map_err(SyncSendError::Read)?;

            send_request_and_read_response(&mut stream, &request)
        }
    }
}

/// Try each `SocketAddr` in `addrs` in order using `connect_timeout`.
///
/// Returns the first successfully connected `TcpStream`, or the last
/// connection error if all addresses fail.  Callers guarantee `addrs` is
/// non-empty.
///
/// This function is the `sync_post` equivalent of the async connector's
/// address-iteration loop in `NgxConnector::connect_dns`.  The same
/// sequential-not-happy-eyeballs policy applies here: simpler, sufficient
/// for a cold-path flush, and consistent with the async path.
fn connect_first_reachable(
    addrs: &[std::net::SocketAddr],
    timeout: Duration,
) -> Result<std::net::TcpStream, std::io::Error> {
    let mut last_err: Option<std::io::Error> = None;
    for addr in addrs {
        match std::net::TcpStream::connect_timeout(addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "connect_first_reachable: no addresses to try",
        )
    }))
}

/// Build the on-wire HTTP/1.1 request bytes for a sync POST.
///
/// Used by both the TCP and Unix-socket paths so the two stay byte-identical
/// modulo authority (`host:port` vs `localhost`) and path.
fn build_http_request(
    authority: &str,
    path: &str,
    extra_headers: &[(std::string::String, std::string::String)],
    body: &[u8],
) -> std::vec::Vec<u8> {
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
    request
}

/// Write the request and read up to 512 response bytes.
///
/// Generic over the stream type so both `TcpStream` and `UnixStream` share
/// the same write-then-read sequence.  We do not parse the response status —
/// the collector either got the bytes before the read budget elapsed or it
/// didn't.
fn send_request_and_read_response<S: Read + Write>(
    stream: &mut S,
    request: &[u8],
) -> Result<(), SyncSendError> {
    stream.write_all(request).map_err(SyncSendError::Write)?;
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

    /// `connect_first_reachable` skips unreachable addresses and connects to
    /// the first reachable one.  Uses two addresses:
    ///   - address[0] = 127.0.0.1:1  (port 1, typically refused immediately)
    ///   - address[1] = 127.0.0.1:N  (an ephemeral port with a listener)
    ///
    /// Asserts that the function returns `Ok` (connected to address[1]) even
    /// though address[0] failed.
    #[test]
    fn connect_first_reachable_skips_to_reachable_address() {
        // Bind a listener on an OS-assigned ephemeral port.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let reachable_port = listener.local_addr().expect("local_addr").port();

        // Spin a server thread that accepts exactly one connection then exits.
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            // Just write a minimal response and close.
            let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        });

        // Address list: first entry is almost certainly refused (port 1);
        // second entry is our listening server.
        let addrs = std::vec![
            std::net::SocketAddr::from(([127, 0, 0, 1], 1u16)),
            std::net::SocketAddr::from(([127, 0, 0, 1], reachable_port)),
        ];

        let result = connect_first_reachable(&addrs, Duration::from_millis(500));
        let _ = server.join();

        assert!(
            result.is_ok(),
            "connect_first_reachable must succeed when the second address is reachable; err: {:?}",
            result.err()
        );
    }

    /// `connect_first_reachable` returns the last error when all addresses fail.
    #[test]
    fn connect_first_reachable_returns_error_when_all_fail() {
        // Port 1 is almost never listening; use two such addresses.
        let addrs = std::vec![
            std::net::SocketAddr::from(([127, 0, 0, 1], 1u16)),
            std::net::SocketAddr::from(([127, 0, 0, 1], 2u16)),
        ];

        let result = connect_first_reachable(&addrs, Duration::from_millis(100));
        assert!(
            result.is_err(),
            "connect_first_reachable must fail when all addresses are unreachable"
        );
    }

    /// `sync_post` resolves a bracketed IPv6 literal (`http://[::1]:PORT/…`) by
    /// stripping the brackets before `to_socket_addrs`.  Binds a TcpListener on
    /// `[::1]:0` and asserts the POST arrives successfully.
    ///
    /// Guards: if IPv6 loopback isn't available (e.g. a CI environment with
    /// `net.ipv6.conf.lo.disable_ipv6=1`), the bind will fail and we skip the
    /// test rather than fail it — the assertion we care about (brackets stripped)
    /// is independently tested by `strip_v6_brackets_removes_brackets_from_ipv6_literal`.
    #[test]
    fn sync_post_to_ipv6_literal_strips_brackets_and_connects() {
        use std::io::{Read, Write};

        let v6_addr: std::net::SocketAddr = "[::1]:0".parse().unwrap();
        let listener = match std::net::TcpListener::bind(v6_addr) {
            Ok(l) => l,
            Err(_) => {
                // IPv6 loopback unavailable — skip gracefully.
                return;
            }
        };
        let port = listener.local_addr().expect("local_addr").port();

        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut buf = std::vec![0u8; 8192];
            let n = conn.read(&mut buf).expect("read");
            buf.truncate(n);
            conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .expect("write response");
            buf
        });

        // The endpoint uses the bracketed form — this is what a real nginx config
        // produces.  The bug was that this string was passed directly
        // to to_socket_addrs, which rejected it.
        let endpoint = std::format!("http://[::1]:{}/v1/metrics", port);
        let body = b"test-v6-payload";
        let result = sync_post(&endpoint, &[], body);
        let request_bytes = server.join().expect("server thread");

        assert!(
            result.is_ok(),
            "sync_post to IPv6 literal [::1] must succeed after bracket strip; err: {:?}",
            result.err()
        );

        let raw = std::string::String::from_utf8_lossy(&request_bytes);
        assert!(
            raw.starts_with("POST /v1/metrics HTTP/1.1\r\n"),
            "request line mismatch for v6 endpoint: {:?}",
            raw.get(..60.min(raw.len())).unwrap_or(&raw)
        );
    }

    /// Same shape as the TCP test, but with a unix-socket endpoint.  Verifies:
    ///   - the unix-socket branch is wired up at all (was previously rejected
    ///     with `UnsupportedScheme`)
    ///   - the request line is `POST / HTTP/1.1\r\n` (the base path `/` stored
    ///     by `ParsedEndpoint::parse` for unix endpoints; per-signal paths are
    ///     appended by `HyperHttpTransport`, not by `sync_post`)
    ///   - the `Host` header is `localhost` (matches HyperHttpTransport)
    ///   - Content-Type / Content-Length are well-formed
    #[test]
    fn sync_post_via_unix_socket_sends_correct_http_request() {
        use std::os::unix::net::UnixListener;

        // Build a unique socket path under /tmp so parallel test runs don't
        // collide.  Pid + nanos is sufficient; we clean up at the end.
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let socket_path = std::format!("/tmp/ngx-otel-sync-uds-{}-{}.sock", pid, nanos);

        // Defensive: remove any stale file at the path so bind() succeeds.
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind unix socket");

        let cleanup_path = socket_path.clone();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut buf = std::vec![0u8; 8192];
            let n = conn.read(&mut buf).expect("read request");
            buf.truncate(n);
            conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .expect("write response");
            let _ = std::fs::remove_file(&cleanup_path);
            buf
        });

        let body = b"\x00\x01\x02\x03protobuf-payload";
        let endpoint = std::format!("unix:{}", socket_path);
        let result = sync_post(&endpoint, &[], body);
        let request_bytes = server.join().expect("server thread panicked");

        assert!(result.is_ok(), "sync_post over unix must succeed: {:?}", result.err());

        let raw = std::string::String::from_utf8_lossy(&request_bytes);
        assert!(
            raw.starts_with("POST / HTTP/1.1\r\n"),
            "request line mismatch; got: {:?}",
            raw.get(..60.min(raw.len())).unwrap_or(&raw)
        );
        assert!(
            raw.contains("Host: localhost\r\n"),
            "Host header should be 'localhost' for unix sockets; raw request: {:?}",
            raw.get(..200.min(raw.len())).unwrap_or(&raw)
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
