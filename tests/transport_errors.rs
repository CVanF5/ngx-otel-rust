// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Error-path tests for `HyperHttpTransport`.
//!
//! These tests do NOT require an external OTel collector.  They target ports /
//! paths that have nothing listening, verifying that the transport surfaces
//! errors cleanly — no panics, no infinite hangs.
//!
//! # Running
//!
//! ```sh
//! NGINX_SOURCE_DIR=.../nginx \
//! NGINX_BUILD_DIR=.../nginx/objs \
//! cargo test --test transport_errors
//! ```

// Pull in NGINX stubs (needed by macOS flat-namespace linker) and the
// spin-loop block_on helper.
mod support;
use support::block_on;

use ngx_http_otel_module::transport::{HyperHttpTransport, Transport, TransportError};

/// Connecting to a port with nothing listening returns a Connection error.
///
/// Port 1 on loopback is unused by any standard service and always refuses
/// immediately; the OS's ECONNREFUSED is wrapped in `TransportError::Connection`.
#[test]
fn connection_refused_returns_error() {
    let mut transport = HyperHttpTransport::new("http://127.0.0.1:1/v1/metrics", vec![])
        .expect("endpoint must parse");

    let result = block_on(transport.send(vec![0u8; 16]));
    match result {
        Err(TransportError::Connection { .. }) => {}
        other => panic!("expected TransportError::Connection, got: {:?}", other),
    }
}

/// Pins the reconnect path: each `send()` opens a fresh connection, so a
/// second call after a connection failure must not panic — just fail again.
#[test]
fn second_send_after_failure_does_not_panic() {
    let mut transport = HyperHttpTransport::new("http://127.0.0.1:1/v1/metrics", vec![])
        .expect("endpoint must parse");

    let first = block_on(transport.send(vec![0u8; 16]));
    assert!(first.is_err(), "first send to closed port must fail");

    let second = block_on(transport.send(vec![0u8; 16]));
    assert!(second.is_err(), "second send to closed port must also fail");
}

/// Parsing an unsupported scheme returns an `InvalidEndpoint` error at
/// construction time — before any network I/O.
#[test]
fn invalid_scheme_rejected_at_construction() {
    let result = HyperHttpTransport::new("grpc://127.0.0.1:4317/", vec![]);
    match result {
        Err(TransportError::InvalidEndpoint { .. }) => {}
        other => panic!("expected TransportError::InvalidEndpoint, got: {:?}", other),
    }
}

/// `https://` is recognized and returns `TlsConfig` (not yet implemented).
#[test]
fn https_returns_tls_config_error() {
    let result = HyperHttpTransport::new("https://127.0.0.1:4318/v1/metrics", vec![]);
    match result {
        Err(TransportError::TlsConfig { .. }) => {}
        Ok(transport) => {
            panic!("expected TransportError::TlsConfig for https://, got Ok: {:?}", transport)
        }
        Err(other) => panic!(
            "expected TransportError::TlsConfig for https://, got different error: {:?}",
            other
        ),
    }
}

/// Connecting to a non-existent Unix socket path returns a Connection error.
#[test]
fn unix_socket_not_found_returns_error() {
    let mut transport =
        HyperHttpTransport::new("unix:///tmp/ngx-otel-step8-nonexistent.sock", vec![])
            .expect("endpoint must parse");

    let result = block_on(transport.send(vec![0u8; 16]));
    match result {
        Err(TransportError::Connection { .. }) => {}
        other => panic!("expected TransportError::Connection for missing socket, got: {:?}", other),
    }
}
