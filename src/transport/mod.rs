// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Step 8: `Transport` trait + hyper HTTP/1 client implementation.
//!
//! The `Transport` trait is the seam between the export loop (Step 9) and the
//! underlying network transport. `HyperHttpTransport` is the only impl in
//! Phase 1.1; it POSTs OTLP/HTTP protobuf bytes over plain TCP or Unix
//! sockets. HTTPS support is reserved for a later phase.

pub mod grpc;
pub mod hyper_http;
pub mod sync_http;

use thiserror::Error;

/// Error variants for transport operations.
///
/// Each variant carries enough context for a single log line at `NGX_LOG_ERR`.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The configured endpoint URL is malformed or uses an unsupported scheme.
    #[error("invalid endpoint \"{input}\": {reason}")]
    InvalidEndpoint { input: std::string::String, reason: &'static str },

    /// TCP / Unix connection failed (network error, host unreachable, etc.).
    #[error("connection failed: {cause}")]
    Connection { cause: std::string::String },

    /// The server returned a non-2xx HTTP status.
    #[error("HTTP {code} response: {message}")]
    HttpStatus { code: u16, message: std::string::String },

    /// Reading or collecting the response body failed.
    #[error("response body read failed: {cause}")]
    BodyRead { cause: std::string::String },

    /// The operation exceeded the configured time limit.
    #[error("request timed out")]
    Timeout,

    /// TLS configuration error (bad cert path, SSL context init, etc.).
    #[error("TLS configuration error: {cause}")]
    TlsConfig { cause: std::string::String },
}

/// Sends a batch of OTLP/HTTP protobuf bytes to a collector endpoint.
///
/// Implementations are free to maintain a cached connection across calls.
/// A `send` failure must drop any cached connection so the next call attempts
/// a fresh connection.
///
/// # Note on `Send`
/// The `Send` bound is required so the impl can be stored in the export-loop
/// task (Step 9). In NGINX's single-threaded worker the bound is trivially
/// satisfied.
#[allow(async_fn_in_trait)]
pub trait Transport: Send {
    async fn send(&mut self, bytes: std::vec::Vec<u8>) -> Result<(), TransportError>;
}

pub use grpc::transport::GrpcTransport;
pub use hyper_http::HyperHttpTransport;
