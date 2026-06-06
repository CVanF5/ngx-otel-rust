// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Transport implementations: the network seam between the export loop and a
//! collector.
//!
//! [`HyperHttpTransport`] POSTs OTLP/HTTP protobuf bytes; [`GrpcTransport`]
//! sends OTLP/gRPC unary over h2c. Each exposes an inherent `send` (metrics)
//! plus a logs entry point; the export loop selects between them with the
//! `ExportTransport` enum. Plaintext TCP or Unix sockets today; TLS is planned
//! for both transports.

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

pub use grpc::transport::GrpcTransport;
pub use hyper_http::HyperHttpTransport;
