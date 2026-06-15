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
pub mod tls;

use core::time::Duration;
use thiserror::Error;

/// The collector's verdict on a delivered batch, normalized across all wire
/// protocols.
///
/// Protocol-agnostic **by construction**: the policy engine matches on this and
/// never on a protocol-specific status code. Each wire protocol (OTLP/HTTP,
/// OTLP/gRPC, OTAP, …) is an *adapter* that maps its native status into this
/// neutral verdict — no protocol is the reference or the default. This type
/// lives in the transport-neutral module (alongside [`TransportError`]) so the
/// policy can be expressed once against it, not inside any OTLP-specific code.
///
/// Note the separation of concerns from [`TransportError`]:
/// - [`TransportError`] = "we could not complete an exchange with the peer"
///   (connection failed, timeout). The peer rendered *no* verdict.
/// - `DeliveryOutcome` = "the peer received the exchange and rendered a verdict."
///
/// A send therefore returns `Result<DeliveryOutcome, TransportError>`:
/// `Err` = couldn't talk; `Ok(outcome)` = the peer's verdict.
///
/// The status-classification adapters and the outcome-driven policy engine are
/// added in later steps; until then every successful send maps to
/// [`DeliveryOutcome::Accepted`] and the drain loop treats any `Ok(outcome)`
/// exactly as it treated today's `Ok(())` (release).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// Fully accepted. Release the batch.
    Accepted,
    /// Accepted, but the peer reported it dropped `rejected` records it could
    /// not store. Counts only — the peer does not identify *which* records, so
    /// this drives a self-metric, not a selective resend.
    PartialReject {
        /// Number of records the peer reported it rejected.
        rejected: u64,
    },
    /// Transient failure. Re-queue; if the peer supplied a backoff hint, do not
    /// re-drain this signal before it elapses.
    Retryable {
        /// Peer-supplied backoff hint, if any (`Retry-After` / `RetryInfo` /
        /// `grpc-retry-pushback-ms`). `None` → the policy engine supplies
        /// exponential backoff.
        retry_after: Option<Duration>,
    },
    /// Permanent rejection (the batch will never be accepted as-is). Drop and
    /// count; do NOT retry.
    Permanent,
    /// Authentication / authorization failure. Stop sending and surface; do not
    /// blind-retry.
    Unauthorized,
}

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
