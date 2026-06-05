// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Production OTLP/gRPC transport: `GrpcTransport<C>` implements [`Transport`]
//! by issuing a unary `MetricsService.Export` call over a persistent h2/tonic
//! connection driven by the NGINX event loop.  No Tokio runtime.
//!
//! # Connection lifecycle
//!
//! The h2 connection is established lazily on the first [`Transport::send`]
//! call and reused across subsequent calls.  If any call fails, the client
//! is dropped so the next [`Transport::send`] reconnects fresh.  This matches
//! the reconnect-on-failure parity expected of the HTTP transport.
//!
//! # No Tokio runtime
//!
//! The h2 stack is driven via `NgxExecutor` + `ngx::async_::spawn` — the
//! same pattern as `smoke.rs:200-271`.  No `tokio::runtime`, no
//! `tokio::spawn`, no `block_on`.
//!
//! # Encode → decode round-trip
//!
//! The incoming `bytes` are an already-encoded `ExportMetricsServiceRequest`
//! (the same bytes the HTTP path POSTs).  `prost::Message::decode` recovers
//! the typed struct, which is then passed to `client.export()`.  The encode
//! → decode round-trip is cold-path and cheap; a zero-copy codec optimisation
//! is deferred to a later phase.

use core::ptr::NonNull;

use http::uri::Uri;
use nginx_sys::ngx_log_t;
use prost::Message;

use crate::encoder::opentelemetry::proto::collector::logs::v1::{
    logs_service_client::LogsServiceClient, ExportLogsServiceRequest,
};
use crate::encoder::opentelemetry::proto::collector::metrics::v1::{
    metrics_service_client::MetricsServiceClient, ExportMetricsServiceRequest,
};
use crate::transport::grpc::executor::NgxExecutor;
use crate::transport::grpc::shim::SendRequestService;
use crate::transport::hyper_http::{Connector, NgxConnector, ParsedEndpoint};
use crate::transport::{Transport, TransportError};

// ── GrpcTransport<C> ─────────────────────────────────────────────────────────

/// OTLP/gRPC production transport.
///
/// Generic over the connector so tests can inject a `SpinConnector`-backed
/// variant; the production path uses
/// [`GrpcTransport::<NgxConnector>::with_ngx_log`].
// `Connector` is intentionally crate-internal (its `connect` signature also
// references the crate-internal `ParsedEndpoint`); this struct is `pub` only so
// integration tests can construct it. Widening `Connector`/`ParsedEndpoint` to
// `pub` would leak internals in a crate with no real public API (cdylib), so
// allow the private-bound lint here and on the inherent impl below.
#[allow(private_bounds)]
pub struct GrpcTransport<C: Connector> {
    /// Parsed endpoint (host + port used by `connector.connect`).
    endpoint: ParsedEndpoint,
    /// `http://host:port` URI passed to `MetricsServiceClient::with_origin`.
    /// Stored once at construction to avoid re-parsing on every send.
    origin: Uri,
    /// Connector used to open new connections (NgxConnector in production).
    connector: C,
    /// Cached gRPC metrics client over the persistent h2 connection.
    /// `None` on construction and after any failed `send`; rebuilt lazily.
    client: Option<MetricsServiceClient<SendRequestService<tonic::body::Body>>>,
    /// Cached gRPC logs client (Phase 2.1).  Uses a separate h2 connection;
    /// a future optimisation could share the sender via `SendRequest::clone()`.
    logs_client: Option<LogsServiceClient<SendRequestService<tonic::body::Body>>>,
}

// SAFETY: `GrpcTransport` is only used from NGINX's single-threaded exporter
// event loop (same reasoning as `NgxConnIo` and `NgxConnector`).
unsafe impl<C: Connector + Send> Send for GrpcTransport<C> {}

impl<C: Connector + core::fmt::Debug> core::fmt::Debug for GrpcTransport<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GrpcTransport")
            .field("origin", &self.origin)
            .field("connector", &self.connector)
            .field("connected", &self.client.is_some())
            .finish()
    }
}

// ── Constructors ─────────────────────────────────────────────────────────────

/// Production constructor — uses [`NgxConnector`] with nginx event integration.
impl GrpcTransport<NgxConnector> {
    /// Build a `GrpcTransport` pointing at `endpoint_str`.
    ///
    /// `endpoint_str` must be `http://host:port` (no path component; the gRPC
    /// origin is host:port only, not `/v1/metrics`).  Unix socket endpoints
    /// are rejected with [`TransportError::InvalidEndpoint`].
    ///
    /// The connection is NOT established here; it is deferred to the first
    /// `send` call (lazy connect).
    pub fn with_ngx_log(
        endpoint_str: &str,
        log: NonNull<ngx_log_t>,
        resolver: Option<core::ptr::NonNull<nginx_sys::ngx_resolver_t>>,
        resolver_timeout: nginx_sys::ngx_msec_t,
    ) -> Result<Self, TransportError> {
        Self::with_connector(
            endpoint_str,
            NgxConnector::with_resolver(log, resolver, resolver_timeout),
        )
    }
}

#[allow(private_bounds)] // see note on the struct above
impl<C: Connector> GrpcTransport<C> {
    /// Generic constructor (used by `with_ngx_log` and may be used by tests).
    pub(crate) fn with_connector(endpoint_str: &str, connector: C) -> Result<Self, TransportError> {
        let endpoint = ParsedEndpoint::parse(endpoint_str)?;

        // Build the origin URI: `http://host:port` (no path).
        // This is what tonic's `MetricsServiceClient::with_origin` expects.
        let origin_str = match &endpoint {
            ParsedEndpoint::Http { host, port, .. } => {
                std::format!("http://{host}:{port}")
            }
            ParsedEndpoint::Unix { .. } => {
                return Err(TransportError::InvalidEndpoint {
                    input: std::string::String::from(endpoint_str),
                    reason:
                        "gRPC transport requires http://host:port; Unix sockets are not supported",
                });
            }
        };

        let origin: Uri = origin_str.parse().map_err(|_: http::uri::InvalidUri| {
            TransportError::InvalidEndpoint {
                input: std::string::String::from(endpoint_str),
                reason: "gRPC: could not parse http://host:port as a valid URI",
            }
        })?;

        Ok(Self { endpoint, origin, connector, client: None, logs_client: None })
    }
}

// ── Transport impl ────────────────────────────────────────────────────────────

impl<C: Connector + Send> Transport for GrpcTransport<C> {
    async fn send(&mut self, bytes: std::vec::Vec<u8>) -> Result<(), TransportError> {
        // ── Decode bytes → typed request ──────────────────────────────────
        //
        // The encoder (OtlpHttpEncoder) emits a bare ExportMetricsServiceRequest
        // protobuf (verified by encoder::tests::round_trip_produces_valid_protobuf).
        // Decoding here is cold-path and cheap (~microseconds for typical batches).
        let req = ExportMetricsServiceRequest::decode(bytes.as_slice()).map_err(|e| {
            TransportError::Connection {
                cause: std::format!(
                    "gRPC transport: failed to decode ExportMetricsServiceRequest: {e}"
                ),
            }
        })?;

        // ── Lazy connect ──────────────────────────────────────────────────
        //
        // If we don't have a live client (first send, or after a prior failure
        // dropped the connection), build one now.  This mirrors the construction
        // in smoke.rs:200-271.
        if self.client.is_none() {
            // 1. Connect via the configured connector (NgxConnector in production).
            let io = self.connector.connect(&self.endpoint).await?;

            // 2. HTTP/2 handshake driven by NgxExecutor.
            //    Turbofish `<_, _, tonic::body::Body>` required so hyper knows
            //    the body type the returned SendRequest will be used for.
            let (sender, conn) =
                hyper::client::conn::http2::handshake::<_, _, tonic::body::Body>(NgxExecutor, io)
                    .await
                    .map_err(|e| TransportError::Connection {
                        cause: std::format!("gRPC h2 handshake failed: {e}"),
                    })?;

            // 3. Drive `conn` (the request-stream dispatcher) on the NGINX event loop.
            //    Detached: we don't need to await its completion; it runs until the
            //    connection closes (at which point it resolves and the task is cleaned up).
            ngx::async_::spawn(async move {
                let _ = conn.await;
            })
            .detach();

            // 4. Build the tonic gRPC client over our SendRequestService shim.
            self.client = Some(MetricsServiceClient::with_origin(
                SendRequestService::new(sender),
                self.origin.clone(),
            ));
        }

        // ── Issue unary Export ────────────────────────────────────────────
        //
        // Take ownership of the client (Option::take) so there is no
        // borrow of `self.client` across the `.await` point, allowing us to
        // either put it back (on success) or drop it (on failure) afterward.
        let mut client = self.client.take().expect("just connected above");
        let result = client.export(tonic::Request::new(req)).await;

        match result {
            Ok(_resp) => {
                // Connection still alive — store the client back for reuse.
                self.client = Some(client);
                Ok(())
            }
            Err(status) => {
                // `client` is dropped here (not stored back), forcing a fresh
                // reconnect on the next `send`.  This matches the reconnect-on-
                // failure parity with HyperHttpTransport (which opens a new
                // connection on every send).
                Err(TransportError::Connection {
                    cause: std::format!("gRPC Export RPC failed: {status}"),
                })
            }
        }
    }
}

// ── Logs send (Phase 2.1) ─────────────────────────────────────────────────────

#[allow(private_bounds)]
impl<C: Connector + Send> GrpcTransport<C> {
    /// Send an `ExportLogsServiceRequest` (already prost-encoded) to the
    /// `LogsService/Export` RPC.
    ///
    /// Mirrors [`Transport::send`] but decodes `ExportLogsServiceRequest` and
    /// uses the `LogsServiceClient`.  Drops and re-creates the logs client on
    /// failure (same reconnect-on-failure parity as the metrics client).
    pub async fn send_logs(
        &mut self,
        bytes: std::vec::Vec<u8>,
    ) -> Result<(), crate::transport::TransportError> {
        use crate::transport::TransportError;

        let req = ExportLogsServiceRequest::decode(bytes.as_slice()).map_err(|e| {
            TransportError::Connection {
                cause: std::format!(
                    "gRPC logs transport: failed to decode ExportLogsServiceRequest: {e}"
                ),
            }
        })?;

        if self.logs_client.is_none() {
            let io = self.connector.connect(&self.endpoint).await?;
            let (sender, conn) = hyper::client::conn::http2::handshake::<_, _, tonic::body::Body>(
                crate::transport::grpc::executor::NgxExecutor,
                io,
            )
            .await
            .map_err(|e| TransportError::Connection {
                cause: std::format!("gRPC logs h2 handshake failed: {e}"),
            })?;
            ngx::async_::spawn(async move {
                let _ = conn.await;
            })
            .detach();
            self.logs_client = Some(LogsServiceClient::with_origin(
                crate::transport::grpc::shim::SendRequestService::new(sender),
                self.origin.clone(),
            ));
        }

        let mut client = self.logs_client.take().expect("just connected above");
        let result = client.export(tonic::Request::new(req)).await;

        match result {
            Ok(_resp) => {
                self.logs_client = Some(client);
                Ok(())
            }
            Err(status) => Err(TransportError::Connection {
                cause: std::format!("gRPC LogsService/Export RPC failed: {status}"),
            }),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::GrpcTransport;
    use crate::transport::hyper_http::NgxConnector;
    use crate::transport::TransportError;

    /// Type-level check: `GrpcTransport<NgxConnector>` is constructible from
    /// a valid endpoint string.  No live collector required — this only tests
    /// the parse/construction path.
    #[test]
    fn grpc_transport_valid_endpoint_parses() {
        // Safety: we never actually use this pointer in the test; we only
        // construct GrpcTransport to verify the parse + URI build succeeds.
        let log_ptr = core::ptr::NonNull::dangling();
        let t = GrpcTransport::<NgxConnector>::with_ngx_log("http://127.0.0.1:4317", log_ptr, None, 0);
        assert!(t.is_ok(), "valid http://host:port endpoint must parse OK");
    }

    /// Unix socket endpoints must be rejected with `InvalidEndpoint`.
    #[test]
    fn grpc_transport_rejects_unix_endpoint() {
        let log_ptr = core::ptr::NonNull::dangling();
        let result = GrpcTransport::<NgxConnector>::with_ngx_log("unix:///tmp/otel.sock", log_ptr, None, 0);
        assert!(
            matches!(result, Err(TransportError::InvalidEndpoint { .. })),
            "unix socket endpoints must be rejected for gRPC transport"
        );
    }

    /// HTTPS endpoints must be rejected (not yet implemented).
    #[test]
    fn grpc_transport_rejects_https_endpoint() {
        let log_ptr = core::ptr::NonNull::dangling();
        let result = GrpcTransport::<NgxConnector>::with_ngx_log("https://127.0.0.1:4317", log_ptr, None, 0);
        assert!(result.is_err(), "https:// endpoints must fail (TLS not implemented)");
    }

    /// `GrpcTransport<NgxConnector>` must satisfy the `Transport + Send` bounds
    /// required by the export loop.
    #[test]
    fn grpc_transport_satisfies_transport_send_bounds() {
        fn assert_transport_send<T: crate::transport::Transport + Send>() {}
        assert_transport_send::<GrpcTransport<NgxConnector>>();
    }
}
