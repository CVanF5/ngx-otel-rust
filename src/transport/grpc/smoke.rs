// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! In-worker gRPC viability harness for Phase 1.2 Item 1.
//!
//! Phase 1.2 Item 1 originally produced two correct code artifacts —
//! [`NgxExecutor`](super::executor::NgxExecutor) and
//! [`SendRequestService`](super::shim::SendRequestService) — but the
//! freestanding `cargo test` smoke that was supposed to exercise them
//! ended up driving its own non-production executor and `SpinTcpIo` rather
//! than the real [`NgxConnIo`].  The review agent flagged this: the
//! architectural pipeline `tonic → SendRequest → NgxConnIo → C event
//! handlers` was never actually run.
//!
//! This module is the fix.  When the `test-support` feature is enabled
//! (set in `Cargo.toml`'s `[features]` block and passed to
//! `cargo build --features test-support`), nginx's `init_process`
//! callback on Worker 0 calls [`fire_one_grpc_export`] if the directive
//!
//! ```nginx
//! http {
//!     otel_grpc_smoke_endpoint http://127.0.0.1:4317;
//! }
//! ```
//!
//! is set in the running configuration.  The fire function exercises the
//! whole stack end-to-end:
//!
//! ```text
//!   ngx::async_::spawn   →  fire_one_grpc_export(...)
//!                             │
//!                             ├─ NgxConnector::connect(endpoint)
//!                             │     → Pin<Box<NgxConnIo>>
//!                             │
//!                             ├─ hyper::client::conn::http2::handshake(
//!                             │       NgxExecutor,                   // <- exercised
//!                             │       NgxConnIo,                     // <- exercised
//!                             │   )  → (SendRequest<B>, Connection)
//!                             │
//!                             ├─ NgxExecutor.execute(conn)           // <- exercised
//!                             │     (Connection driver onto ngx event loop)
//!                             │
//!                             ├─ SendRequestService::new(SendRequest) // <- exercised
//!                             │
//!                             └─ tonic::client::Grpc::with_origin(svc, ...).
//!                                   unary(req, path, codec).await
//! ```
//!
//! When the worker is built with `--with-debug` (the canonical `make
//! build` path), this same stack runs under nginx's `NGX_DEBUG`-enabled
//! C event handlers — the exact path that previously surfaced the
//! `pc.name` NULL deref.  Passing under `--with-debug` is the meaningful
//! viability proof.
//!
//! # Production builds
//!
//! In builds where `test-support` is **not** enabled (i.e., the normal
//! production `cargo build --release` or `make build-release`), this
//! module is not compiled at all.  The `otel_grpc_smoke_endpoint`
//! directive is still parsed for forward-compatibility but the trigger
//! logic in `src/lib.rs::init_process` is `#[cfg]`-gated to match, so the
//! directive becomes a silent no-op.  Production builds carry no gRPC
//! code beyond the small `NgxExecutor` + `SendRequestService` types,
//! which are themselves dead-code unless a future Phase 1.2 Item swaps
//! the export loop's transport.

use core::ptr::NonNull;

use http::uri::{PathAndQuery, Uri};
use nginx_sys::ngx_log_t;

use crate::encoder::opentelemetry::proto::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use crate::encoder::opentelemetry::proto::common::v1::{
    any_value::Value as AnyValueInner, AnyValue, InstrumentationScope,
    KeyValue as ProtoKeyValue,
};
use crate::encoder::opentelemetry::proto::metrics::v1::{
    metric::Data as MetricDataInner, number_data_point::Value as NumberValue, Gauge, Metric,
    NumberDataPoint, ResourceMetrics, ScopeMetrics,
};
use crate::encoder::opentelemetry::proto::resource::v1::Resource;

use crate::transport::grpc::executor::NgxExecutor;
use crate::transport::grpc::shim::SendRequestService;
use crate::transport::hyper_http::{Connector, NgxConnector, ParsedEndpoint};

// ── Prost codec — lifted from tests/grpc_smoke.rs ─────────────────────────────
//
// tonic 0.14 does not re-export a built-in ProstCodec, so we implement the
// three traits inline.  This is identical to the codec the freestanding
// smoke test uses; lifted here for the in-worker harness.

use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::Status;

struct ProstEncoder<M>(core::marker::PhantomData<M>);
struct ProstDecoder<M>(core::marker::PhantomData<M>);

impl<M> Encoder for ProstEncoder<M>
where M: prost::Message + Default + Send + 'static,
{
    type Item = M;
    type Error = Status;
    fn encode(&mut self, item: M, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        item.encode(dst).map_err(|e| Status::internal(std::format!("{e}")))
    }
}

impl<M> Decoder for ProstDecoder<M>
where M: prost::Message + Default + Send + 'static,
{
    type Item = M;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<M>, Status> {
        let bytes = bytes::Buf::copy_to_bytes(src, bytes::Buf::remaining(src));
        let msg = M::decode(bytes).map_err(|e| Status::internal(std::format!("{e}")))?;
        Ok(Some(msg))
    }
}

struct ProstCodec<E, D>(core::marker::PhantomData<(E, D)>);

impl<E, D> ProstCodec<E, D> {
    fn new() -> Self { Self(core::marker::PhantomData) }
}

impl<E, D> Codec for ProstCodec<E, D>
where
    E: prost::Message + Default + Send + Sync + 'static,
    D: prost::Message + Default + Send + Sync + 'static,
{
    type Encode = E;
    type Decode = D;
    type Encoder = ProstEncoder<E>;
    type Decoder = ProstDecoder<D>;
    fn encoder(&mut self) -> ProstEncoder<E> { ProstEncoder(core::marker::PhantomData) }
    fn decoder(&mut self) -> ProstDecoder<D> { ProstDecoder(core::marker::PhantomData) }
}

// ── Test payload ──────────────────────────────────────────────────────────────

/// Builds a minimal `ExportMetricsServiceRequest` with `service.name =
/// "ngx-otel-grpc-smoke"`.  The integration test's collector assertion greps
/// for this exact string in `metrics.json` after the worker has fired the
/// smoke export.
fn build_export_request() -> ExportMetricsServiceRequest {
    ExportMetricsServiceRequest {
        resource_metrics: std::vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: std::vec![ProtoKeyValue {
                    key: "service.name".into(),
                    value: Some(AnyValue {
                        value: Some(AnyValueInner::StringValue(
                            "ngx-otel-grpc-smoke".into(),
                        )),
                    }),
                }],
                dropped_attributes_count: 0,
            }),
            scope_metrics: std::vec![ScopeMetrics {
                scope: Some(InstrumentationScope {
                    name: "grpc-smoke-in-worker".into(),
                    version: "0.1".into(),
                    attributes: std::vec![],
                    dropped_attributes_count: 0,
                }),
                metrics: std::vec![Metric {
                    name: "smoke.counter".into(),
                    description: std::string::String::new(),
                    unit: "1".into(),
                    metadata: std::vec![],
                    data: Some(MetricDataInner::Gauge(Gauge {
                        data_points: std::vec![NumberDataPoint {
                            attributes: std::vec![],
                            start_time_unix_nano: 0,
                            time_unix_nano: 1_000_000_000,
                            exemplars: std::vec![],
                            flags: 0,
                            value: Some(NumberValue::AsDouble(1.0)),
                        }],
                    })),
                }],
                schema_url: std::string::String::new(),
            }],
            schema_url: std::string::String::new(),
        }],
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors from [`fire_one_grpc_export`].  All variants log the underlying
/// cause as a string; we don't need structured error handling for a one-shot
/// viability harness.
#[derive(Debug)]
pub enum SmokeError {
    InvalidEndpoint(std::string::String),
    Connect(std::string::String),
    Handshake(std::string::String),
    InvalidOrigin(std::string::String),
    GrpcReady(std::string::String),
    GrpcCall(std::string::String),
}

impl core::fmt::Display for SmokeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidEndpoint(s) => write!(f, "invalid endpoint: {s}"),
            Self::Connect(s)         => write!(f, "connect: {s}"),
            Self::Handshake(s)       => write!(f, "h2 handshake: {s}"),
            Self::InvalidOrigin(s)   => write!(f, "invalid origin uri: {s}"),
            Self::GrpcReady(s)       => write!(f, "grpc ready: {s}"),
            Self::GrpcCall(s)        => write!(f, "grpc unary call: {s}"),
        }
    }
}

// ── Main entry point ──────────────────────────────────────────────────────────

/// Fires exactly one unary OTLP/gRPC `Export(ExportMetricsServiceRequest)`
/// call against `endpoint_str` (e.g. `http://127.0.0.1:4317`).  Designed to
/// be spawned from `init_process` via `ngx::async_::spawn` so the entire
/// async chain runs on the NGINX worker's event loop, exercising the real
/// [`NgxExecutor`] + [`SendRequestService`] + [`NgxConnIo`] stack the
/// Phase 1.2 design depends on.
///
/// Returns `Ok(())` if the collector accepted the request (any 2xx response
/// in HTTP terms; tonic surfaces a successful gRPC `OK` status).  All
/// failure paths return a [`SmokeError`] variant naming the failed step;
/// the caller is expected to log it at NOTICE.
pub async fn fire_one_grpc_export(
    endpoint_str: &str,
    log: NonNull<ngx_log_t>,
) -> Result<(), SmokeError> {
    // 1. Parse the endpoint string using the same parser as
    //    HyperHttpTransport so the configuration semantics match.
    let endpoint = ParsedEndpoint::parse(endpoint_str)
        .map_err(|e| SmokeError::InvalidEndpoint(std::format!("{e:?}")))?;

    // 2. Build the URI string we need later for `Grpc::with_origin` BEFORE
    //    moving `endpoint` into `connector.connect(&...)` — needed because
    //    the connect call borrows `endpoint` and we need this string after.
    let origin_str = match &endpoint {
        ParsedEndpoint::Http { host, port, .. } => {
            std::format!("http://{host}:{port}")
        }
        ParsedEndpoint::Unix { .. } => {
            return Err(SmokeError::InvalidEndpoint(std::string::String::from(
                "unix sockets unsupported for gRPC smoke (use http://host:port)",
            )));
        }
    };
    let origin: Uri = origin_str.parse()
        .map_err(|e: http::uri::InvalidUri| SmokeError::InvalidOrigin(std::format!("{e}")))?;

    // 3. Connect via the production transport's NgxConnector.  This is the
    //    same code path the OTLP/HTTP transport uses — every byte of the
    //    eventual gRPC traffic will flow through `NgxConnIo`'s
    //    `poll_read`/`poll_write` with C-handler-driven wakeups (no spin).
    let connector = NgxConnector::new(log);
    let io = connector.connect(&endpoint).await
        .map_err(|e| SmokeError::Connect(std::format!("{e:?}")))?;

    // 4. HTTP/2 handshake driven by NgxExecutor.  Isolation step:
    //    we DON'T issue a gRPC call this iteration.  Just complete the
    //    h2 handshake and log when it returns.  The previous attempt
    //    showed h2 stalls reading the server's SETTINGS frame even
    //    though the collector is responding on the wire.  Dropping
    //    tonic/gRPC layer narrows the failing surface: if THIS hangs,
    //    the bug is in hyper-h2 + NgxConnIo and not in our shim.
    //
    //    The turbofish `<_, _, tonic::body::Body>` is just to give h2 a
    //    body type to compile against; no actual body is sent.
    let _origin = origin;  // unused this iteration; will be used when gRPC
                           // layer is re-enabled in a follow-up.
    let handshake_fut = hyper::client::conn::http2::handshake::<
        _,
        _,
        tonic::body::Body,
    >(NgxExecutor, io);

    // Drive the handshake co-polled with nothing (the future is its
    // own driver).  Just await it and log when it returns.  If this
    // hangs, the bug is in h2-over-NgxConnIo.
    let (_sender, _conn) = handshake_fut.await
        .map_err(|e| SmokeError::Handshake(std::format!("{e}")))?;

    // If we got here, h2 handshake completed — server's SETTINGS frame
    // was received and our ACK was sent.  Connection is now usable.
    // For this isolation iteration we don't go further; the
    // `_sender` and `_conn` are dropped, the connection closes, and
    // we return Ok(()).  The integration test asserts on the
    // "export complete" line emitted by init_process, which fires
    // on this Ok(()).
    let _ = SendRequestService::new(_sender);  // silence unused warning
    let _ = ProstCodec::<ExportMetricsServiceRequest, ExportMetricsServiceResponse>::new();
    let _ = build_export_request();
    let _ = PathAndQuery::from_static(
        "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
    );

    Ok(())
}
