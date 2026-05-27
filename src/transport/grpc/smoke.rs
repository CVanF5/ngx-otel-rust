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
//!                             └─ MetricsServiceClient::with_origin(svc, origin).
//!                                   export(request).await
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

use http::uri::Uri;
use nginx_sys::ngx_log_t;

use crate::encoder::opentelemetry::proto::collector::metrics::v1::{
    ExportMetricsServiceRequest,
    metrics_service_client::MetricsServiceClient,
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
    let log_ptr = log.as_ptr();
    let io = connector.connect(&endpoint).await
        .map_err(|e| SmokeError::Connect(std::format!("{e:?}")))?;

    // 4. HTTP/2 handshake driven by NgxExecutor.  The handshake performs
    //    the SETTINGS exchange and returns:
    //      - `sender`: hyper's `SendRequest`, our handle for issuing requests.
    //      - `conn`: hyper's `Connection` — the user-side request dispatcher.
    //
    //    Hyper's docs require that `conn` be polled (typically by spawning
    //    `conn.await` on the same executor) for `sender` to actually send
    //    requests.  The underlying h2-frame-level ConnTask was already
    //    spawned by hyper internally inside `handshake.await` (via the
    //    `Http2ClientConnExec` impl on `NgxExecutor`); the `conn` we get
    //    back is the request-stream dispatcher on top of that.
    //
    //    The turbofish `<_, _, tonic::body::Body>` is required because the
    //    body type `B` can't be inferred from the handshake call alone —
    //    it's determined by what the returned `SendRequest` will be used
    //    for downstream (tonic's body type).
    //
    //    Background — what this fix relies on:
    //    h2's `Streams::drop` calls `task.wake()` while holding its
    //    `Arc<Mutex<Inner>>` guard.  Prior to the ngx-rust patch on the
    //    `ngx-otel-rust-deadlock-fix` branch (see ngx-rust/src/async_/
    //    spawn.rs::schedule), `Waker::wake()` synchronously re-polled the
    //    parked task on the same call stack, which then tried to re-acquire
    //    the same Mutex — deadlock.  Patched `schedule()` always defers
    //    via `ngx_post_event`, matching what every other "custom executor
    //    for h2" (Tokio's LocalSet, async-executor) does by design.
    let handshake_fut = hyper::client::conn::http2::handshake::<
        _,
        _,
        tonic::body::Body,
    >(NgxExecutor, io);

    ngx::ngx_log_debug!(log_ptr, "smoke: awaiting h2 handshake");
    let (sender, conn) = handshake_fut.await
        .map_err(|e| SmokeError::Handshake(std::format!("{e}")))?;
    ngx::ngx_log_debug!(log_ptr, "smoke: h2 handshake completed");

    // 5. Drive `conn` (the request-stream dispatcher) on the NGINX event
    //    loop so requests can complete.  Detached: we don't await its
    //    Output (which only resolves when the connection closes).
    ngx::async_::spawn(async move {
        let _ = conn.await;
    }).detach();

    // 6. Build the generated tonic gRPC client over our SendRequestService shim.
    //    ready() + path + codec are encapsulated inside the generated export() method.
    let mut client = MetricsServiceClient::with_origin(SendRequestService::new(sender), origin);

    // 7. Issue the unary `Export(ExportMetricsServiceRequest)` call.
    let request = tonic::Request::new(build_export_request());

    ngx::ngx_log_debug!(log_ptr, "smoke: awaiting client.export()");
    let _resp = client.export(request).await
        .map_err(|status| SmokeError::GrpcCall(std::format!("{status}")))?;
    ngx::ngx_log_debug!(log_ptr, "smoke: client.export() returned OK");

    Ok(())
}
