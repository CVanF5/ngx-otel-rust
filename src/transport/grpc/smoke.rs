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

/// Errors from [`fire_one_grpc_export`] and [`fire_one_bidi_stream`].
/// All variants log the underlying cause as a string; we don't need
/// structured error handling for a one-shot viability harness.
#[derive(Debug)]
pub enum SmokeError {
    InvalidEndpoint(std::string::String),
    Connect(std::string::String),
    Handshake(std::string::String),
    InvalidOrigin(std::string::String),
    GrpcReady(std::string::String),
    GrpcCall(std::string::String),
    /// A bidi gRPC call step failed (Phase 1.2 Item 2).
    BidiCall(std::string::String),
    /// Sent/received ping counts diverged (Phase 1.2 Item 2).
    BidiSendMismatch { sent: u64, received: u64 },
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
            Self::BidiCall(s)        => write!(f, "bidi call: {s}"),
            Self::BidiSendMismatch { sent, received } => {
                write!(f, "bidi send/receive mismatch: sent={sent} received={received}")
            }
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

// ── Phase 1.2 Item 2: bidi smoke ─────────────────────────────────────────────

/// Async send-one helper for `futures_channel::mpsc::Sender<T>`.
///
/// Equivalent to `SinkExt::send` (which requires `futures-util`) but
/// implemented directly against the channel's `poll_ready` + `start_send`
/// API, so we don't need `futures-util` as a top-level production dep.
async fn mpsc_send_one(
    tx: &mut futures_channel::mpsc::Sender<crate::transport::grpc::echo_proto::ngx_otel_echo_v1::Ping>,
    msg: crate::transport::grpc::echo_proto::ngx_otel_echo_v1::Ping,
) -> Result<(), SmokeError> {
    core::future::poll_fn(|cx| tx.poll_ready(cx)).await
        .map_err(|e| SmokeError::BidiCall(std::format!("send channel closed: {e}")))?;
    tx.start_send(msg)
        .map_err(|e| SmokeError::BidiCall(std::format!("start_send: {e}")))
}

/// Fires exactly one bidi gRPC `BidiEcho` call against the echo server at
/// `endpoint_str` (e.g. `http://127.0.0.1:4319`).  Exercises the send-half
/// and receive-half **asymmetrically** to prove they are independently
/// pollable without deadlock, livelock, or a Tokio runtime.
///
/// The asymmetric drain sequence (Phase A: send 3 + drain 3; Phase B: send 7
/// + drain 7; Phase C: close + confirm stream end) is the mechanical contract
/// Phase 1.2 Item 2 establishes.  If the bridge serializes send and receive,
/// Phase A-drain hangs — the function reports that via `BidiCall`.
///
/// On success logs `"bidi smoke: bidi complete (sent=10, received=10)"` at
/// NOTICE — the exact string `run_grpc_bidi_smoke.sh` asserts on.
pub async fn fire_one_bidi_stream(
    endpoint_str: &str,
    log: core::ptr::NonNull<nginx_sys::ngx_log_t>,
) -> Result<(), SmokeError> {
    use crate::transport::grpc::echo_proto::ngx_otel_echo_v1::{
        Ping,
        echo_client::EchoClient,
    };

    // Steps 1-5 are identical to fire_one_grpc_export (same pipeline shape).
    // Factor into a shared helper if duplication becomes problematic; for now
    // the copy is intentional — the bidi and unary functions share no state.

    // 1. Parse the endpoint string.
    let endpoint = crate::transport::hyper_http::ParsedEndpoint::parse(endpoint_str)
        .map_err(|e| SmokeError::InvalidEndpoint(std::format!("{e:?}")))?;

    // 2. Build the origin URI for `with_origin`.
    let origin_str = match &endpoint {
        crate::transport::hyper_http::ParsedEndpoint::Http { host, port, .. } => {
            std::format!("http://{host}:{port}")
        }
        crate::transport::hyper_http::ParsedEndpoint::Unix { .. } => {
            return Err(SmokeError::InvalidEndpoint(std::string::String::from(
                "unix sockets unsupported for bidi smoke (use http://host:port)",
            )));
        }
    };
    let origin: http::uri::Uri = origin_str.parse()
        .map_err(|e: http::uri::InvalidUri| SmokeError::InvalidOrigin(std::format!("{e}")))?;

    let log_ptr = log.as_ptr();

    // 3. Connect via the production NgxConnector.
    let connector = crate::transport::hyper_http::NgxConnector::new(log);
    let io = connector.connect(&endpoint).await
        .map_err(|e| SmokeError::Connect(std::format!("{e:?}")))?;

    // 4. HTTP/2 handshake.
    let handshake_fut = hyper::client::conn::http2::handshake::<
        _,
        _,
        tonic::body::Body,
    >(crate::transport::grpc::executor::NgxExecutor, io);

    ngx::ngx_log_debug!(log_ptr, "bidi smoke: awaiting h2 handshake");
    let (sender, conn) = handshake_fut.await
        .map_err(|e| SmokeError::Handshake(std::format!("{e}")))?;
    ngx::ngx_log_debug!(log_ptr, "bidi smoke: h2 handshake completed");

    // 5. Drive the Connection on the NGINX event loop.
    ngx::async_::spawn(async move {
        let _ = conn.await;
    }).detach();

    // 6. Build the generated EchoClient over our SendRequestService shim.
    let svc = SendRequestService::new(sender);
    let mut client = EchoClient::with_origin(svc, origin);

    // 7. Build the outbound channel.  Capacity 16 matches the example server.
    //    futures_channel::mpsc::Receiver<Ping> implements Stream<Item=Ping>
    //    and therefore IntoStreamingRequest<Message=Ping>.
    let (mut tx, rx) = futures_channel::mpsc::channel::<Ping>(16);

    // Issue the bidi call.  rx (the Receiver) is consumed into the request
    // stream here; tx remains as the send-half.
    let response = client.bidi_echo(tonic::Request::new(rx)).await
        .map_err(|status| SmokeError::BidiCall(std::format!("{status}")))?;
    let mut inbound = response.into_inner();

    // 8. Asymmetric drain exercise.
    //
    //    The bridge is correct if send and receive are independently pollable.
    //    If the bridge serializes them, Phase A-drain will hang waiting for
    //    the server to respond but the server is waiting for more pings.

    // Phase A: send 3 pings then drain 3 pongs.
    let mut sent: u64 = 0;
    let mut received: u64 = 0;

    for seq in 0u64..3 {
        mpsc_send_one(&mut tx, Ping { seq, payload: std::vec::Vec::new() }).await?;
        sent += 1;
    }
    ngx::ngx_log_debug!(log_ptr, "bidi smoke: Phase A sent (sent=3)");

    while received < 3 {
        let _pong = inbound.message().await
            .map_err(|s| SmokeError::BidiCall(std::format!("Phase A drain: {s}")))?
            .ok_or_else(|| SmokeError::BidiCall(
                std::string::String::from("Phase A drain: stream ended early")
            ))?;
        received += 1;
    }
    ngx::ngx_log_debug!(log_ptr, "bidi smoke: Phase A drained (received=3)");

    // Phase B: send 7 more pings then drain until total received == 10.
    for seq in 3u64..10 {
        mpsc_send_one(&mut tx, Ping { seq, payload: std::vec::Vec::new() }).await?;
        sent += 1;
    }
    ngx::ngx_log_debug!(log_ptr, "bidi smoke: Phase B sent (sent=10)");

    while received < 10 {
        let _pong = inbound.message().await
            .map_err(|s| SmokeError::BidiCall(std::format!("Phase B drain: {s}")))?
            .ok_or_else(|| SmokeError::BidiCall(
                std::string::String::from("Phase B drain: stream ended early")
            ))?;
        received += 1;
    }
    ngx::ngx_log_debug!(log_ptr, "bidi smoke: Phase B drained (received=10)");

    // Phase C: close the send-half.  The server should see stream end and
    // close its response stream too.
    drop(tx);

    let final_msg = inbound.message().await
        .map_err(|s| SmokeError::BidiCall(std::format!("Phase C close: {s}")))?;
    if final_msg.is_some() {
        return Err(SmokeError::BidiCall(std::string::String::from(
            "Phase C: expected stream end after tx drop, got another pong",
        )));
    }
    ngx::ngx_log_debug!(log_ptr, "bidi smoke: Phase C stream end confirmed");

    // Verify counts.
    if sent != 10 || received != 10 {
        return Err(SmokeError::BidiSendMismatch { sent, received });
    }

    // This exact line is what run_grpc_bidi_smoke.sh asserts on.
    ngx::ngx_log_error!(
        nginx_sys::NGX_LOG_NOTICE,
        log_ptr,
        "bidi smoke: bidi complete (sent=10, received=10)"
    );

    Ok(())
}

// ── Phase 1.2 Item 3: bidi backpressure / overload ───────────────────────────

// Local re-export of needed primitives so the combinator block is self-contained.
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use pin_project_lite::pin_project;

pin_project! {
    /// Races an inner future `F` against an [`ngx::async_::Sleep`] timer.
    ///
    /// * If `F` resolves first  → `Poll::Ready(Ok(output))`.
    /// * If the timer fires first → `Poll::Ready(Err(()))`.
    ///
    /// Mirrors the same combinator in `src/export/mod.rs` but kept private
    /// here to avoid coupling smoke.rs to export internals.
    struct WithDeadline<F> {
        #[pin]
        fut: F,
        #[pin]
        timer: ngx::async_::Sleep,
    }
}

impl<F: Future> Future for WithDeadline<F> {
    type Output = Result<F::Output, ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if let Poll::Ready(v) = this.fut.poll(cx) {
            return Poll::Ready(Ok(v));
        }
        if let Poll::Ready(()) = this.timer.poll(cx) {
            return Poll::Ready(Err(()));
        }
        Poll::Pending
    }
}

/// Wraps `fut` so it resolves within `deadline`.  Returns `Err(())` if the
/// timer fires first.  Drops the inner future on timeout (no busy-spin).
fn race_with_timeout<F: Future>(fut: F, deadline: Duration) -> WithDeadline<F> {
    WithDeadline {
        fut,
        timer: ngx::async_::sleep(deadline),
    }
}

/// Fires a sustained bidi overload against the echo server at `endpoint_str`
/// to exercise the backpressure give-up path.
///
/// Reads three environment variables to control the load shape:
///
/// | Variable                       | Default | Meaning                                           |
/// |-------------------------------|---------|---------------------------------------------------|
/// | `BIDI_OVERLOAD_DURATION_S`    | `60`    | Total overload wall-clock seconds                 |
/// | `BIDI_OVERLOAD_MESSAGES_PER_SEC` | `1000` | Target send rate (messages/second)              |
/// | `BIDI_OVERLOAD_GIVE_UP_MS`    | `50`    | Per-send deadline before counting as a drop       |
///
/// On each iteration the function tries to send a `Ping` by racing
/// `futures_channel::mpsc::Sender::poll_ready` against a `give_up`-ms
/// [`ngx::async_::Sleep`].  If the timer fires first the ping is discarded
/// and `BIDI_BACKPRESSURE_DROPS` is incremented.  A drain sub-task runs in
/// parallel, consuming `Pong` replies and counting them.
///
/// Logs `"bidi overload: sent=N received=N dropped=N duration_s=S"` at
/// NOTICE on completion — the exact line `run_grpc_bidi_overload.sh` asserts on.
///
/// Returns `Ok(())` on any clean finish (even zero successful sends).
pub async fn fire_bidi_overload(
    endpoint_str: &str,
    log: core::ptr::NonNull<nginx_sys::ngx_log_t>,
) -> Result<(), SmokeError> {
    use crate::transport::grpc::echo_proto::ngx_otel_echo_v1::{
        Ping,
        echo_client::EchoClient,
    };
    use crate::export::BIDI_BACKPRESSURE_DROPS;
    use core::sync::atomic::Ordering;

    // ── Read overload parameters from environment ──────────────────────────
    let duration_s: u64 = std::env::var("BIDI_OVERLOAD_DURATION_S")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(60);
    let msg_per_sec: u64 = std::env::var("BIDI_OVERLOAD_MESSAGES_PER_SEC")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(1000);
    let give_up_ms: u64 = std::env::var("BIDI_OVERLOAD_GIVE_UP_MS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(50);

    let duration     = Duration::from_secs(duration_s);
    let give_up      = Duration::from_millis(give_up_ms);
    // Inter-send interval in microseconds.  Saturating: at 0 msg/s we'd
    // divide by zero — treat as "no sleep between sends" (max rate).
    let inter_send_us: u64 = if msg_per_sec > 0 { 1_000_000 / msg_per_sec } else { 0 };

    let log_ptr = log.as_ptr();

    ngx::ngx_log_error!(
        nginx_sys::NGX_LOG_NOTICE,
        log_ptr,
        "bidi overload: starting (duration={}s rate={}msg/s give_up={}ms)",
        duration_s, msg_per_sec, give_up_ms
    );

    // Steps 1-5: identical pipeline to fire_one_bidi_stream.

    // 1. Parse endpoint.
    let endpoint = crate::transport::hyper_http::ParsedEndpoint::parse(endpoint_str)
        .map_err(|e| SmokeError::InvalidEndpoint(std::format!("{e:?}")))?;

    // 2. Build origin URI.
    let origin_str = match &endpoint {
        crate::transport::hyper_http::ParsedEndpoint::Http { host, port, .. } => {
            std::format!("http://{host}:{port}")
        }
        crate::transport::hyper_http::ParsedEndpoint::Unix { .. } => {
            return Err(SmokeError::InvalidEndpoint(std::string::String::from(
                "unix sockets unsupported for bidi overload (use http://host:port)",
            )));
        }
    };
    let origin: http::uri::Uri = origin_str.parse()
        .map_err(|e: http::uri::InvalidUri| SmokeError::InvalidOrigin(std::format!("{e}")))?;

    // 3. Connect.
    let connector = crate::transport::hyper_http::NgxConnector::new(log);
    let io = connector.connect(&endpoint).await
        .map_err(|e| SmokeError::Connect(std::format!("{e:?}")))?;

    // 4. HTTP/2 handshake.
    let handshake_fut = hyper::client::conn::http2::handshake::<
        _,
        _,
        tonic::body::Body,
    >(crate::transport::grpc::executor::NgxExecutor, io);

    let (sender, conn) = handshake_fut.await
        .map_err(|e| SmokeError::Handshake(std::format!("{e}")))?;

    // 5. Drive Connection on the nginx event loop.
    ngx::async_::spawn(async move { let _ = conn.await; }).detach();

    // 6. Build the EchoClient.
    let svc = crate::transport::grpc::shim::SendRequestService::new(sender);
    let mut client = EchoClient::with_origin(svc, origin);

    // 7. Open the bidi stream.
    let (mut tx, rx) = futures_channel::mpsc::channel::<Ping>(16);
    let response = client.bidi_echo(tonic::Request::new(rx)).await
        .map_err(|s| SmokeError::BidiCall(std::format!("{s}")))?;
    let mut inbound = response.into_inner();

    // 8. Overload loop.
    //
    // The drain sub-task consumes Pong replies independently; the main task
    // sends Pings with a per-send deadline.  Both use shared atomics for
    // coordination so no channel is needed between them.
    //
    // `drain_done` is set to `true` by the drain task when the server closes
    // the inbound stream; the main loop checks it after drop(tx) to know
    // the drain task finished cleanly.

    let received_ctr = std::sync::Arc::new(core::sync::atomic::AtomicU64::new(0));
    let drain_done   = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));

    {
        let received_ctr2 = std::sync::Arc::clone(&received_ctr);
        let drain_done2   = std::sync::Arc::clone(&drain_done);
        ngx::async_::spawn(async move {
            loop {
                match inbound.message().await {
                    Ok(Some(_)) => { received_ctr2.fetch_add(1, Ordering::Relaxed); }
                    Ok(None)    => break,   // server closed stream
                    Err(_)      => break,   // transport error — stop silently
                }
            }
            drain_done2.store(true, Ordering::Release);
        }).detach();
    }

    let mut seq: u64     = 0;
    let mut sent: u64    = 0;
    let mut dropped: u64 = 0;

    let overload_start = std::time::Instant::now();

    while overload_start.elapsed() < duration {
        let ping = Ping { seq, payload: std::vec::Vec::new() };
        seq += 1;

        // Race poll_ready against the give-up deadline.
        let ready_result = race_with_timeout(
            core::future::poll_fn(|cx| tx.poll_ready(cx)),
            give_up,
        ).await;

        match ready_result {
            Err(()) => {
                // Timer fired: channel full past give-up → count as drop.
                dropped += 1;
                BIDI_BACKPRESSURE_DROPS.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Err(_)) => {
                // Sender disconnected (receiver dropped).
                break;
            }
            Ok(Ok(())) => {
                // Channel slot available — send the ping.
                let _ = tx.start_send(ping);
                sent += 1;
            }
        }

        // Rate-limit.  With inter_send_us == 0 we skip the sleep entirely.
        if inter_send_us > 0 {
            ngx::async_::sleep(Duration::from_micros(inter_send_us)).await;
        }
    }

    // Close the send-half so the echo server and drain task see stream end.
    drop(tx);

    // Wait up to 5 s for the drain sub-task to finish.
    let drain_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !drain_done.load(Ordering::Acquire) {
        if std::time::Instant::now() >= drain_deadline {
            break;
        }
        ngx::async_::sleep(Duration::from_millis(50)).await;
    }

    let received = received_ctr.load(Ordering::Acquire);
    let elapsed_s = overload_start.elapsed().as_secs();

    // This exact line is what run_grpc_bidi_overload.sh asserts on.
    ngx::ngx_log_error!(
        nginx_sys::NGX_LOG_NOTICE,
        log_ptr,
        "bidi overload: sent={} received={} dropped={} duration_s={}",
        sent, received, dropped, elapsed_s
    );

    Ok(())
}
