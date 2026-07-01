// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Unary OTLP/gRPC smoke test.
//!
//! Drives a real `ExportMetricsServiceRequest` over HTTP/2 to a local OTel
//! collector using `hyper` + `tonic` — **no Tokio runtime**.  The futures are
//! driven by a single-threaded spin-loop executor (`TaskQueueExecutor`) that
//! stores background tasks in a `VecDeque` and re-polls them on every
//! iteration.
//!
//! # Prerequisites
//!
//! The OTel collector container must be running on `127.0.0.1:4317`:
//!
//! ```sh
//! docker compose -f test-harness/docker-compose.yml up -d
//! ```
//!
//! # Running
//!
//! ```sh
//! NGINX_SOURCE_DIR=../nginx NGINX_BUILD_DIR=../nginx/objs \
//! cargo test --features test-support --test grpc_smoke -- --ignored
//! ```
//!
//! # Verification
//!
//! After the test completes check that the collector received the payload:
//!
//! ```sh
//! tail -5 test-harness/logs/metrics.json | grep ngx-otel-grpc-smoke
//! ```

// Pull in NGINX C-symbol stubs required at link time on macOS flat-namespace.
mod support;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::Future;
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::time::Duration;

use ngx_http_otel_module::transport::grpc::shim::SendRequestService;
use ngx_http_otel_module::transport::hyper_http::SpinTcpIo;

// Mirrors the include! hierarchy from src/encoder/mod.rs so the generated
// code's `super::super::super::metrics::v1::...` cross-references resolve at
// the correct nesting depth.
mod opentelemetry {
    pub mod proto {
        pub mod common {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/opentelemetry.proto.common.v1.rs"));
            }
        }
        pub mod resource {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/opentelemetry.proto.resource.v1.rs"));
            }
        }
        pub mod metrics {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/opentelemetry.proto.metrics.v1.rs"));
            }
        }
        pub mod collector {
            pub mod metrics {
                pub mod v1 {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/opentelemetry.proto.collector.metrics.v1.rs"
                    ));
                }
            }
        }
    }
}

use opentelemetry::proto::collector::metrics::v1::{
    metrics_service_client::MetricsServiceClient, ExportMetricsServiceRequest,
};
use opentelemetry::proto::common::v1::{
    any_value::Value as AnyValueInner, AnyValue, InstrumentationScope, KeyValue as ProtoKeyValue,
};
use opentelemetry::proto::metrics::v1::{
    metric::Data as MetricDataInner, number_data_point::Value as NumberValue, Gauge, Metric,
    NumberDataPoint, ResourceMetrics, ScopeMetrics,
};
use opentelemetry::proto::resource::v1::Resource;

// Collects futures in an `Rc<RefCell<VecDeque>>` rather than spawning to a
// thread pool; `block_on_with_tasks` drains and polls the queue each
// spin-loop iteration. Intentionally `!Send + !Sync`: `Http2ClientConnExec`
// doesn't require `E: Send`, and all driving happens on one test thread.
type BoxFuture = Pin<Box<dyn Future<Output = ()> + 'static>>;

#[derive(Clone)]
struct TaskQueueExecutor {
    // Newly spawned futures waiting to be moved into `running`.
    queue: Rc<RefCell<VecDeque<BoxFuture>>>,
    // Futures polled at least once and still pending.
    running: Rc<RefCell<Vec<BoxFuture>>>,
}

impl TaskQueueExecutor {
    fn new() -> Self {
        Self {
            queue: Rc::new(RefCell::new(VecDeque::new())),
            running: Rc::new(RefCell::new(Vec::new())),
        }
    }
}

impl<F> hyper::rt::Executor<F> for TaskQueueExecutor
where
    F: Future<Output = ()> + 'static,
{
    fn execute(&self, fut: F) {
        self.queue.borrow_mut().push_back(Box::pin(fut));
    }
}

/// Drive `fut` to completion, polling all background tasks in `exec` on every
/// iteration. No-op waker; progress relies on the spin loop re-polling every
/// task unconditionally, so `SpinTcpIo`'s `wake_by_ref()` on `WouldBlock` is
/// safe (the loop retries immediately regardless). 30 s wall-clock deadline —
/// generous for a slow CI box, still catches a genuinely stalled collector.
fn block_on_with_tasks<F: Future>(exec: &TaskQueueExecutor, fut: F) -> F::Output {
    unsafe fn noop_clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    unsafe fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);

    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "block_on_with_tasks: future did not complete within 30 s — \
             collector may have stalled or the connection is hung"
        );

        exec.running.borrow_mut().extend(exec.queue.borrow_mut().drain(..));

        // Take ownership before polling: polling may call execute() which
        // borrows exec.queue — a *different* RefCell, so no borrow conflict.
        let mut tasks = std::mem::take(&mut *exec.running.borrow_mut());
        tasks.retain_mut(|t| t.as_mut().poll(&mut cx).is_pending());
        tasks.extend(exec.queue.borrow_mut().drain(..));
        *exec.running.borrow_mut() = tasks;

        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(val) => return val,
            Poll::Pending => {
                exec.running.borrow_mut().extend(exec.queue.borrow_mut().drain(..));
                std::thread::yield_now();
            }
        }
    }
}

fn build_export_request() -> ExportMetricsServiceRequest {
    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: vec![ProtoKeyValue {
                    key: "service.name".into(),
                    value: Some(AnyValue {
                        value: Some(AnyValueInner::StringValue("ngx-otel-grpc-smoke".into())),
                    }),
                }],
                dropped_attributes_count: 0,
            }),
            scope_metrics: vec![ScopeMetrics {
                scope: Some(InstrumentationScope {
                    name: "grpc-smoke-test".into(),
                    version: "0.1".into(),
                    attributes: vec![],
                    dropped_attributes_count: 0,
                }),
                metrics: vec![Metric {
                    name: "smoke.counter".into(),
                    description: String::new(),
                    unit: "1".into(),
                    metadata: vec![],
                    data: Some(MetricDataInner::Gauge(Gauge {
                        data_points: vec![NumberDataPoint {
                            attributes: vec![],
                            start_time_unix_nano: 0,
                            time_unix_nano: 1_000_000_000,
                            exemplars: vec![],
                            flags: 0,
                            value: Some(NumberValue::AsDouble(1.0)),
                        }],
                    })),
                }],
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    }
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires OTel collector at 127.0.0.1:4317  (run with -- --ignored)"]
fn grpc_smoke_unary_export() {
    // Read/write timeouts (matching block_on_with_tasks's 30s deadline) make a
    // collector that accepts then stalls on I/O return a socket error instead
    // of blocking the spin loop forever.
    let addr: SocketAddr = "127.0.0.1:4317".parse().unwrap();
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .expect("cannot connect to 127.0.0.1:4317 — start OTel collector first");
    stream.set_read_timeout(Some(Duration::from_secs(30))).expect("set_read_timeout must succeed");
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .expect("set_write_timeout must succeed");
    stream.set_nonblocking(true).unwrap();
    let io = SpinTcpIo::new(stream);

    // During h2 handshake hyper calls exec.execute(ConnTask) to spawn the
    // connection driver, which then lives in exec.running for the test.
    let exec = TaskQueueExecutor::new();

    // Turbofish required: body type `B` isn't inferable from the handshake
    // call alone — it's determined by what `SendRequest` is later used for.
    let handshake_fut =
        hyper::client::conn::http2::handshake::<_, _, tonic::body::Body>(exec.clone(), io);

    let (sender, conn) =
        block_on_with_tasks(&exec, handshake_fut).expect("HTTP/2 handshake failed");

    // Drive the Connection (h2 dispatcher) as a background task; the TCP I/O
    // driver (ConnTask) is already in exec.running from the handshake above.
    exec.queue.borrow_mut().push_back(Box::pin(async move {
        let _ = conn.await;
    }));

    let origin: http::Uri = "http://127.0.0.1:4317".parse().unwrap();
    let mut client = MetricsServiceClient::with_origin(SendRequestService::new(sender), origin);

    let request = tonic::Request::new(build_export_request());
    let result = block_on_with_tasks(&exec, client.export(request));

    assert!(result.is_ok(), "gRPC unary call failed: {:?}", result.err());
}
