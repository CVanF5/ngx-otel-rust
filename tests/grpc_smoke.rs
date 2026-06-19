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

// ── Generated protobuf types ─────────────────────────────────────────────────
//
// Mirror the include! hierarchy from src/encoder/mod.rs so that the
// `super::super::super::metrics::v1::...` cross-references inside the
// generated code resolve correctly at the correct nesting depth.

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

// ── Task-queue executor ───────────────────────────────────────────────────────
//
// A `hyper::rt::Executor<F>` that collects futures in an `Rc<RefCell<VecDeque>>`
// rather than spawning to a thread pool.  `block_on_with_tasks` drains and
// polls that queue on every spin-loop iteration.
//
// The executor is intentionally `!Send + !Sync` — this is fine because:
//   * `Http2ClientConnExec` does not require `E: Send`.
//   * All driving happens on a single test thread.

type BoxFuture = Pin<Box<dyn Future<Output = ()> + 'static>>;

#[derive(Clone)]
struct TaskQueueExecutor {
    /// Newly spawned futures waiting to be moved into `running`.
    queue: Rc<RefCell<VecDeque<BoxFuture>>>,
    /// Futures that have been polled at least once and are still pending.
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

/// `hyper::rt::Executor<F>` — stores `fut` in the task queue for later
/// driving by `block_on_with_tasks`.
impl<F> hyper::rt::Executor<F> for TaskQueueExecutor
where
    F: Future<Output = ()> + 'static,
{
    fn execute(&self, fut: F) {
        self.queue.borrow_mut().push_back(Box::pin(fut));
    }
}

// ── Spin-loop that co-drives background tasks ─────────────────────────────────

/// Drive `fut` to completion, polling all background tasks in `exec` on every
/// iteration.  Returns `F::Output`.
///
/// The waker is a no-op; forward progress relies on the spin loop (every task
/// is polled unconditionally on each iteration).  `SpinTcpIo` calls
/// `wake_by_ref()` on `WouldBlock`, which is safe here because the loop
/// retries immediately.
///
/// A 30-second wall-clock deadline is enforced.  If the future has not
/// resolved within that window the test panics with a clear message instead
/// of hanging indefinitely.  30 seconds is generous enough for a slow CI
/// box while still detecting a genuinely stalled collector.
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

        // ① Move newly queued tasks into the running set.
        exec.running.borrow_mut().extend(exec.queue.borrow_mut().drain(..));

        // ② Take ownership of running tasks (avoids holding the RefCell borrow
        //    while tasks are polled, since polling may call execute() → borrow
        //    exec.queue, which is a *different* RefCell, so there's no conflict).
        let mut tasks = std::mem::take(&mut *exec.running.borrow_mut());

        // ③ Poll each task; discard Ready ones, keep Pending ones.
        tasks.retain_mut(|t| t.as_mut().poll(&mut cx).is_pending());

        // ④ Drain anything the tasks spawned while being polled.
        tasks.extend(exec.queue.borrow_mut().drain(..));

        // ⑤ Put the survivors back.
        *exec.running.borrow_mut() = tasks;

        // ⑥ Poll the main future.
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(val) => return val,
            Poll::Pending => {
                // Drain tasks spawned by the main future before sleeping.
                exec.running.borrow_mut().extend(exec.queue.borrow_mut().drain(..));
                std::thread::yield_now();
            }
        }
    }
}

// ── Test payload ──────────────────────────────────────────────────────────────

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
    // 1. Open a non-blocking TCP connection to the OTel collector.
    //
    //    Read/write timeouts are set so that a collector that accepts the
    //    connection but then stalls on I/O causes the socket to return an
    //    error rather than blocking the spin loop forever.  30 seconds matches
    //    the wall-clock deadline in block_on_with_tasks.
    let addr: SocketAddr = "127.0.0.1:4317".parse().unwrap();
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .expect("cannot connect to 127.0.0.1:4317 — start OTel collector first");
    stream.set_read_timeout(Some(Duration::from_secs(30))).expect("set_read_timeout must succeed");
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .expect("set_write_timeout must succeed");
    stream.set_nonblocking(true).unwrap();
    let io = SpinTcpIo::new(stream);

    // 2. Create the task-queue executor.
    //    During h2 handshake, hyper calls exec.execute(ConnTask) to spawn the
    //    connection driver.  ConnTask lives in exec.running for the lifetime of
    //    the test.
    let exec = TaskQueueExecutor::new();

    // 3. HTTP/2 handshake.
    //    The turbofish `::<_, _, tonic::body::Body>` is required because the
    //    body type `B` cannot be inferred from the handshake call alone — it
    //    is determined by what `SendRequest` will later be used for.
    let handshake_fut =
        hyper::client::conn::http2::handshake::<_, _, tonic::body::Body>(exec.clone(), io);

    let (sender, conn) =
        block_on_with_tasks(&exec, handshake_fut).expect("HTTP/2 handshake failed");

    // 4. Drive the `Connection` (h2 client-task / request dispatcher) as a
    //    background task.  ConnTask (the TCP I/O driver) is already in
    //    exec.running from step 3.
    exec.queue.borrow_mut().push_back(Box::pin(async move {
        let _ = conn.await;
    }));

    // 5. Build the generated tonic gRPC client over our shim.
    //    ready() + path + codec are encapsulated inside the generated export() method.
    let origin: http::Uri = "http://127.0.0.1:4317".parse().unwrap();
    let mut client = MetricsServiceClient::with_origin(SendRequestService::new(sender), origin);

    // 6. Issue a unary ExportMetrics call.
    let request = tonic::Request::new(build_export_request());
    let result = block_on_with_tasks(&exec, client.export(request));

    // 7. Assert success.
    assert!(result.is_ok(), "gRPC unary call failed: {:?}", result.err());
}
