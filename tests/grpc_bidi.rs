// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! In-process bidi gRPC smoke test.
//!
//! Replaces the two-process approach (`bidi_echo_server` binary +
//! `run_grpc_bidi_smoke.sh`) with a single self-contained Rust test.
//!
//! # Architecture
//!
//! ```text
//!   ┌─────────────────────────────────────────────────┐
//!   │  test thread                                    │
//!   │                                                 │
//!   │  TaskQueueExecutor (spin-loop, no Tokio)        │
//!   │    └─ hyper HTTP/2 client                       │
//!   │         └─ SpinTcpIo (non-blocking TcpStream)   │
//!   │              └─ connects to 127.0.0.1:<port>    │
//!   └──────────────────────┬──────────────────────────┘
//!                          │ TCP (ephemeral port)
//!   ┌──────────────────────▼──────────────────────────┐
//!   │  background thread (small Tokio rt)             │
//!   │    tonic::transport::Server                     │
//!   │    bound to 127.0.0.1:0                         │
//!   │    implements Echo.BidiEcho (echo server)       │
//!   └─────────────────────────────────────────────────┘
//! ```
//!
//! Transport seam: **ephemeral TCP port**.
//!
//! `SpinConnector` opens a real non-blocking `TcpStream` — it has no
//! `AsyncRead + AsyncWrite` interface that would accept a `tokio::io::duplex`
//! half.  Binding the server to `127.0.0.1:0` and reading back the assigned
//! port is the simplest fit.  The server thread carries its own small
//! `#[tokio::main]`-style single-threaded runtime so Tokio never appears in
//! the module's production dependency graph.
//!
//! # Coverage
//!
//! Covers all bidi-specific assertions from `run_grpc_bidi_smoke.sh`:
//!
//! | Shell assertion | Rust equivalent |
//! |-----------------|-----------------|
//! | 1 "bidi smoke: firing one bidi stream" line | `fire_one_bidi_stream_inprocess` called once |
//! | 1 "bidi smoke: bidi complete (sent=10, received=10)" line | `result.is_ok()` + counts asserted |
//! | 0 "bidi smoke: bidi failed" lines | no panic / no Err returned |
//!
//! The unary regression gate (shell assertions 1-5) and overload test remain
//! in their respective shell scripts (`run_grpc_bidi_smoke.sh`,
//! `run_grpc_bidi_overload.sh`); the overload test requires a live nginx
//! worker and `ngx::async_::sleep` so it cannot be expressed here.
//!
//! # Running
//!
//! ```sh
//! cargo test --features test-support --test grpc_bidi
//! ```
//!
//! No Docker, no collector, no nginx binary required.

// Pull in NGINX C-symbol stubs required at link time on macOS flat-namespace.
mod support;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::Future;
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::time::Duration;

use futures_channel::mpsc;
use ngx_http_otel_module::transport::grpc::shim::SendRequestService;
use ngx_http_otel_module::transport::hyper_http::SpinTcpIo;

// ── Echo proto — server+client generated code ────────────────────────────────
//
// The server stub (build.rs → OUT_DIR/echo_server_gen/) is generated with
// `build_server(true)` and is full-std-safe.  Tests are full-std binaries
// so we can include it here directly, removing the need for the
// `examples/bidi_echo_server.rs` binary.

pub mod ngx_otel_echo_v1 {
    include!(concat!(env!("OUT_DIR"), "/echo_server_gen/ngx.otel.echo.v1.rs"));
}

use ngx_otel_echo_v1::{
    echo_server::{Echo, EchoServer},
    Ping, Pong,
};

// ── EchoSvc — tonic Echo service implementation ───────────────────────────────
//
// Implements `Echo.BidiEcho`: streams one `Pong` per received `Ping`,
// copying `seq` and `payload`.  Identical in logic to the former
// `examples/bidi_echo_server.rs`.

struct EchoSvc;

#[tonic::async_trait]
impl Echo for EchoSvc {
    type BidiEchoStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<Pong, tonic::Status>> + Send + 'static>>;

    async fn bidi_echo(
        &self,
        request: tonic::Request<tonic::Streaming<Ping>>,
    ) -> Result<tonic::Response<Self::BidiEchoStream>, tonic::Status> {
        use tokio_stream::StreamExt as _;

        let mut inbound = request.into_inner();

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Pong, tonic::Status>>(16);

        tokio::spawn(async move {
            while let Some(item) = inbound.next().await {
                match item {
                    Ok(ping) => {
                        let pong = Pong { seq: ping.seq, payload: ping.payload };
                        if tx.send(Ok(pong)).await.is_err() {
                            break; // client gone
                        }
                    }
                    Err(status) => {
                        let _ = tx.send(Err(status)).await;
                        break;
                    }
                }
            }
        });

        let outbound = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(tonic::Response::new(Box::pin(outbound)))
    }
}

// ── Echo server — start on a background thread ────────────────────────────────

/// Start the echo gRPC server on `127.0.0.1:0` (ephemeral port).
///
/// Spawns a background thread carrying a small Tokio `current_thread` runtime.
/// Returns the `SocketAddr` the server is actually bound to.
///
/// The server runs for the lifetime of the returned `Arc<tokio::sync::Notify>`:
/// when the `Arc` is dropped (i.e., when the test drops its handle) the server
/// shuts down gracefully.
fn start_echo_server() -> (SocketAddr, Arc<tokio::sync::Notify>) {
    // Bind synchronously so the caller gets the port before connecting.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind echo server");
    let addr = listener.local_addr().expect("local_addr");

    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_tx = Arc::clone(&shutdown);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime for echo server");

        rt.block_on(async move {
            // Convert the std TcpListener to a tokio one so tonic can use it.
            listener.set_nonblocking(true).expect("set_nonblocking");
            let tokio_listener =
                tokio::net::TcpListener::from_std(listener).expect("from_std listener");

            let incoming = tokio_stream::wrappers::TcpListenerStream::new(tokio_listener);

            tonic::transport::Server::builder()
                .add_service(EchoServer::new(EchoSvc))
                .serve_with_incoming_shutdown(incoming, async move {
                    shutdown_tx.notified().await;
                })
                .await
                .expect("echo server error");
        });
    });

    (addr, shutdown)
}

// ── Task-queue executor (mirrors grpc_smoke.rs) ───────────────────────────────
//
// A `hyper::rt::Executor<F>` that collects futures in a `VecDeque` rather
// than spawning to a thread pool.  `block_on_with_tasks` drains and polls the
// queue on every spin-loop iteration.

type BoxFuture = Pin<Box<dyn Future<Output = ()> + 'static>>;

#[derive(Clone)]
struct TaskQueueExecutor {
    queue: std::rc::Rc<RefCell<VecDeque<BoxFuture>>>,
    running: std::rc::Rc<RefCell<Vec<BoxFuture>>>,
}

impl TaskQueueExecutor {
    fn new() -> Self {
        Self {
            queue: std::rc::Rc::new(RefCell::new(VecDeque::new())),
            running: std::rc::Rc::new(RefCell::new(Vec::new())),
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

// ── block_on_with_tasks — spin-loop executor ──────────────────────────────────

/// Drive `fut` to completion, co-polling background tasks in `exec` on every
/// iteration.  No-op waker; progress via spin.  30-second wall-clock timeout.
fn block_on_with_tasks<F: Future>(exec: &TaskQueueExecutor, fut: F) -> F::Output {
    unsafe fn noop_clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    unsafe fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

    // SAFETY: the vtable functions are all valid no-ops; the data pointer is
    // never dereferenced (std::ptr::null() is used as a sentinel).
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);

    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "block_on_with_tasks: future did not complete within 30 s — \
             echo server may be stalled or the connection is hung"
        );

        exec.running.borrow_mut().extend(exec.queue.borrow_mut().drain(..));

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

// ── Async send helper ─────────────────────────────────────────────────────────

/// Async send-one over a `futures_channel::mpsc::Sender<Ping>`.
///
/// Mirrors the helper in `src/transport/grpc/smoke.rs` so we can call it
/// from the spin-loop client without pulling in `futures-util`.
async fn mpsc_send_one(tx: &mut mpsc::Sender<Ping>, msg: Ping) -> Result<(), String> {
    core::future::poll_fn(|cx| tx.poll_ready(cx))
        .await
        .map_err(|e| format!("send channel closed: {e}"))?;
    tx.start_send(msg).map_err(|e| format!("start_send: {e}"))
}

// ── In-process bidi smoke exercise ────────────────────────────────────────────

/// Exercise the bidi bridge against `addr` using the spin-loop executor +
/// `SpinTcpIo` (no Tokio runtime).
///
/// Performs the same asymmetric A/B/C drain sequence as `fire_one_bidi_stream`
/// in `src/transport/grpc/smoke.rs`:
///
/// - Phase A: send 3 pings, drain 3 pongs (proves send and receive are
///   independently pollable — if the bridge serialises them the A-drain hangs).
/// - Phase B: send 7 more pings, drain until total received == 10.
/// - Phase C: close the send-half; assert the server closes its stream too.
///
/// Asserts `sent == 10 && received == 10`.
async fn fire_one_bidi_stream_inprocess(addr: SocketAddr, exec: &TaskQueueExecutor) {
    use ngx_otel_echo_v1::echo_client::EchoClient;

    // 1. Open a non-blocking TCP connection to the echo server.
    let stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect to echo server");
    stream.set_read_timeout(Some(Duration::from_secs(30))).expect("set_read_timeout");
    stream.set_write_timeout(Some(Duration::from_secs(30))).expect("set_write_timeout");
    stream.set_nonblocking(true).unwrap();
    let io = SpinTcpIo::new(stream);

    // 2. HTTP/2 handshake.
    let origin: http::Uri = format!("http://{}:{}", addr.ip(), addr.port()).parse().unwrap();
    let handshake_fut =
        hyper::client::conn::http2::handshake::<_, _, tonic::body::Body>(exec.clone(), io);
    let (sender, conn) = block_on_with_tasks(exec, handshake_fut).expect("HTTP/2 handshake failed");

    // 3. Drive the Connection as a background task.
    exec.queue.borrow_mut().push_back(Box::pin(async move {
        let _ = conn.await;
    }));

    // 4. Build the EchoClient over our SendRequestService shim.
    let svc = SendRequestService::new(sender);
    let mut client = EchoClient::with_origin(svc, origin);

    // 5. Open the bidi stream.
    let (mut tx, rx) = mpsc::channel::<Ping>(16);
    let response = block_on_with_tasks(exec, client.bidi_echo(tonic::Request::new(rx)))
        .expect("bidi_echo call failed");
    let mut inbound = response.into_inner();

    // 6. Asymmetric drain.

    // Phase A: send 3 pings, drain 3 pongs.
    let mut sent: u64 = 0;
    let mut received: u64 = 0;

    for seq in 0u64..3 {
        block_on_with_tasks(exec, mpsc_send_one(&mut tx, Ping { seq, payload: vec![] }))
            .expect("Phase A send failed");
        sent += 1;
    }

    while received < 3 {
        let pong = block_on_with_tasks(exec, inbound.message())
            .expect("Phase A recv error")
            .expect("Phase A: stream ended early");
        assert!(pong.seq < 3, "Phase A: unexpected seq {}", pong.seq);
        received += 1;
    }

    // Phase B: send 7 more pings, drain until received == 10.
    for seq in 3u64..10 {
        block_on_with_tasks(exec, mpsc_send_one(&mut tx, Ping { seq, payload: vec![] }))
            .expect("Phase B send failed");
        sent += 1;
    }

    while received < 10 {
        let _pong = block_on_with_tasks(exec, inbound.message())
            .expect("Phase B recv error")
            .expect("Phase B: stream ended early");
        received += 1;
    }

    // Phase C: close the send-half; server must close its response stream.
    drop(tx);

    let final_msg =
        block_on_with_tasks(exec, inbound.message()).expect("Phase C: recv error after tx drop");
    assert!(final_msg.is_none(), "Phase C: expected stream end after tx drop, got another pong");

    // Verify counts — these map directly to the shell assertion
    // "bidi smoke: bidi complete (sent=10, received=10)".
    assert_eq!(sent, 10, "sent count mismatch");
    assert_eq!(received, 10, "received count mismatch");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// In-process bidi gRPC round-trip test.
///
/// Covers the bidi-specific assertions from `run_grpc_bidi_smoke.sh`:
/// - bidi stream fires (sent=10, received=10)
/// - no failures / panics
///
/// Does NOT require a collector, Docker, or nginx binary.
#[test]
fn grpc_bidi_smoke_inprocess() {
    // Start echo server on a background thread (Tokio-backed).
    let (addr, _shutdown) = start_echo_server();

    // Give the server a moment to start accepting connections.
    // The `TcpListenerStream` is ready immediately after `from_std`, but the
    // tonic server needs one event loop tick to register interest.
    std::thread::sleep(Duration::from_millis(50));

    // Create the task-queue executor (spin-loop, no Tokio).
    let exec = TaskQueueExecutor::new();

    // Drive the bidi smoke exercise.
    block_on_with_tasks(&exec, fire_one_bidi_stream_inprocess(addr, &exec));
}
