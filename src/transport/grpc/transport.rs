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
use std::boxed::Box;

use http::uri::Uri;
use nginx_sys::ngx_log_t;
use prost::Message;

use crate::encoder::opentelemetry::proto::collector::logs::v1::{
    logs_service_client::LogsServiceClient, ExportLogsServiceRequest,
};
use crate::encoder::opentelemetry::proto::collector::metrics::v1::{
    metrics_service_client::MetricsServiceClient, ExportMetricsServiceRequest,
};
use crate::encoder::opentelemetry::proto::collector::trace::v1::{
    trace_service_client::TraceServiceClient, ExportTraceServiceRequest,
};
use crate::transport::grpc::executor::NgxExecutor;
use crate::transport::grpc::shim::SendRequestService;
use crate::transport::hyper_http::{
    strip_v6_brackets, wrap_tls_io, Connector, NgxConnector, ParsedEndpoint, TlsOrPlain,
};
use crate::transport::tls::SslCtx;
use crate::transport::TransportError;

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
    /// Cached gRPC traces client (Phase 3.1).  Uses a separate h2 connection.
    traces_client: Option<TraceServiceClient<SendRequestService<tonic::body::Body>>>,
    /// TLS context for `https://` endpoints (TLS Phase A — A2). `None` for
    /// plaintext (`http://`) h2c. `bool` mirrors `ssl_verify off` (insecure).
    /// One `TlsNgxConnIo` engine serves both transports (decision of record);
    /// the gRPC path additionally negotiates ALPN `h2`.
    tls: Option<(SslCtx, bool)>,
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

        // Build the origin URI: `http://host:port` or `https://host:port` (no path).
        // This is what tonic's `MetricsServiceClient::with_origin` expects.
        // For HTTPS endpoints the scheme is `https://` so tonic's H2 framing
        // uses the correct authority and scheme in the :authority / :scheme
        // pseudo-headers.
        let origin_str = match &endpoint {
            ParsedEndpoint::Http { host, port, .. } => {
                std::format!("http://{host}:{port}")
            }
            ParsedEndpoint::Https { host, port, .. } => {
                std::format!("https://{host}:{port}")
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

        Ok(Self {
            endpoint,
            origin,
            connector,
            client: None,
            logs_client: None,
            traces_client: None,
            tls: None,
        })
    }

    /// Wire in a TLS context for `https://` endpoints.
    ///
    /// `ctx` is a pre-built `SslCtx` (from `TlsConfig::build_ctx`); `insecure`
    /// mirrors `ssl_verify off`. Call after `with_connector` / `with_ngx_log`
    /// when the endpoint is `https://`. When set, every gRPC connection is
    /// wrapped with `TlsNgxConnIo` (ALPN `h2`) before the h2 handshake.
    pub fn set_tls(&mut self, ctx: SslCtx, insecure: bool) {
        self.tls = Some((ctx, insecure));
    }
}

#[allow(private_bounds)] // see note on the struct above
impl<C: Connector> GrpcTransport<C>
where
    C::Io: Send + 'static,
{
    /// Open a connection to the endpoint and, for `https://` endpoints, wrap it
    /// with TLS (ALPN `h2`) so tonic's h2 handshake runs over an encrypted
    /// stream. Returns a boxed `TlsOrPlain` so the plain (`h2c`) and TLS paths
    /// share one return type for `hyper::client::conn::http2::handshake`.
    async fn connect_io(&self) -> Result<Box<dyn TlsOrPlain>, TransportError> {
        let raw = self.connector.connect(&self.endpoint).await?;
        if let Some((ctx, insecure)) = &self.tls {
            let host = strip_v6_brackets(self.endpoint.host_str());
            // gRPC over TLS REQUIRES HTTP/2 → offer ALPN `h2`.
            let tls_io = wrap_tls_io(raw, ctx, *insecure, host, Some(b"h2"))?;
            Ok(Box::new(tls_io))
        } else {
            Ok(Box::new(raw))
        }
    }
}

// ── Transport impl ────────────────────────────────────────────────────────────

#[allow(private_bounds)] // see note on the struct definition above
impl<C: Connector + Send> GrpcTransport<C>
where
    C::Io: Send + 'static,
{
    /// Send a batch of OTLP metrics (encoded protobuf) over OTLP/gRPC unary.
    pub async fn send(
        &mut self,
        bytes: std::vec::Vec<u8>,
    ) -> Result<crate::transport::DeliveryOutcome, TransportError> {
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
            // 1. Connect via the configured connector (NgxConnector in
            //    production); for https:// endpoints this wraps the stream in
            //    TLS (ALPN h2) so the h2 handshake runs encrypted.
            let io = self.connect_io().await?;

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
                // S1 default mapping: an OK RPC → Accepted. S3 refines this into
                // the full gRPC-status→DeliveryOutcome adapter.
                Ok(crate::transport::DeliveryOutcome::Accepted)
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

#[allow(private_bounds)] // see note on the struct definition above
impl<C: Connector + Send> GrpcTransport<C>
where
    C::Io: Send + 'static,
{
    /// Send an `ExportLogsServiceRequest` (already prost-encoded) to the
    /// `LogsService/Export` RPC.
    ///
    /// Mirrors [`Transport::send`] but decodes `ExportLogsServiceRequest` and
    /// uses the `LogsServiceClient`.  Drops and re-creates the logs client on
    /// failure (same reconnect-on-failure parity as the metrics client).
    pub async fn send_logs(
        &mut self,
        bytes: std::vec::Vec<u8>,
    ) -> Result<crate::transport::DeliveryOutcome, crate::transport::TransportError> {
        use crate::transport::TransportError;

        let req = ExportLogsServiceRequest::decode(bytes.as_slice()).map_err(|e| {
            TransportError::Connection {
                cause: std::format!(
                    "gRPC logs transport: failed to decode ExportLogsServiceRequest: {e}"
                ),
            }
        })?;

        if self.logs_client.is_none() {
            let io = self.connect_io().await?;
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
                Ok(crate::transport::DeliveryOutcome::Accepted)
            }
            Err(status) => Err(TransportError::Connection {
                cause: std::format!("gRPC LogsService/Export RPC failed: {status}"),
            }),
        }
    }

    /// Send an already-encoded `ExportTraceServiceRequest` over gRPC.
    ///
    /// Decodes the bytes (the same encoding [`OtlpTracesEncoder`] produces)
    /// and issues a unary `TraceService/Export` RPC.  The traces client uses
    /// its own h2 connection (same lazy-connect pattern as `logs_client`).
    ///
    /// On success the client is re-cached for the next call.  On any RPC
    /// error the client is dropped so the next call reconnects fresh.
    pub async fn send_traces(
        &mut self,
        bytes: std::vec::Vec<u8>,
    ) -> Result<crate::transport::DeliveryOutcome, crate::transport::TransportError> {
        use crate::transport::TransportError;

        let req = ExportTraceServiceRequest::decode(bytes.as_slice()).map_err(|e| {
            TransportError::Connection {
                cause: std::format!(
                    "gRPC traces transport: failed to decode ExportTraceServiceRequest: {e}"
                ),
            }
        })?;

        if self.traces_client.is_none() {
            let io = self.connect_io().await?;
            let (sender, conn) = hyper::client::conn::http2::handshake::<_, _, tonic::body::Body>(
                crate::transport::grpc::executor::NgxExecutor,
                io,
            )
            .await
            .map_err(|e| TransportError::Connection {
                cause: std::format!("gRPC traces h2 handshake failed: {e}"),
            })?;
            ngx::async_::spawn(async move {
                let _ = conn.await;
            })
            .detach();
            self.traces_client = Some(TraceServiceClient::with_origin(
                crate::transport::grpc::shim::SendRequestService::new(sender),
                self.origin.clone(),
            ));
        }

        let mut client = self.traces_client.take().expect("just connected above");
        let result = client.export(tonic::Request::new(req)).await;

        match result {
            Ok(_resp) => {
                self.traces_client = Some(client);
                Ok(crate::transport::DeliveryOutcome::Accepted)
            }
            Err(status) => Err(TransportError::Connection {
                cause: std::format!("gRPC TraceService/Export RPC failed: {status}"),
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
        let t =
            GrpcTransport::<NgxConnector>::with_ngx_log("http://127.0.0.1:4317", log_ptr, None, 0);
        assert!(t.is_ok(), "valid http://host:port endpoint must parse OK");
    }

    /// Unix socket endpoints must be rejected with `InvalidEndpoint`.
    #[test]
    fn grpc_transport_rejects_unix_endpoint() {
        let log_ptr = core::ptr::NonNull::dangling();
        let result =
            GrpcTransport::<NgxConnector>::with_ngx_log("unix:///tmp/otel.sock", log_ptr, None, 0);
        assert!(
            matches!(result, Err(TransportError::InvalidEndpoint { .. })),
            "unix socket endpoints must be rejected for gRPC transport"
        );
    }

    /// HTTPS endpoints must be accepted by GrpcTransport (TLS Phase A — A2).
    ///
    /// `ParsedEndpoint::parse("https://...")` now returns `Https { .. }` instead
    /// of an error; `GrpcTransport::with_connector` builds an `https://` origin
    /// URI for tonic.  The TLS handshake is wired in the connector dispatch layer
    /// (A2 / A3); construction itself must succeed here.
    #[test]
    fn grpc_transport_accepts_https_endpoint() {
        let log_ptr = core::ptr::NonNull::dangling();
        let result =
            GrpcTransport::<NgxConnector>::with_ngx_log("https://127.0.0.1:4317", log_ptr, None, 0);
        assert!(
            result.is_ok(),
            "https:// endpoints must be accepted by GrpcTransport (TLS Phase A): {:?}",
            result.err()
        );
    }

    /// `GrpcTransport<NgxConnector>` must be `Send` so it can live in the
    /// export-loop task.
    #[test]
    fn grpc_transport_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<GrpcTransport<NgxConnector>>();
    }

    /// A DNS-name endpoint must parse and construct a `GrpcTransport` without
    /// error.  The transport inherits DNS resolution from `NgxConnector` (Item 3)
    /// via the `Connector::connect` delegation — `GrpcTransport` has no own
    /// connect logic.  The resolver is `None` here; if `send` were called it
    /// would produce a clear `TransportError::Connection` ("configure nginx's
    /// resolver directive…").  This test verifies parse + origin-URI construction
    /// succeed for a hostname endpoint.
    #[test]
    fn grpc_transport_dns_endpoint_constructs_ok() {
        let log_ptr = core::ptr::NonNull::dangling();
        let t = GrpcTransport::<NgxConnector>::with_ngx_log(
            "http://otel-collector.example.com:4317",
            log_ptr,
            None,
            0,
        );
        assert!(
            t.is_ok(),
            "DNS-name gRPC endpoint must parse and construct without error; got: {:?}",
            t.err()
        );
    }

    // ── gRPC TLS dispatch coverage (connect_io wraps the stream in TLS) ───────
    //
    // Drives the PRODUCTION GrpcTransport::connect_io against a real TLS server
    // (`openssl s_server`) over the SpinConnector https path. A working dispatch
    // wraps the stream in TlsNgxConnIo (ALPN h2) → the handshake completes and
    // a round-trip succeeds. Dropping the TLS wrap on the gRPC path (mutation 2)
    // sends cleartext to the TLS server → no round-trip → this test FAILS.
    mod tls_dispatch {
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        use std::boxed::Box;
        use std::process::{Child, Command, Stdio};
        use std::string::{String, ToString};
        use std::sync::atomic::{AtomicU16, Ordering};
        use std::time::{Duration, Instant};
        use std::{format, vec};

        use crate::transport::hyper_http::SpinConnector;
        use crate::transport::tls::TlsConfig;

        use super::super::GrpcTransport;

        fn block_on<F: core::future::Future>(fut: F) -> F::Output {
            unsafe fn noop_clone(_: *const ()) -> RawWaker {
                RawWaker::new(core::ptr::null(), &VTABLE)
            }
            unsafe fn noop(_: *const ()) {}
            static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);
            // SAFETY: standard noop-waker idiom (all fns no-op over a null ptr).
            let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
            let mut cx = Context::from_waker(&waker);
            let mut fut = core::pin::pin!(fut);
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                    return v;
                }
                assert!(Instant::now() < deadline, "block_on timed out");
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        static NEXT: AtomicU16 = AtomicU16::new(0);

        struct Certs {
            dir: std::path::PathBuf,
        }
        impl Certs {
            fn ca_pem(&self) -> String {
                self.dir.join("ca.pem").to_string_lossy().into_owned()
            }
        }
        impl Drop for Certs {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }

        fn run_openssl(args: &[&str], cwd: &std::path::Path) {
            let out = Command::new("openssl")
                .args(args)
                .current_dir(cwd)
                .output()
                .expect("spawn openssl");
            assert!(out.status.success(), "openssl {:?} failed", args);
        }

        fn make_certs(san: &str) -> Certs {
            let dir = std::env::temp_dir().join(format!(
                "ngx-otel-grpc-tls-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let d = dir.as_path();
            run_openssl(&["genrsa", "-out", "ca.key", "2048"], d);
            run_openssl(
                &[
                    "req",
                    "-x509",
                    "-new",
                    "-key",
                    "ca.key",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=Test CA",
                    "-out",
                    "ca.pem",
                ],
                d,
            );
            run_openssl(&["genrsa", "-out", "server.key", "2048"], d);
            run_openssl(
                &["req", "-new", "-key", "server.key", "-subj", "/CN=server", "-out", "server.csr"],
                d,
            );
            std::fs::write(d.join("ext.cnf"), format!("subjectAltName={san}")).unwrap();
            run_openssl(
                &[
                    "x509",
                    "-req",
                    "-in",
                    "server.csr",
                    "-CA",
                    "ca.pem",
                    "-CAkey",
                    "ca.key",
                    "-CAcreateserial",
                    "-days",
                    "1",
                    "-out",
                    "server.pem",
                    "-extfile",
                    "ext.cnf",
                ],
                d,
            );
            Certs { dir }
        }

        struct TestServer {
            child: Child,
            port: u16,
            _guard: std::sync::MutexGuard<'static, ()>,
        }
        impl TestServer {
            fn start(certs: &Certs) -> Self {
                let guard = crate::transport::tls::S_SERVER_TEST_LOCK
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let cert = certs.dir.join("server.pem");
                let key = certs.dir.join("server.key");
                let mut last = String::new();
                for _ in 0..10 {
                    let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
                    let port = l.local_addr().unwrap().port();
                    drop(l);
                    let mut child = Command::new("openssl")
                        .args([
                            "s_server",
                            "-accept",
                            &port.to_string(),
                            "-cert",
                            &cert.to_string_lossy(),
                            "-key",
                            &key.to_string_lossy(),
                            // Offer h2 via ALPN so the gRPC client's ALPN h2 is
                            // accepted; the handshake completes either way, this
                            // just makes the negotiation realistic.
                            "-alpn",
                            "h2",
                            "-quiet",
                            "-rev",
                        ])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .expect("spawn s_server");
                    std::thread::sleep(Duration::from_millis(80));
                    if let Ok(Some(_)) = child.try_wait() {
                        last = format!("s_server exited early on {port}");
                        continue;
                    }
                    let deadline = Instant::now() + Duration::from_secs(5);
                    let mut ready = false;
                    while Instant::now() < deadline {
                        if let Ok(p) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                            drop(p);
                            ready = true;
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    if ready && matches!(child.try_wait(), Ok(None)) {
                        return Self { child, port, _guard: guard };
                    }
                    last = format!("not ready on {port}");
                    let _ = child.kill();
                    let _ = child.wait();
                }
                panic!("could not start s_server: {last}");
            }
        }
        impl Drop for TestServer {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }

        /// The gRPC `connect_io` must wrap the stream in TLS (ALPN h2) for an
        /// https endpoint. We drive it against a TLS s_server and round-trip
        /// bytes via the boxed IO's hyper Read/Write.
        #[test]
        fn grpc_connect_io_https_completes_tls_roundtrip() {
            use hyper::rt::{Read, Write};

            let certs = make_certs("DNS:localhost,IP:127.0.0.1");
            let server = TestServer::start(&certs);
            let endpoint = format!("https://127.0.0.1:{}", server.port);

            let mut last = String::new();
            for attempt in 0..4 {
                let mut t =
                    GrpcTransport::<SpinConnector>::with_connector(&endpoint, SpinConnector)
                        .expect("https grpc endpoint must parse");
                let ctx = TlsConfig { ca_file: Some(certs.ca_pem()), ..Default::default() }
                    .build_ctx(|_| {})
                    .expect("build_ctx");
                t.set_tls(ctx, false);

                let mut io = match block_on(t.connect_io()) {
                    Ok(io) => io,
                    Err(e) => {
                        last = format!("connect_io: {e:?}");
                        std::thread::sleep(Duration::from_millis(50 * (attempt + 1)));
                        continue;
                    }
                };
                let msg = b"grpc-tls-probe\n";
                match block_on(core::future::poll_fn(|cx| {
                    core::pin::Pin::new(&mut io).poll_write(cx, msg)
                })) {
                    Ok(_) => {}
                    Err(e) => {
                        last = format!("write: {e}");
                        std::thread::sleep(Duration::from_millis(50 * (attempt + 1)));
                        continue;
                    }
                }
                let mut got = vec![0u8; 64];
                let n = block_on(core::future::poll_fn(|cx| {
                    let mut rb = hyper::rt::ReadBuf::new(&mut got);
                    match core::pin::Pin::new(&mut io).poll_read(cx, rb.unfilled()) {
                        Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                        Poll::Pending => Poll::Pending,
                    }
                }));
                match n {
                    Ok(n) if n > 0 => return, // TLS round-trip succeeded → dispatch wrapped TLS
                    Ok(_) => last = "no bytes echoed (no TLS round-trip)".to_string(),
                    Err(e) => last = format!("read: {e}"),
                }
                std::thread::sleep(Duration::from_millis(50 * (attempt + 1)));
            }
            panic!("gRPC TLS dispatch round-trip failed after retries: {last}");
        }

        // Keep `Box` referenced (connect_io returns Box<dyn TlsOrPlain>).
        #[allow(dead_code)]
        fn _box_marker() -> Box<u8> {
            Box::new(0)
        }
    }
}
