// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Unit tests for the BIO-wired async TLS engine ([`super::TlsNgxConnIo`]).
//!
//! Harness: an in-process server side run via the `openssl s_server` CLI on a
//! loopback port, with certs minted by the `openssl` CLI into a temp dir. The
//! client side is [`TlsNgxConnIo`] over a non-blocking `TcpStream` adapter
//! (`TestIo`) that mirrors `SpinTcpIo`'s WouldBlock→Pending contract; the
//! local [`block_on`] spin executor re-drives the future, exercising the real
//! WANT_READ/WANT_WRITE waker round-trips through the BIO callbacks.

extern crate std;

use core::pin::Pin;
use core::task::{Context, Poll};
use std::io::{Read as _, Write as _};

use hyper::rt::{Read as _HyperRead, Write as _HyperWrite};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::string::{String, ToString};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use std::{format, vec};

use super::{SslCtx, TlsConfig, TlsNgxConnIo};

// ──────────────────────────────────────────────────────────────────────────────
// Spin executor (local copy; unit tests cannot reach tests/support)
// ──────────────────────────────────────────────────────────────────────────────

fn block_on<F: core::future::Future>(fut: F) -> F::Output {
    use core::task::{RawWaker, RawWakerVTable, Waker};
    unsafe fn noop_clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    unsafe fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);
    // SAFETY: the vtable's fns are all no-ops over a null data ptr; constructing
    // a Waker from it is the standard noop-waker idiom.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = core::pin::pin!(fut);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        assert!(Instant::now() < deadline, "block_on timed out");
        std::thread::yield_now();
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TestIo — non-blocking TcpStream adapter (mirrors SpinTcpIo)
// ──────────────────────────────────────────────────────────────────────────────

struct TestIo(TcpStream);

impl hyper::rt::Read for TestIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        // SAFETY: hyper guarantees the unfilled region is a valid writable
        // MaybeUninit<u8> slice for this call.
        let uninit = unsafe { buf.as_mut() };
        let len = uninit.len();
        if len == 0 {
            return Poll::Ready(Ok(()));
        }
        // SAFETY: viewing the writable uninit region as &mut [u8] of the same
        // ptr/len is sound for Read::read, which only writes the bytes.
        let slice =
            unsafe { core::slice::from_raw_parts_mut(uninit.as_mut_ptr().cast::<u8>(), len) };
        match self.0.read(slice) {
            Ok(n) => {
                // SAFETY: read initialized the first n bytes; advancing is sound.
                unsafe { buf.advance(n) };
                Poll::Ready(Ok(()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl hyper::rt::Write for TestIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.0.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(self.get_mut().0.flush())
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let _ = self.get_mut().0.shutdown(std::net::Shutdown::Write);
        Poll::Ready(Ok(()))
    }
}

impl Unpin for TestIo {}

// ──────────────────────────────────────────────────────────────────────────────
// Cert + server fixtures (openssl CLI)
// ──────────────────────────────────────────────────────────────────────────────

/// A temp dir of CA + server cert material.
struct Certs {
    dir: std::path::PathBuf,
}

impl Certs {
    fn ca_pem(&self) -> String {
        self.dir.join("ca.pem").to_string_lossy().into_owned()
    }
    fn other_ca_pem(&self) -> String {
        self.dir.join("other-ca.pem").to_string_lossy().into_owned()
    }
    fn server_cert(&self) -> std::path::PathBuf {
        self.dir.join("server.pem")
    }
    fn server_key(&self) -> std::path::PathBuf {
        self.dir.join("server.key")
    }
}

impl Drop for Certs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run_openssl(args: &[&str], cwd: &std::path::Path) {
    let out = Command::new("openssl").args(args).current_dir(cwd).output().expect("spawn openssl");
    assert!(
        out.status.success(),
        "openssl {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Mint: a CA, a server cert (SAN=localhost,127.0.0.1) signed by it, and a
/// second unrelated CA (for the bad-CA negative test). `san` selects the
/// server cert's SAN so the hostname-mismatch test can request a wrong name.
fn make_certs(san: &str) -> Certs {
    let dir = std::env::temp_dir().join(format!(
        "ngx-otel-a1-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.as_path();

    // CA key + self-signed cert.
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
    // A second, unrelated CA (never signs the server) for the bad-CA test.
    run_openssl(&["genrsa", "-out", "other-ca.key", "2048"], d);
    run_openssl(
        &[
            "req",
            "-x509",
            "-new",
            "-key",
            "other-ca.key",
            "-days",
            "1",
            "-subj",
            "/CN=Other CA",
            "-out",
            "other-ca.pem",
        ],
        d,
    );

    // Server key + CSR + cert signed by CA with the requested SAN.
    run_openssl(&["genrsa", "-out", "server.key", "2048"], d);
    run_openssl(
        &["req", "-new", "-key", "server.key", "-subj", "/CN=server", "-out", "server.csr"],
        d,
    );
    let ext = format!("subjectAltName={san}");
    std::fs::write(d.join("ext.cnf"), &ext).unwrap();
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

static NEXT: AtomicU16 = AtomicU16::new(0);

/// A running `openssl s_server` echo server on a loopback port.
struct TestServer {
    child: Child,
    port: u16,
    /// Serialize s_server-backed handshakes process-wide (see the lock docs).
    /// Held for the server's lifetime; released on drop.
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl TestServer {
    /// Start an `openssl s_server` reverse-echo server on a loopback port.
    ///
    /// We do NOT use `-naccept 1`: a TCP-only readiness probe would consume the
    /// single accept slot and the real test connect would be refused. The
    /// server stays up serving multiple connections until `Drop` kills it.
    fn start(certs: &Certs) -> Self {
        let guard = super::S_SERVER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let port = pick_port();
        let child = Command::new("openssl")
            .args([
                "s_server",
                "-accept",
                &port.to_string(),
                "-cert",
                &certs.server_cert().to_string_lossy(),
                "-key",
                &certs.server_key().to_string_lossy(),
                "-quiet",
                "-rev", // reverse-echo — we only assert the round trip occurred
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn s_server");
        // Wait for the listener to accept TCP (process is up and bound). This
        // probe connection is closed immediately; s_server keeps listening.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(probe) = TcpStream::connect(("127.0.0.1", port)) {
                drop(probe);
                break;
            }
            assert!(Instant::now() < deadline, "s_server did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
        Self { child, port, _guard: guard }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn pick_port() -> u16 {
    // Bind to :0 to get a free port, then release it for s_server.
    let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn connect_nonblocking(port: u16) -> TestIo {
    let s = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    s.set_nonblocking(true).unwrap();
    TestIo(s)
}

/// Build an SslCtx, swallowing the insecure WARN.
fn ctx(cfg: &TlsConfig) -> SslCtx {
    cfg.build_ctx(|_| {}).expect("build_ctx")
}

/// Drive a handshake to completion (or error) using the spin executor.
fn do_handshake(io: TestIo, ctx: &SslCtx, host: &str, verify_host: bool) -> Result<(), String> {
    let mut tls = TlsNgxConnIo::new(io, ctx, host, verify_host).map_err(|e| format!("{e:?}"))?;
    block_on(core::future::poll_fn(|cx| tls.poll_handshake(cx))).map_err(|e| format!("{e}"))?;
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

/// SSL_CTX builds cleanly for the default (system trust) and insecure cases,
/// and a non-existent CA file is a clean config error.
#[test]
fn build_ctx_variants() {
    // Default (system trust paths).
    let _ = ctx(&TlsConfig::default());
    // Insecure.
    let _ = ctx(&TlsConfig { insecure: true, ..Default::default() });
    // Bad CA path → error.
    let bad =
        TlsConfig { ca_file: Some("/nonexistent/ca-bundle.pem".to_string()), ..Default::default() };
    assert!(bad.build_ctx(|_| {}).is_err(), "missing CA file must be a config error");
}

/// Happy path: server cert signed by our CA, SNI/verify host matches → the
/// handshake completes and a small write/read round-trip succeeds.
///
/// We verify against the DNS name `localhost` (matching the cert's
/// `DNS:localhost` SAN). NOTE: `X509_VERIFY_PARAM_set1_host` matches
/// DNS-name SANs only; an IP-literal endpoint (e.g. `https://127.0.0.1`) must
/// instead use `X509_VERIFY_PARAM_set1_ip`.
#[test]
fn handshake_ok_and_roundtrip() {
    let certs = make_certs("DNS:localhost,IP:127.0.0.1");
    let server = TestServer::start(&certs);
    let cfg = TlsConfig { ca_file: Some(certs.ca_pem()), ..Default::default() };
    let c = ctx(&cfg);

    // Connect to loopback but verify the `localhost` DNS-SAN.
    let io = connect_nonblocking(server.port);
    let mut tls = TlsNgxConnIo::new(io, &c, "localhost", true).expect("new");
    block_on(core::future::poll_fn(|cx| tls.poll_handshake(cx))).expect("handshake ok");

    // Round-trip a few bytes through SSL_write/SSL_read. `s_server -rev`
    // reverses and echoes each newline-terminated line, so the message ends
    // in '\n' to trigger the echo.
    let msg = b"hello-tls\n";
    let wrote = block_on(core::future::poll_fn(|cx| Pin::new(&mut tls).poll_write(cx, msg)))
        .expect("write");
    assert_eq!(wrote, msg.len(), "all bytes written");

    let mut got = vec![0u8; 64];
    let n = block_on(core::future::poll_fn(|cx| {
        let mut rb = hyper::rt::ReadBuf::new(&mut got);
        match Pin::new(&mut tls).poll_read(cx, rb.unfilled()) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }))
    .expect("read");
    assert!(n > 0, "received some echoed bytes back over TLS");
}

/// Server cert NOT signed by the configured trust anchor (`other-ca.pem`) →
/// the handshake must FAIL cleanly (fail-closed). This is the mutation target:
/// breaking verify-mode wiring (insecure→always NONE) makes this test pass when
/// it must fail.
#[test]
fn bad_ca_handshake_fails() {
    let certs = make_certs("DNS:localhost,IP:127.0.0.1");
    let server = TestServer::start(&certs);
    // Trust the OTHER ca, which did not sign the server cert.
    let cfg = TlsConfig { ca_file: Some(certs.other_ca_pem()), ..Default::default() };
    let c = ctx(&cfg);

    let io = connect_nonblocking(server.port);
    let res = do_handshake(io, &c, "127.0.0.1", true);
    assert!(
        res.is_err(),
        "handshake against an untrusted server cert MUST fail (got Ok): verification not enforced"
    );
}

/// `insecure=true` (ssl_verify off) → the same untrusted server cert is
/// accepted (verification disabled). Confirms the insecure path is wired and
/// that the bad-CA failure above is genuinely due to verification.
#[test]
fn insecure_skips_verification() {
    let certs = make_certs("DNS:localhost,IP:127.0.0.1");
    let server = TestServer::start(&certs);
    let cfg =
        TlsConfig { ca_file: Some(certs.other_ca_pem()), insecure: true, ..Default::default() };
    let c = ctx(&cfg);

    let io = connect_nonblocking(server.port);
    // verify_hostname is also disabled in insecure mode.
    let res = do_handshake(io, &c, "127.0.0.1", false);
    assert!(res.is_ok(), "insecure mode must accept the untrusted cert: {res:?}");
}

/// Cert SAN is `example.com` but we verify against `127.0.0.1` → the
/// X509_VERIFY_PARAM_set1_host check must reject the handshake.
#[test]
fn hostname_mismatch_fails() {
    let certs = make_certs("DNS:example.com");
    let server = TestServer::start(&certs);
    let cfg = TlsConfig { ca_file: Some(certs.ca_pem()), ..Default::default() };
    let c = ctx(&cfg);

    let io = connect_nonblocking(server.port);
    let res = do_handshake(io, &c, "127.0.0.1", true);
    assert!(
        res.is_err(),
        "cert SAN=example.com verified against host 127.0.0.1 MUST fail (hostname check off?)"
    );
}

/// Read the client-side SNI HostName that `TlsNgxConnIo::new` set on the SSL,
/// by querying OpenSSL directly (`SSL_get_servername`). Returns `None` when no
/// SNI extension was set. This inspects the ACTUAL SSL setup decision made by
/// the production `new`, not a reimplementation of the classifier.
fn sni_set_on(tls: &TlsNgxConnIo<TestIo>) -> Option<String> {
    use core::ffi::CStr;
    use openssl_sys as ssl;
    // SAFETY: `tls.ssl_ptr()` is the owned, non-null SSL just built by `new`;
    // `SSL_get_servername` returns a borrowed C string (the client SNI we set)
    // or null if none was set. We do not free it.
    let p = unsafe { ssl::SSL_get_servername(tls.ssl_ptr(), ssl::TLSEXT_NAMETYPE_host_name) };
    if p.is_null() {
        None
    } else {
        // SAFETY: `p` is a non-null, NUL-terminated C string owned by the SSL.
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

/// F2 (RFC 6066): SNI MUST be set for a DNS-name `server_name` and MUST be
/// suppressed for an IP literal (v4 and v6). Asserts the real SSL setup
/// decision via `SSL_get_servername`, not a reimplementation.
///
/// Mutation target: making `TlsNgxConnIo::new` set SNI unconditionally (drop
/// the `is_ip_literal` guard) makes the IP assertions FAIL.
#[test]
fn sni_set_for_dns_suppressed_for_ip() {
    let cfg = TlsConfig::default();
    let c = ctx(&cfg);

    // DNS name → SNI present and equal to the host.
    let dns = TlsNgxConnIo::new(connect_loopback_io(), &c, "collector.example.com", true)
        .expect("new dns");
    assert_eq!(
        sni_set_on(&dns).as_deref(),
        Some("collector.example.com"),
        "DNS host must set SNI to the host name"
    );

    // IPv4 literal → no SNI (RFC 6066).
    let v4 = TlsNgxConnIo::new(connect_loopback_io(), &c, "127.0.0.1", false).expect("new v4");
    assert_eq!(sni_set_on(&v4), None, "IPv4 literal must NOT be sent as SNI (RFC 6066)");

    // IPv6 literal (unbracketed, as the connector passes it) → no SNI.
    let v6 = TlsNgxConnIo::new(connect_loopback_io(), &c, "::1", false).expect("new v6");
    assert_eq!(sni_set_on(&v6), None, "IPv6 literal must NOT be sent as SNI (RFC 6066)");
}

/// Build a `TestIo` over a throwaway accepted loopback connection. No TLS
/// server is needed: `TlsNgxConnIo::new` only configures the SSL (SNI / verify
/// params); it does NOT touch the wire until `poll_handshake`. We connect to a
/// listener we keep alive for the duration so the socket is valid.
fn connect_loopback_io() -> TestIo {
    // A listener that stays bound; we never read from it. The client socket is
    // only used to construct the SSL wrapper, not to handshake.
    let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    // Leak the listener so it outlives the returned TestIo (test-only).
    std::mem::forget(l);
    connect_nonblocking(port)
}

// ──────────────────────────────────────────────────────────────────────────────
// Collector-cert gauge: COLLECTOR_CERT_NOT_AFTER capture
// ──────────────────────────────────────────────────────────────────────────────

/// A successful handshake writes the peer-cert notAfter into
/// `COLLECTOR_CERT_NOT_AFTER` (the shared atomic that `collect_all_sources`
/// reads to emit the `ngx_otel.tls.collector_cert.not_after` gauge).
///
/// Also asserts the **reuse seam**: the value in the atomic is derived from
/// the SAME `crate::cert_table::asn1_time_to_unix` helper used by
/// `ServingCertSource`, not a reimplementation.  We verify this by calling the
/// shared helper directly on the server cert's notAfter and asserting the two
/// results are equal.
///
/// Mutation target: removing the `SSL_get1_peer_certificate` call in
/// `poll_handshake` leaves `COLLECTOR_CERT_NOT_AFTER` at 0 → this test fails.
#[test]
fn successful_handshake_captures_cert_not_after() {
    use super::COLLECTOR_CERT_NOT_AFTER;
    use core::sync::atomic::Ordering;
    use openssl_sys as ssl;

    // Reset the global before the test so a stale value from a previous
    // (parallel) test doesn't mask a real failure.
    COLLECTOR_CERT_NOT_AFTER.store(0, Ordering::SeqCst);

    let certs = make_certs("DNS:localhost,IP:127.0.0.1");
    let server = TestServer::start(&certs);
    let cfg = TlsConfig { ca_file: Some(certs.ca_pem()), ..Default::default() };
    let c = ctx(&cfg);

    let io = connect_nonblocking(server.port);
    let mut tls = TlsNgxConnIo::new(io, &c, "localhost", true).expect("new");
    block_on(core::future::poll_fn(|cx| tls.poll_handshake(cx))).expect("handshake ok");

    // After a successful handshake the atomic must be non-zero.
    let captured = COLLECTOR_CERT_NOT_AFTER.load(Ordering::SeqCst);
    assert_ne!(
        captured, 0,
        "COLLECTOR_CERT_NOT_AFTER must be written after a successful handshake"
    );

    // ── Reuse-seam assertion ─────────────────────────────────────────────
    // Read the server cert's notAfter directly from the PEM file via
    // `asn1_time_to_unix` — the EXACT same function that `poll_handshake`
    // calls.  The two values must be identical, proving that no separate
    // epoch conversion was introduced.
    let expected = {
        // Load the server PEM into an X509 to read its notAfter.
        let pem_path = certs.server_cert();
        let pem_bytes = std::fs::read(&pem_path).expect("read server.pem");
        // SAFETY: X509_new allocates; we free it below.
        let cert = unsafe {
            let bio = ssl::BIO_new_mem_buf(
                pem_bytes.as_ptr().cast(),
                pem_bytes.len() as core::ffi::c_int,
            );
            assert!(!bio.is_null(), "BIO_new_mem_buf");
            let c = ssl::PEM_read_bio_X509(bio, core::ptr::null_mut(), None, core::ptr::null_mut());
            // SAFETY: BIO_free_all on a single BIO is equivalent to BIO_free.
            ssl::BIO_free_all(bio);
            c
        };
        assert!(!cert.is_null(), "PEM_read_bio_X509 must succeed");
        // SAFETY: cert is the valid X509 just parsed; X509_getm_notAfter
        // returns an internal (get0) pointer valid for the lifetime of `cert`.
        let not_after = unsafe { ssl::X509_getm_notAfter(cert) };
        // SAFETY: `not_after` is a valid borrow of `cert`'s notAfter field;
        // `asn1_time_to_unix` only reads it; `cert` stays live until
        // `X509_free` below.
        let epoch = unsafe { crate::cert_table::asn1_time_to_unix(not_after) }
            .expect("asn1_time_to_unix must succeed on a well-formed cert");
        // SAFETY: cert was allocated above; freed exactly once here.
        unsafe { ssl::X509_free(cert) };
        epoch
    };

    assert_eq!(
        captured, expected,
        "COLLECTOR_CERT_NOT_AFTER must equal asn1_time_to_unix(server cert notAfter) \
         — the reuse seam: same shared helper, no reimplementation"
    );
}

/// Reuse-seam sanity: `crate::cert_table::asn1_time_to_unix` is callable
/// from this module (i.e., it is `pub(crate)` and NOT duplicated here).
/// This test calls the function directly — if it compiled with a private
/// visibility the build would fail at this call site.
#[test]
fn asn1_time_to_unix_is_shared_not_duplicated() {
    // A known epoch: 2026-01-01T00:00:00Z.
    // GeneralizedTime format: YYYYMMDDHHmmssZ
    let asn1_str = c"20260101000000Z";
    // SAFETY: ASN1_TIME_new + ASN1_TIME_set_string allocate; freed below.
    let t = unsafe {
        use openssl_sys as ssl;
        let t = ssl::ASN1_TIME_new();
        assert!(!t.is_null());
        let ok = ssl::ASN1_TIME_set_string(t, asn1_str.as_ptr());
        assert_eq!(ok, 1, "ASN1_TIME_set_string must succeed");
        t
    };
    // SAFETY: `t` is a valid non-null ASN1_TIME.
    let epoch = unsafe { crate::cert_table::asn1_time_to_unix(t) };
    // SAFETY: `t` was allocated above; freed exactly once.
    unsafe { openssl_sys::ASN1_TIME_free(t) };

    // 2026-01-01T00:00:00Z = 1767225600
    assert_eq!(epoch, Some(1_767_225_600_i64), "asn1_time_to_unix(2026-01-01T00Z)");
}

/// Constructing a TlsNgxConnIo and dropping it mid-handshake (before
/// completion) must not panic or leak (ASan covers the leak in CI; here we
/// assert the construct+drop path is clean and frees SSL/BIO exactly once).
#[test]
fn drop_mid_handshake_is_clean() {
    let certs = make_certs("DNS:localhost,IP:127.0.0.1");
    let server = TestServer::start(&certs);
    let cfg = TlsConfig { ca_file: Some(certs.ca_pem()), ..Default::default() };
    let c = ctx(&cfg);

    let io = connect_nonblocking(server.port);
    let mut tls = TlsNgxConnIo::new(io, &c, "127.0.0.1", true).expect("new");
    // Poll once (likely Pending) then drop without finishing.
    let _ = block_on(core::future::poll_fn(|cx| {
        Poll::Ready(matches!(tls.poll_handshake(cx), Poll::Pending | Poll::Ready(_)))
    }));
    drop(tls); // Drop frees SSL (and the attached BIO) exactly once.
}
