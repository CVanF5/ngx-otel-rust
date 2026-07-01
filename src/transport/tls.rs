// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Async TLS engine for the OTLP exporter transport (`https://`).
//!
//! [`TlsNgxConnIo`] wraps an inner async byte stream (production:
//! `Pin<Box<NgxConnIo>>`; tests: any `hyper::rt::Read + Write`) with an OpenSSL
//! `SSL` client session, performing TLS record framing so that hyper/tonic see
//! a plaintext duplex stream. One type serves BOTH transports (HTTP/1.1 and
//! h2/tonic) because both consume anything implementing
//! `hyper::rt::Read + hyper::rt::Write + Unpin + 'static`.
//!
//! This code runs ONLY in the exporter process; no worker-side code path
//! touches it. No Tokio, no threads — the handshake/IO is driven entirely by
//! the existing waker contract (store-the-waker, return `Pending`; the inner
//! IO's C event handlers fire `wake()`).
//!
//! # BIO ↔ poll re-entrancy contract (THE risk of this module)
//!
//! OpenSSL's `SSL_connect` / `SSL_read` / `SSL_write` need to read and write
//! raw bytes; the `SSL`'s custom `BIO` forwards its read/write callbacks to
//! the inner stream's `poll_read` / `poll_write`. The danger is re-entrancy:
//! those callbacks fire *synchronously from inside* the `SSL_*` call that our
//! own `poll_*` is making. Three rules keep this sound and deadlock-free:
//!
//! 1. **Single direction of calls.** `Self::poll_*` → `SSL_*` → `bio_read` /
//!    `bio_write` → `inner.poll_*`, never the reverse — the BIO callbacks
//!    never call back into `SSL_*`, so there is no recursion and no lock to
//!    re-enter.
//! 2. **The `Context` is published, not captured.** Before each `SSL_*` call
//!    the calling `poll_*` stores a raw pointer to its live `Context` (and a
//!    pinned pointer to the inner IO) into a `BioCtx` that the BIO's `data`
//!    slot points at; the callbacks dereference it to build the `Context`
//!    they hand to `inner.poll_*`. The pointer is valid only for that call's
//!    duration (the `Context` lives on the `poll_*` stack frame, which
//!    outlives the nested call); it is cleared immediately after so a stale
//!    pointer can never be dereferenced later.
//! 3. **Pending → retry, never recurse.** When `inner.poll_*` returns
//!    `Pending`, the callback signals `BIO_set_retry_read`/`_write` and
//!    returns `-1`, which OpenSSL turns into `SSL_ERROR_WANT_READ`/`WRITE`;
//!    our `poll_*` then returns `Pending` too. The inner IO's own waker
//!    contract handles the wakeup — no busy-spin, no recursive poll.
//!
//! # OpenSSL object ownership (free exactly once; no double-free)
//!
//! - `SSL_CTX` (in [`TlsConfig::build_ctx`]): `SSL_CTX_new`-created, owned by
//!   [`SslCtx`], freed once via `SslCtx::drop`'s `SSL_CTX_free`.
//! - `SSL` (in [`TlsNgxConnIo`]): `SSL_new`-created (takes its own ref on the
//!   `SSL_CTX`), owned by the `TlsNgxConnIo`, freed once by its `Drop`.
//! - `BIO`: `BIO_new`-created. `SSL_set_bio(ssl, bio, bio)` passes the same
//!   `BIO` as both read and write side; per `SSL_set_bio(3)`, when
//!   `rbio == wbio` exactly **one** reference is consumed, and ownership
//!   transfers to the `SSL` — `SSL_free` frees it. We therefore MUST NOT call
//!   `BIO_free_all` ourselves (double-free). In `TlsNgxConnIo::new` the only
//!   early-return before `SSL_set_bio` is `BIO_new` returning null (nothing to
//!   free yet); once it succeeds, `SSL_set_bio` runs unconditionally.
//! - `BIO_METHOD`: created once **per concrete inner-IO type `I`** (keyed by
//!   `TypeId` in `BIO_METHODS`) via `BIO_meth_new`, never freed (process-
//!   lifetime, like `'static`). Per-`I` keying is required for soundness: the
//!   callbacks are `I`-monomorphized and cast the BIO `data` slot to
//!   `*mut BioCtx<I>`, so a method built for one `I` must never attach to a
//!   BIO carrying another `I`'s `BioCtx` — that would type-pun the pointer.
//!   OpenSSL does not free a method when a BIO using it is freed.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use core::ffi::{c_char, c_int, c_long, c_void, CStr};
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicI64, Ordering};
use core::task::{Context, Poll};
use std::io;
use std::sync::Once;

use openssl_sys as ssl;

use super::TransportError;

// ── Collector-cert gauge ──────────────────────────────────────────────────────

/// `notAfter` of the peer certificate from the most recent successful TLS
/// handshake with the collector, as Unix epoch seconds.
///
/// `0`  = no successful TLS handshake yet in this exporter generation
///        (plaintext endpoint, or TLS not yet attempted) — the metric is
///        **absent** (absent rather than reported as zero) when this
///        value is zero.
///
/// Written **once per successful handshake** by `TlsNgxConnIo::poll_handshake`
/// (the exporter is single-threaded; the `Relaxed` store/load is sound because
/// the write and the read in `collect_all_sources` happen on the same thread,
/// the nginx exporter event loop, with no concurrent writers).
///
/// The value is **stable per exporter generation**: the collector cert does not
/// change mid-connection; every handshake with the same collector endpoint
/// writes the same value.
pub(crate) static COLLECTOR_CERT_NOT_AFTER: AtomicI64 = AtomicI64::new(0);

// ──────────────────────────────────────────────────────────────────────────────
// TlsConfig + SSL_CTX builder
// ──────────────────────────────────────────────────────────────────────────────

/// TLS client configuration for the exporter connection.
///
/// Built from the `otel_exporter { }` directives: `ca_file` from
/// `trusted_certificate`, `client_cert`/`client_key` from `ssl_certificate` /
/// `ssl_certificate_key`, `insecure` from `ssl_verify off`.
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    /// CA bundle path (`trusted_certificate`). `None` → system default trust
    /// store (`SSL_CTX_set_default_verify_paths`).
    pub ca_file: Option<String>,
    /// mTLS client certificate chain path (`ssl_certificate`). Used only when
    /// BOTH this and `client_key` are set.
    pub client_cert: Option<String>,
    /// mTLS client private key path (`ssl_certificate_key`).
    pub client_key: Option<String>,
    /// Skip server-certificate verification (`ssl_verify off`). INSECURE.
    pub insecure: bool,
}

/// One-shot guard so the `ssl_verify off` insecure WARN is logged once per
/// process, not once per connection.
static INSECURE_WARNED: Once = Once::new();

/// Owns an `SSL_CTX`. Freed exactly once on drop via `SSL_CTX_free`.
pub struct SslCtx {
    ctx: *mut ssl::SSL_CTX,
}

// SAFETY: the exporter is single-threaded (one nginx event loop). The `SSL_CTX`
// is constructed and used only on that thread. `Send` lets it live in the
// transport state moved into the export task; no concurrent access occurs.
unsafe impl Send for SslCtx {}

impl SslCtx {
    /// Raw pointer to the underlying `SSL_CTX` (borrowed; not transferred).
    pub fn as_ptr(&self) -> *mut ssl::SSL_CTX {
        self.ctx
    }
}

impl Drop for SslCtx {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // SAFETY: `self.ctx` was returned by `SSL_CTX_new` in `build_ctx`
            // and is owned solely by this `SslCtx`; `Drop` runs once, so the
            // context is freed exactly once. `SSL_CTX_free` decrements the
            // refcount (any `SSL` created from it held its own ref).
            unsafe { ssl::SSL_CTX_free(self.ctx) };
        }
    }
}

/// Pull the most recent OpenSSL error off the per-thread queue as a String,
/// draining the queue. Returns a placeholder when the queue is empty.
fn openssl_err() -> String {
    // SAFETY: `ERR_get_error` reads/pops the per-thread OpenSSL error queue;
    // no arguments, no aliasing. Returns 0 when empty.
    let code = unsafe { ssl::ERR_get_error() };
    if code == 0 {
        return "no OpenSSL error on queue".to_string();
    }
    // SAFETY: `ERR_reason_error_string` returns a borrowed static string (or
    // null) describing the reason of `code`; no ownership transfer.
    let reason = unsafe { ssl::ERR_reason_error_string(code) };
    let msg = if reason.is_null() {
        alloc::format!("OpenSSL error 0x{code:x}")
    } else {
        // SAFETY: `reason` is a non-null, NUL-terminated, static C string.
        let s = unsafe { CStr::from_ptr(reason) };
        s.to_string_lossy().into_owned()
    };
    // Drain any remaining queued errors so they don't leak into a later call.
    // SAFETY: popping the thread-local error queue until empty.
    while unsafe { ssl::ERR_get_error() } != 0 {}
    msg
}

impl TlsConfig {
    /// Build a client `SSL_CTX` from this config.
    ///
    /// - method: `TLS_client_method`
    /// - minimum protocol: TLS 1.2
    /// - verify mode: `SSL_VERIFY_PEER` unless `insecure` (`SSL_VERIFY_NONE`
    ///   + one-shot WARN via `log_warn`)
    /// - trust anchors: `SSL_CTX_load_verify_locations(ca_file)` if set, else
    ///   `SSL_CTX_set_default_verify_paths`
    /// - client cert/key: loaded only when BOTH paths are set, then
    ///   `SSL_CTX_check_private_key`
    ///
    /// `log_warn` receives the insecure-mode warning string (caller routes it
    /// to the nginx log). Errors map to [`TransportError::TlsConfig`].
    pub fn build_ctx<F: FnOnce(&str)>(&self, log_warn: F) -> Result<SslCtx, TransportError> {
        // SAFETY: `TLS_client_method` returns a static, immutable method table
        // pointer; `SSL_CTX_new` consumes it (borrows, does not free) and
        // returns a fresh owned `SSL_CTX` or null on allocation failure.
        let ctx = unsafe { ssl::SSL_CTX_new(ssl::TLS_client_method()) };
        if ctx.is_null() {
            return Err(TransportError::TlsConfig {
                cause: alloc::format!("SSL_CTX_new failed: {}", openssl_err()),
            });
        }
        // Take ownership immediately so any early-return below frees the ctx.
        let owned = SslCtx { ctx };

        // SAFETY: `ctx` is the freshly-created, owned context. These setters
        // mutate it in place; `TLS1_2_VERSION` is a valid version constant.
        // `SSL_CTX_set_min_proto_version` returns 0 on failure.
        if unsafe { ssl::SSL_CTX_set_min_proto_version(ctx, ssl::TLS1_2_VERSION) } != 1 {
            return Err(TransportError::TlsConfig {
                cause: alloc::format!("set_min_proto_version(TLS1.2) failed: {}", openssl_err()),
            });
        }

        if self.insecure {
            // SAFETY: `ctx` is the owned context; `SSL_VERIFY_NONE` disables
            // peer verification. Passing a null verify callback is valid.
            unsafe { ssl::SSL_CTX_set_verify(ctx, ssl::SSL_VERIFY_NONE, None) };
            INSECURE_WARNED.call_once(|| {
                log_warn(
                    "ssl_verify off: collector certificate verification is DISABLED \
                     (INSECURE — for testing only)",
                );
            });
        } else {
            // SAFETY: `ctx` is the owned context; enable peer verification.
            // A null callback means "use the default verification result".
            unsafe { ssl::SSL_CTX_set_verify(ctx, ssl::SSL_VERIFY_PEER, None) };

            // Load trust anchors.
            match &self.ca_file {
                Some(path) => {
                    let c_path = to_cstring(path)?;
                    // SAFETY: `ctx` is owned; `c_path` is a valid NUL-terminated
                    // C string outliving the call. Second arg null = no CA dir.
                    let rc = unsafe {
                        ssl::SSL_CTX_load_verify_locations(ctx, c_path.as_ptr(), ptr::null())
                    };
                    if rc != 1 {
                        return Err(TransportError::TlsConfig {
                            cause: alloc::format!(
                                "load_verify_locations({path}) failed: {}",
                                openssl_err()
                            ),
                        });
                    }
                }
                None => {
                    // SAFETY: `ctx` is owned; loads OpenSSL's compiled-in default
                    // trust store paths. Returns 0 on failure.
                    if unsafe { ssl::SSL_CTX_set_default_verify_paths(ctx) } != 1 {
                        return Err(TransportError::TlsConfig {
                            cause: alloc::format!(
                                "set_default_verify_paths failed: {}",
                                openssl_err()
                            ),
                        });
                    }
                }
            }
        }

        // mTLS: load client cert + key only when BOTH are configured.
        // Config-time validation (cert-without-key etc.) happens at parse time;
        // here we simply require both present before attempting mTLS.
        if let (Some(cert), Some(key)) = (&self.client_cert, &self.client_key) {
            {
                let c_cert = to_cstring(cert)?;
                let c_key = to_cstring(key)?;
                // SAFETY: `ctx` owned; `c_cert` is a valid NUL-terminated path
                // outliving the call. PEM type constant is correct.
                if unsafe { ssl::SSL_CTX_use_certificate_chain_file(ctx, c_cert.as_ptr()) } != 1 {
                    return Err(TransportError::TlsConfig {
                        cause: alloc::format!(
                            "use_certificate_chain_file({cert}) failed: {}",
                            openssl_err()
                        ),
                    });
                }
                // SAFETY: `ctx` owned; `c_key` valid NUL-terminated path;
                // `SSL_FILETYPE_PEM` selects PEM parsing.
                if unsafe {
                    ssl::SSL_CTX_use_PrivateKey_file(ctx, c_key.as_ptr(), ssl::SSL_FILETYPE_PEM)
                } != 1
                {
                    return Err(TransportError::TlsConfig {
                        cause: alloc::format!(
                            "use_PrivateKey_file({key}) failed: {}",
                            openssl_err()
                        ),
                    });
                }
                // SAFETY: `ctx` owned; validates that the loaded key matches the
                // loaded cert. Returns 0 on mismatch.
                if unsafe { ssl::SSL_CTX_check_private_key(ctx) } != 1 {
                    return Err(TransportError::TlsConfig {
                        cause: alloc::format!(
                            "check_private_key failed (cert/key mismatch): {}",
                            openssl_err()
                        ),
                    });
                }
            }
        }

        Ok(owned)
    }
}

/// Returns `true` when `host` is an IP literal (v4 or v6), which must NOT be
/// sent as an SNI HostName (RFC 6066 §3). `host` is expected already
/// unbracketed (the connector strips IPv6 `[]`); we also accept a bracketed
/// IPv6 form defensively by trimming a single surrounding pair.
fn is_ip_literal(host: &str) -> bool {
    let h = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
    h.parse::<std::net::IpAddr>().is_ok()
}

/// Convert a Rust path string to a C string, mapping interior-NUL to a
/// `TlsConfig` error (paths must not contain NUL).
fn to_cstring(s: &str) -> Result<alloc::ffi::CString, TransportError> {
    alloc::ffi::CString::new(s).map_err(|_| TransportError::TlsConfig {
        cause: alloc::format!("path contains interior NUL byte: {s:?}"),
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Custom BIO: bridges OpenSSL record IO to the inner async stream
// ──────────────────────────────────────────────────────────────────────────────

/// Per-connection data hung off the custom `BIO`'s `data` slot.
///
/// `inner` and `cx` are *published* by the active `poll_*` method only for the
/// duration of a single `SSL_*` call (see the module-level re-entrancy
/// contract) and cleared immediately after. Outside an `SSL_*` call they are
/// null, so a stale-pointer deref is impossible.
struct BioCtx<I> {
    /// Raw pointer to the inner IO (`&mut I`), valid only during an `SSL_*`
    /// call published by `with_published`.
    inner: *mut I,
    /// Raw pointer to the live `Context<'_>` of the active `poll_*`, valid only
    /// during an `SSL_*` call.
    cx: *mut Context<'static>,
}

impl<I> BioCtx<I> {
    fn new() -> Self {
        Self { inner: ptr::null_mut(), cx: ptr::null_mut() }
    }
}

/// `BIO_TYPE_SOURCE_SINK | <next index>` — a source/sink BIO. We OR the
/// source/sink class bit with a fresh per-process index from
/// `BIO_get_new_index`.
const BIO_TYPE_SOURCE_SINK: c_int = 0x0400;

/// Process-wide registry of custom `BIO_METHOD`s, keyed by the concrete
/// inner-IO type `I` (`TypeId`). The method-table pointer is stored as `usize`
/// (raw pointers are not `Send`); it is a process-lifetime allocation never
/// freed (like a `'static`).
///
/// Keying per `I` is REQUIRED for soundness: the read/write callbacks are
/// monomorphized per `I` (`bio_read::<I>` casts the BIO `data` slot to
/// `*mut BioCtx<I>`), so a method built for one `I` must never be attached to a
/// BIO carrying a `BioCtx` of a different `I` — that would type-pun the data
/// pointer. A plain process-global (or a `static` inside this generic fn, which
/// Rust shares across all monomorphizations) would do exactly that when more
/// than one `I` exists in a process (e.g. the test binary uses both `TestIo`
/// and `SpinIo`). In production there is a single `I` (`Pin<Box<NgxConnIo>>`).
static BIO_METHODS: std::sync::Mutex<std::vec::Vec<(core::any::TypeId, usize)>> =
    std::sync::Mutex::new(std::vec::Vec::new());

/// Get (lazily creating) the custom `BIO_METHOD` for the inner-IO type `I`.
fn bio_method<I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static>(
) -> Result<*const ssl::BIO_METHOD, TransportError> {
    let key = core::any::TypeId::of::<I>();
    let mut reg = BIO_METHODS.lock().unwrap_or_else(|e| e.into_inner());

    if let Some((_, p)) = reg.iter().find(|(k, _)| *k == key) {
        return Ok(*p as *const ssl::BIO_METHOD);
    }

    // SAFETY: `BIO_get_new_index` allocates a fresh BIO type index;
    // `BIO_meth_new` allocates a method table with that type + a static name.
    // Both are standard one-shot setup calls.
    let m = unsafe {
        let idx = ssl::BIO_get_new_index();
        let name = c"ngx-otel-tls-bio".as_ptr();
        ssl::BIO_meth_new(BIO_TYPE_SOURCE_SINK | idx, name)
    };
    if m.is_null() {
        return Err(TransportError::TlsConfig {
            cause: "BIO_meth_new failed (out of memory)".to_string(),
        });
    }
    // SAFETY: `m` is the freshly-allocated method table; these setters install
    // our `I`-monomorphized callbacks. The function-pointer types match
    // OpenSSL's "new" BIO method signatures (the `__fixed_rust` aliases in
    // openssl-sys).
    unsafe {
        ssl::BIO_meth_set_write__fixed_rust(m, Some(bio_write::<I>));
        ssl::BIO_meth_set_read__fixed_rust(m, Some(bio_read::<I>));
        ssl::BIO_meth_set_ctrl__fixed_rust(m, Some(bio_ctrl));
        ssl::BIO_meth_set_create__fixed_rust(m, Some(bio_create));
        ssl::BIO_meth_set_destroy__fixed_rust(m, Some(bio_destroy));
    }
    reg.push((key, m as usize));
    Ok(m)
}

// ──────────────────────────────────────────────────────────────────────────────
// Safety note: abort-on-unwind for extern "C" callbacks
//
// All BIO callbacks below (`bio_create`, `bio_destroy`, `bio_ctrl`,
// `bio_read`, `bio_write`) are declared `extern "C"`.  Since Rust 1.81,
// unwinding across an `extern "C"` ABI boundary causes the process to
// **abort** (not unwind into OpenSSL's C stack, which would be UB).
//
// None of these callbacks panics intentionally.  The abort-on-unwind
// guarantee from rustc >=1.81 means that an unexpected panic here is still
// sound — it terminates the exporter process rather than corrupting the C
// call stack — so no `catch_unwind` wrapper is needed.
// ──────────────────────────────────────────────────────────────────────────────

/// BIO create callback: initialize a fresh BIO. We mark it initialized; the
/// `data` slot (our `BioCtx`) is set later by `TlsNgxConnIo::new`.
unsafe extern "C" fn bio_create(b: *mut ssl::BIO) -> c_int {
    // SAFETY: `b` is the BIO OpenSSL just allocated for us; `BIO_set_init(1)`
    // marks it ready. Data is attached by the caller post-`BIO_new`.
    unsafe { ssl::BIO_set_init(b, 1) };
    1
}

/// BIO destroy callback: nothing to free here. The `BioCtx` is owned by the
/// `TlsNgxConnIo` (a `Box`), not by the BIO, so we must NOT free it here —
/// freeing it here would double-free when `TlsNgxConnIo::drop` drops the Box.
unsafe extern "C" fn bio_destroy(_b: *mut ssl::BIO) -> c_int {
    1
}

/// BIO ctrl callback: answer the control queries OpenSSL issues. The only one
/// that matters for a plain source/sink BIO is `BIO_CTRL_FLUSH` (return 1 =
/// success; our inner stream needs no explicit flush).
unsafe extern "C" fn bio_ctrl(
    _b: *mut ssl::BIO,
    cmd: c_int,
    _larg: c_long,
    _parg: *mut c_void,
) -> c_long {
    match cmd {
        ssl::BIO_CTRL_FLUSH => 1,
        _ => 0,
    }
}

/// Recover the `BioCtx<I>` from a BIO's data slot.
///
/// # Safety
/// `b` must be one of our BIOs whose `data` slot holds a live `*mut BioCtx<I>`
/// for the same `I`.
unsafe fn bio_ctx<'a, I>(b: *mut ssl::BIO) -> Option<&'a mut BioCtx<I>> {
    // SAFETY: caller guarantees `b`'s data slot is a `*mut BioCtx<I>` we set in
    // `new`. It is non-null for a live BIO and outlives every `SSL_*` call.
    let p = unsafe { ssl::BIO_get_data(b) }.cast::<BioCtx<I>>();
    // SAFETY: `p` is that pointer; the `BioCtx` is owned by the live
    // `TlsNgxConnIo` and is not aliased mutably elsewhere during the call.
    unsafe { p.as_mut() }
}

/// BIO read callback. Forwards to `inner.poll_read`. On `Pending` it signals
/// `BIO_set_retry_read` and returns -1 (→ `SSL_ERROR_WANT_READ`). NEVER calls
/// any `SSL_*` function — see the module re-entrancy contract.
unsafe extern "C" fn bio_read<I: hyper::rt::Read + Unpin>(
    b: *mut ssl::BIO,
    buf: *mut c_char,
    len: c_int,
) -> c_int {
    // SAFETY: `b` is our BIO; clearing its retry flags before this read.
    unsafe { ssl::BIO_clear_retry_flags(b) };
    // SAFETY: `b`'s data slot is the live `BioCtx<I>` published by the active
    // `poll_*` (re-entrancy contract); recovering it as a `&mut`.
    let Some(ctx) = (unsafe { bio_ctx::<I>(b) }) else {
        return -1;
    };
    if ctx.inner.is_null() || ctx.cx.is_null() || len <= 0 {
        // Called outside a published `SSL_*` window, or zero-length request.
        return -1;
    }
    // SAFETY: `inner` is non-null (checked) and valid for this call's duration:
    // the `poll_*` that published it strictly outlives the nested
    // `SSL_*` → bio_read call; it is the only `&mut I` in scope.
    let inner: Pin<&mut I> = unsafe { Pin::new_unchecked(&mut *ctx.inner) };
    // SAFETY: `cx` is non-null (checked) and points at the live `Context` of
    // the active `poll_*`, valid for this nested call's duration.
    let cx: &mut Context<'_> = unsafe { &mut *ctx.cx };

    // Build a hyper ReadBuf over the C buffer (uninitialized region of `len`).
    // SAFETY: OpenSSL guarantees `buf`/`len` describe a writable region of
    // `len` bytes; we view it as `MaybeUninit<u8>` for hyper's ReadBuf.
    let slice = unsafe {
        core::slice::from_raw_parts_mut(buf.cast::<core::mem::MaybeUninit<u8>>(), len as usize)
    };
    let mut read_buf = hyper::rt::ReadBuf::uninit(slice);
    match inner.poll_read(cx, read_buf.unfilled()) {
        Poll::Ready(Ok(())) => {
            let n = read_buf.filled().len();
            if n == 0 {
                // Clean EOF from the inner stream. Returning 0 tells OpenSSL the
                // transport closed (it surfaces as SSL_ERROR_ZERO_RETURN /
                // SYSCALL during the handshake or read).
                0
            } else {
                n as c_int
            }
        }
        Poll::Ready(Err(_)) => -1,
        Poll::Pending => {
            // SAFETY: `b` is our BIO; set the WANT_READ retry flag so OpenSSL
            // returns SSL_ERROR_WANT_READ instead of treating -1 as fatal.
            unsafe { ssl::BIO_set_retry_read(b) };
            -1
        }
    }
}

/// BIO write callback. Mirror of `bio_read` for the write side.
unsafe extern "C" fn bio_write<I: hyper::rt::Write + Unpin>(
    b: *mut ssl::BIO,
    buf: *const c_char,
    len: c_int,
) -> c_int {
    // SAFETY: `b` is our BIO; clearing its retry flags before this write.
    unsafe { ssl::BIO_clear_retry_flags(b) };
    // SAFETY: `b`'s data slot is the live `BioCtx<I>` published by the active
    // `poll_*` (re-entrancy contract); recovering it as a `&mut`.
    let Some(ctx) = (unsafe { bio_ctx::<I>(b) }) else {
        return -1;
    };
    if ctx.inner.is_null() || ctx.cx.is_null() || len <= 0 {
        return -1;
    }
    // SAFETY: `inner` is non-null (checked) and outlives this nested call (the
    // publishing `poll_*` frame); it is the only `&mut I` in scope.
    let inner: Pin<&mut I> = unsafe { Pin::new_unchecked(&mut *ctx.inner) };
    // SAFETY: `cx` is non-null (checked), the live `Context` of the active
    // `poll_*`, valid for this nested call's duration.
    let cx: &mut Context<'_> = unsafe { &mut *ctx.cx };

    // SAFETY: OpenSSL guarantees `buf`/`len` is a readable region of `len`
    // bytes for the duration of the call.
    let slice = unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), len as usize) };
    match inner.poll_write(cx, slice) {
        Poll::Ready(Ok(n)) => {
            if n == 0 {
                -1
            } else {
                n as c_int
            }
        }
        Poll::Ready(Err(_)) => -1,
        Poll::Pending => {
            // SAFETY: `b` is our BIO; signal WANT_WRITE.
            unsafe { ssl::BIO_set_retry_write(b) };
            -1
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TlsNgxConnIo
// ──────────────────────────────────────────────────────────────────────────────

/// Handshake state machine.
#[derive(PartialEq, Eq, Clone, Copy)]
enum HandshakeState {
    Pending,
    Done,
}

/// Async TLS stream wrapping an inner async byte stream `I`.
///
/// See the module docs for the BIO re-entrancy and OpenSSL ownership contract.
pub struct TlsNgxConnIo<I> {
    /// The inner raw stream. Boxed so its address is stable for the
    /// `BioCtx.inner` raw pointer published into BIO callbacks (the box is
    /// never reallocated for the life of the `TlsNgxConnIo`).
    inner: Box<I>,
    /// The owned SSL session. Frees itself (and the attached BIO) on drop.
    ssl: *mut ssl::SSL,
    /// Per-connection BIO bridge data. Owned here; the BIO's `data` slot points
    /// at it. Boxed for address stability.
    bio_ctx: Box<BioCtx<I>>,
    handshake: HandshakeState,
}

// SAFETY: single-threaded exporter event loop; see `SslCtx`.
unsafe impl<I: Send> Send for TlsNgxConnIo<I> {}

impl<I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static> TlsNgxConnIo<I> {
    /// Create a TLS stream over `inner` using `ctx`, with SNI / hostname
    /// verification for `server_name`.
    ///
    /// `verify_hostname` controls whether `X509_VERIFY_PARAM_set1_host` is
    /// applied (skip it under `ssl_verify off`, where verification is disabled
    /// anyway). The handshake itself is driven later by [`poll_handshake`].
    ///
    /// [`poll_handshake`]: TlsNgxConnIo::poll_handshake
    pub fn new(
        inner: I,
        ctx: &SslCtx,
        server_name: &str,
        verify_hostname: bool,
    ) -> Result<Self, TransportError> {
        let method = bio_method::<I>()?;

        // SAFETY: `ctx.as_ptr()` is a live, owned `SSL_CTX`; `SSL_new` takes its
        // own ref on it and returns a fresh owned `SSL` (or null).
        let ssl_ptr = unsafe { ssl::SSL_new(ctx.as_ptr()) };
        if ssl_ptr.is_null() {
            return Err(TransportError::TlsConfig {
                cause: alloc::format!("SSL_new failed: {}", openssl_err()),
            });
        }

        // SAFETY: `method` is our process-global method table; `BIO_new`
        // allocates a BIO using it (or null on OOM). The only early-return path
        // before `SSL_set_bio` is `BIO_new` returning null — in that case no
        // BIO exists, so nothing to free. On success, `SSL_set_bio` (below)
        // consumes this single ref; `SSL_free` will then free the BIO for us.
        let bio = unsafe { ssl::BIO_new(method) };
        if bio.is_null() {
            // SAFETY: `ssl_ptr` is the owned SSL with no BIO attached yet; free
            // it to avoid a leak before returning the error.
            unsafe { ssl::SSL_free(ssl_ptr) };
            return Err(TransportError::TlsConfig {
                cause: alloc::format!("BIO_new failed: {}", openssl_err()),
            });
        }

        let mut bio_ctx = Box::new(BioCtx::<I>::new());
        // Attach the BioCtx to the BIO. The box's address is stable (it is
        // owned by `self` and never moved/reallocated).
        // SAFETY: `bio` is our freshly-created live BIO; storing a pointer to
        // the owned `BioCtx` in its data slot. The BioCtx outlives the BIO
        // because `SSL_free` (which frees the BIO) runs in `Drop` before the
        // `bio_ctx` Box is dropped (field drop order: declaration order, but we
        // free the SSL explicitly in `Drop` first — see `Drop` impl).
        unsafe { ssl::BIO_set_data(bio, ptr::from_mut(&mut *bio_ctx).cast::<c_void>()) };

        // Transfer BIO ownership to the SSL. Passing the SAME bio as rbio and
        // wbio consumes exactly ONE reference (SSL_set_bio(3)); `SSL_free` will
        // free it. We must NOT free `bio` ourselves after this point.
        // SAFETY: `ssl_ptr` owned SSL; `bio` our live BIO. After this call the
        // SSL owns the BIO's single ref.
        unsafe { ssl::SSL_set_bio(ssl_ptr, bio, bio) };

        // Client mode.
        // SAFETY: `ssl_ptr` is the owned SSL; sets it to perform a client
        // handshake on the next `SSL_connect`.
        unsafe { ssl::SSL_set_connect_state(ssl_ptr) };

        // SNI: set the server name extension (host the collector expects).
        //
        // RFC 6066 §3 forbids IP literals in the SNI HostName ("Literal IPv4
        // and IPv6 addresses are not permitted"). Strict / SNI-routed front
        // ends may reject or mis-route a ClientHello carrying an IP as SNI, so
        // we suppress the extension entirely for IP-literal `server_name`s
        // (the IP path verifies via `X509_VERIFY_PARAM_set1_ip(_asc)` instead).
        // For DNS names we set SNI as normal.
        if !is_ip_literal(server_name) {
            if let Ok(c_name) = to_cstring(server_name) {
                // SAFETY: `ssl_ptr` owned SSL; `SSL_set_tlsext_host_name` is the
                // SNI macro (SSL_ctrl under the hood). It copies the string, so
                // the temporary `c_name` need not outlive the call. The cast to
                // `*mut c_char` matches the macro signature (it does not mutate).
                unsafe {
                    ssl::SSL_set_tlsext_host_name(ssl_ptr, c_name.as_ptr().cast_mut());
                }
            }
        }

        // Hostname verification via X509_VERIFY_PARAM_set1_host (SSL_set1_host
        // is absent from openssl-sys 0.9.116; the VERIFY_PARAM path is the
        // documented equivalent and IS present — verified before coding).
        if verify_hostname {
            // SAFETY: `ssl_ptr` owned SSL; `SSL_get0_param` returns a borrowed
            // (non-owned) pointer to the SSL's verify param, valid while the
            // SSL lives. We do not free it.
            let param = unsafe { ssl::SSL_get0_param(ssl_ptr) };
            // SAFETY: `param` is that borrowed verify param; `set1_host`
            // copies `server_name`/len into it (so the slice need not outlive
            // the call). Returns 0 on failure.
            let rc = unsafe {
                ssl::X509_VERIFY_PARAM_set1_host(
                    param,
                    server_name.as_ptr().cast::<c_char>(),
                    server_name.len(),
                )
            };
            if rc != 1 {
                // SAFETY: `ssl_ptr` owned, BIO already attached → `SSL_free`
                // frees both exactly once. `bio_ctx` Box drops normally after.
                unsafe { ssl::SSL_free(ssl_ptr) };
                return Err(TransportError::TlsConfig {
                    cause: alloc::format!(
                        "X509_VERIFY_PARAM_set1_host({server_name}) failed: {}",
                        openssl_err()
                    ),
                });
            }
        }

        Ok(Self {
            inner: Box::new(inner),
            ssl: ssl_ptr,
            bio_ctx,
            handshake: HandshakeState::Pending,
        })
    }

    /// Raw pointer to the owned `SSL` session.
    ///
    /// Exposed for callers that need to perform additional per-connection
    /// `SSL_*` configuration after `new` but before the handshake (e.g.
    /// `X509_VERIFY_PARAM_set1_ip_asc` for IP-literal endpoints).
    ///
    /// The pointer is owned by this `TlsNgxConnIo` and freed in `Drop`.
    /// Callers MUST NOT free it themselves.
    pub fn ssl_ptr(&self) -> *mut ssl::SSL {
        self.ssl
    }

    /// Run `op` (a closure calling exactly one `SSL_*` function on `self.ssl`)
    /// with the inner IO and `Context` published into the BIO so its read/write
    /// callbacks can reach them. Pointers are cleared before returning.
    ///
    /// This is the ONLY place the re-entrancy window is opened; the closure
    /// runs the `SSL_*` call synchronously, the BIO callbacks fire inside it,
    /// and on return the published pointers are invalidated. See module docs.
    #[inline]
    fn with_published<R>(
        &mut self,
        cx: &mut Context<'_>,
        op: impl FnOnce(*mut ssl::SSL) -> R,
    ) -> R {
        // Publish. The `Context<'_>` is reborrowed to `'static` only as a raw
        // pointer; it is dereferenced solely within `op`'s `SSL_*` call, which
        // strictly nests inside this function's frame where `cx` is live.
        self.bio_ctx.inner = ptr::from_mut::<I>(&mut *self.inner);
        self.bio_ctx.cx = ptr::from_mut::<Context<'_>>(cx).cast::<Context<'static>>();
        let r = op(self.ssl);
        // Invalidate so no later code path can deref a stale Context/IO.
        self.bio_ctx.inner = ptr::null_mut();
        self.bio_ctx.cx = ptr::null_mut();
        r
    }

    /// Drive the TLS handshake to completion. Returns `Pending` (after storing
    /// the inner waker via the BIO contract) on WANT_READ/WANT_WRITE.
    pub fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        if self.handshake == HandshakeState::Done {
            return Poll::Ready(Ok(()));
        }
        // `SSL_connect` on the owned SSL drives the client handshake; the BIO
        // callbacks (published `inner`/`cx`) perform the IO.
        let rc = self.with_published(cx, |s| {
            // SAFETY: `s` is the owned, non-null SSL; called inside the published
            // re-entrancy window so its BIO callbacks have a live `inner`/`cx`.
            unsafe { ssl::SSL_connect(s) }
        });
        if rc == 1 {
            self.handshake = HandshakeState::Done;
            // Capture collector cert notAfter on first successful handshake,
            // via the SHARED `asn1_time_to_unix` helper from `crate::cert_table`
            // (zero duplication of the epoch math; a unit test asserts this
            // reuse seam directly). Absent-not-zero: on failure (null cert or
            // conversion error) the atomic stays at its initial value (0), so
            // the metric stays absent; on success it is overwritten with the
            // same value on every subsequent handshake (stable per
            // endpoint/generation).
            //
            // SAFETY:
            // - `self.ssl` is the owned, non-null SSL; handshake just succeeded.
            // - `SSL_get1_peer_certificate` returns an OWNED `X509*` (the get1
            //   variant increments the refcount; rc 1 guarantees handshake
            //   completed and the peer cert was verified); NULL if the peer
            //   sent no cert (should not happen for a server, but we guard).
            //   We MUST call `X509_free` exactly once after reading to avoid a
            //   reference leak.
            // - `X509_getm_notAfter` returns an INTERNAL (get0) pointer owned by
            //   the cert; valid until `X509_free` is called below.
            let cert = unsafe { ssl::SSL_get1_peer_certificate(self.ssl) };
            if !cert.is_null() {
                // SAFETY: `cert` is the owned, non-null X509 obtained above;
                // `X509_getm_notAfter` returns an internal (get0) borrow valid
                // for the lifetime of `cert` (until `X509_free` below).
                let not_after_asn1 = unsafe { ssl::X509_getm_notAfter(cert) };
                // SAFETY: `not_after_asn1` is a valid borrow of `cert`'s
                // notAfter field; `asn1_time_to_unix` only reads it; `cert`
                // stays live until `X509_free` below.
                let epoch_opt = unsafe { crate::cert_table::asn1_time_to_unix(not_after_asn1) };
                if let Some(epoch_secs) = epoch_opt {
                    // Relaxed is sound: the exporter is single-threaded; the
                    // write and the read in `collect_all_sources` happen on the
                    // same thread with no concurrent writers.
                    COLLECTOR_CERT_NOT_AFTER.store(epoch_secs, Ordering::Relaxed);
                }
                // SAFETY: `cert` was obtained from `SSL_get_peer_certificate`
                // (owned reference); freed exactly once here.
                unsafe { ssl::X509_free(cert) };
            }
            return Poll::Ready(Ok(()));
        }
        self.map_ssl_err(rc, "handshake")
    }

    /// Translate an `SSL_connect`/`SSL_read`/`SSL_write` non-success return into
    /// a `Poll`. WANT_READ/WANT_WRITE → `Pending`; everything else → an IO
    /// error carrying the OpenSSL diagnostic (fail-closed).
    fn map_ssl_err<T>(&mut self, rc: c_int, op: &str) -> Poll<Result<T, io::Error>> {
        // SAFETY: `self.ssl` is the owned SSL; `SSL_get_error` interprets `rc`
        // against the SSL's internal error state. Must be called immediately
        // after the originating `SSL_*` call (it was — see callers).
        let err = unsafe { ssl::SSL_get_error(self.ssl, rc) };
        match err {
            ssl::SSL_ERROR_WANT_READ | ssl::SSL_ERROR_WANT_WRITE => Poll::Pending,
            ssl::SSL_ERROR_ZERO_RETURN => {
                // Peer closed the TLS connection cleanly.
                Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
            }
            _ => {
                let detail = openssl_err();
                Poll::Ready(Err(io::Error::other(alloc::format!(
                    "TLS {op} failed (SSL_get_error={err}): {detail}"
                ))))
            }
        }
    }
}

impl<I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static> hyper::rt::Read for TlsNgxConnIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        // Handshake must complete before application data flows. hyper drives
        // the connection by reading/writing; complete the handshake lazily here
        // (and in poll_write) so a caller that starts by reading still works.
        if this.handshake == HandshakeState::Pending {
            match this.poll_handshake(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // SAFETY: hyper guarantees `buf`'s unfilled region is a valid writable
        // `[MaybeUninit<u8>]` for this call.
        let uninit = unsafe { buf.as_mut() };
        let cap = uninit.len();
        if cap == 0 {
            return Poll::Ready(Ok(()));
        }
        let ptr = uninit.as_mut_ptr().cast::<c_void>();
        let want = cap.min(c_int::MAX as usize) as c_int;
        // `SSL_read` on the owned SSL into the writable region [ptr, ptr+want);
        // the BIO callbacks supply ciphertext.
        let n = this.with_published(cx, |s| {
            // SAFETY: `s` is the owned non-null SSL; `ptr`/`want` is a writable
            // region of `want` bytes (from hyper's unfilled buf); called inside
            // the published re-entrancy window.
            unsafe { ssl::SSL_read(s, ptr, want) }
        });
        if n > 0 {
            // SAFETY: `SSL_read` wrote `n` (≤ cap) bytes into the front of the
            // unfilled region, initializing them; advancing the cursor is sound.
            unsafe { buf.advance(n as usize) };
            return Poll::Ready(Ok(()));
        }
        // SSL_read returned <= 0. Per SSL_read(3)/SSL_get_error(3), a return of
        // 0 is NOT automatically a clean EOF: it must be classified via
        // SSL_get_error. Only SSL_ERROR_ZERO_RETURN means the peer sent a TLS
        // close_notify (a genuine clean stream EOF, reported to hyper as
        // Ok(()) with zero bytes filled). SSL_ERROR_SYSCALL (e.g. a peer RST or
        // a TCP FIN with no close_notify — common with TLS 1.3 behind proxies)
        // is a truncation and MUST surface as an error so hyper does not treat
        // a cut-off response as complete. WANT_READ/WANT_WRITE → Pending; all
        // other codes → an I/O error (fail-closed).
        // <https://docs.openssl.org/master/man3/SSL_read/>
        // <https://docs.openssl.org/master/man3/SSL_get_error/>
        // SAFETY: `this.ssl` is the owned SSL; `SSL_get_error` interprets `n`
        // against the SSL's internal error state and is called immediately
        // after the originating `SSL_read` above.
        let err = unsafe { ssl::SSL_get_error(this.ssl, n) };
        match err {
            ssl::SSL_ERROR_WANT_READ | ssl::SSL_ERROR_WANT_WRITE => Poll::Pending,
            ssl::SSL_ERROR_ZERO_RETURN => {
                // Peer sent close_notify: clean stream EOF.
                Poll::Ready(Ok(()))
            }
            _ => this.map_ssl_err(n, "read"),
        }
    }
}

impl<I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static> hyper::rt::Write for TlsNgxConnIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        if this.handshake == HandshakeState::Pending {
            match this.poll_handshake(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let ptr = data.as_ptr().cast::<c_void>();
        let want = data.len().min(c_int::MAX as usize) as c_int;
        // `SSL_write` on the owned SSL of `want` bytes from the readable `data`
        // slice; the BIO callbacks emit ciphertext.
        let n = this.with_published(cx, |s| {
            // SAFETY: `s` is the owned non-null SSL; `ptr`/`want` is a readable
            // region of `want` bytes (from `data`); called inside the published
            // re-entrancy window.
            unsafe { ssl::SSL_write(s, ptr, want) }
        });
        if n > 0 {
            return Poll::Ready(Ok(n as usize));
        }
        this.map_ssl_err(n, "write")
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        // OpenSSL writes flow straight to the inner stream via the BIO; the
        // inner NgxConnIo treats flush as a no-op. Nothing to buffer here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        // Best-effort single SSL_shutdown (send close_notify). We do NOT wait
        // for the peer's close_notify (no blocking bidirectional wait): one call
        // is enough to be polite, and the inner stream close handles the rest.
        if this.handshake == HandshakeState::Done {
            // `SSL_shutdown` on the owned SSL sends a close_notify alert via the
            // BIO. Return value ignored (best-effort, no bidirectional wait).
            let _ = this.with_published(cx, |s| {
                // SAFETY: `s` is the owned non-null SSL; called inside the
                // published re-entrancy window.
                unsafe { ssl::SSL_shutdown(s) }
            });
        }
        // Then shut down the inner stream.
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

impl<I> Drop for TlsNgxConnIo<I> {
    fn drop(&mut self) {
        // Free the SSL FIRST (while `bio_ctx` is still alive): `SSL_free` frees
        // the attached BIO, whose `data` still points at our `bio_ctx` Box. The
        // BIO's destroy callback does NOT touch `bio_ctx` (it is a no-op), so
        // there is no use-after-free and no double-free. After `SSL_free`
        // returns, the `bio_ctx` and `inner` Boxes drop normally (Rust field
        // drop order). At drop time no `SSL_*` call is in flight, so the
        // published `inner`/`cx` pointers are null and irrelevant.
        if !self.ssl.is_null() {
            // SAFETY: `self.ssl` is the owned SSL created in `new`; `Drop` runs
            // once so it is freed once. `SSL_free` also frees the single BIO
            // whose ownership transferred in `SSL_set_bio`.
            unsafe { ssl::SSL_free(self.ssl) };
            self.ssl = ptr::null_mut();
        }
    }
}

/// Test-only serialization lock for tests that spawn `openssl s_server` and
/// drive a busy-spin client. Many such tests running concurrently overload the
/// scheduler (multiple `s_server` subprocesses + spin loops), causing transient
/// handshake EOFs (`SSL_ERROR_SYSCALL`). Both the `tls` and `hyper_http` test
/// harnesses lock this so only one s_server-backed handshake runs at a time.
#[cfg(test)]
pub(crate) static S_SERVER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
