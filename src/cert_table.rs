// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Config-time TLS serving-certificate table.
//!
//! At `postconfiguration` time (single-threaded master, before workers fork)
//! we walk every `server {}` block, find its `ngx_http_ssl_module` srv conf,
//! and enumerate EVERY leaf certificate installed in the server's `SSL_CTX`
//! (dual RSA+ECDSA blocks must yield BOTH certs).  Each cert is
//! reduced to a [`CertInfo`] row — identity fields only:
//! file path, server name, validity window, subject/issuer CN, serial,
//! public-key algorithm, signature algorithm.  Nothing else is extracted (no
//! PEM, no keys, no fingerprints, no full DNs, no SANs, no key sizes).
//!
//! The resulting `Vec<CertInfo>` is stored on `MainConfig` (plain Rust heap,
//! written once here, read-only afterwards) and is inherited by the exporter
//! process at fork.  The `ngx_otel.tls.certificate.*` gauges are built on top.
//!
//! Layering notes:
//! - `ngx_http_ssl_srv_conf_t` is dereferenced ONLY in the C shim
//!   (`src/shim/ngx_otel_ssl_shim.c`) — see the shim header for the rationale.
//!   `ngx_ssl_t`'s `ctx`/`certs` fields are the exception read directly from
//!   Rust (bitfield-free core struct, layout verified against nginx).
//! - The `ngx_http_ssl_module` global symbol is deliberately NEVER referenced
//!   from Rust: nginx loads dynamic modules with `dlopen(RTLD_NOW)`, so an
//!   undefined data symbol would make a no-ssl nginx binary REFUSE to load us.
//!   Instead the module is located by NAME in `cycle->modules`; when absent,
//!   the table stays empty and a single NOTICE explains why.
//! - Variable (`$var`) certificate paths are skipped with a config-time
//!   NOTICE: nginx defers such certs to per-handshake loading
//!   (`certificate_values`), so they are not in the `SSL_CTX` at config time.

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;
use std::string::{String, ToString};
#[cfg(ngx_feature = "http_ssl")]
use std::vec::Vec;

#[cfg(ngx_feature = "http_ssl")]
use nginx_sys::{ngx_array_t, ngx_http_core_srv_conf_t, ngx_str_t, ngx_uint_t, NGX_HTTP_MODULE};
use nginx_sys::{ngx_conf_t, NGX_LOG_NOTICE};
use ngx::ngx_conf_log_error;
use openssl_sys as ossl;

use crate::config::MainConfig;

/// One serving leaf certificate, collected once at config time.
///
/// Field set is intentionally minimal (identity only) — do not add fields
/// without a deliberate scope decision.
#[derive(Debug, Clone)]
pub struct CertInfo {
    /// Certificate file path as configured by `ssl_certificate`.
    pub file_path: String,
    /// First non-wildcard `server_name` of the owning server block; `"_"`
    /// when the block has none.
    pub server_name: String,
    /// `notBefore` as Unix epoch seconds.
    pub not_before_unix: i64,
    /// `notAfter` as Unix epoch seconds.
    pub not_after_unix: i64,
    /// Subject CN (empty string when the subject has no CN).
    pub subject_cn: String,
    /// Issuer CN (empty string when the issuer has no CN).
    pub issuer_cn: String,
    /// Serial number as an uppercase hex string (no `0x` prefix).
    pub serial: String,
    /// Public-key algorithm (`"RSA"`, `"EC"`, `"ED25519"`, ...).
    pub pubkey_alg: String,
    /// Signature algorithm short name (e.g. `"RSA-SHA256"`).
    pub sig_alg: String,
}

// ── C shim imports (src/shim/ngx_otel_ssl_shim.c) ───────────────────────────
//
// The srv-conf parameter is `void*` on both sides so Rust never names (let
// alone dereferences) `ngx_http_ssl_srv_conf_t`.  The shim signatures are
// type-checked against the C definitions by the C compiler itself.
#[cfg(ngx_feature = "http_ssl")]
extern "C" {
    /// `&((ngx_http_ssl_srv_conf_t *) conf)->ssl`; NULL for NULL input.
    fn ngx_otel_srv_ssl(ssl_srv_conf: *mut c_void) -> *mut nginx_sys::ngx_ssl_t;
    /// `((ngx_http_ssl_srv_conf_t *) conf)->certificates`; may be NULL.
    fn ngx_otel_srv_ssl_certificates(ssl_srv_conf: *mut c_void) -> *mut ngx_array_t;
    /// Full leaf-cert enumeration via OpenSSL's `SSL_CTX_set_current_cert`
    /// cursor macros (config-time only; see the shim header).  `cb` returns 0
    /// to continue.  Returns the number of certificates visited.
    fn ngx_otel_foreach_ctx_cert(
        ctx: *mut ossl::SSL_CTX,
        cb: Option<unsafe extern "C" fn(cert: *mut ossl::X509, data: *mut c_void) -> c_int>,
        data: *mut c_void,
    ) -> c_int;
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// Populate `amcf.cert_table` by walking every server's ssl srv conf.
///
/// Called ONCE from `postconfiguration` (after `ngx_http_ssl_module`'s
/// `merge_srv_conf` has loaded all config-time certificates into each
/// server's `SSL_CTX`), before workers fork.
///
/// # Safety
/// `cf` must be the valid, non-null `ngx_conf_t` nginx passes to
/// `postconfiguration`.
#[cfg(ngx_feature = "http_ssl")]
pub(crate) unsafe fn build_cert_table(amcf: &mut MainConfig, cf: *mut ngx_conf_t) {
    use ngx::http::{HttpModuleMainConf, NgxHttpCoreModule};

    // Locate ngx_http_ssl_module BY NAME (never by symbol — see module docs).
    // SAFETY: `cf` is valid per the fn contract; the helper only reads
    // `cycle->modules`, which nginx populated before config parsing.
    let Some(ssl_ctx_index) = (unsafe { find_http_ssl_ctx_index(cf) }) else {
        ngx_conf_log_error!(
            NGX_LOG_NOTICE,
            cf,
            "otel: cert metrics unavailable: nginx built without http_ssl_module"
        );
        return;
    };

    // SAFETY: per the fn contract `cf` is a valid non-null parse context at
    // postconfiguration; `&*cf` is a sound shared borrow.
    let cf_ref = unsafe { &*cf };
    let Some(cmcf) = NgxHttpCoreModule::main_conf(cf_ref) else {
        return; // no HTTP core — very unusual, skip gracefully
    };

    let n_servers = cmcf.servers.nelts;
    let srv_ptr = cmcf.servers.elts.cast::<*mut ngx_http_core_srv_conf_t>();
    for i in 0..n_servers {
        // SAFETY: `srv_ptr` is `cmcf.servers.elts` viewed as a `*mut *mut
        // ngx_http_core_srv_conf_t` and `i < n_servers = servers.nelts`, so
        // `srv_ptr.add(i)` is an in-bounds element of nginx's servers array.
        let cscf: *mut ngx_http_core_srv_conf_t = unsafe { *srv_ptr.add(i) };
        if cscf.is_null() {
            continue;
        }
        // SAFETY: `cscf` is a non-null server-conf pointer from nginx's array
        // (checked above), valid in conf-pool memory; `collect_server_certs`
        // requires exactly that plus the in-range ssl ctx_index found above.
        unsafe { collect_server_certs(amcf, cf, cscf, ssl_ctx_index) };
    }
}

/// No-ssl-bindings fallback: the module was built against an nginx source
/// tree configured WITHOUT `--with-http_ssl_module`, so the ssl types are
/// absent from the bindings and the C shim compiled its stub variants.  The
/// cert table stays empty; emit the same operator-visible NOTICE as the
/// runtime no-ssl path.
///
/// # Safety
/// `cf` must be the valid, non-null `ngx_conf_t` nginx passes to
/// `postconfiguration`.
#[cfg(not(ngx_feature = "http_ssl"))]
pub(crate) unsafe fn build_cert_table(_amcf: &mut MainConfig, cf: *mut ngx_conf_t) {
    ngx_conf_log_error!(
        NGX_LOG_NOTICE,
        cf,
        "otel: cert metrics unavailable: nginx built without http_ssl_module"
    );
}

/// Find `ngx_http_ssl_module`'s `ctx_index` by walking `cycle->modules`.
///
/// Returns `None` when nginx was built without the http_ssl module.  This is
/// the runtime-robust replacement for referencing the `ngx_http_ssl_module`
/// global: a direct symbol reference would leave an undefined symbol in our
/// `.so` and `dlopen(RTLD_NOW)` of a no-ssl nginx would refuse to load it.
///
/// # Safety
/// `cf` must be a valid, non-null `ngx_conf_t` whose `cycle` is initialised.
#[cfg(ngx_feature = "http_ssl")]
unsafe fn find_http_ssl_ctx_index(cf: *mut ngx_conf_t) -> Option<usize> {
    // SAFETY: `cf` is valid per the fn contract; reading its `cycle` field is
    // sound.
    let cycle = unsafe { (*cf).cycle };
    if cycle.is_null() {
        return None;
    }
    // SAFETY: `cycle` is non-null (checked) and nginx initialises
    // `modules`/`modules_n` before any configuration callback runs.
    let (modules, n) = unsafe { ((*cycle).modules, (*cycle).modules_n) };
    if modules.is_null() {
        return None;
    }
    for i in 0..n {
        // SAFETY: `i < n = cycle->modules_n`, so `modules.add(i)` is an
        // in-bounds element of nginx's modules array.
        let m = unsafe { *modules.add(i) };
        if m.is_null() {
            continue;
        }
        // SAFETY: `m` is a non-null `ngx_module_t*` from nginx's modules array;
        // reading its `type_`/`name` fields is sound.
        let (mtype, name) = unsafe { ((*m).type_, (*m).name) };
        if mtype != NGX_HTTP_MODULE as ngx_uint_t || name.is_null() {
            continue;
        }
        // SAFETY: `name` is a non-null, NUL-terminated module name string that
        // nginx keeps in static storage for the process lifetime.
        if unsafe { CStr::from_ptr(name) }.to_bytes() == b"ngx_http_ssl_module" {
            // SAFETY: `m` is non-null (checked above); reading `ctx_index` is sound.
            return Some(unsafe { (*m).ctx_index });
        }
    }
    None
}

/// Enumerate and record every leaf certificate of one server block.
///
/// # Safety
/// `cf` is the valid postconfiguration context, `cscf` a valid non-null
/// server conf, and `ssl_ctx_index` the http_ssl module's `ctx_index`
/// (in-bounds for every server's `srv_conf` array).
#[cfg(ngx_feature = "http_ssl")]
unsafe fn collect_server_certs(
    amcf: &mut MainConfig,
    cf: *mut ngx_conf_t,
    cscf: *mut ngx_http_core_srv_conf_t,
    ssl_ctx_index: usize,
) {
    // SAFETY: `cscf` is valid per the fn contract; reading `ctx` is sound.
    let ctx = unsafe { (*cscf).ctx };
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is the server's non-null `ngx_http_conf_ctx_t`; reading its
    // `srv_conf` array pointer is sound.
    let srv_conf_arr = unsafe { (*ctx).srv_conf };
    if srv_conf_arr.is_null() {
        return;
    }
    // SAFETY: `ssl_ctx_index` is a registered http module's ctx_index, which is
    // always in-bounds for a server ctx's srv_conf array.
    let sscf: *mut c_void = unsafe { *srv_conf_arr.add(ssl_ctx_index) };
    if sscf.is_null() {
        return;
    }

    // SAFETY: `sscf` is the server's ssl srv conf (or at least the pointer in
    // its slot); the shim only computes `&conf->ssl` and handles NULL.
    let ssl = unsafe { ngx_otel_srv_ssl(sscf) };
    if ssl.is_null() {
        return;
    }
    // `ngx_ssl_t` field reads through the bindings are the exception
    // to the shim rule: bitfield-free struct, layout verified against nginx.
    // SAFETY: `ssl` is the non-null `ngx_ssl_t*` embedded in conf-pool memory;
    // reading its `ctx` pointer field is sound.
    let ngx_ssl_ctx: *mut nginx_sys::SSL_CTX = unsafe { (*ssl).ctx };
    if ngx_ssl_ctx.is_null() {
        // Server block without `ssl_certificate` / not TLS-enabled.
        return;
    }

    // SAFETY: `cscf` is valid per the fn contract; the helper reads only its
    // `server_names` array.
    let server_name = unsafe { pick_server_name(cscf) };

    // Configured cert file paths (as written in the config).  `$var` paths are
    // loaded per-handshake by nginx, never present in the config-time SSL_CTX:
    // NOTICE and (naturally) absent from the enumeration below.
    // SAFETY: `sscf` is the ssl srv conf pointer; the shim only reads its
    // `certificates` field and handles NULL.
    let paths_arr = unsafe { ngx_otel_srv_ssl_certificates(sscf) };
    let mut paths: Vec<String> = Vec::new();
    if !paths_arr.is_null() {
        // SAFETY: `paths_arr` is the non-null `ngx_array_t` of `ngx_str_t`
        // owned by nginx conf memory; nelts/elts describe its live elements.
        let (nelts, elts) = unsafe { ((*paths_arr).nelts, (*paths_arr).elts.cast::<ngx_str_t>()) };
        for j in 0..nelts {
            // SAFETY: `j < nelts`, so `elts.add(j)` is an in-bounds element.
            let s: ngx_str_t = unsafe { *elts.add(j) };
            let path = String::from_utf8_lossy(s.as_bytes()).into_owned();
            if path.contains('$') {
                ngx_conf_log_error!(
                    NGX_LOG_NOTICE,
                    cf,
                    "otel: cert metrics: skipping variable certificate path \"{}\" \
                     (server \"{}\"): loaded per handshake, not at config time",
                    path,
                    server_name
                );
            }
            paths.push(path);
        }
    }

    // THE bindgen↔openssl-sys boundary cast (single documented site): both
    // types describe the very same C `SSL_CTX` (`struct ssl_ctx_st`) — bindgen
    // generated one opaque-ish Rust type from nginx's headers, openssl-sys
    // declares another; the pointee is identical.
    let ssl_ctx: *mut ossl::SSL_CTX = ngx_ssl_ctx.cast::<ossl::SSL_CTX>();

    // Enumerate every leaf cert in the ctx (full enumeration).
    let mut enumerated: Vec<*mut ossl::X509> = Vec::new();
    // SAFETY: `ssl_ctx` is the server's live config-time SSL_CTX; we are in
    // the single-threaded master before workers fork, which is the shim
    // iterator's documented usage window.  The callback only pushes the
    // borrowed pointers into `enumerated`, which outlives the call.
    let _visited = unsafe {
        ngx_otel_foreach_ctx_cert(
            ssl_ctx,
            Some(collect_cert_cb),
            (&raw mut enumerated).cast::<c_void>(),
        )
    };

    for (enum_idx, cert) in enumerated.iter().enumerate() {
        let file_path = path_for_cert(enum_idx, &paths);
        // SAFETY: `cert` is a live X509 borrowed from the SSL_CTX (valid for
        // the whole config phase); extraction only reads it via openssl-sys.
        let Some(info) = (unsafe { extract_cert_info(*cert, file_path, server_name.clone()) })
        else {
            ngx_conf_log_error!(
                NGX_LOG_NOTICE,
                cf,
                "otel: cert metrics: skipping cert[{}] server=\"{}\" \
                 (validity window not parseable)",
                enum_idx,
                server_name
            );
            continue;
        };
        ngx_conf_log_error!(
            NGX_LOG_NOTICE,
            cf,
            "otel: cert metrics: certificate path=\"{}\" server=\"{}\" subject_cn=\"{}\" \
             not_after={}",
            info.file_path,
            info.server_name,
            info.subject_cn,
            info.not_after_unix
        );
        amcf.cert_table.push(info);
    }
}

/// Cursor-enumeration callback: collect each borrowed `X509*`.
#[cfg(ngx_feature = "http_ssl")]
unsafe extern "C" fn collect_cert_cb(cert: *mut ossl::X509, data: *mut c_void) -> c_int {
    // SAFETY: `data` is the `&raw mut Vec<*mut X509>` passed by
    // `collect_server_certs` above, alive for the whole iteration.
    let certs = unsafe { &mut *data.cast::<Vec<*mut ossl::X509>>() };
    certs.push(cert);
    0 // continue
}

/// Map an enumerated cert back to its configured file path by enumeration index.
///
/// `enum_idx` is the cert's position in the `ngx_otel_foreach_ctx_cert`
/// enumeration (0-based).  nginx installs certs into the `SSL_CTX` in
/// configured order (`ngx_ssl_certificate`, `ngx_event_openssl.c`), and
/// OpenSSL's `SSL_CTX_set_current_cert` cursor enumerates them in that same
/// insertion order, so `enum_idx` is index-aligned with the `paths` list.
///
/// The old pointer-identity approach (`ssl->certs` vs `SSL_CTX_get0_certificate`
/// result) was unreliable: OpenSSL stores the leaf cert internally and returns
/// its own pointer from `get0`, which does not alias the pointer nginx cached in
/// `ssl->certs` — so the identity lookup always missed for multi-cert servers,
/// falling through to a `,`-joined join of ALL paths for EVERY cert.
#[cfg(ngx_feature = "http_ssl")]
fn path_for_cert(enum_idx: usize, paths: &[String]) -> String {
    if let Some(p) = paths.get(enum_idx) {
        return p.clone();
    }
    // Fallback: index out of range (should not occur for a well-formed nginx
    // config); if there is exactly one path it is the only candidate; otherwise
    // we cannot determine which path is correct and return empty.
    match paths {
        [single] => single.clone(),
        _ => String::new(),
    }
}

/// First non-wildcard `server_name` of the block; `"_"` when none.
///
/// # Safety
/// `cscf` must be a valid, non-null `ngx_http_core_srv_conf_t*`.
#[cfg(ngx_feature = "http_ssl")]
unsafe fn pick_server_name(cscf: *mut ngx_http_core_srv_conf_t) -> String {
    // SAFETY: `cscf` is valid per the fn contract; `server_names` is an
    // embedded `ngx_array_t` of `ngx_http_server_name_t`.
    let arr = unsafe { &(*cscf).server_names };
    if !arr.elts.is_null() {
        let elts = arr.elts.cast::<nginx_sys::ngx_http_server_name_t>();
        for j in 0..arr.nelts {
            // SAFETY: `j < arr.nelts`, so `elts.add(j)` is an in-bounds element
            // of the server_names array.
            let sn = unsafe { &*elts.add(j) };
            // Regex server_names are never a stable address; skip them.
            if !sn.regex.is_null() {
                continue;
            }
            let name = sn.name.as_bytes();
            if !is_wildcard_name(name) {
                return String::from_utf8_lossy(name).into_owned();
            }
        }
    }
    "_".to_string()
}

/// True for names that don't identify a single host: empty (unnamed default),
/// `*` wildcards, leading-dot shorthand (`.example.com`), and `~` regex forms
/// (defensive — regex entries are normally filtered by their `regex` field).
fn is_wildcard_name(name: &[u8]) -> bool {
    name.is_empty() || name.contains(&b'*') || name[0] == b'.' || name[0] == b'~'
}

// ── Per-cert field extraction (openssl-sys only — no nginx types) ───────────

/// Extract the identity field set from one borrowed leaf cert.
///
/// Returns `None` when either `notBefore` or `notAfter` cannot be parsed —
/// a cert whose validity window is unreadable cannot be tracked for expiry and
/// must be skipped rather than recorded as epoch-zero (1970-01-01), which
/// would appear as permanently expired in the `tls.certificate.*` gauges.
///
/// # Safety
/// `cert` must be a valid, live `X509*` (borrowed from the SSL_CTX).
#[cfg(ngx_feature = "http_ssl")]
unsafe fn extract_cert_info(
    cert: *mut ossl::X509,
    file_path: String,
    server_name: String,
) -> Option<CertInfo> {
    // SAFETY: `cert` is a valid X509 per the fn contract; X509_getm_notBefore
    // returns an internal pointer owned by the cert and asn1_time_to_unix
    // handles NULL.
    let not_before = unsafe { asn1_time_to_unix(ossl::X509_getm_notBefore(cert)) }?;
    // SAFETY: as above.
    let not_after = unsafe { asn1_time_to_unix(ossl::X509_getm_notAfter(cert)) }?;
    // SAFETY: `X509_get_subject_name` returns an internal (get0-style) pointer
    // owned by the cert; `x509_name_cn` handles NULL.
    let subject_cn = unsafe { x509_name_cn(ossl::X509_get_subject_name(cert.cast_const())) };
    // SAFETY: as above, for the issuer name.
    let issuer_cn = unsafe { x509_name_cn(ossl::X509_get_issuer_name(cert.cast_const())) };
    // SAFETY: `X509_get_serialNumber` returns an internal pointer owned by the
    // cert; `asn1_integer_hex` handles NULL and frees its own temporaries.
    let serial = unsafe { asn1_integer_hex(ossl::X509_get_serialNumber(cert)) };
    // SAFETY: `cert` is valid; the helper frees the EVP_PKEY it obtains.
    let pubkey_alg = unsafe { pubkey_alg(cert) };
    // SAFETY: `cert` is valid; `X509_get_signature_nid` only reads it.
    let sig_alg = unsafe { nid_short_name(ossl::X509_get_signature_nid(cert.cast_const())) };

    Some(CertInfo {
        file_path,
        server_name,
        not_before_unix: not_before,
        not_after_unix: not_after,
        subject_cn,
        issuer_cn,
        serial,
        pubkey_alg,
        sig_alg,
    })
}

/// Convert an `ASN1_TIME` (UTCTime or GeneralizedTime — `ASN1_TIME_diff`
/// handles both) to Unix epoch seconds.
///
/// Method: diff against an `ASN1_TIME_set(NULL, 0)` epoch baseline, then
/// `days * 86400 + secs` (`ASN1_TIME_to_tm` is not exposed by openssl-sys).
///
/// Exposed as `pub(crate)` so that `src/transport/tls.rs` can reuse this
/// helper for the collector-cert gauge without duplicating the epoch math.
///
/// # Safety
/// `t` must be NULL or a valid `ASN1_TIME*`.
pub(crate) unsafe fn asn1_time_to_unix(t: *const ossl::ASN1_TIME) -> Option<i64> {
    if t.is_null() {
        return None;
    }
    // SAFETY: `ASN1_TIME_set(NULL, 0)` allocates a fresh ASN1_TIME for the
    // Unix epoch; freed below on every path.
    let epoch = unsafe { ossl::ASN1_TIME_set(ptr::null_mut(), 0) };
    if epoch.is_null() {
        return None;
    }
    let mut days: c_int = 0;
    let mut secs: c_int = 0;
    // SAFETY: `epoch` is the valid baseline just allocated, `t` is valid per
    // the fn contract, and the out-pointers reference live locals.
    let ok = unsafe { ossl::ASN1_TIME_diff(&raw mut days, &raw mut secs, epoch, t) };
    // SAFETY: `epoch` was allocated by ASN1_TIME_set above and not yet freed.
    unsafe { ossl::ASN1_TIME_free(epoch) };
    if ok != 1 {
        return None;
    }
    Some(i64::from(days) * 86_400 + i64::from(secs))
}

/// Extract the CN from an `X509_NAME` (empty string when absent).
///
/// openssl-sys does not expose `X509_NAME_get_text_by_NID` (verified against
/// the 0.9.116 registry source), so this uses the index/entry chain:
/// `X509_NAME_get_index_by_NID` → `X509_NAME_get_entry` →
/// `X509_NAME_ENTRY_get_data` → lossy UTF-8.
///
/// # Safety
/// `name` must be NULL or a valid `X509_NAME*`.
unsafe fn x509_name_cn(name: *const ossl::X509_NAME) -> String {
    if name.is_null() {
        return String::new();
    }
    // SAFETY: `name` is a valid X509_NAME per the fn contract.
    let idx = unsafe { ossl::X509_NAME_get_index_by_NID(name, ossl::NID_commonName, -1) };
    if idx < 0 {
        return String::new();
    }
    // SAFETY: `idx` was just returned for this name, so it is in range.
    let entry = unsafe { ossl::X509_NAME_get_entry(name, idx) };
    if entry.is_null() {
        return String::new();
    }
    // SAFETY: `entry` is the non-null entry returned above; get_data returns
    // an internal pointer owned by the entry.
    let data = unsafe { ossl::X509_NAME_ENTRY_get_data(entry) };
    if data.is_null() {
        return String::new();
    }
    // SAFETY: `data` is the entry's live ASN1_STRING.
    unsafe { asn1_string_lossy(data) }
}

/// Borrowed `ASN1_STRING` bytes → owned lossy-UTF-8 `String`.
///
/// # Safety
/// `s` must be a valid, non-null `ASN1_STRING*`.
unsafe fn asn1_string_lossy(s: *const ossl::ASN1_STRING) -> String {
    // SAFETY: `s` is valid per the fn contract; get0_data/length read it only.
    let (data, len) = unsafe { (ossl::ASN1_STRING_get0_data(s), ossl::ASN1_STRING_length(s)) };
    if data.is_null() || len <= 0 {
        return String::new();
    }
    // SAFETY: openssl guarantees `data` points at `len` live bytes owned by `s`.
    let bytes = unsafe { core::slice::from_raw_parts(data, len as usize) };
    String::from_utf8_lossy(bytes).into_owned()
}

/// Serial number → uppercase hex string (via `ASN1_INTEGER_to_BN` →
/// `BN_bn2hex`; both temporaries freed).  Empty string on NULL/failure.
///
/// RFC 5280 §4.1.2.2 requires serial numbers to be positive; however, some
/// legacy CAs issued certificates whose DER-encoded serial had the high bit
/// set, which OpenSSL interprets as a negative BIGNUM.  `BN_bn2hex` (OpenSSL
/// man page BN_bn2bin(3)) prepends a `-` sign for negative values.  We strip
/// the leading `-` so the serial is always rendered as the canonical absolute
/// hex value — matching the display convention used by `openssl x509 -serial`.
///
/// # Safety
/// `ser` must be NULL or a valid `ASN1_INTEGER*`.
unsafe fn asn1_integer_hex(ser: *const ossl::ASN1_INTEGER) -> String {
    if ser.is_null() {
        return String::new();
    }
    // SAFETY: `ser` is valid per the fn contract; passing NULL `bn` allocates
    // a fresh BIGNUM, freed below.
    let bn = unsafe { ossl::ASN1_INTEGER_to_BN(ser, ptr::null_mut()) };
    if bn.is_null() {
        return String::new();
    }
    // SAFETY: `bn` is the valid BIGNUM just allocated.
    let hex: *mut c_char = unsafe { ossl::BN_bn2hex(bn) };
    let out = if hex.is_null() {
        String::new()
    } else {
        // SAFETY: BN_bn2hex returns a NUL-terminated C string on success.
        let s = unsafe { CStr::from_ptr(hex) }.to_string_lossy().into_owned();
        // SAFETY: `hex` was allocated by BN_bn2hex and must be released with
        // OPENSSL_free exactly once.
        unsafe { ossl::OPENSSL_free(hex.cast::<c_void>()) };
        // Strip the leading `-` that BN_bn2hex emits for negative BIGNUMs
        // (see BN_bn2bin(3): "BN_bn2hex() ... negative numbers are prefixed
        // with a minus sign").  Serial numbers are rendered as their absolute
        // hex value — matches `openssl x509 -serial` canonical output.  If
        // the string has no leading `-`, `strip_prefix` returns None and `s`
        // is returned as-is.
        s.strip_prefix('-').map(String::from).unwrap_or(s)
    };
    // SAFETY: `bn` was allocated by ASN1_INTEGER_to_BN and not yet freed.
    unsafe { ossl::BN_free(bn) };
    out
}

/// Map an `EVP_PKEY` base id to its conventional algorithm name.
///
/// Pure function (unit-testable without OpenSSL objects).  Returns `None` for
/// ids outside the common serving-cert set; callers fall back to the NID
/// short name (`EVP_PKEY` base ids are NIDs).
fn pubkey_alg_name(id: c_int) -> Option<&'static str> {
    match id {
        ossl::EVP_PKEY_RSA => Some("RSA"),
        ossl::EVP_PKEY_RSA_PSS => Some("RSA-PSS"),
        ossl::EVP_PKEY_EC => Some("EC"),
        ossl::EVP_PKEY_ED25519 => Some("ED25519"),
        ossl::EVP_PKEY_ED448 => Some("ED448"),
        ossl::EVP_PKEY_DSA => Some("DSA"),
        _ => None,
    }
}

/// Public-key algorithm of a cert (`"RSA"`, `"EC"`, ...).
///
/// # Safety
/// `cert` must be a valid, live `X509*`.
#[cfg(ngx_feature = "http_ssl")]
unsafe fn pubkey_alg(cert: *mut ossl::X509) -> String {
    // SAFETY: `cert` is valid per the fn contract.  NOTE: X509_get_pubkey
    // (unlike the get0 accessors used elsewhere) returns a REF-COUNTED copy
    // that we must free below.
    let pkey = unsafe { ossl::X509_get_pubkey(cert) };
    if pkey.is_null() {
        return "unknown".to_string();
    }
    // SAFETY: `pkey` is the non-null EVP_PKEY just obtained.
    let id = unsafe { ossl::EVP_PKEY_id(pkey) };
    // SAFETY: releases the reference X509_get_pubkey took; `pkey` is not used
    // after this point.
    unsafe { ossl::EVP_PKEY_free(pkey) };
    match pubkey_alg_name(id) {
        Some(s) => s.to_string(),
        // SAFETY-FREE fallback: EVP_PKEY base ids are NIDs.
        // SAFETY: nid_short_name only calls OBJ_nid2sn, which is total.
        None => unsafe { nid_short_name(id) },
    }
}

/// NID → OpenSSL short name (`"unknown"` when the NID has none).
///
/// # Safety
/// Always safe to call (OBJ_nid2sn is total over `c_int`); marked unsafe only
/// because it is an FFI wrapper.
unsafe fn nid_short_name(nid: c_int) -> String {
    // SAFETY: OBJ_nid2sn accepts any nid and returns NULL or a static string.
    let sn = unsafe { ossl::OBJ_nid2sn(nid) };
    if sn.is_null() {
        return "unknown".to_string();
    }
    // SAFETY: non-NULL OBJ_nid2sn results are static NUL-terminated strings.
    unsafe { CStr::from_ptr(sn) }.to_string_lossy().into_owned()
}

// ─────────────────────────────── tests ──────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// Build an `ASN1_TIME` from an ASN.1 time string (UTCTime `YYMMDD...Z`
    /// or GeneralizedTime `YYYYMMDD...Z`).  Caller frees.
    fn asn1_time_from(s: &str) -> *mut ossl::ASN1_TIME {
        // SAFETY: ASN1_TIME_new allocates a fresh ASN1_TIME.
        let t = unsafe { ossl::ASN1_TIME_new() };
        assert!(!t.is_null());
        let cs = CString::new(s).unwrap();
        // SAFETY: `t` is the valid ASN1_TIME just allocated and `cs` is a
        // valid NUL-terminated string.
        let ok = unsafe { ossl::ASN1_TIME_set_string(t, cs.as_ptr()) };
        assert_eq!(ok, 1, "ASN1_TIME_set_string({s}) failed");
        t
    }

    fn to_unix(s: &str) -> i64 {
        let t = asn1_time_from(s);
        // SAFETY: `t` is the valid ASN1_TIME built above.
        let v = unsafe { asn1_time_to_unix(t) }.expect("conversion must succeed");
        // SAFETY: `t` was allocated by asn1_time_from and not yet freed.
        unsafe { ossl::ASN1_TIME_free(t) };
        v
    }

    // ── ASN1 → epoch (UTCTime window, GeneralizedTime, pre-2000, post-2050) ─

    #[test]
    fn asn1_utctime_high_window_year_49_is_2049() {
        // UTCTime 2-digit years 00-49 → 20xx: 2049-12-31T23:59:59Z.
        assert_eq!(to_unix("491231235959Z"), 2_524_607_999);
    }

    #[test]
    fn asn1_utctime_low_window_year_50_is_1950() {
        // UTCTime 2-digit years 50-99 → 19xx: 1950-01-01T00:00:00Z (negative).
        assert_eq!(to_unix("500101000000Z"), -631_152_000);
    }

    #[test]
    fn asn1_utctime_pre_2000() {
        // 1999-01-01T00:00:00Z.
        assert_eq!(to_unix("990101000000Z"), 915_148_800);
    }

    #[test]
    fn asn1_generalizedtime_2050() {
        // 2050-01-01T00:00:00Z — first instant past the UTCTime window.
        assert_eq!(to_unix("20500101000000Z"), 2_524_608_000);
    }

    #[test]
    fn asn1_generalizedtime_post_2050() {
        // 2100-01-01T00:00:00Z (also exercises the 2100 non-leap century).
        assert_eq!(to_unix("21000101000000Z"), 4_102_444_800);
    }

    #[test]
    fn asn1_generalizedtime_epoch_itself() {
        assert_eq!(to_unix("19700101000000Z"), 0);
    }

    #[test]
    fn asn1_null_time_is_none() {
        // SAFETY: NULL is an accepted input per the fn contract.
        assert_eq!(unsafe { asn1_time_to_unix(ptr::null()) }, None);
    }

    // ── CN extraction (present / missing / non-ASCII UTF-8) ─────────────────

    /// Build an X509_NAME with an optional UTF-8 CN.  Caller frees.
    fn name_with_cn(cn: Option<&str>) -> *mut ossl::X509_NAME {
        // SAFETY: X509_NAME_new allocates a fresh empty name.
        let name = unsafe { ossl::X509_NAME_new() };
        assert!(!name.is_null());
        if let Some(cn) = cn {
            // SAFETY: `name` is the valid X509_NAME just allocated; the byte
            // buffer is live for the call and len is its exact length.
            let ok = unsafe {
                ossl::X509_NAME_add_entry_by_NID(
                    name,
                    ossl::NID_commonName,
                    ossl::MBSTRING_UTF8,
                    cn.as_ptr(),
                    cn.len() as c_int,
                    -1,
                    0,
                )
            };
            assert_eq!(ok, 1, "X509_NAME_add_entry_by_NID failed");
        }
        name
    }

    fn cn_of(cn: Option<&str>) -> String {
        let name = name_with_cn(cn);
        // SAFETY: `name` is the valid X509_NAME built above.
        let got = unsafe { x509_name_cn(name) };
        // SAFETY: `name` was allocated by name_with_cn and not yet freed.
        unsafe { ossl::X509_NAME_free(name) };
        got
    }

    #[test]
    fn cn_present() {
        assert_eq!(cn_of(Some("cert-a.example.test")), "cert-a.example.test");
    }

    #[test]
    fn cn_missing_is_empty_not_crash() {
        assert_eq!(cn_of(None), "");
    }

    #[test]
    fn cn_utf8_preserved() {
        assert_eq!(cn_of(Some("exämple-ü.test")), "exämple-ü.test");
    }

    #[test]
    fn cn_null_name_is_empty() {
        // SAFETY: NULL is an accepted input per the fn contract.
        assert_eq!(unsafe { x509_name_cn(ptr::null()) }, "");
    }

    // ── Fix 1: ASN1 time parse failure → None (not zero / epoch-expired) ───────

    /// Regression: when `ASN1_TIME_diff` cannot parse the time string, the
    /// function must return `None` rather than `Some(0)`.  Before the fix,
    /// `unwrap_or(0)` silently substituted the Unix epoch (1970-01-01), making
    /// a cert with an unreadable validity field appear permanently expired in
    /// the `tls.certificate.*` gauges.
    #[test]
    fn asn1_bad_time_string_is_none() {
        // Build an ASN1_TIME whose string content is deliberately invalid so
        // that ASN1_TIME_diff will fail to parse it.  We allocate a valid
        // ASN1_TIME object first and then overwrite its data with garbage.
        // SAFETY: ASN1_TIME_new allocates a fresh, initialised ASN1_TIME.
        let t = unsafe { ossl::ASN1_TIME_new() };
        assert!(!t.is_null());
        // Set a syntactically valid string first so the object is initialised,
        // then corrupt the data byte so ASN1_TIME_diff sees a bad encoding.
        let cs = std::ffi::CString::new("700101000000Z").unwrap();
        // SAFETY: `t` is valid; ASN1_TIME_set_string just writes the string.
        let ok = unsafe { ossl::ASN1_TIME_set_string(t, cs.as_ptr()) };
        assert_eq!(ok, 1);
        // Overwrite the first byte (month digit) with an unparseable byte so
        // that ASN1_TIME_diff will fail.  The ASN1_STRING data pointer is the
        // mutable byte buffer we write through.
        // SAFETY: `t` cast to ASN1_STRING is sound (ASN1_TIME is ASN1_STRING);
        // the buffer was just allocated and is writable; length is > 0.
        unsafe {
            let data_ptr = ossl::ASN1_STRING_get0_data(t.cast()) as *mut u8;
            assert!(!data_ptr.is_null());
            *data_ptr = b'X'; // 'X' is not a valid digit — diff will reject it
        }
        // SAFETY: `t` is valid (though its content is intentionally corrupt).
        let result = unsafe { asn1_time_to_unix(t) };
        // SAFETY: `t` was allocated by ASN1_TIME_new and not yet freed.
        unsafe { ossl::ASN1_TIME_free(t) };
        assert_eq!(result, None, "unparseable ASN1_TIME must return None, not Some(0)");
    }

    // ── Fix 2: path_for_cert uses enumeration index (dual-cert path labeling) ─

    /// Regression: for a dual RSA+ECDSA server block (two `ssl_certificate`
    /// directives, two enumerated certs) each cert must get its OWN configured
    /// path, not a joined list of all paths.  Before the fix, pointer-identity
    /// matching against `ssl->certs` always missed (OpenSSL returns its own
    /// internal pointer from `SSL_CTX_get0_certificate`, which does not alias
    /// the pointer nginx cached), causing the fallback to join all paths.
    #[test]
    fn path_for_cert_dual_cert_index_aligned() {
        let paths = vec![String::from("rsa.crt"), String::from("ecdsa.crt")];
        // Each cert's enumeration index must map to its own path.
        assert_eq!(path_for_cert(0, &paths), "rsa.crt");
        assert_eq!(path_for_cert(1, &paths), "ecdsa.crt");
    }

    /// Single-cert server: index 0 returns the only path.
    #[test]
    fn path_for_cert_single_cert() {
        let paths = vec![String::from("only.crt")];
        assert_eq!(path_for_cert(0, &paths), "only.crt");
    }

    /// Out-of-range index (should not occur in practice): empty string.
    #[test]
    fn path_for_cert_index_out_of_range_empty() {
        let paths = vec![String::from("a.crt"), String::from("b.crt")];
        assert_eq!(path_for_cert(5, &paths), "");
    }

    // ── Serial hex formatting ────────────────────────────────────────────────

    fn serial_of(v: i64) -> String {
        // SAFETY: allocates a fresh ASN1_STRING of INTEGER type — the valid
        // way to construct an ASN1_INTEGER through openssl-sys (no
        // ASN1_INTEGER_new binding).
        let ser: *mut ossl::ASN1_INTEGER =
            unsafe { ossl::ASN1_STRING_type_new(ossl::V_ASN1_INTEGER) }.cast();
        assert!(!ser.is_null());
        // SAFETY: `ser` is the valid ASN1_INTEGER just allocated.
        let ok = unsafe { ossl::ASN1_INTEGER_set(ser, v) };
        assert_eq!(ok, 1);
        // SAFETY: `ser` is valid and initialised.
        let got = unsafe { asn1_integer_hex(ser) };
        // SAFETY: `ser` was allocated above and not yet freed.
        unsafe { ossl::ASN1_INTEGER_free(ser) };
        got
    }

    #[test]
    fn serial_hex_formats_uppercase() {
        assert_eq!(serial_of(0x1234_ABCD), "1234ABCD");
    }

    #[test]
    fn serial_zero() {
        assert_eq!(serial_of(0), "0");
    }

    #[test]
    fn serial_null_is_empty() {
        // SAFETY: NULL is an accepted input per the fn contract.
        assert_eq!(unsafe { asn1_integer_hex(ptr::null()) }, "");
    }

    /// Regression: a cert whose DER-encoded serial has the high bit set is
    /// interpreted by OpenSSL as a negative BIGNUM; `BN_bn2hex` (BN_bn2bin(3))
    /// prefixes the hex string with `-` for negative values.  Before the fix,
    /// that leading `-` was passed through unchanged.  After the fix, the sign
    /// is stripped so the serial is rendered as the canonical absolute hex value
    /// — matching `openssl x509 -serial` output (RFC 5280 §4.1.2.2 requires
    /// positive serials; legacy CAs occasionally issued non-conformant ones).
    ///
    /// We construct the negative ASN1_INTEGER directly via BN: allocate a
    /// BIGNUM, set it to the absolute value 0xDEADBEEF, mark it negative with
    /// BN_set_negative, then convert to ASN1_INTEGER with BN_to_ASN1_INTEGER.
    #[test]
    fn serial_negative_bignum_no_leading_minus() {
        // SAFETY: BN_new allocates a fresh, zeroed BIGNUM.
        let bn = unsafe { ossl::BN_new() };
        assert!(!bn.is_null());
        // Set bn = 0xDEADBEEF (positive first, then flip sign).
        // SAFETY: `bn` is valid; BN_set_word sets its magnitude.
        let ok = unsafe { ossl::BN_set_word(bn, 0xDEAD_BEEF) };
        assert_eq!(ok, 1);
        // SAFETY: marks the BIGNUM as negative (BN_set_negative(3)).
        unsafe { ossl::BN_set_negative(bn, 1) };

        // Convert the negative BIGNUM to an ASN1_INTEGER.
        // SAFETY: `bn` is valid; BN_to_ASN1_INTEGER with NULL `ai` allocates.
        let ser = unsafe { ossl::BN_to_ASN1_INTEGER(bn, ptr::null_mut()) };
        assert!(!ser.is_null());
        // SAFETY: `bn` was allocated above and is no longer needed.
        unsafe { ossl::BN_free(bn) };

        // SAFETY: `ser` is the valid ASN1_INTEGER just constructed.
        let got = unsafe { asn1_integer_hex(ser) };
        // SAFETY: `ser` was allocated by BN_to_ASN1_INTEGER and not yet freed.
        unsafe { ossl::ASN1_INTEGER_free(ser) };

        // Must be the absolute hex value without any leading `-`.
        assert_eq!(got, "DEADBEEF", "negative serial must render without leading `-`");
        assert!(!got.starts_with('-'), "no leading minus sign in serial hex");
    }

    // ── Pubkey-alg mapping (pure) ────────────────────────────────────────────

    #[test]
    fn pubkey_alg_mapping() {
        assert_eq!(pubkey_alg_name(ossl::EVP_PKEY_RSA), Some("RSA"));
        assert_eq!(pubkey_alg_name(ossl::EVP_PKEY_RSA_PSS), Some("RSA-PSS"));
        assert_eq!(pubkey_alg_name(ossl::EVP_PKEY_EC), Some("EC"));
        assert_eq!(pubkey_alg_name(ossl::EVP_PKEY_ED25519), Some("ED25519"));
        assert_eq!(pubkey_alg_name(ossl::EVP_PKEY_ED448), Some("ED448"));
        assert_eq!(pubkey_alg_name(ossl::EVP_PKEY_DSA), Some("DSA"));
        assert_eq!(pubkey_alg_name(-1), None);
    }

    // ── server_name wildcard policy (pure) ──────────────────────────────────

    #[test]
    fn wildcard_name_policy() {
        assert!(is_wildcard_name(b""));
        assert!(is_wildcard_name(b"*.example.com"));
        assert!(is_wildcard_name(b"www.example.*"));
        assert!(is_wildcard_name(b".example.com"));
        assert!(is_wildcard_name(b"~^www\\d+\\."));
        assert!(!is_wildcard_name(b"example.com"));
        assert!(!is_wildcard_name(b"_"));
    }
}
