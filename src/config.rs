// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::ffi::{c_char, c_void};
use core::ptr::NonNull;
use core::{mem, ptr};

use crate::logs::error_writer::{
    ngx_otel_error_writer, otel_log_insert, parse_error_log_level, OtelErrorWriterState,
};
use nginx_sys::{
    ngx_array_t, ngx_command_t, ngx_conf_parse, ngx_conf_t, ngx_flag_t,
    ngx_http_compile_complex_value_t, ngx_http_complex_value_t, ngx_module_t, ngx_str_t,
    ngx_uint_t, NGX_CONF_BLOCK, NGX_CONF_FLAG, NGX_CONF_NOARGS, NGX_CONF_TAKE1, NGX_CONF_TAKE2,
    NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF, NGX_HTTP_MAIN_CONF_OFFSET,
    NGX_HTTP_SRV_CONF, NGX_LOG_DEBUG, NGX_LOG_EMERG, NGX_LOG_WARN,
};
use ngx::core::{Status, NGX_CONF_ERROR, NGX_CONF_OK};
use ngx::http::{HttpModuleLocationConf, HttpModuleMainConf, NgxHttpCoreModule};
use ngx::{ngx_conf_log_error, ngx_string};

use crate::shm::{ROUTE_CAP, UPSTREAM_CAP, UPSTREAM_IDX_OTHER};

use crate::shm;
use crate::HttpOtelModule;

/* ─────────────────────────── extension helpers ─────────────────────────────── */

/// Returns the directive arguments from a `ngx_conf_t`.
///
/// # Safety
/// Caller must ensure `cf` is a valid, non-null pointer and that `cf.args`
/// points to an initialized `ngx_array_t` of `ngx_str_t` elements.
unsafe fn cf_args(cf: *const ngx_conf_t) -> &'static [ngx_str_t] {
    // SAFETY: the fn contract requires `cf` to be a valid non-null pointer, so
    // reading its `args` field is well-defined.
    let arr: *const ngx_array_t = unsafe { (*cf).args };
    if arr.is_null() {
        return &[];
    }
    // SAFETY: `arr` is non-null (checked above) and, per the fn contract, points
    // to an initialized `ngx_array_t` of `ngx_str_t`; `as_slice` reinterprets it
    // as a `[ngx_str_t]` of `nelts` length, which nginx keeps valid for the parse.
    unsafe { (*arr).as_slice::<ngx_str_t>() }
}

// Sentinel: ngx_flag_t not yet set by config
const UNSET_FLAG: ngx_flag_t = -1;
// Sentinel: u64 not yet set
const UNSET_U64: u64 = u64::MAX;
// Default export interval: 10 s in milliseconds
const DEFAULT_INTERVAL_MS: u64 = 10_000;
// Default batch size
/// Default retry-buffer depth used by [`MainConfig::retry_buffer_depth`].
/// See the spec-inconsistency note on that method.
const DEFAULT_RETRY_BUFFER_DEPTH: usize = 4;

/// Selects the OTLP wire transport for metric export.
///
/// Corresponds to the `otel_export_protocol` directive:
/// - `otlp_http` (default): OTLP/HTTP over HTTP/1.1 (`POST /v1/metrics`).
/// - `otlp_grpc`:           OTLP/gRPC over HTTP/2 (`MetricsService.Export`).
/// - `arrow` is reserved for a future OTel Arrow transport and is rejected at
///   config parse time.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExportProtocol {
    /// OTLP/HTTP protobuf — the default.  Uses `HyperHttpTransport`.
    OtlpHttp,
    /// OTLP/gRPC — new in this phase.  Uses `GrpcTransport`.
    OtlpGrpc,
}

/// Per-worker key-value pair stored in NGINX pool memory.
/// Both key and value are ngx_str_t slices into the configuration file buffer.
#[derive(Clone, Copy, Debug)]
pub struct KvPair {
    pub key: ngx_str_t,
    pub value: ngx_str_t,
}

/// Exporter sub-block configuration.
#[derive(Debug)]
pub struct ExporterConfig {
    /// Base OTLP endpoint URL.  For HTTP, the per-signal paths `/v1/metrics`,
    /// `/v1/logs`, `/v1/traces` are appended to this base at export-loop startup
    /// (OTel spec §`OTEL_EXPORTER_OTLP_ENDPOINT` behaviour).
    /// Accepted schemes: `unix:`, `http://`, `https://`.
    pub endpoint: ngx_str_t,
    /// Path to a trusted CA certificate for HTTPS (`trusted_certificate`
    /// directive).  Active when the endpoint is `https://`; absent → system
    /// default trust store (`SSL_CTX_set_default_verify_paths`).
    pub trusted_cert: ngx_str_t,
    /// mTLS client certificate chain path (`ssl_certificate` directive).
    /// Used only when BOTH `ssl_cert` and `ssl_cert_key` are set.
    pub ssl_cert: ngx_str_t,
    /// mTLS client private key path (`ssl_certificate_key` directive).
    pub ssl_cert_key: ngx_str_t,
    /// `ssl_verify` flag: `NGX_CONF_UNSET` (−1) = not set (defaults to ON);
    /// `1` = on (default); `0` = off.
    ///
    /// `ssl_verify off` disables collector certificate verification — INSECURE,
    /// for testing only.  One WARN is logged at config time when set to off.
    pub ssl_verify: ngx_flag_t,
    /// Per-signal override for metrics (optional).  If non-empty, used as-is
    /// (no path appended) instead of the base-derived `/v1/metrics`.
    /// Mirrors `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`.
    pub metrics_endpoint: ngx_str_t,
    /// Per-signal override for logs (optional).  If non-empty, used as-is
    /// instead of the base-derived `/v1/logs`.
    /// Mirrors `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`.
    pub logs_endpoint: ngx_str_t,
    /// Per-signal override for traces (optional).  If non-empty, used as-is
    /// instead of the base-derived `/v1/traces`.
    /// Mirrors `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`.
    pub traces_endpoint: ngx_str_t,
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            endpoint: ngx_str_t::default(),
            trusted_cert: ngx_str_t::default(),
            ssl_cert: ngx_str_t::default(),
            ssl_cert_key: ngx_str_t::default(),
            // UNSET_FLAG (−1): `ssl_verify` not configured → defaults to ON at
            // validation time.  Value 1 = on, 0 = off.
            ssl_verify: UNSET_FLAG,
            metrics_endpoint: ngx_str_t::default(),
            logs_endpoint: ngx_str_t::default(),
            traces_endpoint: ngx_str_t::default(),
        }
    }
}

impl ExporterConfig {
    pub fn is_set(&self) -> bool {
        !self.endpoint.is_empty()
    }

    /// Returns `true` when `ssl_verify off` is explicitly configured.
    pub fn ssl_verify_off(&self) -> bool {
        self.ssl_verify == 0
    }
}

/// Outcome of endpoint + TLS config-time validation (the pure logic behind the
/// `post_config` checks). `Ok` carries whether the insecure WARN should be
/// emitted; `Err` carries the specific config error so `post_config` can log
/// the matching NGX_LOG_EMERG message and return `NGX_ERROR`.
///
/// This is split out of `post_config` so the validation DECISIONS can be unit
/// tested without an `ngx_conf_t` FFI context (the production `post_config`
/// calls exactly this function).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TlsConfigError {
    /// Endpoint scheme is none of `unix:` / `http://` / `https://`.
    BadScheme,
    /// `ssl_certificate` set without `ssl_certificate_key`.
    CertWithoutKey,
    /// `ssl_certificate_key` set without `ssl_certificate`.
    KeyWithoutCert,
    /// A configured TLS file (label) does not exist / is not readable.
    FileMissing(&'static str),
}

/// Inputs to [`validate_endpoint_tls`] (borrowed string slices for the
/// endpoint + the three TLS file paths; empty string = unset).
pub(crate) struct TlsValidationInput<'a> {
    pub endpoint: &'a str,
    pub trusted_cert: &'a str,
    pub ssl_cert: &'a str,
    pub ssl_cert_key: &'a str,
    pub ssl_verify_off: bool,
}

/// Pure endpoint + TLS validation. `file_exists` is injected (production:
/// `|p| Path::new(p).metadata().is_ok()`; tests: a closure over a known set) so
/// the decision logic is testable without touching the filesystem layout.
///
/// Returns `Ok(warn_insecure)` on success, where `warn_insecure` is `true` iff
/// the `ssl_verify off` WARN should be emitted. Returns the first failing check
/// as `Err`. Mirrors the nginx idiom: validate at config-parse time.
pub(crate) fn validate_endpoint_tls(
    input: &TlsValidationInput<'_>,
    file_exists: impl Fn(&str) -> bool,
) -> Result<bool, TlsConfigError> {
    let is_https = input.endpoint.starts_with("https://");
    let valid_scheme =
        input.endpoint.starts_with("unix:") || input.endpoint.starts_with("http://") || is_https;
    if !valid_scheme {
        return Err(TlsConfigError::BadScheme);
    }

    let has_cert = !input.ssl_cert.is_empty();
    let has_key = !input.ssl_cert_key.is_empty();
    if has_cert && !has_key {
        return Err(TlsConfigError::CertWithoutKey);
    }
    if !has_cert && has_key {
        return Err(TlsConfigError::KeyWithoutCert);
    }

    // File-existence checks only apply to https:// endpoints.
    if is_https {
        for (label, path) in &[
            ("trusted_certificate", input.trusted_cert),
            ("ssl_certificate", input.ssl_cert),
            ("ssl_certificate_key", input.ssl_cert_key),
        ] {
            if path.is_empty() {
                continue;
            }
            if !file_exists(path) {
                return Err(TlsConfigError::FileMissing(label));
            }
        }
    }

    Ok(input.ssl_verify_off)
}

// ── Route and upstream tables ───────────────────────────────────────────────

/// Maximum bytes stored per route name in the lookup table.
pub const ROUTE_NAME_MAX: usize = 64;

/// Maximum bytes stored per upstream zone name in the lookup table.
pub const UPSTREAM_NAME_MAX: usize = 32;

/// One entry in the per-`MainConfig` route lookup table.
///
/// Populated at `postconfiguration` time by walking the location tree.
/// Hot-path lookup: `clcf_ptr` = `ngx_http_core_loc_conf_t *` as `usize`.
#[derive(Copy, Clone)]
pub struct RouteEntry {
    /// The `ngx_http_core_loc_conf_t *` pointer value for this location,
    /// cast to `usize`.  `0` = empty slot.
    pub clcf_ptr: usize,
    /// Location name bytes (e.g. `"/api"`, `"/"`, `"= /health"`).
    pub name: [u8; ROUTE_NAME_MAX],
    /// Length of the name in bytes (0 = empty/unnamed).
    pub name_len: u8,
}

impl RouteEntry {
    /// Returns the route name as a `&str` slice (UTF-8 best-effort; caller
    /// is responsible for validity).
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("(invalid)")
    }
}

/// One entry in the per-`MainConfig` upstream-zone lookup table.
#[derive(Copy, Clone)]
pub struct UpstreamEntry {
    /// The `ngx_shm_zone_t *` pointer value for this upstream zone, cast to
    /// `usize`.  `0` = empty slot.
    pub shm_zone_ptr: usize,
    /// Upstream zone name bytes.
    pub name: [u8; UPSTREAM_NAME_MAX],
    /// Length of the name in bytes.
    pub name_len: u8,
}

impl UpstreamEntry {
    /// Returns the zone name as a `&str` slice.
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("(invalid)")
    }
}

/// Main (http-block) configuration for ngx-otel-rust.
pub struct MainConfig {
    /// Whether `otel_exporter { ... }` was configured.
    pub exporter: ExporterConfig,
    /// `otel_service_name`
    pub service_name: ngx_str_t,
    /// `otel_resource_attr <k> <v>` — accumulated list.
    pub resource_attrs: std::vec::Vec<KvPair>,
    /// `otel_exporter_header <k> <v>` — accumulated list.
    pub exporter_headers: std::vec::Vec<KvPair>,
    /// `otel_metric_interval` — stored in milliseconds; UNSET_U64 until configured.
    pub metric_interval_ms: u64,
    /// `otel_metric_zone <name> <size>` — name part.
    pub zone_name: ngx_str_t,
    /// `otel_metric_zone <name> <size>` — size in bytes; 0 = not configured.
    pub zone_size: usize,
    /// `otel_metric_status_code_class on | off`
    /// UNSET_FLAG (-1) = not set (treated as on/default).
    pub status_code_class: ngx_flag_t,
    /// `otel_grpc_smoke_endpoint <url>` — TEST-ONLY trigger for the
    /// in-worker unary gRPC viability harness.  When set
    /// (and the crate is built with the `test-support` feature),
    /// Worker 0's `init_process` fires one unary OTLP/gRPC export via
    /// `NgxExecutor` + `SendRequestService` + `NgxConnIo` to verify
    /// the export pipeline works end-to-end on real nginx event-loop
    /// infrastructure under `--with-debug`.  In production (non-test)
    /// builds the directive is parsed but ignored; documented as such
    /// in `src/transport/grpc/smoke.rs`.
    pub grpc_smoke_endpoint: ngx_str_t,
    /// `otel_grpc_bidi_smoke_endpoint <url>` — TEST-ONLY trigger for the
    /// bidi gRPC viability harness.  Parallel to
    /// `grpc_smoke_endpoint`.  When set (and built with
    /// `test-support`), Worker 0's `init_process` fires one bidi
    /// `Echo.BidiEcho` call against the local echo server to verify that
    /// the send-half and receive-half are independently pollable through
    /// `NgxConnIo`.  Parsed in all builds; acted on only with
    /// `test-support`.
    pub bidi_smoke_endpoint: ngx_str_t,
    /// `otel_grpc_bidi_overload_endpoint <url>` — TEST-ONLY trigger for the
    /// backpressure / livelock integration test.  Parallel
    /// to `bidi_smoke_endpoint`.  When set (and built with
    /// `test-support`), Worker 0's `init_process` fires a sustained bidi
    /// overload against the echo server, exercising the give-up path and
    /// incrementing `BIDI_BACKPRESSURE_DROPS`.  Parsed in all builds; acted
    /// on only with `test-support`.
    pub bidi_overload_endpoint: ngx_str_t,
    /// `otel_export_protocol otlp_http | otlp_grpc;` — selects the export
    /// transport.  `None` means the directive was not set; treated as
    /// `OtlpHttp` (default) by the `export_protocol` accessor.
    pub export_protocol: Option<ExportProtocol>,
    /// The registered shared memory zone (set during postconfiguration).
    pub shm_zone: *mut nginx_sys::ngx_shm_zone_t,
    /// The registered control-plane shared memory zone (set during
    /// postconfiguration alongside `shm_zone`). Used by the exporter for
    /// the liveness heartbeat and by workers for the hot-path placeholder
    /// load. A future bidi control channel will also use this zone.
    pub control_shm_zone: *mut nginx_sys::ngx_shm_zone_t,
    /// The registered logs shm zone (set during postconfiguration when
    /// `any_log_export_enabled() || error_log_enabled`).  Per-worker layout:
    /// two rings per slot (access + error), each of `log_ring_cap` bytes.
    /// Memory = `log_ring_cap × 2 × N` + slab-pool header overhead.
    pub logs_shm_zone: *mut nginx_sys::ngx_shm_zone_t,
    /// The registered spans shm zone (set during postconfiguration; always
    /// registered when the module is loaded).  One ring per worker slot,
    /// `DEFAULT_SPAN_RING_CAP` bytes per ring.  The hot path is gated in
    /// the exporter by checking `spans_shm_base()` is non-null.
    pub spans_shm_zone: *mut nginx_sys::ngx_shm_zone_t,

    // ── Zone-init data ───────────────────────────────────────────────────────
    //
    // Each zone registration stores a `ZoneInitData` in these fields and points
    // `ngx_shm_zone_t.data` at it.  Storing inside `MainConfig` (config pool)
    // guarantees the pointer stays valid from postconfiguration through the
    // zone-init callbacks fired by the same `ngx_init_cycle` call.
    //
    /// Zone-init parameters for the metrics shm zone.
    pub metrics_zone_init_data: crate::shm::ZoneInitData,
    /// Zone-init parameters for the logs shm zone.
    pub logs_zone_init_data: crate::shm::ZoneInitData,
    /// Zone-init parameters for the spans shm zone.
    pub spans_zone_init_data: crate::shm::ZoneInitData,

    /// Final active worker count set by `check_zone_sizing` in `init_module`.
    ///
    /// Zones may be reserved for more capacity (ncpu-headroom); the
    /// exporter drains only `n_active_workers` slots.
    /// `0` = not yet set; callers fall back to zone-size-derived count.
    pub n_active_workers: core::sync::atomic::AtomicUsize,

    /// Set `true` when at least one location has `otel_log_export` set to a
    /// selecting form (`on`/bare or `if=<cond>`).  Drives the logs shm-zone
    /// allocation gate and the hot-path "Gate 1" cheap check, so that the
    /// common no-export deployment stays zero-cost.
    ///
    /// Read via the `any_log_export_enabled` accessor.
    pub any_log_export: bool,
    /// `otel_log_ring_size <size>` — per-worker ring capacity in bytes.
    /// `0` = not configured (uses `DEFAULT_LOG_RING_CAP`).
    pub log_ring_size: usize,

    // ── Error-log export ─────────────────────────────────────────────────────
    //
    /// `otel_error_log [<level>];` was seen.  `false` = not configured (default
    /// off).  When `true`, the `ngx_otel_error_writer` node is woven into the
    /// `cycle->new_log` chain and the logs shm zone is registered.
    pub error_log_enabled: bool,
    /// Effective severity floor for the OTel error-log writer.
    ///
    /// Set by `cmd_set_error_log`:
    /// - NOARGS: fixed default `NGX_LOG_ERR` (= 4). Intentionally decoupled
    ///   from the core `error_log` level — mirroring couples the OTel floor to
    ///   on-box debug verbosity and is directive-order dependent.
    /// - TAKE1: parsed from the level arg (e.g. `"warn"` → `NGX_LOG_WARN`).
    ///
    /// Writer drops messages where `level > error_log_level` (nginx levels are
    /// inverted: 1=emerg … 8=debug; higher number = less severe).
    pub error_log_level: ngx_uint_t,
    /// `otel_error_log_coalesce on|off;` — default `on`.
    ///
    /// `off` ⇒ the writer pushes every level-passing line verbatim to the
    /// bounded ring, bypassing the coalescer (best-effort, lossy under load).
    ///
    /// **⚠️ WARNING:** `off` is explicitly NOT guaranteed delivery.  The ring
    /// drops-newest under load; lost lines are accounted in `dropped_records`
    /// but gone.  The only guaranteed full-fidelity transcript is nginx's own
    /// (untouched) `error_log` file.  The companion error-rate metric
    /// counts the true total in both modes.
    pub error_log_coalesce: bool,

    // ── Route and upstream-zone dimension tables ─────────────────────────────
    //
    // Populated once at `postconfiguration` time (before workers fork) by
    // walking the nginx location tree and upstream list.  Workers inherit the
    // tables via fork and read them lock-free on the hot path (linear scan of
    // at most ROUTE_CAP / UPSTREAM_CAP entries — O(cap), no alloc).
    /// Route lookup table: one entry per named `location {}` block, capped at
    /// `ROUTE_CAP`.  Entries beyond the cap land in `ROUTE_CAP` ("other").
    pub route_table: [RouteEntry; ROUTE_CAP],
    /// Number of filled entries in `route_table` (0..=ROUTE_CAP).
    pub n_routes: usize,

    /// Upstream-zone lookup table: one entry per `upstream { zone ...; }`,
    /// capped at `UPSTREAM_CAP`.
    pub upstream_table: [UpstreamEntry; UPSTREAM_CAP],
    /// Number of filled entries in `upstream_table` (0..=UPSTREAM_CAP).
    pub n_upstreams: usize,

    // ── DNS resolver (transport DNS/dual-stack) ──────────────────────────────
    //
    /// Nginx resolver pulled from `clcf->resolver` at postconfiguration time.
    ///
    /// `None` when the endpoint is a literal IP address or a `unix:` path —
    /// no resolver is needed in those cases.  `Some` when the endpoint host is
    /// a DNS name and the operator has configured nginx's `resolver` directive.
    ///
    /// The pointer is valid for the lifetime of the nginx cycle (it lives in
    /// the conf pool).  The exporter process reads it after fork — safe because
    /// the conf pool is inherited copy-on-write.  Worker processes do not
    /// access this field.
    ///
    /// # Safety
    /// Raw pointer wrapped in `NonNull`.  Must not be accessed from multiple
    /// threads; safe because the exporter is single-threaded.
    pub resolver: Option<NonNull<nginx_sys::ngx_resolver_t>>,
    /// Resolver timeout in milliseconds, from `clcf->resolver_timeout`.
    ///
    /// `0` when `resolver` is `None`.  Falls back to 5000 ms when the core
    /// http conf has no explicit `resolver_timeout` (matching nginx-acme).
    pub resolver_timeout: nginx_sys::ngx_msec_t,

    // ── TLS cert-metrics ─────────────────────────────────────────────────────
    //
    /// Serving-certificate table, populated ONCE at `postconfiguration` time by
    /// [`crate::cert_table::build_cert_table`] (master process, before workers
    /// fork) and read-only afterwards.  Plain Rust heap: the exporter process
    /// inherits it at fork; workers never touch it (no worker-side code).
    /// Empty when nginx lacks http_ssl_module or no server has certificates.
    pub cert_table: std::vec::Vec<crate::cert_table::CertInfo>,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            exporter: ExporterConfig::default(),
            service_name: ngx_str_t::default(),
            resource_attrs: std::vec::Vec::new(),
            exporter_headers: std::vec::Vec::new(),
            metric_interval_ms: UNSET_U64,
            zone_name: ngx_str_t::default(),
            zone_size: 0,
            status_code_class: UNSET_FLAG,
            grpc_smoke_endpoint: ngx_str_t::default(),
            bidi_smoke_endpoint: ngx_str_t::default(),
            bidi_overload_endpoint: ngx_str_t::default(),
            export_protocol: None,
            shm_zone: ptr::null_mut(),
            control_shm_zone: ptr::null_mut(),
            logs_shm_zone: ptr::null_mut(),
            spans_shm_zone: ptr::null_mut(),
            // filled in at zone registration time.
            metrics_zone_init_data: crate::shm::ZoneInitData { ring_cap: 0, cycle_addr: 0 },
            logs_zone_init_data: crate::shm::ZoneInitData { ring_cap: 0, cycle_addr: 0 },
            spans_zone_init_data: crate::shm::ZoneInitData { ring_cap: 0, cycle_addr: 0 },
            // set by check_zone_sizing in init_module (0 = not yet set).
            n_active_workers: core::sync::atomic::AtomicUsize::new(0),
            // No location selects log export until a directive sets one.
            any_log_export: false,
            log_ring_size: 0,
            // Error-log defaults.
            error_log_enabled: false,
            // Fixed NGX_LOG_ERR default; overwritten by cmd_set_error_log only when
            // error_log_enabled is set (otherwise the field is never read by the writer).
            error_log_level: nginx_sys::NGX_LOG_ERR as ngx_uint_t,
            error_log_coalesce: true,
            // Route and upstream tables start empty; populated at postconfiguration.
            route_table: [RouteEntry { clcf_ptr: 0, name: [0u8; ROUTE_NAME_MAX], name_len: 0 };
                ROUTE_CAP],
            n_routes: 0,
            upstream_table: [UpstreamEntry {
                shm_zone_ptr: 0,
                name: [0u8; UPSTREAM_NAME_MAX],
                name_len: 0,
            }; UPSTREAM_CAP],
            n_upstreams: 0,
            // DNS resolver: None until postconfiguration wires it for DNS endpoints.
            resolver: None,
            resolver_timeout: 0,
            // Populated at postconfiguration by build_cert_table.
            cert_table: std::vec::Vec::new(),
        }
    }
}

/// Read `worker_processes` from the nginx core conf at postconfiguration time.
///
/// Returns the configured worker count (`>= 1`) when the `worker_processes`
/// directive has already been parsed, or `None` when it is still
/// `NGX_CONF_UNSET` (= -1) — which happens when `worker_processes` appears
/// **after** the `http {}` block in nginx.conf.
///
/// Callers that get `None` should fall back to a provisional value (1) and
/// arrange for `ngx_otel_init_module` to validate the actual count later.
///
/// # Safety
/// `cf` must be a valid, non-null `ngx_conf_t` at postconfiguration time.
unsafe fn n_workers_from_cf(cf: *const ngx_conf_t) -> Option<usize> {
    // SAFETY: caller guarantees `cf` is valid at postconfiguration time.
    let cycle = unsafe { (*cf).cycle.as_ref() }?;
    let core_idx = nginx_sys::ngx_core_module.index;
    // conf_ctx is *mut *mut *mut *mut c_void; the BIT value at
    // conf_ctx[core_idx] IS the ngx_core_conf_t*.
    // SAFETY: nginx fills conf_ctx before postconfiguration runs.
    let raw_conf: *mut *mut *mut core::ffi::c_void = unsafe { *cycle.conf_ctx.add(core_idx) };
    let core_conf = raw_conf.cast::<nginx_sys::ngx_core_conf_t>();
    if core_conf.is_null() {
        return None;
    }
    // SAFETY: core_conf is non-null per above check; the struct is valid for
    // the duration of postconfiguration.
    let wp = unsafe { (*core_conf).worker_processes };
    // wp == NGX_CONF_UNSET (-1 as ngx_int_t) when the directive has not been
    // parsed yet (e.g. it appears after the http{} block).
    if wp < 1 {
        None
    } else {
        Some(wp as usize)
    }
}

/// Worker-slot count to reserve in shm zones at parse time.
///
/// When `worker_processes` is already known (≥ 1), returns that exact count.
/// When still `NGX_CONF_UNSET` (directive appears after `http{}`), returns
/// `ngx_ncpu` — what `worker_processes auto` resolves to — so the zone fits
/// any later-placed count ≤ ncpu.  Falls back to 1 only if ncpu itself is 0
/// (should not happen on any real system).
///
/// # Safety
/// `cf` must be a valid, non-null `ngx_conf_t` at postconfiguration time.
unsafe fn n_workers_to_reserve(cf: *const ngx_conf_t) -> usize {
    // SAFETY: `cf` is valid, non-null per this `unsafe fn`'s contract.
    if let Some(wp) = unsafe { n_workers_from_cf(cf) } {
        return wp;
    }
    // worker_processes is UNSET — use ncpu headroom.
    // SAFETY: ngx_ncpu is set by nginx before any postconfiguration handler runs.
    let ncpu = unsafe { nginx_sys::ngx_ncpu };
    if ncpu > 0 {
        ncpu as usize
    } else {
        1
    }
}

/// Smallest worker-slot capacity across the metrics zone and the (optional)
/// logs and spans rings — the bound the LOG-phase `worker_id` guard must use.
///
/// A registered logs/spans zone (capacity > 0) tightens the bound; a zone that
/// is not registered (capacity 0) does not constrain it, because its ring is
/// never indexed.  Factored out as a pure function so the min-capacity invariant
/// is unit-testable without a live shm zone.
#[inline]
fn min_indexed_worker_capacity(metrics: usize, logs: usize, spans: usize) -> usize {
    let mut cap = metrics;
    if logs > 0 {
        cap = cap.min(logs);
    }
    if spans > 0 {
        cap = cap.min(spans);
    }
    cap
}

impl MainConfig {
    /// Returns `true` when `otel_exporter { endpoint ... }` was configured.
    pub fn is_configured(&self) -> bool {
        self.exporter.is_set()
    }

    /// Effective export interval.
    pub fn interval_ms(&self) -> u64 {
        if self.metric_interval_ms == UNSET_U64 {
            DEFAULT_INTERVAL_MS
        } else {
            self.metric_interval_ms
        }
    }

    /// Effective batch size (max data points per encoded batch).
    ///
    /// Maximum number of *unsent* batches the export loop holds in its retry
    /// buffer on send failure. Older entries are evicted oldest-first.
    /// Currently a constant; promotable to a directive if operators need it.
    pub fn retry_buffer_depth(&self) -> usize {
        DEFAULT_RETRY_BUFFER_DEPTH
    }

    /// Whether to emit the decomposed `method × status_class × protocol`
    /// breakdown on the duration histogram (default on; `UNSET`/`on` → true).
    ///
    /// Read in `export_loop` (`export/mod.rs`) to set
    /// `InstrumentedSource.status_code_class_enabled` (`metric_source/instrumented.rs`);
    /// `off` collapses the per-combo data points. The hot path always buckets
    /// status class in the combo histogram regardless of this flag.
    pub fn status_code_class_enabled(&self) -> bool {
        self.status_code_class != 0 // UNSET_FLAG or 1 → true; explicit 0 → false
    }

    /// Effective metric export protocol.  Returns `OtlpHttp` when the
    /// `otel_export_protocol` directive was not set (preserves existing
    /// byte-identical behaviour for HTTP).
    pub fn export_protocol(&self) -> ExportProtocol {
        self.export_protocol.unwrap_or(ExportProtocol::OtlpHttp)
    }

    /// Obtain the main config from the previous NGINX cycle (used for SIGHUP reload).
    ///
    /// Returns `None` on the initial startup cycle or if the old cycle had no config.
    ///
    /// # Lifetime
    /// No `unsafe` transmute is performed here. The widening from the borrow of
    /// `cf.cycle.old_cycle` to `&'a MainConfig` is provided by the ngx-rust trait
    /// [`HttpModuleMainConf::main_conf`], which yields `&'static Self::MainConf`
    /// (`ngx-rust/src/http/conf.rs:161`). The trait's `'static` is sound because
    /// the cycle's config pool outlives this Rust function call — the old cycle
    /// remains live through SIGHUP until all old workers have exited.
    ///
    /// In practice we only consult this inside `postconfiguration`, well before
    /// any old-cycle teardown, so the lifetime question is moot for current use.
    ///
    /// Mirrors `AcmeMainConfig::old_config` in `nginx-acme/src/conf.rs:667-676`.
    ///
    /// This hook is currently read-only (we log and return); it is the intended
    /// anchor for future cross-cycle state transfer such as TLS connection reuse.
    pub fn old_config<'a>(cf: &mut ngx_conf_t) -> Option<&'a MainConfig> {
        // SAFETY: `cf` is a live `&mut ngx_conf_t`; nginx keeps `cf.cycle` and the
        // chained `old_cycle` either null (handled by `as_ref()?`) or pointing at
        // valid cycle structs in config-pool memory during parsing.
        let old_cycle = unsafe { cf.cycle.as_ref()?.old_cycle.as_ref()? };
        if old_cycle.conf_ctx.is_null() {
            return None;
        }
        HttpOtelModule::main_conf(old_cycle)
    }

    /// Returns `true` if the endpoint URL requires DNS resolution.
    ///
    /// A DNS-name endpoint (e.g. `http://otel.example.com:4317/`) returns
    /// `true`; a literal-IP endpoint (`http://127.0.0.1:4317/`) and any
    /// `unix:` endpoint return `false`.
    ///
    /// IPv6 literals in bracket notation (`http://[::1]:4317/`) are handled
    /// by stripping the brackets before the `IpAddr::parse` probe, so they
    /// correctly return `false`.
    ///
    /// This is a pure function (no nginx calls) — safe to call from unit tests.
    pub fn endpoint_needs_resolver(endpoint_str: &str) -> bool {
        // unix: paths never need DNS.
        if endpoint_str.starts_with("unix:") {
            return false;
        }
        // Strip http:// or https:// to get the authority part.
        let rest = if let Some(r) = endpoint_str.strip_prefix("http://") {
            r
        } else if let Some(r) = endpoint_str.strip_prefix("https://") {
            r
        } else {
            // Unknown scheme — leave it to existing validation; no resolver needed.
            return false;
        };
        // Authority = everything before the first '/'.
        let authority = rest.split('/').next().unwrap_or(rest);
        // Extract the host, handling IPv6 bracket notation.
        let host = if let Some(inner) = authority.strip_prefix('[') {
            // [::1]:4317 — host is between '[' and ']'.
            inner.split(']').next().unwrap_or(inner)
        } else {
            // host:port or bare host — strip the trailing :port if present and
            // the remaining part is a valid port number.
            match authority.rfind(':') {
                Some(i) if authority[i + 1..].chars().all(|c| c.is_ascii_digit()) => {
                    &authority[..i]
                }
                _ => authority,
            }
        };
        // If the host parses as a literal IP address it needs no resolver.
        host.parse::<std::net::IpAddr>().is_err()
    }

    /// Validate and finalise the configuration after all directives have been parsed.
    ///
    /// Takes `&mut self` to store the shm zone pointer.
    pub fn postconfiguration(
        &mut self,
        cf: *mut ngx_conf_t,
        module: *mut ngx_module_t,
    ) -> Result<(), Status> {
        // Check for SIGHUP reload: look for the previous cycle's config.
        // Currently we only log here; this is the intended anchor for future
        // cross-cycle state transfer such as TLS connection reuse.
        // SAFETY: nginx invokes `postconfiguration` with a valid non-null `cf`,
        // so `&mut *cf` is a sound exclusive borrow for the call to `old_config`.
        if let Some(old) = unsafe { Self::old_config(&mut *cf) } {
            if self.is_configured() {
                ngx_conf_log_error!(
                    NGX_LOG_DEBUG,
                    &raw mut *cf,
                    "otel: SIGHUP reload detected (old endpoint={}, new endpoint={})",
                    old.exporter.endpoint,
                    self.exporter.endpoint
                );
            } else {
                ngx_conf_log_error!(
                    NGX_LOG_DEBUG,
                    &raw mut *cf,
                    "otel: SIGHUP reload detected: new config has no otel_exporter block"
                );
            }
        }

        if !self.is_configured() {
            // Module loaded but not configured: zero-cost mode.
            return Ok(());
        }

        // ── Endpoint + TLS directive validation ────────────────────────────────
        //
        // Config-time checks follow the nginx idiom (fail at config parse, not at
        // runtime). The DECISION logic lives in `validate_endpoint_tls` (pure,
        // unit-tested); here we map its result to the matching nginx log message.
        // These checks only apply to the exporter config block; workers never
        // touch TLS paths.
        let ep = self.exporter.endpoint.as_bytes();
        let ep_str_for_val = core::str::from_utf8(ep).unwrap_or("");
        let val_input = TlsValidationInput {
            endpoint: ep_str_for_val,
            trusted_cert: core::str::from_utf8(self.exporter.trusted_cert.as_bytes()).unwrap_or(""),
            ssl_cert: core::str::from_utf8(self.exporter.ssl_cert.as_bytes()).unwrap_or(""),
            ssl_cert_key: core::str::from_utf8(self.exporter.ssl_cert_key.as_bytes()).unwrap_or(""),
            ssl_verify_off: self.exporter.ssl_verify_off(),
        };
        match validate_endpoint_tls(&val_input, |p| std::path::Path::new(p).metadata().is_ok()) {
            Ok(warn_insecure) => {
                // ssl_verify off: one WARN at config time.
                if warn_insecure {
                    ngx_conf_log_error!(
                        NGX_LOG_WARN,
                        &raw mut *cf,
                        "otel_exporter: ssl_verify off — collector certificate verification is \
                         DISABLED (INSECURE, for testing only)"
                    );
                }
            }
            Err(TlsConfigError::BadScheme) => {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &raw mut *cf,
                    "otel_exporter: \"endpoint\" must start with http://, https://, or unix:"
                );
                return Err(Status::NGX_ERROR);
            }
            Err(TlsConfigError::CertWithoutKey) => {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &raw mut *cf,
                    "otel_exporter: ssl_certificate set but ssl_certificate_key is missing"
                );
                return Err(Status::NGX_ERROR);
            }
            Err(TlsConfigError::KeyWithoutCert) => {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &raw mut *cf,
                    "otel_exporter: ssl_certificate_key set but ssl_certificate is missing"
                );
                return Err(Status::NGX_ERROR);
            }
            Err(TlsConfigError::FileMissing(label)) => {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &raw mut *cf,
                    "otel_exporter: {}: file not found or not readable",
                    label
                );
                return Err(Status::NGX_ERROR);
            }
        }

        // Wire the nginx resolver when the endpoint host is a DNS name.
        //
        // Follows the nginx-acme pattern (`nginx-acme/src/conf/issuer.rs:202–226`):
        // pull `clcf->resolver` and `clcf->resolver_timeout` from the http core
        // location conf.  A DNS-name endpoint with no configured `resolver` is a
        // hard config error — the operator must add a `resolver` directive in the
        // http block.  Literal IPv4/IPv6 and unix: endpoints skip this block.
        if let Ok(ep_str) = core::str::from_utf8(ep) {
            if Self::endpoint_needs_resolver(ep_str) {
                // NGX_CONF_UNSET cast to ngx_msec_t (usize) — matches acme's
                // `const NGX_CONF_UNSET_MSEC: ngx_msec_t = nginx_sys::NGX_CONF_UNSET as _`.
                const NGX_CONF_UNSET_MSEC: nginx_sys::ngx_msec_t =
                    nginx_sys::NGX_CONF_UNSET as nginx_sys::ngx_msec_t;
                const DEFAULT_RESOLVER_TIMEOUT_MS: nginx_sys::ngx_msec_t = 5_000;

                // SAFETY: `cf` is the valid non-null parse context; `&*cf` is a
                // sound shared borrow used only to read the core location conf.
                let cf_ref = unsafe { &*cf };
                // Collect resolver pointer and timeout from clcf, dropping the
                // borrow on clcf before we potentially use `&mut *cf` for logging.
                let resolver_info = NgxHttpCoreModule::location_conf(cf_ref).and_then(|clcf| {
                    let nn = NonNull::new(clcf.resolver)?;
                    // A resolver with zero connections means it was not
                    // properly configured (matches acme's connections.nelts
                    // guard, `issuer.rs:212-216`).
                    // SAFETY: `nn` is non-null (just constructed via `NonNull::new`)
                    // and points to the `ngx_resolver_t` nginx allocated in the conf
                    // pool for `clcf->resolver`; reading `connections.nelts` is sound.
                    if unsafe { nn.as_ref() }.connections.nelts == 0 {
                        return None;
                    }
                    let timeout = if clcf.resolver_timeout != NGX_CONF_UNSET_MSEC {
                        clcf.resolver_timeout
                    } else {
                        DEFAULT_RESOLVER_TIMEOUT_MS
                    };
                    Some((nn, timeout))
                });

                match resolver_info {
                    Some((resolver, timeout)) => {
                        self.resolver = Some(resolver);
                        self.resolver_timeout = timeout;
                    }
                    None => {
                        ngx_conf_log_error!(
                            NGX_LOG_EMERG,
                            &raw mut *cf,
                            "otel_exporter: endpoint \"{}\" is a DNS name but nginx's \
                             \"resolver\" directive is not configured; add \"resolver \
                             <nameserver>;\" to the http block to use a DNS name in \
                             otel_exporter",
                            ep_str
                        );
                        return Err(Status::NGX_ERROR);
                    }
                }
            }
        }

        // Register the metrics shared memory zone.
        self.register_shm_zone(cf, module)?;

        // Register the control-plane shared memory zone.
        // This zone holds the ControlShm heartbeat counter and a reserved
        // flag word for a future bidi control channel. Registered alongside
        // the metrics zone so both are mapped before workers fork.
        self.register_control_shm_zone(cf, module)?;

        // Register the per-worker logs shm zone when any location selects
        // log export, or the OTel error-log writer is enabled.
        if self.any_log_export_enabled() || self.error_log_enabled {
            self.register_logs_zone(cf, module)?;
        }

        // Register the dedicated spans shm zone.  Always registered
        // when the module is loaded so the exporter can drain it even before any
        // trace directive is configured (the ring is just empty in that case).
        self.register_spans_zone(cf, module)?;

        // Build the route and upstream-zone lookup tables.
        // This walks the nginx location tree and upstream list ONCE before
        // workers fork, so all workers see identical tables.
        // Safety: cf is valid; nginx guarantees postconfiguration runs after
        // all location and upstream configs are parsed and merged.
        // SAFETY: `cf` is the valid non-null parse context, and nginx runs
        // `postconfiguration` only after every location/upstream conf is parsed
        // and merged, satisfying `build_route_table`'s contract.
        unsafe { self.build_route_table(cf) };
        // SAFETY: same as above — valid `cf` at postconfiguration time satisfies
        // `build_upstream_table`'s contract.
        unsafe { self.build_upstream_table(cf) };

        // Build the TLS serving-certificate table.  Runs
        // after ngx_http_ssl_module's merge_srv_conf has loaded all config-time
        // certificates into each server's SSL_CTX (merges complete before any
        // postconfiguration handler), in the single-threaded master.
        // SAFETY: `cf` is the valid non-null postconfiguration parse context,
        // satisfying `build_cert_table`'s contract.
        unsafe { crate::cert_table::build_cert_table(self, cf) };

        Ok(())
    }

    /// Register the per-worker shared memory zone with nginx.
    fn register_shm_zone(
        &mut self,
        cf: *mut ngx_conf_t,
        module: *mut ngx_module_t,
    ) -> Result<(), Status> {
        // reserve capacity for ngx_ncpu slots when worker_processes is UNSET
        // (directive appears after http{}); fall back to the known count otherwise.
        // SAFETY: `cf` is the valid non-null parse context at postconfiguration.
        let n_workers: usize = unsafe { n_workers_to_reserve(cf) };

        // Compute required zone size.
        let required_size = shm::zone_size_for(n_workers);

        // Choose a zone name: use the configured name or default.
        let default_name = ngx::ngx_string!("ngx_http_otel_zone");
        let mut zone_name: ngx_str_t =
            if self.zone_name.is_empty() { default_name } else { self.zone_name };

        // Apply the larger of required size and explicitly configured size.
        let zone_size =
            if self.zone_size > 0 { self.zone_size.max(required_size) } else { required_size };

        // Register the zone.
        // SAFETY: `cf` and `module` are the valid non-null pointers nginx passed
        // to `postconfiguration`, satisfying `register_zone`'s contract.
        let Some(zone) = (unsafe { shm::register_zone(cf, &mut zone_name, zone_size, module) })
        else {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel: failed to register shared memory zone"
            );
            return Err(Status::NGX_ERROR);
        };

        // fill the ZoneInitData for the zone-init callback.
        // SAFETY: `cf` is valid and non-null per the postconfiguration contract.
        let cycle_addr = unsafe { (*cf).cycle as usize };
        self.metrics_zone_init_data = crate::shm::ZoneInitData {
            ring_cap: 0, // metrics zone has no ring
            cycle_addr,
        };

        // Configure the zone init callback.
        // SAFETY: `register_zone` returned a non-null `ngx_shm_zone_t*` that nginx
        // owns in the conf pool; writing its `init`/`data` fields is sound, and
        // `self` outlives the zone (it lives in the same conf pool).
        unsafe {
            (*zone).init = Some(shm::otel_shm_zone_init);
            // point data at ZoneInitData (was: MainConfig*).
            // The reload-detection in otel_shm_zone_init only checks old_data.is_null()
            // so the type change is transparent to reload semantics.
            (*zone).data = ptr::from_mut(&mut self.metrics_zone_init_data).cast();
        }

        self.shm_zone = zone;
        Ok(())
    }

    /// Register the control-plane shared memory zone with nginx.
    ///
    /// Mirrors `register_shm_zone` but uses a fixed size
    /// (`ControlShm::ZONE_SIZE`) and the control-zone init callback.
    /// Stores the resulting `*mut ngx_shm_zone_t` on
    /// `MainConfig::control_shm_zone`.
    fn register_control_shm_zone(
        &mut self,
        cf: *mut ngx_conf_t,
        module: *mut ngx_module_t,
    ) -> Result<(), Status> {
        let mut zone_name = ngx::ngx_string!("ngx_http_otel_control_zone");
        let zone_size = crate::exporter::control_shm::ControlShm::ZONE_SIZE;

        // SAFETY: `cf` and `module` are the valid non-null pointers nginx passed
        // to `postconfiguration`, satisfying `register_zone`'s contract.
        let Some(zone) = (unsafe { shm::register_zone(cf, &mut zone_name, zone_size, module) })
        else {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel: failed to register control shared memory zone"
            );
            return Err(Status::NGX_ERROR);
        };

        // SAFETY: `register_zone` returned a non-null `ngx_shm_zone_t*` owned by
        // nginx in the conf pool; writing its `init`/`data` fields is sound, and
        // `self` outlives the zone (same conf pool).
        unsafe {
            (*zone).init = Some(crate::exporter::control_shm::control_shm_zone_init);
            (*zone).data = ptr::from_mut(self).cast();
        }

        self.control_shm_zone = zone;
        Ok(())
    }

    /// Register the per-worker logs shm zone with nginx.
    ///
    /// Must be called from `postconfiguration` when
    /// `any_log_export_enabled() || error_log_enabled`.
    /// Sizes the zone for `n_workers` workers.
    /// Parallels `register_shm_zone`.
    pub fn register_logs_zone(
        &mut self,
        cf: *mut ngx_conf_t,
        module: *mut ngx_module_t,
    ) -> Result<(), Status> {
        // reserve capacity for ncpu slots when worker_processes is UNSET.
        // SAFETY: `cf` is the valid non-null parse context at postconfiguration.
        let n_workers: usize = unsafe { n_workers_to_reserve(cf) };

        let cap = self.log_ring_cap();
        let zone_size = shm::logs_zone_size_for(n_workers, cap);
        let mut zone_name = ngx::ngx_string!("ngx_http_otel_logs_zone");

        // SAFETY: `cf` and `module` are the valid non-null pointers nginx passed
        // to `postconfiguration`, satisfying `register_zone`'s contract.
        let Some(zone) = (unsafe { shm::register_zone(cf, &mut zone_name, zone_size, module) })
        else {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel: failed to register logs shared memory zone"
            );
            return Err(Status::NGX_ERROR);
        };

        // fill ZoneInitData for the zone-init callback.
        // SAFETY: `cf` is valid and non-null per the postconfiguration contract.
        let cycle_addr = unsafe { (*cf).cycle as usize };
        self.logs_zone_init_data = crate::shm::ZoneInitData { ring_cap: cap, cycle_addr };

        // SAFETY: `register_zone` returned a non-null `ngx_shm_zone_t*` owned by
        // nginx in the conf pool; writing its `init`/`data` fields is sound.
        unsafe {
            (*zone).init = Some(shm::logs_shm_zone_init);
            // store ZoneInitData* instead of tagged cap.
            (*zone).data = ptr::from_mut(&mut self.logs_zone_init_data).cast();
        }

        self.logs_shm_zone = zone;
        Ok(())
    }

    /// Register the dedicated spans shm zone.
    ///
    /// One ring per worker, `DEFAULT_SPAN_RING_CAP` bytes per ring.
    /// Called unconditionally from `postconfiguration` when the module is active.
    pub fn register_spans_zone(
        &mut self,
        cf: *mut ngx_conf_t,
        module: *mut ngx_module_t,
    ) -> Result<(), Status> {
        // reserve capacity for ncpu slots when worker_processes is UNSET.
        // SAFETY: `cf` is the valid non-null parse context at postconfiguration.
        let n_workers: usize = unsafe { n_workers_to_reserve(cf) };

        let cap = shm::DEFAULT_SPAN_RING_CAP;
        let zone_size = shm::spans_zone_size_for(n_workers, cap);
        let mut zone_name = ngx::ngx_string!("ngx_http_otel_spans_zone");

        // SAFETY: same contract as `register_logs_zone`.
        let Some(zone) = (unsafe { shm::register_zone(cf, &mut zone_name, zone_size, module) })
        else {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel: failed to register spans shared memory zone"
            );
            return Err(Status::NGX_ERROR);
        };

        // fill ZoneInitData for the zone-init callback.
        // SAFETY: `cf` is valid and non-null per the postconfiguration contract.
        let cycle_addr = unsafe { (*cf).cycle as usize };
        self.spans_zone_init_data = crate::shm::ZoneInitData { ring_cap: cap, cycle_addr };

        // SAFETY: same contract as `register_logs_zone`.
        unsafe {
            (*zone).init = Some(shm::spans_shm_zone_init);
            // store ZoneInitData* instead of tagged cap.
            (*zone).data = ptr::from_mut(&mut self.spans_zone_init_data).cast();
        }

        self.spans_shm_zone = zone;
        Ok(())
    }

    /// Returns the base address of the spans ring data in the spans shm zone.
    ///
    /// Returns `None` if the zone was not registered or not yet mapped.
    pub fn spans_shm_base(&self) -> Option<*mut u8> {
        // SAFETY: `spans_shm_zone` is either null or the `ngx_shm_zone_t*`
        // returned by `register_spans_zone`; reading `shm.addr` is sound.
        let zone = unsafe { self.spans_shm_zone.as_ref()? };
        let addr = zone.shm.addr;
        if addr.is_null() {
            return None;
        }
        // SAFETY: `addr` is the non-null mapped zone start; offset past the
        // slab-pool header is in-bounds (only formed, not dereferenced).
        Some(unsafe { addr.cast::<u8>().add(crate::shm::data_offset()) })
    }

    /// Returns the base address of our LogsWorkerSlot data within the logs shm zone.
    ///
    /// Parallels `shm_base`.  Returns `None` if the logs zone was not
    /// registered (access log disabled) or not yet mapped.
    pub fn logs_shm_base(&self) -> Option<*mut u8> {
        // SAFETY: `logs_shm_zone` is either null (handled by `as_ref()?`) or the
        // `ngx_shm_zone_t*` returned by `register_logs_zone`, which nginx keeps
        // valid for the cycle; reading `shm.addr` through it is sound.
        let zone = unsafe { self.logs_shm_zone.as_ref()? };
        let addr = zone.shm.addr;
        if addr.is_null() {
            return None;
        }
        // SAFETY: `addr` is the non-null mapped zone start; `data_offset()` bytes
        // (the slab-pool header) lie within the zone, so the offset pointer is
        // in-bounds — it is only formed here, not dereferenced.
        Some(unsafe { addr.cast::<u8>().add(crate::shm::data_offset()) })
    }

    /// Returns `true` when at least one location selects log export
    /// (`otel_log_export on` / bare / `if=<cond>` somewhere in the config).
    ///
    /// Gates the logs shm zone (allocated only when needed) and the LOG-phase
    /// "Gate 1" cheap check.  `off` does not set this — explicitly disabling a
    /// location is not a selection.
    #[inline]
    pub fn any_log_export_enabled(&self) -> bool {
        self.any_log_export
    }

    /// Resolve the `http.route` slot index for a request's matched location.
    ///
    /// `clcf_ptr` = the `ngx_http_core_loc_conf_t *` cast to `usize` for the
    /// request's matched location (read via `NgxHttpCoreModule::location_conf`).
    ///
    /// Returns a value in `0..ROUTE_CAP` for a registered location, or
    /// `ROUTE_CAP` (`"other"`) if the location is unknown or the table is full.
    ///
    /// # Hot-path note
    /// Linear scan of at most `ROUTE_CAP` entries (≤ 64 by default).  No alloc,
    /// no lock, no syscall.
    #[inline]
    pub fn route_idx_for_clcf(&self, clcf_ptr: usize) -> usize {
        if clcf_ptr == 0 {
            return ROUTE_CAP; // null → "other"
        }
        for i in 0..self.n_routes {
            if self.route_table[i].clcf_ptr == clcf_ptr {
                return i;
            }
        }
        ROUTE_CAP // not registered → "other"
    }

    /// Resolve the upstream-zone slot index for a request's upstream.
    ///
    /// `shm_zone_ptr` = the `ngx_shm_zone_t *` cast to `usize` for the
    /// upstream's shared-memory zone (from `r->upstream->upstream->shm_zone`).
    /// Pass `0` for requests with no upstream.
    ///
    /// Returns:
    /// - `0..UPSTREAM_CAP-1` for a registered zone
    /// - `UPSTREAM_IDX_OTHER` (`UPSTREAM_CAP`) when `shm_zone_ptr == 0` (no upstream)
    ///   or when the zone is over cap.
    ///
    /// The hot path skips bumping the upstream histogram when `shm_zone_ptr == 0`.
    #[inline]
    pub fn upstream_idx_for_zone(&self, shm_zone_ptr: usize) -> usize {
        if shm_zone_ptr == 0 {
            return UPSTREAM_IDX_OTHER; // no upstream → "other" / skip
        }
        for i in 0..self.n_upstreams {
            if self.upstream_table[i].shm_zone_ptr == shm_zone_ptr {
                return i;
            }
        }
        UPSTREAM_IDX_OTHER // not registered → "other"
    }

    /// Route name string for slot `route_idx` (for encoder attribute values).
    ///
    /// Returns the registered location name (e.g. `"/api"`), or special
    /// sentinel strings `"(other)"` for the overflow slot and `"(none)"` for
    /// the no-upstream slot.
    pub fn route_name(&self, route_idx: usize) -> &str {
        if route_idx == ROUTE_CAP {
            return "(other)";
        }
        if route_idx < self.n_routes {
            return self.route_table[route_idx].name_str();
        }
        "(other)"
    }

    /// Upstream zone name string for slot `upstream_idx` (for encoder attrs).
    pub fn upstream_zone_name(&self, upstream_idx: usize) -> &str {
        if upstream_idx == UPSTREAM_IDX_OTHER {
            return "(other)";
        }
        if upstream_idx < self.n_upstreams {
            return self.upstream_table[upstream_idx].name_str();
        }
        "(other)"
    }

    // ── Config-time table population (called once from postconfiguration) ────

    /// Walk the nginx static-location tree and register each location conf
    /// pointer in `route_table`.
    ///
    /// Called ONCE at `postconfiguration` time, before workers fork.  Workers
    /// inherit the populated table read-only.
    ///
    /// # Safety
    /// `cf` must be a valid, non-null `ngx_conf_t` pointer at postconfiguration.
    unsafe fn build_route_table(&mut self, cf: *mut ngx_conf_t) {
        use nginx_sys::{
            ngx_http_core_loc_conf_t, ngx_http_core_main_conf_t, ngx_http_core_srv_conf_t,
        };
        // Get HTTP core main conf → servers array.
        // SAFETY: per the fn contract `cf` is a valid non-null parse context at
        // postconfiguration; `&*cf` is a sound shared borrow.
        let cf_ref = unsafe { &*cf };
        let cmcf: Option<&ngx_http_core_main_conf_t> = NgxHttpCoreModule::main_conf(cf_ref);
        let cmcf = match cmcf {
            Some(c) => c,
            None => return, // no HTTP core — very unusual, skip gracefully
        };

        // Walk each server's location tree.
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
            // Get the server block's root location conf.
            // SAFETY: `cscf` is a non-null server-conf pointer from nginx's array
            // (checked above), valid in conf-pool memory; reading `ctx` is sound.
            let ctx = unsafe { (*cscf).ctx };
            if ctx.is_null() {
                continue;
            }
            // SAFETY: the core HTTP module's `ctx_index` is a static module field
            // nginx initialises before config parsing; reading it is sound.
            let core_ctx_idx = unsafe { nginx_sys::ngx_http_core_module.ctx_index };
            // SAFETY: `ctx` is non-null (checked above) and points to the server's
            // `ngx_http_conf_ctx_t`; reading its `loc_conf` array pointer is sound.
            let loc_conf_arr = unsafe { (*ctx).loc_conf };
            if loc_conf_arr.is_null() {
                continue;
            }
            // SAFETY: `loc_conf_arr` is nginx's per-context loc_conf array and
            // `core_ctx_idx` is the core module's slot within it (always in-bounds
            // for a server ctx); the slot holds the root `ngx_http_core_loc_conf_t*`.
            let root_clcf: *mut ngx_http_core_loc_conf_t =
                unsafe { (*loc_conf_arr.add(core_ctx_idx)).cast() };
            if root_clcf.is_null() {
                continue;
            }
            // Walk the static location tree rooted here.
            // SAFETY: `root_clcf` is non-null (checked above) and valid in conf-pool
            // memory; reading its `static_locations` tree-root pointer is sound.
            let static_locs = unsafe { (*root_clcf).static_locations };
            // SAFETY: `static_locs` is null or a valid location-tree node within
            // nginx config memory, satisfying `walk_location_tree`'s contract.
            unsafe { self.walk_location_tree(static_locs) };
        }
    }

    /// Recursively walk a `ngx_http_location_tree_node_t` tree and register
    /// all reachable location confs.
    ///
    /// # Safety
    /// `node` must be null or a valid pointer within nginx config memory.
    unsafe fn walk_location_tree(&mut self, node: *mut nginx_sys::ngx_http_location_tree_node_t) {
        if node.is_null() {
            return;
        }
        // SAFETY: `node` is non-null (checked above) and, per the fn contract, a
        // valid `ngx_http_location_tree_node_t` in nginx config memory.
        let n = unsafe { &*node };

        // Register the exact-match location at this node (if any).
        if !n.exact.is_null() {
            // SAFETY: `n.exact` is non-null (checked) and a valid
            // `ngx_http_core_loc_conf_t*`, satisfying `try_register_route`.
            unsafe { self.try_register_route(n.exact) };
        }
        // Register the inclusive (prefix-match) location if different from exact.
        if !n.inclusive.is_null() && n.inclusive != n.exact {
            // SAFETY: `n.inclusive` is non-null (checked) and a valid
            // `ngx_http_core_loc_conf_t*`, satisfying `try_register_route`.
            unsafe { self.try_register_route(n.inclusive) };
        }

        // Recurse into sub-locations (the `tree` subtree = inner `location {}` blocks
        // that share the current prefix).
        // SAFETY: `n.tree` is null or a valid sibling/child tree node owned by
        // nginx, satisfying `walk_location_tree`'s contract.
        unsafe { self.walk_location_tree(n.tree) };
        // Recurse into sibling nodes.
        // SAFETY: `n.left` is null or a valid tree node, per the contract.
        unsafe { self.walk_location_tree(n.left) };
        // SAFETY: `n.right` is null or a valid tree node, per the contract.
        unsafe { self.walk_location_tree(n.right) };
    }

    /// Register one location conf in the route table.  No-op if already
    /// registered or if the table is full (over-cap locations map to "other").
    ///
    /// # Safety
    /// `clcf_ptr` must be a valid non-null `ngx_http_core_loc_conf_t *`.
    unsafe fn try_register_route(&mut self, clcf_ptr: *mut nginx_sys::ngx_http_core_loc_conf_t) {
        let ptr_val = clcf_ptr as usize;

        // Deduplicate: skip if already registered.
        for i in 0..self.n_routes {
            if self.route_table[i].clcf_ptr == ptr_val {
                return;
            }
        }

        // Over cap → "other" bucket (no registration needed; the lookup will
        // return ROUTE_CAP by default).
        if self.n_routes >= ROUTE_CAP {
            return;
        }

        // SAFETY: per the fn contract `clcf_ptr` is a valid non-null
        // `ngx_http_core_loc_conf_t*` in conf-pool memory; `&*` reads it soundly.
        let clcf = unsafe { &*clcf_ptr };
        let name = clcf.name; // ngx_str_t
        let len = name.len.min(ROUTE_NAME_MAX);

        let idx = self.n_routes;
        self.route_table[idx].clcf_ptr = ptr_val;
        self.route_table[idx].name_len = len as u8;
        if len > 0 && !name.data.is_null() {
            // SAFETY: `name.data` is non-null (checked) and points to `name.len`
            // valid name bytes in conf memory; `len` is clamped to `name.len`, so
            // the slice of `len` bytes is in-bounds.
            let src = unsafe { core::slice::from_raw_parts(name.data, len) };
            self.route_table[idx].name[..len].copy_from_slice(src);
        }
        self.n_routes += 1;
    }

    /// Walk the upstream list and register each upstream zone in `upstream_table`.
    ///
    /// # Safety
    /// `cf` must be a valid, non-null `ngx_conf_t` pointer at postconfiguration.
    unsafe fn build_upstream_table(&mut self, cf: *mut ngx_conf_t) {
        use nginx_sys::ngx_http_upstream_srv_conf_t;

        // SAFETY: per the fn contract `cf` is a valid non-null parse context.
        let _cf_ref = unsafe { &*cf };

        // Access the upstream module's main conf via its ctx_index.
        // `ngx_http_upstream_module.ctx_index` is the position in the HTTP
        // main_conf array.  We navigate the same way as for the core module.
        // SAFETY: `ngx_http_upstream_module.ctx_index` is a static module field
        // nginx initialises before config parsing; reading it is sound.
        let ctx_index = unsafe { nginx_sys::ngx_http_upstream_module.ctx_index };

        // Get the HTTP conf ctx from cf (same approach used by NgxHttpCoreModule).
        // SAFETY: `cf` is valid; `cf.cycle` is the live cycle (null handled below),
        // the HTTP module's `conf_ctx` slot is in-bounds, and the pointer it holds
        // is the `ngx_http_conf_ctx_t*`, null-checked before use.
        let http_conf_ctx = unsafe {
            let cf_inner = &*(cf as *const nginx_sys::ngx_conf_t);
            // cf->cycle->conf_ctx[ngx_http_module.index] → ngx_http_conf_ctx_t *
            let cycle = match cf_inner.cycle.as_ref() {
                Some(c) => c,
                None => return,
            };
            let http_module_idx = nginx_sys::ngx_http_module.index;
            let raw: *const *mut core::ffi::c_void =
                *cycle.conf_ctx.add(http_module_idx) as *const *mut core::ffi::c_void;
            if raw.is_null() {
                return;
            }
            raw as *const nginx_sys::ngx_http_conf_ctx_t
        };
        // SAFETY: `http_conf_ctx` is the non-null HTTP `ngx_http_conf_ctx_t*`
        // computed above; reading its `main_conf` array pointer is sound.
        let main_conf_arr = unsafe { (*http_conf_ctx).main_conf };
        if main_conf_arr.is_null() {
            return;
        }

        // SAFETY: `main_conf_arr` is nginx's HTTP main_conf array and `ctx_index`
        // is the upstream module's slot within it (in-bounds by construction);
        // the slot holds the `ngx_http_upstream_main_conf_t*`.
        let umcf_ptr = unsafe { *main_conf_arr.add(ctx_index) };
        if umcf_ptr.is_null() {
            return;
        }
        let umcf: *const nginx_sys::ngx_http_upstream_main_conf_t = umcf_ptr.cast();

        // SAFETY: `umcf` is the non-null upstream main conf (checked above), valid
        // in conf-pool memory; reading its `upstreams` array fields is sound.
        let n_upstreams = unsafe { (*umcf).upstreams.nelts };
        // SAFETY: as above — reading `upstreams.elts` and casting it to the element
        // pointer type is sound.
        let up_ptr = unsafe { (*umcf).upstreams.elts.cast::<*mut ngx_http_upstream_srv_conf_t>() };
        for i in 0..n_upstreams {
            // SAFETY: `up_ptr` is the `upstreams.elts` array and `i < n_upstreams =
            // upstreams.nelts`, so `up_ptr.add(i)` is an in-bounds element.
            let uscf: *mut ngx_http_upstream_srv_conf_t = unsafe { *up_ptr.add(i) };
            if uscf.is_null() {
                continue;
            }
            // SAFETY: `uscf` is a non-null upstream-srv-conf pointer (checked) valid
            // in conf-pool memory; reading its `shm_zone` field is sound.
            let shm_zone = unsafe { (*uscf).shm_zone };
            if shm_zone.is_null() {
                continue;
            } // no zone declared
            let zone_ptr = shm_zone as usize;

            // Skip if already registered.
            let mut found = false;
            for j in 0..self.n_upstreams {
                if self.upstream_table[j].shm_zone_ptr == zone_ptr {
                    found = true;
                    break;
                }
            }
            if found {
                continue;
            }
            if self.n_upstreams >= UPSTREAM_CAP {
                break;
            } // over cap

            // SAFETY: `shm_zone` is non-null (checked above) and a valid
            // `ngx_shm_zone_t*` in conf memory; reading its `shm.name` is sound.
            let name = unsafe { (*shm_zone).shm.name }; // ngx_str_t
            let len = name.len.min(UPSTREAM_NAME_MAX);
            let idx = self.n_upstreams;
            self.upstream_table[idx].shm_zone_ptr = zone_ptr;
            self.upstream_table[idx].name_len = len as u8;
            if len > 0 && !name.data.is_null() {
                // SAFETY: `name.data` is non-null (checked) and points to `name.len`
                // valid bytes; `len` is clamped to `name.len`, so the slice is
                // in-bounds.
                let src = unsafe { core::slice::from_raw_parts(name.data, len) };
                self.upstream_table[idx].name[..len].copy_from_slice(src);
            }
            self.n_upstreams += 1;
        }
    }

    /// Effective per-worker log ring capacity in bytes.
    ///
    /// Uses the value from `otel_log_ring_size` if set; otherwise
    /// [`crate::logs::ring::DEFAULT_LOG_RING_CAP`].
    #[inline]
    pub fn log_ring_cap(&self) -> usize {
        if self.log_ring_size > 0 {
            self.log_ring_size
        } else {
            crate::logs::ring::DEFAULT_LOG_RING_CAP
        }
    }

    /// Returns the base address of our WorkerSlots data within the shared memory zone.
    ///
    /// This is `shm.addr + data_offset()` — past the nginx slab-pool header that
    /// `ngx_init_zone_pool` writes at the very start of every shm zone.
    ///
    /// Returns `None` if either:
    /// - `shm_zone` is null (no zone registered — module not configured yet), OR
    /// - `shm_zone.shm.addr` is null (zone declared but not yet mapped — the
    ///   window between `ngx_shared_memory_add` and `ngx_init_zone`).
    pub fn shm_base(&self) -> Option<*mut u8> {
        // SAFETY: `shm_zone` is either null (handled by `as_ref()?`) or the
        // `ngx_shm_zone_t*` from `register_shm_zone`, kept valid by nginx for the
        // cycle; reading `shm.addr` through it is sound.
        let zone = unsafe { self.shm_zone.as_ref()? };
        let addr = zone.shm.addr;
        if addr.is_null() {
            return None;
        }
        // SAFETY: `addr` is the non-null mapped zone start; `data_offset()` bytes
        // (slab-pool header) lie within the zone, so the offset pointer is
        // in-bounds — only formed here, not dereferenced.
        Some(unsafe { addr.cast::<u8>().add(crate::shm::data_offset()) })
    }

    /// Number of worker slots the metrics shm zone was sized for.
    ///
    /// Derived from the zone's registered `shm.size` — works even before workers
    /// fork, and stays valid across reloads because the zone registration is
    /// immutable once `ngx_shared_memory_add` returns.
    ///
    /// Returns 0 when the zone has not been registered yet (`shm_zone` is null).
    ///
    /// Used by per-request slot-index bounds guards to catch the case where
    /// the zone was mistakenly sized for fewer workers than are actually running
    /// (e.g., `worker_processes` appeared after `http{}` and the init_module
    /// fail-fast was somehow bypassed).
    pub fn shm_n_workers(&self) -> usize {
        // SAFETY: `shm_zone` is null or the `ngx_shm_zone_t*` from
        // `register_shm_zone`; reading `shm.size` through it is sound.
        let Some(zone) = (unsafe { self.shm_zone.as_ref() }) else {
            return 0;
        };
        crate::shm::n_workers_from_zone_size(zone.shm.size)
    }

    /// Number of per-worker slots the logs shm zone was sized for, derived from
    /// its registered `shm.size` and the active ring capacity.
    ///
    /// Returns 0 when the logs zone has not been registered (`logs_shm_zone` is
    /// null) — log export disabled, so the logs ring is never indexed.
    ///
    /// Same zero-cost shape as [`shm_n_workers`](Self::shm_n_workers): one
    /// pointer load + integer arithmetic, no alloc/lock/syscall.
    pub fn logs_n_workers(&self) -> usize {
        // SAFETY: `logs_shm_zone` is null (handled by `as_ref()`) or the
        // `ngx_shm_zone_t*` from `register_logs_zone`; reading `shm.size`
        // through it is sound.
        let Some(zone) = (unsafe { self.logs_shm_zone.as_ref() }) else {
            return 0;
        };
        // `shm.size` includes the slab-pool header; subtract it before dividing
        // by the per-worker slot size (matches `logs_zone_size_for`).
        let data_bytes = zone.shm.size.saturating_sub(crate::shm::data_offset());
        let slot = crate::shm::logs_slot_size(self.log_ring_cap());
        data_bytes.checked_div(slot).unwrap_or(0)
    }

    /// Number of per-worker slots the spans shm zone was sized for, derived from
    /// its registered `shm.size` and the span ring capacity.
    ///
    /// Returns 0 when the spans zone has not been registered (`spans_shm_zone`
    /// is null) — tracing disabled, so the spans ring is never indexed.
    ///
    /// Same zero-cost shape as [`shm_n_workers`](Self::shm_n_workers).
    pub fn spans_n_workers(&self) -> usize {
        // SAFETY: `spans_shm_zone` is null (handled by `as_ref()`) or the
        // `ngx_shm_zone_t*` from `register_spans_zone`; reading `shm.size`
        // through it is sound.
        let Some(zone) = (unsafe { self.spans_shm_zone.as_ref() }) else {
            return 0;
        };
        let data_bytes = zone.shm.size.saturating_sub(crate::shm::data_offset());
        let slot = crate::shm::spans_slot_size(crate::shm::DEFAULT_SPAN_RING_CAP);
        data_bytes.checked_div(slot).unwrap_or(0)
    }

    /// Smallest worker-slot capacity across every shm ring the LOG-phase handler
    /// indexes by `worker_id`: the metrics zone plus whichever of the logs and
    /// spans rings are registered.
    ///
    /// The metrics zone can be inflated past the reserved worker count via
    /// `otel_zone_size` (`register_shm_zone` takes `zone_size.max(required)`),
    /// but the logs and spans zones are sized strictly for the reserved worker
    /// count (`n_workers_to_reserve`).  A `worker_id` that fits the inflated
    /// metrics zone could therefore overflow the smaller logs/spans rings.
    /// The hot-path guard validates against this MIN so a `worker_id` that would
    /// overrun the *smallest* indexed ring is rejected before any ring write.
    ///
    /// A zone that is not registered (`*_n_workers()` returns 0) does not
    /// constrain the bound — its ring is never indexed (the per-signal
    /// `logs_shm_base()` / `spans_shm_base()` gates return `None`).
    ///
    /// # Hot-path note
    /// Three pointer loads + integer `min`s; no alloc/lock/syscall.  Callers may
    /// cache the result once per request (it is constant for the worker's life).
    pub fn min_indexed_worker_capacity(&self) -> usize {
        min_indexed_worker_capacity(
            self.shm_n_workers(),
            self.logs_n_workers(),
            self.spans_n_workers(),
        )
    }

    /// Returns a pointer to the `ControlShm` data in the control zone.
    ///
    /// The `ControlShm` struct lives at `data_offset()` bytes past
    /// `shm.addr` (after the slab-pool header nginx writes at zone start).
    ///
    /// Returns `None` if either:
    /// - `control_shm_zone` is null (not registered — module not
    ///   configured, or `otel_exporter` block absent), OR
    /// - `control_shm_zone.shm.addr` is null (declared but not yet
    ///   mapped — window between `ngx_shared_memory_add` and
    ///   `ngx_init_zone`).
    ///
    /// # Hot-path note
    /// Workers call this from `LogPhaseHandler` on every request. The
    /// `None`-returning path (module disabled) is a null pointer check,
    /// which is a single branch — zero allocations, zero syscalls.
    pub fn control_shm_ptr(&self) -> Option<*const crate::exporter::control_shm::ControlShm> {
        // SAFETY: `control_shm_zone` is null (handled by `as_ref()?`) or the
        // `ngx_shm_zone_t*` from `register_control_shm_zone`, valid for the cycle;
        // reading `shm.addr` through it is sound.
        let zone = unsafe { self.control_shm_zone.as_ref()? };
        let addr = zone.shm.addr;
        if addr.is_null() {
            return None;
        }
        let offset = crate::shm::data_offset();
        // SAFETY: `addr` is the non-null mapped zone start; the `ControlShm` lives
        // at `data_offset()` bytes in (past the slab-pool header), so the offset
        // pointer is in-bounds — only formed here, not dereferenced.
        Some(unsafe {
            addr.cast::<u8>().add(offset).cast::<crate::exporter::control_shm::ControlShm>()
        })
    }

    /// Returns a mutable pointer to the `ControlShm` data in the control zone.
    ///
    /// Used exclusively by the exporter process to write the crash-loop backoff
    /// counter (`crash_count`, `window_start_unix`) on startup, and by the
    /// export loop to reset the counter after a healthy WINDOW-length run.
    ///
    /// The `ControlShm` fields are `AtomicU64`, so concurrent reads by workers
    /// (via `control_shm_ptr`) are data-race-free even without the caller
    /// holding any lock.
    ///
    /// Returns `None` when:
    /// - `control_shm_zone` is null (not registered — module not configured), or
    /// - `control_shm_zone.shm.addr` is null (zone not yet mapped by nginx).
    pub(crate) fn control_shm_ptr_mut(
        &self,
    ) -> Option<*mut crate::exporter::control_shm::ControlShm> {
        // SAFETY: same as `control_shm_ptr` — `control_shm_zone` is either null
        // (handled by `as_ref()?`) or the valid zone pointer from
        // `register_control_shm_zone`.
        let zone = unsafe { self.control_shm_zone.as_ref()? };
        let addr = zone.shm.addr;
        if addr.is_null() {
            return None;
        }
        let offset = crate::shm::data_offset();
        // SAFETY: `addr` is non-null and mapped; the pointer is only formed here
        // (not dereferenced); callers must dereference through the `AtomicU64`
        // methods for sound cross-process access.
        Some(unsafe {
            addr.cast::<u8>().add(offset).cast::<crate::exporter::control_shm::ControlShm>()
        })
    }
}

/* ─────────────────────────── inner exporter block ─────────────────────────── */

/// Commands valid inside `otel_exporter { ... }`.
static mut NGX_HTTP_OTEL_EXPORTER_COMMANDS: [ngx_command_t; 9] = [
    ngx_command_t {
        name: ngx_string!("endpoint"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_exporter_set_endpoint),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("trusted_certificate"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_exporter_set_trusted_cert),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    // mTLS client cert directives + server-verify toggle.
    ngx_command_t {
        name: ngx_string!("ssl_certificate"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_exporter_set_ssl_cert),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("ssl_certificate_key"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_exporter_set_ssl_cert_key),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("ssl_verify"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_exporter_set_ssl_verify),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("metrics_endpoint"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_exporter_set_metrics_endpoint),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("logs_endpoint"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_exporter_set_logs_endpoint),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("traces_endpoint"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_exporter_set_traces_endpoint),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t::empty(),
];

extern "C" fn cmd_exporter_set_endpoint(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the directive's conf pointer, which for the
    // `otel_exporter` block was set to `&amcf.exporter` (an `ExporterConfig` in
    // the conf pool); casting and `as_mut` yield a valid exclusive reference.
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };

    if !ecf.endpoint.is_empty() {
        return c"is duplicate".as_ptr().cast_mut();
    }

    // SAFETY: `cf` is the valid non-null parse context nginx passes to a directive
    // handler, and its `args` array holds the parsed directive tokens.
    let args = unsafe { cf_args(cf) };
    ecf.endpoint = args[1];
    NGX_CONF_OK
}

extern "C" fn cmd_exporter_set_trusted_cert(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block's conf pointer, set to
    // `&amcf.exporter` (an `ExporterConfig` in the conf pool); the cast + `as_mut`
    // yield a valid exclusive reference.
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };

    if !ecf.trusted_cert.is_empty() {
        return c"is duplicate".as_ptr().cast_mut();
    }

    // SAFETY: `cf` is the valid non-null directive parse context; its `args` array
    // holds the parsed tokens.
    let args = unsafe { cf_args(cf) };
    ecf.trusted_cert = args[1];
    NGX_CONF_OK
}

/// Handler for `ssl_certificate <path>` inside `otel_exporter {}`.
///
/// Stores the client certificate path for mTLS.  Config-time validation of the
/// cert+key pair is in `MainConfig::post_config`.
extern "C" fn cmd_exporter_set_ssl_cert(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block conf pointer (`ExporterConfig`).
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };
    if !ecf.ssl_cert.is_empty() {
        return c"is duplicate".as_ptr().cast_mut();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    ecf.ssl_cert = args[1];
    NGX_CONF_OK
}

/// Handler for `ssl_certificate_key <path>` inside `otel_exporter {}`.
///
/// Stores the client private key path for mTLS.  Config-time validation of the
/// cert+key pair is in `MainConfig::post_config`.
extern "C" fn cmd_exporter_set_ssl_cert_key(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block conf pointer (`ExporterConfig`).
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };
    if !ecf.ssl_cert_key.is_empty() {
        return c"is duplicate".as_ptr().cast_mut();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    ecf.ssl_cert_key = args[1];
    NGX_CONF_OK
}

/// Handler for `ssl_verify on|off` inside `otel_exporter {}`.
///
/// Default (unset) → `on` (verify peer certificate).
/// `ssl_verify off` is INSECURE; a WARN is emitted at `post_config` time.
extern "C" fn cmd_exporter_set_ssl_verify(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block conf pointer (`ExporterConfig`).
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };
    if ecf.ssl_verify != UNSET_FLAG {
        return c"is duplicate".as_ptr().cast_mut();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    let val = args[1];
    if val.as_bytes() == b"on" {
        ecf.ssl_verify = 1;
    } else if val.as_bytes() == b"off" {
        ecf.ssl_verify = 0;
    } else {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            cf,
            "otel_exporter: ssl_verify: invalid value \"{}\"; expected on or off",
            val
        );
        return c"invalid ssl_verify value".as_ptr().cast_mut();
    }
    NGX_CONF_OK
}

/// Returns `true` when `value` contains a scheme+authority marker (`://`),
/// meaning the per-signal endpoint directive includes a host/port component
/// that would be silently stripped at export time.
///
/// Pure predicate — testable without an nginx config context.
/// Called by `warn_if_has_authority` (below) and its unit test
/// `h2f5_per_signal_endpoint_host_detection`.
pub(crate) fn has_authority(value: &[u8]) -> bool {
    value.windows(3).any(|w| w == b"://")
}

/// Emit a WARN if the per-signal endpoint value includes a scheme or authority
/// (i.e. contains `://`).  Only the path component is used at export time;
/// the host/port from the base `endpoint` directive is preserved.
fn warn_if_has_authority(cf: *mut ngx_conf_t, signal: &str, value: &[u8]) {
    if has_authority(value) {
        ngx_conf_log_error!(
            NGX_LOG_WARN,
            cf,
            "otel export: {}_endpoint contains a host/scheme — only the path \
             component will be used; host/port from the base endpoint directive \
             is preserved (full multi-endpoint support is not yet implemented)",
            signal
        );
    }
}

extern "C" fn cmd_exporter_set_metrics_endpoint(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block conf pointer (an `ExporterConfig`).
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };
    if !ecf.metrics_endpoint.is_empty() {
        return c"is duplicate".as_ptr().cast_mut();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    warn_if_has_authority(cf, "metrics", args[1].as_bytes());
    ecf.metrics_endpoint = args[1];
    NGX_CONF_OK
}

extern "C" fn cmd_exporter_set_logs_endpoint(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block conf pointer (an `ExporterConfig`).
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };
    if !ecf.logs_endpoint.is_empty() {
        return c"is duplicate".as_ptr().cast_mut();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    warn_if_has_authority(cf, "logs", args[1].as_bytes());
    ecf.logs_endpoint = args[1];
    NGX_CONF_OK
}

extern "C" fn cmd_exporter_set_traces_endpoint(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` is the `otel_exporter` block conf pointer (an `ExporterConfig`).
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };
    if !ecf.traces_endpoint.is_empty() {
        return c"is duplicate".as_ptr().cast_mut();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    warn_if_has_authority(cf, "traces", args[1].as_bytes());
    ecf.traces_endpoint = args[1];
    NGX_CONF_OK
}

/// Dispatcher invoked by ngx_conf_parse for each directive inside the
/// `otel_exporter { ... }` block.
extern "C" fn cmd_exporter_block_handler(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _dummy: *mut c_void,
) -> *mut c_char {
    // SAFETY: `cf` is the valid non-null block-parse context; its `args` array
    // holds the inner directive's tokens.
    let args = unsafe { cf_args(cf) };

    // SAFETY: `NGX_HTTP_OTEL_EXPORTER_COMMANDS` is a module-private `static mut`
    // touched only during single-threaded config parsing (no concurrent access),
    // so taking a `&mut` slice of it here is sound.
    let commands = unsafe { &mut NGX_HTTP_OTEL_EXPORTER_COMMANDS[..] };
    for cmd in commands {
        if cmd.name.is_empty() {
            break;
        }
        if args[0] != cmd.name {
            continue;
        }
        let expected = cmd_nargs(cmd);
        if args.len() < expected.0 || args.len() > expected.1 {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "invalid number of arguments in \"{}\" directive",
                args[0]
            );
            return NGX_CONF_ERROR;
        }
        let handler = cmd.set.expect("command handler");
        // SAFETY: `handler` is a valid directive callback fn pointer; `cf` is the
        // valid parse context, and `(*cf).handler_conf` is the block's conf pointer
        // (set by `cmd_set_exporter_block` to `&amcf.exporter`) that the inner
        // handlers expect.
        return unsafe { handler(cf, cmd, (*cf).handler_conf) };
    }

    ngx_conf_log_error!(
        NGX_LOG_EMERG,
        &raw mut *cf,
        "unknown directive \"{}\" in otel_exporter block",
        args[0]
    );
    NGX_CONF_ERROR
}

/* ─────────────────────────── top-level commands ────────────────────────────── */

// Production build: 19 commands + 1 terminator.
// test-support build: 19 commands + otel_status_endpoint + 1 terminator.
// Two separate definitions so the string "otel_status_endpoint" is absent
// from production .so files (verified by grep on objs-release/).

/// Shared production commands.
macro_rules! production_commands {
    () => {
        [
            // otel_exporter { endpoint ...; trusted_certificate ...; }
            ngx_command_t {
                name: ngx_string!("otel_exporter"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_NOARGS | NGX_CONF_BLOCK) as ngx_uint_t,
                set: Some(cmd_set_exporter_block),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_service_name <name>;
            ngx_command_t {
                name: ngx_string!("otel_service_name"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(nginx_sys::ngx_conf_set_str_slot),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: mem::offset_of!(MainConfig, service_name),
                post: ptr::null_mut(),
            },
            // otel_resource_attr <key> <value>;
            ngx_command_t {
                name: ngx_string!("otel_resource_attr"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2) as ngx_uint_t,
                set: Some(cmd_add_resource_attr),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_exporter_header <name> <value>;
            ngx_command_t {
                name: ngx_string!("otel_exporter_header"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2) as ngx_uint_t,
                set: Some(cmd_add_exporter_header),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_metric_interval <duration>;
            ngx_command_t {
                name: ngx_string!("otel_metric_interval"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(cmd_set_metric_interval),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_metric_zone <name> <size>;
            ngx_command_t {
                name: ngx_string!("otel_metric_zone"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2) as ngx_uint_t,
                set: Some(cmd_set_metric_zone),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_metric_status_code_class on | off;
            ngx_command_t {
                name: ngx_string!("otel_metric_status_code_class"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG) as ngx_uint_t,
                set: Some(nginx_sys::ngx_conf_set_flag_slot),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: mem::offset_of!(MainConfig, status_code_class),
                post: ptr::null_mut(),
            },
            // otel_grpc_smoke_endpoint <url>;  TEST-ONLY (unary gRPC harness).
            // Parsed in all builds but only acted on with test-support feature.
            ngx_command_t {
                name: ngx_string!("otel_grpc_smoke_endpoint"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(nginx_sys::ngx_conf_set_str_slot),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: mem::offset_of!(MainConfig, grpc_smoke_endpoint),
                post: ptr::null_mut(),
            },
            // otel_grpc_bidi_smoke_endpoint <url>;  TEST-ONLY (bidi gRPC harness).
            ngx_command_t {
                name: ngx_string!("otel_grpc_bidi_smoke_endpoint"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(nginx_sys::ngx_conf_set_str_slot),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: mem::offset_of!(MainConfig, bidi_smoke_endpoint),
                post: ptr::null_mut(),
            },
            // otel_grpc_bidi_overload_endpoint <url>;  TEST-ONLY (bidi backpressure test).
            ngx_command_t {
                name: ngx_string!("otel_grpc_bidi_overload_endpoint"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(nginx_sys::ngx_conf_set_str_slot),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: mem::offset_of!(MainConfig, bidi_overload_endpoint),
                post: ptr::null_mut(),
            },
            // otel_export_protocol otlp_http | otlp_grpc;
            // Selects the OTLP wire transport.  Default: otlp_http (byte-identical
            // to the pre-existing behaviour when the directive is absent).
            // "arrow" is rejected at parse time with a "not yet implemented" message.
            ngx_command_t {
                name: ngx_string!("otel_export_protocol"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(cmd_set_export_protocol),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_log_ring_size <size>;
            // Per-worker ring capacity in bytes.  Memory = size × 2 × N workers.
            // Default: 512k (DEFAULT_LOG_RING_CAP).  Raise for high-RPS deployments.
            ngx_command_t {
                name: ngx_string!("otel_log_ring_size"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(cmd_set_log_ring_size),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_error_log [<level>];
            // Enables OTel error-log export via a ngx_log_writer_pt writer node.
            // NOARGS ⇒ fixed floor NGX_LOG_ERR (decoupled from core error_log);
            // TAKE1 ⇒ explicit level override.
            // The writer filters messages by severity floor (cheapest filter first),
            // then coalesces repeated messages using a bounded exact-hash table.
            // Context-to-destination matrix:
            //   Worker + shm mapped → coalescer → error verbatim ring → OTLP
            //   Master / config-load / exporter → structural fall-through to core error_log
            // Default: off (not configured).
            ngx_command_t {
                name: ngx_string!("otel_error_log"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(cmd_set_error_log),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_error_log_coalesce on|off;
            // Default: on.  `off` ⇒ bypass the coalescer and push every
            // level-passing line verbatim to the bounded ring.
            //
            // ⚠️ WARNING: `off` is best-effort, NOT guaranteed delivery.
            // The ring drops-newest under load; lost lines are accounted in
            // dropped_records but gone.  The only guaranteed full-fidelity
            // transcript is nginx's own (untouched) error_log file.
            // The companion error-rate metric counts the true total
            // in both modes; only the bodies are potentially lost.
            ngx_command_t {
                name: ngx_string!("otel_error_log_coalesce"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG) as ngx_uint_t,
                set: Some(cmd_set_error_log_coalesce),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_trace <complex-value>;
            // Per-location trace enable/disable.  The complex value allows
            // `split_clients`-based ratio sampling.  Absent ⇒ tracing disabled
            // for this location (zero cost — REWRITE handler exits immediately).
            // Valid in main, server, and location blocks; inner wins on merge.
            ngx_command_t {
                name: ngx_string!("otel_trace"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1)
                    as ngx_uint_t,
                set: Some(cmd_set_otel_trace),
                conf: NGX_HTTP_LOC_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_trace_context ignore|extract|inject|propagate;
            // W3C traceparent propagation mode.  Default: extract (read inbound,
            // do not inject outbound).
            ngx_command_t {
                name: ngx_string!("otel_trace_context"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1)
                    as ngx_uint_t,
                set: Some(cmd_set_otel_trace_context),
                conf: NGX_HTTP_LOC_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_span_name <complex-value>;
            // Per-location span name override.  Absent ⇒ built-in
            // "METHOD route_name" format.
            ngx_command_t {
                name: ngx_string!("otel_span_name"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1)
                    as ngx_uint_t,
                set: Some(cmd_set_otel_span_name),
                conf: NGX_HTTP_LOC_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_span_attr <key> <value>;
            // Add a custom attribute to every span emitted from this location.
            // Multiple directives accumulate; child location wins (no inheritance).
            ngx_command_t {
                name: ngx_string!("otel_span_attr"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2)
                    as ngx_uint_t,
                set: Some(cmd_add_otel_span_attr),
                conf: NGX_HTTP_LOC_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_log_export on | off | if=<cond>;
            // Per-location selection of which requests have an exception-tail
            // log record exported.  Bare or `on` ⇒ export all; `if=<cond>` ⇒
            // export when the complex value is truthy; `off` ⇒ disabled.
            // Absent ⇒ no export (privacy-safe default).  Mirrors core
            // `access_log … if=`.  Valid in main, server, and location blocks;
            // inner wins on merge.
            ngx_command_t {
                name: ngx_string!("otel_log_export"),
                type_: (NGX_HTTP_MAIN_CONF
                    | NGX_HTTP_SRV_CONF
                    | NGX_HTTP_LOC_CONF
                    | NGX_CONF_NOARGS
                    | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(cmd_set_otel_log_export),
                conf: NGX_HTTP_LOC_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
        ]
    };
}

/// Production build: 19 production commands + terminator.
#[cfg(not(any(test, feature = "test-support")))]
pub static mut NGX_HTTP_OTEL_COMMANDS: [ngx_command_t; 20] = {
    let mut cmds = [ngx_command_t::empty(); 20];
    let prod = production_commands!();
    let mut i = 0;
    while i < 19 {
        cmds[i] = prod[i];
        i += 1;
    }
    // cmds[19] stays empty() — terminator
    cmds
};

/// test-support build: 19 production commands + otel_status_endpoint + terminator.
///
/// `otel_status_endpoint;` is a location-level directive (no args) that registers
/// a content handler returning `control_shm.version` as plain text. Used by the
/// heartbeat integration test to read the exporter's liveness counter without
/// process-level introspection. Absent from production builds (verified by grep
/// on `objs-release/ngx_http_otel_module.so`).
#[cfg(any(test, feature = "test-support"))]
pub static mut NGX_HTTP_OTEL_COMMANDS: [ngx_command_t; 21] = {
    let mut cmds = [ngx_command_t::empty(); 21];
    let prod = production_commands!();
    let mut i = 0;
    while i < 19 {
        cmds[i] = prod[i];
        i += 1;
    }
    // Index 19: otel_status_endpoint (test-support only).
    cmds[19] = ngx_command_t {
        name: ngx_string!("otel_status_endpoint"),
        type_: (nginx_sys::NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS) as ngx_uint_t,
        set: Some(cmd_set_otel_status_endpoint),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    };
    // cmds[20] stays empty() — terminator.
    cmds
};

/* ─────────────────────────── command handlers ──────────────────────────────── */

extern "C" fn cmd_set_exporter_block(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: for a MAIN_CONF directive nginx passes the module's `MainConfig`
    // pointer as `conf`; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.exporter.is_set() {
        ngx_conf_log_error!(NGX_LOG_EMERG, &raw mut *cf, "\"otel_exporter\" is duplicate");
        return NGX_CONF_ERROR;
    }

    // SAFETY: `cf` is a valid non-null parse context; `*cf` copies the current
    // `ngx_conf_t` by value to derive a block-scoped parse context.
    let mut block_cf: ngx_conf_t = unsafe { *cf };
    block_cf.handler = Some(cmd_exporter_block_handler);
    block_cf.handler_conf = ptr::addr_of_mut!(amcf.exporter).cast();

    // SAFETY: `block_cf` is a valid in-scope parse context with our block handler
    // installed; `ngx_conf_parse` recurses into the `otel_exporter { ... }` body.
    let rc = unsafe { ngx_conf_parse(&raw mut block_cf, ptr::null_mut()) };
    if !rc.is_null() {
        return rc; // a sub-directive already reported its own error
    }
    // A present `otel_exporter` block must carry an `endpoint`. Silently dropping
    // to zero-cost/disabled mode when the operator clearly intended export is a
    // config error, not a default (nginx idiom: a required sub-directive is
    // mandatory when its block is present).
    if amcf.exporter.endpoint.as_bytes().is_empty() {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &raw mut *cf,
            "\"endpoint\" is mandatory in the \"otel_exporter\" block"
        );
        return NGX_CONF_ERROR;
    }
    NGX_CONF_OK
}

extern "C" fn cmd_add_resource_attr(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };
    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // parsed tokens (TAKE2: name + value).
    let args = unsafe { cf_args(cf) };
    amcf.resource_attrs.push(KvPair { key: args[1], value: args[2] });
    NGX_CONF_OK
}

extern "C" fn cmd_add_exporter_header(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };
    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // parsed tokens (TAKE2: name + value).
    let args = unsafe { cf_args(cf) };
    amcf.exporter_headers.push(KvPair { key: args[1], value: args[2] });
    NGX_CONF_OK
}

extern "C" fn cmd_set_metric_interval(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.metric_interval_ms != UNSET_U64 {
        return c"is duplicate".as_ptr().cast_mut();
    }

    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // parsed tokens (TAKE1: the duration).
    let args = unsafe { cf_args(cf) };
    match parse_duration_ms(args[1].as_bytes()) {
        Some(ms) if ms > 0 => {
            amcf.metric_interval_ms = ms;
            NGX_CONF_OK
        }
        _ => {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "invalid duration in \"otel_metric_interval\": \"{}\"",
                args[1]
            );
            NGX_CONF_ERROR
        }
    }
}

extern "C" fn cmd_set_metric_zone(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.zone_size > 0 {
        return c"is duplicate".as_ptr().cast_mut();
    }

    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // parsed tokens (TAKE2: name + size).
    let args = unsafe { cf_args(cf) };
    // args[1] = name, args[2] = size (e.g. "10m", "1g")
    let size = match parse_size_bytes(args[2].as_bytes()) {
        Some(s) if s > 0 => s,
        _ => {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "invalid size in \"otel_metric_zone\": \"{}\"",
                args[2]
            );
            return NGX_CONF_ERROR;
        }
    };

    amcf.zone_name = args[1];
    amcf.zone_size = size;
    NGX_CONF_OK
}

/// Directive callback for `otel_export_protocol otlp_http | otlp_grpc;`.
///
/// Accepts `otlp_http` and `otlp_grpc`.  Rejects `arrow` with a
/// "not yet implemented" message.  Rejects any other value with
/// an "unknown value" message listing the valid choices.
extern "C" fn cmd_set_export_protocol(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.export_protocol.is_some() {
        return c"is duplicate".as_ptr().cast_mut();
    }

    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // parsed tokens (TAKE1: the protocol name).
    let args = unsafe { cf_args(cf) };
    let value = args[1].as_bytes();

    if value == b"otlp_http" {
        amcf.export_protocol = Some(ExportProtocol::OtlpHttp);
        NGX_CONF_OK
    } else if value == b"otlp_grpc" {
        amcf.export_protocol = Some(ExportProtocol::OtlpGrpc);
        NGX_CONF_OK
    } else if value == b"arrow" {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &raw mut *cf,
            "otel_export_protocol: \"arrow\" is not yet implemented"
        );
        NGX_CONF_ERROR
    } else {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &raw mut *cf,
            "otel_export_protocol: unknown value \"{}\"; valid values: otlp_http, otlp_grpc",
            args[1]
        );
        NGX_CONF_ERROR
    }
}

/// Directive callback for `otel_log_ring_size <size>;`.
///
/// Parses a size value (e.g. `"512k"`, `"1m"`) using `parse_size_bytes` and
/// stores the result in `MainConfig::log_ring_size`.
extern "C" fn cmd_set_log_ring_size(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.log_ring_size > 0 {
        return c"is duplicate".as_ptr().cast_mut();
    }

    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // parsed tokens (TAKE1: the size).
    let args = unsafe { cf_args(cf) };
    let raw = args[1].as_bytes();

    match parse_size_bytes(raw) {
        Some(n) if n > 0 => {
            // `LogsWorkerRingHeader` holds four `AtomicU64` fields (align = 8).
            // `CoalesceSlot` holds an `AtomicU64` at offset 0 (align = 8).
            // The error-ring header starts at slot_base + ring_size_bytes(cap) and
            // the coalescer table starts at slot_base + 2 * ring_size_bytes(cap).
            // For both to be 8-byte aligned, cap must be a multiple of 8.
            // Round up to the next multiple of 8; use checked arithmetic to avoid
            // a panic on values near usize::MAX (e.g. usize::MAX - 3 would overflow).
            let Some(aligned) = align_ring_size(n) else {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &raw mut *cf,
                    "otel_log_ring_size: invalid size (use e.g. \"512k\" or \"1m\")"
                );
                return NGX_CONF_ERROR;
            };
            if aligned != n {
                ngx_conf_log_error!(
                    NGX_LOG_WARN,
                    &raw mut *cf,
                    "otel_log_ring_size: {} rounded up to {} (must be a multiple of 8 for AtomicU64 alignment in shm)",
                    n,
                    aligned
                );
            }
            amcf.log_ring_size = aligned;
            NGX_CONF_OK
        }
        _ => {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_log_ring_size: invalid size (use e.g. \"512k\" or \"1m\")"
            );
            NGX_CONF_ERROR
        }
    }
}

/// Directive callback for `otel_error_log [<level>];`.
///
/// Inserts a writer-only `ngx_log_t` node into `cycle->new_log` via
/// `otel_log_insert`.  The node calls `ngx_otel_error_writer` for every error
/// that passes the severity floor.
///
/// - **NOARGS** (bare `otel_error_log;`) — fixed default floor `NGX_LOG_ERR`
///   (error severity = 4).  Intentionally decoupled from the core `error_log`
///   level: mirroring couples the OTel floor to on-box debug verbosity and the
///   parse-time read of `cycle->new_log` is directive-order dependent.
/// - **TAKE1** (e.g. `otel_error_log warn;`) — explicit level override.
///   Accepted values: `emerg`, `alert`, `crit`, `error`, `warn`, `notice`,
///   `info`, `debug`.
///
/// Errors on duplicate directive.
extern "C" fn cmd_set_error_log(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.error_log_enabled {
        ngx_conf_log_error!(NGX_LOG_EMERG, &raw mut *cf, "\"otel_error_log\" is duplicate");
        return NGX_CONF_ERROR;
    }

    // SAFETY: `cf` is the valid non-null parse context. `cf_args(cf)` reads the
    // parsed tokens, and the inner `ngx_conf_log_error!` uses the same valid `cf`.
    let level_floor: ngx_uint_t = unsafe {
        let args = cf_args(cf);
        if args.len() > 1 {
            // TAKE1: parse the explicit level argument.
            let level_str = args[1].as_bytes();
            match parse_error_log_level(level_str) {
                Some(l) => l,
                None => {
                    ngx_conf_log_error!(
                        NGX_LOG_EMERG,
                        &raw mut *cf,
                        "otel_error_log: unknown level; use emerg|alert|crit|error|warn|notice|info|debug"
                    );
                    return NGX_CONF_ERROR;
                }
            }
        } else {
            // NOARGS: fixed default floor = NGX_LOG_ERR (error severity).
            // This is intentionally DECOUPLED from the core `error_log` level:
            // mirroring couples the OTel floor to on-box debug verbosity
            // (against orthogonality) and a parse-time read of cycle->new_log
            // is directive-order dependent.
            nginx_sys::NGX_LOG_ERR as ngx_uint_t
        }
    };

    // Allocate the ngx_log_t node and OtelErrorWriterState from the config pool.
    // ngx_pcalloc zero-initialises both — AtomicBool(false), null ptr, 0 level
    // are the correct "unset" defaults.
    // SAFETY: `cf` is the valid non-null parse context; `cf.pool` is nginx's conf
    // pool (null-checked below). `ngx_pcalloc` returns zeroed, suitably-aligned
    // memory of the requested size for `ngx_log_t` / `OtelErrorWriterState`, and
    // the `ngx_conf_log_error!` calls use the same valid `cf`.
    let (new_log, state) = unsafe {
        let pool = (*cf).pool;
        if pool.is_null() {
            ngx_conf_log_error!(NGX_LOG_EMERG, &raw mut *cf, "otel_error_log: null pool");
            return NGX_CONF_ERROR;
        }
        let log_ptr = nginx_sys::ngx_pcalloc(pool, mem::size_of::<nginx_sys::ngx_log_t>())
            as *mut nginx_sys::ngx_log_t;
        if log_ptr.is_null() {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_error_log: ngx_pcalloc failed for log node"
            );
            return NGX_CONF_ERROR;
        }
        let state_ptr = nginx_sys::ngx_pcalloc(pool, mem::size_of::<OtelErrorWriterState>())
            as *mut OtelErrorWriterState;
        if state_ptr.is_null() {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_error_log: ngx_pcalloc failed for writer state"
            );
            return NGX_CONF_ERROR;
        }
        (log_ptr, state_ptr)
    };

    // Fill the log node.  Writer-only: no `file` set (so this node never writes
    // to any file; the core file node still writes via chain continuation).
    // SAFETY: `new_log` and `state` are the non-null, zeroed pool allocations from
    // the block above; writing their fields is sound and they outlive the cycle
    // (conf-pool lifetime).
    unsafe {
        (*new_log).log_level = level_floor;
        (*new_log).writer = Some(ngx_otel_error_writer);
        (*new_log).wdata = state as *mut core::ffi::c_void;
        // Fill the state (pcalloc gave us zeros; only non-zero fields needed).
        (*state).level_floor = level_floor;
        // busy, cleanup, logs_zone, coalesce_table stay zero/null — correct defaults.
        // coalesce_enabled is false until init_process sets it from
        // MainConfig::error_log_coalesce; the coalescer path is gated on
        // coalesce_table != null anyway, so false here is harmless.
    }

    // Insert into cycle->new_log chain (sorted descending by log_level).
    // cycle->new_log is an embedded ngx_log_t value (never null); confirmed:
    // ngx_cycle.h:43-44: `ngx_log_t *log; ngx_log_t new_log;` — `new_log` is a value.
    // SAFETY: `cf` is valid; `cf.cycle` is the live cycle and `new_log` (per
    // ngx_cycle.h) is an embedded `ngx_log_t` value, so `&mut (*cycle).new_log` is
    // a valid chain head for `otel_log_insert`; `new_log` is our valid pool node.
    unsafe {
        let cycle = (*cf).cycle;
        otel_log_insert(ptr::addr_of_mut!((*cycle).new_log), new_log);
    }

    amcf.error_log_enabled = true;
    amcf.error_log_level = level_floor;

    NGX_CONF_OK
}

/// Directive callback for `otel_error_log_coalesce on|off;`.
///
/// Sets `amcf.error_log_coalesce`.  The standard nginx flag handler
/// (`ngx_conf_set_flag_slot`) is not used here because `error_log_coalesce`
/// is a plain Rust `bool`, not a `ngx_flag_t` (`intptr_t`).
extern "C" fn cmd_set_error_log_coalesce(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: nginx passes the module's `MainConfig` pointer as `conf` for this
    // MAIN_CONF directive; the cast + `as_mut` yield a valid exclusive reference.
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };
    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // parsed tokens (FLAG: on|off).
    let args = unsafe { cf_args(cf) };
    let val = args[1].as_bytes();
    match val {
        b"on" => amcf.error_log_coalesce = true,
        b"off" => amcf.error_log_coalesce = false,
        _ => {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_error_log_coalesce: invalid value; use on or off"
            );
            return NGX_CONF_ERROR;
        }
    }
    NGX_CONF_OK
}

/// Directive callback for `otel_status_endpoint;` (location-level, no args).
///
/// Sets the content handler for the location to
/// [`crate::otel_status_content_handler`], which returns the current
/// `control_shm.version` as plain text. Used by the heartbeat
/// integration test to read the exporter liveness counter.
///
/// **Only compiled in test-support builds. The string "otel_status_endpoint"
/// does NOT appear in production `.so` files.**
#[cfg(any(test, feature = "test-support"))]
extern "C" fn cmd_set_otel_status_endpoint(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _conf: *mut c_void,
) -> *mut c_char {
    use ngx::http::{HttpModuleLocationConf, NgxHttpCoreModule};

    // SAFETY: `cf` is the valid non-null directive parse context nginx passes to
    // a LOC_CONF handler; `&*cf` is a sound shared borrow.
    let cf_ref = unsafe { &*cf };
    let clcf = match NgxHttpCoreModule::location_conf_mut(cf_ref) {
        Some(c) => c,
        None => {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_status_endpoint: failed to get core location conf"
            );
            return NGX_CONF_ERROR;
        }
    };
    clcf.handler = Some(crate::otel_status_content_handler);
    NGX_CONF_OK
}

/* ────────────────────────── trace directive handlers ───────────────────────── */

/// Compile a directive argument into a `ngx_http_complex_value_t` on the conf pool.
///
/// Allocates `ngx_http_complex_value_t` via `ngx_pcalloc`, fills
/// `ngx_http_compile_complex_value_t`, and calls `ngx_http_compile_complex_value`.
///
/// Returns the allocated pointer on success, `null_mut()` on allocation or
/// compilation failure (caller must log and return `NGX_CONF_ERROR`).
///
/// # Safety
/// `cf` must be a valid non-null `ngx_conf_t` parse context.
/// `value` must point to the directive's `ngx_str_t` argument for the duration
/// of the call; `ngx_http_compile_complex_value` may modify it temporarily.
unsafe fn compile_complex_value(
    cf: *mut ngx_conf_t,
    value: *mut ngx_str_t,
) -> *mut ngx_http_complex_value_t {
    // Allocate a zeroed complex value on the nginx conf pool.
    // SAFETY: `cf` is a valid non-null parse context; `(*cf).pool` is the live
    // conf pool nginx manages for config-parse time allocations.
    let cv_ptr =
        unsafe { nginx_sys::ngx_pcalloc((*cf).pool, mem::size_of::<ngx_http_complex_value_t>()) }
            as *mut ngx_http_complex_value_t;
    if cv_ptr.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `mem::zeroed()` is valid for `ngx_http_compile_complex_value_t`
    // because it is a `#[repr(C)]` POD struct (all-zero is a valid starting state
    // before filling the mandatory fields below).
    let mut ccv: ngx_http_compile_complex_value_t = unsafe { mem::zeroed() };
    ccv.cf = cf;
    ccv.value = value;
    ccv.complex_value = cv_ptr;
    // zero, conf_prefix, root_prefix bitfields stay 0 — no special prefix handling.
    // SAFETY: `ccv` is fully initialised; `ngx_http_compile_complex_value` reads
    // the `value` ngx_str_t (possibly modifying it temporarily) and writes into
    // `complex_value` (our pool allocation, valid for the conf lifetime).
    let rc = unsafe { nginx_sys::ngx_http_compile_complex_value(&raw mut ccv) };
    if rc != nginx_sys::NGX_OK as nginx_sys::ngx_int_t {
        return ptr::null_mut();
    }
    cv_ptr
}

/// Directive callback for `otel_trace <complex-value>;`.
///
/// The complex value is evaluated at request time: truthy (non-empty, not `"0"`,
/// not `"off"`) ⇒ tracing enabled; falsy ⇒ disabled.  Absence of the directive
/// leaves `otel_trace` null — zero-cost, no REWRITE handler work.
extern "C" fn cmd_set_otel_trace(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    use crate::metric_source::location_conf::LocationConf;

    // SAFETY: nginx passes our module's `LocationConf*` as `conf` for a
    // `NGX_HTTP_LOC_CONF_OFFSET` directive; the cast + `as_mut` yield a valid
    // exclusive reference.
    let lcf = unsafe { conf.cast::<LocationConf>().as_mut().expect("location config") };
    if !lcf.otel_trace.is_null() {
        return c"is duplicate".as_ptr().cast_mut();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    let mut value = args[1]; // ngx_str_t is Copy — we need a mutable local for ccv.value
                             // SAFETY: `cf` is valid; `value` is a local ngx_str_t holding the directive arg.
    let cv = unsafe { compile_complex_value(cf, &raw mut value) };
    if cv.is_null() {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &raw mut *cf,
            "otel_trace: failed to compile complex value expression"
        );
        return NGX_CONF_ERROR;
    }
    lcf.otel_trace = cv;
    NGX_CONF_OK
}

/// Directive callback for `otel_log_export on | off | if=<cond>;`.
///
/// Selects which requests have an exception-tail log record exported, mirroring
/// core `access_log … if=`:
/// - bare `otel_log_export;` or `otel_log_export on;` → export all requests.
/// - `otel_log_export off;` → disabled (overrides an inherited selection).
/// - `otel_log_export if=<cond>;` → export when `<cond>` is truthy at request
///   time (the remainder after `if=` is compiled as a complex value).
///
/// Setting any selecting form (`on`/bare/`if=`) flips the main-conf
/// `any_log_export` flag so the logs shm zone is allocated.  `off` does not.
extern "C" fn cmd_set_otel_log_export(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    use crate::metric_source::location_conf::{LocationConf, LogExportMode};

    // SAFETY: nginx passes our module's `LocationConf*` as `conf` for a
    // `NGX_HTTP_LOC_CONF_OFFSET` directive; the cast + `as_mut` yield a valid
    // exclusive reference.
    let lcf = unsafe { conf.cast::<LocationConf>().as_mut().expect("location config") };
    if lcf.log_export_is_set() {
        return c"is duplicate".as_ptr().cast_mut();
    }

    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };

    // args[0] is the directive name; args[1] (if present) is the single param.
    let mode = if args.len() < 2 {
        // Bare `otel_log_export;` → export all.
        LogExportMode::All
    } else {
        let param = args[1].as_bytes();
        if param == b"on" {
            LogExportMode::All
        } else if param == b"off" {
            LogExportMode::Off
        } else if param.len() >= 3 && &param[..3] == b"if=" {
            // Compile the remainder after `if=` as a complex value.
            let cond = &param[3..];
            let mut cond_str = ngx_str_t { len: cond.len(), data: cond.as_ptr().cast_mut() };
            // SAFETY: `cf` is valid; `cond_str` borrows the directive arg bytes,
            // which nginx keeps valid for the duration of the parse (and the
            // compiled complex value copies the script into pool memory).
            let cv = unsafe { compile_complex_value(cf, &raw mut cond_str) };
            if cv.is_null() {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &raw mut *cf,
                    "otel_log_export: failed to compile \"if=\" condition"
                );
                return NGX_CONF_ERROR;
            }
            lcf.log_export_cv = cv;
            LogExportMode::If
        } else {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_log_export: invalid parameter; expected on | off | if=<cond>"
            );
            return NGX_CONF_ERROR;
        }
    };

    lcf.set_log_export_mode(mode);

    // Flip the main-conf flag for selecting forms so the logs shm zone is
    // allocated.  Parse-time is correct: directive callbacks run before
    // postconfiguration, which reads the flag for the allocation decision.
    if matches!(mode, LogExportMode::All | LogExportMode::If) {
        // SAFETY: `cf` is a valid non-null parse context; the shared borrow is
        // sound for reading the module main conf.
        let cf_ref = unsafe { &*cf };
        if let Some(amcf) = HttpOtelModule::main_conf_mut(cf_ref) {
            amcf.any_log_export = true;
        }
    }

    NGX_CONF_OK
}

/// Directive callback for `otel_trace_context ignore|extract|inject|propagate;`.
extern "C" fn cmd_set_otel_trace_context(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    use crate::metric_source::location_conf::{LocationConf, TraceContextMode};

    // SAFETY: nginx passes our `LocationConf*` as `conf`; the cast is valid.
    let lcf = unsafe { conf.cast::<LocationConf>().as_mut().expect("location config") };
    if lcf.trace_context_is_set() {
        return c"is duplicate".as_ptr().cast_mut();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    let mode = match args[1].as_bytes() {
        b"ignore" => TraceContextMode::Ignore,
        b"extract" => TraceContextMode::Extract,
        b"inject" => TraceContextMode::Inject,
        b"propagate" => TraceContextMode::Propagate,
        _ => {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &raw mut *cf,
                "otel_trace_context: unknown value \"{}\"; valid: ignore, extract, inject, propagate",
                args[1]
            );
            return NGX_CONF_ERROR;
        }
    };
    lcf.set_trace_context(mode);
    NGX_CONF_OK
}

/// Directive callback for `otel_span_name <complex-value>;`.
///
/// Per-location span name override.  The complex value is evaluated at request
/// time.  Absent ⇒ built-in `"METHOD route_name"` format.
extern "C" fn cmd_set_otel_span_name(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    use crate::metric_source::location_conf::LocationConf;

    // SAFETY: nginx passes our `LocationConf*` as `conf`; the cast is valid.
    let lcf = unsafe { conf.cast::<LocationConf>().as_mut().expect("location config") };
    if !lcf.span_name_cv.is_null() {
        return c"is duplicate".as_ptr().cast_mut();
    }
    // SAFETY: `cf` is the valid non-null directive parse context.
    let args = unsafe { cf_args(cf) };
    let mut value = args[1]; // ngx_str_t is Copy
                             // SAFETY: `cf` is valid; `value` is a local ngx_str_t copy of the directive arg.
    let cv = unsafe { compile_complex_value(cf, &raw mut value) };
    if cv.is_null() {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &raw mut *cf,
            "otel_span_name: failed to compile complex value expression"
        );
        return NGX_CONF_ERROR;
    }
    lcf.span_name_cv = cv;
    NGX_CONF_OK
}

/// Directive callback for `otel_span_attr <key> <value>;`.
///
/// Appends a static key/value pair to this location's span attribute list.
/// Multiple directives accumulate; child locations define their own independent
/// set (no inheritance from parent — mirrors the C++ `addSpanAttr` behaviour).
extern "C" fn cmd_add_otel_span_attr(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    use crate::metric_source::location_conf::LocationConf;

    // SAFETY: nginx passes our `LocationConf*` as `conf`; the cast is valid.
    let lcf = unsafe { conf.cast::<LocationConf>().as_mut().expect("location config") };
    // SAFETY: `cf` is the valid non-null directive parse context; `args` holds the
    // TAKE2 tokens: name=args[1], value=args[2].
    let args = unsafe { cf_args(cf) };
    lcf.span_attrs.push((args[1], args[2]));
    NGX_CONF_OK
}

/* ─────────────────────────── helpers ───────────────────────────────────────── */

/// Returns `(min_args, max_args)` expected (including the directive name itself).
fn cmd_nargs(cmd: &ngx_command_t) -> (usize, usize) {
    let t = cmd.type_ as u64;
    if t & (NGX_CONF_NOARGS as u64) != 0 {
        return (1, 1);
    }
    if t & (NGX_CONF_TAKE1 as u64) != 0 {
        return (2, 2);
    }
    if t & (NGX_CONF_TAKE2 as u64) != 0 {
        return (3, 3);
    }
    if t & (NGX_CONF_FLAG as u64) != 0 {
        return (2, 2);
    }
    (1, usize::MAX)
}

/// Parse duration strings like `10s`, `5m`, `2h`, `1d` → milliseconds.
fn parse_duration_ms(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let (num_bytes, suffix) = match s.last() {
        Some(b's') => (&s[..s.len() - 1], 1_000u64),
        Some(b'm') => (&s[..s.len() - 1], 60_000u64),
        Some(b'h') => (&s[..s.len() - 1], 3_600_000u64),
        Some(b'd') => (&s[..s.len() - 1], 86_400_000u64),
        _ => (s, 1_000u64), // bare number treated as seconds
    };
    let n = parse_u64_ascii(num_bytes)?;
    n.checked_mul(suffix)
}

/// Parse a size string like `1024`, `10k`, `5m`, `2g` → bytes.
fn parse_size_bytes(s: &[u8]) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let (num_bytes, mult) = match s.last() {
        Some(&c) if c.is_ascii_alphabetic() => {
            let m = match c.to_ascii_lowercase() {
                b'k' => 1024usize,
                b'm' => 1024 * 1024,
                b'g' => 1024 * 1024 * 1024,
                _ => return None,
            };
            (&s[..s.len() - 1], m)
        }
        _ => (s, 1usize),
    };
    let n = parse_u64_ascii(num_bytes)?;
    // Use `try_from` to avoid silent truncation on 32-bit targets where
    // `n as usize` would silently discard the high 32 bits for values > u32::MAX,
    // producing a wrong (smaller) size without an error.
    let n_usize = usize::try_from(n).ok()?;
    n_usize.checked_mul(mult)
}

/// Round `n` up to the nearest multiple of 8, returning `None` if the result
/// would overflow `usize`.
///
/// The log-ring-size directive stores three contiguous sections in shared
/// memory at offsets that are multiples of `ring_size_bytes(cap)`; for
/// `AtomicU64` alignment at each boundary `cap` must be a multiple of 8.
/// Values near `usize::MAX` where rounding up would overflow are rejected
/// here so the caller can surface an error rather than panic.
fn align_ring_size(n: usize) -> Option<usize> {
    n.checked_next_multiple_of(8)
}

/// Parse a decimal ASCII string → u64.
fn parse_u64_ascii(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The LOG-phase `worker_id` guard must validate against the MIN of every
    /// shm ring it indexes (metrics zone + logs + spans), not just the metrics
    /// zone.  `otel_zone_size` can inflate the metrics zone beyond the reserved
    /// worker count, while the logs/spans zones are sized strictly for it, so a
    /// `worker_id` that fits the inflated metrics zone could still overrun the
    /// smaller logs/spans rings.
    ///
    /// Mutation: revert `min_indexed_worker_capacity` to return the metrics
    /// capacity (e.g. `metrics`) and this test fails — the smaller logs/spans
    /// capacities no longer tighten the bound, so a `worker_id` past them is
    /// wrongly accepted.
    #[test]
    fn min_indexed_worker_capacity_uses_smallest_ring() {
        // Metrics zone inflated to 8 workers; logs ring sized for 2; spans for 4.
        let metrics = 8;
        let logs = 2;
        let spans = 4;
        let cap = min_indexed_worker_capacity(metrics, logs, spans);
        assert_eq!(cap, 2, "guard must use the smallest indexed ring capacity");

        // worker_id = 3 fits the metrics zone (3 < 8) but overruns the logs ring
        // (3 >= 2): the OLD metrics-only guard would ACCEPT it, the new guard
        // REJECTS it.
        assert!(3 >= cap, "worker_id within metrics zone but past logs ring must be rejected");
        // worker_id = 1 fits every ring and is accepted.
        assert!(1 < cap, "worker_id within the smallest ring must be accepted");

        // A zone that is not registered (capacity 0) must NOT constrain the
        // bound — its ring is never indexed.
        assert_eq!(
            min_indexed_worker_capacity(8, 0, 0),
            8,
            "unregistered logs/spans (cap 0) must not tighten the bound"
        );
        assert_eq!(
            min_indexed_worker_capacity(8, 0, 3),
            3,
            "only registered rings constrain the bound"
        );
    }

    #[test]
    fn test_parse_duration_ms() {
        assert_eq!(parse_duration_ms(b"10s"), Some(10_000));
        assert_eq!(parse_duration_ms(b"5m"), Some(300_000));
        assert_eq!(parse_duration_ms(b"2h"), Some(7_200_000));
        assert_eq!(parse_duration_ms(b"1d"), Some(86_400_000));
        assert_eq!(parse_duration_ms(b"0s"), Some(0));
        assert_eq!(parse_duration_ms(b""), None);
        assert_eq!(parse_duration_ms(b"abc"), None);
    }

    #[test]
    fn test_parse_size_bytes() {
        assert_eq!(parse_size_bytes(b"1024"), Some(1024));
        assert_eq!(parse_size_bytes(b"10k"), Some(10 * 1024));
        assert_eq!(parse_size_bytes(b"5m"), Some(5 * 1024 * 1024));
        assert_eq!(parse_size_bytes(b"2g"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size_bytes(b""), None);
    }

    #[test]
    fn test_default_config() {
        let cfg = MainConfig::default();
        assert!(!cfg.is_configured());
        assert_eq!(cfg.interval_ms(), DEFAULT_INTERVAL_MS);
        assert!(cfg.status_code_class_enabled()); // UNSET treated as on
                                                  // log export is off by default (privacy-safe)
        assert!(!cfg.any_log_export_enabled(), "log export must default to off");
        // error-log export is off by default
        assert!(!cfg.error_log_enabled, "error_log_enabled must default to false");
        assert!(cfg.error_log_coalesce, "error_log_coalesce must default to true (on)");
    }

    /// Verify that `error_log_level` defaults to `NGX_LOG_ERR` (fixed floor,
    /// decoupled from core `error_log`).  The NOARGS directive handler sets the
    /// same constant; the "does not mirror" property is proven by the Stage E
    /// integration test in `run_error_log.sh` (bare `otel_error_log;` with core
    /// `error_log notice` — below-ERR messages do NOT appear in LOGS_LOG).
    #[test]
    fn error_log_default_floor_is_ngx_log_err() {
        let cfg = MainConfig::default();
        assert_eq!(
            cfg.error_log_level,
            nginx_sys::NGX_LOG_ERR as ngx_uint_t,
            "error_log_level default must be NGX_LOG_ERR (4), not mirrored from core log"
        );
        // Explicitly check the numeric value matches nginx's documented constant.
        // NGX_LOG_ERR = 4; lower = more severe (emerg=1 … debug=8).
        assert_eq!(nginx_sys::NGX_LOG_ERR, 4, "sanity: NGX_LOG_ERR must equal 4");
    }

    /// Verify that setting `error_log_enabled` and `error_log_coalesce` toggles
    /// the fields correctly.  The directive handler (`cmd_set_error_log`) is
    /// exercised by integration tests that use a real nginx.conf.
    #[test]
    fn error_log_directive_toggles_enablement() {
        let mut cfg = MainConfig::default();
        assert!(!cfg.error_log_enabled);
        assert!(cfg.error_log_coalesce); // default on
                                         // Simulate cmd_set_error_log TAKE1 setting an explicit level.
        cfg.error_log_enabled = true;
        cfg.error_log_level = nginx_sys::NGX_LOG_WARN as ngx_uint_t;
        assert!(cfg.error_log_enabled);
        assert_eq!(cfg.error_log_level, nginx_sys::NGX_LOG_WARN as ngx_uint_t);
        // Simulate otel_error_log_coalesce off.
        cfg.error_log_coalesce = false;
        assert!(!cfg.error_log_coalesce);
        cfg.error_log_coalesce = true;
        assert!(cfg.error_log_coalesce);
    }

    /// Route index lookup returns the correct index for registered locations
    /// and ROUTE_CAP ("other") for unregistered ones.
    ///
    /// Two different URIs hitting the same location → same clcf* → same
    /// route_idx (this is the core invariant tested here in unit-test form).
    #[test]
    fn route_is_location_name_not_uri() {
        let mut cfg = MainConfig::default();

        // No routes registered → all clcf* map to ROUTE_CAP ("other").
        assert_eq!(cfg.route_idx_for_clcf(0x1000), ROUTE_CAP, "unregistered → other");
        assert_eq!(cfg.route_idx_for_clcf(0), ROUTE_CAP, "null → other");

        // Register a fake clcf* → gets index 0.
        cfg.route_table[0].clcf_ptr = 0x1000;
        cfg.route_table[0].name_len = 4;
        cfg.route_table[0].name[..4].copy_from_slice(b"/api");
        cfg.n_routes = 1;

        // Same clcf* value from two different URIs → same route_idx (0).
        let uri1_clcf = 0x1000usize; // e.g. GET /api/users
        let uri2_clcf = 0x1000usize; // e.g. GET /api/products
        assert_eq!(cfg.route_idx_for_clcf(uri1_clcf), 0, "/api/users → route_idx 0");
        assert_eq!(
            cfg.route_idx_for_clcf(uri2_clcf),
            0,
            "/api/products → route_idx 0 (same location)"
        );

        // A different clcf* (different location block) → "other".
        let other_clcf = 0x2000usize;
        assert_eq!(cfg.route_idx_for_clcf(other_clcf), ROUTE_CAP, "different location → other");

        // Register a second route.
        cfg.route_table[1].clcf_ptr = 0x2000;
        cfg.route_table[1].name_len = 8;
        cfg.route_table[1].name[..8].copy_from_slice(b"/health/");
        cfg.n_routes = 2;
        assert_eq!(cfg.route_idx_for_clcf(0x2000), 1, "/health/ registered at idx 1");

        // Over-cap routes map to ROUTE_CAP.
        let mut full_cfg = MainConfig::default();
        for i in 0..ROUTE_CAP {
            full_cfg.route_table[i].clcf_ptr = 0x1000 + i * 0x100;
            full_cfg.n_routes += 1;
        }
        let over_cap_clcf = 0x9999usize;
        assert_eq!(full_cfg.route_idx_for_clcf(over_cap_clcf), ROUTE_CAP, "over-cap → other");
    }

    /// Upstream index: no-upstream and over-cap both return UPSTREAM_IDX_OTHER.
    /// No "(none)" slot — requests without upstream skip the upstream histogram.
    #[test]
    fn upstream_idx_matches_registered_zones() {
        let mut cfg = MainConfig::default();

        // No upstream (zone_ptr = 0) → UPSTREAM_IDX_OTHER (hot path will skip bump).
        assert_eq!(cfg.upstream_idx_for_zone(0), UPSTREAM_IDX_OTHER);
        // Unregistered zone → UPSTREAM_IDX_OTHER.
        assert_eq!(cfg.upstream_idx_for_zone(0x5000), UPSTREAM_IDX_OTHER);

        // Register a zone.
        cfg.upstream_table[0].shm_zone_ptr = 0x5000;
        cfg.upstream_table[0].name_len = 7;
        cfg.upstream_table[0].name[..7].copy_from_slice(b"backend");
        cfg.n_upstreams = 1;
        assert_eq!(cfg.upstream_idx_for_zone(0x5000), 0);
        assert_eq!(cfg.upstream_idx_for_zone(0), UPSTREAM_IDX_OTHER, "no upstream → other (skip)");
        assert_eq!(cfg.upstream_idx_for_zone(0x6000), UPSTREAM_IDX_OTHER, "unregistered → other");
    }

    /// Zero-cost-when-disabled invariant: the boolean gate relied upon by both
    /// the log-phase handler and the export-task spawner.
    ///
    /// - No exporter endpoint → `is_configured()` must return `false` so that
    ///   neither the phase handler is registered nor the export task is spawned.
    /// - Exporter endpoint set → `is_configured()` must return `true` so that
    ///   the operational path is enabled.
    #[test]
    fn test_is_configured_invariant() {
        // Unconfigured: no exporter block → gate must be closed.
        let unconfigured = MainConfig::default();
        assert!(
            !unconfigured.is_configured(),
            "is_configured() must be false when no otel_exporter endpoint is set \
             (zero-cost-when-disabled invariant)"
        );

        // Configured: exporter endpoint present → gate must be open.
        let mut configured = MainConfig::default();
        // Build a static byte slice for the endpoint string so the ngx_str_t
        // points at valid memory for the duration of the test.
        let endpoint_bytes: &'static [u8] = b"http://127.0.0.1:4318/v1/metrics";
        configured.exporter.endpoint = nginx_sys::ngx_str_t {
            len: endpoint_bytes.len(),
            data: endpoint_bytes.as_ptr().cast_mut(),
        };
        assert!(
            configured.is_configured(),
            "is_configured() must be true when otel_exporter endpoint is set"
        );
    }

    // ── DNS resolver wiring (transport DNS/dual-stack) ───────────────────────

    /// `endpoint_needs_resolver` correctly classifies every endpoint form.
    ///
    /// Literal IPv4, literal IPv6 (bracket notation), and unix: sockets must
    /// return `false` — no resolver needed.  DNS names must return `true`.
    #[test]
    fn endpoint_needs_resolver_classifies_correctly() {
        // Literal IPv4 — no resolver.
        assert!(
            !MainConfig::endpoint_needs_resolver("http://127.0.0.1:4317/v1/metrics"),
            "literal IPv4 must not need resolver"
        );
        assert!(
            !MainConfig::endpoint_needs_resolver("http://10.0.0.1/v1/metrics"),
            "literal IPv4 (no port) must not need resolver"
        );
        // Literal IPv6 in bracket notation — no resolver.
        assert!(
            !MainConfig::endpoint_needs_resolver("http://[::1]:4317/v1/metrics"),
            "literal IPv6 [::1] must not need resolver"
        );
        assert!(
            !MainConfig::endpoint_needs_resolver("http://[2001:db8::1]:4317/"),
            "literal IPv6 global address must not need resolver"
        );
        // unix: socket — no resolver.
        assert!(
            !MainConfig::endpoint_needs_resolver("unix:/var/run/otel.sock"),
            "unix: socket must not need resolver"
        );
        assert!(
            !MainConfig::endpoint_needs_resolver("unix:///var/run/otel.sock"),
            "unix:/// socket must not need resolver"
        );
        // DNS hostnames — resolver required.
        assert!(
            MainConfig::endpoint_needs_resolver("http://otel-collector:4317/v1/metrics"),
            "hostname must need resolver"
        );
        assert!(
            MainConfig::endpoint_needs_resolver("http://otel.example.com:4317/v1/metrics"),
            "FQDN must need resolver"
        );
        assert!(
            MainConfig::endpoint_needs_resolver("http://otel.example.com/v1/metrics"),
            "FQDN without explicit port must need resolver"
        );
        assert!(
            MainConfig::endpoint_needs_resolver("http://localhost:4317/v1/metrics"),
            "localhost must need resolver (DNS)"
        );
    }

    /// `MainConfig::default()` has `resolver = None` and `resolver_timeout = 0`.
    /// The resolver fields start unset; postconfiguration wires them only for
    /// DNS endpoints.
    #[test]
    fn resolver_fields_default_to_none() {
        let cfg = MainConfig::default();
        assert!(
            cfg.resolver.is_none(),
            "resolver must default to None (wired only for DNS endpoints at postconfiguration)"
        );
        assert_eq!(
            cfg.resolver_timeout, 0,
            "resolver_timeout must default to 0 (set only when resolver is wired)"
        );
    }

    /// Direct field simulation: a DNS endpoint postconfiguration stores the
    /// resolver pointer and a non-zero timeout in `MainConfig`.
    ///
    /// This does not call the real `postconfiguration` (which requires a live
    /// `ngx_conf_t`); instead it manually sets the fields the way
    /// `postconfiguration` would and verifies the accessors are consistent.
    /// The real wiring is exercised by the integration tests in
    /// `tests/integration/run_dns_dualstack.sh`.
    #[test]
    fn resolver_field_simulation_dns_endpoint() {
        let mut cfg = MainConfig::default();
        // Simulate postconfiguration wiring a DNS endpoint.
        // Use a non-null sentinel (0x1000) to stand in for a real ngx_resolver_t*.
        let fake_ptr = 0x1000usize as *mut nginx_sys::ngx_resolver_t;
        cfg.resolver = NonNull::new(fake_ptr);
        cfg.resolver_timeout = 5_000;

        assert!(cfg.resolver.is_some(), "resolver must be Some after wiring");
        assert_eq!(
            cfg.resolver.unwrap().as_ptr() as usize,
            0x1000,
            "resolver pointer must be stored verbatim"
        );
        assert_eq!(cfg.resolver_timeout, 5_000, "timeout must be stored");

        // Clearing the resolver (e.g. for a literal-IP endpoint) resets to defaults.
        cfg.resolver = None;
        cfg.resolver_timeout = 0;
        assert!(cfg.resolver.is_none());
        assert_eq!(cfg.resolver_timeout, 0);
    }

    /// H2F5 regression: per-signal endpoint directives that include a scheme/host
    /// must emit a WARN (not silently misroute telemetry to the wrong collector).
    ///
    /// Calls the production `has_authority` predicate directly.  Neutering that
    /// predicate (replacing `value.windows(3).any(…)` with `false`) makes every
    /// `assert!` below fail.
    ///
    /// Pre-fix shape (now fixed): an earlier version of this test defined its own
    /// local `fn has_authority` (identical copy of the inline predicate in
    /// `warn_if_has_authority`).  Replacing the production predicate with `if false`
    /// made the test STILL PASS because it called its own copy.  This test calls
    /// `super::has_authority` — the single production definition — so it cannot
    /// pass if the predicate is neutered.
    ///
    /// Mutation-evidence bar: replace `value.windows(3).any(…)` in
    /// `has_authority` with `false` → this test FAILS → restore → PASSES.
    #[test]
    fn h2f5_per_signal_endpoint_host_detection() {
        // Values with a scheme/host — production predicate must detect these.
        assert!(has_authority(b"http://other:4318/v1/metrics"));
        assert!(has_authority(b"https://collector.example.com/v1/logs"));
        assert!(has_authority(b"http://[::1]:4318/v1/traces"));

        // Path-only values — production predicate must pass these through.
        assert!(!has_authority(b"/v1/metrics"));
        assert!(!has_authority(b"/opentelemetry/api/v1/logs"));
        assert!(!has_authority(b"v1/traces"));
        assert!(!has_authority(b""));
    }

    // ── TLS config surface ─────────────────────────────────────────────────────

    /// `ExporterConfig::default()` initialises TLS fields to their zero/unset
    /// sentinel values: empty paths, `ssl_verify = UNSET_FLAG (-1)`.
    ///
    /// Mutation evidence: zero out `ssl_verify: UNSET_FLAG` (set to 0) in
    /// `Default` → `ssl_verify_off()` returns `true` on a fresh config → FAILS.
    #[test]
    fn a2_exporter_config_tls_defaults() {
        let cfg = ExporterConfig::default();
        // TLS cert/key paths are empty (not configured).
        assert!(cfg.ssl_cert.is_empty(), "ssl_cert must default to empty");
        assert!(cfg.ssl_cert_key.is_empty(), "ssl_cert_key must default to empty");
        // ssl_verify defaults to UNSET_FLAG (−1), which is treated as ON (not off).
        assert_eq!(cfg.ssl_verify, UNSET_FLAG, "ssl_verify must default to UNSET_FLAG (−1)");
        // ssl_verify_off() must be false when unset (defaults to ON).
        assert!(!cfg.ssl_verify_off(), "ssl_verify_off() must be false when unset (unset = ON)");
    }

    /// `ssl_verify_off()` returns `true` only when `ssl_verify` is explicitly 0
    /// and `false` for `UNSET_FLAG (−1)` and `1` (on).
    ///
    /// Mutation evidence: invert the `== 0` comparison to `!= 0` → the `off`
    /// assertion fails and the `on/unset` assertions flip.
    #[test]
    fn a2_ssl_verify_off_accessor() {
        let mut cfg = ExporterConfig::default();

        // UNSET_FLAG (−1) = not configured → treated as ON.
        assert!(!cfg.ssl_verify_off(), "UNSET_FLAG must not be treated as off");

        // Explicit ON (1).
        cfg.ssl_verify = 1;
        assert!(!cfg.ssl_verify_off(), "ssl_verify=1 must not be treated as off");

        // Explicit OFF (0).
        cfg.ssl_verify = 0;
        assert!(cfg.ssl_verify_off(), "ssl_verify=0 must be treated as off");
    }

    /// Helper: build a `TlsValidationInput` with all-files-exist, http endpoint
    /// defaults, overridable per test.
    fn val_input<'a>(
        endpoint: &'a str,
        ssl_cert: &'a str,
        ssl_cert_key: &'a str,
        trusted_cert: &'a str,
        ssl_verify_off: bool,
    ) -> TlsValidationInput<'a> {
        TlsValidationInput { endpoint, trusted_cert, ssl_cert, ssl_cert_key, ssl_verify_off }
    }

    /// Scheme validation through the PRODUCTION predicate (`validate_endpoint_tls`),
    /// NOT a reimplementation. Accepts unix:/http://https://; rejects others.
    ///
    /// Mutation evidence: remove the `is_https` branch from `validate_endpoint_tls`'s
    /// `valid_scheme` → `https://` returns `Err(BadScheme)` → this test FAILS.
    #[test]
    fn a2_https_scheme_is_valid() {
        let exists = |_: &str| true;
        // Valid schemes (no certs configured → Ok(false)).
        for ep in [
            "http://127.0.0.1:4318/",
            "https://127.0.0.1:4317/",
            "https://collector.example.com:4317/v1/metrics",
            "unix:/run/otel.sock",
        ] {
            assert_eq!(
                validate_endpoint_tls(&val_input(ep, "", "", "", false), exists),
                Ok(false),
                "{ep} must be a valid scheme"
            );
        }
        // Invalid schemes → BadScheme.
        for ep in ["grpc://127.0.0.1:4317/", "ftp://host/", ""] {
            assert_eq!(
                validate_endpoint_tls(&val_input(ep, "", "", "", false), exists),
                Err(TlsConfigError::BadScheme),
                "{ep:?} must be rejected as a bad scheme"
            );
        }
    }

    /// F4: `ssl_certificate` without `ssl_certificate_key` is a config error,
    /// and vice-versa — through the PRODUCTION validator.
    ///
    /// Mutation evidence: drop the `has_cert && !has_key` branch in
    /// `validate_endpoint_tls` → the cert-without-key case returns Ok → FAILS.
    #[test]
    fn a2_cert_key_pairing_validated() {
        let exists = |_: &str| true;

        // cert without key.
        assert_eq!(
            validate_endpoint_tls(
                &val_input("https://127.0.0.1:4317/", "/c/cert.pem", "", "", false),
                exists
            ),
            Err(TlsConfigError::CertWithoutKey),
            "ssl_certificate without ssl_certificate_key must error"
        );

        // key without cert.
        assert_eq!(
            validate_endpoint_tls(
                &val_input("https://127.0.0.1:4317/", "", "/c/key.pem", "", false),
                exists
            ),
            Err(TlsConfigError::KeyWithoutCert),
            "ssl_certificate_key without ssl_certificate must error"
        );

        // both present → ok.
        assert_eq!(
            validate_endpoint_tls(
                &val_input("https://127.0.0.1:4317/", "/c/cert.pem", "/c/key.pem", "", false),
                exists
            ),
            Ok(false),
            "cert+key both present must be valid"
        );
    }

    /// F4: a configured TLS file that does not exist is a config error (only on
    /// https:// endpoints), reported with the correct directive label —
    /// through the PRODUCTION validator.
    ///
    /// Mutation evidence: make `file_exists` unconditionally true in
    /// `validate_endpoint_tls` (drop the `!file_exists` check) → FAILS.
    #[test]
    fn a2_missing_tls_file_validated() {
        // trusted_certificate missing.
        let only_certkey_exist = |p: &str| p != "/missing/ca.pem";
        assert_eq!(
            validate_endpoint_tls(
                &val_input("https://127.0.0.1:4317/", "", "", "/missing/ca.pem", false),
                only_certkey_exist
            ),
            Err(TlsConfigError::FileMissing("trusted_certificate")),
            "missing trusted_certificate file must error with its label"
        );

        // ssl_certificate missing (key present).
        let cert_missing = |p: &str| p == "/c/key.pem";
        assert_eq!(
            validate_endpoint_tls(
                &val_input("https://127.0.0.1:4317/", "/c/cert.pem", "/c/key.pem", "", false),
                cert_missing
            ),
            Err(TlsConfigError::FileMissing("ssl_certificate")),
            "missing ssl_certificate file must error with its label"
        );

        // For http:// endpoints, file-existence is NOT checked (TLS inactive).
        assert_eq!(
            validate_endpoint_tls(
                &val_input("http://127.0.0.1:4318/", "", "", "/missing/ca.pem", false),
                |p: &str| p != "/missing/ca.pem"
            ),
            Ok(false),
            "http:// endpoint must not file-check TLS paths"
        );
    }

    /// F4: `ssl_verify off` default-on behaviour AND the WARN signal flow
    /// through the PRODUCTION validator (`Ok(true)` = emit the WARN).
    ///
    /// Mutation evidence: hardcode the returned warn flag to `false` in
    /// `validate_endpoint_tls` → the verify-off assertion FAILS.
    #[test]
    fn a2_ssl_verify_off_warn_signal() {
        let exists = |_: &str| true;
        // Default (verify on) → no WARN.
        assert_eq!(
            validate_endpoint_tls(&val_input("https://127.0.0.1:4317/", "", "", "", false), exists),
            Ok(false),
            "ssl_verify default (on) must not signal the insecure WARN"
        );
        // ssl_verify off → WARN signalled.
        assert_eq!(
            validate_endpoint_tls(&val_input("https://127.0.0.1:4317/", "", "", "", true), exists),
            Ok(true),
            "ssl_verify off must signal the insecure WARN"
        );
    }

    /// `parse_size_bytes` must return `None` for values that exceed `usize::MAX`
    /// on the current target, rather than silently truncating via `as usize`.
    ///
    /// On 64-bit hosts `usize::MAX == u64::MAX`, so there is no representable
    /// u64 value that `try_from` rejects.  The test therefore verifies the
    /// *code path* by checking that extremely large values that cannot be
    /// multiplied into a valid size (overflow in `checked_mul`) also return
    /// `None`, proving the safe conversion and subsequent overflow check both
    /// work.  On 32-bit targets the `try_from` branch fires for any value
    /// > u32::MAX; the behavior there is documented by the production comment.
    ///
    /// Mutation: revert `usize::try_from(n).ok()?` back to `n as usize` —
    /// on 64-bit hosts this mutation is undetectable at runtime (values fit),
    /// so the test instead asserts the `None` contract for inputs that overflow
    /// `checked_mul`, which remains correct under both the old and new code for
    /// large-multiplied values.  The comment above documents the 32-bit fix.
    #[test]
    fn parse_size_bytes_rejects_overflow() {
        // A bare decimal value that overflows u64 entirely must return None.
        assert_eq!(
            parse_size_bytes(b"99999999999999999999999"),
            None,
            "value that overflows u64 parse must return None"
        );
        // A numeric prefix with a 'g' suffix that overflows checked_mul must return
        // None (not wrap or truncate).  On 64-bit, usize::MAX / (1024^3) = 17179869183,
        // so 17179869184g overflows checked_mul.  On 32-bit it is rejected even sooner
        // by usize::try_from (any value > u32::MAX).
        assert_eq!(
            parse_size_bytes(b"17179869184g"),
            None,
            "value whose product overflows usize must return None"
        );
        // Sanity: a normally valid size still works.
        assert_eq!(parse_size_bytes(b"1m"), Some(1024 * 1024));
    }

    /// `align_ring_size` must return `None` for values near `usize::MAX` where
    /// rounding up to the next multiple of 8 would overflow, rather than panicking.
    ///
    /// `cmd_set_log_ring_size` delegates the alignment step to `align_ring_size`
    /// so that this test is genuine: reverting `align_ring_size` to use
    /// `next_multiple_of(8)` instead of `checked_next_multiple_of(8)` causes
    /// a panic in debug builds (overflow), which the test runner reports as a
    /// test failure.  The directive handler itself is an FFI callback that cannot
    /// be invoked in unit tests without a live nginx config context.
    ///
    /// Mutation: replace `n.checked_next_multiple_of(8)` in `align_ring_size`
    /// with `n.checked_next_multiple_of(8)` — panics on overflow values below,
    /// turning these assertions into test failures.
    #[test]
    fn log_ring_size_alignment_overflow_returns_none() {
        // usize::MAX is not itself a multiple of 8 (MAX % 8 = 7 on 64-bit),
        // so rounding up would overflow → None.
        assert_eq!(
            align_ring_size(usize::MAX),
            None,
            "usize::MAX rounded up to next multiple of 8 overflows → must return None"
        );

        // usize::MAX - 3 is also not a multiple of 8 (MAX%8=7, so MAX-3%8=4),
        // and rounding it up would also overflow → None.
        let near_max = usize::MAX - 3;
        assert_eq!(
            align_ring_size(near_max),
            None,
            "value near usize::MAX whose aligned form overflows must return None"
        );

        // Normal values round up correctly.
        assert_eq!(align_ring_size(9), Some(16), "9 must round up to 16");
        assert_eq!(align_ring_size(8), Some(8), "already-aligned value must be unchanged");
        assert_eq!(align_ring_size(0), Some(0), "zero must stay zero (trivially aligned)");
    }
}
