// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::ptr::NonNull;
use core::{mem, ptr};

use nginx_sys::{
    ngx_array_t, ngx_command_t, ngx_conf_t, ngx_flag_t, ngx_module_t, ngx_str_t, ngx_uint_t,
    NGX_CONF_BLOCK, NGX_CONF_FLAG, NGX_CONF_NOARGS, NGX_CONF_TAKE1, NGX_CONF_TAKE2,
    NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF, NGX_HTTP_MAIN_CONF_OFFSET,
    NGX_HTTP_SRV_CONF, NGX_LOG_DEBUG, NGX_LOG_EMERG, NGX_LOG_WARN,
};
use ngx::core::Status;
use ngx::http::{HttpModuleLocationConf, HttpModuleMainConf, NgxHttpCoreModule};
use ngx::{ngx_conf_log_error, ngx_string};

use crate::shm::{ROUTE_CAP, UPSTREAM_CAP, UPSTREAM_IDX_OTHER};

use crate::shm;
use crate::HttpOtelModule;

mod directives;
mod parse;

pub(super) use directives::*;
pub(crate) use parse::*;

/* ─────────────────────────── extension helpers ─────────────────────────────── */

/// Returns the directive arguments from a `ngx_conf_t`.
///
/// # Safety
/// Caller must ensure `cf` is a valid, non-null pointer and that `cf.args`
/// points to an initialized `ngx_array_t` of `ngx_str_t` elements.
pub(super) unsafe fn cf_args(cf: *const ngx_conf_t) -> &'static [ngx_str_t] {
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

/// Sentinel: `ngx_flag_t` not yet set by config.
pub(super) const UNSET_FLAG: ngx_flag_t = -1;
/// Sentinel: u64 not yet set.
pub(super) const UNSET_U64: u64 = u64::MAX;
/// Default export interval (matches the OTel SDK and C++ `nginx-otel` defaults).
const DEFAULT_INTERVAL_MS: u64 = 5_000;
/// Default retry-buffer depth ([`MainConfig::retry_buffer_depth`]).
const DEFAULT_RETRY_BUFFER_DEPTH: usize = 4;

/// OTLP wire transport for metric export, selected by `otel_export_protocol`.
/// `arrow` is reserved for a future OTel Arrow transport and rejected at parse time.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExportProtocol {
    /// OTLP/HTTP protobuf — the default. Uses `HyperHttpTransport`.
    OtlpHttp,
    /// OTLP/gRPC. Uses `GrpcTransport`.
    OtlpGrpc,
}

/// Key-value pair stored in NGINX pool memory (slices into the config buffer).
#[derive(Clone, Copy, Debug)]
pub struct KvPair {
    pub key: ngx_str_t,
    pub value: ngx_str_t,
}

/// `otel_exporter { ... }` sub-block configuration.
#[derive(Debug)]
pub struct ExporterConfig {
    /// Base OTLP endpoint URL (`endpoint`). Per-signal paths (`/v1/metrics`,
    /// `/v1/logs`, `/v1/traces`) are appended at export-loop startup unless
    /// overridden below. Accepted schemes: `unix:`, `http://`, `https://`.
    pub endpoint: ngx_str_t,
    /// Trusted CA cert path (`trusted_certificate`); used for `https://`.
    /// Absent → system default trust store.
    pub trusted_cert: ngx_str_t,
    /// mTLS client cert chain path (`ssl_certificate`). Active only when
    /// BOTH `ssl_cert` and `ssl_cert_key` are set.
    pub ssl_cert: ngx_str_t,
    /// mTLS client private key path (`ssl_certificate_key`).
    pub ssl_cert_key: ngx_str_t,
    /// `ssl_verify` flag: `UNSET_FLAG` (−1) = defaults to on; `1` = on; `0` = off.
    /// `off` is INSECURE (disables collector cert verification); WARN at config time.
    pub ssl_verify: ngx_flag_t,
    /// Per-signal metrics endpoint override (`OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`
    /// equivalent). If non-empty, used as-is instead of the base-derived path.
    pub metrics_endpoint: ngx_str_t,
    /// Per-signal logs endpoint override; see `metrics_endpoint`.
    pub logs_endpoint: ngx_str_t,
    /// Per-signal traces endpoint override; see `metrics_endpoint`.
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

/// Config-time endpoint/TLS validation failure, mapped 1:1 to an
/// `NGX_LOG_EMERG` message by `postconfiguration`. Split out as pure logic so
/// it is unit-testable without an `ngx_conf_t` FFI context.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TlsConfigError {
    /// Endpoint scheme is none of `unix:` / `http://` / `https://`.
    BadScheme,
    /// The host part of the endpoint authority is empty.
    BadHost,
    /// The port part of the endpoint authority is not a valid `u16 > 0`.
    BadPort,
    /// `ssl_certificate` set without `ssl_certificate_key`.
    CertWithoutKey,
    /// `ssl_certificate_key` set without `ssl_certificate`.
    KeyWithoutCert,
    /// A configured TLS file (label) does not exist / is not readable.
    FileMissing(&'static str),
}

/// Inputs to [`validate_endpoint_tls`] (empty string = unset).
pub(crate) struct TlsValidationInput<'a> {
    pub endpoint: &'a str,
    pub trusted_cert: &'a str,
    pub ssl_cert: &'a str,
    pub ssl_cert_key: &'a str,
    pub ssl_verify_off: bool,
}

/// Pure endpoint + TLS validation (nginx idiom: fail at config-parse time, not
/// runtime). `file_exists` is injected so filesystem checks are testable.
/// Returns `Ok(warn_insecure)` — `true` iff the `ssl_verify off` WARN should
/// fire — or the first failing check as `Err`.
pub(crate) fn validate_endpoint_tls(
    input: &TlsValidationInput<'_>,
    file_exists: impl Fn(&str) -> bool,
) -> Result<bool, TlsConfigError> {
    let is_https = input.endpoint.starts_with("https://");
    let is_http = input.endpoint.starts_with("http://");
    let valid_scheme = input.endpoint.starts_with("unix:") || is_http || is_https;
    if !valid_scheme {
        return Err(TlsConfigError::BadScheme);
    }

    // Authority validation applies to http(s):// only; unix: is a socket path.
    // IPv6-bracket aware, mirroring `parse_authority` (transport layer): for a
    // bracketed host `[...]`, the port-separator `:` is searched for only
    // after the closing `]`.
    if is_http || is_https {
        let scheme_len = if is_https { "https://".len() } else { "http://".len() };
        let rest = &input.endpoint[scheme_len..];
        let authority = rest.split('/').next().unwrap_or("");

        let search_start =
            if authority.starts_with('[') { authority.find(']').map_or(0, |i| i + 1) } else { 0 };

        let (host_raw, port_str) = match authority[search_start..].rfind(':') {
            Some(rel_idx) => {
                let idx = search_start + rel_idx;
                (&authority[..idx], Some(&authority[idx + 1..]))
            }
            None => (authority, None),
        };

        let host_inner = if host_raw.starts_with('[') && host_raw.ends_with(']') {
            &host_raw[1..host_raw.len() - 1]
        } else {
            host_raw
        };
        if host_inner.is_empty() {
            return Err(TlsConfigError::BadHost);
        }

        if let Some(p) = port_str {
            match p.parse::<u16>() {
                Ok(n) if n > 0 => {}
                _ => return Err(TlsConfigError::BadPort),
            }
        }
    }

    let has_cert = !input.ssl_cert.is_empty();
    let has_key = !input.ssl_cert_key.is_empty();
    if has_cert && !has_key {
        return Err(TlsConfigError::CertWithoutKey);
    }
    if !has_cert && has_key {
        return Err(TlsConfigError::KeyWithoutCert);
    }

    // File-existence checks apply only to https:// endpoints.
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

/// One entry in the per-`MainConfig` route lookup table, populated at
/// `postconfiguration` by walking the location tree.
#[derive(Copy, Clone)]
pub struct RouteEntry {
    /// `ngx_http_core_loc_conf_t *` for this location, cast to `usize`. `0` = empty slot.
    pub clcf_ptr: usize,
    /// Location name bytes (e.g. `"/api"`, `"/"`, `"= /health"`).
    pub name: [u8; ROUTE_NAME_MAX],
    /// Length of the name in bytes (0 = empty/unnamed).
    pub name_len: u8,
}

impl RouteEntry {
    /// Returns the route name (UTF-8 best-effort).
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("(invalid)")
    }
}

/// One entry in the per-`MainConfig` upstream-zone lookup table.
#[derive(Copy, Clone)]
pub struct UpstreamEntry {
    /// `ngx_shm_zone_t *` for this upstream zone, cast to `usize`. `0` = empty slot.
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
    /// `otel_exporter { ... }` sub-block; `is_set()` reflects whether it was configured.
    pub exporter: ExporterConfig,
    /// `otel_service_name`
    pub service_name: ngx_str_t,
    /// `otel_resource_attr <k> <v>` — accumulated list.
    pub resource_attrs: std::vec::Vec<KvPair>,
    /// `otel_exporter_header <k> <v>` — accumulated list.
    pub exporter_headers: std::vec::Vec<KvPair>,
    /// `otel_metric_interval`, in milliseconds; `UNSET_U64` until configured.
    pub metric_interval_ms: u64,
    /// `otel_metrics on | off` (default on). `off` leaves the metrics shm zone
    /// unregistered and skips histogram bumps/drain; traces and logs are
    /// unaffected — the setting for operators migrating from the traces-only
    /// C++ `nginx-otel` module. `UNSET_FLAG` (−1) = absent, treated as `on`.
    pub metrics_enabled: ngx_flag_t,
    /// `otel_metric_status_code_class on | off`. `UNSET_FLAG` (−1) = not set (→ on).
    pub status_code_class: ngx_flag_t,
    /// `otel_grpc_smoke_endpoint <url>` — TEST-ONLY unary gRPC viability trigger
    /// (see `src/transport/grpc/smoke.rs`). Field and directive exist only in
    /// test-support builds; absent from the production command table and `.so`.
    #[cfg(any(test, feature = "test-support"))]
    pub grpc_smoke_endpoint: ngx_str_t,
    /// `otel_grpc_bidi_smoke_endpoint <url>` — TEST-ONLY bidi gRPC viability
    /// trigger, parallel to `grpc_smoke_endpoint`.
    #[cfg(any(test, feature = "test-support"))]
    pub bidi_smoke_endpoint: ngx_str_t,
    /// `otel_grpc_bidi_overload_endpoint <url>` — TEST-ONLY bidi backpressure /
    /// give-up trigger, parallel to `bidi_smoke_endpoint`.
    #[cfg(any(test, feature = "test-support"))]
    pub bidi_overload_endpoint: ngx_str_t,
    /// `otel_export_protocol otlp_http | otlp_grpc;`. `None` = not set, treated
    /// as `OtlpHttp` by the `export_protocol` accessor.
    pub export_protocol: Option<ExportProtocol>,
    /// The registered metrics shared memory zone (set during postconfiguration).
    pub shm_zone: *mut nginx_sys::ngx_shm_zone_t,
    /// The registered control-plane shm zone (liveness heartbeat + hot-path
    /// flags word; reserved for a future bidi control channel).
    pub control_shm_zone: *mut nginx_sys::ngx_shm_zone_t,
    /// The registered logs shm zone (set when `any_log_export_enabled() ||
    /// error_log_enabled`). Per-worker layout: two rings (access + error) of
    /// `log_ring_cap` bytes each.
    pub logs_shm_zone: *mut nginx_sys::ngx_shm_zone_t,
    /// The registered spans shm zone (always registered when the module loads).
    /// One `DEFAULT_SPAN_RING_CAP`-byte ring per worker.
    pub spans_shm_zone: *mut nginx_sys::ngx_shm_zone_t,

    // Zone-init data: each registration stores a `ZoneInitData` here and points
    // `ngx_shm_zone_t.data` at it, so the pointer stays valid (config-pool
    // lifetime) from postconfiguration through the zone-init callback.
    /// Zone-init parameters for the metrics shm zone.
    pub metrics_zone_init_data: crate::shm::ZoneInitData,
    /// Zone-init parameters for the logs shm zone.
    pub logs_zone_init_data: crate::shm::ZoneInitData,
    /// Zone-init parameters for the spans shm zone.
    pub spans_zone_init_data: crate::shm::ZoneInitData,

    /// Final active worker count set by `check_zone_sizing` in `init_module`.
    /// Zones may reserve more (ncpu headroom); the exporter drains only this
    /// many slots. `0` = not yet set; callers fall back to zone-size-derived count.
    pub n_active_workers: core::sync::atomic::AtomicUsize,

    /// `true` when any location has `otel_log_export` in a selecting form
    /// (`on`/bare/`if=`). Gates the logs shm-zone allocation and the hot-path
    /// "Gate 1" check. Read via `any_log_export_enabled`.
    pub any_log_export: bool,
    /// `otel_log_ring_size <size>` — per-worker ring capacity in bytes; `0` =
    /// use [`crate::logs::ring::DEFAULT_LOG_RING_CAP`]. Test-support only —
    /// production always uses the auto-default.
    #[cfg(any(test, feature = "test-support"))]
    pub log_ring_size: usize,

    /// `otel_error_log [<level>];` was seen (default off). When `true`, the
    /// `ngx_otel_error_writer` node is woven into `cycle->new_log`.
    pub error_log_enabled: bool,
    /// Effective severity floor for the error-log writer, set by
    /// `cmd_set_error_log` (NOARGS → `NGX_LOG_ERR`, intentionally decoupled from
    /// core `error_log`; TAKE1 → explicit level). Writer drops messages where
    /// `level > error_log_level` (nginx levels inverted: 1=emerg … 8=debug).
    pub error_log_level: ngx_uint_t,
    /// `otel_error_log_coalesce on|off;` (default on). `off` bypasses the
    /// coalescer — best-effort, lossy under load (ring drops-newest; lost
    /// lines are counted in `dropped_records` but gone; the rate metric still
    /// counts the true total). nginx's own `error_log` file remains the only
    /// guaranteed full-fidelity transcript.
    pub error_log_coalesce: bool,

    // Route/upstream dimension tables: populated once at `postconfiguration`
    // (before fork) by walking the location tree and upstream list; workers
    // inherit them via fork and read lock-free (O(cap) linear scan, no alloc).
    /// Route lookup table: one entry per named `location {}`, capped at
    /// `ROUTE_CAP`; over-cap locations map to `ROUTE_CAP` ("other").
    pub route_table: [RouteEntry; ROUTE_CAP],
    /// Number of filled entries in `route_table` (0..=ROUTE_CAP).
    pub n_routes: usize,

    /// Upstream-zone lookup table: one entry per `upstream { zone ...; }`, capped at `UPSTREAM_CAP`.
    pub upstream_table: [UpstreamEntry; UPSTREAM_CAP],
    /// Number of filled entries in `upstream_table` (0..=UPSTREAM_CAP).
    pub n_upstreams: usize,

    /// Nginx resolver pulled from `clcf->resolver` at postconfiguration.
    /// `None` for literal-IP/`unix:` endpoints (no resolution needed).
    /// Config-pool lifetime; the exporter reads it post-fork (copy-on-write),
    /// workers never touch it.
    ///
    /// # Safety
    /// Raw pointer wrapped in `NonNull`; must not be accessed from multiple
    /// threads (sound because the exporter is single-threaded).
    pub resolver: Option<NonNull<nginx_sys::ngx_resolver_t>>,
    /// Resolver timeout in ms from `clcf->resolver_timeout`; `0` when `resolver`
    /// is `None`. Falls back to 5000 ms if unset (matches nginx-acme).
    pub resolver_timeout: nginx_sys::ngx_msec_t,

    /// Serving-certificate table, populated once at `postconfiguration` by
    /// [`crate::cert_table::build_cert_table`] and read-only afterwards. Empty
    /// when nginx lacks `http_ssl_module` or no server has certificates.
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
            metrics_enabled: UNSET_FLAG,
            status_code_class: UNSET_FLAG,
            #[cfg(any(test, feature = "test-support"))]
            grpc_smoke_endpoint: ngx_str_t::default(),
            #[cfg(any(test, feature = "test-support"))]
            bidi_smoke_endpoint: ngx_str_t::default(),
            #[cfg(any(test, feature = "test-support"))]
            bidi_overload_endpoint: ngx_str_t::default(),
            export_protocol: None,
            shm_zone: ptr::null_mut(),
            control_shm_zone: ptr::null_mut(),
            logs_shm_zone: ptr::null_mut(),
            spans_shm_zone: ptr::null_mut(),
            // Filled in at zone registration time.
            metrics_zone_init_data: crate::shm::ZoneInitData { ring_cap: 0, cycle_addr: 0 },
            logs_zone_init_data: crate::shm::ZoneInitData { ring_cap: 0, cycle_addr: 0 },
            spans_zone_init_data: crate::shm::ZoneInitData { ring_cap: 0, cycle_addr: 0 },
            n_active_workers: core::sync::atomic::AtomicUsize::new(0),
            any_log_export: false,
            #[cfg(any(test, feature = "test-support"))]
            log_ring_size: 0,
            error_log_enabled: false,
            // Overwritten by cmd_set_error_log only when error_log_enabled is set.
            error_log_level: nginx_sys::NGX_LOG_ERR as ngx_uint_t,
            error_log_coalesce: true,
            route_table: [RouteEntry { clcf_ptr: 0, name: [0u8; ROUTE_NAME_MAX], name_len: 0 };
                ROUTE_CAP],
            n_routes: 0,
            upstream_table: [UpstreamEntry {
                shm_zone_ptr: 0,
                name: [0u8; UPSTREAM_NAME_MAX],
                name_len: 0,
            }; UPSTREAM_CAP],
            n_upstreams: 0,
            resolver: None,
            resolver_timeout: 0,
            cert_table: std::vec::Vec::new(),
        }
    }
}

/// Reads `worker_processes` from the nginx core conf. Returns `None` when it
/// is still `NGX_CONF_UNSET` (-1) — i.e. the directive appears after the
/// `http {}` block. Callers should fall back to a provisional value (1) and
/// let `ngx_otel_init_module` validate the actual count later.
///
/// # Safety
/// `cf` must be a valid, non-null `ngx_conf_t` at postconfiguration time.
unsafe fn n_workers_from_cf(cf: *const ngx_conf_t) -> Option<usize> {
    // SAFETY: caller guarantees `cf` is valid at postconfiguration time.
    let cycle = unsafe { (*cf).cycle.as_ref() }?;
    let core_idx = nginx_sys::ngx_core_module.index;
    // SAFETY: nginx fills conf_ctx before postconfiguration runs; conf_ctx[core_idx]
    // is the ngx_core_conf_t*.
    let raw_conf: *mut *mut *mut core::ffi::c_void = unsafe { *cycle.conf_ctx.add(core_idx) };
    let core_conf = raw_conf.cast::<nginx_sys::ngx_core_conf_t>();
    if core_conf.is_null() {
        return None;
    }
    // SAFETY: core_conf is non-null per above check and valid for postconfiguration.
    let wp = unsafe { (*core_conf).worker_processes };
    // NGX_CONF_UNSET (-1) when the directive hasn't been parsed yet.
    if wp < 1 {
        None
    } else {
        Some(wp as usize)
    }
}

/// Worker-slot count to reserve in shm zones at parse time. Returns the exact
/// count when `worker_processes` is known (≥ 1); otherwise `ngx_ncpu` (what
/// `worker_processes auto` resolves to, so the zone fits any later count ≤
/// ncpu), falling back to 1 only if ncpu is somehow 0.
///
/// # Safety
/// `cf` must be a valid, non-null `ngx_conf_t` at postconfiguration time.
unsafe fn n_workers_to_reserve(cf: *const ngx_conf_t) -> usize {
    // SAFETY: `cf` is valid, non-null per this `unsafe fn`'s contract.
    if let Some(wp) = unsafe { n_workers_from_cf(cf) } {
        return wp;
    }
    // SAFETY: ngx_ncpu is set by nginx before any postconfiguration handler runs.
    let ncpu = unsafe { nginx_sys::ngx_ncpu };
    if ncpu > 0 {
        ncpu as usize
    } else {
        1
    }
}

/// Smallest worker-slot capacity across all *registered* (capacity > 0) shm
/// rings — the bound the LOG-phase `worker_id` guard must use, since any of
/// the three zones may be absent (e.g. `otel_metrics off`). Returns 0 when no
/// zone is registered, causing the bounds guard to skip all work. Factored out
/// as a pure function so the min-capacity invariant is unit-testable.
#[inline]
fn min_indexed_worker_capacity(metrics: usize, logs: usize, spans: usize) -> usize {
    let mut cap = usize::MAX;
    if metrics > 0 {
        cap = cap.min(metrics);
    }
    if logs > 0 {
        cap = cap.min(logs);
    }
    if spans > 0 {
        cap = cap.min(spans);
    }
    // No zone registered → return 0 so the bounds guard fires.
    if cap == usize::MAX {
        0
    } else {
        cap
    }
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

    /// Max number of *unsent* batches the export loop retains on send failure
    /// (oldest evicted first). Currently a constant; promotable to a directive
    /// if operators need it.
    pub fn retry_buffer_depth(&self) -> usize {
        DEFAULT_RETRY_BUFFER_DEPTH
    }

    /// Returns `true` when metric collection and export is enabled
    /// (`otel_metrics` absent/`on`); `false` (`off`) skips shm registration,
    /// histogram bumps, and the exporter's metrics drain loop. `UNSET_FLAG`
    /// (−1) is the initial sentinel and is treated as `on`.
    pub fn metrics_enabled(&self) -> bool {
        self.metrics_enabled != 0
    }

    /// `otel_metric_status_code_class`; `off` collapses the per-combo data
    /// points. The hot path always buckets status class in the combo
    /// histogram regardless of this flag.
    pub fn status_code_class_enabled(&self) -> bool {
        self.status_code_class != 0
    }

    /// Effective metric export protocol.  Returns `OtlpHttp` when the
    /// `otel_export_protocol` directive was not set (preserves existing
    /// byte-identical behaviour for HTTP).
    pub fn export_protocol(&self) -> ExportProtocol {
        self.export_protocol.unwrap_or(ExportProtocol::OtlpHttp)
    }

    /// Obtain the main config from the previous NGINX cycle (SIGHUP reload
    /// detection). `None` on initial startup or if the old cycle had no config.
    /// Read-only today; the intended anchor for future cross-cycle state
    /// transfer (e.g. TLS connection reuse). Mirrors
    /// `AcmeMainConfig::old_config` (`nginx-acme/src/conf.rs:667-676`).
    ///
    /// # Lifetime
    /// No unsafe transmute: the borrow of `cf.cycle.old_cycle` widens to `&'a
    /// MainConfig` via [`HttpModuleMainConf::main_conf`], which yields
    /// `&'static Self::MainConf` and is sound because the cycle's config pool
    /// outlives this call — the old cycle stays live through SIGHUP until all
    /// old workers exit. This is only called from `postconfiguration`, well
    /// before any old-cycle teardown.
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

    /// Returns `true` if the endpoint URL requires DNS resolution: a DNS-name
    /// endpoint (`http://otel.example.com:4317/`) → `true`; a literal-IP
    /// endpoint or any `unix:` endpoint → `false`. IPv6 bracket notation
    /// (`http://[::1]:4317/`) is unwrapped before the `IpAddr` probe. Pure
    /// function (no nginx calls) — safe to call from unit tests.
    pub fn endpoint_needs_resolver(endpoint_str: &str) -> bool {
        if endpoint_str.starts_with("unix:") {
            return false;
        }
        let rest = if let Some(r) = endpoint_str.strip_prefix("http://") {
            r
        } else if let Some(r) = endpoint_str.strip_prefix("https://") {
            r
        } else {
            // Unknown scheme — leave it to existing validation; no resolver needed.
            return false;
        };
        let authority = rest.split('/').next().unwrap_or(rest);
        let host = if let Some(inner) = authority.strip_prefix('[') {
            inner.split(']').next().unwrap_or(inner)
        } else {
            match authority.rfind(':') {
                Some(i) if authority[i + 1..].chars().all(|c| c.is_ascii_digit()) => {
                    &authority[..i]
                }
                _ => authority,
            }
        };
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
        // SIGHUP reload detection: log if the previous cycle had a config.
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

        // Endpoint + TLS validation: decision logic is in `validate_endpoint_tls`
        // (pure, unit-tested); map its result to the matching nginx log message.
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
            Err(TlsConfigError::BadHost) => {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &raw mut *cf,
                    "otel_exporter: \"endpoint\" has an invalid host"
                );
                return Err(Status::NGX_ERROR);
            }
            Err(TlsConfigError::BadPort) => {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &raw mut *cf,
                    "otel_exporter: \"endpoint\" has an invalid port"
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

        // Wire the nginx resolver when the endpoint host is a DNS name (follows
        // nginx-acme's pattern, `nginx-acme/src/conf/issuer.rs:202-226`). A
        // DNS-name endpoint with no configured `resolver` is a hard config
        // error. Literal IPv4/IPv6 and unix: endpoints skip this block.
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
                // Drop the borrow on clcf before a possible `&mut *cf` for logging.
                let resolver_info = NgxHttpCoreModule::location_conf(cf_ref).and_then(|clcf| {
                    let nn = NonNull::new(clcf.resolver)?;
                    // Zero connections means not properly configured (matches
                    // acme's connections.nelts guard, `issuer.rs:212-216`).
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

        // `otel_metrics off` leaves the zone null: workers see `shm_base()` ==
        // `None` and skip histogram bumps at zero cost; drain loop checks
        // `metrics_enabled()`.
        if self.metrics_enabled() {
            self.register_shm_zone(cf, module)?;
        }

        // Control-plane zone: ControlShm heartbeat + a reserved flags word for
        // a future bidi control channel.
        self.register_control_shm_zone(cf, module)?;

        if self.any_log_export_enabled() || self.error_log_enabled {
            self.register_logs_zone(cf, module)?;
        }

        // Always registered so the exporter can drain it even with no trace
        // directive configured (ring is simply empty).
        self.register_spans_zone(cf, module)?;

        // Walk the location tree and upstream list once, before fork, so all
        // workers see identical tables.
        // SAFETY: `cf` is the valid non-null parse context, and nginx runs
        // `postconfiguration` only after every location/upstream conf is parsed
        // and merged, satisfying `build_route_table`'s contract.
        unsafe { self.build_route_table(cf) };
        // SAFETY: same as above — valid `cf` at postconfiguration time satisfies
        // `build_upstream_table`'s contract.
        unsafe { self.build_upstream_table(cf) };

        // Runs after ngx_http_ssl_module's merge_srv_conf has loaded all
        // config-time certificates into each server's SSL_CTX.
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
        // SAFETY: `cf` is the valid non-null parse context at postconfiguration.
        let n_workers: usize = unsafe { n_workers_to_reserve(cf) };

        // Internal per-worker metrics buffer: no operator-facing name/size knob.
        let zone_size = shm::zone_size_for(n_workers);
        let mut zone_name = ngx::ngx_string!("ngx_http_otel_zone");

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

        // SAFETY: `cf` is valid and non-null per the postconfiguration contract.
        let cycle_addr = unsafe { (*cf).cycle as usize };
        self.metrics_zone_init_data = crate::shm::ZoneInitData {
            ring_cap: 0, // metrics zone has no ring
            cycle_addr,
        };

        // SAFETY: `register_zone` returned a non-null `ngx_shm_zone_t*` that nginx
        // owns in the conf pool; writing its `init`/`data` fields is sound, and
        // `self` outlives the zone (it lives in the same conf pool).
        unsafe {
            (*zone).init = Some(shm::otel_shm_zone_init);
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

    /// Register the per-worker logs shm zone. Must be called from
    /// `postconfiguration` when `any_log_export_enabled() || error_log_enabled`.
    /// Parallels `register_shm_zone`.
    pub fn register_logs_zone(
        &mut self,
        cf: *mut ngx_conf_t,
        module: *mut ngx_module_t,
    ) -> Result<(), Status> {
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

        // SAFETY: `cf` is valid and non-null per the postconfiguration contract.
        let cycle_addr = unsafe { (*cf).cycle as usize };
        self.logs_zone_init_data = crate::shm::ZoneInitData { ring_cap: cap, cycle_addr };

        // SAFETY: `register_zone` returned a non-null `ngx_shm_zone_t*` owned by
        // nginx in the conf pool; writing its `init`/`data` fields is sound.
        unsafe {
            (*zone).init = Some(shm::logs_shm_zone_init);
            (*zone).data = ptr::from_mut(&mut self.logs_zone_init_data).cast();
        }

        self.logs_shm_zone = zone;
        Ok(())
    }

    /// Register the dedicated spans shm zone: one ring per worker,
    /// `DEFAULT_SPAN_RING_CAP` bytes per ring. Called unconditionally from
    /// `postconfiguration` when the module is active.
    pub fn register_spans_zone(
        &mut self,
        cf: *mut ngx_conf_t,
        module: *mut ngx_module_t,
    ) -> Result<(), Status> {
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

        // SAFETY: `cf` is valid and non-null per the postconfiguration contract.
        let cycle_addr = unsafe { (*cf).cycle as usize };
        self.spans_zone_init_data = crate::shm::ZoneInitData { ring_cap: cap, cycle_addr };

        // SAFETY: same contract as `register_logs_zone`.
        unsafe {
            (*zone).init = Some(shm::spans_shm_zone_init);
            (*zone).data = ptr::from_mut(&mut self.spans_zone_init_data).cast();
        }

        self.spans_shm_zone = zone;
        Ok(())
    }

    /// Returns the base address of the spans ring data, or `None` if the zone
    /// was not registered or not yet mapped.
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

    /// Returns the base address of our `LogsWorkerSlot` data (parallels
    /// `shm_base`), or `None` if the logs zone is unregistered or unmapped.
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

    /// `true` when at least one location selects log export (`otel_log_export
    /// on`/bare/`if=<cond>`). Gates the logs shm zone and the LOG-phase "Gate 1"
    /// check. `off` does not set this — disabling is not a selection.
    #[inline]
    pub fn any_log_export_enabled(&self) -> bool {
        self.any_log_export
    }

    /// Resolves the `http.route` slot index for `clcf_ptr` (the matched
    /// location's `ngx_http_core_loc_conf_t *` cast to `usize`, from
    /// `NgxHttpCoreModule::location_conf`). Returns `0..ROUTE_CAP` for a
    /// registered location, or `ROUTE_CAP` ("other") otherwise.
    ///
    /// # Hot-path note
    /// Linear scan of at most `ROUTE_CAP` entries (≤ 64 by default). No alloc,
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

    /// Resolves the upstream-zone slot index for `shm_zone_ptr` (the
    /// `ngx_shm_zone_t *` cast to `usize` from
    /// `r->upstream->upstream->shm_zone`; pass `0` for no upstream). Returns
    /// `0..UPSTREAM_CAP-1` for a registered zone, else `UPSTREAM_IDX_OTHER`.
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

    /// Route name string for slot `route_idx` (for encoder attribute values);
    /// `"(other)"` for the overflow slot.
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

    /// Walks the nginx static-location tree and registers each location conf
    /// pointer in `route_table`. Called once at `postconfiguration`, before
    /// workers fork; workers inherit the table read-only.
    ///
    /// # Safety
    /// `cf` must be a valid, non-null `ngx_conf_t` pointer at postconfiguration.
    unsafe fn build_route_table(&mut self, cf: *mut ngx_conf_t) {
        use nginx_sys::{
            ngx_http_core_loc_conf_t, ngx_http_core_main_conf_t, ngx_http_core_srv_conf_t,
        };
        // SAFETY: per the fn contract `cf` is a valid non-null parse context at
        // postconfiguration; `&*cf` is a sound shared borrow.
        let cf_ref = unsafe { &*cf };
        let cmcf: Option<&ngx_http_core_main_conf_t> = NgxHttpCoreModule::main_conf(cf_ref);
        let cmcf = match cmcf {
            Some(c) => c,
            None => return, // no HTTP core — very unusual, skip gracefully
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
            // SAFETY: `root_clcf` is non-null (checked above) and valid in conf-pool
            // memory; reading its `static_locations` tree-root pointer is sound.
            let static_locs = unsafe { (*root_clcf).static_locations };
            // SAFETY: `static_locs` is null or a valid location-tree node within
            // nginx config memory, satisfying `walk_location_tree`'s contract.
            unsafe { self.walk_location_tree(static_locs) };
        }
    }

    /// Recursively walks a `ngx_http_location_tree_node_t` tree, registering
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

        if !n.exact.is_null() {
            // SAFETY: `n.exact` is non-null (checked) and a valid
            // `ngx_http_core_loc_conf_t*`, satisfying `try_register_route`.
            unsafe { self.try_register_route(n.exact) };
        }
        // Inclusive (prefix-match) location, if different from exact.
        if !n.inclusive.is_null() && n.inclusive != n.exact {
            // SAFETY: `n.inclusive` is non-null (checked) and a valid
            // `ngx_http_core_loc_conf_t*`, satisfying `try_register_route`.
            unsafe { self.try_register_route(n.inclusive) };
        }

        // SAFETY: `n.tree` is null or a valid sibling/child tree node owned by
        // nginx, satisfying `walk_location_tree`'s contract.
        unsafe { self.walk_location_tree(n.tree) };
        // SAFETY: `n.left` is null or a valid tree node, per the contract.
        unsafe { self.walk_location_tree(n.left) };
        // SAFETY: `n.right` is null or a valid tree node, per the contract.
        unsafe { self.walk_location_tree(n.right) };
    }

    /// Registers one location conf in the route table. No-op if already
    /// registered or the table is full (over-cap locations map to "other").
    ///
    /// # Safety
    /// `clcf_ptr` must be a valid non-null `ngx_http_core_loc_conf_t *`.
    unsafe fn try_register_route(&mut self, clcf_ptr: *mut nginx_sys::ngx_http_core_loc_conf_t) {
        let ptr_val = clcf_ptr as usize;

        for i in 0..self.n_routes {
            if self.route_table[i].clcf_ptr == ptr_val {
                return; // already registered
            }
        }

        if self.n_routes >= ROUTE_CAP {
            return; // over cap → "other" bucket
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

    /// Walks the upstream list and registers each upstream zone in `upstream_table`.
    ///
    /// # Safety
    /// `cf` must be a valid, non-null `ngx_conf_t` pointer at postconfiguration.
    unsafe fn build_upstream_table(&mut self, cf: *mut ngx_conf_t) {
        use nginx_sys::ngx_http_upstream_srv_conf_t;

        // SAFETY: per the fn contract `cf` is a valid non-null parse context.
        let _cf_ref = unsafe { &*cf };

        // SAFETY: `ngx_http_upstream_module.ctx_index` is a static module field
        // nginx initialises before config parsing; reading it is sound.
        let ctx_index = unsafe { nginx_sys::ngx_http_upstream_module.ctx_index };

        // SAFETY: `cf` is valid; `cf.cycle` is the live cycle (null handled below),
        // the HTTP module's `conf_ctx` slot is in-bounds, and the pointer it holds
        // is the `ngx_http_conf_ctx_t*`, null-checked before use.
        let http_conf_ctx = unsafe {
            let cf_inner = &*(cf as *const nginx_sys::ngx_conf_t);
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

            let mut found = false;
            for j in 0..self.n_upstreams {
                if self.upstream_table[j].shm_zone_ptr == zone_ptr {
                    found = true;
                    break;
                }
            }
            if found {
                continue; // already registered
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

    /// Effective per-worker log ring capacity in bytes. Production always uses
    /// the auto-default ([`crate::logs::ring::DEFAULT_LOG_RING_CAP`]);
    /// test-support builds may override via `otel_log_ring_size` to provoke overflow.
    #[inline]
    pub fn log_ring_cap(&self) -> usize {
        #[cfg(any(test, feature = "test-support"))]
        if self.log_ring_size > 0 {
            return self.log_ring_size;
        }
        crate::logs::ring::DEFAULT_LOG_RING_CAP
    }

    /// Returns the base address of our `WorkerSlots` data (`shm.addr +
    /// data_offset()`, past the nginx slab-pool header), or `None` if
    /// `shm_zone` is null (unconfigured) or not yet mapped.
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

    /// Number of worker slots the metrics shm zone was sized for, derived from
    /// its registered `shm.size` (stable across reloads and pre-fork). Used by
    /// per-request bounds guards to catch under-sizing. `0` if unregistered.
    pub fn shm_n_workers(&self) -> usize {
        // SAFETY: `shm_zone` is null or the `ngx_shm_zone_t*` from
        // `register_shm_zone`; reading `shm.size` through it is sound.
        let Some(zone) = (unsafe { self.shm_zone.as_ref() }) else {
            return 0;
        };
        crate::shm::n_workers_from_zone_size(zone.shm.size)
    }

    /// Like [`shm_n_workers`](Self::shm_n_workers) for the logs shm zone. `0`
    /// when unregistered (log export disabled).
    pub fn logs_n_workers(&self) -> usize {
        // SAFETY: `logs_shm_zone` is null (handled by `as_ref()`) or the
        // `ngx_shm_zone_t*` from `register_logs_zone`; reading `shm.size`
        // through it is sound.
        let Some(zone) = (unsafe { self.logs_shm_zone.as_ref() }) else {
            return 0;
        };
        // shm.size includes the slab-pool header; subtract before dividing by
        // the per-worker slot size (matches `logs_zone_size_for`).
        let data_bytes = zone.shm.size.saturating_sub(crate::shm::data_offset());
        let slot = crate::shm::logs_slot_size(self.log_ring_cap());
        data_bytes.checked_div(slot).unwrap_or(0)
    }

    /// Like [`shm_n_workers`](Self::shm_n_workers) for the spans shm zone. `0`
    /// when unregistered (tracing disabled).
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

    /// Smallest worker-slot capacity across every shm ring the LOG-phase
    /// handler indexes by `worker_id` (metrics/logs/spans, each if
    /// registered). The three zones size independently and may differ (e.g.
    /// `otel_metrics off`, or a reload re-deriving a different count for a
    /// surviving zone), so a `worker_id` fitting one ring could overrun a
    /// smaller sibling; the hot-path guard validates against this MIN. `0`
    /// when no zone is registered, skipping all LOG-phase work.
    ///
    /// # Hot-path note
    /// Three pointer loads + integer `min`s; no alloc/lock/syscall. Callers may
    /// cache the result once per request (constant for the worker's life).
    pub fn min_indexed_worker_capacity(&self) -> usize {
        min_indexed_worker_capacity(
            self.shm_n_workers(),
            self.logs_n_workers(),
            self.spans_n_workers(),
        )
    }

    /// Returns a pointer to the `ControlShm` data in the control zone
    /// (`data_offset()` bytes past `shm.addr`), or `None` if unregistered or
    /// not yet mapped.
    ///
    /// # Hot-path note
    /// Called from `LogPhaseHandler` on every request; the disabled path is a
    /// single null-pointer branch — zero allocations, zero syscalls.
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

    /// Mutable counterpart to [`control_shm_ptr`](Self::control_shm_ptr), used
    /// by the exporter process to write the crash-loop backoff counter
    /// (`crash_count`, `window_start_unix`). Fields are `AtomicU64`, so
    /// concurrent reads by workers are data-race-free without a lock.
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
pub(super) static mut NGX_HTTP_OTEL_EXPORTER_COMMANDS: [ngx_command_t; 13] = [
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
    // mTLS client cert + server-verify toggle.
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
    // C++-compatible aliases: header, interval, batch_size, batch_count.
    // `header <name> <value>` appends to the same `exporter_headers` Vec as
    // the top-level `otel_exporter_header` directive.
    ngx_command_t {
        name: ngx_string!("header"),
        type_: NGX_CONF_TAKE2 as ngx_uint_t,
        set: Some(cmd_exporter_block_add_header),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    // `interval <msec>` sets the metric export interval.
    ngx_command_t {
        name: ngx_string!("interval"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_exporter_block_set_interval),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    // `batch_size <n>` — accepted for C++ compat, ignored (fixed-size ring, no equivalent).
    ngx_command_t {
        name: ngx_string!("batch_size"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_exporter_block_ignore_batch_size),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    // `batch_count <n>` — accepted for C++ compat, ignored (fixed retry-buffer depth, no equivalent).
    ngx_command_t {
        name: ngx_string!("batch_count"),
        type_: NGX_CONF_TAKE1 as ngx_uint_t,
        set: Some(cmd_exporter_block_ignore_batch_count),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t::empty(),
];
/* ─────────────────────────── top-level commands ────────────────────────────── */

// Two separate command-table definitions (below) so the test-only directive
// strings are absent from production .so files (verified by grep on objs-release/).

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
            // otel_metric_status_code_class on | off;
            ngx_command_t {
                name: ngx_string!("otel_metric_status_code_class"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG) as ngx_uint_t,
                set: Some(nginx_sys::ngx_conf_set_flag_slot),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: mem::offset_of!(MainConfig, status_code_class),
                post: ptr::null_mut(),
            },
            // otel_export_protocol otlp_http | otlp_grpc; default otlp_http
            // (byte-identical to pre-existing behaviour). "arrow" rejected at parse time.
            ngx_command_t {
                name: ngx_string!("otel_export_protocol"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(cmd_set_export_protocol),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_error_log [<level>]; default off. Weaves a ngx_log_writer_pt
            // node into cycle->new_log: NOARGS -> fixed floor NGX_LOG_ERR
            // (decoupled from core error_log), TAKE1 -> explicit level. Worker
            // context coalesces into the verbatim ring -> OTLP; master/config-load
            // falls through structurally to core error_log.
            ngx_command_t {
                name: ngx_string!("otel_error_log"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(cmd_set_error_log),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_error_log_coalesce on|off; default on. `off` bypasses the
            // coalescer (best-effort, NOT guaranteed delivery — ring
            // drops-newest under load; dropped_records still counts the true
            // total). nginx's own error_log remains the full-fidelity transcript.
            ngx_command_t {
                name: ngx_string!("otel_error_log_coalesce"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG) as ngx_uint_t,
                set: Some(cmd_set_error_log_coalesce),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_trace <complex-value>; per-location enable, allows
            // split_clients-based ratio sampling. Absent = disabled, zero cost
            // (REWRITE exits immediately). Inner block wins on merge.
            ngx_command_t {
                name: ngx_string!("otel_trace"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1)
                    as ngx_uint_t,
                set: Some(cmd_set_otel_trace),
                conf: NGX_HTTP_LOC_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_trace_context ignore|extract|inject|propagate; W3C traceparent
            // mode, default extract (read inbound, no outbound injection).
            ngx_command_t {
                name: ngx_string!("otel_trace_context"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1)
                    as ngx_uint_t,
                set: Some(cmd_set_otel_trace_context),
                conf: NGX_HTTP_LOC_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_span_name <complex-value>; per-location override, default "METHOD route_name".
            ngx_command_t {
                name: ngx_string!("otel_span_name"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1)
                    as ngx_uint_t,
                set: Some(cmd_set_otel_span_name),
                conf: NGX_HTTP_LOC_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_span_attr <key> <value>; accumulates per location, no
            // inheritance (child locations start with an empty set).
            ngx_command_t {
                name: ngx_string!("otel_span_attr"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2)
                    as ngx_uint_t,
                set: Some(cmd_add_otel_span_attr),
                conf: NGX_HTTP_LOC_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_log_export on | off | if=<cond>; selects exception-tail log
            // export per request. Absent = no export (privacy-safe default).
            // Mirrors core access_log ... if=; inner block wins on merge.
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
            // otel_metrics on | off; default on. `off` suppresses metric
            // collection/export (shm not allocated, drain loop skipped);
            // traces/logs unaffected. Matches the traces-only C++ nginx-otel module.
            ngx_command_t {
                name: ngx_string!("otel_metrics"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG) as ngx_uint_t,
                set: Some(nginx_sys::ngx_conf_set_flag_slot),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: mem::offset_of!(MainConfig, metrics_enabled),
                post: ptr::null_mut(),
            },
        ]
    };
}

/// Production build: 15 production commands + terminator.
#[cfg(not(any(test, feature = "test-support")))]
pub static mut NGX_HTTP_OTEL_COMMANDS: [ngx_command_t; 16] = {
    let mut cmds = [ngx_command_t::empty(); 16];
    let prod = production_commands!();
    let mut i = 0;
    while i < 15 {
        cmds[i] = prod[i];
        i += 1;
    }
    // cmds[15] stays empty() — terminator
    cmds
};

/// test-support build: 15 production commands + 5 test-only directives + terminator.
///
/// Test-only directives (absent from the production table and `.so`, verified
/// by grep on `objs-release/ngx_http_otel_module.so`): `otel_log_ring_size`
/// (shrink the log ring to provoke overflow deterministically),
/// `otel_status_endpoint` (exposes `control_shm.version` for the heartbeat
/// integration test), and the gRPC unary/bidi/overload smoke-test triggers.
#[cfg(any(test, feature = "test-support"))]
pub static mut NGX_HTTP_OTEL_COMMANDS: [ngx_command_t; 21] = {
    let mut cmds = [ngx_command_t::empty(); 21];
    let prod = production_commands!();
    let mut i = 0;
    while i < 15 {
        cmds[i] = prod[i];
        i += 1;
    }
    // Index 15: otel_log_ring_size (test-support only).
    cmds[15] = ngx_command_t {
        name: ngx_string!("otel_log_ring_size"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(cmd_set_log_ring_size),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    };
    // Index 16: otel_status_endpoint (test-support only).
    cmds[16] = ngx_command_t {
        name: ngx_string!("otel_status_endpoint"),
        type_: (nginx_sys::NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS) as ngx_uint_t,
        set: Some(cmd_set_otel_status_endpoint),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    };
    // Index 17: otel_grpc_smoke_endpoint (test-support only).
    cmds[17] = ngx_command_t {
        name: ngx_string!("otel_grpc_smoke_endpoint"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(nginx_sys::ngx_conf_set_str_slot),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: mem::offset_of!(MainConfig, grpc_smoke_endpoint),
        post: ptr::null_mut(),
    };
    // Index 18: otel_grpc_bidi_smoke_endpoint (test-support only).
    cmds[18] = ngx_command_t {
        name: ngx_string!("otel_grpc_bidi_smoke_endpoint"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(nginx_sys::ngx_conf_set_str_slot),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: mem::offset_of!(MainConfig, bidi_smoke_endpoint),
        post: ptr::null_mut(),
    };
    // Index 19: otel_grpc_bidi_overload_endpoint (test-support only).
    cmds[19] = ngx_command_t {
        name: ngx_string!("otel_grpc_bidi_overload_endpoint"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(nginx_sys::ngx_conf_set_str_slot),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: mem::offset_of!(MainConfig, bidi_overload_endpoint),
        post: ptr::null_mut(),
    };
    // cmds[20] stays empty() — terminator.
    cmds
};
#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_char;

    /// Pins: the LOG-phase `worker_id` guard validates against the MIN of every
    /// registered shm ring (metrics/logs/spans), not just metrics — the three
    /// zones size independently, so a `worker_id` fitting one ring could
    /// overrun a smaller sibling.
    #[test]
    fn min_indexed_worker_capacity_uses_smallest_ring() {
        let metrics = 8;
        let logs = 2;
        let spans = 4;
        let cap = min_indexed_worker_capacity(metrics, logs, spans);
        assert_eq!(cap, 2, "guard must use the smallest indexed ring capacity");

        // worker_id=3 fits metrics (3<8) but overruns logs (3>=2): must be rejected.
        assert!(3 >= cap, "worker_id within metrics zone but past logs ring must be rejected");
        assert!(1 < cap, "worker_id within the smallest ring must be accepted");

        // Unregistered zones (capacity 0) must not constrain the bound.
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

        // Metrics absent (e.g. `otel_metrics off`): bound must come from
        // logs/spans only, not collapse to 0.
        assert_eq!(
            min_indexed_worker_capacity(0, 4, 3),
            3,
            "metrics absent: bound must be min(logs=4, spans=3) = 3"
        );
        assert_eq!(
            min_indexed_worker_capacity(0, 4, 0),
            4,
            "metrics absent, spans absent: bound must be logs=4"
        );
        assert_eq!(
            min_indexed_worker_capacity(0, 0, 3),
            3,
            "metrics absent, logs absent: bound must be spans=3"
        );
        assert_eq!(
            min_indexed_worker_capacity(0, 0, 0),
            0,
            "no zones registered: bound must be 0 (bounds guard fires, nothing indexed)"
        );
    }

    #[test]
    fn test_parse_duration_ms() {
        assert_eq!(parse_duration_ms(b"10s"), Some(10_000));
        assert_eq!(parse_duration_ms(b"5m"), Some(300_000));
        assert_eq!(parse_duration_ms(b"2h"), Some(7_200_000));
        assert_eq!(parse_duration_ms(b"1d"), Some(86_400_000));
        assert_eq!(parse_duration_ms(b"0s"), Some(0));
        assert_eq!(parse_duration_ms(b"500ms"), Some(500));
        assert_eq!(parse_duration_ms(b"5000ms"), Some(5_000));
        assert_eq!(parse_duration_ms(b"0ms"), Some(0));
        assert_eq!(parse_duration_ms(b"5"), Some(5_000)); // bare integer = seconds
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
        assert!(!cfg.any_log_export_enabled(), "log export must default to off");
        assert!(!cfg.error_log_enabled, "error_log_enabled must default to false");
        assert!(cfg.error_log_coalesce, "error_log_coalesce must default to true (on)");
    }

    /// Pins: `error_log_level` defaults to `NGX_LOG_ERR` (fixed floor, not
    /// mirrored from core `error_log`) — cross-checked by the Stage E
    /// integration test `run_error_log.sh`.
    #[test]
    fn error_log_default_floor_is_ngx_log_err() {
        let cfg = MainConfig::default();
        assert_eq!(
            cfg.error_log_level,
            nginx_sys::NGX_LOG_ERR as ngx_uint_t,
            "error_log_level default must be NGX_LOG_ERR (4), not mirrored from core log"
        );
        assert_eq!(nginx_sys::NGX_LOG_ERR, 4, "sanity: NGX_LOG_ERR must equal 4");
    }

    /// Pins: `error_log_enabled`/`error_log_coalesce` toggle correctly
    /// (directive handlers are exercised by integration tests separately).
    #[test]
    fn error_log_directive_toggles_enablement() {
        let mut cfg = MainConfig::default();
        assert!(!cfg.error_log_enabled);
        assert!(cfg.error_log_coalesce); // default on
        cfg.error_log_enabled = true;
        cfg.error_log_level = nginx_sys::NGX_LOG_WARN as ngx_uint_t;
        assert!(cfg.error_log_enabled);
        assert_eq!(cfg.error_log_level, nginx_sys::NGX_LOG_WARN as ngx_uint_t);
        cfg.error_log_coalesce = false;
        assert!(!cfg.error_log_coalesce);
        cfg.error_log_coalesce = true;
        assert!(cfg.error_log_coalesce);
    }

    /// Pins: route index lookup is keyed on the location conf pointer, not
    /// the URI — two different URIs hitting the same location resolve to the
    /// same `route_idx`.
    #[test]
    fn route_is_location_name_not_uri() {
        let mut cfg = MainConfig::default();

        assert_eq!(cfg.route_idx_for_clcf(0x1000), ROUTE_CAP, "unregistered → other");
        assert_eq!(cfg.route_idx_for_clcf(0), ROUTE_CAP, "null → other");

        cfg.route_table[0].clcf_ptr = 0x1000;
        cfg.route_table[0].name_len = 4;
        cfg.route_table[0].name[..4].copy_from_slice(b"/api");
        cfg.n_routes = 1;

        // Same clcf* from two different URIs (e.g. /api/users, /api/products) → same route_idx.
        let uri1_clcf = 0x1000usize;
        let uri2_clcf = 0x1000usize;
        assert_eq!(cfg.route_idx_for_clcf(uri1_clcf), 0, "/api/users → route_idx 0");
        assert_eq!(
            cfg.route_idx_for_clcf(uri2_clcf),
            0,
            "/api/products → route_idx 0 (same location)"
        );

        let other_clcf = 0x2000usize;
        assert_eq!(cfg.route_idx_for_clcf(other_clcf), ROUTE_CAP, "different location → other");

        cfg.route_table[1].clcf_ptr = 0x2000;
        cfg.route_table[1].name_len = 8;
        cfg.route_table[1].name[..8].copy_from_slice(b"/health/");
        cfg.n_routes = 2;
        assert_eq!(cfg.route_idx_for_clcf(0x2000), 1, "/health/ registered at idx 1");

        let mut full_cfg = MainConfig::default(); // over-cap routes map to ROUTE_CAP
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

    /// Pins field consistency for a DNS-endpoint postconfiguration wiring,
    /// simulated by setting the fields directly (no live `ngx_conf_t`); the
    /// real wiring is exercised by `tests/integration/run_dns_dualstack.sh`.
    #[test]
    fn resolver_field_simulation_dns_endpoint() {
        let mut cfg = MainConfig::default();
        // Non-null sentinel standing in for a real ngx_resolver_t*.
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

    /// Pins: per-signal endpoint directives with a scheme/host emit a WARN
    /// (not silent misrouting). Calls the production `has_authority`
    /// predicate directly (not a local copy), so neutering it fails this test.
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

    /// Pins: authority (host + port) validation for http(s):// endpoints —
    /// valid: no-port, explicit port, bracketed IPv6, path suffix, unix:
    /// socket (always passes). Invalid: empty host, out-of-range/zero/non-numeric port.
    #[test]
    fn a2_authority_validated() {
        let exists = |_: &str| true;

        // ── valid endpoints (must return Ok) ──────────────────────────────────
        for ep in [
            "http://h",
            "http://h:4317",
            "http://h:4317/v1",
            "http://[::1]:4318",
            "http://[::1]",
            "https://h:443/p",
            "unix:/run/x.sock",
        ] {
            assert_eq!(
                validate_endpoint_tls(&val_input(ep, "", "", "", false), exists),
                Ok(false),
                "{ep:?} should be valid"
            );
        }

        // ── invalid: empty host ────────────────────────────────────────────────
        for ep in ["http://:4317", "http:///v1", "https://"] {
            assert_eq!(
                validate_endpoint_tls(&val_input(ep, "", "", "", false), exists),
                Err(TlsConfigError::BadHost),
                "{ep:?} should fail with BadHost"
            );
        }

        // ── invalid: bad port ──────────────────────────────────────────────────
        for ep in ["http://h:99999", "http://h:abc", "http://h:0", "https://h:65536"] {
            assert_eq!(
                validate_endpoint_tls(&val_input(ep, "", "", "", false), exists),
                Err(TlsConfigError::BadPort),
                "{ep:?} should fail with BadPort"
            );
        }
    }

    /// Pins: `parse_size_bytes` returns `None` (not a silent truncation via
    /// `as usize`) for values that overflow `usize` — both the too-large-for-u64
    /// case and the checked_mul-overflow case (64-bit: usize::MAX / 1024^3 =
    /// 17179869183, so 17179869184g overflows).
    #[test]
    fn parse_size_bytes_rejects_overflow() {
        assert_eq!(
            parse_size_bytes(b"99999999999999999999999"),
            None,
            "value that overflows u64 parse must return None"
        );
        assert_eq!(
            parse_size_bytes(b"17179869184g"),
            None,
            "value whose product overflows usize must return None"
        );
        // Sanity: a normally valid size still works.
        assert_eq!(parse_size_bytes(b"1m"), Some(1024 * 1024));
    }

    /// Pins: `otel_metrics` defaults to enabled (UNSET_FLAG treated as on) so
    /// existing deployments that never set the directive keep emitting metrics.
    #[test]
    fn metrics_enabled_default_is_true() {
        let cfg = MainConfig::default();
        assert_eq!(cfg.metrics_enabled, UNSET_FLAG, "initial sentinel must be UNSET_FLAG");
        assert!(cfg.metrics_enabled(), "metrics must be enabled by default");
    }

    /// Pins: `otel_metrics off` (metrics_enabled = 0, as written by
    /// `ngx_conf_set_flag_slot`) disables metrics.
    #[test]
    fn metrics_enabled_off_disables_metrics() {
        // Struct-update syntax to satisfy clippy::field_reassign_with_default.
        let cfg = MainConfig { metrics_enabled: 0, ..Default::default() };
        assert!(!cfg.metrics_enabled(), "metrics_enabled = 0 must return false");
    }

    /// Pins: `otel_metrics on` (metrics_enabled = 1) explicitly enables metrics.
    #[test]
    fn metrics_enabled_on_is_true() {
        let cfg = MainConfig { metrics_enabled: 1, ..Default::default() };
        assert!(cfg.metrics_enabled(), "metrics_enabled = 1 must return true");
    }

    /// Pins: `align_ring_size` returns `None` (not a debug-build overflow
    /// panic) for values near `usize::MAX` where rounding up to the next
    /// multiple of 8 would overflow.
    #[test]
    fn log_ring_size_alignment_overflow_returns_none() {
        assert_eq!(
            align_ring_size(usize::MAX),
            None,
            "usize::MAX rounded up to next multiple of 8 overflows → must return None"
        );

        let near_max = usize::MAX - 3;
        assert_eq!(
            align_ring_size(near_max),
            None,
            "value near usize::MAX whose aligned form overflows must return None"
        );

        assert_eq!(align_ring_size(9), Some(16), "9 must round up to 16");
        assert_eq!(align_ring_size(8), Some(8), "already-aligned value must be unchanged");
        assert_eq!(align_ring_size(0), Some(0), "zero must stay zero (trivially aligned)");
    }

    /// `DEFAULT_INTERVAL_MS` must be 5000 to match the OTel SDK / C++
    /// nginx-otel module default of 5 s.
    ///
    /// Mutation evidence: change `DEFAULT_INTERVAL_MS` back to 10_000 →
    /// both the constant assertion and the `interval_ms()` default assertion fail.
    #[test]
    fn exporter_block_default_interval_is_5s() {
        assert_eq!(DEFAULT_INTERVAL_MS, 5_000, "default export interval must be 5 s (5000 ms)");
        let cfg = MainConfig::default();
        assert_eq!(
            cfg.interval_ms(),
            5_000,
            "MainConfig::interval_ms() must return 5000 when unconfigured"
        );
    }

    /// Pins: `cmd_exporter_block_add_header` appends to `exporter_headers` via
    /// the container-of recovery of `MainConfig` from `&amcf.exporter` (the
    /// same conf pointer `cmd_set_exporter_block` stores in `handler_conf`).
    /// Breaking that subtraction corrupts `amcf` and fails the assertions below.
    #[test]
    fn exporter_block_header_appends_to_main_config_exporter_headers() {
        use core::ffi::c_void;

        let mut amcf = MainConfig::default();

        // conf = &amcf.exporter cast to *mut c_void, as cmd_set_exporter_block does.
        let fake_conf: *mut c_void = ptr::addr_of_mut!(amcf.exporter).cast();

        // args[0] = directive name (unused), args[1] = key, args[2] = value.
        let k_bytes = b"authorization";
        let v_bytes = b"Bearer tok";
        let fake_args: [nginx_sys::ngx_str_t; 3] = [
            nginx_sys::ngx_str_t { len: 6, data: b"header".as_ptr().cast_mut() },
            nginx_sys::ngx_str_t { len: k_bytes.len(), data: k_bytes.as_ptr().cast_mut() },
            nginx_sys::ngx_str_t { len: v_bytes.len(), data: v_bytes.as_ptr().cast_mut() },
        ];

        let mut fake_arr = nginx_sys::ngx_array_t {
            elts: fake_args.as_ptr().cast_mut().cast(),
            nelts: 3,
            size: core::mem::size_of::<nginx_sys::ngx_str_t>(),
            nalloc: 3,
            pool: core::ptr::null_mut(),
        };

        // SAFETY: `ngx_conf_t` is a `#[repr(C)]` struct of integer fields and
        // raw pointers; the all-zero bit pattern is a valid (null-pointer/zero)
        // initial state. Only the `args` field is accessed by the handler.
        let mut fake_cf: nginx_sys::ngx_conf_t = unsafe { core::mem::zeroed() };
        fake_cf.args = ptr::addr_of_mut!(fake_arr);

        let rc = cmd_exporter_block_add_header(
            ptr::addr_of_mut!(fake_cf),
            core::ptr::null_mut(),
            fake_conf,
        );

        assert!(rc.is_null(), "handler must return NGX_CONF_OK (null ptr)");
        assert_eq!(amcf.exporter_headers.len(), 1, "must have appended one header");
        assert_eq!(amcf.exporter_headers[0].key.as_bytes(), k_bytes, "header key must match");
        assert_eq!(amcf.exporter_headers[0].value.as_bytes(), v_bytes, "header value must match");
    }

    /// Pins: `cmd_exporter_block_set_interval` parses the C++
    /// `ngx_conf_set_msec_slot` grammar (`5s`, `500ms`, bare `5` = seconds)
    /// and writes `metric_interval_ms` on the containing `MainConfig`.
    #[test]
    fn exporter_block_interval_parses_time_string() {
        use core::ffi::c_void;

        // Helper: run the handler with a given value string on a fresh MainConfig.
        fn call_interval(val: &[u8]) -> (*mut c_char, u64) {
            let mut amcf = MainConfig::default();
            let fake_conf: *mut c_void = ptr::addr_of_mut!(amcf.exporter).cast();
            let fake_args: [nginx_sys::ngx_str_t; 2] = [
                nginx_sys::ngx_str_t { len: 8, data: b"interval".as_ptr().cast_mut() },
                nginx_sys::ngx_str_t { len: val.len(), data: val.as_ptr().cast_mut() },
            ];
            let mut fake_arr = nginx_sys::ngx_array_t {
                elts: fake_args.as_ptr().cast_mut().cast(),
                nelts: 2,
                size: core::mem::size_of::<nginx_sys::ngx_str_t>(),
                nalloc: 2,
                pool: core::ptr::null_mut(),
            };
            // SAFETY: `ngx_conf_t` is a POD struct; all-zero is valid for this test.
            let mut fake_cf: nginx_sys::ngx_conf_t = unsafe { core::mem::zeroed() };
            fake_cf.args = ptr::addr_of_mut!(fake_arr);
            let rc = cmd_exporter_block_set_interval(
                ptr::addr_of_mut!(fake_cf),
                core::ptr::null_mut(),
                fake_conf,
            );
            (rc, amcf.metric_interval_ms)
        }

        // `5s` → 5000 ms: the form used in the C++ nginx-otel documentation.
        let (rc, ms) = call_interval(b"5s");
        assert!(rc.is_null(), "interval 5s must return NGX_CONF_OK");
        assert_eq!(ms, 5_000, "5s must store 5000 ms");

        // `500ms` → 500 ms: explicit millisecond suffix (nginx msec grammar).
        let (rc, ms) = call_interval(b"500ms");
        assert!(rc.is_null(), "interval 500ms must return NGX_CONF_OK");
        assert_eq!(ms, 500, "500ms must store 500 ms");

        // Bare `5` → 5000 ms: bare integer treated as seconds, matching C++.
        let (rc, ms) = call_interval(b"5");
        assert!(rc.is_null(), "bare interval 5 must return NGX_CONF_OK");
        assert_eq!(ms, 5_000, "bare 5 must store 5000 ms (treated as seconds)");
    }

    /// `cmd_exporter_block_set_interval` returns duplicate error when called
    /// twice on the same `MainConfig`.
    #[test]
    fn exporter_block_interval_duplicate_rejected() {
        use core::ffi::c_void;

        // Pre-set metric_interval_ms to simulate a duplicate directive.
        let mut amcf = MainConfig { metric_interval_ms: 5_000, ..MainConfig::default() };

        let fake_conf: *mut c_void = ptr::addr_of_mut!(amcf.exporter).cast();

        let val_bytes = b"3000";
        let fake_args: [nginx_sys::ngx_str_t; 2] = [
            nginx_sys::ngx_str_t { len: 8, data: b"interval".as_ptr().cast_mut() },
            nginx_sys::ngx_str_t { len: val_bytes.len(), data: val_bytes.as_ptr().cast_mut() },
        ];
        let mut fake_arr = nginx_sys::ngx_array_t {
            elts: fake_args.as_ptr().cast_mut().cast(),
            nelts: 2,
            size: core::mem::size_of::<nginx_sys::ngx_str_t>(),
            nalloc: 2,
            pool: core::ptr::null_mut(),
        };
        // SAFETY: `ngx_conf_t` is a POD struct; all-zero is valid for this test.
        let mut fake_cf: nginx_sys::ngx_conf_t = unsafe { core::mem::zeroed() };
        fake_cf.args = ptr::addr_of_mut!(fake_arr);

        let rc = cmd_exporter_block_set_interval(
            ptr::addr_of_mut!(fake_cf),
            core::ptr::null_mut(),
            fake_conf,
        );

        assert!(!rc.is_null(), "duplicate interval must return an error pointer");
        assert_eq!(amcf.metric_interval_ms, 5_000, "existing value must be unchanged");
    }

    /// Pins: `batch_size`/`batch_count` accept the nginx size-string grammar
    /// (matching C++ `ngx_conf_set_size_slot`, cpp:137/143), parse-then-discard
    /// the value on success (NGX_CONF_OK), and reject unparseable values
    /// (NGX_CONF_ERROR). The stub log needs `log_level = NGX_LOG_DEBUG` so
    /// `ngx_conf_log_error!`'s level check passes through to the no-op stub.
    #[test]
    fn exporter_block_batch_size_and_count_accept_size_string_and_reject_invalid() {
        // SAFETY: `ngx_log_t` is a POD struct; all-zero is a valid initial state.
        let mut stub_log: nginx_sys::ngx_log_t = unsafe { core::mem::zeroed() };
        stub_log.log_level = nginx_sys::NGX_LOG_DEBUG as nginx_sys::ngx_uint_t;

        // Each test case keeps its args array alive independently so that
        // arr.elts points to a live [ngx_str_t; 2] for the duration of the call.

        // batch_size plain integer (C++ default is 512) → NGX_CONF_OK.
        {
            let ok_bytes = b"512";
            let args_a: [nginx_sys::ngx_str_t; 2] = [
                nginx_sys::ngx_str_t { len: 10, data: b"batch_size".as_ptr().cast_mut() },
                nginx_sys::ngx_str_t { len: ok_bytes.len(), data: ok_bytes.as_ptr().cast_mut() },
            ];
            let mut arr_a = nginx_sys::ngx_array_t {
                elts: args_a.as_ptr().cast_mut().cast(),
                nelts: 2,
                size: core::mem::size_of::<nginx_sys::ngx_str_t>(),
                nalloc: 2,
                pool: core::ptr::null_mut(),
            };
            // SAFETY: `ngx_conf_t` is a POD struct; all-zero is valid.
            let mut cf_a: nginx_sys::ngx_conf_t = unsafe { core::mem::zeroed() };
            cf_a.args = ptr::addr_of_mut!(arr_a);
            cf_a.log = ptr::addr_of_mut!(stub_log);
            let rc = cmd_exporter_block_ignore_batch_size(
                ptr::addr_of_mut!(cf_a),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            assert!(rc.is_null(), "batch_size 512 must return NGX_CONF_OK");
        }

        // batch_size with `k` suffix (`1k` = 1024) → NGX_CONF_OK.
        // Validates the fix: parse_u64_ascii rejected `1k`; parse_size_bytes accepts it.
        {
            let ok_bytes = b"1k";
            let args_k: [nginx_sys::ngx_str_t; 2] = [
                nginx_sys::ngx_str_t { len: 10, data: b"batch_size".as_ptr().cast_mut() },
                nginx_sys::ngx_str_t { len: ok_bytes.len(), data: ok_bytes.as_ptr().cast_mut() },
            ];
            let mut arr_k = nginx_sys::ngx_array_t {
                elts: args_k.as_ptr().cast_mut().cast(),
                nelts: 2,
                size: core::mem::size_of::<nginx_sys::ngx_str_t>(),
                nalloc: 2,
                pool: core::ptr::null_mut(),
            };
            // SAFETY: `ngx_conf_t` is a POD struct; all-zero is valid.
            let mut cf_k: nginx_sys::ngx_conf_t = unsafe { core::mem::zeroed() };
            cf_k.args = ptr::addr_of_mut!(arr_k);
            cf_k.log = ptr::addr_of_mut!(stub_log);
            let rc = cmd_exporter_block_ignore_batch_size(
                ptr::addr_of_mut!(cf_k),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            assert!(rc.is_null(), "batch_size 1k must return NGX_CONF_OK (size-string accepted)");
        }

        // batch_count plain integer (C++ default is 4) → NGX_CONF_OK.
        {
            let ok_bytes = b"4";
            let args_b: [nginx_sys::ngx_str_t; 2] = [
                nginx_sys::ngx_str_t { len: 11, data: b"batch_count".as_ptr().cast_mut() },
                nginx_sys::ngx_str_t { len: ok_bytes.len(), data: ok_bytes.as_ptr().cast_mut() },
            ];
            let mut arr_b = nginx_sys::ngx_array_t {
                elts: args_b.as_ptr().cast_mut().cast(),
                nelts: 2,
                size: core::mem::size_of::<nginx_sys::ngx_str_t>(),
                nalloc: 2,
                pool: core::ptr::null_mut(),
            };
            // SAFETY: `ngx_conf_t` is a POD struct; all-zero is valid.
            let mut cf_b: nginx_sys::ngx_conf_t = unsafe { core::mem::zeroed() };
            cf_b.args = ptr::addr_of_mut!(arr_b);
            cf_b.log = ptr::addr_of_mut!(stub_log);
            let rc = cmd_exporter_block_ignore_batch_count(
                ptr::addr_of_mut!(cf_b),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            assert!(rc.is_null(), "batch_count 4 must return NGX_CONF_OK");
        }

        // batch_size non-parseable value → NGX_CONF_ERROR.
        {
            let bad_bytes = b"notanumber";
            let args_c: [nginx_sys::ngx_str_t; 2] = [
                nginx_sys::ngx_str_t { len: 10, data: b"batch_size".as_ptr().cast_mut() },
                nginx_sys::ngx_str_t { len: bad_bytes.len(), data: bad_bytes.as_ptr().cast_mut() },
            ];
            let mut arr_c = nginx_sys::ngx_array_t {
                elts: args_c.as_ptr().cast_mut().cast(),
                nelts: 2,
                size: core::mem::size_of::<nginx_sys::ngx_str_t>(),
                nalloc: 2,
                pool: core::ptr::null_mut(),
            };
            // SAFETY: `ngx_conf_t` is a POD struct; all-zero is valid.
            let mut cf_c: nginx_sys::ngx_conf_t = unsafe { core::mem::zeroed() };
            cf_c.args = ptr::addr_of_mut!(arr_c);
            cf_c.log = ptr::addr_of_mut!(stub_log);
            let rc = cmd_exporter_block_ignore_batch_size(
                ptr::addr_of_mut!(cf_c),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            assert!(!rc.is_null(), "batch_size with unparseable value must return NGX_CONF_ERROR");
        }

        // batch_count non-parseable value → NGX_CONF_ERROR.
        {
            let bad_bytes = b"notanumber";
            let args_d: [nginx_sys::ngx_str_t; 2] = [
                nginx_sys::ngx_str_t { len: 11, data: b"batch_count".as_ptr().cast_mut() },
                nginx_sys::ngx_str_t { len: bad_bytes.len(), data: bad_bytes.as_ptr().cast_mut() },
            ];
            let mut arr_d = nginx_sys::ngx_array_t {
                elts: args_d.as_ptr().cast_mut().cast(),
                nelts: 2,
                size: core::mem::size_of::<nginx_sys::ngx_str_t>(),
                nalloc: 2,
                pool: core::ptr::null_mut(),
            };
            // SAFETY: `ngx_conf_t` is a POD struct; all-zero is valid.
            let mut cf_d: nginx_sys::ngx_conf_t = unsafe { core::mem::zeroed() };
            cf_d.args = ptr::addr_of_mut!(arr_d);
            cf_d.log = ptr::addr_of_mut!(stub_log);
            let rc = cmd_exporter_block_ignore_batch_count(
                ptr::addr_of_mut!(cf_d),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            assert!(!rc.is_null(), "batch_count with unparseable value must return NGX_CONF_ERROR");
        }
    }
}
