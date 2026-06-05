// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::ffi::{c_char, c_void};
use core::{mem, ptr};

use nginx_sys::{
    ngx_array_t, ngx_command_t, ngx_conf_parse, ngx_conf_t, ngx_flag_t, ngx_module_t, ngx_str_t,
    ngx_uint_t, NGX_CONF_BLOCK, NGX_CONF_FLAG, NGX_CONF_NOARGS, NGX_CONF_TAKE1, NGX_CONF_TAKE2,
    NGX_HTTP_MAIN_CONF, NGX_HTTP_MAIN_CONF_OFFSET, NGX_LOG_DEBUG, NGX_LOG_EMERG,
};
use crate::logs::error_writer::{
    ngx_otel_error_writer, otel_log_insert, parse_error_log_level, OtelErrorWriterState,
};
use ngx::core::{Status, NGX_CONF_ERROR, NGX_CONF_OK};
use ngx::http::{HttpModuleMainConf, NgxHttpCoreModule};
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
    let arr: *const ngx_array_t = unsafe { (*cf).args };
    if arr.is_null() {
        return &[];
    }
    unsafe { (*arr).as_slice::<ngx_str_t>() }
}

// Sentinel: ngx_flag_t not yet set by config
const UNSET_FLAG: ngx_flag_t = -1;
// Sentinel: u64 not yet set
const UNSET_U64: u64 = u64::MAX;
// Default export interval: 10 s in milliseconds
const DEFAULT_INTERVAL_MS: u64 = 10_000;
// Default batch size
const DEFAULT_BATCH_SIZE: u64 = 100;
/// Default retry-buffer depth used by [`MainConfig::retry_buffer_depth`].
/// See the spec-inconsistency note on that method.
const DEFAULT_RETRY_BUFFER_DEPTH: usize = 4;

/// Selects the OTLP wire transport for metric export.
///
/// Corresponds to the `otel_export_protocol` directive:
/// - `otlp_http` (default): OTLP/HTTP over HTTP/1.1 (`POST /v1/metrics`).
/// - `otlp_grpc`:           OTLP/gRPC over HTTP/2 (`MetricsService.Export`).
/// - `arrow` is reserved for Phase 5 and is rejected at config parse time.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MetricProtocol {
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
#[derive(Debug, Default)]
pub struct ExporterConfig {
    /// The OTLP/HTTP endpoint URL.
    /// Accepted schemes: `unix:`, `http://`, `https://`
    pub endpoint: ngx_str_t,
    /// Path to a trusted CA certificate for HTTPS (optional).
    pub trusted_cert: ngx_str_t,
}

impl ExporterConfig {
    pub fn is_set(&self) -> bool {
        !self.endpoint.is_empty()
    }
}

// ── Route and upstream tables (Phase 2.2 DP-E) ──────────────────────────────

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
    /// `otel_metric_batch_size` — UNSET_U64 until configured.
    pub metric_batch_size: u64,
    /// `otel_metric_zone <name> <size>` — name part.
    pub zone_name: ngx_str_t,
    /// `otel_metric_zone <name> <size>` — size in bytes; 0 = not configured.
    pub zone_size: usize,
    /// `otel_metric_status_code_class on | off`
    /// UNSET_FLAG (-1) = not set (treated as on/default).
    pub status_code_class: ngx_flag_t,
    /// `otel_metric_high_cardinality_attr <attr>` — accumulated list.
    pub high_cardinality_attrs: std::vec::Vec<ngx_str_t>,
    /// `otel_grpc_smoke_endpoint <url>` — TEST-ONLY trigger for the
    /// Phase 1.2 Item 1 in-worker gRPC viability harness.  When set
    /// (and the crate is built with the `test-support` feature),
    /// Worker 0's `init_process` fires one unary OTLP/gRPC export via
    /// `NgxExecutor` + `SendRequestService` + `NgxConnIo` to verify
    /// the §7.3 pipeline works end-to-end on real nginx event-loop
    /// infrastructure under `--with-debug`.  In production (non-test)
    /// builds the directive is parsed but ignored; documented as such
    /// in `src/transport/grpc/smoke.rs`.
    pub grpc_smoke_endpoint: ngx_str_t,
    /// `otel_grpc_bidi_smoke_endpoint <url>` — TEST-ONLY trigger for the
    /// Phase 1.2 Item 2 bidi gRPC viability harness.  Parallel to
    /// `grpc_smoke_endpoint` (Item 1).  When set (and built with
    /// `test-support`), Worker 0's `init_process` fires one bidi
    /// `Echo.BidiEcho` call against the local echo server to verify that
    /// the send-half and receive-half are independently pollable through
    /// `NgxConnIo`.  Parsed in all builds; acted on only with
    /// `test-support`.
    pub bidi_smoke_endpoint: ngx_str_t,
    /// `otel_grpc_bidi_overload_endpoint <url>` — TEST-ONLY trigger for the
    /// Phase 1.2 Item 3 backpressure / livelock integration test.  Parallel
    /// to `bidi_smoke_endpoint` (Item 2).  When set (and built with
    /// `test-support`), Worker 0's `init_process` fires a sustained bidi
    /// overload against the echo server, exercising the give-up path and
    /// incrementing `BIDI_BACKPRESSURE_DROPS`.  Parsed in all builds; acted
    /// on only with `test-support`.
    pub bidi_overload_endpoint: ngx_str_t,
    /// `otel_export_protocol otlp_http | otlp_grpc;` — selects the export
    /// transport.  `None` means the directive was not set; treated as
    /// `OtlpHttp` (default) by [`metric_protocol`].
    pub metric_protocol: Option<MetricProtocol>,
    /// The registered shared memory zone (set during postconfiguration).
    pub shm_zone: *mut nginx_sys::ngx_shm_zone_t,
    /// The registered control-plane shared memory zone (set during
    /// postconfiguration alongside `shm_zone`). Used by the exporter for
    /// the liveness heartbeat and by workers for the hot-path placeholder
    /// load (Phase 1.3.3). Phase 5 wires the bidi control channel to it.
    pub control_shm_zone: *mut nginx_sys::ngx_shm_zone_t,
    /// The registered logs shm zone (set during postconfiguration when
    /// `is_access_sample_enabled() || error_log_enabled`).  Per-worker layout:
    /// two rings per slot (access + error), each of `log_ring_cap` bytes.
    /// Memory = `log_ring_cap × 2 × N` + slab-pool header overhead.
    pub logs_shm_zone: *mut nginx_sys::ngx_shm_zone_t,
    /// `otel_access_log_sample <size>` — reservoir size for the exception-tail
    /// exemplar reservoir.  `0` = not configured (default off).
    /// Presence ⇒ exception tail + exemplar sampling on; absent ⇒ off.
    /// The histogram is always-on regardless of this field.
    ///
    /// Read via [`is_access_sample_enabled`] / [`access_sample_size`].
    pub access_sample_size: usize,
    /// `otel_log_ring_size <size>` — per-worker ring capacity in bytes.
    /// `0` = not configured (uses `DEFAULT_LOG_RING_CAP`).
    pub log_ring_size: usize,

    // ── Phase 2.3: error-log export ──────────────────────────────────────────
    //
    /// `otel_error_log [<level>];` was seen.  `false` = not configured (default
    /// off).  When `true`, the `ngx_otel_error_writer` node is woven into the
    /// `cycle->new_log` chain and the logs shm zone is registered.
    pub error_log_enabled: bool,
    /// Effective severity floor for the OTel error-log writer.
    ///
    /// Set by `cmd_set_error_log`:
    /// - NOARGS: mirrors `cf->cycle->log->log_level` (the core `error_log` level).
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
    /// (untouched) `error_log` file.  The companion error-rate metric (DP-B)
    /// counts the true total in both modes.
    pub error_log_coalesce: bool,

    // ── Phase 2.2 DP-E: route and upstream-zone dimension tables ─────────────
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
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            exporter: ExporterConfig::default(),
            service_name: ngx_str_t::default(),
            resource_attrs: std::vec::Vec::new(),
            exporter_headers: std::vec::Vec::new(),
            metric_interval_ms: UNSET_U64,
            metric_batch_size: UNSET_U64,
            zone_name: ngx_str_t::default(),
            zone_size: 0,
            status_code_class: UNSET_FLAG,
            high_cardinality_attrs: std::vec::Vec::new(),
            grpc_smoke_endpoint: ngx_str_t::default(),
            bidi_smoke_endpoint: ngx_str_t::default(),
            bidi_overload_endpoint: ngx_str_t::default(),
            metric_protocol: None,
            shm_zone: ptr::null_mut(),
            control_shm_zone: ptr::null_mut(),
            logs_shm_zone: ptr::null_mut(),
            // 0 = not configured (off by default).
            access_sample_size: 0,
            log_ring_size: 0,
            // Phase 2.3 error-log defaults.
            error_log_enabled: false,
            error_log_level: 0,   // overwritten by cmd_set_error_log
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
        }
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

    /// Effective batch size (max data points per encoded batch).
    ///
    /// **NOTE — currently unused.** The export loop emits one batch per
    /// interval regardless of size; the directive is reserved for a future
    /// iteration that chunks large collections. Do not remove without
    /// updating the directive table.
    #[allow(dead_code)]
    pub fn batch_size(&self) -> u64 {
        if self.metric_batch_size == UNSET_U64 {
            DEFAULT_BATCH_SIZE
        } else {
            self.metric_batch_size
        }
    }

    /// Maximum number of *unsent* batches the export loop holds in its retry
    /// buffer on send failure. Older entries are evicted oldest-first.
    ///
    /// Distinct from [`batch_size`](Self::batch_size), which is points-per-batch.
    /// The Step 9 spec's claim that "depth from otel_metric_batch_size, default
    /// reasonable 4-8 batches" is internally inconsistent (batch_size defaults
    /// to 100, which would buffer 10k+ points). The "reasonable default" reading
    /// wins here. Currently a constant; promotable to a directive if operators
    /// need to tune it.
    pub fn retry_buffer_depth(&self) -> usize {
        DEFAULT_RETRY_BUFFER_DEPTH
    }

    /// Whether HTTP status code class bucketing is enabled (default: true).
    ///
    /// Currently unused: the status-class breakdown is bucketed in the hot
    /// path but not yet emitted (see `TODO(fix3b)` in
    /// `metric_source/instrumented.rs`). Emission is deferred to Phase 2,
    /// when per-data-point attributes + multi-dimensional shm land — at which
    /// point this accessor gates the emission.
    #[allow(dead_code)]
    pub fn status_code_class_enabled(&self) -> bool {
        self.status_code_class != 0 // UNSET_FLAG or 1 → true; explicit 0 → false
    }

    /// Effective metric export protocol.  Returns `OtlpHttp` when the
    /// `otel_export_protocol` directive was not set (preserves existing
    /// byte-identical behaviour for HTTP).
    pub fn metric_protocol(&self) -> MetricProtocol {
        self.metric_protocol.unwrap_or(MetricProtocol::OtlpHttp)
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
    /// Phase 1.2 will use this hook for TLS connection reuse and related cross-cycle
    /// state transfer. In Phase 1.1 the hook is read-only: we log and return.
    pub fn old_config<'a>(cf: &mut ngx_conf_t) -> Option<&'a MainConfig> {
        let old_cycle = unsafe { cf.cycle.as_ref()?.old_cycle.as_ref()? };
        if old_cycle.conf_ctx.is_null() {
            return None;
        }
        HttpOtelModule::main_conf(old_cycle)
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
        // Phase 1.2 will use this hook for TLS connection reuse and related
        // cross-cycle state transfer. In Phase 1.1 we only log.
        if let Some(old) = unsafe { Self::old_config(&mut *cf) } {
            if self.is_configured() {
                unsafe {
                    ngx_conf_log_error!(
                        NGX_LOG_DEBUG,
                        &mut *cf,
                        "otel: SIGHUP reload detected (old endpoint={}, new endpoint={})",
                        old.exporter.endpoint,
                        self.exporter.endpoint
                    );
                }
            } else {
                unsafe {
                    ngx_conf_log_error!(
                        NGX_LOG_DEBUG,
                        &mut *cf,
                        "otel: SIGHUP reload detected: new config has no otel_exporter block"
                    );
                }
            }
        }

        if !self.is_configured() {
            // Module loaded but not configured: zero-cost mode.
            return Ok(());
        }

        // Validate endpoint scheme.
        let ep = self.exporter.endpoint.as_bytes();
        let valid_scheme =
            ep.starts_with(b"unix:") || ep.starts_with(b"http://") || ep.starts_with(b"https://");

        if !valid_scheme {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "otel_exporter: \"endpoint\" must start with unix:, http://, or https://"
                );
            }
            return Err(Status::NGX_ERROR);
        }

        // Register the metrics shared memory zone.
        self.register_shm_zone(cf, module)?;

        // Register the control-plane shared memory zone (Phase 1.3.3).
        // This zone holds the ControlShm heartbeat counter and the
        // Phase 5 flag word. Registered alongside the metrics zone so
        // both are mapped before workers fork.
        self.register_control_shm_zone(cf, module)?;

        // Register the per-worker logs shm zone when the access exception-tail
        // (Phase 2.2) or the OTel error-log writer (Phase 2.3) is enabled.
        if self.is_access_sample_enabled() || self.error_log_enabled {
            self.register_logs_zone(cf, module)?;
        }

        // Build the route and upstream-zone lookup tables (Phase 2.2 DP-E).
        // This walks the nginx location tree and upstream list ONCE before
        // workers fork, so all workers see identical tables.
        // Safety: cf is valid; nginx guarantees postconfiguration runs after
        // all location and upstream configs are parsed and merged.
        unsafe { self.build_route_table(cf) };
        unsafe { self.build_upstream_table(cf) };

        Ok(())
    }

    /// Register the per-worker shared memory zone with nginx.
    fn register_shm_zone(
        &mut self,
        cf: *mut ngx_conf_t,
        module: *mut ngx_module_t,
    ) -> Result<(), Status> {
        // Determine the number of worker processes from ngx_core_conf_t.
        // ngx_get_conf(cycle->conf_ctx, ngx_core_module) = conf_ctx[ngx_core_module.index]
        // is a void* pointing to ngx_core_conf_t (typed as void*** in the binding).
        let n_workers: usize = unsafe {
            let cycle = (*cf).cycle.as_ref().ok_or(Status::NGX_ERROR)?;
            let core_idx = nginx_sys::ngx_core_module.index;
            // conf_ctx is *mut *mut *mut *mut c_void; indexing gives *mut *mut *mut c_void.
            // The BIT value of that pointer IS the ngx_core_conf_t*.
            let raw_conf: *mut *mut *mut core::ffi::c_void = *cycle.conf_ctx.add(core_idx);
            let core_conf: *const nginx_sys::ngx_core_conf_t = raw_conf.cast();
            if core_conf.is_null() {
                1 // fallback
            } else {
                (*core_conf).worker_processes.max(1) as usize
            }
        };

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
        let Some(zone) = (unsafe { shm::register_zone(cf, &mut zone_name, zone_size, module) })
        else {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "otel: failed to register shared memory zone"
                );
            }
            return Err(Status::NGX_ERROR);
        };

        // Configure the zone init callback.
        unsafe {
            (*zone).init = Some(shm::otel_shm_zone_init);
            (*zone).data = ptr::from_mut(self).cast();
        }

        self.shm_zone = zone;
        Ok(())
    }

    /// Register the control-plane shared memory zone with nginx.
    ///
    /// Mirrors [`register_shm_zone`] but uses a fixed size
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

        let Some(zone) = (unsafe { shm::register_zone(cf, &mut zone_name, zone_size, module) })
        else {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "otel: failed to register control shared memory zone"
                );
            }
            return Err(Status::NGX_ERROR);
        };

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
    /// `is_access_sample_enabled() || error_log_enabled`.
    /// Sizes the zone for `n_workers` workers.
    /// Parallels [`register_shm_zone`].
    pub fn register_logs_zone(
        &mut self,
        cf: *mut ngx_conf_t,
        module: *mut ngx_module_t,
    ) -> Result<(), Status> {
        let n_workers: usize = unsafe {
            let cycle = (*cf).cycle.as_ref().ok_or(Status::NGX_ERROR)?;
            let core_idx = nginx_sys::ngx_core_module.index;
            let raw_conf: *mut *mut *mut core::ffi::c_void = *cycle.conf_ctx.add(core_idx);
            let core_conf: *const nginx_sys::ngx_core_conf_t = raw_conf.cast();
            if core_conf.is_null() {
                1
            } else {
                (*core_conf).worker_processes.max(1) as usize
            }
        };

        let cap = self.log_ring_cap();
        let zone_size = shm::logs_zone_size_for(n_workers, cap);
        let mut zone_name = ngx::ngx_string!("ngx_http_otel_logs_zone");

        let Some(zone) = (unsafe { shm::register_zone(cf, &mut zone_name, zone_size, module) })
        else {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "otel: failed to register logs shared memory zone"
                );
            }
            return Err(Status::NGX_ERROR);
        };

        unsafe {
            (*zone).init = Some(shm::logs_shm_zone_init);
            // Store `cap` as a tagged pointer in `zone.data` so the init
            // callback can stamp it into every ring header without needing a
            // MainConfig pointer (which would be stale after a reload).
            (*zone).data = cap as *mut core::ffi::c_void;
        }

        self.logs_shm_zone = zone;
        Ok(())
    }

    /// Returns the base address of our LogsWorkerSlot data within the logs shm zone.
    ///
    /// Parallels [`shm_base`].  Returns `None` if the logs zone was not
    /// registered (access log disabled) or not yet mapped.
    pub fn logs_shm_base(&self) -> Option<*mut u8> {
        let zone = unsafe { self.logs_shm_zone.as_ref()? };
        let addr = zone.shm.addr;
        if addr.is_null() {
            return None;
        }
        Some(unsafe { addr.cast::<u8>().add(crate::shm::data_offset()) })
    }

    /// Returns `true` when `otel_access_log_sample <size>` was configured.
    ///
    /// `access_sample_size == 0` = not configured → off (default).
    /// `access_sample_size > 0` = configured → exception tail + exemplar sampling on.
    ///
    /// The histogram is always-on regardless; this gate controls only the tail ring
    /// and exemplar reservoir.
    #[inline]
    pub fn is_access_sample_enabled(&self) -> bool {
        self.access_sample_size > 0
    }

    /// Effective exemplar reservoir size (from `otel_access_log_sample <size>`).
    ///
    /// Returns 0 when the directive was not configured.
    #[inline]
    pub fn access_sample_size(&self) -> usize {
        self.access_sample_size
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
            let cscf: *mut ngx_http_core_srv_conf_t = unsafe { *srv_ptr.add(i) };
            if cscf.is_null() {
                continue;
            }
            // Get the server block's root location conf.
            let ctx = unsafe { (*cscf).ctx };
            if ctx.is_null() {
                continue;
            }
            let core_ctx_idx = unsafe { nginx_sys::ngx_http_core_module.ctx_index };
            let loc_conf_arr = unsafe { (*ctx).loc_conf };
            if loc_conf_arr.is_null() {
                continue;
            }
            let root_clcf: *mut ngx_http_core_loc_conf_t =
                unsafe { (*loc_conf_arr.add(core_ctx_idx)).cast() };
            if root_clcf.is_null() {
                continue;
            }
            // Walk the static location tree rooted here.
            let static_locs = unsafe { (*root_clcf).static_locations };
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
        let n = unsafe { &*node };

        // Register the exact-match location at this node (if any).
        if !n.exact.is_null() {
            unsafe { self.try_register_route(n.exact) };
        }
        // Register the inclusive (prefix-match) location if different from exact.
        if !n.inclusive.is_null() && n.inclusive != n.exact {
            unsafe { self.try_register_route(n.inclusive) };
        }

        // Recurse into sub-locations (the `tree` subtree = inner `location {}` blocks
        // that share the current prefix).
        unsafe { self.walk_location_tree(n.tree) };
        // Recurse into sibling nodes.
        unsafe { self.walk_location_tree(n.left) };
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

        let clcf = unsafe { &*clcf_ptr };
        let name = clcf.name; // ngx_str_t
        let len = name.len.min(ROUTE_NAME_MAX);

        let idx = self.n_routes;
        self.route_table[idx].clcf_ptr = ptr_val;
        self.route_table[idx].name_len = len as u8;
        if len > 0 && !name.data.is_null() {
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

        let _cf_ref = unsafe { &*cf };

        // Access the upstream module's main conf via its ctx_index.
        // `ngx_http_upstream_module.ctx_index` is the position in the HTTP
        // main_conf array.  We navigate the same way as for the core module.
        let ctx_index = unsafe { nginx_sys::ngx_http_upstream_module.ctx_index };

        // Get the HTTP conf ctx from cf (same approach used by NgxHttpCoreModule).
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
        let main_conf_arr = unsafe { (*http_conf_ctx).main_conf };
        if main_conf_arr.is_null() {
            return;
        }

        let umcf_ptr = unsafe { *main_conf_arr.add(ctx_index) };
        if umcf_ptr.is_null() {
            return;
        }
        let umcf: *const nginx_sys::ngx_http_upstream_main_conf_t = umcf_ptr.cast();

        let n_upstreams = unsafe { (*umcf).upstreams.nelts };
        let up_ptr = unsafe { (*umcf).upstreams.elts.cast::<*mut ngx_http_upstream_srv_conf_t>() };
        for i in 0..n_upstreams {
            let uscf: *mut ngx_http_upstream_srv_conf_t = unsafe { *up_ptr.add(i) };
            if uscf.is_null() {
                continue;
            }
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

            let name = unsafe { (*shm_zone).shm.name }; // ngx_str_t
            let len = name.len.min(UPSTREAM_NAME_MAX);
            let idx = self.n_upstreams;
            self.upstream_table[idx].shm_zone_ptr = zone_ptr;
            self.upstream_table[idx].name_len = len as u8;
            if len > 0 && !name.data.is_null() {
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
        let zone = unsafe { self.shm_zone.as_ref()? };
        let addr = zone.shm.addr;
        if addr.is_null() {
            return None;
        }
        Some(unsafe { addr.cast::<u8>().add(crate::shm::data_offset()) })
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
    /// # Hot-path note (Sub-item 2)
    /// Workers call this from `LogPhaseHandler` on every request. The
    /// `None`-returning path (module disabled) is a null pointer check,
    /// which is a single branch — zero allocations, zero syscalls.
    pub fn control_shm_ptr(&self) -> Option<*const crate::exporter::control_shm::ControlShm> {
        let zone = unsafe { self.control_shm_zone.as_ref()? };
        let addr = zone.shm.addr;
        if addr.is_null() {
            return None;
        }
        let offset = crate::shm::data_offset();
        Some(unsafe {
            addr.cast::<u8>().add(offset).cast::<crate::exporter::control_shm::ControlShm>()
        })
    }
}

/* ─────────────────────────── inner exporter block ─────────────────────────── */

/// Commands valid inside `otel_exporter { ... }`.
static mut NGX_HTTP_OTEL_EXPORTER_COMMANDS: [ngx_command_t; 3] = [
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
    ngx_command_t::empty(),
];

extern "C" fn cmd_exporter_set_endpoint(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };

    if !ecf.endpoint.is_empty() {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let args = unsafe { cf_args(cf) };
    ecf.endpoint = args[1];
    NGX_CONF_OK
}

extern "C" fn cmd_exporter_set_trusted_cert(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let ecf = unsafe { conf.cast::<ExporterConfig>().as_mut().expect("exporter config") };

    if !ecf.trusted_cert.is_empty() {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let args = unsafe { cf_args(cf) };
    ecf.trusted_cert = args[1];
    NGX_CONF_OK
}

/// Dispatcher invoked by ngx_conf_parse for each directive inside the
/// `otel_exporter { ... }` block.
extern "C" fn cmd_exporter_block_handler(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _dummy: *mut c_void,
) -> *mut c_char {
    let args = unsafe { cf_args(cf) };

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
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "invalid number of arguments in \"{}\" directive",
                    args[0]
                );
            }
            return NGX_CONF_ERROR;
        }
        let handler = cmd.set.expect("command handler");
        return unsafe { handler(cf, cmd, (*cf).handler_conf) };
    }

    unsafe {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            &mut *cf,
            "unknown directive \"{}\" in otel_exporter block",
            args[0]
        );
    }
    NGX_CONF_ERROR
}

/* ─────────────────────────── top-level commands ────────────────────────────── */

// Production build: 12 commands + 1 terminator.
// test-support build: 12 commands + otel_status_endpoint + 1 terminator.
// Two separate definitions so the string "otel_status_endpoint" is absent
// from production .so files (verified by grep on objs-release/).

/// Shared production commands (indices 0–11 in both builds).
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
            // otel_metric_batch_size <count>;
            ngx_command_t {
                name: ngx_string!("otel_metric_batch_size"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(cmd_set_metric_batch_size),
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
            // otel_grpc_smoke_endpoint <url>;  TEST-ONLY (Phase 1.2 Item 1).
            // Parsed in all builds but only acted on with test-support feature.
            ngx_command_t {
                name: ngx_string!("otel_grpc_smoke_endpoint"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(nginx_sys::ngx_conf_set_str_slot),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: mem::offset_of!(MainConfig, grpc_smoke_endpoint),
                post: ptr::null_mut(),
            },
            // otel_grpc_bidi_smoke_endpoint <url>;  TEST-ONLY (Phase 1.2 Item 2).
            ngx_command_t {
                name: ngx_string!("otel_grpc_bidi_smoke_endpoint"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(nginx_sys::ngx_conf_set_str_slot),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: mem::offset_of!(MainConfig, bidi_smoke_endpoint),
                post: ptr::null_mut(),
            },
            // otel_metric_high_cardinality_attr <attr>;
            ngx_command_t {
                name: ngx_string!("otel_metric_high_cardinality_attr"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(cmd_add_high_cardinality_attr),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_grpc_bidi_overload_endpoint <url>;  TEST-ONLY (Phase 1.2 Item 3).
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
            // "arrow" is rejected with a "not yet implemented (Phase 5)" message.
            ngx_command_t {
                name: ngx_string!("otel_export_protocol"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(cmd_set_export_protocol),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_access_log_sample <size>;  (Phase 2.2 DP-D)
            // Enables the exception tail + exemplar reservoir and sizes the
            // per-worker exemplar reservoir to <size> entries.  Absent ⇒ off.
            // The histogram is always-on regardless of this directive.
            ngx_command_t {
                name: ngx_string!("otel_access_log_sample"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
                set: Some(cmd_set_access_sample),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
            // otel_log_ring_size <size>;  (Phase 2.1 FU3)
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
            // otel_error_log [<level>];  (Phase 2.3 §6.6.2)
            // Enables OTel error-log export via a ngx_log_writer_pt writer node.
            // NOARGS ⇒ mirror the core error_log level; TAKE1 ⇒ explicit override.
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
            // otel_error_log_coalesce on|off;  (Phase 2.3 §6.6.2)
            // Default: on.  `off` ⇒ bypass the coalescer and push every
            // level-passing line verbatim to the bounded ring.
            //
            // ⚠️ WARNING: `off` is best-effort, NOT guaranteed delivery.
            // The ring drops-newest under load; lost lines are accounted in
            // dropped_records but gone.  The only guaranteed full-fidelity
            // transcript is nginx's own (untouched) error_log file.
            // The companion error-rate metric (DP-B) counts the true total
            // in both modes; only the bodies are potentially lost.
            ngx_command_t {
                name: ngx_string!("otel_error_log_coalesce"),
                type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG) as ngx_uint_t,
                set: Some(cmd_set_error_log_coalesce),
                conf: NGX_HTTP_MAIN_CONF_OFFSET,
                offset: 0,
                post: ptr::null_mut(),
            },
        ]
    };
}

/// Production build: 17 production commands + terminator.
#[cfg(not(any(test, feature = "test-support")))]
pub static mut NGX_HTTP_OTEL_COMMANDS: [ngx_command_t; 18] = {
    let mut cmds = [ngx_command_t::empty(); 18];
    let prod = production_commands!();
    let mut i = 0;
    while i < 17 {
        cmds[i] = prod[i];
        i += 1;
    }
    // cmds[17] stays empty() — terminator
    cmds
};

/// test-support build: 17 production commands + otel_status_endpoint + terminator.
///
/// `otel_status_endpoint;` is a location-level directive (no args) that registers
/// a content handler returning `control_shm.version` as plain text. Used by the
/// heartbeat integration test to read the exporter's liveness counter without
/// process-level introspection. Absent from production builds (verified by grep
/// on `objs-release/ngx_http_otel_module.so`).
#[cfg(any(test, feature = "test-support"))]
pub static mut NGX_HTTP_OTEL_COMMANDS: [ngx_command_t; 19] = {
    let mut cmds = [ngx_command_t::empty(); 19];
    let prod = production_commands!();
    let mut i = 0;
    while i < 17 {
        cmds[i] = prod[i];
        i += 1;
    }
    // Index 17: otel_status_endpoint (test-support only).
    cmds[17] = ngx_command_t {
        name: ngx_string!("otel_status_endpoint"),
        type_: (nginx_sys::NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS) as ngx_uint_t,
        set: Some(cmd_set_otel_status_endpoint),
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    };
    // cmds[18] stays empty() — terminator.
    cmds
};

/* ─────────────────────────── command handlers ──────────────────────────────── */

extern "C" fn cmd_set_exporter_block(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.exporter.is_set() {
        unsafe {
            ngx_conf_log_error!(NGX_LOG_EMERG, &mut *cf, "\"otel_exporter\" is duplicate");
        }
        return NGX_CONF_ERROR;
    }

    let mut block_cf: ngx_conf_t = unsafe { *cf };
    block_cf.handler = Some(cmd_exporter_block_handler);
    block_cf.handler_conf = ptr::addr_of_mut!(amcf.exporter).cast();

    unsafe { ngx_conf_parse(&mut block_cf, ptr::null_mut()) }
}

extern "C" fn cmd_add_resource_attr(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };
    let args = unsafe { cf_args(cf) };
    amcf.resource_attrs.push(KvPair { key: args[1], value: args[2] });
    NGX_CONF_OK
}

extern "C" fn cmd_add_exporter_header(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };
    let args = unsafe { cf_args(cf) };
    amcf.exporter_headers.push(KvPair { key: args[1], value: args[2] });
    NGX_CONF_OK
}

extern "C" fn cmd_set_metric_interval(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.metric_interval_ms != UNSET_U64 {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let args = unsafe { cf_args(cf) };
    match parse_duration_ms(args[1].as_bytes()) {
        Some(ms) if ms > 0 => {
            amcf.metric_interval_ms = ms;
            NGX_CONF_OK
        }
        _ => {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "invalid duration in \"otel_metric_interval\": \"{}\"",
                    args[1]
                );
            }
            NGX_CONF_ERROR
        }
    }
}

extern "C" fn cmd_set_metric_batch_size(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.metric_batch_size != UNSET_U64 {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let args = unsafe { cf_args(cf) };
    match parse_u64_ascii(args[1].as_bytes()) {
        Some(n) if n > 0 => {
            amcf.metric_batch_size = n;
            NGX_CONF_OK
        }
        _ => {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "invalid value in \"otel_metric_batch_size\": \"{}\"",
                    args[1]
                );
            }
            NGX_CONF_ERROR
        }
    }
}

extern "C" fn cmd_set_metric_zone(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.zone_size > 0 {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let args = unsafe { cf_args(cf) };
    // args[1] = name, args[2] = size (e.g. "10m", "1g")
    let size = match parse_size_bytes(args[2].as_bytes()) {
        Some(s) if s > 0 => s,
        _ => {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "invalid size in \"otel_metric_zone\": \"{}\"",
                    args[2]
                );
            }
            return NGX_CONF_ERROR;
        }
    };

    amcf.zone_name = args[1];
    amcf.zone_size = size;
    NGX_CONF_OK
}

extern "C" fn cmd_add_high_cardinality_attr(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };
    let args = unsafe { cf_args(cf) };

    let attr = args[1];
    let valid = attr.as_bytes() == b"url.path"
        || attr.as_bytes() == b"client.address"
        || attr.as_bytes() == b"user_agent.original";

    if !valid {
        unsafe {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &mut *cf,
                "unknown high-cardinality attr \"{}\"; valid values: url.path, client.address, user_agent.original",
                attr
            );
        }
        return NGX_CONF_ERROR;
    }

    amcf.high_cardinality_attrs.push(attr);
    NGX_CONF_OK
}

/// Directive callback for `otel_export_protocol otlp_http | otlp_grpc;`.
///
/// Accepts `otlp_http` and `otlp_grpc`.  Rejects `arrow` with a
/// "not yet implemented (Phase 5)" message.  Rejects any other value with
/// an "unknown value" message listing the valid choices.
extern "C" fn cmd_set_export_protocol(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.metric_protocol.is_some() {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let args = unsafe { cf_args(cf) };
    let value = args[1].as_bytes();

    if value == b"otlp_http" {
        amcf.metric_protocol = Some(MetricProtocol::OtlpHttp);
        NGX_CONF_OK
    } else if value == b"otlp_grpc" {
        amcf.metric_protocol = Some(MetricProtocol::OtlpGrpc);
        NGX_CONF_OK
    } else if value == b"arrow" {
        unsafe {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &mut *cf,
                "otel_export_protocol: \"arrow\" is not yet implemented (Phase 5)"
            );
        }
        NGX_CONF_ERROR
    } else {
        unsafe {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &mut *cf,
                "otel_export_protocol: unknown value \"{}\"; valid values: otlp_http, otlp_grpc",
                args[1]
            );
        }
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
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.log_ring_size > 0 {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let args = unsafe { cf_args(cf) };
    let raw = args[1].as_bytes();

    match parse_size_bytes(raw) {
        Some(n) if n > 0 => {
            amcf.log_ring_size = n;
            NGX_CONF_OK
        }
        _ => {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "otel_log_ring_size: invalid size (use e.g. \"512k\" or \"1m\")"
                );
            }
            NGX_CONF_ERROR
        }
    }
}

/// Directive callback for `otel_access_log_sample <size>;` (Phase 2.2 DP-D).
///
/// Enables the exception-tail ring + exemplar reservoir and sizes the per-worker
/// reservoir to `<size>` entries.  Must be ≥ 1.  Parsed as a plain integer
/// (e.g. `16` or `32`).
extern "C" fn cmd_set_access_sample(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.access_sample_size > 0 {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let args = unsafe { cf_args(cf) };
    let raw = args[1].as_bytes();

    match parse_size_bytes(raw) {
        Some(n) if n > 0 => {
            amcf.access_sample_size = n;
            NGX_CONF_OK
        }
        _ => {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "otel_access_log_sample: invalid size; must be a positive integer (e.g. \"16\")"
                );
            }
            NGX_CONF_ERROR
        }
    }
}

/// Directive callback for `otel_error_log [<level>];` (Phase 2.3 §6.6.2).
///
/// Inserts a writer-only `ngx_log_t` node into `cycle->new_log` via
/// `otel_log_insert`.  The node calls `ngx_otel_error_writer` for every error
/// that passes the severity floor.
///
/// - **NOARGS** (bare `otel_error_log;`) — mirrors the core `error_log` level
///   (`cf->cycle->new_log.log_level`, the effective level at config time).  The
///   OTel stream and the file stream match by default.
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
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };

    if amcf.error_log_enabled {
        unsafe {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                &mut *cf,
                "\"otel_error_log\" is duplicate"
            );
        }
        return NGX_CONF_ERROR;
    }

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
                        &mut *cf,
                        "otel_error_log: unknown level; use emerg|alert|crit|error|warn|notice|info|debug"
                    );
                    return NGX_CONF_ERROR;
                }
            }
        } else {
            // NOARGS: mirror the core error_log level.
            // `cycle->new_log` is the current chain head at config time;
            // its log_level is the effective core error_log level.
            let cycle = (*cf).cycle;
            if cycle.is_null() {
                ngx_conf_log_error!(NGX_LOG_EMERG, &mut *cf, "otel_error_log: null cycle");
                return NGX_CONF_ERROR;
            }
            (*cycle).new_log.log_level
        }
    };

    // Allocate the ngx_log_t node and OtelErrorWriterState from the config pool.
    // ngx_pcalloc zero-initialises both — AtomicBool(false), null ptr, 0 level
    // are the correct "unset" defaults.
    let (new_log, state) = unsafe {
        let pool = (*cf).pool;
        if pool.is_null() {
            ngx_conf_log_error!(NGX_LOG_EMERG, &mut *cf, "otel_error_log: null pool");
            return NGX_CONF_ERROR;
        }
        let log_ptr = nginx_sys::ngx_pcalloc(pool, mem::size_of::<nginx_sys::ngx_log_t>())
            as *mut nginx_sys::ngx_log_t;
        if log_ptr.is_null() {
            ngx_conf_log_error!(NGX_LOG_EMERG, &mut *cf, "otel_error_log: ngx_pcalloc failed for log node");
            return NGX_CONF_ERROR;
        }
        let state_ptr =
            nginx_sys::ngx_pcalloc(pool, mem::size_of::<OtelErrorWriterState>())
                as *mut OtelErrorWriterState;
        if state_ptr.is_null() {
            ngx_conf_log_error!(NGX_LOG_EMERG, &mut *cf, "otel_error_log: ngx_pcalloc failed for writer state");
            return NGX_CONF_ERROR;
        }
        (log_ptr, state_ptr)
    };

    // Fill the log node.  Writer-only: no `file` set (so this node never writes
    // to any file; the core file node still writes via chain continuation).
    unsafe {
        (*new_log).log_level = level_floor;
        (*new_log).writer = Some(ngx_otel_error_writer);
        (*new_log).wdata = state as *mut core::ffi::c_void;
        // Fill the state (pcalloc gave us zeros; only non-zero fields needed).
        (*state).level_floor = level_floor;
        // busy, cleanup, logs_zone, coalesce_table stay zero/null — correct defaults.
        // coalesce_enabled is false until init_process (Step 2.3.5) sets it from
        // MainConfig::error_log_coalesce; the coalescer path is gated on
        // coalesce_table != null anyway, so false here is harmless.
    }

    // Insert into cycle->new_log chain (sorted descending by log_level).
    // cycle->new_log is an embedded ngx_log_t value (never null); confirmed:
    // ngx_cycle.h:43-44: `ngx_log_t *log; ngx_log_t new_log;` — `new_log` is a value.
    unsafe {
        let cycle = (*cf).cycle;
        otel_log_insert(ptr::addr_of_mut!((*cycle).new_log), new_log);
    }

    amcf.error_log_enabled = true;
    amcf.error_log_level = level_floor;

    NGX_CONF_OK
}

/// Directive callback for `otel_error_log_coalesce on|off;` (Phase 2.3 §6.6.2).
///
/// Sets `amcf.error_log_coalesce`.  The standard nginx flag handler
/// (`ngx_conf_set_flag_slot`) is not used here because `error_log_coalesce`
/// is a plain Rust `bool`, not a `ngx_flag_t` (`intptr_t`).
extern "C" fn cmd_set_error_log_coalesce(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let amcf = unsafe { conf.cast::<MainConfig>().as_mut().expect("main config") };
    let args = unsafe { cf_args(cf) };
    let val = args[1].as_bytes();
    match val {
        b"on" => amcf.error_log_coalesce = true,
        b"off" => amcf.error_log_coalesce = false,
        _ => {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "otel_error_log_coalesce: invalid value; use on or off"
                );
            }
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

    let cf_ref = unsafe { &*cf };
    let clcf = match NgxHttpCoreModule::location_conf_mut(cf_ref) {
        Some(c) => c,
        None => {
            unsafe {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    &mut *cf,
                    "otel_status_endpoint: failed to get core location conf"
                );
            }
            return NGX_CONF_ERROR;
        }
    };
    clcf.handler = Some(crate::otel_status_content_handler);
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
    (n as usize).checked_mul(mult)
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
        assert_eq!(cfg.batch_size(), DEFAULT_BATCH_SIZE);
        assert!(cfg.status_code_class_enabled()); // UNSET treated as on
        // exception-tail / exemplar sampling is off by default (Phase 2.2)
        assert!(!cfg.is_access_sample_enabled(), "access sample must default to off");
        // error-log export is off by default (Phase 2.3)
        assert!(!cfg.error_log_enabled, "error_log_enabled must default to false");
        assert!(cfg.error_log_coalesce, "error_log_coalesce must default to true (on)");
    }

    /// Verify that setting `error_log_enabled` and `error_log_coalesce` toggles
    /// the fields correctly.  The directive handler (`cmd_set_error_log`) is
    /// exercised by integration tests that use a real nginx.conf.
    #[test]
    fn error_log_directive_toggles_enablement() {
        let mut cfg = MainConfig::default();
        assert!(!cfg.error_log_enabled);
        assert!(cfg.error_log_coalesce); // default on
        // Simulate cmd_set_error_log setting fields (mirrors what the handler does).
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

    /// Verify that `otel_access_log_sample` toggles `is_access_sample_enabled()`
    /// and records the reservoir size.
    ///
    /// This is a unit test of the accessor and field — the directive handler
    /// (`cmd_set_access_sample`) is exercised implicitly by integration tests that
    /// send a real nginx.conf containing `otel_access_log_sample 16;`.
    #[test]
    fn access_sample_directive_toggles_enablement() {
        let mut cfg = MainConfig::default();
        // Default: off (0).
        assert!(!cfg.is_access_sample_enabled());
        assert_eq!(cfg.access_sample_size(), 0);
        // Set directly (mirrors what cmd_set_access_sample does).
        cfg.access_sample_size = 16;
        assert!(cfg.is_access_sample_enabled());
        assert_eq!(cfg.access_sample_size(), 16);
        cfg.access_sample_size = 0;
        assert!(!cfg.is_access_sample_enabled());
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
    /// FU1: no "(none)" slot — requests without upstream skip the upstream histogram.
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
}
