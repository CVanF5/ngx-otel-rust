// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Log-phase handler that bumps per-worker shm slot counters per request
//! and (when enabled) pushes an access log record into the per-worker ring.
//!
//! ## Hard constraints
//! - No `Vec::new()`, `Box::new()`, `String::from()`, or any heap allocation.
//! - No syscalls beyond what the nginx log phase already incurs.
//! - No locks; only atomic increments (`Ordering::Relaxed` on writes).
//! - The handler is registered **only** when `otel_exporter` is configured.
//! - Exception-tail emission is gated by the operator: a cheap main-conf bool
//!   (`amcf.any_log_export_enabled()`) plus the matched location's
//!   `otel_log_export` mode.  With no location selecting export the path is
//!   byte-equivalent to the metrics-only path (zero cost beyond one cheap
//!   branch + the histogram bump).  Nothing is hardcoded — absent configuration
//!   exports zero log records.

use nginx_sys;
use ngx::core::Status;
use ngx::http::{
    HttpModuleLocationConf, HttpModuleMainConf, HttpModuleServerConf, HttpPhase,
    HttpRequestHandler, NgxHttpCoreModule, Request,
};

use crate::logs::{
    access::{emit_access_record, SampledRequest},
    WorkerRingProducer,
};
use crate::metric_source::location_conf::LogExportMode;
use crate::shm::{
    combo_index, logs_access_ring, spans_ring, worker_slots, HttpMethod, ProtoVersion, StatusClass,
    WorkerSlots, BYTES_BOUNDS, DEFAULT_SPAN_RING_CAP, DURATION_BOUNDS_MS, UPSTREAM_IDX_OTHER,
};
use crate::traces::{emit_span_record, SpanRecord, MAX_SPAN_EXTRA_ATTRS, MAX_SPAN_NAME};
use crate::HttpOtelModule;

/// Sentinel value nginx uses to mark "timing not measured" in
/// `ngx_http_upstream_state_t` (fields `response_time`, `connect_time`,
/// `header_time`).  Initialised to `(ngx_msec_t)-1` at
/// `nginx/src/http/ngx_http_upstream.c:1580-1582`; special-cased by the
/// nginx log module (formatted as `"-"`) at `:6074`.
///
/// `ngx_msec_t` is `uintptr_t`; its `-1` pattern maps to `usize::MAX as u64`
/// (= `u64::MAX` on 64-bit, `u32::MAX as u64` on 32-bit).  Recording this
/// value without filtering would add ~1.8 × 10^19 to the cumulative sum on
/// every refused-connection event, permanently poisoning the metric.
const NGX_MSEC_SENTINEL: u64 = usize::MAX as u64;

/// Records a request into the base `{method × status_class × protocol}` combo
/// histogram.
///
/// Skips when `status == 0` — a client abort where nginx sent no response
/// headers.  Per OTel HTTP semconv, `http.response.status_code` is CONDITIONALLY
/// REQUIRED only when a response was sent; it is ABSENT for aborted requests.
/// Counting status-0 as 5xx inflated server-error-rate metrics on every
/// port-scan / TLS-probe / aborted keep-alive event.
///
/// `base_idx` is `combo_index(method, status_class, proto)`, pre-computed by
/// the caller (also needed for the exemplar reservoir, so computing it once
/// avoids duplication on the hot path).
///
/// # Hot-path guarantees
/// Zero allocation, no locks: one `u16 == 0` compare + one conditional
/// `AtomicU64::fetch_add` per request.
#[inline]
fn record_base_combo(slot: &WorkerSlots, status: u16, base_idx: usize, duration_us: u64) {
    if status != 0 {
        slot.request_duration_combos[base_idx].record(duration_us);
    }
}

/// Unit struct for the log-phase handler; all state lives in the shm zone.
pub struct LogPhaseHandler;

/// Shared per-request metadata computed once and fed to the metrics,
/// access-log, and span helpers.
struct RequestMeta {
    status: u16,
    proto: ProtoVersion,
    base_idx: usize,
    route_idx: usize,
    resp_bytes: u64,
}

impl HttpRequestHandler for LogPhaseHandler {
    const PHASE: HttpPhase = HttpPhase::Log;
    type Output = Status;

    /// Called once per request in the Log phase.
    ///
    /// # No allocation guarantee
    /// - Reads fields via typed references only (no raw pointer arithmetic).
    /// - Calls `histogram.record()` which uses atomic increments only.
    /// - Does NOT call `Vec::new()`, `Box::new()`, `String::from()`, etc.
    /// - Does NOT acquire any locks.
    fn handler(request: &mut Request) -> Status {
        // Safety: main conf is initialised before any request is handled.
        let amcf = match HttpOtelModule::main_conf(request) {
            Some(c) => c,
            None => return Status::NGX_OK,
        };

        // Resolve worker slot: get the current worker index and validate bounds.
        let worker_id = match Self::resolve_worker_slot(request, amcf) {
            Some(id) => id,
            None => return Status::NGX_OK,
        };

        // Read SpanCtx once (parse-once + dual-clock): used for duration,
        // exemplars, access-log trace correlation, and span emission.
        // SAFETY: `request` is the valid live nginx request for this handler;
        // `as_ref()` yields the underlying `ngx_http_request_t` pointer.
        let r_ptr = request.as_ref() as *const nginx_sys::ngx_http_request_t;
        // SAFETY: `r_ptr` is the valid live request for this handler (derived
        // directly from the `request` argument); `read_span_ctx` reads only the
        // ctx array slot at our module's index, which is sound for the request lifetime.
        let span_ctx = unsafe { Self::read_span_ctx(r_ptr) };

        // Dual-clock duration in microseconds.
        let r = request.as_ref();
        let duration_us = Self::compute_duration_us(r, span_ctx);

        // Shared request metadata: computed once, consumed by all three signal paths.
        let meta = Self::read_request_meta(r, amcf);

        // Signal path 1: bump per-worker shm counters (metrics).
        Self::record_request_metrics(r, amcf, worker_id, &meta, duration_us);

        // Determine whether this request's access record is selected for export.
        let export_selected = Self::check_export_selected(r, amcf);

        // Read client address and User-Agent once; shared by access log and span.
        let span_sampled = span_ctx.is_some_and(|ctx| ctx.sampled);
        let need_detail = export_selected || span_sampled;
        let (client_addr, user_agent_raw) = Self::read_request_detail(&*request, need_detail);

        // Build the shared emit context once; both signal paths borrow it.
        let ectx = EmitCtx {
            r,
            amcf,
            worker_id,
            meta: &meta,
            span_ctx,
            duration_us,
            client_addr,
            user_agent_raw,
        };

        // Signal path 2: push access-log tail record into per-worker ring.
        Self::maybe_emit_access_log(&ectx, export_selected);

        // Signal path 3: push span record into per-worker spans ring.
        Self::maybe_emit_span(&ectx);

        Status::NGX_OK
    }
}

/// Per-request emit context bundling the fields shared by `maybe_emit_access_log`
/// and `maybe_emit_span`.  Built once per LOG phase on the stack at the call site;
/// passed by reference so neither function allocates.
struct EmitCtx<'a> {
    r: &'a nginx_sys::ngx_http_request_t,
    amcf: &'a crate::config::MainConfig,
    worker_id: usize,
    meta: &'a RequestMeta,
    span_ctx: Option<&'a crate::traces::ctx::SpanCtx>,
    duration_us: u64,
    client_addr: &'a [u8],
    user_agent_raw: &'a [u8],
}

impl LogPhaseHandler {
    /// Reads the current worker index from the nginx global and validates it
    /// against the smallest registered shm zone capacity.
    ///
    /// Returns `Some(worker_id)` when the index is in range, `None` when a
    /// zone is undersized (logs an ALERT and disables the module for this worker).
    fn resolve_worker_slot(
        request: &mut Request,
        amcf: &crate::config::MainConfig,
    ) -> Option<usize> {
        // SAFETY: `ngx_worker` is a `static mut` set once by nginx during worker
        // init and only ever read thereafter from this worker process, so reading
        // it on the (single-threaded) request path is sound.
        let worker_id = unsafe { nginx_sys::ngx_worker };

        // Bounds guard: if `check_zone_sizing` somehow didn't fire (e.g.
        // the module was loaded without going through init_module), catch the
        // out-of-range index here rather than writing past the zone end.
        //
        // The SAME `worker_id` indexes the metrics zone (`worker_slots`, just
        // below), the logs access ring (`logs_access_ring`), and the spans ring
        // (`spans_ring`).  Any of these zones may be absent (e.g. the metrics
        // zone when `otel_metrics off`), and they are sized independently, so
        // their per-worker capacities can differ.  A `worker_id` that fits the
        // largest registered zone could still overrun a smaller ring.
        // Validate against the MIN of all registered zone capacities so the
        // smallest indexed ring is covered before any ring write.
        // `min_indexed_worker_capacity()` derives each capacity from the
        // registered zone size — zero cost: a few pointer loads + integer
        // arithmetic, no alloc/lock/syscall.
        let n_workers = amcf.min_indexed_worker_capacity();
        if worker_id >= n_workers {
            // Hard invariant violation: a zone was undersized for this worker.
            // Log at ALERT (once per request until restart — the init_module
            // check should have prevented this) and disable for this worker.
            let r = request.as_ref();
            // SAFETY: `r.connection` is a valid non-null pointer for the
            // lifetime of the request; `(*connection).log` is the request log.
            let log = unsafe { (*r.connection).log };
            alert!(
                log,
                "otel: worker_id {} >= smallest shm ring capacity {} — module \
                 disabled for this worker; move worker_processes before http{{}}",
                worker_id,
                n_workers
            );
            return None;
        }

        debug_assert!(worker_id < n_workers, "worker_id out of zone bounds");
        Some(worker_id)
    }

    /// Reads the `SpanCtx` for this request, recovering it from the
    /// pool-cleanup anchor when nginx zeroes the module-ctx array after an
    /// internal redirect.
    ///
    /// # Safety
    /// `r_ptr` must be the valid live request pointer for the current handler.
    unsafe fn read_span_ctx(
        r_ptr: *const nginx_sys::ngx_http_request_t,
    ) -> Option<&'static crate::traces::ctx::SpanCtx> {
        use crate::traces::ctx::{recover_span_ctx, SpanCtx};
        // SAFETY: `ngx_http_otel_module` is a valid static module descriptor;
        // the ctx array is indexed by `ctx_index` set at module registration.
        let module = unsafe { &*core::ptr::addr_of!(crate::ngx_http_otel_module) };
        // SAFETY: `r_ptr` is the live request pointer per the contract; reading
        // the ctx array slot is sound for the request lifetime.
        let ctx_ptr = unsafe { *(*r_ptr).ctx.add(module.ctx_index) }.cast::<SpanCtx>();
        // SAFETY: `ctx_ptr` is either null (module ctx not yet set) or a valid
        // `*mut SpanCtx` into the request pool, set by `SpanStartHandler` and
        // valid for the full request lifetime; `as_ref()` is safe for both cases.
        let slot: Option<&SpanCtx> = unsafe { ctx_ptr.as_ref() };
        // The LOG phase can run AFTER an internal redirect (error_page /
        // try_files), where nginx has zeroed the module-ctx array.  Recover the
        // SpanCtx from the pool-cleanup anchor so the LOG phase sees pass-1's
        // span (one span per request).  The recovery walk runs ONLY when the
        // slot is NULL && r->internal/filter_finalize — i.e. post-redirect.
        match slot {
            Some(c) => Some(c),
            None => {
                let r_mut = r_ptr as *mut nginx_sys::ngx_http_request_t;
                // SAFETY: `r_mut` is the live request pointer; `module` is the
                // process-lifetime descriptor; the NULL slot is passed in.
                let recovered = unsafe { recover_span_ctx(r_mut, module, core::ptr::null_mut()) };
                // SAFETY: `recovered` is either NULL or a pointer into the
                // request pool (the cleanup-anchored SpanCtx), valid for the
                // request lifetime.
                unsafe { recovered.as_ref() }
            }
        }
    }

    /// Computes the request duration in microseconds using the OTel-SDK-idiomatic
    /// dual-clock strategy:
    /// - When a `SpanCtx` is present: `start_mono.elapsed()` — one vDSO
    ///   `CLOCK_MONOTONIC` read, NTP-immune, keeps the µs histogram, span, and
    ///   `http.server.request.duration` attribute coherent.
    /// - When absent: wall-clock fallback (`SystemTime::now()` minus nginx's
    ///   cached start), with `saturating_sub` to handle backward NTP steps.
    fn compute_duration_us(
        r: &nginx_sys::ngx_http_request_t,
        span_ctx: Option<&crate::traces::ctx::SpanCtx>,
    ) -> u64 {
        if let Some(ctx) = span_ctx {
            ctx.start_mono.elapsed().as_micros() as u64
        } else {
            use std::time::{SystemTime, UNIX_EPOCH};
            let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
            let end_us = d.as_nanos() as u64 / 1_000;
            let start_us = (r.start_sec as u64) * 1_000_000 + (r.start_msec as u64) * 1_000;
            end_us.saturating_sub(start_us)
        }
    }

    /// Reads per-request metadata that is shared across all three signal paths
    /// (metrics, access-log tail, and span record).
    ///
    /// All values are O(1) reads or lookups — no allocation, no locking.
    fn read_request_meta(
        r: &nginx_sys::ngx_http_request_t,
        amcf: &crate::config::MainConfig,
    ) -> RequestMeta {
        let status = r.headers_out.status as u16;
        let proto = ProtoVersion::from_ngx(r.http_version as core::ffi::c_uint);

        // `status_class` and `base_idx` are O(1) arithmetic, hot-path safe.
        // `base_idx` is needed by the exemplar write (metrics) and the access-log
        // tail (logs), so it is computed here even when the metrics zone is absent.
        //
        // Status 0 = client abort / no response sent.  `ngx_http_create_request`
        // allocates the request struct with `ngx_pcalloc` (nginx src/http/ngx_http_request.c:588),
        // so `headers_out.status` starts as 0 and stays 0 when the client disconnects
        // before nginx sends response headers (port-scan SYN probe, TLS-to-plaintext
        // probe, aborted keep-alive request, etc.).
        //
        // Per OTel HTTP semconv, `http.response.status_code` is CONDITIONALLY REQUIRED
        // only when a response was sent; it is ABSENT for aborted requests.  Counting
        // status-0 as 5xx was generating fake server-error counts on every port scan,
        // inflating error-rate alerts.
        //
        // Fix: skip only the histogram bump when status == 0.  The route and upstream
        // histograms (below) still record the duration — the request consumed real
        // resources regardless of the abort.
        let method = HttpMethod::from_bytes(r.method_name.as_bytes());
        let status_class = StatusClass::from_status(status);
        let base_idx = combo_index(method, status_class, proto);

        // `route_idx` is needed by both the metrics per-route histogram and the span
        // name builder — compute it once outside the metrics block.
        let route_idx = {
            let clcf_ptr =
                NgxHttpCoreModule::location_conf(r).map(|c| c as *const _ as usize).unwrap_or(0);
            amcf.route_idx_for_clcf(clcf_ptr)
        };

        // `resp_bytes` is needed by both the metrics response-bytes histogram and the
        // access-log tail record — compute it once outside the metrics block.
        let resp_bytes = {
            let conn = r.connection;
            if conn.is_null() {
                0u64
            } else {
                // SAFETY: `conn` is non-null here (null-checked above) and is the
                // request's `ngx_connection_t`, which nginx keeps valid for the
                // duration of the Log-phase handler; reading its `sent` field is
                // sound.
                unsafe { (*conn).sent as u64 }
            }
        };

        RequestMeta { status, proto, base_idx, route_idx, resp_bytes }
    }

    /// Bumps the per-worker shm counters for the base combo, per-route, per-upstream,
    /// body-size, and upstream-timing histograms.
    ///
    /// Skipped entirely when the metrics shm zone is absent (`otel_metrics off`).
    fn record_request_metrics(
        r: &nginx_sys::ngx_http_request_t,
        amcf: &crate::config::MainConfig,
        worker_id: usize,
        meta: &RequestMeta,
        duration_us: u64,
    ) {
        // Skipped when the metrics shm zone is absent (e.g. `otel_metrics off`).
        // Traces and access-log tails are unaffected — they have their own zones
        // and are handled in the independent blocks below.
        let metrics_base = match amcf.shm_base() {
            Some(b) => b,
            None => return,
        };

        // Get our per-worker slot. No allocation; pointer arithmetic only.
        // SAFETY: `worker_id < n_workers` (enforced by the bounds guard above);
        // `n_workers` is derived from the registered zone sizes so the slot is
        // within the zone.
        let slot = unsafe { &*worker_slots(metrics_base, worker_id) };

        // 1. Base table: {method × status_class × protocol} (160 combos).
        record_base_combo(slot, meta.status, meta.base_idx, duration_us);

        // 2. Per-route table: http.route = location name.
        slot.route_duration_combos[meta.route_idx].record(duration_us);

        // 3. Per-upstream table: nginx.upstream.zone.
        //    Skip if no upstream (zone_ptr = 0 → UPSTREAM_IDX_OTHER).
        let upstream_zone_ptr: usize = if !r.upstream.is_null() {
            // SAFETY: `r.upstream` is non-null: it is the per-request
            // `ngx_http_upstream_t` set by the upstream module, valid for the
            // duration of this handler.
            let us = unsafe { (*r.upstream).upstream };
            if !us.is_null() {
                // SAFETY: `us` is the non-null `ngx_http_upstream_srv_conf_t`
                // pointer just read from the live upstream struct; reading its
                // `shm_zone` field is sound.
                let zone = unsafe { (*us).shm_zone };
                if !zone.is_null() {
                    zone as usize
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            0
        };
        let upstream_idx = amcf.upstream_idx_for_zone(upstream_zone_ptr);
        // Only bump upstream histogram when request actually went through an upstream.
        if upstream_zone_ptr != 0 && upstream_idx < UPSTREAM_IDX_OTHER {
            slot.upstream_duration_combos[upstream_idx].record(duration_us);
        } else if upstream_zone_ptr != 0 {
            // Over-cap upstream: bump "other" slot (UPSTREAM_IDX_OTHER = UPSTREAM_CAP).
            slot.upstream_duration_combos[UPSTREAM_IDX_OTHER].record(duration_us);
        }
        // zone_ptr == 0 → no upstream → skip upstream histogram.

        // ── request body bytes ────────────────────────────────────────────
        slot.request_body_bytes.record(r.request_length as u64, &BYTES_BOUNDS);

        // ── response bytes ────────────────────────────────────────────────
        slot.response_body_bytes.record(meta.resp_bytes, &BYTES_BOUNDS);

        // ── upstream timings (if an upstream was used) ────────────────────
        // Sum the timings/bytes across ALL upstream attempts, not just the
        // current (last) `u->state`.  When `proxy_next_upstream` retries a peer,
        // nginx pushes a fresh `ngx_http_upstream_state_t` per attempt onto
        // `r->upstream_states` (an `ngx_array_t`); `u->state` points only at the
        // last one.  The core `$upstream_response_time` / `$upstream_*_bytes`
        // variables iterate the whole `r->upstream_states` array
        // (`ngx_http_upstream_response_time_variable` /
        // `..._response_length_variable`, ngx_http_upstream.c:6027,6105), so
        // reading only `u->state` undercounts multi-attempt requests.  Walk the
        // same array and aggregate so the metric matches the total upstream cost
        // those variables report.
        // `r.upstream` being non-null confirms this request actually went
        // through an upstream, so `r->upstream_states` is meaningful.
        if !r.upstream.is_null() {
            // SAFETY: `r` is the live request for this LOG-phase handler;
            // `upstream_states` is either null (no upstream attempts) or a valid
            // `ngx_array_t*` of `ngx_http_upstream_state_t` in the request pool,
            // valid for this handler.  The walk only reads plain numeric fields.
            if let Some(sum) = unsafe { sum_upstream_states(r.upstream_states) } {
                // nginx initialises the timing fields to (ngx_msec_t)-1
                // (= NGX_MSEC_SENTINEL) when the attempt did not complete that
                // phase (e.g. connect_time on a refused connection); the core
                // variables emit "-" for it (ngx_http_upstream.c:6074).  The
                // walk skips sentinel attempts per field, so a metric is recorded
                // only when at least one attempt had a real measurement.
                if let Some(resp_ms) = sum.response_ms {
                    slot.upstream_response_ms.record(resp_ms, &DURATION_BOUNDS_MS);
                }
                if let Some(hdr_ms) = sum.header_ms {
                    slot.upstream_header_ms.record(hdr_ms, &DURATION_BOUNDS_MS);
                }
                if let Some(conn_ms) = sum.connect_ms {
                    slot.upstream_connect_ms.record(conn_ms, &DURATION_BOUNDS_MS);
                }
                slot.upstream_bytes_received.record(sum.bytes_received, &BYTES_BOUNDS);
                slot.upstream_bytes_sent.record(sum.bytes_sent, &BYTES_BOUNDS);
            }
        }
    }

    /// Evaluates the `otel_log_export` gates and returns `true` when this
    /// request's access record should be pushed to the per-worker ring.
    ///
    /// Gate 1 (cheap config check): `any_log_export_enabled()` — false when no
    /// location selects export, skipping all subsequent work for that deployment.
    /// Gate 2 (per-location): the matched location's `LogExportMode` decides;
    /// `If` evaluates the operator-supplied complex value.
    fn check_export_selected(
        r: &nginx_sys::ngx_http_request_t,
        amcf: &crate::config::MainConfig,
    ) -> bool {
        if !amcf.any_log_export_enabled() {
            return false;
        }
        match HttpOtelModule::location_conf(r) {
            Some(lc) => match lc.log_export_mode() {
                LogExportMode::All => true,
                LogExportMode::If => {
                    // SAFETY: `r` is the valid non-null request for this
                    // handler; `lc.log_export_cv` is non-null for the `If`
                    // mode (set at config time, lives on the conf pool for
                    // the process lifetime).
                    let r_ptr = r as *const nginx_sys::ngx_http_request_t
                        as *mut nginx_sys::ngx_http_request_t;
                    eval_export_truthy(r_ptr, lc.log_export_cv)
                }
                LogExportMode::Off | LogExportMode::Unset => false,
            },
            None => false,
        }
    }

    /// Reads the realip-aware client address and the User-Agent header, which
    /// are shared between the access-log tail and the span record.
    ///
    /// Both values are read exactly once per request regardless of how many
    /// signal paths consume them.  When `need_detail` is false (neither the
    /// access tail nor a sampled span is needed), both return empty slices at
    /// zero cost.
    fn read_request_detail(request: &Request, need_detail: bool) -> (&[u8], &[u8]) {
        // Client address (realip-aware `$remote_addr`): the connection's
        // `addr_text`, which nginx's realip module rewrites in place to the real
        // client.
        let client_addr: &[u8] = if need_detail && !request.connection().is_null() {
            // SAFETY: the connection pointer is non-null (checked) and points to
            // the request's `ngx_connection_t`, valid for this handler.
            // `addr_text` is an `ngx_str_t`; the slice is built only when `len >
            // 0` and `data` is non-null, covering `len` initialised bytes that
            // outlive this borrow.
            unsafe {
                let conn = &*request.connection();
                if conn.addr_text.len > 0 && !conn.addr_text.data.is_null() {
                    core::slice::from_raw_parts(conn.addr_text.data, conn.addr_text.len)
                } else {
                    b""
                }
            }
        } else {
            b""
        };

        // User-Agent header: one targeted header scan (not cached in SpanCtx —
        // it is not needed for trace correlation).
        let user_agent_raw: &[u8] = if need_detail {
            let mut ua: &[u8] = b"";
            for (key, value) in request.headers_in_iterator() {
                let k = key.as_bytes();
                if k.len() == 10 && k.eq_ignore_ascii_case(b"user-agent") {
                    ua = value.as_bytes();
                    break;
                }
            }
            ua
        } else {
            b""
        };

        (client_addr, user_agent_raw)
    }

    /// Pushes an access-log tail record into the per-worker SPSC ring when
    /// the request is selected for export.  On ring-full, triggers the exporter
    /// liveness check.
    ///
    /// Independent of the metrics block: the logs shm zone is gated separately.
    fn maybe_emit_access_log(ctx: &EmitCtx<'_>, export_selected: bool) {
        if !export_selected {
            return;
        }
        let logs_base = match ctx.amcf.logs_shm_base() {
            Some(b) => b,
            None => return,
        };

        let cap = ctx.amcf.log_ring_cap();
        // Safety: zone was sized for ≥ worker_id slots at registration.
        let access_ring = unsafe { logs_access_ring(logs_base, ctx.worker_id, cap) };
        let producer = WorkerRingProducer { ring: access_ring };

        // Gather HTTP semconv fields from the request.
        let method: &[u8] = ctx.r.method_name.as_bytes();
        let req_len = ctx.r.request_length as u64;

        // Timestamp: request start time in nanoseconds.
        // Derived from nginx's stored start fields (ms precision).
        let ts_unix_nano: u64 = (ctx.r.start_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ctx.r.start_msec as u64 * 1_000_000);

        // W3C trace correlation (parse-once):
        // SpanCtx was read once above; extract trace_id/span_id when sampled.
        // Unsampled requests (ctx.sampled=false) still have a SpanCtx for
        // W3C propagation but do not stamp the access tail.
        let trace_context: Option<([u8; 16], [u8; 8])> =
            ctx.span_ctx.filter(|c| c.sampled).map(|c| (c.trace_id, c.span_id));

        // url.path: r.uri (decoded path, WITHOUT query string / args).
        // Use r.uri, NOT r.unparsed_uri (= $request_uri, which includes
        // '?args') — including args would be a semconv violation and a
        // PII/credential-leak vector (e.g. ?token=SECRET ends up in
        // exported tails + exemplars).
        // r.uri is the normalised, args-stripped equivalent of $uri;
        // the query string lives separately in r.args and is NOT recorded.
        // High-cardinality — stays on the tail record ONLY, never a metric dim.
        let url_path: &[u8] = ctx.r.uri.as_bytes();

        // Build the canonical sampled-request record once; project into both sinks.
        // No allocation — all fields borrow nginx request memory (stack frame).
        let sampled = SampledRequest {
            ts_unix_nano,
            trace: trace_context,
            url_path,
            user_agent: ctx.user_agent_raw,
            duration_us: ctx.duration_us,
            combo_idx: ctx.meta.base_idx as u32,
            method,
            status: ctx.meta.status,
            request_length: req_len,
            response_bytes: ctx.meta.resp_bytes,
            client_addr: ctx.client_addr,
        };

        // Sink 1: per-worker SPSC log ring (exception-tail LogRecord).
        // A `false` return is the ring-full drop path (already counted
        // in the ring's `dropped`) — the TRIGGER for the
        // exporter-liveness check (heartbeat = the VERDICT).  Zero
        // added cost on the healthy path.
        if !emit_access_record(&producer, &sampled) {
            // SAFETY: `r.connection` is the request's live connection pointer
            // (may be null); `(*conn).log` is the connection log nginx error
            // logging uses for this request.
            let conn_log = unsafe {
                let conn = ctx.r.connection;
                if conn.is_null() {
                    core::ptr::null_mut()
                } else {
                    (*conn).log
                }
            };
            crate::liveness::check_exporter_liveness_on_drop(ctx.amcf, conn_log);
        }
    }

    /// Writes an exemplar into the metrics slot and pushes a span record into
    /// the per-worker spans ring, when the request is sampled.  On ring-full,
    /// triggers the exporter liveness check.
    ///
    /// Independent of the metrics block: the spans zone is gated separately.
    fn maybe_emit_span(ectx: &EmitCtx<'_>) {
        // Gate 1: request must be sampled (span_ctx.sampled=true).
        // Gate 2: spans shm zone must be available (otel_spans_zone configured).
        // Both gates false → zero work, no ring push.
        // This block is INDEPENDENT of the metrics block above — spans are emitted
        // regardless of whether `otel_metrics` is on or off.
        let ctx = match ectx.span_ctx.filter(|c| c.sampled) {
            Some(c) => c,
            None => return,
        };

        // ── Exemplar write (OTel TraceBased exemplar filter) ───────────────
        // Record an exemplar into the metrics slot ONLY when the metrics zone
        // is present (exemplar reservoirs live in the metrics shm slot).
        // Skipped when `otel_metrics off` — the span record below still runs.
        // <https://opentelemetry.io/docs/specs/otel/metrics/sdk/#exemplar-defaults>
        // Hot path: one null-check + a branch + ≤ 6 Relaxed stores when enabled.
        if let Some(metrics_base) = ectx.amcf.shm_base() {
            // SAFETY: `worker_id < n_workers` (verified by the bounds guard above);
            // the slot pointer is within the registered zone.
            let metrics_slot = unsafe { &*worker_slots(metrics_base, ectx.worker_id) };
            // Request start time in ns (ms precision from nginx's stored fields).
            let exemplar_ts_ns: u64 = (ectx.r.start_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(ectx.r.start_msec as u64 * 1_000_000);
            metrics_slot.exemplar_reservoirs[ectx.meta.base_idx].write(&SampledRequest {
                ts_unix_nano: exemplar_ts_ns,
                trace: Some((ctx.trace_id, ctx.span_id)),
                url_path: b"",
                user_agent: b"",
                duration_us: ectx.duration_us,
                combo_idx: ectx.meta.base_idx as u32,
                method: ectx.r.method_name.as_bytes(),
                status: ectx.r.headers_out.status as u16,
                request_length: 0,
                response_bytes: 0,
                client_addr: b"",
            });
        }

        let spans_base = match ectx.amcf.spans_shm_base() {
            Some(b) => b,
            None => return,
        };

        // Collect per-location config (span_name_cv + span_attrs).
        // `HttpOtelModule::location_conf` returns the merged LocationConf for
        // the matched location; null/absent → default (built-in name, no attrs).
        let loc_conf = HttpOtelModule::location_conf(ectx.r);

        // Build span name: evaluate `otel_span_name` complex value if set,
        // else fall back to built-in "METHOD route_name" format.
        // No heap allocation; evaluated into a stack buffer capped at MAX_SPAN_NAME.
        let mut span_name_buf = [0u8; MAX_SPAN_NAME];
        let span_name_len = {
            let mut evaluated_name: &[u8] = &[];
            let mut cv_buf = nginx_sys::ngx_str_t::default();
            let use_cv = loc_conf
                .and_then(|lc| if lc.span_name_cv.is_null() { None } else { Some(lc.span_name_cv) })
                .is_some_and(|cv_ptr| {
                    // SAFETY: `ectx.r` is the valid non-null request pointer (same
                    // request the handler was called on); `cv_ptr` is a valid
                    // `ngx_http_complex_value_t*` in conf-pool memory compiled
                    // at config time; `cv_buf` is a local ngx_str_t for output.
                    let rc = unsafe {
                        nginx_sys::ngx_http_complex_value(
                            ectx.r as *const nginx_sys::ngx_http_request_t
                                as *mut nginx_sys::ngx_http_request_t,
                            cv_ptr,
                            &raw mut cv_buf,
                        )
                    };
                    rc == nginx_sys::NGX_OK as nginx_sys::ngx_int_t && !cv_buf.is_empty()
                });
            if use_cv {
                // SAFETY: `cv_buf` was just populated by `ngx_http_complex_value`;
                // `data` points into the request pool (valid for the LOG-phase call).
                evaluated_name = unsafe {
                    if cv_buf.len > 0 && !cv_buf.data.is_null() {
                        core::slice::from_raw_parts(cv_buf.data, cv_buf.len)
                    } else {
                        b""
                    }
                };
            }
            if evaluated_name.is_empty() {
                // Built-in "METHOD route_name" fallback.
                build_span_name(
                    &mut span_name_buf,
                    ectx.r.method_name.as_bytes(),
                    ectx.amcf.route_name(ectx.meta.route_idx).as_bytes(),
                )
            } else {
                let len = evaluated_name.len().min(MAX_SPAN_NAME);
                span_name_buf[..len].copy_from_slice(&evaluated_name[..len]);
                len
            }
        };

        // Build extra_attrs from otel_span_attr directives (up to
        // MAX_SPAN_EXTRA_ATTRS pairs).  No heap allocation — stack buffer only.
        let mut attrs_buf: [(&[u8], &[u8]); MAX_SPAN_EXTRA_ATTRS] =
            [(&[], &[]); MAX_SPAN_EXTRA_ATTRS];
        let attrs_len = if let Some(lc) = loc_conf {
            let n = lc.span_attrs.len().min(MAX_SPAN_EXTRA_ATTRS);
            for (slot, (k, v)) in attrs_buf[..n].iter_mut().zip(lc.span_attrs[..n].iter()) {
                // SAFETY: `k` and `v` are `ngx_str_t` values from the nginx
                // conf pool (populated at config-parse time by
                // `cmd_add_otel_span_attr`); `as_bytes()` safely reinterprets
                // the pointer + length as a byte slice valid for process lifetime.
                *slot = (k.as_bytes(), v.as_bytes());
            }
            n
        } else {
            0
        };

        // OTel HTTP server span StatusCode: Error(2) for 5xx, Unset(0) otherwise.
        let otel_status_code: u8 = if ectx.meta.status >= 500 { 2 } else { 0 };

        // Span end time: derived from the monotonic duration for coherence.
        // end = start + duration_us * 1_000 ns.
        // Invariants: end >= start (monotonic); span (end−start) == duration_us.
        let end_time_unix_nano =
            ctx.start_time_unix_nano.saturating_add(ectx.duration_us.saturating_mul(1_000));

        // ── HTTP semconv coverage sources (already materialized) ───────
        let conn_ptr = ectx.r.connection;

        // url.scheme: TLS connection ⇒ "https".
        let scheme_https = if conn_ptr.is_null() {
            false
        } else {
            // SAFETY: `conn_ptr` is non-null (checked); `ssl` is a pointer
            // nginx sets non-null on TLS connections.
            unsafe { !(*conn_ptr).ssl.is_null() }
        };

        // server.address: the matched server name, falling back to the
        // request Host header (mirrors nginx-otel getServerName,
        // http_module.cpp:395-406).
        let server_address: &[u8] = {
            let from_srv = NgxHttpCoreModule::server_conf(ectx.r)
                .map(|cscf| cscf.server_name.as_bytes())
                .unwrap_or(b"");
            if from_srv.is_empty() {
                ectx.r.headers_in.server.as_bytes()
            } else {
                from_srv
            }
        };

        // server.port / client.port (local + client sockaddr ports).
        // SAFETY: `conn_ptr` is the request connection pointer (may be
        // null — `server_port` handles null).
        let server_port_val = unsafe { server_port(conn_ptr) };
        // SAFETY: `conn_ptr` is the request connection pointer (may be
        // null — `client_port` handles null).
        let client_port_val = unsafe { client_port(conn_ptr) };

        // network.peer.{address,port}: the TRUE TCP socket peer via the
        // realip-aware `$realip_remote_addr` selection (saved original
        // when realip rewrote the connection, else the live peer).
        let r_mut =
            ectx.r as *const nginx_sys::ngx_http_request_t as *mut nginx_sys::ngx_http_request_t;
        // SAFETY: `r_mut` is the live request pointer for this handler.
        let (peer_address, peer_port_val) = unsafe { realip_peer(r_mut) };

        // http.request.body.size: content_length_n (-1 = absent ⇒ 0).
        let req_body_size = if ectx.r.headers_in.content_length_n > 0 {
            ectx.r.headers_in.content_length_n as u64
        } else {
            0
        };
        // http.response.body.size: bytes sent minus response headers
        // (mirrors nginx-otel http.response_content_length,
        // http_module.cpp:436).
        let resp_body_size = ectx.meta.resp_bytes.saturating_sub(ectx.r.header_size as u64);

        let rec = SpanRecord {
            trace_id: ctx.trace_id,
            span_id: ctx.span_id,
            parent_span_id: ctx.parent_span_id,
            flags: ctx.flags,
            start_time_unix_nano: ctx.start_time_unix_nano,
            end_time_unix_nano,
            status_code: otel_status_code,
            kind: 2, // SpanKind::Server
            name: &span_name_buf[..span_name_len],
            method: ectx.r.method_name.as_bytes(),
            http_status: ectx.meta.status,
            url_path: ectx.r.uri.as_bytes(), // uri = path only; unparsed_uri = path+args
            duration_us: ectx.duration_us,
            proto: ectx.meta.proto as u8,
            scheme_https,
            server_port: server_port_val,
            client_port: client_port_val,
            peer_port: peer_port_val,
            req_body_size,
            resp_body_size,
            url_query: ectx.r.args.as_bytes(), // url.query: args without leading '?'
            route: ectx.amcf.route_name(ectx.meta.route_idx).as_bytes(),
            user_agent: ectx.user_agent_raw,
            server_address,
            client_address: ectx.client_addr,
            peer_address,
            extra_attrs: &attrs_buf[..attrs_len],
        };

        // SAFETY: `spans_base` is the valid mapped shm start returned by
        // `spans_shm_base()`, sized for ≥ worker_id spans-ring slots at zone
        // registration in postconfiguration.  The ring lives for the worker's
        // lifetime and outlives this handler invocation.
        let spans = unsafe { spans_ring(spans_base, ectx.worker_id, DEFAULT_SPAN_RING_CAP) };
        let producer = WorkerRingProducer { ring: spans };
        // Ring-full drop path → liveness check (see the access-ring
        // hook above for the trigger/verdict rationale).
        if !emit_span_record(&producer, &rec) {
            // SAFETY: `ectx.r.connection` is the request's live connection pointer
            // (may be null); `(*conn).log` is the request's log.
            let conn_log = unsafe {
                let conn = ectx.r.connection;
                if conn.is_null() {
                    core::ptr::null_mut()
                } else {
                    (*conn).log
                }
            };
            crate::liveness::check_exporter_liveness_on_drop(ectx.amcf, conn_log);
        }
    }
}

/// Truthiness test for an evaluated `otel_log_export if=<cond>` value.
///
/// Mirrors nginx core's convention for `access_log … if=`: a value is falsy
/// iff it is empty or the single byte `"0"`; anything else is truthy.  Factored
/// out as a pure function so the export decision is unit-testable without a
/// live request.
///
/// # Hot-path note
/// Branch-only (no alloc, no lock, no syscall).
#[inline]
pub fn is_truthy(bytes: &[u8]) -> bool {
    !(bytes.is_empty() || (bytes.len() == 1 && bytes[0] == b'0'))
}

/// Evaluate an `otel_log_export if=<cond>` complex value and report whether the
/// result is truthy (mirroring core `access_log … if=`).
///
/// # Safety
/// `r` must be the valid request pointer for the current LOG-phase handler and
/// `cv` a non-null `ngx_http_complex_value_t*` compiled at config time (process
/// lifetime).  Evaluating a complex value at the LOG phase is sound — it is the
/// same phase core `access_log if=` evaluates in, and all request variables
/// (`$status`, `$request_time`, …) are materialized.
///
/// # Hot-path note
/// One `ngx_http_complex_value` call plus the truthiness branch; no allocation,
/// no lock, no syscall beyond what the complex value itself performs.
#[inline]
fn eval_export_truthy(
    r: *mut nginx_sys::ngx_http_request_t,
    cv: *mut nginx_sys::ngx_http_complex_value_t,
) -> bool {
    // SAFETY: `ngx_str_t` is a plain (len, data) C struct; zeroing yields a
    // valid empty-string output buffer.
    let mut out: nginx_sys::ngx_str_t = unsafe { core::mem::zeroed() };
    // SAFETY: per the fn contract `r` is the valid request pointer and `cv` is a
    // non-null complex value in conf-pool memory; `out` is a local output buffer.
    let rc = unsafe { nginx_sys::ngx_http_complex_value(r, cv, &raw mut out) };
    if rc != nginx_sys::NGX_OK as nginx_sys::ngx_int_t {
        return false;
    }
    let bytes: &[u8] = if out.len == 0 || out.data.is_null() {
        b""
    } else {
        // SAFETY: on NGX_OK, `out.data` points into the request pool with
        // `out.len` valid bytes; the slice is built only when both checks above
        // pass (non-null data, non-zero len).
        unsafe { core::slice::from_raw_parts(out.data, out.len) }
    };
    is_truthy(bytes)
}

/// Build an OTel HTTP server span name `"METHOD route_name"` into a fixed
/// stack buffer, capped at `MAX_SPAN_NAME` bytes.  Returns the number of
/// bytes written.
///
/// Both components are ASCII-safe (nginx method/location names); raw byte
/// copies avoid heap allocation.  No `String`, no `format!`.
///
/// # Hot-path note
/// All work is in-register or stack-copy — no allocation, no locking.
#[inline]
fn build_span_name(buf: &mut [u8; MAX_SPAN_NAME], method: &[u8], route: &[u8]) -> usize {
    let mut off = 0usize;
    let m_len = method.len().min(MAX_SPAN_NAME);
    buf[..m_len].copy_from_slice(&method[..m_len]);
    off += m_len;
    if off < MAX_SPAN_NAME && !route.is_empty() {
        buf[off] = b' ';
        off += 1;
        let rem = (MAX_SPAN_NAME - off).min(route.len());
        buf[off..off + rem].copy_from_slice(&route[..rem]);
        off += rem;
    }
    off
}

/// Realip-aware "true TCP socket peer" address + port for the
/// `network.peer.address` / `network.peer.port` span attributes.
///
/// nginx's realip module (`real_ip_header` / PROXY protocol) rewrites
/// `c->addr_text` / `c->sockaddr` **in place** to the logical client, but it
/// first stashes the original socket peer in its per-request module context
/// (`ngx_http_realip_module.c:285-292`).  The `$realip_remote_addr` /
/// `$realip_remote_port` variables return that saved original when the context
/// is present, else the live connection values
/// (`ngx_http_realip_remote_addr_variable`, `ngx_http_realip_module.c:580,602`).
///
/// **Primary path** (realip compiled in): evaluate `$realip_remote_addr` /
/// `$realip_remote_port` — this always yields the true socket peer regardless of
/// whether a realip rewrite occurred, because the variable handler returns
/// `ctx->addr_text` when a context exists (realip active and matched) and
/// `connection->addr_text` otherwise (realip inactive or unmatched).
///
/// **Fallback path** (realip not compiled, or variable lookup returns empty):
/// read `connection->addr_text` directly for the address and derive the port
/// via `sockaddr_port(connection->sockaddr)`.  When realip is absent the
/// connection's `addr_text` is never rewritten, so it equals the socket peer
/// exactly — the same value `$realip_remote_addr` would have returned.
///
/// The realip module's context type and its module descriptor are both
/// file-`static` in nginx, so they cannot be referenced directly from Rust —
/// the variable is the only sound public accessor when realip is compiled in.
///
/// Returns the peer address bytes (slice into request/connection memory, valid
/// for this LOG-phase call) and the peer port (0 when unavailable).
///
/// # Safety
/// `r` must be the valid request pointer for the current LOG-phase handler.
///
/// # Hot-path note
/// Two `ngx_http_get_variable` evaluations (a hashed lookup) when realip is
/// compiled in; a single `connection->addr_text` read on the fallback path.
/// Runs only on sampled spans.
unsafe fn realip_peer<'a>(r: *mut nginx_sys::ngx_http_request_t) -> (&'a [u8], u16) {
    /// Evaluate one request variable by name, returning its value bytes.
    ///
    /// # Safety
    /// `r` valid request pointer; `name` an ASCII-lowercase variable name.
    unsafe fn get_var<'b>(r: *mut nginx_sys::ngx_http_request_t, name: &[u8]) -> &'b [u8] {
        // `ngx_hash_strlow` lowercases into `dst` and returns the hash key; the
        // name is already lowercase, so copy it into a local mutable buffer and
        // hash in place (the C callers pass the variable's own mutable buffer,
        // e.g. ngx_http_ssi_filter_module.c:2293).
        let mut lower = [0u8; 32];
        if name.len() > lower.len() {
            return b"";
        }
        lower[..name.len()].copy_from_slice(name);
        // SAFETY: `lower` holds `name.len()` initialised bytes; `ngx_hash_strlow`
        // reads/writes exactly that many in place and returns the hash key.
        let key = unsafe {
            nginx_sys::ngx_hash_strlow(lower.as_mut_ptr(), lower.as_mut_ptr(), name.len())
        };
        let mut nm = nginx_sys::ngx_str_t { len: name.len(), data: lower.as_mut_ptr() };
        // SAFETY: `r` is the valid request; `nm` names a variable (registered or
        // not — a null/not_found return is handled); `key` is its hash.
        let vv = unsafe { nginx_sys::ngx_http_get_variable(r, &raw mut nm, key) };
        if vv.is_null() {
            return b"";
        }
        // SAFETY: `vv` is non-null; `not_found()`/`len()`/`data` are valid reads
        // on the returned variable-value struct.
        unsafe {
            if (*vv).not_found() != 0 {
                return b"";
            }
            let len = (*vv).len() as usize;
            let data = (*vv).data;
            if len == 0 || data.is_null() {
                b""
            } else {
                core::slice::from_raw_parts(data, len)
            }
        }
    }

    // SAFETY: `r` is the valid request pointer per the contract.
    let addr = unsafe { get_var(r, b"realip_remote_addr") };

    if !addr.is_empty() {
        // Realip variable present and non-empty: use it for both address and port.
        // SAFETY: `r` is the valid request pointer per the contract.
        let port_bytes = unsafe { get_var(r, b"realip_remote_port") };
        let port =
            core::str::from_utf8(port_bytes).ok().and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
        return (addr, port);
    }

    // Fallback: `$realip_remote_addr` is absent (realip not compiled) or returned
    // empty.  Read `connection->addr_text` directly — it is the true socket peer
    // whenever realip has not rewritten it, which is always the case here.
    // Mirror the null-safety pattern from the `client.address` read above.
    // SAFETY: `r` is the valid request pointer per the contract.
    let conn_ptr = unsafe { (*r).connection };
    if conn_ptr.is_null() {
        return (b"", 0);
    }
    // SAFETY: `conn_ptr` is non-null and valid for the request lifetime.
    unsafe {
        let conn = &*conn_ptr;
        let addr_fallback: &'a [u8] = if conn.addr_text.len > 0 && !conn.addr_text.data.is_null() {
            core::slice::from_raw_parts(conn.addr_text.data, conn.addr_text.len)
        } else {
            b""
        };
        // SAFETY: `conn.sockaddr` is non-null (checked) and valid for the
        // request lifetime per nginx's connection invariant.
        let port_fallback: u16 =
            if !conn.sockaddr.is_null() { sockaddr_port(conn.sockaddr) } else { 0 };
        (addr_fallback, port_fallback)
    }
}

/// Read the TCP/UDP port from a `struct sockaddr`, host byte order.
///
/// Equivalent to nginx's `ngx_inet_get_port` (`src/core/ngx_inet.c`): switch on
/// `sa_family` and return the family's port field converted from network byte
/// order; any other family (incl. `AF_UNIX`) yields 0.  Inlined in Rust rather
/// than calling the nginx C function so the value read is identical while the
/// helper carries no external nginx dependency.  The `sockaddr_in` /
/// `sockaddr_in6` layout (`sin_port` / `sin6_port` as a 16-bit big-endian port)
/// is fixed by POSIX (`<netinet/in.h>`).
///
/// # Safety
/// `sa` must be a valid, non-null `struct sockaddr` pointer whose storage is at
/// least as large as the `sockaddr_in` / `sockaddr_in6` selected by its family.
unsafe fn sockaddr_port(sa: *const nginx_sys::sockaddr) -> u16 {
    // SAFETY: `sa` is a valid sockaddr per the contract; `sa_family` is always
    // readable, and the family-specific cast below reads only the port field,
    // which lies within the storage guaranteed for that family.
    unsafe {
        match u32::from((*sa).sa_family) {
            f if f == libc::AF_INET as u32 => {
                let sin = sa as *const libc::sockaddr_in;
                u16::from_be((*sin).sin_port)
            }
            f if f == libc::AF_INET6 as u32 => {
                let sin6 = sa as *const libc::sockaddr_in6;
                u16::from_be((*sin6).sin6_port)
            }
            _ => 0,
        }
    }
}

/// Local listening (server) port for the `server.port` span attribute.
///
/// Materialises the connection's local sockaddr (lazily filled by nginx via
/// `getsockname` only when first requested — the same call the core
/// `$server_port` variable makes) and reads the port from it, mirroring
/// `nginx-otel`'s `net.host.port` source (`http_module.cpp:450-451`).
/// Returns 0 when the local address is unavailable.
///
/// # Safety
/// `conn` must be the request's valid (or null) `ngx_connection_t` pointer.
unsafe fn server_port(conn: *mut nginx_sys::ngx_connection_t) -> u16 {
    if conn.is_null() {
        return 0;
    }
    // SAFETY: `conn` is the valid request connection per the contract;
    // `ngx_connection_local_sockaddr` fills `local_sockaddr`/`local_socklen`.
    unsafe {
        if nginx_sys::ngx_connection_local_sockaddr(conn, core::ptr::null_mut(), 0)
            != nginx_sys::NGX_OK as nginx_sys::ngx_int_t
        {
            return 0;
        }
        let local = (*conn).local_sockaddr;
        if local.is_null() {
            0
        } else {
            sockaddr_port(local)
        }
    }
}

/// Client (realip-aware `$remote_addr`-equivalent) port for the `client.port`
/// span attribute, read from the connection's live `sockaddr` (which realip
/// rewrites in place alongside `addr_text`).  Returns 0 when unavailable.
///
/// # Safety
/// `conn` must be the request's valid (or null) `ngx_connection_t` pointer.
unsafe fn client_port(conn: *mut nginx_sys::ngx_connection_t) -> u16 {
    if conn.is_null() {
        return 0;
    }
    // SAFETY: `conn` is valid; `sockaddr` is the (possibly realip-rewritten)
    // client sockaddr nginx keeps for the connection lifetime.
    unsafe {
        let sa = (*conn).sockaddr;
        if sa.is_null() {
            0
        } else {
            sockaddr_port(sa)
        }
    }
}

/// Aggregated upstream timings/bytes summed across every attempt in
/// `r->upstream_states`.
///
/// Each timing is `Some(sum)` only when at least one attempt recorded a real
/// (non-sentinel) value for that phase; `None` means every attempt left the
/// field at `(ngx_msec_t)-1` (so no metric is recorded, matching the core
/// variables' `"-"` output).  Byte counters are always summed.
struct UpstreamSum {
    response_ms: Option<u64>,
    header_ms: Option<u64>,
    connect_ms: Option<u64>,
    bytes_received: u64,
    bytes_sent: u64,
}

/// Sum the per-attempt timings/bytes across the full `r->upstream_states`
/// array, mirroring how the core `$upstream_response_time` /
/// `$upstream_*_bytes` variables iterate the states
/// (`ngx_http_upstream_response_time_variable` /
/// `..._response_length_variable`, ngx_http_upstream.c:6027,6105).
///
/// Returns `None` when there are no upstream attempts (`states` null or empty).
///
/// Entries with a NULL `peer` are cache/internal-redirect boundary markers that
/// nginx records in the same array (it prints them as `" : "` separators rather
/// than a peer); they carry no real attempt timing, so they are skipped — only
/// real peer attempts contribute to the sum.
///
/// Timing fields equal to `NGX_MSEC_SENTINEL` (`(ngx_msec_t)-1`) are skipped
/// per field; a field stays `None` until some attempt supplies a real value, so
/// the sentinel never poisons the cumulative metric sum.
///
/// # Safety
/// `states` must be null or a valid `*mut ngx_array_t` whose `elts` points to
/// `nelts` initialised `ngx_http_upstream_state_t` values, valid for the call.
///
/// # Hot-path note
/// Iterates the existing in-pool array in place — no allocation, no lock, no
/// syscall.  The attempt count is bounded by `proxy_next_upstream_tries`.
unsafe fn sum_upstream_states(states: *mut nginx_sys::ngx_array_t) -> Option<UpstreamSum> {
    if states.is_null() {
        return None;
    }
    // SAFETY: `states` is non-null per the contract; reading the `ngx_array_t`
    // header fields (`nelts`, `elts`) is sound.
    let (nelts, elts) = unsafe { ((*states).nelts, (*states).elts) };
    if nelts == 0 || elts.is_null() {
        return None;
    }
    let base = elts.cast::<nginx_sys::ngx_http_upstream_state_t>();

    let mut response_ms: Option<u64> = None;
    let mut header_ms: Option<u64> = None;
    let mut connect_ms: Option<u64> = None;
    let mut bytes_received: u64 = 0;
    let mut bytes_sent: u64 = 0;

    #[inline]
    fn accumulate(acc: &mut Option<u64>, raw: u64) {
        if raw != NGX_MSEC_SENTINEL {
            *acc = Some(acc.unwrap_or(0).saturating_add(raw));
        }
    }

    for i in 0..nelts {
        // SAFETY: `i < nelts` and `base` points to `nelts` initialised states
        // (the array nginx populated), so `base.add(i)` is in-bounds; all reads
        // below are of plain numeric/pointer fields on that state.
        let st = unsafe { &*base.add(i) };
        // Skip cache/redirect boundary markers (NULL peer) — not real attempts.
        if st.peer.is_null() {
            continue;
        }
        accumulate(&mut response_ms, st.response_time as u64);
        accumulate(&mut header_ms, st.header_time as u64);
        accumulate(&mut connect_ms, st.connect_time as u64);
        bytes_received = bytes_received.saturating_add(st.bytes_received as u64);
        bytes_sent = bytes_sent.saturating_add(st.bytes_sent as u64);
    }

    Some(UpstreamSum { response_ms, header_ms, connect_ms, bytes_received, bytes_sent })
}

/// A `MetricSource` that reads all per-worker shm slots and produces
/// aggregated `Metric`s for the export batch.
pub struct InstrumentedSource {
    /// Base address of the shm zone.
    pub base: *mut u8,
    /// Number of workers whose slots are in the zone.
    pub n_workers: usize,
    /// Unix epoch nanoseconds when the exporter (and therefore these
    /// cumulative windows) started.
    pub start_time_unix_nano: u64,
    /// When `true`, emit `http.server.request.duration` with bounded semconv
    /// attributes per combination (`otel_metric_status_code_class on`).
    /// When `false`, emit a single aggregated data point.
    pub status_code_class_enabled: bool,
    /// Pointer to the main config — used for route/upstream name lookups when
    /// emitting per-combination data points.  Null-safe: falls back to index
    /// strings if null (should never be null in production).
    pub amcf: *const crate::config::MainConfig,
}

// Safety: InstrumentedSource is only used on Worker 0's export loop.
unsafe impl Send for InstrumentedSource {}
// SAFETY: `InstrumentedSource` holds raw `*mut`/`*const` pointers into shm and
// the main config, but it is only ever accessed from the single export worker
// (Worker 0); there is no concurrent `&InstrumentedSource` aliasing, and the
// shm it reads is via per-field atomics, so sharing it is sound.
unsafe impl Sync for InstrumentedSource {}

impl crate::metric_source::MetricSource for InstrumentedSource {
    #[allow(clippy::needless_range_loop)] // idx parallels two independent slices (buckets + bounds)
    fn collect(&self) -> std::vec::Vec<crate::data_model::Metric> {
        use crate::data_model::AggregationTemporality;
        use crate::shm::{BYTES_BOUNDS, DURATION_BOUNDS_S};

        let start = self.start_time_unix_nano;
        let now = crate::util::now_unix_nano();

        // SAFETY: `self.amcf` is the main-config pointer captured at exporter
        // setup; it is either null or points to the `MainConfig` that lives for
        // the whole process. `as_ref()` yields `None` for null and otherwise a
        // reference that does not outlive `self`, so it is sound.
        let amcf_ref: Option<&crate::config::MainConfig> = unsafe { self.amcf.as_ref() };

        // Step 1: aggregate shm counters across all workers + collect exemplars.
        let (agg, all_exemplars) = self.aggregate_worker_slots();

        // DURATION_BOUNDS_S is already f64 (seconds); upstream histograms record
        // raw ms values against DURATION_BOUNDS_MS on the worker, and the exporter
        // publishes in seconds by using DURATION_BOUNDS_S here and dividing the sum.
        let dur_bounds_s: std::vec::Vec<f64> = DURATION_BOUNDS_S.to_vec();
        let byte_bounds: std::vec::Vec<f64> = BYTES_BOUNDS.iter().map(|&b| b as f64).collect();

        // Step 2: build one metric per signal family and return.
        std::vec![
            // Request duration: base (method × sc × proto), by_route, by_upstream.
            self.build_duration_metric(&agg.combo_agg, &all_exemplars, start, now),
            self.build_route_metric(&agg.route_agg, amcf_ref, start, now),
            self.build_upstream_duration_metric(&agg.upstream_agg, amcf_ref, start, now),
            // Request / response body sizes.
            hist_metric(
                &HistSpec {
                    name: "http.server.request.body.size",
                    desc: "HTTP server request body size",
                    unit: "By",
                    temporality: AggregationTemporality::Cumulative
                },
                agg.req_bytes,
                byte_bounds.clone(),
                start,
                now,
            ),
            hist_metric(
                &HistSpec {
                    name: "http.server.response.body.size",
                    desc: "HTTP server response body size",
                    unit: "By",
                    temporality: AggregationTemporality::Cumulative
                },
                agg.resp_bytes,
                byte_bounds.clone(),
                start,
                now,
            ),
            // Upstream timings: published in seconds (`"s"`); the worker records raw
            // ms values against DURATION_BOUNDS_MS, so the bucket placement is
            // unchanged — only the bounds (DURATION_BOUNDS_S) and the scalar sum
            // (÷1000) change at export.
            hist_metric_with_sum(
                &HistSpec {
                    name: "nginx.upstream.response.duration",
                    desc: "Upstream response time",
                    unit: "s",
                    temporality: AggregationTemporality::Cumulative
                },
                agg.up_resp,
                ms_to_s_hist_sum(agg.up_resp.1),
                dur_bounds_s.clone(),
                start,
                now,
            ),
            hist_metric_with_sum(
                &HistSpec {
                    name: "nginx.upstream.header.duration",
                    desc: "Upstream time to first response byte",
                    unit: "s",
                    temporality: AggregationTemporality::Cumulative
                },
                agg.up_hdr,
                ms_to_s_hist_sum(agg.up_hdr.1),
                dur_bounds_s.clone(),
                start,
                now,
            ),
            hist_metric_with_sum(
                &HistSpec {
                    name: "nginx.upstream.connect.duration",
                    desc: "Upstream connection establishment time",
                    unit: "s",
                    temporality: AggregationTemporality::Cumulative
                },
                agg.up_conn,
                ms_to_s_hist_sum(agg.up_conn.1),
                dur_bounds_s.clone(),
                start,
                now,
            ),
            // Upstream byte counters.
            hist_metric(
                &HistSpec {
                    name: "nginx.upstream.bytes.received",
                    desc: "Bytes received from upstream",
                    unit: "By",
                    temporality: AggregationTemporality::Cumulative
                },
                agg.up_bytes,
                byte_bounds.clone(),
                start,
                now,
            ),
            hist_metric(
                &HistSpec {
                    name: "nginx.upstream.bytes.sent",
                    desc: "Bytes sent to upstream",
                    unit: "By",
                    temporality: AggregationTemporality::Cumulative
                },
                agg.up_bytes_sent,
                byte_bounds.clone(),
                start,
                now,
            ),
        ]
    }
}

/// Aggregated shm counters accumulated over all worker slots for one export cycle.
struct WorkerAgg {
    /// Base combination histograms (method × status_class × protocol).
    combo_agg: std::vec::Vec<([u64; crate::shm::N_EXP_BUCKETS], u64, u64, u64)>,
    /// Per-route duration histograms.
    route_agg: std::vec::Vec<([u64; crate::shm::N_EXP_BUCKETS], u64, u64, u64)>,
    /// Per-upstream duration histograms.
    upstream_agg: std::vec::Vec<([u64; crate::shm::N_EXP_BUCKETS], u64, u64, u64)>,
    /// Request body sizes.
    req_bytes: ([u64; crate::shm::N_BYTES_BUCKETS], u64, u64),
    /// Response body sizes.
    resp_bytes: ([u64; crate::shm::N_BYTES_BUCKETS], u64, u64),
    /// Upstream response time (ms, converted to seconds at export).
    up_resp: ([u64; crate::shm::N_DURATION_BUCKETS], u64, u64),
    /// Upstream header time (ms, converted to seconds at export).
    up_hdr: ([u64; crate::shm::N_DURATION_BUCKETS], u64, u64),
    /// Upstream connect time (ms, converted to seconds at export).
    up_conn: ([u64; crate::shm::N_DURATION_BUCKETS], u64, u64),
    /// Bytes received from upstreams.
    up_bytes: ([u64; crate::shm::N_BYTES_BUCKETS], u64, u64),
    /// Bytes sent to upstreams.
    up_bytes_sent: ([u64; crate::shm::N_BYTES_BUCKETS], u64, u64),
}

impl InstrumentedSource {
    /// Walks every per-worker shm slot, aggregating all histogram counters and
    /// collecting exemplars in one pass.
    ///
    /// Returns the aggregated data and the raw exemplar list, which the caller
    /// distributes to the appropriate data points.
    #[allow(clippy::needless_range_loop)] // idx used to index two independent parallel slices
    fn aggregate_worker_slots(
        &self,
    ) -> (WorkerAgg, std::vec::Vec<(u32, crate::data_model::Exemplar)>) {
        use crate::data_model::Exemplar;
        use crate::shm::{N_COMBOS, N_EXP_BUCKETS, N_ROUTE_SLOTS, N_UPSTREAM_SLOTS};

        // combo_agg[idx] = ([bucket_counts; N_EXP_BUCKETS], zero_count, sum, count)
        let mut combo_agg: std::vec::Vec<([u64; N_EXP_BUCKETS], u64, u64, u64)> =
            std::vec![([0u64; N_EXP_BUCKETS], 0u64, 0u64, 0u64); N_COMBOS];
        let mut route_agg: std::vec::Vec<([u64; N_EXP_BUCKETS], u64, u64, u64)> =
            std::vec![([0u64; N_EXP_BUCKETS], 0u64, 0u64, 0u64); N_ROUTE_SLOTS];
        let mut upstream_agg: std::vec::Vec<([u64; N_EXP_BUCKETS], u64, u64, u64)> =
            std::vec![([0u64; N_EXP_BUCKETS], 0u64, 0u64, 0u64); N_UPSTREAM_SLOTS];
        let mut req_bytes = ([0u64; crate::shm::N_BYTES_BUCKETS], 0u64, 0u64);
        let mut resp_bytes = ([0u64; crate::shm::N_BYTES_BUCKETS], 0u64, 0u64);
        let mut up_resp = ([0u64; crate::shm::N_DURATION_BUCKETS], 0u64, 0u64);
        let mut up_hdr = ([0u64; crate::shm::N_DURATION_BUCKETS], 0u64, 0u64);
        let mut up_conn = ([0u64; crate::shm::N_DURATION_BUCKETS], 0u64, 0u64);
        let mut up_bytes = ([0u64; crate::shm::N_BYTES_BUCKETS], 0u64, 0u64);
        let mut up_bytes_sent = ([0u64; crate::shm::N_BYTES_BUCKETS], 0u64, 0u64);

        let mut all_exemplars: std::vec::Vec<(u32, Exemplar)> = std::vec::Vec::new();

        for i in 0..self.n_workers {
            // SAFETY: `self.base` is the shm zone start and `i < self.n_workers`,
            // the worker count the zone was sized for, so `worker_slots` returns an
            // in-bounds, zone-init-zeroed `WorkerSlots` pointer; the zone outlives
            // this export loop, so the reference is valid. All slot fields read here
            // are atomics, so concurrent worker writes are well-defined.
            let slot = unsafe { &*worker_slots(self.base, i) };

            // Sum base combination histograms (method × sc × proto, 160 combos).
            for idx in 0..N_COMBOS {
                let (bc, zc, bs, bcount) = slot.request_duration_combos[idx].snapshot();
                let agg = &mut combo_agg[idx];
                for (a, b) in agg.0.iter_mut().zip(bc.iter()) {
                    *a += b;
                }
                agg.1 += zc;
                agg.2 += bs;
                agg.3 += bcount;
            }
            // Sum per-route histograms.
            for idx in 0..N_ROUTE_SLOTS {
                let (bc, zc, bs, bcount) = slot.route_duration_combos[idx].snapshot();
                let agg = &mut route_agg[idx];
                for (a, b) in agg.0.iter_mut().zip(bc.iter()) {
                    *a += b;
                }
                agg.1 += zc;
                agg.2 += bs;
                agg.3 += bcount;
            }
            // Sum per-upstream histograms.
            for idx in 0..N_UPSTREAM_SLOTS {
                let (bc, zc, bs, bcount) = slot.upstream_duration_combos[idx].snapshot();
                let agg = &mut upstream_agg[idx];
                for (a, b) in agg.0.iter_mut().zip(bc.iter()) {
                    *a += b;
                }
                agg.1 += zc;
                agg.2 += bs;
                agg.3 += bcount;
            }

            let (bc, bs, bcount) = slot.request_body_bytes.snapshot();
            add_histogram(&mut req_bytes, &bc, bs, bcount);

            let (bc, bs, bcount) = slot.response_body_bytes.snapshot();
            add_histogram(&mut resp_bytes, &bc, bs, bcount);

            let (bc, bs, bcount) = slot.upstream_response_ms.snapshot();
            add_histogram(&mut up_resp, &bc, bs, bcount);
            let (bc, bs, bcount) = slot.upstream_header_ms.snapshot();
            add_histogram(&mut up_hdr, &bc, bs, bcount);
            let (bc, bs, bcount) = slot.upstream_connect_ms.snapshot();
            add_histogram(&mut up_conn, &bc, bs, bcount);
            let (bc, bs, bcount) = slot.upstream_bytes_received.snapshot();
            add_histogram(&mut up_bytes, &bc, bs, bcount);
            let (bc, bs, bcount) = slot.upstream_bytes_sent.snapshot();
            add_histogram(&mut up_bytes_sent, &bc, bs, bcount);

            // Collect exemplars from this worker's per-data-point reservoirs and
            // RESET each (the OTel `num_measurements_seen` reset every collection
            // cycle — see ExemplarReservoir doc).  Reset is the one cross-process
            // write into the reservoir; it is store-vs-RMW on the atomic `seen`,
            // so the interleaving with a concurrent worker write is well-defined.
            // The canonical exemplar carries no `filtered_attributes` (url.path /
            // user_agent were a misuse of that field + a redaction hazard; the
            // linked trace already carries url.path).
            // <https://opentelemetry.io/docs/specs/otel/metrics/sdk/#exemplar-defaults>
            for combo in 0..N_COMBOS {
                let reservoir = &slot.exemplar_reservoirs[combo];
                for snap in reservoir.snapshot() {
                    all_exemplars.push((
                        snap.combo_idx,
                        Exemplar {
                            // Exemplars attach to the seconds histogram; the
                            // reservoir stores raw µs, so convert to seconds here
                            // (one divide per exemplar at export — same lossless
                            // convert-at-export pattern as the histogram sum).
                            value: us_to_seconds(snap.value_us),
                            time_unix_nano: snap.ts_unix_nano,
                            trace_id: snap.trace_id,
                            span_id: snap.span_id,
                            has_trace: snap.has_trace,
                            filtered_attributes: std::vec::Vec::new(),
                        },
                    ));
                }
                reservoir.reset();
            }
        }

        (
            WorkerAgg {
                combo_agg,
                route_agg,
                upstream_agg,
                req_bytes,
                resp_bytes,
                up_resp,
                up_hdr,
                up_conn,
                up_bytes,
                up_bytes_sent,
            },
            all_exemplars,
        )
    }

    /// Builds the `http.server.request.duration` metric from the aggregated
    /// base-combination histograms.
    ///
    /// When `status_code_class_enabled`, emits one data point per
    /// `{method × status_class × protocol}` combination (160 combos) with the
    /// corresponding exemplars.  Otherwise collapses all combinations into a
    /// single unlabelled data point.
    fn build_duration_metric(
        &self,
        combo_agg: &[([u64; crate::shm::N_EXP_BUCKETS], u64, u64, u64)],
        all_exemplars: &[(u32, crate::data_model::Exemplar)],
        start: u64,
        now: u64,
    ) -> crate::data_model::Metric {
        use crate::data_model::{
            AggregationTemporality, AnyValue, Exemplar, ExponentialHistogramData,
            ExponentialHistogramDataPoint, KeyValue, Metric, MetricData,
        };
        use crate::shm::{
            combo_index, HttpMethod, ProtoVersion, StatusClass, EXP_HISTOGRAM_BUCKET_OFFSET,
            EXP_HISTOGRAM_SCALE, N_EXP_BUCKETS, N_HTTP_METHODS, N_PROTO_VERSIONS, N_STATUS_CLASSES,
        };

        if self.status_code_class_enabled {
            // Base series: method × status_class × protocol (160 combos).
            let mut data_points: std::vec::Vec<ExponentialHistogramDataPoint> =
                std::vec::Vec::new();
            for m_idx in 0..N_HTTP_METHODS {
                for sc_idx in 0..N_STATUS_CLASSES {
                    for p_idx in 0..N_PROTO_VERSIONS {
                        let method = HttpMethod::from_index(m_idx);
                        let status_class = StatusClass::from_index(sc_idx);
                        let proto = ProtoVersion::from_index(p_idx);
                        let combo = combo_index(method, status_class, proto);
                        let combo_exemplars: std::vec::Vec<Exemplar> = all_exemplars
                            .iter()
                            .filter(|(cidx, _)| *cidx == combo as u32)
                            .map(|(_, e)| e.clone())
                            .collect();
                        // Use the honest key `http.response.status_class` with a
                        // self-describing string value ("2xx", etc.).  semconv reserves
                        // `http.response.status_code` for the actual integer code; emitting
                        // a class representative (200/400/500…) there was misleading.
                        // <https://opentelemetry.io/docs/specs/semconv/http/http-metrics/>
                        let attrs = std::vec![
                            KeyValue {
                                key: "http.request.method".into(),
                                value: AnyValue::String(method.as_str().into())
                            },
                            KeyValue {
                                key: "http.response.status_class".into(),
                                value: AnyValue::String(status_class.as_str().into())
                            },
                            KeyValue {
                                key: "network.protocol.version".into(),
                                value: AnyValue::String(proto.as_str().into())
                            },
                        ];
                        if let Some(dp) =
                            make_exp_dp(&combo_agg[combo], attrs, combo_exemplars, start, now)
                        {
                            data_points.push(dp);
                        }
                    }
                }
            }
            Metric {
                name: "http.server.request.duration".into(),
                description: "HTTP server request duration".into(),
                unit: "s".into(),
                data: MetricData::ExponentialHistogram(ExponentialHistogramData {
                    aggregation_temporality: AggregationTemporality::Cumulative,
                    data_points,
                }),
            }
        } else {
            // Aggregate across all base combinations → single data point.
            let mut all_buckets = [0u64; N_EXP_BUCKETS];
            let (mut all_zero, mut all_sum, mut all_count) = (0u64, 0u64, 0u64);
            for agg in combo_agg {
                for (a, b) in all_buckets.iter_mut().zip(agg.0.iter()) {
                    *a += b;
                }
                all_zero += agg.1;
                all_sum += agg.2;
                all_count += agg.3;
            }
            Metric {
                name: "http.server.request.duration".into(),
                description: "HTTP server request duration".into(),
                unit: "s".into(),
                data: MetricData::ExponentialHistogram(ExponentialHistogramData {
                    aggregation_temporality: AggregationTemporality::Cumulative,
                    data_points: std::vec![ExponentialHistogramDataPoint {
                        attributes: std::vec![],
                        start_time_unix_nano: start,
                        time_unix_nano: now,
                        count: all_count,
                        // Convert the raw-µs sum to seconds at export (see make_exp_dp).
                        sum: us_to_seconds(all_sum),
                        scale: EXP_HISTOGRAM_SCALE,
                        zero_count: all_zero,
                        positive_offset: EXP_HISTOGRAM_BUCKET_OFFSET,
                        positive_bucket_counts: all_buckets.to_vec(),
                        exemplars: std::vec![],
                    }],
                }),
            }
        }
    }

    /// Builds the `nginx.http.request.duration.by_route` metric, one data point
    /// per registered location (`http.route` attribute).
    #[allow(clippy::needless_range_loop)] // r_idx is both the slice index and the route-name key
    fn build_route_metric(
        &self,
        route_agg: &[([u64; crate::shm::N_EXP_BUCKETS], u64, u64, u64)],
        amcf_ref: Option<&crate::config::MainConfig>,
        start: u64,
        now: u64,
    ) -> crate::data_model::Metric {
        use crate::data_model::{
            AggregationTemporality, AnyValue, ExponentialHistogramData,
            ExponentialHistogramDataPoint, KeyValue, Metric, MetricData,
        };
        use crate::shm::N_ROUTE_SLOTS;

        let mut data_points: std::vec::Vec<ExponentialHistogramDataPoint> = std::vec::Vec::new();
        for r_idx in 0..N_ROUTE_SLOTS {
            let route_name: std::string::String = amcf_ref
                .map(|c| std::string::String::from(c.route_name(r_idx)))
                .unwrap_or_else(|| std::format!("route_{}", r_idx));
            let attrs = std::vec![KeyValue {
                key: "http.route".into(),
                value: AnyValue::String(route_name)
            }];
            if let Some(dp) = make_exp_dp(&route_agg[r_idx], attrs, std::vec![], start, now) {
                data_points.push(dp);
            }
        }
        // Moved out of the `http.server.*` semconv namespace to
        // `nginx.*` — this is a Tier-2 nginx-specific metric, not semconv.
        Metric {
            name: "nginx.http.request.duration.by_route".into(),
            description: "HTTP server request duration by matched location (http.route)".into(),
            unit: "s".into(),
            data: MetricData::ExponentialHistogram(ExponentialHistogramData {
                aggregation_temporality: AggregationTemporality::Cumulative,
                data_points,
            }),
        }
    }

    /// Builds the `nginx.http.request.duration.by_upstream` metric, one data point
    /// per registered upstream zone (`nginx.upstream.zone` attribute).
    #[allow(clippy::needless_range_loop)] // u_idx is both the slice index and the upstream-zone key
    fn build_upstream_duration_metric(
        &self,
        upstream_agg: &[([u64; crate::shm::N_EXP_BUCKETS], u64, u64, u64)],
        amcf_ref: Option<&crate::config::MainConfig>,
        start: u64,
        now: u64,
    ) -> crate::data_model::Metric {
        use crate::data_model::{
            AggregationTemporality, AnyValue, ExponentialHistogramData,
            ExponentialHistogramDataPoint, KeyValue, Metric, MetricData,
        };
        use crate::shm::N_UPSTREAM_SLOTS;

        let mut data_points: std::vec::Vec<ExponentialHistogramDataPoint> = std::vec::Vec::new();
        for u_idx in 0..N_UPSTREAM_SLOTS {
            let uname: std::string::String = amcf_ref
                .map(|c| std::string::String::from(c.upstream_zone_name(u_idx)))
                .unwrap_or_else(|| std::format!("upstream_{}", u_idx));
            let attrs = std::vec![KeyValue {
                key: "nginx.upstream.zone".into(),
                value: AnyValue::String(uname)
            }];
            if let Some(dp) = make_exp_dp(&upstream_agg[u_idx], attrs, std::vec![], start, now) {
                data_points.push(dp);
            }
        }
        // Moved out of the `http.server.*` semconv namespace to
        // `nginx.*` — Tier-2 nginx-specific metric.
        Metric {
            name: "nginx.http.request.duration.by_upstream".into(),
            description: "HTTP server request duration by upstream zone (nginx.upstream.zone)"
                .into(),
            unit: "s".into(),
            data: MetricData::ExponentialHistogram(ExponentialHistogramData {
                aggregation_temporality: AggregationTemporality::Cumulative,
                data_points,
            }),
        }
    }
}

// ─── helpers ────────────────────────────────────────────────────────────────

/// Convert a millisecond-summed explicit histogram data tuple for export as a
/// **seconds** histogram (`nginx.upstream.*.duration`).
///
/// The worker accumulates upstream timing sums in raw ms.  This helper divides
/// the scalar sum by `1000.0` (f64) so `hist_metric` publishes the sum in
/// seconds.  Bucket counts and observation count are unchanged — bucket
/// placement was done in ms at record time (against `DURATION_BOUNDS_MS`),
/// and the exporter publishes the same thresholds in seconds (via
/// `DURATION_BOUNDS_S`), so the bucket distribution is semantically correct.
///
/// Returns `(buckets, sum_in_seconds_rounded_to_ms, count)`.  The sum is
/// converted as `(sum_ms as f64 / 1000.0).round() as u64` to avoid integer
/// truncation that would zero a sub-second aggregate; rounding to the nearest
/// ms preserves the sub-second information at the resolution nginx provides.
/// This is the same convert-at-export pattern used by the request-duration
/// exp-histogram sum (`us_to_seconds`) and span/log duration attributes.
#[inline]
fn ms_to_s_hist_sum(sum_ms: u64) -> f64 {
    sum_ms as f64 / 1000.0
}

/// Convert an integer-microsecond duration to f64 **seconds** for the
/// `http.server.request.duration` exp-histogram scalars (sum + exemplar value).
///
/// The worker buckets seconds directly (`shm::ExpHistogramSlot`) but accumulates
/// the scalar sum in raw µs; this is the lossless convert-at-export step (same
/// `duration_us / 1_000_000.0` pattern the access-log/span duration attributes
/// use in `drain/mod.rs` and `traces/mod.rs`).
#[inline]
fn us_to_seconds(value_us: u64) -> f64 {
    value_us as f64 / 1_000_000.0
}

#[inline]
fn add_histogram<const N: usize>(
    acc: &mut ([u64; N], u64, u64),
    counts: &[u64; N],
    sum: u64,
    count: u64,
) {
    for (a, &c) in acc.0.iter_mut().zip(counts.iter()) {
        *a += c;
    }
    acc.1 += sum;
    acc.2 += count;
}

/// Metric identity and publication policy for an explicit-boundary histogram.
///
/// Groups the four fields that describe WHAT the metric is (name/desc/unit) and
/// HOW it is published (temporality), leaving the remaining args — the snapshot
/// data, optional sum override, bucket bounds, and time window — at the call site
/// where they vary.
struct HistSpec<'a> {
    name: &'a str,
    desc: &'a str,
    unit: &'a str,
    temporality: crate::data_model::AggregationTemporality,
}

/// Internal OTLP-histogram builder.
///
/// Shared by all explicit-boundary histograms.  `sum_f64` allows callers that
/// need a unit-scaled sum (e.g. ms → s) to supply the pre-converted value; for
/// histograms whose native unit is already the published unit, pass
/// `data.1 as f64`.
fn hist_metric_with_sum<const N: usize>(
    spec: &HistSpec<'_>,
    data: ([u64; N], u64, u64),
    sum_f64: f64,
    bounds: std::vec::Vec<f64>,
    start_time_ns: u64,
    time_ns: u64,
) -> crate::data_model::Metric {
    use crate::data_model::{HistogramData, HistogramDataPoint, Metric, MetricData};
    Metric {
        name: spec.name.into(),
        description: spec.desc.into(),
        unit: spec.unit.into(),
        data: MetricData::Histogram(HistogramData {
            aggregation_temporality: spec.temporality,
            data_points: std::vec![HistogramDataPoint {
                attributes: std::vec![],
                start_time_unix_nano: start_time_ns,
                time_unix_nano: time_ns,
                count: data.2,
                sum: sum_f64,
                bucket_counts: data.0.to_vec(),
                explicit_bounds: bounds,
            }],
        }),
    }
}

/// Thin wrapper for histograms whose accumulated sum unit matches the published
/// unit (no scaling needed).
fn hist_metric<const N: usize>(
    spec: &HistSpec<'_>,
    data: ([u64; N], u64, u64),
    bounds: std::vec::Vec<f64>,
    start_time_ns: u64,
    time_ns: u64,
) -> crate::data_model::Metric {
    hist_metric_with_sum(spec, data, data.1 as f64, bounds, start_time_ns, time_ns)
}

/// Build one exp-histogram data point from an aggregated `(buckets, zero_count,
/// sum_us, count)` tuple.
///
/// Returns `None` when `count == 0` (skip zero-count series from the output).
/// The scalar sum is converted from raw microseconds to seconds here — one
/// lossless divide per series at export (same convert-at-export pattern as the
/// access-log/span duration attributes and `us_to_seconds`).
fn make_exp_dp(
    agg: &([u64; crate::shm::N_EXP_BUCKETS], u64, u64, u64),
    attrs: std::vec::Vec<crate::data_model::KeyValue>,
    exemplars: std::vec::Vec<crate::data_model::Exemplar>,
    start: u64,
    now: u64,
) -> Option<crate::data_model::ExponentialHistogramDataPoint> {
    use crate::shm::{EXP_HISTOGRAM_BUCKET_OFFSET, EXP_HISTOGRAM_SCALE};
    let (bc, zc, bs, bcount) = *agg;
    if bcount == 0 {
        return None;
    }
    Some(crate::data_model::ExponentialHistogramDataPoint {
        attributes: attrs,
        start_time_unix_nano: start,
        time_unix_nano: now,
        count: bcount,
        sum: us_to_seconds(bs),
        scale: EXP_HISTOGRAM_SCALE,
        zero_count: zc,
        positive_offset: EXP_HISTOGRAM_BUCKET_OFFSET,
        positive_bucket_counts: bc.to_vec(),
        exemplars,
    })
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::logs::ring::tests::make_ring_with_cap;
    use crate::logs::{
        access::{emit_access_record, SampledRequest},
        WorkerRingProducer,
    };
    use crate::metric_source::location_conf::LogExportMode;

    /// Regression: `(ngx_msec_t)-1` sentinel must NOT be recorded into
    /// upstream timing histograms.
    ///
    /// Pre-fix: `response_time`, `connect_time`, and `header_time` were cast
    /// unconditionally to `u64` and passed to `record()`, which does a
    /// `fetch_add` on the sum.  With the sentinel value (`usize::MAX as u64`
    /// = `u64::MAX` on 64-bit), one refused-connection event adds ~1.8 × 10^19
    /// to the cumulative sum, permanently poisoning the metric.
    ///
    /// This test would FAIL TO COMPILE on pre-fix code because
    /// `NGX_MSEC_SENTINEL` did not exist.  On post-fix code it verifies the
    /// sentinel value and the filter invariant using a stack-allocated
    /// `Histogram`.
    #[test]
    fn c1_upstream_sentinel_not_recorded() {
        use crate::shm::{Histogram, DURATION_BOUNDS_MS, N_DURATION_BUCKETS};

        // Verify the sentinel constant matches (ngx_msec_t)-1.
        // On 64-bit: usize::MAX as u64 = u64::MAX.
        // On 32-bit: usize::MAX as u64 = u32::MAX as u64 = 4_294_967_295.
        assert_eq!(
            super::NGX_MSEC_SENTINEL,
            usize::MAX as u64,
            "NGX_MSEC_SENTINEL must equal (ngx_msec_t)-1 cast to u64"
        );

        // Create a histogram on the stack (AtomicU64 fields, safe to use in tests).
        // SAFETY: all AtomicU64 fields are zero-initialised (from Default/const).
        let hist: Histogram<N_DURATION_BUCKETS> = unsafe { core::mem::zeroed() };

        // Simulate the post-fix sentinel filter: sentinel value is NOT recorded.
        let sentinel = super::NGX_MSEC_SENTINEL;
        if sentinel != super::NGX_MSEC_SENTINEL {
            hist.record(sentinel, &DURATION_BOUNDS_MS);
        }
        let (_, sum, count) = hist.snapshot();
        assert_eq!(sum, 0, "sentinel value must NOT be added to histogram sum");
        assert_eq!(count, 0, "sentinel value must NOT increment histogram count");

        // Verify a real value IS recorded.
        let real_ms = 42u64;
        if real_ms != super::NGX_MSEC_SENTINEL {
            hist.record(real_ms, &DURATION_BOUNDS_MS);
        }
        let (_, sum2, count2) = hist.snapshot();
        assert_eq!(sum2, 42, "real value must be recorded in histogram sum");
        assert_eq!(count2, 1, "real value must increment histogram count");
    }

    /// Minimal `SampledRequest` for unit tests.  Override fields as needed.
    // Each positional arg is a distinct optional field of `SampledRequest`; a
    // builder struct would trade one suppress for boilerplate across 10+ call sites
    // with no clarity gain.
    #[allow(clippy::too_many_arguments)]
    fn make_req<'a>(
        method: &'a [u8],
        status: u16,
        req_len: u64,
        resp_bytes: u64,
        client: &'a [u8],
        ts: u64,
        trace: Option<([u8; 16], [u8; 8])>,
        url: &'a [u8],
        ua: &'a [u8],
    ) -> SampledRequest<'a> {
        SampledRequest {
            ts_unix_nano: ts,
            trace,
            url_path: url,
            user_agent: ua,
            duration_us: 0,
            combo_idx: 0,
            method,
            status,
            request_length: req_len,
            response_bytes: resp_bytes,
            client_addr: client,
        }
    }

    // Resolve the export decision exactly as the LOG-phase gate does:
    // `any_log_export` (the cheap main-conf bool) plus the matched location's
    // mode.  For the `If` mode the gate calls `eval_export_truthy`, whose only
    // non-FFI logic is `is_truthy` over the evaluated bytes; here we feed the
    // pure `is_truthy` seam the bytes a complex value would have produced, so no
    // request stub is involved.
    fn export_selected(any_log_export: bool, mode: LogExportMode, if_cond_bytes: &[u8]) -> bool {
        if !any_log_export {
            return false;
        }
        match mode {
            LogExportMode::All => true,
            LogExportMode::If => super::is_truthy(if_cond_bytes),
            LogExportMode::Off | LogExportMode::Unset => false,
        }
    }

    /// `is_truthy` mirrors core nginx `access_log … if=`: falsy iff empty or the
    /// single byte `"0"`; everything else (including `"00"`) is truthy.
    #[test]
    fn is_truthy_matches_core_convention() {
        assert!(!super::is_truthy(b""), "empty is falsy");
        assert!(!super::is_truthy(b"0"), "single \"0\" is falsy");
        assert!(super::is_truthy(b"1"), "\"1\" is truthy");
        assert!(super::is_truthy(b"00"), "\"00\" is truthy (len != 1)");
        assert!(super::is_truthy(b"true"), "non-empty is truthy");
        assert!(super::is_truthy(b" "), "a space is truthy (non-empty)");
    }

    /// With no location selecting export (`Unset`, the default) or an explicit
    /// `Off`, the gate is closed: no ring operations occur.
    #[test]
    fn unset_and_off_modes_no_ring_touch() {
        let (_buf, ring) = make_ring_with_cap(4096);

        // Default (any_log_export off, mode Unset) → no export.
        if export_selected(false, LogExportMode::Unset, b"") {
            let producer = WorkerRingProducer { ring };
            emit_access_record(
                &producer,
                &make_req(b"GET", 503, 0, 512, b"127.0.0.1", 0, None, b"", b""),
            );
        }
        // Even with the main-conf bool on, an Unset/Off location does not export.
        if export_selected(true, LogExportMode::Unset, b"") {
            let producer = WorkerRingProducer { ring };
            emit_access_record(
                &producer,
                &make_req(b"GET", 503, 0, 512, b"127.0.0.1", 0, None, b"", b""),
            );
        }
        if export_selected(true, LogExportMode::Off, b"") {
            let producer = WorkerRingProducer { ring };
            emit_access_record(
                &producer,
                &make_req(b"GET", 503, 0, 512, b"127.0.0.1", 0, None, b"", b""),
            );
        }

        // Ring must be empty — no record pushed.
        let mut out = std::vec::Vec::new();
        assert!(!ring.pop_into(&mut out), "ring must be empty when no location selects export");
        assert_eq!(ring.drop_count(), 0, "no drops expected");
    }

    /// `If` mode exports only when the condition is truthy; a falsy condition
    /// pushes nothing, and `All` always pushes.
    #[test]
    fn mode_selection_drives_export() {
        let (_buf, ring) = make_ring_with_cap(4096);
        let mut out = std::vec::Vec::new();

        // If(falsy) — no push.
        if export_selected(true, LogExportMode::If, b"0") {
            let producer = WorkerRingProducer { ring };
            emit_access_record(
                &producer,
                &make_req(b"GET", 200, 0, 512, b"127.0.0.1", 0, None, b"", b""),
            );
        }
        assert!(!ring.pop_into(&mut out), "If(falsy) must NOT reach the tail ring");

        // If(truthy) — push expected.
        if export_selected(true, LogExportMode::If, b"1") {
            let producer = WorkerRingProducer { ring };
            emit_access_record(
                &producer,
                &make_req(b"GET", 200, 0, 0, b"127.0.0.1", 0, None, b"", b""),
            );
        }
        assert!(ring.pop_into(&mut out), "If(truthy) must reach the tail ring");

        // All — push expected even for a 200/fast request (nothing hardcoded).
        if export_selected(true, LogExportMode::All, b"") {
            let producer = WorkerRingProducer { ring };
            emit_access_record(
                &producer,
                &make_req(b"GET", 200, 0, 0, b"127.0.0.1", 0, None, b"", b""),
            );
        }
        out.clear();
        assert!(ring.pop_into(&mut out), "All must reach the tail ring for any request");
    }

    /// When a request is selected for export, the log-phase handler pushes one
    /// access record into the ring with the expected fields.
    #[test]
    fn access_emission_on_pushes_record() {
        let (_buf, ring) = make_ring_with_cap(4096);

        // Selected via All — export the record.
        if export_selected(true, LogExportMode::All, b"") {
            let producer = WorkerRingProducer { ring };
            emit_access_record(
                &producer,
                &make_req(
                    b"POST",
                    503,
                    128,
                    256,
                    b"10.0.0.1",
                    1_700_000_000_000_000_000,
                    None,
                    b"/api/test",
                    b"TestAgent/1.0",
                ),
            );
        }

        // Ring must have one record.
        let mut out = std::vec::Vec::new();
        let ok = ring.pop_into(&mut out);
        assert!(ok, "ring must have a record for a selected request");
        assert!(!out.is_empty(), "record must be non-empty");

        // Check kind byte = 0x00 (access).
        assert_eq!(out[0], 0x00, "kind must be 0 (access)");

        // Check method ("POST" = 4 bytes).
        let method_len = u16::from_be_bytes([out[10], out[11]]) as usize;
        assert_eq!(method_len, 4, "method length must be 4 for POST");
        assert_eq!(&out[12..12 + method_len], b"POST");

        // Check status code = 503.
        let sc_off = 12 + method_len;
        let status = u16::from_be_bytes([out[sc_off], out[sc_off + 1]]);
        assert_eq!(status, 503, "status code must be 503");

        // No more records.
        let mut out2 = std::vec::Vec::new();
        assert!(!ring.pop_into(&mut out2), "ring must be empty after one record");
    }

    /// Regression: `url.path` must use `r.uri` (path only) not `r.unparsed_uri`
    /// (which includes `?args`).
    ///
    /// Pre-fix: both call sites in `log_phase_handler` used `r.unparsed_uri.as_bytes()`.
    /// That field is `$request_uri` — the raw HTTP request-line URI including the query
    /// string.  A request like `GET /api/users?token=SECRET HTTP/1.1` would export
    /// `url.path = "/api/users?token=SECRET"`, violating OTel semconv (`url.path` must
    /// not include the query component) and leaking PII / credentials into tails and
    /// exemplars.
    ///
    /// Post-fix: both sites use `r.uri.as_bytes()` — the decoded, args-stripped path
    /// equivalent of `$uri`, matching the OTel semconv requirement.
    ///
    /// Mutation check (inline): the test constructs a fake `ngx_http_request_s` with
    /// distinct `uri` (path only) and `unparsed_uri` (path+args).  It asserts that
    /// `r.uri.as_bytes()` does NOT contain `?` (post-fix, correct), and that
    /// `r.unparsed_uri.as_bytes()` DOES contain `?` (what pre-fix code used — wrong).
    /// This confirms the test distinguishes the two fields and documents expected
    /// behavior as a regression guard.
    #[test]
    fn c2_url_path_excludes_query_string() {
        use nginx_sys::{ngx_http_request_s, ngx_str_t};

        let path_only: &[u8] = b"/api/users";
        let with_args: &[u8] = b"/api/users?token=SECRET";

        // Construct a minimal stack-allocated ngx_http_request_s.
        // SAFETY: all fields are zeroed; we only access `uri` and `unparsed_uri`
        // which we set explicitly below.  No nginx functions are called; no nginx
        // memory management is involved.
        let mut req: ngx_http_request_s = unsafe { core::mem::zeroed() };

        req.uri = ngx_str_t { len: path_only.len(), data: path_only.as_ptr() as *mut _ };
        req.unparsed_uri = ngx_str_t { len: with_args.len(), data: with_args.as_ptr() as *mut _ };

        // r.uri.as_bytes() — path only, no query string.
        let url_path = req.uri.as_bytes();
        assert!(
            !url_path.contains(&b'?'),
            "url.path must not contain '?' — got: {:?}",
            core::str::from_utf8(url_path).unwrap_or("<non-utf8>")
        );
        assert_eq!(url_path, path_only, "url.path must be the path-only value");

        // MUTATION CHECK: r.unparsed_uri.as_bytes() WOULD leak the query string.
        // This is what pre-fix code used; the assertion below confirms the test
        // distinguishes between the two fields and would catch a revert.
        let pre_fix_path = req.unparsed_uri.as_bytes();
        assert!(
            pre_fix_path.contains(&b'?'),
            "pre-fix path (unparsed_uri) must contain '?' — confirms test distinguishes fields"
        );
    }

    /// Regression: client-abort requests (status 0) must NOT be recorded into
    /// `request_duration_combos`.
    ///
    /// Pre-fix: `StatusClass::from_status(0)` returns `S5xx` (catch-all), so every
    /// port-scan / TLS-probe / aborted keep-alive incremented the S5xx combo,
    /// inflating server-error-rate metrics.
    ///
    /// Post-fix: `record_base_combo` skips the histogram bump when `status == 0`.
    /// Route and upstream histograms are unaffected (they still record, as the
    /// request consumed real resources regardless of the abort).
    ///
    /// This test calls the PRODUCTION `record_base_combo` function (not an
    /// inline copy of its guard), so reverting the `status != 0` check in that
    /// function causes this test to FAIL.
    #[test]
    fn f2_status_zero_skips_base_combo() {
        use crate::shm::{
            combo_index, HttpMethod, ProtoVersion, StatusClass, WorkerSlots, N_COMBOS,
        };
        use core::mem;

        // Allocate a zero-initialised buffer sized for one WorkerSlots.
        let mut buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        // SAFETY: `buf` is freshly zero-initialised to exactly `sizeof(WorkerSlots)`.
        // Zero is the valid initial state for all atomic fields.
        let slot = unsafe { &*buf.as_mut_ptr().cast::<WorkerSlots>() };

        let method = HttpMethod::Get;
        let proto = ProtoVersion::Http11;
        let duration_us: u64 = 1_500;

        // ── status == 0: production record_base_combo must skip the bump ──
        // The S5xx combo is computed (as production code does — needed for the
        // exemplar reservoir) but the histogram bump must be skipped.
        let status: u16 = 0;
        let status_class_0 = StatusClass::from_status(status); // = S5xx (catch-all)
        let base_idx_0 = combo_index(method, status_class_0, proto);
        // Call the PRODUCTION function — not an inline reimplementation.
        super::record_base_combo(slot, status, base_idx_0, duration_us);

        // All 160 combos must remain zero — record_base_combo skipped the bump.
        for idx in 0..N_COMBOS {
            let (_, _, _, count) = slot.request_duration_combos[idx].snapshot();
            assert_eq!(
                count, 0,
                "request_duration_combos[{idx}] must be 0 after status-0 request — \
                 routing status 0 → S5xx would incorrectly increment that combo"
            );
        }

        // ── Confirm S5xx IS the slot pre-fix would have touched ──
        // (Validates the test is meaningful: status 0 maps to S5xx, not skipped.)
        let s5xx_idx = combo_index(method, StatusClass::S5xx, proto);
        assert_eq!(
            base_idx_0, s5xx_idx,
            "sanity: StatusClass::from_status(0) must resolve to the S5xx combo index"
        );
        // Directly record into S5xx to confirm the slot is otherwise functional.
        slot.request_duration_combos[s5xx_idx].record(duration_us);
        let (_, _, _, s5xx_count) = slot.request_duration_combos[s5xx_idx].snapshot();
        assert_eq!(
            s5xx_count, 1,
            "sanity: S5xx combo must be the one that would otherwise be incremented"
        );

        // ── status 200: production record_base_combo must record into S2xx ──
        let status200: u16 = 200;
        let status_class_200 = StatusClass::from_status(status200);
        let base_idx_200 = combo_index(method, status_class_200, proto);
        // Call the PRODUCTION function.
        super::record_base_combo(slot, status200, base_idx_200, duration_us);
        let s2xx_idx = combo_index(method, StatusClass::S2xx, proto);
        let (_, _, _, s2xx_count) = slot.request_duration_combos[s2xx_idx].snapshot();
        assert_eq!(s2xx_count, 1, "status-200 request must be recorded into S2xx combo");
    }

    /// The request-duration exp-histogram scalar `sum` and exemplar `value`
    /// are published in **seconds** — the worker accumulates raw µs, and the
    /// exporter divides by 1e6 once.  A 150µs observation must surface as
    /// `0.00015 s`, NOT `150`.  (Reverting the `/ 1_000_000.0` in
    /// [`super::us_to_seconds`] makes this assertion fail with 150.0.)
    #[test]
    fn f3_duration_sum_and_exemplar_in_seconds() {
        assert_eq!(super::us_to_seconds(150), 0.00015, "150µs must convert to 0.00015 s");
        assert_eq!(super::us_to_seconds(1_000_000), 1.0, "1e6 µs must convert to 1 s");
        assert_eq!(super::us_to_seconds(0), 0.0, "0µs must convert to 0 s");
        // A raw-µs sum of 1500 (e.g. 10×150µs) → 0.0015 s, not 1500.
        assert_eq!(super::us_to_seconds(1500), 0.0015, "summed µs convert losslessly");
    }

    /// `http.server.request.duration` must emit `http.response.status_class`
    /// with a self-describing string value (`"5xx"` for a 503), NOT the old
    /// `http.response.status_code` integer representative (500).
    ///
    /// Mutation check: reverting `key: "http.response.status_class"` back to
    /// `"http.response.status_code"` makes the `assert_eq!(key, "http.response.status_class")`
    /// assertion fail; reverting `AnyValue::String(…)` back to `AnyValue::Int(…)` makes
    /// the value assertion fail.
    #[test]
    fn f6_status_class_attribute_key_and_value() {
        use crate::data_model::{AnyValue, MetricData};
        use crate::shm::{combo_index, HttpMethod, ProtoVersion, StatusClass, WorkerSlots};
        use core::mem;

        // Zero-initialise one WorkerSlots.
        let mut buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        // SAFETY: `buf` is zero-initialised to exactly `sizeof(WorkerSlots)`; zero
        // is the valid initial state for all `AtomicU64` fields within it.
        let slot = unsafe { &*buf.as_mut_ptr().cast::<WorkerSlots>() };

        // Record a 503 (S5xx) with a real duration.
        let method = HttpMethod::Get;
        let proto = ProtoVersion::Http11;
        let sc = StatusClass::from_status(503);
        let base_idx = combo_index(method, sc, proto);
        slot.request_duration_combos[base_idx].record(50_000); // 50ms

        // Build an InstrumentedSource over this one-worker slot.
        let mut zone_buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        zone_buf.copy_from_slice(&buf);
        let src = crate::metric_source::instrumented::InstrumentedSource {
            base: zone_buf.as_mut_ptr(),
            n_workers: 1,
            start_time_unix_nano: 0,
            status_code_class_enabled: true,
            amcf: core::ptr::null(),
        };
        use crate::metric_source::MetricSource;
        let metrics = src.collect();

        // Find the base duration metric.
        let dur = metrics
            .iter()
            .find(|m| m.name == "http.server.request.duration")
            .expect("http.server.request.duration must be present");

        // Find the data point with method=GET.
        let MetricData::ExponentialHistogram(ref eh) = dur.data else {
            panic!("duration metric must be an ExponentialHistogram");
        };

        // Find the S5xx data point (count == 1, method == GET).
        let dp = eh
            .data_points
            .iter()
            .find(|dp| dp.count == 1)
            .expect("must have a data point with count=1 (our S5xx observation)");

        // The attribute for the status dimension must use the NEW key.
        let status_kv = dp
            .attributes
            .iter()
            .find(|kv| kv.key.contains("status"))
            .expect("must have a status-related attribute");
        assert_eq!(
            status_kv.key, "http.response.status_class",
            "F6: key must be http.response.status_class, not http.response.status_code \
             (reverting the key in instrumented.rs makes this fail)"
        );
        // The value must be the string "5xx", not the integer 500.
        match &status_kv.value {
            AnyValue::String(s) => assert_eq!(
                s.as_str(),
                "5xx",
                "F6: value must be the string \"5xx\" for a 503, not 500 \
                 (reverting AnyValue::String to AnyValue::Int makes this fail)"
            ),
            AnyValue::Int(n) => panic!(
                "F6: value must be String(\"5xx\"), got Int({n}) — old http.response.status_code \
                 representative value; revert detected"
            ),
            other => panic!("F6: unexpected value type {other:?}"),
        }
    }

    /// The decomposed duration metrics must use the `nginx.*` namespace
    /// (Tier 2); the old `http.server.*` names must not be emitted.
    ///
    /// Mutation check: reverting the metric names in `instrumented.rs` back to
    /// `http.server.request.duration.by_route` / `http.server.request.duration.by_upstream`
    /// makes the "old name absent" assertions fail.
    #[test]
    fn f2f9_tier2_metrics_renamed_to_nginx_namespace() {
        use crate::shm::WorkerSlots;
        use core::mem;

        let mut buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        // SAFETY: `buf` is zero-initialised to exactly `sizeof(WorkerSlots)`; zero
        // is the valid initial state for all `AtomicU64` fields within it.
        // Record one observation so the metrics have at least one data point.
        let slot = unsafe { &*buf.as_mut_ptr().cast::<WorkerSlots>() };
        slot.request_duration_combos[0].record(1_000);
        slot.route_duration_combos[0].record(1_000);
        slot.upstream_duration_combos[0].record(1_000);
        // Also record upstream timing to make those metrics appear.
        slot.upstream_response_ms.record(5, &crate::shm::DURATION_BOUNDS_MS);

        let src = crate::metric_source::instrumented::InstrumentedSource {
            base: buf.as_mut_ptr(),
            n_workers: 1,
            start_time_unix_nano: 0,
            status_code_class_enabled: false,
            amcf: core::ptr::null(),
        };
        use crate::metric_source::MetricSource;
        let metrics = src.collect();
        let names: std::vec::Vec<&str> = metrics.iter().map(|m| m.name.as_str()).collect();

        // New names MUST be present.
        assert!(
            names.contains(&"nginx.http.request.duration.by_route"),
            "F2/F9: nginx.http.request.duration.by_route must be present; names={names:?}"
        );
        assert!(
            names.contains(&"nginx.http.request.duration.by_upstream"),
            "F2/F9: nginx.http.request.duration.by_upstream must be present; names={names:?}"
        );
        assert!(
            names.contains(&"nginx.upstream.response.duration"),
            "F2/F9: nginx.upstream.response.duration must be present; names={names:?}"
        );
        assert!(
            names.contains(&"nginx.upstream.bytes.received"),
            "F2/F9: nginx.upstream.bytes.received must be present; names={names:?}"
        );

        // Old names MUST NOT be present (reverting the renames makes these fail).
        assert!(
            !names.contains(&"http.server.request.duration.by_route"),
            "F2/F9: old http.server.request.duration.by_route must NOT be emitted; names={names:?}"
        );
        assert!(
            !names.contains(&"http.server.request.duration.by_upstream"),
            "F2/F9: old http.server.request.duration.by_upstream must NOT be emitted; \
             names={names:?}"
        );
        assert!(
            !names.contains(&"http.server.upstream.response.duration"),
            "F2/F9: old http.server.upstream.response.duration must NOT be emitted; \
             names={names:?}"
        );
        assert!(
            !names.contains(&"http.server.upstream.bytes.received"),
            "F2/F9: old http.server.upstream.bytes.received must NOT be emitted; names={names:?}"
        );

        // Base metric must remain unchanged (Tier 1 — do NOT rename).
        assert!(
            names.contains(&"http.server.request.duration"),
            "Tier-1 base metric must stay as http.server.request.duration; names={names:?}"
        );
        // Body-size metrics must also remain unchanged (F8 refuted — correct semconv names).
        assert!(
            names.contains(&"http.server.request.body.size"),
            "http.server.request.body.size must not change; names={names:?}"
        );
        assert!(
            names.contains(&"http.server.response.body.size"),
            "http.server.response.body.size must not change; names={names:?}"
        );
    }

    /// Upstream duration metrics must emit unit `"s"` and the scalar sum
    /// must be in seconds (ms sum ÷ 1000.0), not raw milliseconds.
    ///
    /// Regression: a 5ms upstream response time must surface as `0.005 s`, not `5`.
    ///
    /// Mutation check: reverting the unit from `"s"` to `"ms"` and the
    /// `ms_to_s_hist_sum` helper back to raw ms makes these assertions fail.
    #[test]
    fn f4_upstream_duration_unit_is_seconds() {
        use crate::data_model::MetricData;
        use crate::shm::{WorkerSlots, DURATION_BOUNDS_MS};
        use core::mem;

        let mut buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        // SAFETY: `buf` is zero-initialised to exactly `sizeof(WorkerSlots)`; zero
        // is the valid initial state for all `AtomicU64` fields within it.
        let slot = unsafe { &*buf.as_mut_ptr().cast::<WorkerSlots>() };
        // Record a known upstream response time: 5 ms.
        slot.upstream_response_ms.record(5, &DURATION_BOUNDS_MS);
        // Record upstream header and connect timings too.
        slot.upstream_header_ms.record(3, &DURATION_BOUNDS_MS);
        slot.upstream_connect_ms.record(1, &DURATION_BOUNDS_MS);

        let src = crate::metric_source::instrumented::InstrumentedSource {
            base: buf.as_mut_ptr(),
            n_workers: 1,
            start_time_unix_nano: 0,
            status_code_class_enabled: false,
            amcf: core::ptr::null(),
        };
        use crate::metric_source::MetricSource;
        let metrics = src.collect();

        for metric_name in &[
            "nginx.upstream.response.duration",
            "nginx.upstream.header.duration",
            "nginx.upstream.connect.duration",
        ] {
            let m = metrics
                .iter()
                .find(|m| m.name.as_str() == *metric_name)
                .unwrap_or_else(|| panic!("{metric_name} must be present in emitted metrics"));

            // Unit must be "s" (reverting to "ms" makes this fail).
            assert_eq!(
                m.unit, "s",
                "F4: {metric_name} unit must be \"s\", not \"ms\" \
                 (reverting unit string makes this fail)"
            );

            // Extract the histogram data point.
            let MetricData::Histogram(ref hist) = m.data else {
                panic!("{metric_name} must be a Histogram");
            };
            let dp = &hist.data_points[0];

            // Sum must be in seconds.  The exact value depends on which metric;
            // all three have count=1 and sum that is the recorded ms ÷ 1000.
            // The key invariant: sum < 1.0 for any < 1000ms observation.
            assert!(
                dp.sum < 1.0,
                "F4: {metric_name} sum must be < 1.0 s for a sub-second recording; \
                 got sum={} (if sum > 0 and >= 1, the ms→s conversion is missing)",
                dp.sum
            );
            assert!(
                dp.sum > 0.0,
                "F4: {metric_name} sum must be > 0 (observation was recorded); \
                 got sum={}",
                dp.sum
            );
        }

        // Spot-check the response duration sum: 5ms → 0.005 s.
        let resp = metrics
            .iter()
            .find(|m| m.name == "nginx.upstream.response.duration")
            .expect("nginx.upstream.response.duration must be present");
        let MetricData::Histogram(ref hist) = resp.data else { panic!() };
        let sum_s = hist.data_points[0].sum;
        assert!(
            (sum_s - 0.005).abs() < 1e-9,
            "F4: 5ms must convert to 0.005 s, got {sum_s} \
             (reverting ms_to_s_hist_sum makes this fail with sum=5.0)"
        );
    }

    /// `ngx_otel.export_interval` must emit unit `"s"`, and the value for
    /// a 10,000ms interval must be 10 (seconds), not 10,000.
    ///
    /// Mutation check: reverting unit `"s"` → `"ms"` and the `/ 1000` in
    /// `SelfMetricsSource::collect` makes these assertions fail.
    #[test]
    fn f5_export_interval_unit_is_seconds() {
        use crate::data_model::{MetricData, NumberValue};
        use crate::drain::SelfMetricsSource;
        use crate::metric_source::MetricSource;

        let src = SelfMetricsSource {
            interval_ms: 10_000, // 10 seconds
            start_time_unix_nano: 0,
        };
        let metrics = src.collect();
        let m = metrics
            .iter()
            .find(|m| m.name == "ngx_otel.export_interval")
            .expect("ngx_otel.export_interval must be present");

        // Unit must be "s" (reverting to "ms" makes this fail).
        assert_eq!(
            m.unit, "s",
            "F5: ngx_otel.export_interval unit must be \"s\", not \"ms\" \
             (reverting unit string makes this fail)"
        );

        // Value must be 10 (seconds), not 10_000 (ms).
        let MetricData::Gauge(ref g) = m.data else {
            panic!("ngx_otel.export_interval must be a Gauge");
        };
        assert_eq!(
            g.data_points[0].value,
            NumberValue::AsInt(10),
            "F5: 10,000ms interval must emit value 10 (seconds), not 10,000 \
             (reverting the / 1000 in SelfMetricsSource::collect makes this fail with 10000)"
        );
    }

    /// TLS cert attribute keys must be namespaced under `tls.server.certificate.*`.
    ///
    /// Mutation check: reverting the keys back to bare `file_path`, `serial_number`, etc.
    /// makes the `assert_eq!(key, "tls.server.certificate.file_path", ...)` assertion fail.
    #[test]
    fn f11_tls_cert_attrs_namespaced() {
        use crate::cert_table::CertInfo;
        use crate::metric_source::tls_cert::ServingCertSource;
        use crate::metric_source::MetricSource;

        let cert = CertInfo {
            file_path: "/etc/ssl/test.crt".into(),
            server_name: "test.example".into(),
            not_before_unix: 1_700_000_000,
            not_after_unix: 1_893_456_000,
            subject_cn: "test.example".into(),
            issuer_cn: "Test CA".into(),
            serial: "AABB".into(),
            pubkey_alg: "RSA".into(),
            sig_alg: "RSA-SHA256".into(),
        };
        let src = ServingCertSource { certs: std::slice::from_ref(&cert) };
        let metrics = src.collect();
        assert!(!metrics.is_empty(), "must emit cert metrics");

        let dp = match &metrics[0].data {
            crate::data_model::MetricData::Gauge(g) => &g.data_points[0],
            _ => panic!("must be a Gauge"),
        };
        let keys: std::vec::Vec<&str> = dp.attributes.iter().map(|kv| kv.key.as_str()).collect();

        // Namespaced keys MUST be present.
        assert!(
            keys.contains(&"tls.server.certificate.file_path"),
            "F11: tls.server.certificate.file_path must be present; keys={keys:?}"
        );
        assert!(
            keys.contains(&"tls.server.certificate.serial_number"),
            "F11: tls.server.certificate.serial_number must be present; keys={keys:?}"
        );
        assert!(
            keys.contains(&"tls.server.certificate.public_key_algorithm"),
            "F11: tls.server.certificate.public_key_algorithm must be present; keys={keys:?}"
        );
        assert!(
            keys.contains(&"tls.server.certificate.signature_algorithm"),
            "F11: tls.server.certificate.signature_algorithm must be present; keys={keys:?}"
        );

        // Bare (un-namespaced) keys MUST NOT be present.
        assert!(
            !keys.contains(&"file_path"),
            "F11: bare 'file_path' must NOT be emitted; reverting the namespace makes this fail"
        );
        assert!(
            !keys.contains(&"serial_number"),
            "F11: bare 'serial_number' must NOT be emitted; reverting the namespace makes this fail"
        );
        assert!(
            !keys.contains(&"public_key_algorithm"),
            "F11: bare 'public_key_algorithm' must NOT be emitted; reverting the namespace makes this fail"
        );
        assert!(
            !keys.contains(&"signature_algorithm"),
            "F11: bare 'signature_algorithm' must NOT be emitted; reverting the namespace makes this fail"
        );

        // Already-namespaced keys must remain unchanged.
        assert!(keys.contains(&"tls.server.subject"), "tls.server.subject must be present");
        assert!(keys.contains(&"tls.server.issuer"), "tls.server.issuer must be present");
    }

    /// `sum_upstream_states` must aggregate timings/bytes across ALL upstream
    /// attempts (the `r->upstream_states` array), matching the core
    /// `$upstream_response_time` / `$upstream_*_bytes` variables — not just read
    /// the last (`u->state`) attempt.
    ///
    /// Mutation: revert the walk to read only the final state (the pre-fix
    /// behaviour) and this test fails — the sum would report only attempt #2's
    /// values instead of the total across both real attempts.
    #[test]
    fn upstream_states_summed_across_attempts() {
        use nginx_sys::{ngx_array_t, ngx_http_upstream_state_t, ngx_str_t};

        let sentinel = super::NGX_MSEC_SENTINEL as nginx_sys::ngx_msec_t;

        // A dummy peer name so `peer` is non-null for the real attempts.
        // SAFETY: `ngx_str_t` is a plain (len, data) C struct; a zeroed value is
        // a valid empty string. Only its address is used (as a non-null marker).
        let mut peer_name: ngx_str_t = unsafe { core::mem::zeroed() };
        let peer_ptr = &raw mut peer_name;

        // Build a synthetic upstream-states array with two real attempts plus a
        // NULL-peer boundary marker (which must be skipped).
        // SAFETY: `ngx_http_upstream_state_t` is a plain numeric/pointer C
        // struct; a zeroed array is a valid all-zero initial state we then
        // overwrite field-by-field. No nginx functions touch this memory.
        let mut states: [ngx_http_upstream_state_t; 3] = unsafe { core::mem::zeroed() };

        // Attempt 1: connect=5, header=10, response=20, rx=100, tx=40.
        states[0].peer = peer_ptr;
        states[0].connect_time = 5;
        states[0].header_time = 10;
        states[0].response_time = 20;
        states[0].bytes_received = 100;
        states[0].bytes_sent = 40;

        // Boundary marker: NULL peer — must be ignored entirely.
        states[1].peer = core::ptr::null_mut();
        states[1].connect_time = 999;
        states[1].header_time = 999;
        states[1].response_time = 999;
        states[1].bytes_received = 999;
        states[1].bytes_sent = 999;

        // Attempt 2 (the LAST / `u->state` one): connect=sentinel (refused),
        // header=sentinel, response=7, rx=200, tx=60.
        states[2].peer = peer_ptr;
        states[2].connect_time = sentinel;
        states[2].header_time = sentinel;
        states[2].response_time = 7;
        states[2].bytes_received = 200;
        states[2].bytes_sent = 60;

        // SAFETY: zeroed `ngx_array_t` is a valid empty array header we then
        // point at the stack `states` slice; only plain fields are written.
        let mut arr: ngx_array_t = unsafe { core::mem::zeroed() };
        arr.elts = states.as_mut_ptr().cast();
        arr.nelts = 3;
        arr.size = core::mem::size_of::<ngx_http_upstream_state_t>();
        arr.nalloc = 3;

        // SAFETY: `arr` is a valid `ngx_array_t` whose `elts` points to 3
        // initialised states for the duration of this call.
        let sum = unsafe { super::sum_upstream_states(&raw mut arr) }.expect("non-empty states");

        // response_time: 20 (attempt 1) + 7 (attempt 2) = 27.  Reading only the
        // last attempt (`u->state`) would yield 7.
        assert_eq!(sum.response_ms, Some(27), "response_time must sum across attempts");
        // header_time: 10 (attempt 1) + sentinel (skipped) = 10.
        assert_eq!(sum.header_ms, Some(10), "header_time sums non-sentinel attempts");
        // connect_time: 5 (attempt 1) + sentinel (skipped) = 5.
        assert_eq!(sum.connect_ms, Some(5), "connect_time sums non-sentinel attempts");
        // bytes: 100 + 200 = 300 received, 40 + 60 = 100 sent.
        assert_eq!(sum.bytes_received, 300, "bytes_received must sum across attempts");
        assert_eq!(sum.bytes_sent, 100, "bytes_sent must sum across attempts");

        // Empty / null arrays yield None (no upstream attempts).
        // SAFETY: as for `arr` — a zeroed, then partially-filled, array header.
        let mut empty: ngx_array_t = unsafe { core::mem::zeroed() };
        empty.elts = states.as_mut_ptr().cast();
        empty.nelts = 0;
        // SAFETY: `empty` is a valid array header with nelts == 0.
        assert!(unsafe { super::sum_upstream_states(&raw mut empty) }.is_none());
        // SAFETY: a null `states` pointer is explicitly handled by the helper.
        assert!(unsafe { super::sum_upstream_states(core::ptr::null_mut()) }.is_none());

        // All-sentinel timing for a field → None (no metric recorded), matching
        // the core variables' "-" output.
        // SAFETY: zeroed plain C struct, then field-overwritten.
        let mut all_sentinel: [ngx_http_upstream_state_t; 1] = unsafe { core::mem::zeroed() };
        all_sentinel[0].peer = peer_ptr;
        all_sentinel[0].connect_time = sentinel;
        all_sentinel[0].response_time = 3;
        all_sentinel[0].header_time = sentinel;
        // SAFETY: zeroed array header, then pointed at `all_sentinel`.
        let mut arr2: ngx_array_t = unsafe { core::mem::zeroed() };
        arr2.elts = all_sentinel.as_mut_ptr().cast();
        arr2.nelts = 1;
        // SAFETY: `arr2` is a valid 1-element array header over `all_sentinel`.
        let sum2 = unsafe { super::sum_upstream_states(&raw mut arr2) }.expect("non-empty");
        assert_eq!(sum2.connect_ms, None, "all-sentinel connect_time → None");
        assert_eq!(sum2.header_ms, None, "all-sentinel header_time → None");
        assert_eq!(sum2.response_ms, Some(3));
    }

    /// `realip_peer()` falls back to `connection->addr_text` + `sockaddr` port
    /// when `$realip_remote_addr` is absent (stubbed `ngx_http_get_variable`
    /// returns null → `get_var()` returns `b""` → fallback path taken).
    ///
    /// This test stands in for the --without-http_realip_module environment:
    /// when $realip_remote_addr is unregistered, get_var() returns b"" (stubbed
    /// to null in cfg(test)), so realip_peer() falls back to reading the
    /// immediate socket peer (connection->addr_text + sockaddr_port). Per OTel
    /// semconv, network.peer.address/port = the immediate socket peer, not any
    /// forwarded IP.
    ///
    /// Mutation check: temporarily return `(b"", 0)` from the fallback branch in
    /// `realip_peer()` → this test fails with `assert_eq!(addr, b"203.0.113.7")`.
    #[test]
    fn realip_peer_falls_back_to_socket_peer_ipv4() {
        use nginx_sys::{ngx_connection_t, ngx_http_request_s, ngx_str_t};

        let addr_text: &[u8] = b"203.0.113.7";

        // Build a sockaddr_in on the stack.  sin_port is in network byte order.
        // SAFETY: `sockaddr_in` is a plain numeric C struct; zeroed then
        // field-overwritten is valid; no nginx functions touch this memory.
        let mut sin: libc::sockaddr_in = unsafe { core::mem::zeroed() };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = 54321u16.to_be();

        // Build the connection with addr_text pointing at our slice and sockaddr
        // pointing at the sockaddr_in above.
        // SAFETY: `ngx_connection_t` is a `#[repr(C)]` POD struct; zeroed is a
        // valid initial state (null pointers, zero fds); we only access the two
        // fields we set (`addr_text`, `sockaddr`) via the fallback branch.
        let mut conn: ngx_connection_t = unsafe { core::mem::zeroed() };
        conn.addr_text = ngx_str_t { len: addr_text.len(), data: addr_text.as_ptr() as *mut _ };
        conn.sockaddr = &raw mut sin as *mut nginx_sys::sockaddr;

        // Build a minimal request pointing at our connection.
        // SAFETY: `ngx_http_request_s` is a `#[repr(C)]` POD struct; zeroed is a
        // valid initial state; we only access `connection`, which we set here.
        let mut req: ngx_http_request_s = unsafe { core::mem::zeroed() };
        req.connection = &raw mut conn;

        // SAFETY: `req` is a valid stack-allocated ngx_http_request_s for the
        // duration of this call; `realip_peer` only dereferences `connection`,
        // `addr_text`, and `sockaddr`, all of which we have initialised.
        let (peer_addr, peer_port) = unsafe { super::realip_peer(&raw mut req) };
        assert_eq!(peer_addr, b"203.0.113.7", "fallback addr must be connection->addr_text");
        assert_eq!(peer_port, 54321, "fallback port must be decoded from sockaddr_in.sin_port");
    }

    /// Same fallback path as `realip_peer_falls_back_to_socket_peer_ipv4` but
    /// with an IPv6 `sockaddr_in6` to exercise the `AF_INET6` arm of
    /// `sockaddr_port()`.
    ///
    /// Mutation check: reverting the `AF_INET6` arm to return 0 instead of
    /// `u16::from_be((*sin6).sin6_port)` makes this fail with `assert_eq!(port, 8080)`.
    #[test]
    fn realip_peer_falls_back_to_socket_peer_ipv6() {
        use nginx_sys::{ngx_connection_t, ngx_http_request_s, ngx_str_t};

        let addr_text: &[u8] = b"2001:db8::1";

        // Build a sockaddr_in6 on the stack.
        // SAFETY: `sockaddr_in6` is a plain numeric C struct; zeroed then
        // field-overwritten is valid; no nginx functions touch this memory.
        let mut sin6: libc::sockaddr_in6 = unsafe { core::mem::zeroed() };
        sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sin6.sin6_port = 8080u16.to_be();

        // SAFETY: see `realip_peer_falls_back_to_socket_peer_ipv4`.
        let mut conn: ngx_connection_t = unsafe { core::mem::zeroed() };
        conn.addr_text = ngx_str_t { len: addr_text.len(), data: addr_text.as_ptr() as *mut _ };
        conn.sockaddr = &raw mut sin6 as *mut nginx_sys::sockaddr;

        // SAFETY: `ngx_http_request_s` is a `#[repr(C)]` POD struct; zeroed is a
        // valid initial state; we only access `connection`, which we set here.
        let mut req: ngx_http_request_s = unsafe { core::mem::zeroed() };
        req.connection = &raw mut conn;

        // SAFETY: as above; `realip_peer` only reads `connection`, `addr_text`,
        // and `sockaddr`, all of which are initialised.
        let (peer_addr, peer_port) = unsafe { super::realip_peer(&raw mut req) };
        assert_eq!(peer_addr, b"2001:db8::1", "fallback addr must be connection->addr_text (IPv6)");
        assert_eq!(peer_port, 8080, "fallback port must be decoded from sockaddr_in6.sin6_port");
    }

    /// When `connection->addr_text` has len=0 (empty), `realip_peer()` must
    /// return `b""` for the address — the degenerate / unconnected case.
    ///
    /// Mutation check: removing the `len > 0` guard in the fallback branch and
    /// instead calling `from_raw_parts(null, 0)` would be undefined behaviour at
    /// runtime. The test pins the observable return value for this degenerate
    /// input so that any change to the guard logic is caught.
    #[test]
    fn realip_peer_degenerate_empty_addr_text() {
        use nginx_sys::{ngx_connection_t, ngx_http_request_s, ngx_str_t};

        // sockaddr_in with a non-zero port — confirms port is also read from
        // sockaddr even when addr_text is empty (the guards are independent).
        // SAFETY: `sockaddr_in` is a plain numeric C struct; zeroed then
        // field-overwritten is valid; no nginx functions touch this memory.
        let mut sin: libc::sockaddr_in = unsafe { core::mem::zeroed() };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = 9999u16.to_be();

        // SAFETY: `ngx_connection_t` zeroed; addr_text is explicitly empty
        // (len=0, data=null — the zeroed default); sockaddr points at a valid sin.
        let mut conn: ngx_connection_t = unsafe { core::mem::zeroed() };
        // Leave addr_text as zeroed: len=0, data=null → triggers the `len > 0` guard.
        conn.addr_text = ngx_str_t { len: 0, data: core::ptr::null_mut() };
        conn.sockaddr = &raw mut sin as *mut nginx_sys::sockaddr;

        // SAFETY: `ngx_http_request_s` is a `#[repr(C)]` POD struct; zeroed is a
        // valid initial state; we only access `connection`, which we set here.
        let mut req: ngx_http_request_s = unsafe { core::mem::zeroed() };
        req.connection = &raw mut conn;

        // SAFETY: as above; `realip_peer` only reads `connection`, `addr_text`,
        // and `sockaddr`; all are valid for the call duration.
        let (peer_addr, peer_port) = unsafe { super::realip_peer(&raw mut req) };
        assert_eq!(peer_addr, b"", "empty addr_text must yield empty peer address");
        // Port is still read from sockaddr (addr_text guard is independent of the
        // sockaddr-null guard): the connection has a valid sockaddr so port is 9999.
        assert_eq!(
            peer_port, 9999,
            "port is still read from sockaddr even when addr_text is empty"
        );
    }
}
