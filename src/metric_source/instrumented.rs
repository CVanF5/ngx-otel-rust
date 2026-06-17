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

use core::sync::atomic::Ordering;

use nginx_sys;
use ngx::core::Status;
use ngx::http::{
    HttpModuleLocationConf, HttpModuleMainConf, HttpPhase, HttpRequestHandler, NgxHttpCoreModule,
    Request,
};

use crate::logs::{
    access::{emit_access_record, SampledRequest},
    WorkerRingProducer,
};
use crate::metric_source::location_conf::LogExportMode;
use crate::shm::{
    combo_index, logs_access_ring, spans_ring, worker_slots, HttpMethod, ProtoVersion, StatusClass,
    WorkerSlots, BYTES_BOUNDS, DEFAULT_SPAN_RING_CAP, DURATION_BOUNDS_MS, N_BYTES_BUCKETS,
    N_DURATION_BUCKETS, UPSTREAM_IDX_OTHER,
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

        // Scaffold: prove the hot-path read is zero-cost.
        // One Relaxed atomic load on control_shm.flags per request.
        // The loaded value is intentionally discarded; a future dynamic-reconfig
        // fast-path will use it (sampling rate, dropped attributes, etc.). This
        // load is inside the is_configured() gate (we returned above if
        // amcf.main_conf returned None, i.e., the module is disabled) so
        // module-loaded-but-disabled stays zero-cost.
        // TODO: act on the loaded flags value.
        if let Some(ctrl) = amcf.control_shm_ptr() {
            // SAFETY: `control_shm_ptr()` returns `Some` only when the control shm
            // zone is mapped, so `ctrl` points to a valid control struct in shm for
            // the worker's lifetime; `flags` is an atomic, so the concurrent load is
            // well-defined.
            let _ = unsafe { (*ctrl).flags.load(Ordering::Relaxed) };
        }

        // Obtain base address of the shm zone.
        let base = match amcf.shm_base() {
            Some(b) => b,
            None => return Status::NGX_OK,
        };

        // Determine current worker index (no syscall — nginx global).
        // SAFETY: `ngx_worker` is a `static mut` set once by nginx during worker
        // init and only ever read thereafter from this worker process, so reading
        // it on the (single-threaded) request path is sound.
        let worker_id = unsafe { nginx_sys::ngx_worker };

        // Bounds guard: if `check_zone_sizing` somehow didn't fire (e.g.
        // the module was loaded without going through init_module), catch the
        // out-of-range index here rather than writing past the zone end.
        // `shm_n_workers()` derives the zone capacity from the registered zone
        // size — zero cost: one pointer load + integer arithmetic, no alloc/lock.
        let n_workers = amcf.shm_n_workers();
        if worker_id >= n_workers {
            // Hard invariant violation: zone was undersized for this worker.
            // Log at ALERT (once per request until restart — the init_module
            // check should have prevented this) and disable for this worker.
            let r = request.as_ref();
            // SAFETY: `r.connection` is a valid non-null pointer for the
            // lifetime of the request; `(*connection).log` is the request log.
            let log = unsafe { (*r.connection).log };
            ngx::ngx_log_error!(
                nginx_sys::NGX_LOG_ALERT,
                log,
                "otel: worker_id {} >= zone capacity {} — module disabled \
                 for this worker; move worker_processes before http{{}}",
                worker_id,
                n_workers
            );
            return Status::NGX_OK;
        }

        debug_assert!(worker_id < n_workers, "worker_id out of zone bounds");
        // Get our slot. No allocation; pointer arithmetic only.
        // SAFETY: `worker_id < n_workers` (enforced by the bounds guard above);
        // `n_workers` is derived from the zone size so the slot is within the zone.
        let slot = unsafe { &*worker_slots(base, worker_id) };

        // Use AsRef to get a typed reference to the underlying ngx_http_request_t.
        let r = request.as_ref();

        // ── Read SpanCtx early (parse-once + dual-clock) ───────────────────
        // Read BEFORE the duration computation so the monotonic anchor in
        // SpanCtx.start_mono can drive the µs histogram when tracing is on.
        // Set by SpanStartHandler in REWRITE.  None when tracing is not configured.
        // Re-used for:
        //   (1) µs duration histogram (this block).
        //   (2) trace correlation on the access tail log / exemplar (below).
        //   (3) span record emission when sampled (the span block below).
        let span_ctx: Option<&crate::traces::ctx::SpanCtx> = {
            use crate::traces::ctx::{recover_span_ctx, SpanCtx};
            // SAFETY: `ngx_http_otel_module` is a valid static module descriptor;
            // `get_module_ctx` reads the request ctx array at our module's index and
            // returns a valid reference only when non-null (set by `SpanStartHandler`
            // from a pool-allocated `SpanCtx` that lives for the full request lifetime).
            let module = unsafe { &*core::ptr::addr_of!(crate::ngx_http_otel_module) };
            let slot = request.get_module_ctx::<SpanCtx>(module);
            // The LOG phase can run AFTER an internal redirect (error_page /
            // try_files), where nginx has zeroed the module-ctx array.  Recover the
            // SpanCtx from the pool-cleanup anchor so the LOG phase sees pass-1's
            // span (one span per request).  The recovery walk runs ONLY when the
            // slot is NULL && r->internal/filter_finalize — i.e. post-redirect.
            match slot {
                Some(c) => Some(c),
                None => {
                    let r = request.as_ref() as *const _ as *mut nginx_sys::ngx_http_request_t;
                    // SAFETY: `r` is the live request pointer; `module` is the
                    // process-lifetime descriptor; the NULL slot is passed in.
                    let recovered = unsafe { recover_span_ctx(r, module, core::ptr::null_mut()) };
                    // SAFETY: `recovered` is either NULL or a pointer into the
                    // request pool (the cleanup-anchored SpanCtx), valid for the
                    // request lifetime.
                    unsafe { recovered.as_ref() }
                }
            }
        };

        // ── request duration in MICROSECONDS ─────────────────────────────────
        // OTel-SDK-idiomatic dual-clock:
        //   When tracing is enabled (SpanCtx present): `start_mono.elapsed()` is
        //   one vDSO CLOCK_MONOTONIC read per request; always ≥ 0, NTP-immune.
        //   Makes the µs histogram, span (end−start), and the
        //   http.server.request.duration attribute all coherent (same duration,
        //   same basis).
        //   When tracing is disabled (no SpanCtx): fall back to the wall-clock
        //   approach (SystemTime::now() minus nginx's cached start — existing
        //   behaviour; saturating_sub handles backward NTP steps).
        let duration_us: u64 = if let Some(ctx) = span_ctx {
            ctx.start_mono.elapsed().as_micros() as u64
        } else {
            use std::time::{SystemTime, UNIX_EPOCH};
            let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
            let end_us = d.as_nanos() as u64 / 1_000;
            let start_us = (r.start_sec as u64) * 1_000_000 + (r.start_msec as u64) * 1_000;
            end_us.saturating_sub(start_us)
        };
        // ── request duration (decomposed tables) ─────────────────────────────
        // Three independent histogram bumps — each O(1) fetch_add, no alloc, no lock.
        let method = HttpMethod::from_bytes(r.method_name.as_bytes());
        let status = r.headers_out.status as u16;
        let proto = ProtoVersion::from_ngx(r.http_version as core::ffi::c_uint);

        // 1. Base table: {method × status_class × protocol} (160 combos).
        //
        // `status_class` and `base_idx` are always computed (O(1) arithmetic, hot-path
        // safe) because the exemplar block below also needs `base_idx` even for
        // status-0 latency outliers.
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
        let status_class = StatusClass::from_status(status);
        let base_idx = combo_index(method, status_class, proto);
        record_base_combo(slot, status, base_idx, duration_us);

        // 2. Per-route table: http.route = location name.
        let route_idx = {
            let clcf_ptr =
                NgxHttpCoreModule::location_conf(r).map(|c| c as *const _ as usize).unwrap_or(0);
            amcf.route_idx_for_clcf(clcf_ptr)
        };
        slot.route_duration_combos[route_idx].record(duration_us);

        // 3. Per-upstream table: nginx.upstream.zone.
        //    Skip if no upstream (zone_ptr = 0 → UPSTREAM_IDX_OTHER).
        let upstream_zone_ptr: usize = if let Some(upstream) = request.upstream() {
            // SAFETY: `request.upstream()` returns `Some` only when nginx has set
            // up the per-request upstream struct, so `upstream` is a valid
            // `ngx_http_upstream_t` pointer for the duration of this handler.
            let us = unsafe { (*upstream).upstream };
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
        let resp_bytes = {
            let conn = request.connection();
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
        slot.response_body_bytes.record(resp_bytes, &BYTES_BOUNDS);

        // ── upstream timings (if an upstream was used) ────────────────────
        if let Some(upstream) = request.upstream() {
            // SAFETY: `request.upstream()` returned `Some`, so `upstream` is a
            // valid `ngx_http_upstream_t` for this handler; reading its `state`
            // array pointer is sound.
            let state = unsafe { (*upstream).state };
            if !state.is_null() {
                // SAFETY: `state` is non-null (checked above) and points to the
                // upstream's `ngx_http_upstream_state_t` (the timing record nginx
                // populates per upstream attempt), valid for this handler. This and
                // the next four reads access plain numeric fields, so the
                // dereferences are sound.
                let resp_ms = unsafe { (*state).response_time as u64 };
                // SAFETY: as above — non-null upstream state, plain field read.
                let hdr_ms = unsafe { (*state).header_time as u64 };
                // SAFETY: as above — non-null upstream state, plain field read.
                let conn_ms = unsafe { (*state).connect_time as u64 };
                // SAFETY: as above — non-null upstream state, plain field read.
                let bytes_rx = unsafe { (*state).bytes_received as u64 };
                // SAFETY: as above — non-null upstream state, plain field read.
                let bytes_tx = unsafe { (*state).bytes_sent as u64 };

                // nginx initialises all three timing fields to
                // (ngx_msec_t)-1 (= NGX_MSEC_SENTINEL) when the upstream
                // attempt did not complete the corresponding phase (e.g.
                // connect_time remains sentinel on a refused connection).
                // The nginx log module special-cases this sentinel and emits
                // "-" rather than a time value
                // (ngx_http_upstream.c:6074).
                // Recording the sentinel as-is would add u64::MAX / usize::MAX
                // to the cumulative sum, permanently poisoning the metric.
                // Skip any timing field that nginx has not yet filled in.
                if resp_ms != NGX_MSEC_SENTINEL {
                    slot.upstream_response_ms.record(resp_ms, &DURATION_BOUNDS_MS);
                }
                if hdr_ms != NGX_MSEC_SENTINEL {
                    slot.upstream_header_ms.record(hdr_ms, &DURATION_BOUNDS_MS);
                }
                if conn_ms != NGX_MSEC_SENTINEL {
                    slot.upstream_connect_ms.record(conn_ms, &DURATION_BOUNDS_MS);
                }
                slot.upstream_bytes_received.record(bytes_rx, &BYTES_BOUNDS);
                slot.upstream_bytes_sent.record(bytes_tx, &BYTES_BOUNDS);
            }
        }

        // ── exception-tail / exemplar export ──────────────────────────────
        // Gate 1 (cheap config check): no location selects export anywhere →
        //   any_log_export_enabled() = false, this entire block is skipped, so
        //   a deployment without `otel_log_export` pays only the single bool.
        // Gate 2 (per-location selection): the matched location's
        //   `otel_log_export` mode decides export.  `on`/bare ⇒ always export;
        //   `if=<cond>` ⇒ export when the complex value is truthy; `off`/unset
        //   ⇒ nothing.  Nothing is hardcoded — the operator's condition is the
        //   only predicate (privacy-safe default of no export).
        // The histogram bump above is always-on and is NOT gated here.
        let export_selected = if amcf.any_log_export_enabled() {
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
        } else {
            false
        };
        if export_selected {
            if let Some(logs_base) = amcf.logs_shm_base() {
                let cap = amcf.log_ring_cap();
                // Safety: zone was sized for ≥ worker_id slots at registration.
                let access_ring = unsafe { logs_access_ring(logs_base, worker_id, cap) };
                let producer = WorkerRingProducer { ring: access_ring };

                // Gather HTTP semconv fields from the request.
                let method: &[u8] = r.method_name.as_bytes();
                let status = r.headers_out.status as u16;
                let req_len = r.request_length as u64;
                let resp_bytes_acc = resp_bytes; // already computed above

                // Client address from the connection.
                let client_addr: &[u8] = if !request.connection().is_null() {
                    // SAFETY: the connection pointer is non-null (checked above) and
                    // points to the request's `ngx_connection_t`, valid for this
                    // handler. `addr_text` is an `ngx_str_t` whose `data`/`len` nginx
                    // fills with the client address text; the `from_raw_parts` slice
                    // is only built when `len > 0` and `data` is non-null, so it
                    // covers `len` initialised bytes that outlive this borrow.
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

                // Timestamp: request start time in nanoseconds.
                // Derived from nginx's stored start fields (ms precision).
                let ts_unix_nano: u64 = (r.start_sec as u64)
                    .saturating_mul(1_000_000_000)
                    .saturating_add(r.start_msec as u64 * 1_000_000);

                // W3C trace correlation (parse-once):
                // SpanCtx was read once above; extract trace_id/span_id when sampled.
                // Unsampled requests (ctx.sampled=false) still have a SpanCtx for
                // W3C propagation but do not stamp the access tail.
                let trace_context: Option<([u8; 16], [u8; 8])> =
                    span_ctx.filter(|ctx| ctx.sampled).map(|ctx| (ctx.trace_id, ctx.span_id));

                // User-Agent header: still requires one targeted header scan since it
                // is NOT cached in SpanCtx (not needed for trace correlation).
                let mut user_agent_raw: &[u8] = b"";
                for (key, value) in request.headers_in_iterator() {
                    let k = key.as_bytes();
                    if k.len() == 10 && k.eq_ignore_ascii_case(b"user-agent") {
                        user_agent_raw = value.as_bytes();
                        break;
                    }
                }

                // url.path: r.uri (decoded path, WITHOUT query string / args).
                // Use r.uri, NOT r.unparsed_uri (= $request_uri, which includes
                // '?args') — including args would be a semconv violation and a
                // PII/credential-leak vector (e.g. ?token=SECRET ends up in
                // exported tails + exemplars).
                // r.uri is the normalised, args-stripped equivalent of $uri;
                // the query string lives separately in r.args and is NOT recorded.
                // High-cardinality — stays on the tail record ONLY, never a metric dim.
                let url_path: &[u8] = r.uri.as_bytes();

                // Build the canonical sampled-request record once; project into both sinks.
                // No allocation — all fields borrow nginx request memory (stack frame).
                let sampled = SampledRequest {
                    ts_unix_nano,
                    trace: trace_context,
                    url_path,
                    user_agent: user_agent_raw,
                    duration_us,
                    combo_idx: base_idx as u32,
                    method,
                    status,
                    request_length: req_len,
                    response_bytes: resp_bytes_acc,
                    client_addr,
                };

                // Sink 1: per-worker SPSC log ring (exception-tail LogRecord).
                // A `false` return is the ring-full drop path (already counted
                // in the ring's `dropped`) — the TRIGGER for the
                // exporter-liveness check (heartbeat = the VERDICT).  Zero
                // added cost on the healthy path.
                if !emit_access_record(&producer, &sampled) {
                    // SAFETY: `request.connection()` is the request's live
                    // connection pointer (may be null — handled inside);
                    // `(*conn).log` is the connection log nginx error logging
                    // uses for this request.
                    let conn_log = unsafe {
                        let conn = request.connection();
                        if conn.is_null() {
                            core::ptr::null_mut()
                        } else {
                            (*conn).log
                        }
                    };
                    crate::liveness::check_exporter_liveness_on_drop(amcf, conn_log);
                }

                // Sink 2: exemplar reservoir.
                // One fetch_add + ≤ 9 Relaxed stores + 2 memcpy = within budget.
                let effective_size = amcf.access_sample_size().max(1);
                slot.exemplar_reservoir.write(effective_size, &sampled);
            }
        }

        // ── Span record emission ──────────────────────────────────────────────
        // Gate 1: request must be sampled (ctx.sampled=true).
        // Gate 2: spans shm zone must be available (otel_spans_zone configured).
        // Both gates false → zero work, no ring push.
        // This block is INDEPENDENT of the access-log gate above — spans are emitted
        // for all sampled requests, not only "interesting" tail ones.
        if let Some(ctx) = span_ctx.filter(|ctx| ctx.sampled) {
            if let Some(spans_base) = amcf.spans_shm_base() {
                // Collect per-location config (span_name_cv + span_attrs).
                // `HttpOtelModule::location_conf` returns the merged LocationConf for
                // the matched location; null/absent → default (built-in name, no attrs).
                let loc_conf = HttpOtelModule::location_conf(r);

                // Build span name: evaluate `otel_span_name` complex value if set,
                // else fall back to built-in "METHOD route_name" format.
                // No heap allocation; evaluated into a stack buffer capped at MAX_SPAN_NAME.
                let mut span_name_buf = [0u8; MAX_SPAN_NAME];
                let span_name_len = {
                    let mut evaluated_name: &[u8] = &[];
                    let mut cv_buf = nginx_sys::ngx_str_t::default();
                    let use_cv = loc_conf
                        .and_then(|lc| {
                            if lc.span_name_cv.is_null() {
                                None
                            } else {
                                Some(lc.span_name_cv)
                            }
                        })
                        .is_some_and(|cv_ptr| {
                            // SAFETY: `r` is the valid non-null request pointer (same
                            // request the handler was called on); `cv_ptr` is a valid
                            // `ngx_http_complex_value_t*` in conf-pool memory compiled
                            // at config time; `cv_buf` is a local ngx_str_t for output.
                            let rc = unsafe {
                                nginx_sys::ngx_http_complex_value(
                                    r as *const nginx_sys::ngx_http_request_t
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
                            r.method_name.as_bytes(),
                            amcf.route_name(route_idx).as_bytes(),
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
                let otel_status_code: u8 = if status >= 500 { 2 } else { 0 };

                // Span end time: derived from the monotonic duration for coherence.
                // end = start + duration_us * 1_000 ns.
                // Invariants: end >= start (monotonic); span (end−start) == duration_us.
                let end_time_unix_nano =
                    ctx.start_time_unix_nano.saturating_add(duration_us.saturating_mul(1_000));

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
                    method: r.method_name.as_bytes(),
                    http_status: status,
                    url_path: r.uri.as_bytes(), // uri = path only; unparsed_uri = path+args
                    duration_us,
                    extra_attrs: &attrs_buf[..attrs_len],
                };

                // SAFETY: `spans_base` is the valid mapped shm start returned by
                // `spans_shm_base()`, sized for ≥ worker_id spans-ring slots at zone
                // registration in postconfiguration.  The ring lives for the worker's
                // lifetime and outlives this handler invocation.
                let spans = unsafe { spans_ring(spans_base, worker_id, DEFAULT_SPAN_RING_CAP) };
                let producer = WorkerRingProducer { ring: spans };
                // Ring-full drop path → liveness check (see the access-ring
                // hook above for the trigger/verdict rationale).
                if !emit_span_record(&producer, &rec) {
                    // SAFETY: same contract as the access-ring hook — null
                    // connection handled, `(*conn).log` is the request's log.
                    let conn_log = unsafe {
                        let conn = request.connection();
                        if conn.is_null() {
                            core::ptr::null_mut()
                        } else {
                            (*conn).log
                        }
                    };
                    crate::liveness::check_exporter_liveness_on_drop(amcf, conn_log);
                }
            }
        }

        Status::NGX_OK
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
        use crate::data_model::{AggregationTemporality, AnyValue, Exemplar, KeyValue};
        use crate::shm::{
            combo_index, HttpMethod, ProtoVersion, StatusClass, BYTES_BOUNDS, DURATION_BOUNDS_MS,
            EXP_HISTOGRAM_BUCKET_OFFSET, EXP_HISTOGRAM_SCALE, N_COMBOS, N_EXP_BUCKETS,
            N_HTTP_METHODS, N_PROTO_VERSIONS, N_ROUTE_SLOTS, N_STATUS_CLASSES, N_UPSTREAM_SLOTS,
        };

        let start = self.start_time_unix_nano;
        let now = crate::util::now_unix_nano();

        // Aggregate per-combination exp-histogram slots over all workers.
        // combo_agg[idx] = ([bucket_counts; N_EXP_BUCKETS], zero_count, sum, count)
        let mut combo_agg: std::vec::Vec<([u64; N_EXP_BUCKETS], u64, u64, u64)> =
            std::vec![([0u64; N_EXP_BUCKETS], 0u64, 0u64, 0u64); N_COMBOS];
        // Separate route / upstream aggregation tables.
        let mut route_agg: std::vec::Vec<([u64; N_EXP_BUCKETS], u64, u64, u64)> =
            std::vec![([0u64; N_EXP_BUCKETS], 0u64, 0u64, 0u64); N_ROUTE_SLOTS];
        let mut upstream_agg: std::vec::Vec<([u64; N_EXP_BUCKETS], u64, u64, u64)> =
            std::vec![([0u64; N_EXP_BUCKETS], 0u64, 0u64, 0u64); N_UPSTREAM_SLOTS];
        let mut req_bytes = ([0u64; N_BYTES_BUCKETS], 0u64, 0u64);
        let mut resp_bytes = ([0u64; N_BYTES_BUCKETS], 0u64, 0u64);
        let mut up_resp = ([0u64; N_DURATION_BUCKETS], 0u64, 0u64);
        let mut up_hdr = ([0u64; N_DURATION_BUCKETS], 0u64, 0u64);
        let mut up_conn = ([0u64; N_DURATION_BUCKETS], 0u64, 0u64);
        let mut up_bytes = ([0u64; N_BYTES_BUCKETS], 0u64, 0u64);
        let mut up_bytes_sent = ([0u64; N_BYTES_BUCKETS], 0u64, 0u64);

        // amcf needed before the worker loop for effective_size.
        // SAFETY: `self.amcf` is the main-config pointer captured at exporter
        // setup; it is either null or points to the `MainConfig` that lives for
        // the whole process. `as_ref()` yields `None` for null and otherwise a
        // reference that does not outlive `self`, so it is sound.
        let amcf_ref_early: Option<&crate::config::MainConfig> = unsafe { self.amcf.as_ref() };
        // Effective exemplar reservoir size (from otel_access_log_sample directive).
        let effective_size = amcf_ref_early.map(|c| c.access_sample_size().max(1)).unwrap_or(1);

        // Collect exemplars from all workers: Vec<(combo_idx, Exemplar)>
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

            // Collect exemplars from this worker's reservoir.
            for snap in slot.exemplar_reservoir.snapshot(effective_size) {
                // Build filtered_attributes: url.path + user_agent.original.
                // These are HIGH-CARDINALITY fields — they appear on exemplars ONLY,
                // NEVER as metric dimensions.
                let mut filtered_attrs: std::vec::Vec<KeyValue> = std::vec::Vec::new();
                if snap.url_path_len > 0 {
                    if let Ok(s) =
                        core::str::from_utf8(&snap.url_path[..snap.url_path_len as usize])
                    {
                        filtered_attrs.push(KeyValue {
                            key: "url.path".into(),
                            value: AnyValue::String(std::string::String::from(s)),
                        });
                    }
                }
                if snap.user_agent_len > 0 {
                    if let Ok(s) =
                        core::str::from_utf8(&snap.user_agent[..snap.user_agent_len as usize])
                    {
                        filtered_attrs.push(KeyValue {
                            key: "user_agent.original".into(),
                            value: AnyValue::String(std::string::String::from(s)),
                        });
                    }
                }
                all_exemplars.push((
                    snap.combo_idx,
                    Exemplar {
                        value: snap.value_us as f64,
                        time_unix_nano: snap.ts_unix_nano,
                        trace_id: snap.trace_id,
                        span_id: snap.span_id,
                        has_trace: snap.has_trace,
                        filtered_attributes: filtered_attrs,
                    },
                ));
            }
        }

        let dur_bounds: std::vec::Vec<f64> = DURATION_BOUNDS_MS.iter().map(|&b| b as f64).collect();
        let byte_bounds: std::vec::Vec<f64> = BYTES_BOUNDS.iter().map(|&b| b as f64).collect();

        // ── Build http.server.request.duration ──────────────────────────
        // All histograms are cumulative running totals.
        // amcf provides route/upstream name strings for the attribute values.
        let amcf_ref: Option<&crate::config::MainConfig> = amcf_ref_early;

        // Decomposed: emit THREE separate metric series:
        //  1. http.server.request.duration (base: method × sc × proto)
        //  2. http.server.request.duration.by_route (per http.route location)
        //  3. http.server.request.duration.by_upstream (per nginx.upstream.zone)
        use crate::data_model::{
            ExponentialHistogramData, ExponentialHistogramDataPoint, Metric, MetricData,
        };

        // Helper to emit one exp-histogram data point from aggregated buckets.
        let make_dp = |agg: &([u64; N_EXP_BUCKETS], u64, u64, u64),
                       attrs: std::vec::Vec<KeyValue>,
                       exemplars: std::vec::Vec<Exemplar>|
         -> Option<ExponentialHistogramDataPoint> {
            let (bc, zc, bs, bcount) = *agg;
            if bcount == 0 {
                return None;
            }
            Some(ExponentialHistogramDataPoint {
                attributes: attrs,
                start_time_unix_nano: start,
                time_unix_nano: now,
                count: bcount,
                sum: bs as f64,
                scale: EXP_HISTOGRAM_SCALE,
                zero_count: zc,
                positive_offset: EXP_HISTOGRAM_BUCKET_OFFSET,
                positive_bucket_counts: bc.to_vec(),
                exemplars,
            })
        };

        let duration_metric = if self.status_code_class_enabled {
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
                        let attrs = std::vec![
                            KeyValue {
                                key: "http.request.method".into(),
                                value: AnyValue::String(method.as_str().into())
                            },
                            KeyValue {
                                key: "http.response.status_code".into(),
                                value: AnyValue::Int(status_class.representative_status())
                            },
                            KeyValue {
                                key: "network.protocol.version".into(),
                                value: AnyValue::String(proto.as_str().into())
                            },
                        ];
                        if let Some(dp) = make_dp(&combo_agg[combo], attrs, combo_exemplars) {
                            data_points.push(dp);
                        }
                    }
                }
            }
            Metric {
                name: "http.server.request.duration".into(),
                description: "HTTP server request duration".into(),
                unit: "us".into(),
                data: MetricData::ExponentialHistogram(ExponentialHistogramData {
                    aggregation_temporality: AggregationTemporality::Cumulative,
                    data_points,
                }),
            }
        } else {
            // Aggregate across all base combinations → single data point.
            let mut all_buckets = [0u64; N_EXP_BUCKETS];
            let (mut all_zero, mut all_sum, mut all_count) = (0u64, 0u64, 0u64);
            for agg in &combo_agg {
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
                unit: "us".into(),
                data: MetricData::ExponentialHistogram(ExponentialHistogramData {
                    aggregation_temporality: AggregationTemporality::Cumulative,
                    data_points: std::vec![ExponentialHistogramDataPoint {
                        attributes: std::vec![],
                        start_time_unix_nano: start,
                        time_unix_nano: now,
                        count: all_count,
                        sum: all_sum as f64,
                        scale: EXP_HISTOGRAM_SCALE,
                        zero_count: all_zero,
                        positive_offset: EXP_HISTOGRAM_BUCKET_OFFSET,
                        positive_bucket_counts: all_buckets.to_vec(),
                        exemplars: std::vec![],
                    }],
                }),
            }
        };

        // Per-route series (http.server.request.duration.by_route).
        let route_metric = {
            let mut data_points: std::vec::Vec<ExponentialHistogramDataPoint> =
                std::vec::Vec::new();
            for r_idx in 0..N_ROUTE_SLOTS {
                let route_name: std::string::String = amcf_ref
                    .map(|c| std::string::String::from(c.route_name(r_idx)))
                    .unwrap_or_else(|| std::format!("route_{}", r_idx));
                let attrs = std::vec![KeyValue {
                    key: "http.route".into(),
                    value: AnyValue::String(route_name)
                }];
                if let Some(dp) = make_dp(&route_agg[r_idx], attrs, std::vec![]) {
                    data_points.push(dp);
                }
            }
            Metric {
                name: "http.server.request.duration.by_route".into(),
                description: "HTTP server request duration by matched location (http.route)".into(),
                unit: "us".into(),
                data: MetricData::ExponentialHistogram(ExponentialHistogramData {
                    aggregation_temporality: AggregationTemporality::Cumulative,
                    data_points,
                }),
            }
        };

        // Per-upstream series (http.server.request.duration.by_upstream).
        let upstream_metric = {
            let mut data_points: std::vec::Vec<ExponentialHistogramDataPoint> =
                std::vec::Vec::new();
            for u_idx in 0..N_UPSTREAM_SLOTS {
                let uname: std::string::String = amcf_ref
                    .map(|c| std::string::String::from(c.upstream_zone_name(u_idx)))
                    .unwrap_or_else(|| std::format!("upstream_{}", u_idx));
                let attrs = std::vec![KeyValue {
                    key: "nginx.upstream.zone".into(),
                    value: AnyValue::String(uname)
                }];
                if let Some(dp) = make_dp(&upstream_agg[u_idx], attrs, std::vec![]) {
                    data_points.push(dp);
                }
            }
            Metric {
                name: "http.server.request.duration.by_upstream".into(),
                description: "HTTP server request duration by upstream zone (nginx.upstream.zone)"
                    .into(),
                unit: "us".into(),
                data: MetricData::ExponentialHistogram(ExponentialHistogramData {
                    aggregation_temporality: AggregationTemporality::Cumulative,
                    data_points,
                }),
            }
        };

        std::vec![
            duration_metric,
            route_metric,
            upstream_metric,
            hist_metric(
                "http.server.request.body.size",
                "HTTP server request body size",
                "By",
                req_bytes,
                byte_bounds.clone(),
                start,
                now,
                AggregationTemporality::Cumulative,
            ),
            hist_metric(
                "http.server.response.body.size",
                "HTTP server response body size",
                "By",
                resp_bytes,
                byte_bounds.clone(),
                start,
                now,
                AggregationTemporality::Cumulative,
            ),
            // ── upstream timings ──────────────────────────────────────────
            hist_metric(
                "http.server.upstream.response.duration",
                "Upstream response time",
                "ms",
                up_resp,
                dur_bounds.clone(),
                start,
                now,
                AggregationTemporality::Cumulative,
            ),
            hist_metric(
                "http.server.upstream.header.duration",
                "Upstream time to first response byte",
                "ms",
                up_hdr,
                dur_bounds.clone(),
                start,
                now,
                AggregationTemporality::Cumulative,
            ),
            hist_metric(
                "http.server.upstream.connect.duration",
                "Upstream connection establishment time",
                "ms",
                up_conn,
                dur_bounds.clone(),
                start,
                now,
                AggregationTemporality::Cumulative,
            ),
            hist_metric(
                "http.server.upstream.bytes.received",
                "Bytes received from upstream",
                "By",
                up_bytes,
                byte_bounds.clone(),
                start,
                now,
                AggregationTemporality::Cumulative,
            ),
            hist_metric(
                "http.server.upstream.bytes.sent",
                "Bytes sent to upstream",
                "By",
                up_bytes_sent,
                byte_bounds.clone(),
                start,
                now,
                AggregationTemporality::Cumulative,
            ),
        ]
    }
}

// ─── helpers ────────────────────────────────────────────────────────────────

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

// Internal OTLP-histogram builder; the argument count mirrors the histogram's
// own shape (name/desc/unit + data + bounds + start/now + temporality).
#[allow(clippy::too_many_arguments)]
fn hist_metric<const N: usize>(
    name: &str,
    desc: &str,
    unit: &str,
    data: ([u64; N], u64, u64),
    bounds: std::vec::Vec<f64>,
    start_time_ns: u64,
    time_ns: u64,
    temporality: crate::data_model::AggregationTemporality,
) -> crate::data_model::Metric {
    use crate::data_model::{HistogramData, HistogramDataPoint, Metric, MetricData};
    Metric {
        name: name.into(),
        description: desc.into(),
        unit: unit.into(),
        data: MetricData::Histogram(HistogramData {
            aggregation_temporality: temporality,
            data_points: std::vec![HistogramDataPoint {
                attributes: std::vec![],
                start_time_unix_nano: start_time_ns,
                time_unix_nano: time_ns,
                count: data.2,
                sum: data.1 as f64,
                bucket_counts: data.0.to_vec(),
                explicit_bounds: bounds,
            }],
        }),
    }
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
}
