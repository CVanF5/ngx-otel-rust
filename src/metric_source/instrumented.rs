// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Log-phase handler that bumps per-worker shm slot counters per request.
//!
//! ## Hard constraints (verified in Step 6)
//! - No `Vec::new()`, `Box::new()`, `String::from()`, or any heap allocation.
//! - No syscalls beyond what the nginx log phase already incurs.
//! - No locks; only atomic increments (`Ordering::Relaxed` on writes).
//! - The handler is registered **only** when `otel_exporter` is configured.

use core::sync::atomic::Ordering;

use ngx::core::Status;
use ngx::http::{HttpModuleMainConf, HttpPhase, HttpRequestHandler, Request};

use crate::shm::{
    worker_slots, BYTES_BOUNDS, DURATION_BOUNDS_MS, N_BYTES_BUCKETS, N_DURATION_BUCKETS,
};
use crate::HttpOtelModule;

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

        // Phase 1.3.3 scaffold: prove the hot-path read is zero-cost.
        // One Relaxed atomic load on control_shm.flags per request.
        // The loaded value is intentionally discarded; Phase 5 will use
        // it for dynamic-reconfig fast-path checks (sampling rate, dropped
        // attributes, etc.). This load is inside the is_configured() gate
        // (we returned above if amcf.main_conf returned None, i.e., the
        // module is disabled) so module-loaded-but-disabled stays zero-cost.
        // TODO(phase-5): act on the loaded flags value.
        if let Some(ctrl) = amcf.control_shm_ptr() {
            let _ = unsafe { (*ctrl).flags.load(Ordering::Relaxed) };
        }

        // Obtain base address of the shm zone.
        let base = match amcf.shm_base() {
            Some(b) => b,
            None => return Status::NGX_OK,
        };

        // Determine current worker index (no syscall — nginx global).
        let worker_id = unsafe { nginx_sys::ngx_worker as usize };

        // Get our slot. No allocation; pointer arithmetic only.
        // Safety: zone was sized for ≥ worker_id slots during postconfiguration.
        let slot = unsafe { &*worker_slots(base, worker_id) };

        // Use AsRef to get a typed reference to the underlying ngx_http_request_t.
        let r = request.as_ref();

        // ── request duration in milliseconds ──────────────────────────────
        // duration_ms = ngx_current_msec - r->start_msec
        let duration_ms: u64 = unsafe {
            (nginx_sys::ngx_current_msec as u64).saturating_sub(r.start_msec as u64)
        };
        slot.request_duration_ms.record(duration_ms, &DURATION_BOUNDS_MS);

        // ── request body bytes ────────────────────────────────────────────
        slot.request_body_bytes.record(r.request_length as u64, &BYTES_BOUNDS);

        // ── response bytes ────────────────────────────────────────────────
        let resp_bytes = {
            let conn = request.connection();
            if conn.is_null() { 0u64 } else { unsafe { (*conn).sent as u64 } }
        };
        slot.response_body_bytes.record(resp_bytes, &BYTES_BOUNDS);

        // ── status code class ─────────────────────────────────────────────
        let status = r.headers_out.status as u16;
        match status {
            100..=199 => slot.status_1xx.fetch_add(1, Ordering::Relaxed),
            200..=299 => slot.status_2xx.fetch_add(1, Ordering::Relaxed),
            300..=399 => slot.status_3xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => slot.status_4xx.fetch_add(1, Ordering::Relaxed),
            _ => slot.status_5xx.fetch_add(1, Ordering::Relaxed),
        };

        // ── upstream timings (if an upstream was used) ────────────────────
        if let Some(upstream) = request.upstream() {
            let state = unsafe { (*upstream).state };
            if !state.is_null() {
                let resp_ms = unsafe { (*state).response_time as u64 };
                let hdr_ms = unsafe { (*state).header_time as u64 };
                let conn_ms = unsafe { (*state).connect_time as u64 };
                let bytes_rx = unsafe { (*state).bytes_received as u64 };
                let bytes_tx = unsafe { (*state).bytes_sent as u64 };

                slot.upstream_response_ms.record(resp_ms, &DURATION_BOUNDS_MS);
                slot.upstream_header_ms.record(hdr_ms, &DURATION_BOUNDS_MS);
                slot.upstream_connect_ms.record(conn_ms, &DURATION_BOUNDS_MS);
                slot.upstream_bytes_received.record(bytes_rx, &BYTES_BOUNDS);
                slot.upstream_bytes_sent.record(bytes_tx, &BYTES_BOUNDS);
            }
        }

        Status::NGX_OK
    }
}

/// A `MetricSource` that reads all per-worker shm slots and produces
/// aggregated `Metric`s for the export batch.
pub struct InstrumentedSource {
    /// Base address of the shm zone.
    pub base: *mut u8,
    /// Number of workers whose slots are in the zone.
    pub n_workers: usize,
}

// Safety: InstrumentedSource is only used on Worker 0's export loop.
unsafe impl Send for InstrumentedSource {}
unsafe impl Sync for InstrumentedSource {}

impl crate::metric_source::MetricSource for InstrumentedSource {
    fn collect(&self) -> std::vec::Vec<crate::data_model::Metric> {
        use crate::data_model::AggregationTemporality;

        let now = now_unix_nano();

        // Aggregate all workers.
        let mut dur = ([0u64; N_DURATION_BUCKETS], 0u64, 0u64);
        let mut req_bytes = ([0u64; N_BYTES_BUCKETS], 0u64, 0u64);
        let mut resp_bytes = ([0u64; N_BYTES_BUCKETS], 0u64, 0u64);
        let mut s1xx = 0u64;
        let mut s2xx = 0u64;
        let mut s3xx = 0u64;
        let mut s4xx = 0u64;
        let mut s5xx = 0u64;
        let mut up_resp = ([0u64; N_DURATION_BUCKETS], 0u64, 0u64);
        let mut up_hdr = ([0u64; N_DURATION_BUCKETS], 0u64, 0u64);
        let mut up_conn = ([0u64; N_DURATION_BUCKETS], 0u64, 0u64);
        let mut up_bytes = ([0u64; N_BYTES_BUCKETS], 0u64, 0u64);
        let mut up_bytes_sent = ([0u64; N_BYTES_BUCKETS], 0u64, 0u64);

        for i in 0..self.n_workers {
            let slot = unsafe { &*worker_slots(self.base, i) };

            let (bc, bs, bcount) = slot.request_duration_ms.snapshot();
            add_histogram(&mut dur, &bc, bs, bcount);

            let (bc, bs, bcount) = slot.request_body_bytes.snapshot();
            add_histogram(&mut req_bytes, &bc, bs, bcount);

            let (bc, bs, bcount) = slot.response_body_bytes.snapshot();
            add_histogram(&mut resp_bytes, &bc, bs, bcount);

            s1xx += slot.status_1xx.load(Ordering::Acquire);
            s2xx += slot.status_2xx.load(Ordering::Acquire);
            s3xx += slot.status_3xx.load(Ordering::Acquire);
            s4xx += slot.status_4xx.load(Ordering::Acquire);
            s5xx += slot.status_5xx.load(Ordering::Acquire);

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
        }

        use crate::shm::{BYTES_BOUNDS, DURATION_BOUNDS_MS};

        let dur_bounds: std::vec::Vec<f64> =
            DURATION_BOUNDS_MS.iter().map(|&b| b as f64).collect();
        let byte_bounds: std::vec::Vec<f64> = BYTES_BOUNDS.iter().map(|&b| b as f64).collect();

        // TODO(fix3b): Per OTel semconv, http.server.request.duration should be
        // broken down by {http.request.method, http.response.status_code,
        // network.protocol.version}. Doing this with per-request attributes
        // requires one histogram slot per {method × status_class × protocol}
        // combination in WorkerSlots (multi-dimensional shm histogram). The
        // current design has a single aggregated histogram; the multi-dim
        // slots arrive in a follow-on architectural pass (requires shm layout
        // change + migration).
        //
        // Cardinality discipline (proposal §6.4 "Producer-side cardinality
        // discipline"): when the multi-dim slots land, the attribute keys MUST
        // be a closed Rust enum drawn from the OTel HTTP semantic conventions
        // ONLY. The bounded set is:
        //   - http.request.method        (~7 values; WithinU8 for the OTAP
        //                                  classifier)
        //   - http.response.status_code  (~30 values, or 5 status classes;
        //                                  WithinU8 either way)
        //   - network.protocol.version   (H1/H2/H3; WithinU8)
        //
        // No free-form String keys; no raw url.path, no client.address, no
        // user_agent.original on data points by default. Unbounded attribute
        // values would defeat the OTAP collector-side classifier's dictionary
        // encoding (concatenate.rs::estimate_cardinality → GreaterThanU16,
        // plain column on the wire) and explode per-point bytes on the wire.
        // High-cardinality attributes stay opt-in-only behind the explicit
        // directives specified in proposal §3 Phase 1.1.
        //
        // The status class totals (s1xx–s5xx) are available for reference but
        // are not emitted as separate metrics: per OTel semconv the status
        // breakdown belongs as an attribute on the duration histogram, not as
        // standalone counters. They will be wired in once the multi-dim
        // histogram slots exist.
        let _ = (s1xx, s2xx, s3xx, s4xx, s5xx);

        std::vec![
            // ── request metrics ───────────────────────────────────────────
            hist_metric(
                "http.server.request.duration",
                "HTTP server request duration",
                "ms",
                dur,
                dur_bounds.clone(),
                now,
                AggregationTemporality::Delta,
            ),
            hist_metric(
                "http.server.request.body.size",
                "HTTP server request body size",
                "By",
                req_bytes,
                byte_bounds.clone(),
                now,
                AggregationTemporality::Delta,
            ),
            hist_metric(
                "http.server.response.body.size",
                "HTTP server response body size",
                "By",
                resp_bytes,
                byte_bounds.clone(),
                now,
                AggregationTemporality::Delta,
            ),
            // ── upstream timings ──────────────────────────────────────────
            hist_metric(
                "http.server.upstream.response.duration",
                "Upstream response time",
                "ms",
                up_resp,
                dur_bounds.clone(),
                now,
                AggregationTemporality::Delta,
            ),
            hist_metric(
                "http.server.upstream.header.duration",
                "Upstream time to first response byte",
                "ms",
                up_hdr,
                dur_bounds.clone(),
                now,
                AggregationTemporality::Delta,
            ),
            hist_metric(
                "http.server.upstream.connect.duration",
                "Upstream connection establishment time",
                "ms",
                up_conn,
                dur_bounds.clone(),
                now,
                AggregationTemporality::Delta,
            ),
            hist_metric(
                "http.server.upstream.bytes.received",
                "Bytes received from upstream",
                "By",
                up_bytes,
                byte_bounds.clone(),
                now,
                AggregationTemporality::Delta,
            ),
            hist_metric(
                "http.server.upstream.bytes.sent",
                "Bytes sent to upstream",
                "By",
                up_bytes_sent,
                byte_bounds.clone(),
                now,
                AggregationTemporality::Delta,
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

fn hist_metric<const N: usize>(
    name: &str,
    desc: &str,
    unit: &str,
    data: ([u64; N], u64, u64),
    bounds: std::vec::Vec<f64>,
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
                start_time_unix_nano: 0,
                time_unix_nano: time_ns,
                count: data.2,
                sum: data.1 as f64,
                bucket_counts: data.0.to_vec(),
                explicit_bounds: bounds,
            }],
        }),
    }
}

fn now_unix_nano() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
