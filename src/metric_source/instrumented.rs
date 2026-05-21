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

use nginx_sys::{
    ngx_array_push, ngx_conf_t, ngx_http_handler_pt,
    ngx_http_phases_NGX_HTTP_LOG_PHASE, ngx_http_request_t, ngx_int_t,
};
use ngx::core::Status;
use ngx::http::{HttpModuleMainConf, NgxHttpCoreModule};

use crate::shm::{
    worker_slots, BYTES_BOUNDS, DURATION_BOUNDS_MS, N_BYTES_BUCKETS, N_DURATION_BUCKETS,
};
use crate::HttpOtelModule;

/// Register the log-phase handler into the nginx phase array.
///
/// Called from `postconfiguration` only when `otel_exporter` is configured.
pub fn register_log_handler(cf: &mut ngx_conf_t) -> Result<(), Status> {
    let cmcf = NgxHttpCoreModule::main_conf_mut(cf).ok_or(Status::NGX_ERROR)?;

    let h: *mut ngx_http_handler_pt = unsafe {
        ngx_array_push(
            &mut cmcf.phases[ngx_http_phases_NGX_HTTP_LOG_PHASE as usize].handlers,
        )
    }
    .cast();

    if h.is_null() {
        return Err(Status::NGX_ERROR);
    }

    unsafe { *h = Some(otel_log_handler) };

    Ok(())
}

/// Log-phase handler: atomically updates the current worker's shm slot.
///
/// # No allocation guarantee
/// This function:
/// - Reads fields via raw pointer dereferences only.
/// - Calls `histogram.record()` which uses atomic increments only.
/// - Does NOT call `Vec::new()`, `Box::new()`, `String::from()`, etc.
/// - Does NOT acquire any locks.
unsafe extern "C" fn otel_log_handler(r: *mut ngx_http_request_t) -> ngx_int_t {
    // Safety: main conf is initialised before any request is handled.
    // Use the Request wrapper only for conf access; keep r for raw field reads.
    let request = unsafe { ngx::http::Request::from_ngx_http_request(r) };
    let amcf = match HttpOtelModule::main_conf(request) {
        Some(c) => c,
        None => return Status::NGX_OK.into(),
    };

    // Obtain base address of the shm zone.
    let base = match amcf.shm_base() {
        Some(b) => b,
        None => return Status::NGX_OK.into(),
    };

    // Determine current worker index (no syscall — nginx global).
    let worker_id = unsafe { nginx_sys::ngx_worker as usize };

    // Get our slot. No allocation; pointer arithmetic only.
    // Safety: zone was sized for ≥ worker_id slots during postconfiguration.
    let slot = unsafe { &*worker_slots(base, worker_id) };

    // ── raw request pointer (already have it as the function arg) ────────
    let r: *const ngx_http_request_t = r;

    // ── request duration in milliseconds ────────────────────────────────
    // duration_ms = ngx_current_msec - r->start_msec
    // Both are u64-compatible (ngx_msec_t = ulong on 64-bit).
    let duration_ms: u64 = unsafe {
        let now = nginx_sys::ngx_current_msec as u64;
        let start = (*r).start_msec as u64;
        now.saturating_sub(start)
    };

    slot.request_duration_ms.record(duration_ms, &DURATION_BOUNDS_MS);

    // ── request body bytes ───────────────────────────────────────────────
    let req_bytes = unsafe { (*r).request_length as u64 };
    slot.request_body_bytes.record(req_bytes, &BYTES_BOUNDS);

    // ── response bytes ───────────────────────────────────────────────────
    let resp_bytes = unsafe {
        let conn = (*r).connection;
        if conn.is_null() { 0u64 } else { (*conn).sent as u64 }
    };
    slot.response_body_bytes.record(resp_bytes, &BYTES_BOUNDS);

    // ── status code class ────────────────────────────────────────────────
    let status = unsafe { (*r).headers_out.status as u16 };
    match status {
        100..=199 => slot.status_1xx.fetch_add(1, Ordering::Relaxed),
        200..=299 => slot.status_2xx.fetch_add(1, Ordering::Relaxed),
        300..=399 => slot.status_3xx.fetch_add(1, Ordering::Relaxed),
        400..=499 => slot.status_4xx.fetch_add(1, Ordering::Relaxed),
        _ => slot.status_5xx.fetch_add(1, Ordering::Relaxed),
    };

    // ── upstream timings (if an upstream was used) ───────────────────────
    let upstream = unsafe { (*r).upstream };
    if !upstream.is_null() {
        let state = unsafe { (*upstream).state };
        if !state.is_null() {
            let resp_ms = unsafe { (*state).response_time as u64 };
            let hdr_ms = unsafe { (*state).header_time as u64 };
            let conn_ms = unsafe { (*state).connect_time as u64 };
            let bytes_rx = unsafe { (*state).bytes_received as u64 };

            slot.upstream_response_ms.record(resp_ms, &DURATION_BOUNDS_MS);
            slot.upstream_header_ms.record(hdr_ms, &DURATION_BOUNDS_MS);
            slot.upstream_connect_ms.record(conn_ms, &DURATION_BOUNDS_MS);
            slot.upstream_bytes_received.record(bytes_rx, &BYTES_BOUNDS);
        }
    }

    Status::NGX_OK.into()
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
        use crate::data_model::{
            AggregationTemporality, HistogramData, HistogramDataPoint, Metric, MetricData,
        };

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
        }

        use crate::shm::{BYTES_BOUNDS, DURATION_BOUNDS_MS};

        let dur_bounds: std::vec::Vec<f64> =
            DURATION_BOUNDS_MS.iter().map(|&b| b as f64).collect();
        let byte_bounds: std::vec::Vec<f64> = BYTES_BOUNDS.iter().map(|&b| b as f64).collect();

        std::vec![
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
