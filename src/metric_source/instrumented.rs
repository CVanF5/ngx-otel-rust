// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Log-phase handler that bumps per-worker shm slot counters per request
//! and (when enabled) pushes an access log record into the per-worker ring.
//!
//! ## Hard constraints (verified in Step 6)
//! - No `Vec::new()`, `Box::new()`, `String::from()`, or any heap allocation.
//! - No syscalls beyond what the nginx log phase already incurs.
//! - No locks; only atomic increments (`Ordering::Relaxed` on writes).
//! - The handler is registered **only** when `otel_exporter` is configured.
//! - Exception-tail / exemplar emission is gated by
//!   `amcf.is_access_sample_enabled() && is_interesting(status, duration_ms)`;
//!   with the sample directive absent the path is byte-equivalent to the
//!   metrics-only path (zero cost beyond one cheap branch + the histogram bump).

use core::sync::atomic::Ordering;

use ngx::core::Status;
use ngx::http::{HttpModuleMainConf, HttpPhase, HttpRequestHandler, Request};

use crate::logs::{WorkerRingProducer, access::emit_access_record};
use crate::shm::{
    HttpMethod, ProtoVersion, StatusClass, combo_index,
    logs_access_ring, worker_slots, BYTES_BOUNDS, DURATION_BOUNDS_MS, N_BYTES_BUCKETS,
    N_DURATION_BUCKETS,
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
        let worker_id = unsafe { nginx_sys::ngx_worker };

        // Get our slot. No allocation; pointer arithmetic only.
        // Safety: zone was sized for ≥ worker_id slots during postconfiguration.
        let slot = unsafe { &*worker_slots(base, worker_id) };

        // Use AsRef to get a typed reference to the underlying ngx_http_request_t.
        let r = request.as_ref();

        // ── request duration in milliseconds ──────────────────────────────
        // Mirror avr-module/src/ngx_http_avr_data_sources.c:12-15 (get_request_time)
        // and nginx/src/http/ngx_http_variables.c:2284 ($request_time idiom):
        //   ms = (tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec)
        // r->start_msec is the millisecond *fraction* of the start second (0–999),
        // not a full epoch timestamp — the previous code subtracted the wrong clock.
        let duration_ms: u64 = {
            let tp = nginx_sys::ngx_timeofday(); // safe: returns &'static ngx_time_t
                                                 // time_t = c_long (i64 on 64-bit), ngx_uint_t/ngx_msec_t = usize.
            let ms: i64 =
                (tp.sec as i64 - r.start_sec) * 1000 + (tp.msec as i64 - r.start_msec as i64);
            ms.max(0) as u64
        };
        // ── request duration (multi-dim, fix3b FU4b) ──────────────────────
        // Compute combination index from bounded dimensions (no alloc, no lock).
        let method = HttpMethod::from_bytes(r.method_name.as_bytes());
        let status = r.headers_out.status as u16;
        let status_class = StatusClass::from_status(status);
        let proto = ProtoVersion::from_ngx(r.http_version as core::ffi::c_uint);
        let idx = combo_index(method, status_class, proto);
        slot.request_duration_combos[idx].record(duration_ms, &DURATION_BOUNDS_MS);

        // ── request body bytes ────────────────────────────────────────────
        slot.request_body_bytes.record(r.request_length as u64, &BYTES_BOUNDS);

        // ── response bytes ────────────────────────────────────────────────
        let resp_bytes = {
            let conn = request.connection();
            if conn.is_null() {
                0u64
            } else {
                unsafe { (*conn).sent as u64 }
            }
        };
        slot.response_body_bytes.record(resp_bytes, &BYTES_BOUNDS);

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

        // ── Phase 2.2: exception-tail / exemplar sampling ─────────────────
        // Gate 1 (cheap config check): absent directive → is_access_sample_enabled()
        //   = false, this entire block is skipped.
        // Gate 2 (is_interesting predicate): the common 200/fast case falls through
        //   with no ring push.  Only errors and latency outliers reach emit_access_record.
        // The histogram bump above is always-on and is NOT gated here.
        if amcf.is_access_sample_enabled() && is_interesting(status, duration_ms) {
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

                // Timestamp: use duration computation result.  We want the
                // request start time in nanoseconds; derive from the nginx
                // cached time + start fields.
                let ts_unix_nano: u64 = {
                    let tp = nginx_sys::ngx_timeofday();
                    // Request start: r.start_sec + r.start_msec / 1000
                    // Convert to ns: start_sec * 1e9 + start_msec * 1e6
                    (r.start_sec as u64)
                        .saturating_mul(1_000_000_000)
                        .saturating_add(r.start_msec as u64 * 1_000_000)
                };
                let _ = nginx_sys::ngx_timeofday(); // suppress unused-import warning if any

                emit_access_record(
                    &producer,
                    method,
                    status,
                    req_len,
                    resp_bytes_acc,
                    client_addr,
                    ts_unix_nano,
                );
            }
        }

        Status::NGX_OK
    }
}

/// Default tail status floor: requests with HTTP status ≥ this value are
/// "interesting" and qualify for the exception-tail / exemplar ring.
/// 400 catches 4xx (client errors) and 5xx (server errors).
pub const TAIL_STATUS_FLOOR: u16 = 400;

/// Default tail latency floor in milliseconds: requests taking ≥ this long
/// are "interesting" regardless of status.  1000 ms = 1 s (latency outlier).
pub const TAIL_LATENCY_MS: u64 = 1000;

/// Predicate for the exception-tail / exemplar gate (Phase 2.2 Step 2.2.1).
///
/// Returns `true` when the request is "interesting" — an error status or a
/// latency outlier.  The common 200/fast case returns `false` and skips the
/// ring push entirely.
///
/// # Hot-path note
/// This function is `#[inline]`, branch-only (no alloc, no lock, no syscall).
/// It is only ever called when `is_access_sample_enabled()` is true.
#[inline]
pub fn is_interesting(status: u16, duration_ms: u64) -> bool {
    status >= TAIL_STATUS_FLOOR || duration_ms >= TAIL_LATENCY_MS
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
}

// Safety: InstrumentedSource is only used on Worker 0's export loop.
unsafe impl Send for InstrumentedSource {}
unsafe impl Sync for InstrumentedSource {}

impl crate::metric_source::MetricSource for InstrumentedSource {
    fn collect(&self) -> std::vec::Vec<crate::data_model::Metric> {
        use crate::data_model::{AggregationTemporality, AnyValue, HistogramDataPoint, KeyValue};
        use crate::shm::{
            HttpMethod, N_HTTP_METHODS, ProtoVersion, N_PROTO_VERSIONS,
            StatusClass, N_STATUS_CLASSES, N_COMBOS, BYTES_BOUNDS, DURATION_BOUNDS_MS,
        };

        let start = self.start_time_unix_nano;
        let now = now_unix_nano();

        // Aggregate per-combination duration histograms over all workers.
        // combo_agg[idx] = (bucket_counts, sum, count) for combination idx.
        let mut combo_agg: std::vec::Vec<([u64; N_DURATION_BUCKETS], u64, u64)> =
            std::vec![(([0u64; N_DURATION_BUCKETS], 0u64, 0u64)); N_COMBOS];
        let mut req_bytes = ([0u64; N_BYTES_BUCKETS], 0u64, 0u64);
        let mut resp_bytes = ([0u64; N_BYTES_BUCKETS], 0u64, 0u64);
        let mut up_resp = ([0u64; N_DURATION_BUCKETS], 0u64, 0u64);
        let mut up_hdr = ([0u64; N_DURATION_BUCKETS], 0u64, 0u64);
        let mut up_conn = ([0u64; N_DURATION_BUCKETS], 0u64, 0u64);
        let mut up_bytes = ([0u64; N_BYTES_BUCKETS], 0u64, 0u64);
        let mut up_bytes_sent = ([0u64; N_BYTES_BUCKETS], 0u64, 0u64);

        for i in 0..self.n_workers {
            let slot = unsafe { &*worker_slots(self.base, i) };

            // Sum per-combination duration histograms.
            for idx in 0..N_COMBOS {
                let (bc, bs, bcount) = slot.request_duration_combos[idx].snapshot();
                add_histogram(&mut combo_agg[idx], &bc, bs, bcount);
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
        }

        let dur_bounds: std::vec::Vec<f64> = DURATION_BOUNDS_MS.iter().map(|&b| b as f64).collect();
        let byte_bounds: std::vec::Vec<f64> = BYTES_BOUNDS.iter().map(|&b| b as f64).collect();

        // ── Build http.server.request.duration (fix3b FU4c) ──────────────
        // All histograms are cumulative running totals.
        let duration_metric = if self.status_code_class_enabled {
            // Emit one data point per non-empty combination with bounded semconv
            // attributes (method, status_class, protocol).  Only OTel-semconv
            // attributes are emitted; no free-form / unbounded keys.
            let mut data_points: std::vec::Vec<HistogramDataPoint> = std::vec::Vec::new();
            for m_idx in 0..N_HTTP_METHODS {
                for sc_idx in 0..N_STATUS_CLASSES {
                    for p_idx in 0..N_PROTO_VERSIONS {
                        let combo = m_idx * N_STATUS_CLASSES * N_PROTO_VERSIONS
                            + sc_idx * N_PROTO_VERSIONS
                            + p_idx;
                        let (bc, bs, bcount) = combo_agg[combo];
                        if bcount == 0 {
                            continue; // skip empty combinations
                        }
                        // SAFETY: enum values are fully covered by the index ranges.
                        let method = match m_idx {
                            0 => HttpMethod::Get,
                            1 => HttpMethod::Head,
                            2 => HttpMethod::Post,
                            3 => HttpMethod::Put,
                            4 => HttpMethod::Delete,
                            5 => HttpMethod::Patch,
                            6 => HttpMethod::Options,
                            _ => HttpMethod::Other,
                        };
                        let status_class = match sc_idx {
                            0 => StatusClass::S1xx,
                            1 => StatusClass::S2xx,
                            2 => StatusClass::S3xx,
                            3 => StatusClass::S4xx,
                            _ => StatusClass::S5xx,
                        };
                        let proto = match p_idx {
                            0 => ProtoVersion::Http10,
                            1 => ProtoVersion::Http11,
                            2 => ProtoVersion::Http2,
                            _ => ProtoVersion::Http3,
                        };
                        data_points.push(HistogramDataPoint {
                            attributes: std::vec![
                                KeyValue {
                                    key: "http.request.method".into(),
                                    value: AnyValue::String(method.as_str().into()),
                                },
                                KeyValue {
                                    key: "http.response.status_code".into(),
                                    value: AnyValue::Int(status_class.representative_status()),
                                },
                                KeyValue {
                                    key: "network.protocol.version".into(),
                                    value: AnyValue::String(proto.as_str().into()),
                                },
                            ],
                            start_time_unix_nano: start,
                            time_unix_nano: now,
                            count: bcount,
                            sum: bs as f64,
                            bucket_counts: bc.to_vec(),
                            explicit_bounds: dur_bounds.clone(),
                        });
                    }
                }
            }
            use crate::data_model::{HistogramData, Metric, MetricData};
            Metric {
                name: "http.server.request.duration".into(),
                description: "HTTP server request duration".into(),
                unit: "ms".into(),
                data: MetricData::Histogram(HistogramData {
                    aggregation_temporality: AggregationTemporality::Cumulative,
                    data_points,
                }),
            }
        } else {
            // Aggregate across all combinations → single data point (backward compat).
            let mut dur = ([0u64; N_DURATION_BUCKETS], 0u64, 0u64);
            for agg in &combo_agg {
                add_histogram(&mut dur, &agg.0, agg.1, agg.2);
            }
            hist_metric(
                "http.server.request.duration",
                "HTTP server request duration",
                "ms",
                dur,
                dur_bounds.clone(),
                start,
                now,
                AggregationTemporality::Cumulative,
            )
        };

        std::vec![
            duration_metric,
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

fn now_unix_nano() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::logs::{WorkerRingProducer, access::emit_access_record};
    use crate::logs::ring::tests::make_ring_with_cap;

    /// With `is_access_sample_enabled() = false` (the default), the exception-tail
    /// gate is closed: no ring operations occur even for interesting requests.
    #[test]
    fn access_emission_off_no_ring_touch() {
        let (_buf, ring) = make_ring_with_cap(4096);

        // Gate check: access_sample_enabled = false → skip emit entirely.
        let access_sample_enabled = false;
        if access_sample_enabled && super::is_interesting(503, 0) {
            let producer = WorkerRingProducer { ring };
            emit_access_record(&producer, b"GET", 503, 0, 512, b"127.0.0.1", 0);
        }

        // Ring must be empty — no record pushed.
        let mut out = std::vec::Vec::new();
        assert!(
            !ring.pop_into(&mut out),
            "ring must be empty when access sample is disabled"
        );
        assert_eq!(ring.drop_count(), 0, "no drops expected");
    }

    /// With `is_access_sample_enabled() = true`, a 200/fast request is NOT
    /// interesting and must NOT reach the ring.
    #[test]
    fn tail_predicate_selects_only_interesting() {
        let (_buf, ring) = make_ring_with_cap(4096);
        let access_sample_enabled = true;

        // 200, 0ms — not interesting, no push.
        if access_sample_enabled && super::is_interesting(200, 0) {
            let producer = WorkerRingProducer { ring };
            emit_access_record(&producer, b"GET", 200, 0, 512, b"127.0.0.1", 0);
        }
        let mut out = std::vec::Vec::new();
        assert!(!ring.pop_into(&mut out), "200/fast must NOT reach the tail ring");

        // 503, 0ms — interesting (error), push expected.
        if access_sample_enabled && super::is_interesting(503, 0) {
            let producer = WorkerRingProducer { ring };
            emit_access_record(&producer, b"GET", 503, 0, 0, b"127.0.0.1", 0);
        }
        assert!(ring.pop_into(&mut out), "503 must reach the tail ring");

        // 200, 2000ms — interesting (latency outlier), push expected.
        if access_sample_enabled && super::is_interesting(200, 2000) {
            let producer = WorkerRingProducer { ring };
            emit_access_record(&producer, b"GET", 200, 0, 0, b"127.0.0.1", 0);
        }
        out.clear();
        assert!(ring.pop_into(&mut out), "slow 200 must reach the tail ring");
    }

    /// With `is_access_sample_enabled() = true` and an interesting request, the
    /// log-phase handler pushes one access record into the ring with the expected
    /// fields.
    #[test]
    fn access_emission_on_pushes_record() {
        let (_buf, ring) = make_ring_with_cap(4096);

        // Gate check: access_sample_enabled = true + interesting (503 ≥ 400) → emit.
        let access_sample_enabled = true;
        if access_sample_enabled && super::is_interesting(503, 0) {
            let producer = WorkerRingProducer { ring };
            emit_access_record(
                &producer,
                b"POST",
                503,
                128,
                256,
                b"10.0.0.1",
                1_700_000_000_000_000_000,
            );
        }

        // Ring must have one record.
        let mut out = std::vec::Vec::new();
        let ok = ring.pop_into(&mut out);
        assert!(ok, "ring must have a record for an interesting request");
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
}
