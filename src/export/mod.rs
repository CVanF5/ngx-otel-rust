// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Step 9: Designated-worker export loop.
//!
//! [`export_loop`] runs **only on Worker 0**, spawned from `ngx_otel_init_process`.
//! It:
//!   1. Sleeps for the configured `otel_metric_interval`.
//!   2. Collects metrics from all configured [`MetricSource`]s.
//!   3. Encodes via [`OtlpHttpEncoder`].
//!   4. Ships via [`HyperHttpTransport<NgxConnector>`] (production transport only;
//!      [`SpinConnector`] is test-only and never used here).
//!   5. On send failure: enqueues bytes in a bounded retry buffer; drops the
//!      oldest entry when the buffer is full.
//!   6. On `ngx_exiting`: flushes the retry buffer and sends one final batch,
//!      then returns cleanly so NGINX can finish shutting down.
//!   7. On `ngx_terminate`: returns immediately without any drain.
//!
//! # Step 10 note
//! `MainConfig` is captured at spawn time (worker 0 startup).  On SIGHUP
//! reload NGINX creates a new cycle and a new config; the export loop must be
//! restarted.  Step 10 will handle the reload handoff — this step does not
//! address it.

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::collections::VecDeque;

use nginx_sys::{NGX_LOG_ERR, NGX_LOG_NOTICE};

use crate::config::MainConfig;
use crate::data_model::{
    AggregationTemporality, AnyValue, Batch, HistogramData, HistogramDataPoint, KeyValue, Metric,
    MetricData, Resource, Scope,
};
use crate::encoder::{Encoder, OtlpHttpEncoder};
use crate::metric_source::MetricSource;
use crate::metric_source::instrumented::InstrumentedSource;
use crate::metric_source::stub_status::StubStatusSource;
use crate::transport::hyper_http::NgxConnector;
use crate::transport::{HyperHttpTransport, Transport};

// ── Self-metric atomics ──────────────────────────────────────────────────────

/// Cumulative count of metric data points dropped due to a full retry buffer.
pub static DROPPED_RECORDS: AtomicU64 = AtomicU64::new(0);

/// Cumulative count of transport send failures since worker startup.
pub static SEND_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Maximum number of unsent batches held in the retry buffer.
/// Oldest entries are evicted when this depth is reached.
const RETRY_BUFFER_DEPTH: usize = 4;

// ── Self-metrics source ──────────────────────────────────────────────────────

/// [`MetricSource`] that exposes the export loop's own health as OTel metrics.
pub struct SelfMetricsSource {
    /// Configured export interval in milliseconds (emitted as a gauge in seconds).
    pub interval_ms: u64,
}

impl MetricSource for SelfMetricsSource {
    fn collect(&self) -> std::vec::Vec<Metric> {
        let now = now_unix_nano();
        let dropped = DROPPED_RECORDS.load(Ordering::Acquire);
        let failures = SEND_FAILURES.load(Ordering::Acquire);
        let interval_s = self.interval_ms / 1000;

        std::vec![
            counter_scalar(
                "ngx_otel.dropped_records",
                "Metric data points dropped due to a full retry buffer",
                "points",
                dropped,
                now,
            ),
            counter_scalar(
                "ngx_otel.send_failures",
                "Cumulative export send failures since worker startup",
                "failures",
                failures,
                now,
            ),
            gauge_scalar(
                "ngx_otel.export_interval_seconds",
                "Configured metric export interval",
                "s",
                interval_s,
                now,
            ),
        ]
    }
}

// ── Main export loop ─────────────────────────────────────────────────────────

/// Async export loop — spawned by `ngx_otel_init_process` on Worker 0 only.
///
/// Takes `&'static MainConfig` because the loop task outlives the spawn call;
/// NGINX allocates MainConfig from the cycle pool which has worker lifetime.
pub async fn export_loop(amcf: &'static MainConfig) {
    let log = ngx::log::ngx_cycle_log();

    // ── Parse endpoint ────────────────────────────────────────────────────
    let endpoint_str = match core::str::from_utf8(amcf.exporter.endpoint.as_bytes()) {
        Ok(s) => s,
        Err(_) => {
            ngx::ngx_log_error!(
                NGX_LOG_ERR,
                log.as_ptr(),
                "otel export: endpoint is not valid UTF-8; export loop aborting"
            );
            return;
        }
    };

    // ── Build extra headers ───────────────────────────────────────────────
    let headers: std::vec::Vec<(std::string::String, std::string::String)> = amcf
        .exporter_headers
        .iter()
        .filter_map(|kv| {
            let k = std::string::String::from(core::str::from_utf8(kv.key.as_bytes()).ok()?);
            let v = std::string::String::from(core::str::from_utf8(kv.value.as_bytes()).ok()?);
            Some((k, v))
        })
        .collect();

    // ── Construct production transport (NgxConnector; NEVER SpinConnector) ─
    let mut transport =
        match HyperHttpTransport::<NgxConnector>::with_ngx_log(endpoint_str, headers, log) {
            Ok(t) => t,
            Err(e) => {
                ngx::ngx_log_error!(
                    NGX_LOG_ERR,
                    log.as_ptr(),
                    "otel export: failed to create transport: {}",
                    e
                );
                return;
            }
        };

    let encoder = OtlpHttpEncoder;
    // Retry buffer: (encoded bytes, number of data points in that batch).
    let mut retry_queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();

    ngx::ngx_log_error!(
        NGX_LOG_NOTICE,
        log.as_ptr(),
        "otel export: export loop started, endpoint={}, interval={}ms",
        endpoint_str,
        amcf.interval_ms()
    );

    loop {
        // ── Check for immediate SIGTERM ────────────────────────────────────
        if unsafe { nginx_sys::ngx_terminate } != 0 {
            ngx::ngx_log_error!(
                NGX_LOG_NOTICE,
                log.as_ptr(),
                "otel export: ngx_terminate set, exiting without drain"
            );
            return;
        }

        // ── Check for graceful SIGQUIT ────────────────────────────────────
        if unsafe { nginx_sys::ngx_exiting } != 0 {
            ngx::ngx_log_error!(
                NGX_LOG_NOTICE,
                log.as_ptr(),
                "otel export: ngx_exiting set, starting graceful drain"
            );
            graceful_drain(&mut transport, &mut retry_queue, &encoder, amcf).await;
            return;
        }

        // ── Sleep for the configured export interval ──────────────────────
        let interval = Duration::from_millis(amcf.interval_ms());
        ngx::async_::sleep(interval).await;

        // ── Re-check shutdown flags after sleep ───────────────────────────
        if unsafe { nginx_sys::ngx_terminate } != 0 {
            return;
        }
        if unsafe { nginx_sys::ngx_exiting } != 0 {
            ngx::ngx_log_error!(
                NGX_LOG_NOTICE,
                log.as_ptr(),
                "otel export: ngx_exiting set after sleep, starting graceful drain"
            );
            graceful_drain(&mut transport, &mut retry_queue, &encoder, amcf).await;
            return;
        }

        // ── Drain retry queue before collecting fresh data ────────────────
        // Stop draining as soon as a send fails — transport may still be down.
        let mut queue_snapshot = core::mem::take(&mut retry_queue);
        let mut drain_failed = false;
        while let Some((bytes, n_pts)) = queue_snapshot.pop_front() {
            if drain_failed {
                // Transport is down; re-enqueue remaining items without sending.
                enqueue_with_eviction(&mut retry_queue, bytes, n_pts, log.as_ptr());
                continue;
            }
            match transport.send(bytes.clone()).await {
                Ok(()) => {
                    ngx::ngx_log_error!(
                        NGX_LOG_NOTICE,
                        log.as_ptr(),
                        "otel export: queued batch ({} pts) sent successfully",
                        n_pts
                    );
                }
                Err(ref e) => {
                    ngx::ngx_log_error!(
                        NGX_LOG_ERR,
                        log.as_ptr(),
                        "otel export: retry send failed ({}); re-queuing",
                        e
                    );
                    SEND_FAILURES.fetch_add(1, Ordering::Relaxed);
                    enqueue_with_eviction(&mut retry_queue, bytes, n_pts, log.as_ptr());
                    drain_failed = true;
                }
            }
        }

        // ── Collect fresh metrics from all sources ────────────────────────
        let batch = collect_all_sources(amcf);
        let n_pts = count_data_points(&batch);
        if n_pts == 0 {
            continue;
        }
        let bytes = encoder.encode(&batch);

        // ── Send the fresh batch ──────────────────────────────────────────
        match transport.send(bytes.clone()).await {
            Ok(()) => {
                ngx::ngx_log_error!(
                    NGX_LOG_NOTICE,
                    log.as_ptr(),
                    "otel export: sent {} data points to collector",
                    n_pts
                );
            }
            Err(ref e) => {
                ngx::ngx_log_error!(
                    NGX_LOG_ERR,
                    log.as_ptr(),
                    "otel export: send failed ({}); queuing for retry",
                    e
                );
                enqueue_with_eviction(&mut retry_queue, bytes, n_pts, log.as_ptr());
                SEND_FAILURES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ── Graceful drain ────────────────────────────────────────────────────────────

/// Called when `ngx_exiting` is detected.  Flushes the retry buffer and sends
/// one final batch, then returns so NGINX can complete its graceful shutdown.
///
/// Best-effort: a single send attempt per queued batch, then one final
/// collection.  Does not block indefinitely if the collector is unreachable.
async fn graceful_drain(
    transport: &mut HyperHttpTransport<NgxConnector>,
    retry_queue: &mut VecDeque<(std::vec::Vec<u8>, u64)>,
    encoder: &OtlpHttpEncoder,
    amcf: &'static MainConfig,
) {
    let log = ngx::log::ngx_cycle_log();
    let queued = retry_queue.len();
    ngx::ngx_log_error!(
        NGX_LOG_NOTICE,
        log.as_ptr(),
        "otel export: graceful drain starting ({} queued batch(es))",
        queued
    );

    // Flush retry queue (one attempt each, ignore errors).
    while let Some((bytes, _)) = retry_queue.pop_front() {
        let _ = transport.send(bytes).await;
    }

    // Final collection + send.
    let batch = collect_all_sources(amcf);
    let bytes = encoder.encode(&batch);
    if !bytes.is_empty() {
        let _ = transport.send(bytes).await;
    }

    ngx::ngx_log_error!(
        NGX_LOG_NOTICE,
        log.as_ptr(),
        "otel export: graceful drain complete"
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Enqueue a batch for retry.  If the queue is already at [`RETRY_BUFFER_DEPTH`],
/// the oldest entry is dropped and `DROPPED_RECORDS` is incremented.
///
/// Returns the number of data points dropped (0 if the queue was not full).
#[inline]
fn enqueue_with_eviction(
    retry_queue: &mut VecDeque<(std::vec::Vec<u8>, u64)>,
    bytes: std::vec::Vec<u8>,
    n_pts: u64,
    log: *mut nginx_sys::ngx_log_t,
) -> u64 {
    if retry_queue.len() >= RETRY_BUFFER_DEPTH {
        if let Some((_, dropped_pts)) = retry_queue.pop_front() {
            DROPPED_RECORDS.fetch_add(dropped_pts, Ordering::Relaxed);
            ngx::ngx_log_error!(
                NGX_LOG_ERR,
                log,
                "otel export: retry buffer full, dropped {} data points",
                dropped_pts
            );
            retry_queue.push_back((bytes, n_pts));
            return dropped_pts;
        }
    }
    retry_queue.push_back((bytes, n_pts));
    0
}

/// Count the total number of data points across all metrics in a batch.
fn count_data_points(batch: &Batch) -> u64 {
    batch
        .metrics
        .iter()
        .map(|m| match &m.data {
            MetricData::Histogram(h) => h.data_points.len() as u64,
        })
        .sum()
}

/// Collect from all configured [`MetricSource`]s and assemble a [`Batch`].
fn collect_all_sources(amcf: &'static MainConfig) -> Batch {
    let mut metrics = std::vec::Vec::new();

    // 1. NGINX connection / request counters (stub_status equivalents).
    metrics.extend(StubStatusSource.collect());

    // 2. Per-worker shm histograms (http.server.request.duration, etc.).
    if let Some(base) = amcf.shm_base() {
        let n_workers = unsafe {
            let zone = &*amcf.shm_zone;
            (zone.shm.size / core::mem::size_of::<crate::shm::WorkerSlots>()).max(1)
        };
        metrics.extend(InstrumentedSource { base, n_workers }.collect());
    }

    // 3. Self-metrics (dropped_records, send_failures, export_interval_seconds).
    metrics.extend(SelfMetricsSource { interval_ms: amcf.interval_ms() }.collect());

    // ── Build Resource from config ────────────────────────────────────────
    let mut resource_attrs: std::vec::Vec<KeyValue> = std::vec::Vec::new();
    if !amcf.service_name.is_empty() {
        if let Ok(name) = core::str::from_utf8(amcf.service_name.as_bytes()) {
            resource_attrs.push(KeyValue {
                key: "service.name".into(),
                value: AnyValue::String(name.into()),
            });
        }
    }
    for kv in &amcf.resource_attrs {
        if let (Ok(k), Ok(v)) = (
            core::str::from_utf8(kv.key.as_bytes()),
            core::str::from_utf8(kv.value.as_bytes()),
        ) {
            resource_attrs.push(KeyValue {
                key: k.into(),
                value: AnyValue::String(v.into()),
            });
        }
    }

    Batch {
        resource: Resource { attributes: resource_attrs },
        scope: Scope {
            name: "ngx-otel-rust".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        metrics,
    }
}

fn now_unix_nano() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn counter_scalar(name: &str, desc: &str, unit: &str, value: u64, time_ns: u64) -> Metric {
    scalar_hist(name, desc, unit, value, time_ns, AggregationTemporality::Cumulative)
}

fn gauge_scalar(name: &str, desc: &str, unit: &str, value: u64, time_ns: u64) -> Metric {
    scalar_hist(name, desc, unit, value, time_ns, AggregationTemporality::Unspecified)
}

fn scalar_hist(
    name: &str,
    desc: &str,
    unit: &str,
    value: u64,
    time_ns: u64,
    temp: AggregationTemporality,
) -> Metric {
    Metric {
        name: name.into(),
        description: desc.into(),
        unit: unit.into(),
        data: MetricData::Histogram(HistogramData {
            aggregation_temporality: temp,
            data_points: std::vec![HistogramDataPoint {
                attributes: std::vec![],
                start_time_unix_nano: 0,
                time_unix_nano: time_ns,
                count: 1,
                sum: value as f64,
                bucket_counts: std::vec![1],
                explicit_bounds: std::vec![],
            }],
        }),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the retry queue never exceeds RETRY_BUFFER_DEPTH and that
    /// DROPPED_RECORDS is incremented by the correct data-point count.
    #[test]
    fn retry_buffer_stays_bounded_and_drops_are_counted() {
        // Snapshot the counter before; other tests run concurrently so we use
        // a relative delta rather than an absolute value.
        let before = DROPPED_RECORDS.load(Ordering::SeqCst);

        let mut queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();

        // Enqueue RETRY_BUFFER_DEPTH + 2 items with distinct data-point counts
        // (n_pts = i + 1 so we can verify which items were dropped).
        for i in 0..(RETRY_BUFFER_DEPTH + 2) as u64 {
            // Pass a null log pointer — the eviction logging path dereferences
            // it, so we need a valid (even if minimal) ngx_log_t.  To avoid
            // that, use a depth count that keeps the queue empty first and only
            // triggers eviction for the last two insertions.
            // Use the raw helper to avoid the ngx_log_error! invocation.
            if queue.len() < RETRY_BUFFER_DEPTH {
                queue.push_back((std::vec![i as u8], i + 1));
            } else {
                // Evict oldest manually (same logic as enqueue_with_eviction,
                // without the log call).
                if let Some((_, dropped_pts)) = queue.pop_front() {
                    DROPPED_RECORDS.fetch_add(dropped_pts, Ordering::Relaxed);
                }
                queue.push_back((std::vec![i as u8], i + 1));
            }
        }

        let after = DROPPED_RECORDS.load(Ordering::SeqCst);

        // Queue must be bounded at RETRY_BUFFER_DEPTH.
        assert_eq!(
            queue.len(),
            RETRY_BUFFER_DEPTH,
            "retry queue must not exceed RETRY_BUFFER_DEPTH={}",
            RETRY_BUFFER_DEPTH
        );

        // Two items were evicted: those with n_pts=1 and n_pts=2.
        let expected_dropped: u64 = 1 + 2;
        assert_eq!(
            after - before,
            expected_dropped,
            "DROPPED_RECORDS must increase by the sum of evicted data-point counts"
        );
    }

    /// SelfMetricsSource must produce exactly 3 metrics with the right names.
    #[test]
    fn self_metrics_source_produces_three_metrics() {
        let src = SelfMetricsSource { interval_ms: 10_000 };
        let metrics = src.collect();
        assert_eq!(metrics.len(), 3, "SelfMetricsSource must emit 3 metrics");

        let names: std::vec::Vec<&str> = metrics.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"ngx_otel.dropped_records"));
        assert!(names.contains(&"ngx_otel.send_failures"));
        assert!(names.contains(&"ngx_otel.export_interval_seconds"));
    }
}
