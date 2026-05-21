// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Reads NGINX's built-in `ngx_stat_*` atomics and converts them into OTel
//! `Metric` values (equivalent to what the stub_status module exposes).
//!
//! Requires nginx built with `--with-http_stub_status_module` (`NGX_STAT_STUB`).

use core::sync::atomic::Ordering;

use crate::data_model::{
    AggregationTemporality, HistogramData, Metric, MetricData,
};
use crate::metric_source::MetricSource;

/// A `MetricSource` that reads NGINX's internal connection/request counters.
///
/// These are the same values exposed by the HTTP stub_status module.
/// All reads happen only on the designated export worker (`NgxProcess::Worker(0)`),
/// never on the request path.
pub struct StubStatusSource;

impl MetricSource for StubStatusSource {
    fn collect(&self) -> std::vec::Vec<Metric> {
        // Safety: ngx_stat_* are initialised before any worker starts.
        // We read them on Worker 0 only, in the export loop context.
        let (accepted, handled, requests, active, reading, writing, waiting) =
            unsafe { read_stats() };

        let now = now_unix_nano();

        std::vec![
            counter_metric(
                "nginx.connections.accepted",
                "Total accepted connections",
                "connections",
                accepted,
                now,
            ),
            counter_metric(
                "nginx.connections.handled",
                "Total handled connections",
                "connections",
                handled,
                now,
            ),
            counter_metric(
                "nginx.requests.total",
                "Total HTTP requests processed",
                "requests",
                requests,
                now,
            ),
            gauge_metric(
                "nginx.connections.active",
                "Active connections (reading + writing + waiting)",
                "connections",
                active,
                now,
            ),
            gauge_metric(
                "nginx.connections.reading",
                "Connections reading request headers",
                "connections",
                reading,
                now,
            ),
            gauge_metric(
                "nginx.connections.writing",
                "Connections writing responses",
                "connections",
                writing,
                now,
            ),
            gauge_metric(
                "nginx.connections.waiting",
                "Idle keep-alive connections",
                "connections",
                waiting,
                now,
            ),
        ]
    }
}

/// Read all seven `ngx_stat_*` atomics in one place.
///
/// # Safety
/// Caller must be on the designated export worker; `ngx_stat_*` must be
/// initialised (they always are once nginx has started).
#[cfg(ngx_feature = "stat_stub")]
unsafe fn read_stats() -> (u64, u64, u64, u64, u64, u64, u64) {
    use nginx_sys::{
        ngx_stat_accepted, ngx_stat_active, ngx_stat_handled, ngx_stat_reading,
        ngx_stat_requests, ngx_stat_waiting, ngx_stat_writing,
    };

    macro_rules! load {
        ($ptr:expr) => {
            // ngx_stat_* is a *mut ngx_atomic_t (= *mut c_ulong).
            // We treat the underlying memory as an AtomicU64.
            // TODO(portability): ngx_atomic_t is c_ulong-wide. This alias is correct
            // on 64-bit Linux/macOS where c_ulong == u64, but breaks on 32-bit
            // platforms where c_ulong == u32. Revisit before declaring v1.0 portable.
            unsafe {
                (*(($ptr) as *const core::sync::atomic::AtomicU64))
                    .load(Ordering::Acquire)
            }
        };
    }

    (
        load!(ngx_stat_accepted),
        load!(ngx_stat_handled),
        load!(ngx_stat_requests),
        load!(ngx_stat_active),
        load!(ngx_stat_reading),
        load!(ngx_stat_writing),
        load!(ngx_stat_waiting),
    )
}

/// Stub for when nginx is built without `--with-http_stub_status_module`.
/// Returns all zeros; the export loop should not be started in this case.
#[cfg(not(ngx_feature = "stat_stub"))]
unsafe fn read_stats() -> (u64, u64, u64, u64, u64, u64, u64) {
    (0, 0, 0, 0, 0, 0, 0)
}

// ─── helpers ────────────────────────────────────────────────────────────────

/// Returns the current time as Unix epoch nanoseconds.
fn now_unix_nano() -> u64 {
    // In nginx context we'd use ngx_timeofday(), but for Phase 1.1 std::time is fine
    // because this runs only on the export worker (not the request path).
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Build a cumulative-sum "counter" metric from a scalar value.
///
/// We model counters as single-bucket histograms (count=1, sum=value) so the
/// encoder can emit them uniformly.  A proper `Sum` instrument is added in
/// Step 7's encoder.
fn counter_metric(name: &str, desc: &str, unit: &str, value: u64, time_ns: u64) -> Metric {
    scalar_histogram(name, desc, unit, value, time_ns, AggregationTemporality::Cumulative)
}

/// Build a gauge metric from a scalar value.
fn gauge_metric(name: &str, desc: &str, unit: &str, value: u64, time_ns: u64) -> Metric {
    scalar_histogram(name, desc, unit, value, time_ns, AggregationTemporality::Unspecified)
}

fn scalar_histogram(
    name: &str,
    desc: &str,
    unit: &str,
    value: u64,
    time_ns: u64,
    temporality: AggregationTemporality,
) -> Metric {
    use crate::data_model::HistogramDataPoint;
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
                count: 1,
                sum: value as f64,
                // Single "catch-all" bucket: no explicit boundaries.
                bucket_counts: std::vec![1],
                explicit_bounds: std::vec![],
            }],
        }),
    }
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_model::MetricData;

    #[test]
    fn stub_status_produces_seven_metrics() {
        let src = StubStatusSource;
        let metrics = src.collect();
        assert_eq!(metrics.len(), 7, "expected 7 stub_status metrics");

        let names: std::vec::Vec<&str> = metrics.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"nginx.connections.accepted"));
        assert!(names.contains(&"nginx.connections.handled"));
        assert!(names.contains(&"nginx.requests.total"));
        assert!(names.contains(&"nginx.connections.active"));
        assert!(names.contains(&"nginx.connections.reading"));
        assert!(names.contains(&"nginx.connections.writing"));
        assert!(names.contains(&"nginx.connections.waiting"));

        // Each metric has exactly one data point.
        for m in &metrics {
            let MetricData::Histogram(ref h) = m.data;
            assert_eq!(h.data_points.len(), 1, "metric {} has wrong #points", m.name);
        }
    }
}
