// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Reads NGINX's built-in `ngx_stat_*` atomics and converts them into OTel
//! `Metric` values (equivalent to what the stub_status module exposes).
//!
//! Requires nginx built with `--with-http_stub_status_module` (`NGX_STAT_STUB`).

// Only used by the stat_stub variant of `read_stats` (atomic loads); in a
// no-flag build that variant is cfg'd out, so the import would be unused.
#[cfg(ngx_feature = "stat_stub")]
use core::sync::atomic::Ordering;

use crate::data_model::{Metric, MetricData};
use crate::export::monotonic_sum_metric;
use crate::metric_source::MetricSource;

/// A `MetricSource` that reads NGINX's internal connection/request counters.
///
/// These are the same values exposed by the HTTP stub_status module.
/// All reads happen only on the designated export worker (`NgxProcess::Worker(0)`),
/// never on the request path.
pub struct StubStatusSource {
    /// Exporter process start time (Unix epoch, nanoseconds). Used as the
    /// `start_time_unix_nano` for the three monotonic cumulative Sums
    /// (`nginx.connections.accepted`, `nginx.connections.handled`,
    /// `nginx.requests.total`) so that downstream rate/delta-conversion
    /// processors can anchor windows correctly. Captured once at exporter-loop
    /// init (`export_loop`) and threaded in via `collect_all_sources`.
    pub start_time_unix_nano: u64,
}

impl MetricSource for StubStatusSource {
    fn collect(&self) -> std::vec::Vec<Metric> {
        // Safety: ngx_stat_* are initialised before any worker starts.
        // We read them on Worker 0 only, in the export loop context.
        let (accepted, handled, requests, active, reading, writing, waiting) =
            unsafe { read_stats() };

        let now = crate::util::now_unix_nano();

        std::vec![
            monotonic_sum_metric(
                "nginx.connections.accepted",
                "Total accepted connections",
                "{connection}",
                accepted as i64,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "nginx.connections.handled",
                "Total handled connections",
                "{connection}",
                handled as i64,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "nginx.requests.total",
                "Total HTTP requests processed",
                "{request}",
                requests as i64,
                self.start_time_unix_nano,
                now,
            ),
            gauge_metric(
                "nginx.connections.active",
                "Active connections (reading + writing + waiting)",
                "{connection}",
                active,
                now,
            ),
            gauge_metric(
                "nginx.connections.reading",
                "Connections reading request headers",
                "{connection}",
                reading,
                now,
            ),
            gauge_metric(
                "nginx.connections.writing",
                "Connections writing responses",
                "{connection}",
                writing,
                now,
            ),
            gauge_metric(
                "nginx.connections.waiting",
                "Idle keep-alive connections",
                "{connection}",
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
        ngx_stat_accepted, ngx_stat_active, ngx_stat_handled, ngx_stat_reading, ngx_stat_requests,
        ngx_stat_waiting, ngx_stat_writing,
    };

    macro_rules! load {
        ($ptr:expr) => {
            // ngx_stat_* is a *mut ngx_atomic_t (= *mut c_ulong).
            // We treat the underlying memory as an AtomicU64.
            // ngx_atomic_t is c_ulong-wide. This alias is correct on 64-bit
            // Linux/macOS where c_ulong == u64, but would break on 32-bit platforms
            // where c_ulong == u32. 32-bit targets are rejected at compile time by
            // the compile_error! guard in lib.rs.
            // SAFETY: `$ptr` is one of nginx's `ngx_stat_*` globals (a non-null
            // `*mut ngx_atomic_t`), allocated and zero-initialised by nginx at
            // startup before any worker runs (the `read_stats` fn contract requires
            // nginx to have started), so it is valid and properly aligned. We only
            // ever read it, never write, so casting to `*const AtomicU64` and taking
            // an `Acquire` load is sound: `AtomicU64` matches `ngx_atomic_t`'s
            // 8-byte layout on the supported 64-bit targets (see TODO above), and the
            // atomic load is the correct way to observe a counter that other workers
            // mutate concurrently via nginx's own atomic ops.
            unsafe { (*(($ptr) as *const core::sync::atomic::AtomicU64)).load(Ordering::Acquire) }
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

/// Build a gauge metric (instantaneous value) from a scalar.
///
/// Emitted as a real OTLP `Gauge` — NOT a Sum. The stub_status connection
/// counts (active/reading/writing/waiting) are instantaneous gauges.
fn gauge_metric(name: &str, desc: &str, unit: &str, value: u64, time_ns: u64) -> Metric {
    use crate::data_model::{GaugeData, NumberDataPoint, NumberValue};
    Metric {
        name: name.into(),
        description: desc.into(),
        unit: unit.into(),
        data: MetricData::Gauge(GaugeData {
            data_points: std::vec![NumberDataPoint {
                attributes: std::vec![],
                start_time_unix_nano: 0,
                time_unix_nano: time_ns,
                value: NumberValue::AsInt(value as i64),
            }],
        }),
    }
}

// ─── tests ──────────────────────────────────────────────────────────────────

// In a stub-enabled build (`--with-http_stub_status_module` → NGX_STAT_STUB →
// `ngx_feature = "stat_stub"`) the source is registered and yields all 7 series.
// See `collect_all_sources_omits_stub_status_without_stat_stub` in `export` for the
// inverse (no-flag build): the source is NOT registered, so the 7 series are ABSENT.
// The whole module is gated on `stat_stub` because its sole test exercises the
// stub-enabled path; the no-stub inverse is asserted at the registration site.
#[cfg(all(test, ngx_feature = "stat_stub"))]
mod tests {
    use super::*;
    use crate::data_model::{AggregationTemporality, MetricData};

    const TEST_START_NS: u64 = 1_700_000_000_000_000_000;

    #[test]
    fn stub_status_produces_seven_metrics() {
        let src = StubStatusSource { start_time_unix_nano: TEST_START_NS };
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

        // The three monotonic counters must be OTLP Sums (monotonic, Cumulative)
        // with the exporter start time set. The four connection-state series must
        // remain real OTLP Gauges (instantaneous, no start time).
        let counter_names =
            ["nginx.connections.accepted", "nginx.connections.handled", "nginx.requests.total"];
        let gauge_names = [
            "nginx.connections.active",
            "nginx.connections.reading",
            "nginx.connections.writing",
            "nginx.connections.waiting",
        ];
        for m in &metrics {
            if counter_names.contains(&m.name.as_str()) {
                let MetricData::Sum(ref s) = m.data else {
                    panic!(
                        "stub_status counter {} must be a Sum (got {:?})",
                        m.name,
                        core::mem::discriminant(&m.data)
                    );
                };
                assert!(s.is_monotonic, "counter {} Sum must be monotonic", m.name);
                assert_eq!(
                    s.aggregation_temporality,
                    AggregationTemporality::Cumulative,
                    "counter {} Sum must be Cumulative",
                    m.name
                );
                assert_eq!(s.data_points.len(), 1, "counter {} has wrong #points", m.name);
                assert_eq!(
                    s.data_points[0].start_time_unix_nano, TEST_START_NS,
                    "counter {} must carry the exporter start time",
                    m.name
                );
            } else if gauge_names.contains(&m.name.as_str()) {
                let MetricData::Gauge(ref g) = m.data else {
                    panic!("stub_status connection gauge {} must be a Gauge", m.name);
                };
                assert_eq!(g.data_points.len(), 1, "gauge {} has wrong #points", m.name);
            } else {
                panic!("unexpected metric name: {}", m.name);
            }
        }
    }

    /// Mutation-cycle assertion: the three counters are Sums (not Histograms).
    ///
    /// To verify this is a real guard: revert `monotonic_sum_metric` calls in
    /// `StubStatusSource::collect` back to `counter_metric`/`scalar_histogram`
    /// and this test fails with "must be a Sum (got Histogram)".
    #[test]
    fn counters_are_sums_not_histograms() {
        let src = StubStatusSource { start_time_unix_nano: TEST_START_NS };
        let metrics = src.collect();
        for m in &metrics {
            match m.name.as_str() {
                "nginx.connections.accepted"
                | "nginx.connections.handled"
                | "nginx.requests.total" => {
                    assert!(
                        matches!(m.data, MetricData::Sum(_)),
                        "{} must be MetricData::Sum, not a Histogram",
                        m.name
                    );
                }
                _ => {}
            }
        }
    }
}
