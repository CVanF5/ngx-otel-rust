// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Self-metric counters and the [`SelfMetricsSource`] collector.
//!
//! The atomics here are the single source of truth for the drain loop's own
//! health signals.  All writes come from the drain loop task (single-threaded
//! exporter process); reads come from [`SelfMetricsSource::collect`] on the
//! same thread, and from integration tests.  The `pub` visibility mirrors the
//! original flat-module visibility — external paths (`crate::drain::FOO`) work
//! via the re-exports in `drain/mod.rs`.

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

use crate::data_model::Metric;
use crate::metric_source::MetricSource;

// ── Self-metric atomics ──────────────────────────────────────────────────────

/// Cumulative count of records (any signal — metrics, logs, spans) dropped
/// because the per-signal retry buffer was full (oldest batch evicted) or
/// because a drain-abort discarded queued batches on graceful shutdown.
///
/// All three retry lanes (`retry_queue`, `logs_retry_queue`,
/// `spans_retry_queue`) credit this counter so the single self-metric
/// `ngx_otel.dropped_records` gives the operator the total drop budget across
/// all signals.  Per-signal ring-level drops are tracked separately
/// (`ACCESS_LOGS_DROPPED`, `ERROR_LOGS_DROPPED`, `TRACES_DROPPED_RECORDS`).
pub static DROPPED_RECORDS: AtomicU64 = AtomicU64::new(0);

/// Cumulative count of transport send failures since worker startup.
pub static SEND_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Cumulative count of bidi outbound messages dropped because the outbound
/// channel's `poll_ready` was `Pending` past the give-up deadline.  Indicates
/// backpressure pushed back on the producer.  Bidi overload path only — not
/// on the production OTLP/HTTP export loop.  Exposed as
/// `ngx_otel.bidi_backpressure_drops` self-metric so the overload integration
/// test can verify the counter is non-zero via the collector's metrics.json.
pub static BIDI_BACKPRESSURE_DROPS: AtomicU64 = AtomicU64::new(0);

// ── Log-specific self-metric atomics ─────────────────────────────────────────

/// Access-log records dropped by the producer because the ring was full.
/// Sum of per-worker `ring.drop_count()` snapshots at each drain cycle.
pub static ACCESS_LOGS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Error-log records dropped by the producer (kept here so the
/// metric is exposed even before the error-log path is wired in).
pub static ERROR_LOGS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Cumulative coalesced-count occurrences orphaned because the interval's
/// verbatim ring push was dropped (ring full).  Incremented by
/// `collect_log_records` once per drain cycle for each orphaned slot.
///
/// Unlike `ERROR_LOGS_DROPPED` (which snapshots the ring's cumulative drop
/// counter via `store`), this is accumulated additively with `fetch_add`
/// so it represents a true cumulative total across all drain cycles.
pub static ERROR_LOGS_COALESCED_ORPHANED: AtomicU64 = AtomicU64::new(0);

/// Cumulative logs transport send failures since exporter startup.
pub static LOGS_SEND_FAILURES: AtomicU64 = AtomicU64::new(0);

// ── Traces self-metric atomics ────────────────────────────────────────────────

/// Span records dropped by the producer because the spans ring was full.
/// Sum of per-worker `ring.drop_count()` snapshots at each drain cycle.
pub static TRACES_DROPPED_RECORDS: AtomicU64 = AtomicU64::new(0);

/// Cumulative traces transport send failures since exporter startup.
pub static TRACES_SEND_FAILURES: AtomicU64 = AtomicU64::new(0);

// ── Delivery-outcome self-metric atomics ──────────────────────────────────────
//
// These are the same single-writer exporter-local atomic pattern as the drop /
// send-failure counters above (written only by the exporter task in the policy
// engine, read later by `SelfMetricsSource`). They back the
// `ngx_otel.delivery.{permanent_rejected, partial_rejected, unauthorized}`
// self-metrics, which read these atomics rather than maintaining their own.

/// Cumulative count of batches the peer rejected as **permanently** unacceptable
/// (`DeliveryOutcome::Permanent`). These batches are dropped, never retried.
pub static PERMANENT_REJECTED: AtomicU64 = AtomicU64::new(0);

/// Cumulative count of individual records the peer reported it dropped on an
/// otherwise-accepted batch (`DeliveryOutcome::PartialReject { rejected }`).
/// Accumulates the `rejected` count; the batch itself is released.
pub static PARTIAL_REJECTED: AtomicU64 = AtomicU64::new(0);

/// Cumulative count of batches dropped because the peer reported an
/// authentication/authorization failure (`DeliveryOutcome::Unauthorized`).
/// Same policy action as `Permanent` (drop, no retry/backoff/pause); kept in a
/// distinct counter for observability plus a rate-limited "check credentials"
/// log.
pub static UNAUTHORIZED_REJECTED: AtomicU64 = AtomicU64::new(0);

/// Number of prior exporter crashes observed in the crash-loop window when
/// this exporter process started.  Set once by `otel_exporter_cycle` before
/// `export_loop` runs; 0 on a clean first start.  Exposed as the
/// `ngx_otel.exporter.restarts` gauge so operators can observe crash-loop
/// recovery without tailing the error log.
pub(crate) static EXPORTER_RESTARTS: AtomicU64 = AtomicU64::new(0);

/// Master (parent) PID captured once at exporter startup via `nginx_sys::ngx_parent`.
///
/// Written once by [`super::export_loop`] before the first export tick.  Used by
/// `build_resource_attrs` to populate the `service.instance.id` resource
/// attribute on **both** the metrics and logs OTLP Resource.
///
/// Key properties:
/// - **Stable across crash-respawn**: the master re-forks the exporter with the
///   same `ngx_parent`, so the id is unchanged and cumulative shm series continue.
/// - **Distinct across USR2 live binary upgrade**: the new master (different PID)
///   forks the new exporter; `ngx_parent` in the new child is the new master's PID.
/// - **Zero** = loop not yet started (pre-init, or SIGQUIT before first tick).
pub static MASTER_PID: AtomicI64 = AtomicI64::new(0);

/// Set to `true` by [`super::export_loop`] just before it returns after a graceful
/// drain on `ngx_quit`. The exporter cycle polls this flag in its `ngx_quit`
/// branch to know when the drain has completed and it is safe to exit.
///
/// Process-global; the exporter process is single-instance so
/// there is exactly one export_loop per process lifetime.
pub(crate) static EXPORT_LOOP_DONE: AtomicBool = AtomicBool::new(false);

// ── Self-metrics source ──────────────────────────────────────────────────────

/// [`MetricSource`] that exposes the drain loop's own health as OTel metrics.
pub struct SelfMetricsSource {
    /// Configured export interval in milliseconds.  Emitted as a Gauge in
    /// **seconds** (`"s"`) — OTel convention is to bake the unit into the
    /// unit field, not into the metric name.  The name `ngx_otel.export_interval`
    /// is unchanged; the value is `interval_ms / 1000` (integer seconds, rounded
    /// down; sub-second intervals are uncommon in practice).
    pub interval_ms: u64,
    /// Worker startup time (Unix epoch, nanoseconds). Used as the
    /// `start_time_unix_nano` for the cumulative monotonic Sums so that
    /// downstream rate/delta-conversion processors can anchor windows
    /// correctly. Captured once at [`super::export_loop`] init; see field
    /// initialisation in `collect_all_sources`.
    pub start_time_unix_nano: u64,
}

/// Convert an unsigned self-metric counter to the `i64` carried on the OTLP
/// `NumberDataPoint`, saturating at `i64::MAX` rather than wrapping negative.
///
/// These counters are exported as OTLP monotonic Sums, which the OTLP/Metrics
/// data model requires to be non-decreasing
/// (<https://opentelemetry.io/docs/specs/otel/metrics/data-model/#sums>). A raw
/// `as i64` cast of a `u64` past `i64::MAX` wraps to a negative value, which
/// would both violate monotonicity and read as a huge backwards jump. Saturation
/// keeps the series monotonic; the cap is only reachable at otherwise-impossible
/// counts, so no realistic value is distorted.
#[inline]
pub(super) fn counter_to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

impl MetricSource for SelfMetricsSource {
    fn collect(&self) -> std::vec::Vec<Metric> {
        let now = crate::util::now_unix_nano();
        let dropped = counter_to_i64(DROPPED_RECORDS.load(Ordering::Acquire));
        let failures = counter_to_i64(SEND_FAILURES.load(Ordering::Acquire));
        // Emit in seconds (unit "s"), not ms.  The name stays
        // `ngx_otel.export_interval` — OTel convention is to NOT bake units
        // into metric names; the unit field carries the information instead.
        let interval_s = counter_to_i64(self.interval_ms / 1000);

        let backpressure_drops = counter_to_i64(BIDI_BACKPRESSURE_DROPS.load(Ordering::Acquire));
        let access_logs_dropped = counter_to_i64(ACCESS_LOGS_DROPPED.load(Ordering::Acquire));
        let error_logs_dropped = counter_to_i64(ERROR_LOGS_DROPPED.load(Ordering::Acquire));
        let error_logs_coalesced_orphaned =
            counter_to_i64(ERROR_LOGS_COALESCED_ORPHANED.load(Ordering::Acquire));
        let logs_send_failures = counter_to_i64(LOGS_SEND_FAILURES.load(Ordering::Acquire));
        let traces_dropped = counter_to_i64(TRACES_DROPPED_RECORDS.load(Ordering::Acquire));
        let exporter_restarts = counter_to_i64(EXPORTER_RESTARTS.load(Ordering::Acquire));
        let permanent_rejected = counter_to_i64(PERMANENT_REJECTED.load(Ordering::Acquire));
        let partial_rejected = counter_to_i64(PARTIAL_REJECTED.load(Ordering::Acquire));
        let unauthorized_rejected = counter_to_i64(UNAUTHORIZED_REJECTED.load(Ordering::Acquire));
        std::vec![
            super::monotonic_sum_metric(
                "ngx_otel.dropped_records",
                "Records from any signal (metrics, logs, spans) dropped because the \
                 per-signal retry buffer was full or a drain-abort discarded queued batches",
                "{record}",
                dropped,
                self.start_time_unix_nano,
                now,
            ),
            super::monotonic_sum_metric(
                "ngx_otel.send_failures",
                "Cumulative export send failures since worker startup",
                "{failure}",
                failures,
                self.start_time_unix_nano,
                now,
            ),
            super::monotonic_sum_metric(
                "ngx_otel.bidi_backpressure_drops",
                "Bidi outbound messages dropped due to channel backpressure",
                "{message}",
                backpressure_drops,
                self.start_time_unix_nano,
                now,
            ),
            super::monotonic_sum_metric(
                "ngx_otel.logs.access.dropped_records",
                "Access log records dropped because the per-worker ring was full",
                "{record}",
                access_logs_dropped,
                self.start_time_unix_nano,
                now,
            ),
            super::monotonic_sum_metric(
                "ngx_otel.logs.error.dropped_records",
                "Error log records dropped because the per-worker ring was full",
                "{record}",
                error_logs_dropped,
                self.start_time_unix_nano,
                now,
            ),
            super::monotonic_sum_metric(
                "ngx_otel.logs.error.coalesced_orphaned_records",
                "Error log coalesced-count occurrences orphaned because the verbatim \
                 ring sample was dropped (ring full); a synthetic record is emitted \
                 per orphaned slot so backends still receive the occurrence count",
                "{record}",
                error_logs_coalesced_orphaned,
                self.start_time_unix_nano,
                now,
            ),
            super::monotonic_sum_metric(
                "ngx_otel.logs.send_failures",
                "Cumulative logs transport send failures since exporter startup",
                "{failure}",
                logs_send_failures,
                self.start_time_unix_nano,
                now,
            ),
            super::monotonic_sum_metric(
                "ngx_otel.traces.dropped_records",
                "Span records dropped because the per-worker spans ring was full",
                "{record}",
                traces_dropped,
                self.start_time_unix_nano,
                now,
            ),
            super::gauge_metric(
                "ngx_otel.export_interval",
                "Configured metric export interval",
                "s",
                interval_s,
                now,
            ),
            super::gauge_metric(
                "ngx_otel.exporter.restarts",
                "Prior exporter crashes in the current crash-loop window at this process start (0 = clean start; nginx request handling is never affected by the exporter crash-loop state)",
                "{crash}",
                exporter_restarts,
                now,
            ),
            super::monotonic_sum_metric(
                "ngx_otel.delivery.permanent_rejected",
                "Batches the peer rejected as permanently unacceptable \
                 (e.g. HTTP 400/413, gRPC INVALID_ARGUMENT/INTERNAL/UNIMPLEMENTED); \
                 dropped and never retried",
                "{batch}",
                permanent_rejected,
                self.start_time_unix_nano,
                now,
            ),
            super::monotonic_sum_metric(
                "ngx_otel.delivery.partial_rejected",
                "Individual records the peer reported it dropped on an otherwise-accepted batch \
                 (OTLP partial_success / gRPC partial-success body); the batch is released, \
                 only the reported rejected count is accumulated here",
                "{record}",
                partial_rejected,
                self.start_time_unix_nano,
                now,
            ),
            super::monotonic_sum_metric(
                "ngx_otel.delivery.unauthorized",
                "Batches dropped because the peer reported an authentication or authorization \
                 failure (HTTP 401/403, gRPC UNAUTHENTICATED/PERMISSION_DENIED); same drop \
                 policy as permanent_rejected (no retry, no backoff, no auto-pause) but kept \
                 in a distinct counter for observability — a non-zero value indicates a \
                 credential or permission problem on the exporter endpoint",
                "{batch}",
                unauthorized_rejected,
                self.start_time_unix_nano,
                now,
            ),
        ]
    }
}
