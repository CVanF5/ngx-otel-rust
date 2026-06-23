// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Export loop running in the `nginx: otel exporter` process.
//!
//! [`export_loop`] runs inside the **exporter process**, spawned by
//! `otel_exporter_cycle` in `src/exporter/mod.rs`. It:
//!   1. Sleeps for the configured `otel_metric_interval`.
//!   2. Collects metrics from all configured [`MetricSource`]s.
//!      (shm rings written by workers, mapped via fork-shared pages)
//!   3. Encodes via [`OtlpHttpEncoder`].
//!   4. Ships via [`HyperHttpTransport<NgxConnector>`] (production transport only;
//!      `SpinConnector` is test-only and never used here).
//!   5. On send failure: enqueues bytes in a bounded retry buffer; drops the
//!      oldest entry when the buffer is full.
//!   6. On `ngx_quit`: flushes the retry buffer and sends one final batch,
//!      then sets [`EXPORT_LOOP_DONE`] and returns cleanly.
//!   7. On `ngx_terminate`: returns immediately without any drain.
//!
//! # Config capture
//! `MainConfig` is captured at spawn time (exporter startup). On SIGHUP
//! reload nginx creates a new exporter process with a new cycle and config.
//! The new exporter spawns its own `export_loop` task.
//! `MainConfig::old_config` provides the hook for cross-cycle
//! state transfer (TLS connection reuse, etc.).
//!
//! # Graceful drain on SIGQUIT-during-sleep
//! The exporter is not a worker and is not subject to
//! `ngx_event_no_timers_left`. Cancelable timers fire normally
//! when the exporter exits on `ngx_quit`, so the chunked sleep reliably
//! detects shutdown and runs the drain (see [`graceful_drain`]). No separate
//! `exit_process` flush path on the worker side is needed.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;
use std::collections::VecDeque;

use nginx_sys::{NGX_LOG_ERR, NGX_LOG_INFO, NGX_LOG_NOTICE, NGX_LOG_WARN};
use pin_project_lite::pin_project;

use crate::config::{ExportProtocol, MainConfig};
use crate::data_model::{
    AggregationTemporality, AnyValue, Batch, GaugeData, KeyValue, LogRecord, LogsBatch, Metric,
    MetricData, NumberDataPoint, NumberValue, SumData,
};
use crate::data_model::{Pdata, Resource, Scope, Span, SpansBatch};
use crate::encoder::{OtlpHttpEncoder, OtlpLogsEncoder, OtlpTracesEncoder};
use crate::logs::coalesce;
use crate::logs::severity::nginx_to_otel;
use crate::metric_source::instrumented::InstrumentedSource;
#[cfg(ngx_feature = "stat_stub")]
use crate::metric_source::stub_status::StubStatusSource;
use crate::metric_source::tls_cert::ServingCertSource;
use crate::metric_source::MetricSource;
use crate::processor::Processor;
use crate::shm::{
    logs_access_ring, logs_coalesce_table, logs_error_ring, logs_n_workers_from_zone,
    spans_n_workers_from_zone, spans_ring, DEFAULT_SPAN_RING_CAP,
};
use crate::transport::hyper_http::{extract_http_path, NgxConnector, ParsedEndpoint};
use crate::transport::tls::{TlsConfig, COLLECTOR_CERT_NOT_AFTER};
use crate::transport::{GrpcTransport, HyperHttpTransport};

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
/// Written once by [`export_loop`] before the first export tick.  Used by
/// [`build_resource_attrs`] to populate the `service.instance.id` resource
/// attribute on **both** the metrics and logs OTLP Resource.
///
/// Key properties:
/// - **Stable across crash-respawn**: the master re-forks the exporter with the
///   same `ngx_parent`, so the id is unchanged and cumulative shm series continue.
/// - **Distinct across USR2 live binary upgrade**: the new master (different PID)
///   forks the new exporter; `ngx_parent` in the new child is the new master's PID.
/// - **Zero** = loop not yet started (pre-init, or SIGQUIT before first tick).
pub static MASTER_PID: AtomicI64 = AtomicI64::new(0);

/// Set to `true` by [`export_loop`] just before it returns after a graceful
/// drain on `ngx_quit`. The exporter cycle polls this flag in its `ngx_quit`
/// branch to know when the drain has completed and it is safe to exit.
///
/// Process-global; the exporter process is single-instance so
/// there is exactly one export_loop per process lifetime.
pub(crate) static EXPORT_LOOP_DONE: AtomicBool = AtomicBool::new(false);

/// RAII guard that stores `true` to [`EXPORT_LOOP_DONE`] on every exit path of
/// [`export_loop`], including early returns on startup failures.
///
/// Before this guard existed, early returns at the endpoint-parse and
/// transport-construction paths left `EXPORT_LOOP_DONE` unset. The drain-wait
/// loop in `otel_exporter_cycle` then blocked indefinitely inside
/// `ngx_process_events_and_timers` (no active fds or timers → epoll/kqueue
/// never returned) → `nginx -s quit` hung until manual SIGTERM.
///
/// A local `let _done_guard = ExportLoopDoneGuard;` at the top of `export_loop`
/// ensures the flag is set whenever the future resolves, regardless of which
/// `return` is taken.
struct ExportLoopDoneGuard;

impl Drop for ExportLoopDoneGuard {
    fn drop(&mut self) {
        EXPORT_LOOP_DONE.store(true, Ordering::Release);
    }
}

/// Wall-clock budget for the graceful drain on `ngx_quit`. Each send attempt
/// inside the drain is capped at this duration so a dead collector cannot
/// stall exporter shutdown.
const GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET: Duration = Duration::from_secs(2);

/// Per-attempt wall-clock budget for every *periodic* (non-drain) send —
/// fresh metrics/logs/spans batches and their retry-queue drains.
///
/// Why this is needed: periodic sends were previously awaited bare. The only
/// backstop is the transport's read timer (`DEFAULT_READ_TIMEOUT_MS` = 60 s),
/// and that only covers connect + read — a `poll_write` that returns `NGX_AGAIN`
/// against a collector whose receive window has stalled arms NO timer, so a
/// write can hang unbounded. Even within the 60 s read backstop, a single
/// export wake chains several sends (3 retry drains + up to 3 fresh sends), so
/// one wake could stall for minutes, and shutdown flags are only polled
/// *between* wakes — `nginx -s quit` would block for that whole time.
///
/// Value choice (15 s): it must be ≤ the 60 s read backstop (so it is the
/// effective cap, not a no-op) yet comfortably larger than a healthy send's
/// latency so a momentarily slow-but-live collector is not falsely treated as
/// failed (a healthy OTLP POST completes in well under a second). It is
/// deliberately *much* larger than the 250 ms `SHUTDOWN_POLL_INTERVAL` drain
/// tick and independent of `otel_metric_interval` (which gates how often a wake
/// occurs, not how long one send may take): the budget bounds a single hung
/// send, while the inter-send flag checks added in `export_loop` bound how many
/// such sends a quit can wait behind within one wake. Worst-case quit latency
/// is therefore one in-flight send's remaining budget (< 15 s), not minutes.
/// On expiry the batch takes the EXISTING transient-failure path (retry-queue
/// enqueue with eviction + failure-counter bump + ERR log) — no new semantics,
/// no wire-byte change (the in-flight future is dropped, cancelling the
/// connection via `Drop`, exactly as a transport error would unwind).
const PERIODIC_SEND_BUDGET: Duration = Duration::from_secs(15);

/// Maximum slice of the export interval that may pass between `ngx_quit`
/// polls. Chunked sleep ensures shutdown is responsive even with a long
/// configured `otel_metric_interval` — we never wait more than this between
/// shutdown checks. The cost is one extra timer wake per chunk; negligible.
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Base interval for the no-hint exponential backoff applied to a
/// `DeliveryOutcome::Retryable` that carried no peer hint. The OTLP spec
/// `SHOULD`s exponential backoff for the no-hint retryable case
/// (<https://opentelemetry.io/docs/specs/otlp/#failures-1>). The base is
/// the sub-interval drain cadence (`SHUTDOWN_POLL_INTERVAL`, 250 ms): the first
/// no-hint retryable defers one drain tick, and each consecutive retryable
/// doubles the deferral up to [`BACKOFF_CAP_MS`]. Reset to baseline on the next
/// `Accepted`. No directive surface — hardcoded per the spec.
const BACKOFF_BASE_MS: u64 = 250;

/// Ceiling for the no-hint exponential backoff (30 s). Doubling stops here
/// so a sustained-overload peer is retried at most every 30 s rather than
/// growing unbounded. A peer-supplied hint (`Retry-After`/`RetryInfo`/pushback)
/// is honored verbatim and is NOT subject to this cap.
const BACKOFF_CAP_MS: u64 = 30_000;

/// Selects between the HTTP and gRPC production transports.
///
/// Built once in [`export_loop`] from `amcf.export_protocol()` and threaded
/// through [`graceful_drain`].  A concrete enum (rather than a boxed trait
/// object) keeps `send` statically dispatched (both variants are cold-path
/// anyway — the export loop runs in a dedicated process that is not on the hot
/// request path).
///
/// # Exit-time flush note
///
/// The final flush is handled uniformly for both transports by the in-loop
/// async [`graceful_drain`], which runs while the nginx event loop is still
/// alive. There is no separate synchronous exit-time flush path: it would
/// mean building a blocking one-shot stack after the async runtime has been
/// torn down, which is fragile (and impossible for gRPC's h2). This is safe
/// because the exporter process stays alive until `EXPORT_LOOP_DONE` is set
/// (by `graceful_drain` after it completes), so `graceful_drain` always runs
/// before `process::exit`.
#[allow(clippy::large_enum_variant)]
enum ExportTransport {
    Http(HyperHttpTransport<NgxConnector>),
    Grpc(GrpcTransport<NgxConnector>),
}

impl ExportTransport {
    /// Send a batch of OTLP metrics, dispatching to the selected transport.
    async fn send(
        &mut self,
        bytes: std::vec::Vec<u8>,
    ) -> Result<crate::transport::DeliveryOutcome, crate::transport::TransportError> {
        match self {
            Self::Http(t) => t.send(bytes).await,
            Self::Grpc(t) => t.send(bytes).await,
        }
    }

    /// Send logs bytes to the OTel logs endpoint.
    ///
    /// For HTTP: POSTs to the derived logs path (`base/v1/logs` by default,
    /// or the `logs_endpoint` per-signal override if configured).
    /// For gRPC: calls `LogsService/Export`.
    ///
    /// Logs ship over the same transport selected by `otel_export_protocol`.
    async fn send_logs(
        &mut self,
        bytes: std::vec::Vec<u8>,
    ) -> Result<crate::transport::DeliveryOutcome, crate::transport::TransportError> {
        match self {
            Self::Http(t) => t.send_logs(bytes).await,
            Self::Grpc(t) => t.send_logs(bytes).await,
        }
    }

    /// Send trace bytes to the OTel traces endpoint.
    ///
    /// For HTTP: POSTs to the derived traces path (`base/v1/traces` by default,
    /// or the `traces_endpoint` per-signal override if configured).
    /// For gRPC: calls `TraceService/Export`.
    ///
    /// Traces ship over the same transport selected by `otel_export_protocol`.
    async fn send_traces(
        &mut self,
        bytes: std::vec::Vec<u8>,
    ) -> Result<crate::transport::DeliveryOutcome, crate::transport::TransportError> {
        match self {
            Self::Http(t) => t.send_traces(bytes).await,
            Self::Grpc(t) => t.send_traces(bytes).await,
        }
    }

    /// Unified send dispatch for the `Pdata` pipeline (Step U2).
    ///
    /// Routes `bytes` to the per-signal endpoint derived from the `Pdata` variant.
    /// The bytes must already be encoded (via [`encode_pdata`]) for the matching
    /// signal — the variant is used only for routing, not for re-encoding.
    async fn send_pdata(
        &mut self,
        signal: &Pdata,
        bytes: std::vec::Vec<u8>,
    ) -> Result<crate::transport::DeliveryOutcome, crate::transport::TransportError> {
        match signal {
            Pdata::Metrics(_) => self.send(bytes).await,
            Pdata::Logs(_) => self.send_logs(bytes).await,
            Pdata::Spans(_) => self.send_traces(bytes).await,
        }
    }
}

/// Why the chunked sleep terminated early, if it did.
#[derive(Copy, Clone)]
enum ShutdownKind {
    None,
    Exiting,
    Terminate,
}

/// True if the master has signalled shutdown (`ngx_quit` graceful or
/// `ngx_terminate` immediate). Checked BETWEEN consecutive periodic sends within
/// a single export wake so that a quit arriving mid-wake is honoured promptly
/// rather than waiting for every remaining (possibly deadline-bounded) send to
/// finish. Worst case a quit waits behind only the one send currently in flight.
#[inline]
fn shutdown_requested() -> bool {
    // SAFETY: `ngx_quit` / `ngx_terminate` are nginx-owned `sig_atomic_t`
    // globals, set on the master signal path and read here in the
    // single-threaded exporter process; plain reads are well-defined.
    unsafe { nginx_sys::ngx_quit != 0 || nginx_sys::ngx_terminate != 0 }
}

// ── Self-metrics source ──────────────────────────────────────────────────────

/// [`MetricSource`] that exposes the export loop's own health as OTel metrics.
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
    /// correctly. Captured once at [`export_loop`] init; see field
    /// initialisation in [`collect_all_sources`].
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
fn counter_to_i64(v: u64) -> i64 {
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
            monotonic_sum_metric(
                "ngx_otel.dropped_records",
                "Records from any signal (metrics, logs, spans) dropped because the \
                 per-signal retry buffer was full or a drain-abort discarded queued batches",
                "{record}",
                dropped,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.send_failures",
                "Cumulative export send failures since worker startup",
                "{failure}",
                failures,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.bidi_backpressure_drops",
                "Bidi outbound messages dropped due to channel backpressure",
                "{message}",
                backpressure_drops,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.logs.access.dropped_records",
                "Access log records dropped because the per-worker ring was full",
                "{record}",
                access_logs_dropped,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.logs.error.dropped_records",
                "Error log records dropped because the per-worker ring was full",
                "{record}",
                error_logs_dropped,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.logs.error.coalesced_orphaned_records",
                "Error log coalesced-count occurrences orphaned because the verbatim \
                 ring sample was dropped (ring full); a synthetic record is emitted \
                 per orphaned slot so backends still receive the occurrence count",
                "{record}",
                error_logs_coalesced_orphaned,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.logs.send_failures",
                "Cumulative logs transport send failures since exporter startup",
                "{failure}",
                logs_send_failures,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.traces.dropped_records",
                "Span records dropped because the per-worker spans ring was full",
                "{record}",
                traces_dropped,
                self.start_time_unix_nano,
                now,
            ),
            gauge_metric(
                "ngx_otel.export_interval",
                "Configured metric export interval",
                "s",
                interval_s,
                now,
            ),
            gauge_metric(
                "ngx_otel.exporter.restarts",
                "Prior exporter crashes in the current crash-loop window at this process start (0 = clean start; nginx request handling is never affected by the exporter crash-loop state)",
                "{crash}",
                exporter_restarts,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.delivery.permanent_rejected",
                "Batches the peer rejected as permanently unacceptable \
                 (e.g. HTTP 400/413, gRPC INVALID_ARGUMENT/INTERNAL/UNIMPLEMENTED); \
                 dropped and never retried",
                "{batch}",
                permanent_rejected,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.delivery.partial_rejected",
                "Individual records the peer reported it dropped on an otherwise-accepted batch \
                 (OTLP partial_success / gRPC partial-success body); the batch is released, \
                 only the reported rejected count is accumulated here",
                "{record}",
                partial_rejected,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
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

// ── Main export loop ─────────────────────────────────────────────────────────

/// Async export loop — spawned by `otel_exporter_cycle` inside the exporter process.
///
/// Runs in the `nginx: otel exporter` process, not a worker.
/// The shm rings (written by worker bumps) are read across the fork boundary
/// via the same mapped pages — fork-shared memory is coherent for atomic reads.
///
/// Takes `&'static MainConfig` because the loop task outlives the spawn call;
/// NGINX allocates MainConfig from the cycle pool which has exporter lifetime.
///
/// Decide which per-signal endpoint directives are silently ignored under
/// gRPC transport (path routing is not applicable to gRPC). Returns the signal
/// names (in metrics/logs/traces order) whose endpoint field is non-empty — the
/// caller logs one WARN per returned name. Extracted so the predicate is unit-
/// testable without a live exporter loop (the production `export_loop` calls this
/// exact function; see `grpc_ignored_endpoint_names_predicate`).
fn grpc_ignored_endpoint_names(
    metrics: &nginx_sys::ngx_str_t,
    logs: &nginx_sys::ngx_str_t,
    traces: &nginx_sys::ngx_str_t,
) -> std::vec::Vec<&'static str> {
    let mut names = std::vec::Vec::new();
    if !metrics.is_empty() {
        names.push("metrics");
    }
    if !logs.is_empty() {
        names.push("logs");
    }
    if !traces.is_empty() {
        names.push("traces");
    }
    names
}

/// When `ngx_quit` is detected, runs [`graceful_drain`], sets
/// [`EXPORT_LOOP_DONE`], and returns. The exporter cycle polls
/// `EXPORT_LOOP_DONE` before calling `process::exit`.
pub async fn export_loop(amcf: &'static MainConfig) {
    let log = ngx::log::ngx_cycle_log();

    // RAII guard — ensures EXPORT_LOOP_DONE is set on every exit path of
    // this function (early return, normal return). Earlier, early returns at
    // the endpoint-parse and transport-construction paths left the flag unset,
    // so the drain-wait in otel_exporter_cycle blocked indefinitely.
    let _done_guard = ExportLoopDoneGuard;

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

    // ── Collector host for the collector-cert gauge attribute ────────────
    // Parsed once at startup; stable per exporter generation.  Plaintext
    // endpoints parse to a host string too — the gauge is gated on the
    // COLLECTOR_CERT_NOT_AFTER atomic (which is only written by TLS
    // handshakes), so no metric appears for plaintext even if the host is set.
    let collector_host: std::string::String = ParsedEndpoint::parse(endpoint_str)
        .map(|ep| std::string::String::from(ep.host_str()))
        .unwrap_or_default();

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

    // ── Build TLS config (https:// endpoints only) ───────────────────────────
    //
    // TLS config is constructed here, in the exporter process, from the
    // ExporterConfig directives set by the master process at config time.
    // Workers never reach this path.
    let is_https = endpoint_str.starts_with("https://");
    let tls_ctx_opt: Option<(crate::transport::tls::SslCtx, bool)> = if is_https {
        let trusted_cert = core::str::from_utf8(amcf.exporter.trusted_cert.as_bytes())
            .ok()
            .filter(|s| !s.is_empty())
            .map(std::string::String::from);
        let client_cert = core::str::from_utf8(amcf.exporter.ssl_cert.as_bytes())
            .ok()
            .filter(|s| !s.is_empty())
            .map(std::string::String::from);
        let client_key = core::str::from_utf8(amcf.exporter.ssl_cert_key.as_bytes())
            .ok()
            .filter(|s| !s.is_empty())
            .map(std::string::String::from);
        let insecure = amcf.exporter.ssl_verify_off();
        let tls_cfg = TlsConfig { ca_file: trusted_cert, client_cert, client_key, insecure };
        let log_ptr = log.as_ptr();
        match tls_cfg.build_ctx(|msg| {
            ngx::ngx_log_error!(NGX_LOG_WARN, log_ptr, "otel export: {}", msg);
        }) {
            Ok(ctx) => Some((ctx, insecure)),
            Err(e) => {
                ngx::ngx_log_error!(
                    NGX_LOG_ERR,
                    log.as_ptr(),
                    "otel export: failed to build TLS context: {}",
                    e
                );
                return;
            }
        }
    } else {
        None
    };

    // ── Construct production transport (NgxConnector; NEVER SpinConnector) ─
    //
    // Transport selected by `otel_export_protocol` (default: otlp_http).
    // For gRPC the connection is lazy (deferred to first send).
    let mut transport = match amcf.export_protocol() {
        ExportProtocol::OtlpHttp => {
            match HyperHttpTransport::<NgxConnector>::with_ngx_log(
                endpoint_str,
                headers,
                log,
                amcf.resolver,
                amcf.resolver_timeout,
            ) {
                Ok(mut t) => {
                    // Wire TLS context for https:// endpoints.
                    if let Some((ctx, insecure)) = tls_ctx_opt {
                        t.set_tls(ctx, insecure);
                    }
                    ExportTransport::Http(t)
                }
                Err(e) => {
                    ngx::ngx_log_error!(
                        NGX_LOG_ERR,
                        log.as_ptr(),
                        "otel export: failed to create HTTP transport: {}",
                        e
                    );
                    return;
                }
            }
        }
        ExportProtocol::OtlpGrpc => {
            // gRPC over https:// wraps each h2 connection in TLS (ALPN h2) via
            // the same TlsNgxConnIo engine as the HTTP transport — the decision
            // of record (ONE TLS engine, both transports). Plaintext http://
            // endpoints leave `tls` unset → h2c, unchanged.
            match GrpcTransport::<NgxConnector>::with_ngx_log(
                endpoint_str,
                log,
                amcf.resolver,
                amcf.resolver_timeout,
            ) {
                Ok(mut t) => {
                    if let Some((ctx, insecure)) = tls_ctx_opt {
                        t.set_tls(ctx, insecure);
                    }
                    ExportTransport::Grpc(t)
                }
                Err(e) => {
                    ngx::ngx_log_error!(
                        NGX_LOG_ERR,
                        log.as_ptr(),
                        "otel export: failed to create gRPC transport: {}",
                        e
                    );
                    return;
                }
            }
        }
    };

    // ── Apply per-signal endpoint overrides (HTTP transport only) ────────────
    //
    // If `metrics_endpoint`, `logs_endpoint`, or `traces_endpoint` is set in
    // the `otel_exporter {}` block, use it as-is (no path appended) instead of
    // the base-derived path.  Accepts full URLs (`http://host:port/path`) or
    // bare paths (`/v1/metrics`); `extract_http_path` normalises to the path
    // component.  gRPC is unaffected (path routing is not applicable to gRPC).
    //
    // Under gRPC transport the per-signal endpoint directives are silently
    // ignored.  Warn once at exporter startup so the operator knows the config
    // has no effect.
    if let ExportTransport::Grpc(_) = transport {
        for name in grpc_ignored_endpoint_names(
            &amcf.exporter.metrics_endpoint,
            &amcf.exporter.logs_endpoint,
            &amcf.exporter.traces_endpoint,
        ) {
            ngx::ngx_log_error!(
                NGX_LOG_WARN,
                log.as_ptr(),
                "otel export: {}_endpoint ignored under grpc transport \
                 (path routing is not applicable)",
                name
            );
        }
    }
    if let ExportTransport::Http(ref mut t) = transport {
        let me = &amcf.exporter.metrics_endpoint;
        if !me.is_empty() {
            if let Ok(s) = core::str::from_utf8(me.as_bytes()) {
                t.set_metrics_path(extract_http_path(s));
            }
        }
        let le = &amcf.exporter.logs_endpoint;
        if !le.is_empty() {
            if let Ok(s) = core::str::from_utf8(le.as_bytes()) {
                t.set_logs_path(extract_http_path(s));
            }
        }
        let te = &amcf.exporter.traces_endpoint;
        if !te.is_empty() {
            if let Ok(s) = core::str::from_utf8(te.as_bytes()) {
                t.set_traces_path(extract_http_path(s));
            }
        }
    }

    // Capture worker start time once — used as the start_time_unix_nano
    // for cumulative monotonic Sum self-metrics so that downstream rate
    // panels and delta-conversion processors can anchor windows correctly.
    let worker_start_ns = crate::util::now_unix_nano();

    // Snapshot successor_gen at startup.  On QUIT, graceful_drain
    // compares current_gen against my_gen to decide between:
    //   current_gen > my_gen → reload → abdicate ring pops (new exporter owns)
    //   current_gen == my_gen → shutdown → full drain (we are sole consumer)
    // SAFETY: control_shm_ptr() returns Some only when the zone is registered
    // and mapped; loading successor_gen is a single Acquire atomic load.
    let my_gen: u64 = amcf
        .control_shm_ptr()
        .map(|p| unsafe { (*p).successor_gen.load(core::sync::atomic::Ordering::Acquire) })
        .unwrap_or(0);

    // One-way abdication latch for the periodic ring-pop path.
    // Set to `true` the first time `successor_announced()` returns true;
    // never reset.  Once abdicated the periodic drain skips log/span ring
    // pops for the remainder of this exporter's lifetime, leaving the rings
    // exclusively to the new (successor) exporter.
    // Cumulative-metrics READ snapshots are NOT gated — they are pure loads,
    // safe across the overlap window (cumulative counters dedup by timestamp).
    let mut periodic_abdicated = false;

    // test-support: QUIT-DEFER hook ──────────────────────────────────────────
    // NGX_OTEL_QUIT_DEFER_TICKS delays ngx_quit processing for N × 250 ms
    // periodic ticks, keeping the old exporter's ring drains alive during the
    // overlap window with a newly-started successor exporter.  Used by
    // mutation-evidence runs to create a deterministic SPSC race window:
    //   fixed code  + defer → abdicates within one tick (successor_announced
    //               returns true) → chaos PASSES
    //   mutated code + defer → both exporters drain the same rings for N ticks
    //               → duplicates / conservation FAIL
    // This variable is only compiled when the "test-support" feature is
    // enabled — zero production code change.
    #[cfg(feature = "test-support")]
    let mut quit_defer_ticks: u32 =
        std::env::var("NGX_OTEL_QUIT_DEFER_TICKS").ok().and_then(|s| s.parse().ok()).unwrap_or(0);

    // Capture the master (parent) PID once at export loop startup.
    // nginx_sys::ngx_parent is set by ngx_spawn_process to the master's PID
    // before fork, so in the exporter child it always equals the master PID.
    // Stable across crash-respawn (same master re-forks with same ngx_parent).
    // Distinct across USR2 (new master forks with its own PID as ngx_parent).
    // Safety: ngx_parent is a mutable static written by nginx before fork
    // and never changed afterwards; reading it here is safe in a single process.
    let master_pid = unsafe { nginx_sys::ngx_parent } as i64;
    MASTER_PID.store(master_pid, Ordering::Relaxed);

    // Crash-loop healthy-reset tracking: after running successfully for a full
    // CRASH_WINDOW_SECS window the crash counter in shm is zeroed. This prevents
    // a single crash after a long healthy run from being counted against old
    // in-window crashes that happened during a previous short-lived startup.
    // `healthy_since` is set to `worker_start_ns` on the first successful export
    // tick (i.e. when `ngx_quit` / `ngx_terminate` were NOT set). The reset
    // fires once and is idempotent (`crash_counter_reset` flag).
    let healthy_since_ns = worker_start_ns;
    let mut crash_counter_reset = false;

    // Retry buffer: (encoded bytes, number of data points in that batch).
    // Depth is configured (see `MainConfig::retry_buffer_depth`) so that
    // tuning later is a config change, not a code change.
    let retry_buffer_depth = amcf.retry_buffer_depth();
    let mut retry_queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();

    // Separate retry queue for log batches so that failed log sends don't
    // evict metric batches (and vice versa).
    let mut logs_retry_queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();

    // Separate retry queue for span batches.
    let mut spans_retry_queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();

    // Per-signal backoff/defer state for the outcome-driven policy engine.
    // Each lane carries a "not before" monotonic timestamp + a consecutive-
    // `Retryable`-failure counter (reset on `Accepted`). These are exporter-task
    // locals — never shared across threads. A `Retryable` verdict defers the
    // NEXT DRAIN of that signal (it does NOT grow the bounded buffer); the
    // defer gate is checked before each lane's drain/fresh-send below.
    let mut metrics_backoff = SignalBackoff::default();
    let mut logs_backoff = SignalBackoff::default();
    let mut spans_backoff = SignalBackoff::default();

    // Processor stage: drain → [process] → encode → send.  Constructed once at
    // exporter startup from a JSON config blob.  Currently always empty (→ Noop
    // passthrough); wired to operator directives in a follow-on phase.
    // The `from_config` API is designed for future bidi-driven remote
    // reconfiguration (control-shm + bidi channel) — a staged follow-on.
    let processor = Processor::from_config(&serde_json::Value::Object(Default::default()));

    let protocol_str = match amcf.export_protocol() {
        ExportProtocol::OtlpHttp => "otlp_http",
        ExportProtocol::OtlpGrpc => "otlp_grpc",
    };
    ngx::ngx_log_error!(
        NGX_LOG_NOTICE,
        log.as_ptr(),
        "otel export: export loop started, endpoint={}, protocol={}, interval={}ms, retry_depth={}",
        endpoint_str,
        protocol_str,
        amcf.interval_ms(),
        retry_buffer_depth
    );

    // In a no-flag build (nginx without --with-http_stub_status_module,
    // so `NGX_STAT_STUB` undefined → no `ngx_feature = "stat_stub"`) the stub_status
    // MetricSource is not registered in `collect_all_sources`. Emit a single
    // degraded-feature notice naming the missing flag and the affected series so the
    // operator understands why `nginx.connections.*` / `nginx.requests.total` are
    // absent. WARN (not ERR): the module otherwise works; this is a degraded feature,
    // not a failure. One-shot at startup, matching the lifecycle-line convention.
    #[cfg(not(ngx_feature = "stat_stub"))]
    ngx::ngx_log_error!(
        NGX_LOG_WARN,
        log.as_ptr(),
        "otel export: stub_status metrics disabled: nginx built without \
         --with-http_stub_status_module; nginx.connections.* and \
         nginx.requests.total will not be exported"
    );

    loop {
        // ── Check for immediate SIGTERM ────────────────────────────────────
        // SAFETY: `ngx_terminate` is a `sig_atomic_t` global owned by nginx,
        // written only by the master/signal-delivery path and read here in the
        // single-threaded exporter process; a plain read of it is well-defined.
        if unsafe { nginx_sys::ngx_terminate } != 0 {
            ngx::ngx_log_error!(
                NGX_LOG_NOTICE,
                log.as_ptr(),
                "otel export: ngx_terminate set, exiting without drain"
            );
            return;
        }

        // ── Check for graceful SIGQUIT ────────────────────────────────────
        // Poll ngx_quit (not ngx_exiting). The exporter is not a
        // worker; master signals it to quit via ngx_quit on the channel handler
        // path (SIGQUIT → master → NGX_CMD_QUIT → ngx_quit). ngx_exiting is a
        // worker-specific flag set by the worker's SIGQUIT handler.
        // SAFETY: `ngx_quit` is a `sig_atomic_t` global owned by nginx, set via
        // the master's NGX_CMD_QUIT channel handler and read here in the
        // single-threaded exporter process; a plain read of it is well-defined.
        if unsafe { nginx_sys::ngx_quit } != 0 {
            // test-support: QUIT-DEFER — if ticks remain, fall through to the
            // inner sleep loop so periodic ring drains keep running during the
            // overlap window.  Compiled away in production builds.
            let should_drain_now: bool = {
                #[cfg(feature = "test-support")]
                {
                    quit_defer_ticks == 0
                }
                #[cfg(not(feature = "test-support"))]
                {
                    true
                }
            };
            if should_drain_now {
                ngx::ngx_log_error!(
                    NGX_LOG_NOTICE,
                    log.as_ptr(),
                    "otel export: ngx_quit set, starting graceful drain"
                );
                graceful_drain(
                    &mut transport,
                    &mut DrainQueues {
                        metrics: &mut retry_queue,
                        logs: &mut logs_retry_queue,
                        spans: &mut spans_retry_queue,
                    },
                    amcf,
                    worker_start_ns,
                    &processor,
                    my_gen,
                    &collector_host,
                )
                .await;
                EXPORT_LOOP_DONE.store(true, Ordering::Release);
                return;
            }
            // else (test-support with ticks > 0): fall through to inner loop
        }

        // ── Chunked sleep for the configured export interval ──────────────────
        // We must check ngx_quit at least every SHUTDOWN_POLL_INTERVAL so that
        // SIGQUIT during a long sleep doesn't delay the drain significantly.
        // Unlike workers, the exporter is not subject to
        // ngx_event_no_timers_left, so cancelable timers fire reliably on quit.
        //
        // Logs are drained on EVERY sub-interval wake (SHUTDOWN_POLL_INTERVAL,
        // default 250 ms), decoupled from the metric aggregation interval; metrics
        // aggregate and export only at the full otel_metric_interval boundary.
        // Rationale: the original motive was draining a
        // per-request log firehose before the ring saturated under high RPS. The
        // summary+samples redesign collapsed that volume (the ring now carries only the
        // thin exception tail + coalesced error samples), so the fast cadence now exists
        // for: (a) timeliness — ship the high-value tail/error records promptly instead
        // of holding them up to a full (possibly long) metric interval; (b) incident-burst
        // resilience — a spike of 5xx-tail / novel / high-severity records is exactly when
        // the bounded ring could fill and drop; (c) it protects the
        // `otel_error_log_coalesce off` verbatim opt-out. Near-free: it piggybacks the
        // shutdown poll the loop already wakes on, and an empty ring sends nothing.
        let interval = Duration::from_millis(amcf.interval_ms());
        let mut slept = Duration::ZERO;
        let mut shutdown_during_sleep = ShutdownKind::None;
        while slept < interval {
            let chunk = (interval - slept).min(SHUTDOWN_POLL_INTERVAL);
            ngx::async_::sleep(chunk).await;
            slept += chunk;
            // SAFETY: `ngx_terminate` is a nginx-owned `sig_atomic_t` global;
            // read here in the single-threaded exporter process, the read is
            // well-defined.
            if unsafe { nginx_sys::ngx_terminate } != 0 {
                shutdown_during_sleep = ShutdownKind::Terminate;
                break;
            }
            // SAFETY: `ngx_quit` is a nginx-owned `sig_atomic_t` global; read
            // here in the single-threaded exporter process, the read is
            // well-defined.
            if unsafe { nginx_sys::ngx_quit } != 0 {
                // test-support: QUIT-DEFER — consume one tick; the periodic
                // drain code below the check still runs this sub-interval.
                // When ticks reach zero we fall through to the normal exit.
                #[cfg(feature = "test-support")]
                if quit_defer_ticks > 0 {
                    quit_defer_ticks -= 1;
                    // Do NOT break — let periodic drain fire this tick.
                } else {
                    shutdown_during_sleep = ShutdownKind::Exiting;
                    break;
                }
                #[cfg(not(feature = "test-support"))]
                {
                    shutdown_during_sleep = ShutdownKind::Exiting;
                    break;
                }
            }

            // Whether a QUIT-DEFER overlap window is currently active.
            // When active (test-support only), shutdown is being deliberately
            // deferred to keep ring drains alive during a successor overlap, so
            // the inter-send shutdown short-circuits below must NOT fire — they
            // would skip exactly the drains the defer window exists to run.
            // Always false in production builds (no defer mechanism compiled in).
            let defer_active: bool = {
                #[cfg(feature = "test-support")]
                {
                    quit_defer_ticks > 0
                }
                #[cfg(not(feature = "test-support"))]
                {
                    false
                }
            };

            // Check for successor before periodic ring pops.
            // One Acquire load of successor_gen; sets the latch permanently on first
            // abdication.  The load is on the cold path (occurs only once per drain tick;
            // the latch short-circuits immediately after the first true result).
            if !periodic_abdicated && successor_announced(amcf, my_gen) {
                periodic_abdicated = true;
                ngx::ngx_log_error!(
                    NGX_LOG_NOTICE,
                    log.as_ptr(),
                    "otel export: successor announced — abdicating periodic ring pops \
                     (my_gen={})",
                    my_gen
                );
            }

            // Monotonic basis for the per-signal backoff defer checks this
            // tick (one read; reused across all lanes). Reuses nginx's cached
            // CLOCK_MONOTONIC (`ngx_current_msec`) — no new clock.
            let now_msec = now_monotonic_msec();

            // ── Log drain: every sub-interval wake ──────────────────────────
            // Skip the entire logs lane (retry drain AND fresh send) while a
            // `Retryable` backoff defers it. Deferring the DRAIN — not growing
            // the buffer — is how a peer backoff hint / exponential backoff is
            // honored. Other signals are unaffected.
            let logs_deferred = logs_backoff.is_deferred(now_msec);
            if !logs_deferred {
                // Drain the logs retry queue first (best-effort; stop on failure).
                drain_retry_queue_once(
                    &mut logs_retry_queue,
                    retry_buffer_depth,
                    log.as_ptr(),
                    &LOGS_SEND_FAILURES,
                    "logs",
                    &mut LogsRetry(&mut transport),
                    &mut logs_backoff,
                )
                .await;
            }

            // Inter-send shutdown check — a quit/terminate that arrived
            // while the logs-retry drain above was in flight is honoured now,
            // before chaining further (deadline-bounded) sends in this same tick.
            // Break out of the chunked sleep so the post-loop shutdown handling
            // (graceful drain on quit, immediate return on terminate) runs.
            if shutdown_requested() && !defer_active {
                // SAFETY: nginx-owned `sig_atomic_t` global, read in the
                // single-threaded exporter process — a plain read is well-defined.
                shutdown_during_sleep = if unsafe { nginx_sys::ngx_terminate } != 0 {
                    ShutdownKind::Terminate
                } else {
                    ShutdownKind::Exiting
                };
                break;
            }

            // Drain fresh log records from all workers' rings and ship them.
            // Skipped on abdication — new exporter is sole consumer.
            // Gate on log export OR error_log — either enables the logs shm path.
            if !periodic_abdicated
                && !logs_deferred
                && (amcf.any_log_export_enabled() || amcf.error_log_enabled)
            {
                if let Some(logs_base) = amcf.logs_shm_base() {
                    // SAFETY: `logs_shm_base()` returned `Some`, so the logs zone
                    // was registered and mapped; `amcf.logs_shm_zone` therefore
                    // points to a live `ngx_shm_zone_t` valid for the exporter's
                    // lifetime (cycle-pool allocated). The `&*` borrow does not
                    // escape this block, and `shm.size` is a plain field read.
                    // Use n_active_workers to drain only active slots; the
                    // zone may be reserved for more (ncpu-headroom) but inactive
                    // slots are OS-zeroed pages — scanning them faults RAM in.
                    let n_workers = {
                        use core::sync::atomic::Ordering;
                        let n = amcf.n_active_workers.load(Ordering::Relaxed);
                        if n > 0 {
                            n
                        } else {
                            // Fallback for callers that did not go through check_zone_sizing.
                            // SAFETY: amcf.logs_shm_zone is non-null when logs_shm_base()
                            // returned Some above; `&*` and `shm.size` read do not escape.
                            unsafe {
                                let zone = &*amcf.logs_shm_zone;
                                let avail = zone.shm.size.saturating_sub(crate::shm::data_offset());
                                logs_n_workers_from_zone(avail, amcf.log_ring_cap())
                            }
                        }
                    };
                    // Pdata pipeline: wrap → process → encode → send (Step U2).
                    let mut logs_pd = Pdata::Logs(collect_log_records(
                        amcf,
                        logs_base,
                        n_workers,
                        worker_start_ns,
                    ));
                    processor.process(&mut logs_pd);
                    let n_logs = count_pdata_records(&logs_pd);
                    if n_logs > 0 {
                        let logs_bytes = encode_pdata(&logs_pd);
                        // Cap at PERIODIC_SEND_BUDGET; deadline expiry is a
                        // transient failure taking the identical enqueue/counter/ERR path.
                        match with_deadline(
                            transport.send_pdata(&logs_pd, logs_bytes.clone()),
                            PERIODIC_SEND_BUDGET,
                        )
                        .await
                        {
                            // Outcome-driven policy (release / requeue+defer / drop).
                            Ok(Ok(ref outcome)) => {
                                // Re-read the monotonic clock here, AFTER the
                                // logs retry-drain and fresh-send awaits (each
                                // capped at PERIODIC_SEND_BUDGET). A `Retryable`
                                // verdict sets `not_before_msec = basis +
                                // defer_ms`; with a stale (pre-send) basis the
                                // deadline can already be in the past once
                                // `defer_ms` is capped at `BACKOFF_CAP_MS`, so
                                // `is_deferred` would return false and the
                                // exporter would hammer a failing collector at
                                // full cadence. `is_deferred` at the top of the
                                // loop intentionally keeps the pre-send capture
                                // (it gates entry for THIS iteration).
                                // `apply_logs_fresh_send_outcome` re-reads the
                                // clock internally (post-send); the call site
                                // cannot accidentally supply a stale basis.
                                if apply_logs_fresh_send_outcome(
                                    outcome,
                                    &mut logs_backoff,
                                    &mut logs_retry_queue,
                                    logs_bytes,
                                    n_logs,
                                    retry_buffer_depth,
                                    &LOGS_SEND_FAILURES,
                                    log.as_ptr(),
                                ) == OutcomeAction::Release
                                {
                                    ngx::ngx_log_error!(
                                        NGX_LOG_INFO,
                                        log.as_ptr(),
                                        "otel export: sent {} log records to collector",
                                        n_logs
                                    );
                                }
                            }
                            Ok(Err(ref e)) => {
                                ngx::ngx_log_error!(
                                    NGX_LOG_ERR,
                                    log.as_ptr(),
                                    "otel export: logs send failed ({}); queuing for retry",
                                    e
                                );
                                enqueue_with_eviction(
                                    &mut logs_retry_queue,
                                    logs_bytes,
                                    n_logs,
                                    retry_buffer_depth,
                                    log.as_ptr(),
                                );
                                LOGS_SEND_FAILURES.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(DeadlineExceeded) => {
                                ngx::ngx_log_error!(
                                    NGX_LOG_ERR,
                                    log.as_ptr(),
                                    "otel export: logs send timed out after {:?}; queuing for retry",
                                    PERIODIC_SEND_BUDGET
                                );
                                enqueue_with_eviction(
                                    &mut logs_retry_queue,
                                    logs_bytes,
                                    n_logs,
                                    retry_buffer_depth,
                                    log.as_ptr(),
                                );
                                LOGS_SEND_FAILURES.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }

            // Inter-send shutdown check before the span lane (see logs lane).
            if shutdown_requested() && !defer_active {
                // SAFETY: nginx-owned `sig_atomic_t` global; single-threaded read.
                shutdown_during_sleep = if unsafe { nginx_sys::ngx_terminate } != 0 {
                    ShutdownKind::Terminate
                } else {
                    ShutdownKind::Exiting
                };
                break;
            }

            // ── Span drain: every sub-interval wake ─────────────────────────
            // Skip the entire spans lane while a `Retryable` backoff defers
            // it (deferring the DRAIN, not growing the buffer). Independent of
            // the other lanes.
            let spans_deferred = spans_backoff.is_deferred(now_msec);
            if !spans_deferred {
                // Drain the spans retry queue first (best-effort; stop on failure).
                drain_retry_queue_once(
                    &mut spans_retry_queue,
                    retry_buffer_depth,
                    log.as_ptr(),
                    &TRACES_SEND_FAILURES,
                    "spans",
                    &mut SpansRetry(&mut transport),
                    &mut spans_backoff,
                )
                .await;
            }

            // Inter-send shutdown check before the fresh-span send.
            if shutdown_requested() && !defer_active {
                // SAFETY: nginx-owned `sig_atomic_t` global; single-threaded read.
                shutdown_during_sleep = if unsafe { nginx_sys::ngx_terminate } != 0 {
                    ShutdownKind::Terminate
                } else {
                    ShutdownKind::Exiting
                };
                break;
            }

            // Drain fresh span records from all workers' rings and ship them.
            // Skipped on abdication — new exporter is sole consumer.
            if !periodic_abdicated && !spans_deferred {
                if let Some(spans_base) = amcf.spans_shm_base() {
                    // SAFETY: `spans_shm_base()` returned `Some`, so the spans zone
                    // was registered and mapped; `amcf.spans_shm_zone` therefore
                    // points to a live `ngx_shm_zone_t` valid for the exporter's
                    // lifetime. The `&*` borrow does not escape this block, and
                    // `shm.size` is a plain field read.
                    // Use n_active_workers (same rationale as logs above).
                    let n_workers = {
                        use core::sync::atomic::Ordering;
                        let n = amcf.n_active_workers.load(Ordering::Relaxed);
                        if n > 0 {
                            n
                        } else {
                            // SAFETY: amcf.spans_shm_zone is non-null when spans_shm_base()
                            // returned Some above; `&*` and `shm.size` read do not escape.
                            unsafe {
                                let zone = &*amcf.spans_shm_zone;
                                let avail = zone.shm.size.saturating_sub(crate::shm::data_offset());
                                spans_n_workers_from_zone(avail, DEFAULT_SPAN_RING_CAP)
                            }
                        }
                    };
                    // Pdata pipeline: wrap → process → encode → send (Step U2).
                    let mut spans_pd =
                        Pdata::Spans(collect_span_records(amcf, spans_base, n_workers));
                    processor.process(&mut spans_pd);
                    let n_spans = count_pdata_records(&spans_pd);
                    if n_spans > 0 {
                        let spans_bytes = encode_pdata(&spans_pd);
                        // Cap at PERIODIC_SEND_BUDGET; deadline expiry is a
                        // transient failure taking the identical enqueue/counter/ERR path.
                        match with_deadline(
                            transport.send_pdata(&spans_pd, spans_bytes.clone()),
                            PERIODIC_SEND_BUDGET,
                        )
                        .await
                        {
                            // Outcome-driven policy (release / requeue+defer / drop).
                            Ok(Ok(ref outcome)) => {
                                // Re-read the monotonic clock here, AFTER the
                                // spans retry-drain and fresh-send awaits (each
                                // capped at PERIODIC_SEND_BUDGET). A `Retryable`
                                // verdict sets `not_before_msec = basis +
                                // defer_ms`; with a stale (pre-send) basis the
                                // deadline can already be in the past once
                                // `defer_ms` is capped at `BACKOFF_CAP_MS`, so
                                // `is_deferred` would return false and the
                                // exporter would hammer a failing collector at
                                // full cadence. `is_deferred` at the top of the
                                // loop intentionally keeps the pre-send capture
                                // (it gates entry for THIS iteration).
                                // `apply_spans_fresh_send_outcome` re-reads the
                                // clock internally (post-send); the call site
                                // cannot accidentally supply a stale basis.
                                if apply_spans_fresh_send_outcome(
                                    outcome,
                                    &mut spans_backoff,
                                    &mut spans_retry_queue,
                                    spans_bytes,
                                    n_spans,
                                    retry_buffer_depth,
                                    &TRACES_SEND_FAILURES,
                                    log.as_ptr(),
                                ) == OutcomeAction::Release
                                {
                                    ngx::ngx_log_error!(
                                        NGX_LOG_INFO,
                                        log.as_ptr(),
                                        "otel export: sent {} span records to collector",
                                        n_spans
                                    );
                                }
                            }
                            Ok(Err(ref e)) => {
                                ngx::ngx_log_error!(
                                    NGX_LOG_ERR,
                                    log.as_ptr(),
                                    "otel export: spans send failed ({}); queuing for retry",
                                    e
                                );
                                enqueue_with_eviction(
                                    &mut spans_retry_queue,
                                    spans_bytes,
                                    n_spans,
                                    retry_buffer_depth,
                                    log.as_ptr(),
                                );
                                TRACES_SEND_FAILURES.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(DeadlineExceeded) => {
                                ngx::ngx_log_error!(
                                    NGX_LOG_ERR,
                                    log.as_ptr(),
                                    "otel export: spans send timed out after {:?}; queuing for retry",
                                    PERIODIC_SEND_BUDGET
                                );
                                enqueue_with_eviction(
                                    &mut spans_retry_queue,
                                    spans_bytes,
                                    n_spans,
                                    retry_buffer_depth,
                                    log.as_ptr(),
                                );
                                TRACES_SEND_FAILURES.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        }

        // ── Re-check shutdown flags after sleep ───────────────────────────
        if matches!(shutdown_during_sleep, ShutdownKind::Terminate)
            // SAFETY: nginx-owned `sig_atomic_t` global, read in the
            // single-threaded exporter process — a plain read is well-defined.
            || unsafe { nginx_sys::ngx_terminate } != 0
        {
            return;
        }
        if matches!(shutdown_during_sleep, ShutdownKind::Exiting)
            // SAFETY: nginx-owned `sig_atomic_t` global, read in the
            // single-threaded exporter process — a plain read is well-defined.
            || unsafe { nginx_sys::ngx_quit } != 0
        {
            // test-support: QUIT-DEFER — if the inner loop exhausted the
            // full sleep interval (slept >= interval, no break) while quit
            // was set and ticks were still being consumed, we need to
            // continue the outer loop for another round of periodic drains.
            #[cfg(feature = "test-support")]
            if quit_defer_ticks > 0 {
                // shutdown_during_sleep is re-declared at the top of each
                // outer loop iteration, so no reset needed — just continue.
                continue; // outer loop: back to top
            }
            ngx::ngx_log_error!(
                NGX_LOG_NOTICE,
                log.as_ptr(),
                "otel export: ngx_quit set during sleep, starting graceful drain"
            );
            graceful_drain(
                &mut transport,
                &mut DrainQueues {
                    metrics: &mut retry_queue,
                    logs: &mut logs_retry_queue,
                    spans: &mut spans_retry_queue,
                },
                amcf,
                worker_start_ns,
                &processor,
                my_gen,
                &collector_host,
            )
            .await;
            EXPORT_LOOP_DONE.store(true, Ordering::Release);
            return;
        }

        // ── Control-shm heartbeat ───────────────────────────────────────────
        // Bump version once per drain cycle as a liveness heartbeat.
        // A future reconfig path will reuse this increment after applying a
        // reconfig to signal delivery convergence to the collector.
        // TODO: also write reconfig payload from the control channel
        // into control_shm.flags before/after this bump.
        if let Some(ctrl) = amcf.control_shm_ptr() {
            // SAFETY: `control_shm_ptr()` returned `Some`, so `ctrl` points to a
            // live control-shm header in the mapped zone (valid for the
            // exporter's lifetime). `version` is an `AtomicU64`, so the
            // cross-process `fetch_add` is well-defined.
            unsafe { (*ctrl).version.fetch_add(1, Ordering::Relaxed) };
        }

        // ── Crash-loop healthy-reset ──────────────────────────────────────────
        // Once the export loop has run for a full CRASH_WINDOW_SECS without
        // crashing, clear the crash counter in shm.  This ensures a single crash
        // after a long healthy run is not counted against stale in-window crashes,
        // and prevents a legitimate SIGHUP-triggered exporter from being penalised
        // for crashes that happened much earlier in a previous short session.
        // The reset fires at most once per process lifetime (idempotent flag).
        if !crash_counter_reset {
            let elapsed_ns = crate::util::now_unix_nano().saturating_sub(healthy_since_ns);
            // CRASH_WINDOW_SECS from exporter/mod.rs converted to nanoseconds.
            const CRASH_WINDOW_NS: u64 = crate::exporter::CRASH_WINDOW_SECS * 1_000_000_000;
            if elapsed_ns >= CRASH_WINDOW_NS {
                if let Some(ctrl_ptr) = amcf.control_shm_ptr_mut() {
                    // SAFETY: `control_shm_ptr_mut()` returned a valid, non-null
                    // pointer to the live control-shm zone (mapped before fork,
                    // valid for the exporter's lifetime). `crash_count` and
                    // `window_start_unix` are `AtomicU64`; the stores are safe.
                    let ctrl = unsafe { &*ctrl_ptr };
                    ctrl.crash_count.store(0, Ordering::Relaxed);
                    ctrl.window_start_unix.store(0, Ordering::Relaxed);
                }
                crash_counter_reset = true;
                ngx::ngx_log_error!(
                    NGX_LOG_INFO,
                    log.as_ptr(),
                    "otel export: exporter healthy for {}s — crash counter reset",
                    crate::exporter::CRASH_WINDOW_SECS,
                );
            }
        }

        // ── Drain retry queue before collecting fresh data ────────────────
        // Stop draining as soon as a send fails — transport may still be down.
        // Note: the per-retry-success INFO log ("queued batch sent successfully")
        // previously emitted only by this lane is intentionally omitted in the
        // shared helper — it was operational noise absent from the logs/spans lanes.
        // Skip the entire metrics lane (retry drain AND fresh send) when
        // `otel_metrics off` is configured — no shm zone was registered so
        // there is nothing to drain.  Also skip while a `Retryable` backoff
        // defers it — deferring the DRAIN, not growing the buffer. Independent
        // of the logs/spans lanes.
        let metrics_now_msec = now_monotonic_msec();
        let metrics_deferred = metrics_backoff.is_deferred(metrics_now_msec);
        if amcf.metrics_enabled() && !metrics_deferred {
            drain_retry_queue_once(
                &mut retry_queue,
                retry_buffer_depth,
                log.as_ptr(),
                &SEND_FAILURES,
                "metrics",
                &mut MetricsRetry(&mut transport),
                &mut metrics_backoff,
            )
            .await;
        }

        // Inter-send shutdown check between the metrics retry drain and the
        // fresh-metrics send. A quit/terminate arriving while the (deadline-bounded)
        // retry drain was in flight loops back to the top of the outer loop, which
        // immediately runs graceful_drain (quit) or returns (terminate) rather than
        // chaining the fresh-metrics send first. Skipped during a QUIT-DEFER window
        // so the overlap-window drains complete (test-support only; never in prod).
        let metrics_defer_active: bool = {
            #[cfg(feature = "test-support")]
            {
                quit_defer_ticks > 0
            }
            #[cfg(not(feature = "test-support"))]
            {
                false
            }
        };
        if shutdown_requested() && !metrics_defer_active {
            continue;
        }

        // ── Collect fresh metrics from all sources ────────────────────────
        // Pdata pipeline: wrap → process → encode → send (Step U2).
        // Skipped entirely when `otel_metrics off` — no shm zone was registered.
        if !amcf.metrics_enabled() {
            continue;
        }
        let mut metrics_pd =
            Pdata::Metrics(collect_all_sources(amcf, worker_start_ns, &collector_host));
        processor.process(&mut metrics_pd);
        let n_pts = count_pdata_records(&metrics_pd);
        if n_pts > 0 && !metrics_deferred {
            let bytes = encode_pdata(&metrics_pd);

            // ── Send the fresh batch ──────────────────────────────────────
            // Cap at PERIODIC_SEND_BUDGET; deadline expiry is a transient
            // failure taking the identical enqueue/counter/ERR path.
            match with_deadline(
                transport.send_pdata(&metrics_pd, bytes.clone()),
                PERIODIC_SEND_BUDGET,
            )
            .await
            {
                // Outcome-driven policy (release / requeue+defer / drop).
                Ok(Ok(ref outcome)) => {
                    // Re-read the monotonic clock here, AFTER the retry-drain and
                    // fresh-send awaits (each capped at PERIODIC_SEND_BUDGET, so up
                    // to two ~15s waits may have elapsed since `metrics_now_msec`
                    // was captured at the top of this iteration). A `Retryable`
                    // verdict computes `not_before_msec = basis + defer_ms`; with a
                    // stale (pre-send) basis the deadline can already be in the past
                    // once `defer_ms` is capped at `BACKOFF_CAP_MS`, so `is_deferred`
                    // would return false and the next iteration would hammer a
                    // failing collector at full cadence. The backoff basis must be a
                    // fresh "now". `is_deferred` above intentionally keeps the
                    // pre-send capture (it gates entry for THIS iteration).
                    // `apply_metrics_fresh_send_outcome` re-reads the clock
                    // internally (post-send); the call site cannot accidentally
                    // supply a stale basis.
                    if apply_metrics_fresh_send_outcome(
                        outcome,
                        &mut metrics_backoff,
                        &mut retry_queue,
                        bytes,
                        n_pts,
                        retry_buffer_depth,
                        &SEND_FAILURES,
                        log.as_ptr(),
                    ) == OutcomeAction::Release
                    {
                        ngx::ngx_log_error!(
                            NGX_LOG_INFO,
                            log.as_ptr(),
                            "otel export: sent {} data points to collector",
                            n_pts
                        );
                    }
                }
                Ok(Err(ref e)) => {
                    ngx::ngx_log_error!(
                        NGX_LOG_ERR,
                        log.as_ptr(),
                        "otel export: send failed ({}); queuing for retry",
                        e
                    );
                    enqueue_with_eviction(
                        &mut retry_queue,
                        bytes,
                        n_pts,
                        retry_buffer_depth,
                        log.as_ptr(),
                    );
                    SEND_FAILURES.fetch_add(1, Ordering::Relaxed);
                }
                Err(DeadlineExceeded) => {
                    ngx::ngx_log_error!(
                        NGX_LOG_ERR,
                        log.as_ptr(),
                        "otel export: send timed out after {:?}; queuing for retry",
                        PERIODIC_SEND_BUDGET
                    );
                    enqueue_with_eviction(
                        &mut retry_queue,
                        bytes,
                        n_pts,
                        retry_buffer_depth,
                        log.as_ptr(),
                    );
                    SEND_FAILURES.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // (Log drain happens every SHUTDOWN_POLL_INTERVAL inside the chunked
        // sleep above — no separate log drain here.)
    }
}

// ── Graceful drain ────────────────────────────────────────────────────────────

/// F6: Credits `counter` for all pending `(bytes, n_records)` batches in
/// `queue`, then clears it.
///
/// Called from `graceful_drain`'s send-failure and timeout arms for the logs
/// and spans retry queues.  Pre-fix, `clear()` ran without accumulating the
/// count — queued records were silently discarded without incrementing any
/// drop counter.
///
/// Extracted to a named function so the test can call the production logic
/// directly rather than re-implementing the pattern inline.
fn account_drops_and_clear(
    queue: &mut VecDeque<(std::vec::Vec<u8>, u64)>,
    counter: &core::sync::atomic::AtomicU64,
) {
    let remaining: u64 = queue.iter().map(|(_, n)| *n).sum();
    if remaining > 0 {
        counter.fetch_add(remaining, Ordering::Relaxed);
    }
    queue.clear();
}

/// Returns `true` when a successor exporter generation has been
/// announced — `ControlShm::successor_gen > my_gen` — meaning this exporter
/// must abdicate mutating ring pops (logs/spans).
///
/// Used by both the periodic drain path (see `export_loop`) and
/// [`graceful_drain`] — one definition, two call sites, no inline copy
/// (a second copy would let the two callers drift apart).
///
/// # Safety
/// `control_shm_ptr()` returns `Some` only when the zone is registered and
/// mapped; `successor_gen` is read with `Acquire` ordering.
fn successor_announced(amcf: &MainConfig, my_gen: u64) -> bool {
    amcf.control_shm_ptr()
        .map(|p| {
            // SAFETY: `control_shm_ptr()` returns `Some` only when the control
            // shm zone is registered and mapped; the raw pointer is valid for
            // this exporter's lifetime (cycle-pool allocated).
            (unsafe { (*p).successor_gen.load(core::sync::atomic::Ordering::Acquire) }) > my_gen
        })
        .unwrap_or(false)
}

/// Retry queues for all three signal transports — metrics, logs, and spans.
///
/// Bundled into a single argument to keep [`graceful_drain`]'s signature
/// concise.  Each field is a mutable borrow of the queue owned by
/// [`export_loop`], so the queues are drained in-place during the flush.
struct DrainQueues<'a> {
    /// Retry queue for OTLP metrics batches.
    metrics: &'a mut VecDeque<(std::vec::Vec<u8>, u64)>,
    /// Retry queue for OTLP logs batches.
    logs: &'a mut VecDeque<(std::vec::Vec<u8>, u64)>,
    /// Retry queue for OTLP spans batches.
    spans: &'a mut VecDeque<(std::vec::Vec<u8>, u64)>,
}

/// Called when `ngx_quit` is detected from inside [`export_loop`].
///
/// Runs on the **exporter's** `ngx_quit` path, not a worker's
/// `ngx_exiting` path. The exporter receives SIGQUIT via master's channel
/// write (`NGX_CMD_QUIT` → `ngx_quit`).
///
/// Best-effort: attempt to flush the retry queue (one send per queued batch)
/// and then send one final freshly-collected batch. Each send is wrapped in a
/// short wall-clock budget ([`GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET`]) so that an
/// unreachable collector cannot stall exporter shutdown.
///
/// # Lifetime safety
///
/// `ngx_quit` only marks the process as quitting — the event loop is still
/// running (the exporter cycle continues calling `ngx_process_events_and_timers`
/// until `EXPORT_LOOP_DONE` is set), the cycle pool is still live, and our
/// spawned task is still being polled. The Task handle is dropped at cycle-pool
/// teardown, which happens *after* this function returns. Awaiting
/// `transport.send()` here is safe.
///
/// # Why the chunked sleep timer fires on quit
///
/// `ngx_event_no_timers_left()` returns `NGX_OK` (worker may exit) when the
/// only pending timers are `cancelable`. The ngx-rust SDK marks every
/// [`ngx::async_::sleep`] timer as cancelable
/// (`ngx-rust/src/async_/sleep.rs:94: ev.set_cancelable(1)`), so a worker
/// between intervals would be treated as idle and exit before its timer fired.
/// The exporter, however, is not a worker and is not subject to
/// `ngx_event_no_timers_left`. When SIGQUIT arrives while the exporter is
/// between intervals, nginx's event loop does NOT cancel the sleep timer — it
/// fires normally, the export loop detects `ngx_quit`, and runs this drain.
/// The chunked sleep ([`SHUTDOWN_POLL_INTERVAL`]) caps detection latency at
/// 250 ms.
///
/// This async drain is the sole final-flush path. The exporter cycle waits
/// for [`EXPORT_LOOP_DONE`] before calling `process::exit`, ensuring the
/// drain always completes.
///
/// # Reload-safe graceful drain.
///
/// On SIGHUP reload the master announces a successor by incrementing
/// `ControlShm::successor_gen` (with Release ordering) BEFORE forking the new
/// exporter AND before sending `NGX_CMD_QUIT` to the old exporter.  The channel
/// write/read provides the happens-before ordering that makes this visible.
///
/// When `current_gen > my_gen` (a successor is in place) this function
/// **abdicates** log/span ring drains:
/// - Already-popped in-process retry buffers are flushed (private memory, safe).
/// - Final cumulative-metrics batch is sent (pure WorkerSlots reads, always safe).
/// - Log/span ring `pop_into` calls and the coalesce-table reset are SKIPPED;
///   the new exporter picks those up as the sole consumer.
///
/// When `current_gen == my_gen` (pure shutdown, no successor) the old exporter
/// is the sole consumer and performs a full drain including ring pops.
///
/// Note on dedup: deduping by `time_unix_nano` is safe ONLY for cumulative
/// metrics (the collector can dedup identical counter data points by
/// {start_time, time} range). It does NOT hold for length-prefixed log/span
/// rings: two concurrent `pop_into` callers race on `read_offset` (Relaxed
/// load + Release store, no CAS) and can yield garbage record lengths (up to
/// 4 GiB on a producer wrap-around). Making the new exporter the sole ring
/// consumer on reload restores the SPSC invariant.
async fn graceful_drain(
    transport: &mut ExportTransport,
    queues: &mut DrainQueues<'_>,
    amcf: &'static MainConfig,
    worker_start_ns: u64,
    processor: &Processor,
    my_gen: u64,
    collector_host: &str,
) {
    let log = ngx::log::ngx_cycle_log();
    let queued = queues.metrics.len();

    // Check whether a successor was announced (reload) or not (shutdown).
    // Use the shared successor_announced() check — one definition for both
    // the periodic drain path and graceful_drain.
    let has_successor = successor_announced(amcf, my_gen);

    ngx::ngx_log_error!(
        NGX_LOG_NOTICE,
        log.as_ptr(),
        "otel export: graceful drain starting ({} queued batch(es), successor={})",
        queued,
        has_successor as u8
    );
    if has_successor {
        // Abdication path — log/span ring pops are skipped (new exporter owns).
        // Still flush in-process retry buffers and final cumulative-metrics batch.
        ngx::ngx_log_error!(
            NGX_LOG_NOTICE,
            log.as_ptr(),
            "otel export: successor announced — abdicating log/span ring drains \
             (new exporter is sole consumer)"
        );
    }

    // Flush metrics retry queue and final metrics batch only when metrics are
    // enabled.  When `otel_metrics off` the retry queue is always empty (no
    // metrics were ever sent) and there is no shm zone to collect from.
    if amcf.metrics_enabled() {
        // Flush metrics retry queue (one bounded attempt each, ignore errors).
        while let Some((bytes, n_pts)) = queues.metrics.pop_front() {
            match with_deadline(transport.send(bytes), GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET).await {
                // Any Ok(outcome) is treated as release; the outcome-driven policy
                // (release/requeue+defer/drop) applies.
                Ok(Ok(_outcome)) => {}
                Ok(Err(e)) => {
                    ngx::ngx_log_error!(
                        NGX_LOG_ERR,
                        log.as_ptr(),
                        "otel export: drain: queued batch ({} pts) send failed: {}",
                        n_pts,
                        e
                    );
                    // Other queued batches likely fail too; stop and let the
                    // remainder be dropped when the loop returns.
                    let remaining: u64 = queues.metrics.iter().map(|(_, n)| n).sum();
                    if remaining > 0 {
                        DROPPED_RECORDS.fetch_add(remaining, Ordering::Relaxed);
                    }
                    queues.metrics.clear();
                    break;
                }
                Err(DeadlineExceeded) => {
                    ngx::ngx_log_error!(
                        NGX_LOG_NOTICE,
                        log.as_ptr(),
                        "otel export: drain: queued batch ({} pts) timed out after {:?}",
                        n_pts,
                        GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET
                    );
                    let remaining: u64 = queues.metrics.iter().map(|(_, n)| n).sum();
                    if remaining > 0 {
                        DROPPED_RECORDS.fetch_add(remaining, Ordering::Relaxed);
                    }
                    queues.metrics.clear();
                    break;
                }
            }
        }

        // Final freshly-collected metrics batch (Pdata pipeline, Step U2).
        let mut final_pd =
            Pdata::Metrics(collect_all_sources(amcf, worker_start_ns, collector_host));
        processor.process(&mut final_pd);
        let n_pts = count_pdata_records(&final_pd);
        if n_pts > 0 {
            let bytes = encode_pdata(&final_pd);
            match with_deadline(
                transport.send_pdata(&final_pd, bytes),
                GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET,
            )
            .await
            {
                // Any Ok(outcome) treated as release (the outcome-driven policy applies).
                Ok(Ok(_outcome)) => {
                    ngx::ngx_log_error!(
                        NGX_LOG_NOTICE,
                        log.as_ptr(),
                        "otel export: drain: final batch sent ({} data points)",
                        n_pts
                    );
                }
                Ok(Err(e)) => {
                    ngx::ngx_log_error!(
                        NGX_LOG_ERR,
                        log.as_ptr(),
                        "otel export: drain: final batch failed: {}",
                        e
                    );
                }
                Err(DeadlineExceeded) => {
                    ngx::ngx_log_error!(
                        NGX_LOG_NOTICE,
                        log.as_ptr(),
                        "otel export: drain: final batch timed out after {:?}",
                        GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET
                    );
                }
            }
        }
    }

    // Drain pending logs retry queue (one bounded attempt each).
    while let Some((bytes, n_logs)) = queues.logs.pop_front() {
        match with_deadline(transport.send_logs(bytes), GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET).await {
            // Any Ok(outcome) is treated as release; the outcome-driven policy
            // (release/requeue+defer/drop) applies.
            Ok(Ok(_outcome)) => {}
            Ok(Err(e)) => {
                ngx::ngx_log_error!(
                    NGX_LOG_ERR,
                    log.as_ptr(),
                    "otel export: drain: logs queued batch ({} records) send failed: {}",
                    n_logs,
                    e
                );
                // F6: credit remaining queued logs records to DROPPED_RECORDS before
                // clearing so the self-metric reflects the full drop, not just the
                // current batch.  Mirrors the metrics-lane drain-abort pattern.
                account_drops_and_clear(queues.logs, &DROPPED_RECORDS);
                break;
            }
            Err(DeadlineExceeded) => {
                ngx::ngx_log_error!(
                    NGX_LOG_NOTICE,
                    log.as_ptr(),
                    "otel export: drain: logs queued batch ({} records) timed out",
                    n_logs
                );
                // F6: same as the error arm above.
                account_drops_and_clear(queues.logs, &DROPPED_RECORDS);
                break;
            }
        }
    }

    // Final freshly-collected logs batch (access + error rings).
    // Skipped on abdication — new exporter is sole consumer of the rings.
    if !has_successor && (amcf.any_log_export_enabled() || amcf.error_log_enabled) {
        if let Some(logs_base) = amcf.logs_shm_base() {
            // Use n_active_workers (same rationale as export path).
            let n_workers = {
                use core::sync::atomic::Ordering;
                let n = amcf.n_active_workers.load(Ordering::Relaxed);
                if n > 0 {
                    n
                } else {
                    // SAFETY: `logs_shm_base()` returned `Some`, so the logs zone is
                    // registered and mapped; `amcf.logs_shm_zone` points to a live
                    // `ngx_shm_zone_t` valid for the exporter's lifetime. The `&*`
                    // borrow does not escape this block; `shm.size` is a plain read.
                    unsafe {
                        let zone = &*amcf.logs_shm_zone;
                        let avail = zone.shm.size.saturating_sub(crate::shm::data_offset());
                        logs_n_workers_from_zone(avail, amcf.log_ring_cap())
                    }
                }
            };
            // Pdata pipeline: wrap → process → encode → send (Step U2).
            let mut logs_pd =
                Pdata::Logs(collect_log_records(amcf, logs_base, n_workers, worker_start_ns));
            processor.process(&mut logs_pd);
            let n_logs = count_pdata_records(&logs_pd);
            if n_logs > 0 {
                let logs_bytes = encode_pdata(&logs_pd);
                match with_deadline(
                    transport.send_pdata(&logs_pd, logs_bytes),
                    GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET,
                )
                .await
                {
                    // Any Ok(outcome) treated as release (the outcome-driven policy applies).
                    Ok(Ok(_outcome)) => {
                        ngx::ngx_log_error!(
                            NGX_LOG_NOTICE,
                            log.as_ptr(),
                            "otel export: drain: final logs batch sent ({} records)",
                            n_logs
                        );
                    }
                    Ok(Err(e)) => {
                        ngx::ngx_log_error!(
                            NGX_LOG_ERR,
                            log.as_ptr(),
                            "otel export: drain: final logs batch failed: {}",
                            e
                        );
                    }
                    Err(DeadlineExceeded) => {
                        ngx::ngx_log_error!(
                            NGX_LOG_NOTICE,
                            log.as_ptr(),
                            "otel export: drain: final logs batch timed out"
                        );
                    }
                }
            }
        }
    }

    // Drain pending spans retry queue (one bounded attempt each).
    while let Some((bytes, n_spans)) = queues.spans.pop_front() {
        match with_deadline(transport.send_traces(bytes), GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET).await {
            // Any Ok(outcome) is treated as release; the outcome-driven policy
            // (release/requeue+defer/drop) applies.
            Ok(Ok(_outcome)) => {}
            Ok(Err(e)) => {
                ngx::ngx_log_error!(
                    NGX_LOG_ERR,
                    log.as_ptr(),
                    "otel export: drain: spans queued batch ({} records) send failed: {}",
                    n_spans,
                    e
                );
                // F6: credit remaining queued spans records before clearing.
                account_drops_and_clear(queues.spans, &DROPPED_RECORDS);
                break;
            }
            Err(DeadlineExceeded) => {
                ngx::ngx_log_error!(
                    NGX_LOG_NOTICE,
                    log.as_ptr(),
                    "otel export: drain: spans queued batch ({} records) timed out",
                    n_spans
                );
                // F6: same as the error arm above.
                account_drops_and_clear(queues.spans, &DROPPED_RECORDS);
                break;
            }
        }
    }

    // Final freshly-collected spans batch (Pdata pipeline, Step U2).
    // Skipped on abdication — new exporter is sole consumer of the rings.
    if !has_successor {
        if let Some(spans_base) = amcf.spans_shm_base() {
            // Use n_active_workers (same rationale as export path).
            let n_workers = {
                use core::sync::atomic::Ordering;
                let n = amcf.n_active_workers.load(Ordering::Relaxed);
                if n > 0 {
                    n
                } else {
                    // SAFETY: `spans_shm_base()` returned `Some`, so the spans zone is
                    // registered and mapped; `amcf.spans_shm_zone` points to a live
                    // `ngx_shm_zone_t` valid for the exporter's lifetime. The `&*`
                    // borrow does not escape this block; `shm.size` is a plain read.
                    unsafe {
                        let zone = &*amcf.spans_shm_zone;
                        let avail = zone.shm.size.saturating_sub(crate::shm::data_offset());
                        spans_n_workers_from_zone(avail, DEFAULT_SPAN_RING_CAP)
                    }
                }
            };
            let mut spans_pd = Pdata::Spans(collect_span_records(amcf, spans_base, n_workers));
            processor.process(&mut spans_pd);
            let n_spans = count_pdata_records(&spans_pd);
            if n_spans > 0 {
                let spans_bytes = encode_pdata(&spans_pd);
                match with_deadline(
                    transport.send_pdata(&spans_pd, spans_bytes),
                    GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET,
                )
                .await
                {
                    // Any Ok(outcome) treated as release (the outcome-driven policy applies).
                    Ok(Ok(_outcome)) => {
                        ngx::ngx_log_error!(
                            NGX_LOG_NOTICE,
                            log.as_ptr(),
                            "otel export: drain: final spans batch sent ({} records)",
                            n_spans
                        );
                    }
                    Ok(Err(e)) => {
                        ngx::ngx_log_error!(
                            NGX_LOG_ERR,
                            log.as_ptr(),
                            "otel export: drain: final spans batch failed: {}",
                            e
                        );
                    }
                    Err(DeadlineExceeded) => {
                        ngx::ngx_log_error!(
                            NGX_LOG_NOTICE,
                            log.as_ptr(),
                            "otel export: drain: final spans batch timed out"
                        );
                    }
                }
            }
        }
    } // end `if !has_successor` for spans ring drain

    ngx::ngx_log_error!(NGX_LOG_NOTICE, log.as_ptr(), "otel export: graceful drain complete");
}

// ── Deadline-bounded future ─────────────────────────────────────────────────

/// Sentinel returned by [`with_deadline`] when the timer fires before the
/// inner future completes.
struct DeadlineExceeded;

pin_project! {
    /// Races an inner future against a timer future. Whichever resolves first
    /// wins. No allocation, no `select!` machinery.
    ///
    /// Generic over the timer type `T` so that production passes
    /// [`ngx::async_::Sleep`] (driven by the NGINX event loop) while unit tests
    /// can inject a deterministic, runtime-free timer (e.g. ready-on-first-poll)
    /// to exercise the deadline-expiry arm without a real wall-clock wait.
    struct WithDeadline<F, T> {
        #[pin]
        fut: F,
        #[pin]
        timer: T,
    }
}

impl<F: Future, T: Future<Output = ()>> Future for WithDeadline<F, T> {
    type Output = Result<F::Output, DeadlineExceeded>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if let Poll::Ready(output) = this.fut.poll(cx) {
            return Poll::Ready(Ok(output));
        }
        if let Poll::Ready(()) = this.timer.poll(cx) {
            return Poll::Ready(Err(DeadlineExceeded));
        }
        Poll::Pending
    }
}

/// Wraps `fut` so it resolves at most after `timeout`. On timeout the inner
/// future is dropped — for a hyper send this means the in-flight connection
/// future is cancelled cleanly via [`Drop`].
fn with_deadline<F: Future>(fut: F, timeout: Duration) -> WithDeadline<F, ngx::async_::Sleep> {
    WithDeadline { fut, timer: ngx::async_::sleep(timeout) }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Enqueue a batch for retry.  If the queue is already at `max_depth`,
/// the oldest entry is evicted and `DROPPED_RECORDS` is incremented (F6:
/// `DROPPED_RECORDS` covers all three signal lanes — metrics, logs, spans).
///
/// Returns the number of records dropped (0 if the queue was not full).
///
/// `log` may be null; the eviction-logging path is guarded against that so the
/// unit test can call this directly without constructing an `ngx_log_t`.
#[inline]
fn enqueue_with_eviction(
    retry_queue: &mut VecDeque<(std::vec::Vec<u8>, u64)>,
    bytes: std::vec::Vec<u8>,
    n_pts: u64,
    max_depth: usize,
    log: *mut nginx_sys::ngx_log_t,
) -> u64 {
    if retry_queue.len() >= max_depth {
        if let Some((_, dropped_pts)) = retry_queue.pop_front() {
            DROPPED_RECORDS.fetch_add(dropped_pts, Ordering::Relaxed);
            if !log.is_null() {
                ngx::ngx_log_error!(
                    NGX_LOG_ERR,
                    log,
                    "otel export: retry buffer full, dropped {} records",
                    dropped_pts
                );
            }
            retry_queue.push_back((bytes, n_pts));
            return dropped_pts;
        }
    }
    retry_queue.push_back((bytes, n_pts));
    0
}

/// Returns true if the transport error is a permanent 4xx HTTP rejection that
/// must be dropped rather than re-queued.
#[inline]
fn is_permanent_rejection(e: &crate::transport::TransportError) -> bool {
    matches!(e, crate::transport::TransportError::HttpStatus { code, .. } if *code >= 400 && *code < 500)
}

// ── Outcome-driven policy engine ───────────────────────────────────────────────
//
// The policy is written ONCE against the protocol-agnostic `DeliveryOutcome`
// (the transport adapters already mapped native HTTP/gRPC status into it). The
// engine NEVER branches on an HTTP code or a gRPC code here.
//
// Defer mechanism: a per-signal "not before"
// monotonic timestamp + a per-signal consecutive-`Retryable`-failure counter.
// Honoring a backoff DEFERS THE NEXT DRAIN of that signal — it does NOT grow the
// buffer or add any unbounded store. The bounded per-signal retry buffer with
// drop-oldest eviction remains the backstop, unchanged.

/// Per-signal backoff/defer state. Lives in `export_loop` locals (one per
/// signal lane) — single-task, exporter-local; never shared across threads.
#[derive(Debug, Default, Clone, Copy)]
struct SignalBackoff {
    /// Monotonic `ngx_current_msec` value before which this signal must NOT be
    /// drained again. `0` = no active deferral. The drain loop reuses nginx's
    /// existing cached `CLOCK_MONOTONIC` millisecond basis (`ngx_current_msec`)
    /// — no new clock is introduced.
    not_before_msec: u64,
    /// Count of consecutive `Retryable` verdicts for this signal since the last
    /// `Accepted`. Drives the no-hint exponential backoff doubling; reset to 0
    /// on the next `Accepted`.
    consecutive_retryable: u32,
}

impl SignalBackoff {
    /// Whether a drain of this signal is currently deferred at `now_msec`.
    /// `not_before_msec == 0` means no deferral is active.
    #[inline]
    fn is_deferred(&self, now_msec: u64) -> bool {
        self.not_before_msec != 0 && now_msec < self.not_before_msec
    }
}

/// The action the policy engine prescribes for a drained/sent batch. The caller
/// performs the buffer mutation (release = drop the in-hand batch; requeue =
/// `enqueue_with_eviction`; drop = discard); the defer/backoff bookkeeping has
/// already been applied to the `SignalBackoff` by [`apply_delivery_outcome`].
#[derive(Debug, PartialEq, Eq)]
enum OutcomeAction {
    /// Release the batch (delivered). Backoff was reset.
    Release,
    /// Re-queue the batch into the bounded buffer; the next drain of this signal
    /// is deferred (see the `SignalBackoff`).
    Requeue,
    /// Drop the batch permanently (Permanent / Unauthorized); do NOT retry.
    Drop,
}

/// Compute the no-hint exponential backoff duration (ms) for the
/// `consecutive_retryable`-th consecutive retryable failure: `base << (n-1)`,
/// saturating at `cap`. `n == 0` is treated as the first failure.
#[inline]
fn backoff_ms(consecutive_retryable: u32, base_ms: u64, cap_ms: u64) -> u64 {
    if base_ms == 0 {
        return 0;
    }
    let shift = consecutive_retryable.saturating_sub(1);
    // `<<` can both wrap (shift ≥ 64) and silently overflow the value (shift <
    // 64 but `base << shift` exceeds u64). Guard both with a saturating shift:
    // if the shift exceeds the headroom in `base_ms`, the product would exceed
    // u64, so saturate straight to the cap.
    if shift >= base_ms.leading_zeros() {
        return cap_ms;
    }
    (base_ms << shift).min(cap_ms)
}

/// The outcome-driven policy, written ONCE against `DeliveryOutcome`. Updates
/// `backoff` (defer timestamp + consecutive-failure counter) and the
/// delivery-outcome self-metric counters, and returns the buffer action for the
/// caller to perform.
///
/// `now_msec` is the current monotonic basis (`ngx_current_msec` in production;
/// an injected value in tests). `signal` and `log` are used only for the
/// rate-limited `Unauthorized` "check credentials" log.
fn apply_delivery_outcome(
    outcome: &crate::transport::DeliveryOutcome,
    backoff: &mut SignalBackoff,
    now_msec: u64,
    log: *mut nginx_sys::ngx_log_t,
    signal: &str,
) -> OutcomeAction {
    use crate::transport::DeliveryOutcome as DO;
    match outcome {
        DO::Accepted => {
            // Success resets the backoff for this signal.
            backoff.consecutive_retryable = 0;
            backoff.not_before_msec = 0;
            OutcomeAction::Release
        }
        DO::PartialReject { rejected } => {
            // Accepted overall → release the batch + reset backoff; the peer
            // dropped `rejected` records it could not store (counts only).
            backoff.consecutive_retryable = 0;
            backoff.not_before_msec = 0;
            PARTIAL_REJECTED.fetch_add(*rejected, Ordering::Relaxed);
            OutcomeAction::Release
        }
        DO::Retryable { retry_after } => {
            // Transient: re-queue into the bounded buffer (caller) AND defer the
            // next drain of this signal. Honor a peer hint verbatim; otherwise
            // apply the hardcoded exponential backoff (doubling per consecutive
            // retryable failure, capped). The defer NEVER grows the buffer.
            backoff.consecutive_retryable = backoff.consecutive_retryable.saturating_add(1);
            let defer_ms = match retry_after {
                Some(hint) => {
                    // Hint honored verbatim (NOT subject to the no-hint cap).
                    // Round up sub-ms hints to at least one tick so a defer is
                    // always observable.
                    let ms = hint.as_millis();
                    u64::try_from(ms).unwrap_or(u64::MAX).max(1)
                }
                None => backoff_ms(backoff.consecutive_retryable, BACKOFF_BASE_MS, BACKOFF_CAP_MS),
            };
            backoff.not_before_msec = now_msec.saturating_add(defer_ms).max(1);
            OutcomeAction::Requeue
        }
        DO::Permanent => {
            // Permanent rejection — drop + count, never retry. Backoff is not a
            // factor (we are not deferring; the batch is gone).
            PERMANENT_REJECTED.fetch_add(1, Ordering::Relaxed);
            OutcomeAction::Drop
        }
        DO::Unauthorized => {
            // SAME policy action as Permanent (drop + count, NO retry, NO
            // backoff, NO auto-pause) — auth failures are a config/credential
            // problem retrying cannot fix. Distinct counter + a rate-limited
            // "check credentials" log so the real signal is not buried, and so
            // we never silently stop the exporter or the other signals.
            UNAUTHORIZED_REJECTED.fetch_add(1, Ordering::Relaxed);
            maybe_log_unauthorized(log, signal);
            OutcomeAction::Drop
        }
    }
}

/// Apply the outcome-driven policy to a *fresh* (newly-collected) batch
/// send result. Shared by the metrics/logs/spans fresh-send sites so the policy
/// is written once. On `Requeue`/transient the batch is re-queued into the
/// bounded buffer (drop-oldest backstop, unchanged) and `failure_counter` is
/// bumped; on `Drop` the batch is discarded (the dedicated delivery counter was
/// bumped inside [`apply_delivery_outcome`]); on `Release` nothing is queued.
///
/// Returns the [`OutcomeAction`] so the caller can emit its signal-specific
/// success log with the original wording (a chaos test parses those exact
/// "sent N {log,span} records to collector" lines).
///
/// `now_msec` is the monotonic basis for the defer timestamp recorded in
/// `backoff`. `bytes`/`n_records` are the fresh batch (consumed only when
/// re-queued).
#[allow(clippy::too_many_arguments)]
fn handle_fresh_send_outcome(
    outcome: &crate::transport::DeliveryOutcome,
    backoff: &mut SignalBackoff,
    now_msec: u64,
    queue: &mut VecDeque<(std::vec::Vec<u8>, u64)>,
    bytes: std::vec::Vec<u8>,
    n_records: u64,
    retry_buffer_depth: usize,
    failure_counter: &AtomicU64,
    log: *mut nginx_sys::ngx_log_t,
    signal: &'static str,
) -> OutcomeAction {
    let action = apply_delivery_outcome(outcome, backoff, now_msec, log, signal);
    match action {
        // Caller logs the success line (signal-specific wording).
        OutcomeAction::Release => {}
        OutcomeAction::Requeue => {
            if !log.is_null() {
                ngx::ngx_log_error!(
                    NGX_LOG_ERR,
                    log,
                    "otel export: {} send retryable; queuing for retry and deferring next drain",
                    signal
                );
            }
            enqueue_with_eviction(queue, bytes, n_records, retry_buffer_depth, log);
            failure_counter.fetch_add(1, Ordering::Relaxed);
        }
        OutcomeAction::Drop => {
            if !log.is_null() {
                ngx::ngx_log_error!(
                    NGX_LOG_ERR,
                    log,
                    "otel export: dropping fresh {} batch — non-retryable verdict",
                    signal
                );
            }
        }
    }
    action
}

/// Apply the send outcome for a **fresh metrics batch**, re-reading the
/// monotonic clock internally (after the send await) so the backoff deadline
/// is computed from a fresh "now", not a pre-send stale capture.
///
/// Each signal has its own wrapper so the call sites cannot accidentally pass
/// a stale pre-send clock value — the basis is always read here, immediately
/// before delegating to [`handle_fresh_send_outcome`].
#[allow(clippy::too_many_arguments)]
fn apply_metrics_fresh_send_outcome(
    outcome: &crate::transport::DeliveryOutcome,
    backoff: &mut SignalBackoff,
    queue: &mut VecDeque<(std::vec::Vec<u8>, u64)>,
    bytes: std::vec::Vec<u8>,
    n_records: u64,
    retry_buffer_depth: usize,
    failure_counter: &AtomicU64,
    log: *mut nginx_sys::ngx_log_t,
) -> OutcomeAction {
    // Re-read the clock AFTER the send await returns. See `post_send_backoff_basis`.
    let basis = post_send_backoff_basis();
    handle_fresh_send_outcome(
        outcome,
        backoff,
        basis,
        queue,
        bytes,
        n_records,
        retry_buffer_depth,
        failure_counter,
        log,
        "metrics",
    )
}

/// Apply the send outcome for a **fresh logs batch**; see
/// [`apply_metrics_fresh_send_outcome`] for the stale-basis rationale.
#[allow(clippy::too_many_arguments)]
fn apply_logs_fresh_send_outcome(
    outcome: &crate::transport::DeliveryOutcome,
    backoff: &mut SignalBackoff,
    queue: &mut VecDeque<(std::vec::Vec<u8>, u64)>,
    bytes: std::vec::Vec<u8>,
    n_records: u64,
    retry_buffer_depth: usize,
    failure_counter: &AtomicU64,
    log: *mut nginx_sys::ngx_log_t,
) -> OutcomeAction {
    let basis = post_send_backoff_basis();
    handle_fresh_send_outcome(
        outcome,
        backoff,
        basis,
        queue,
        bytes,
        n_records,
        retry_buffer_depth,
        failure_counter,
        log,
        "logs",
    )
}

/// Apply the send outcome for a **fresh spans batch**; see
/// [`apply_metrics_fresh_send_outcome`] for the stale-basis rationale.
#[allow(clippy::too_many_arguments)]
fn apply_spans_fresh_send_outcome(
    outcome: &crate::transport::DeliveryOutcome,
    backoff: &mut SignalBackoff,
    queue: &mut VecDeque<(std::vec::Vec<u8>, u64)>,
    bytes: std::vec::Vec<u8>,
    n_records: u64,
    retry_buffer_depth: usize,
    failure_counter: &AtomicU64,
    log: *mut nginx_sys::ngx_log_t,
) -> OutcomeAction {
    let basis = post_send_backoff_basis();
    handle_fresh_send_outcome(
        outcome,
        backoff,
        basis,
        queue,
        bytes,
        n_records,
        retry_buffer_depth,
        failure_counter,
        log,
        "spans",
    )
}

/// Last `ngx_current_msec` at which the "check exporter credentials" line was
/// emitted (0 = never). Rate-limits the `Unauthorized` log to at most once per
/// [`UNAUTHORIZED_LOG_INTERVAL_MS`] so a per-batch 401/403 storm cannot hammer
/// the error log. Exporter-local single-writer atomic (same pattern as the
/// other counters); the read-modify-write is benign even if it ever raced.
static UNAUTHORIZED_LOG_LAST_MSEC: AtomicU64 = AtomicU64::new(0);

/// Minimum spacing between successive `Unauthorized` "check credentials" log
/// lines (60 s).
const UNAUTHORIZED_LOG_INTERVAL_MS: u64 = 60_000;

/// Emit the "check exporter credentials" error line at most once per
/// [`UNAUTHORIZED_LOG_INTERVAL_MS`]. Uses the same monotonic
/// `ngx_current_msec` basis as the defer timestamps.
fn maybe_log_unauthorized(log: *mut nginx_sys::ngx_log_t, signal: &str) {
    if log.is_null() {
        return;
    }
    // SAFETY: `ngx_current_msec` is an nginx global updated by the event loop
    // in this single-threaded exporter process; a plain read is well-defined.
    let now = unsafe { nginx_sys::ngx_current_msec } as u64;
    let last = UNAUTHORIZED_LOG_LAST_MSEC.load(Ordering::Relaxed);
    // First occurrence (last == 0) always logs; thereafter respect the interval.
    if last != 0 && now.saturating_sub(last) < UNAUTHORIZED_LOG_INTERVAL_MS {
        return;
    }
    UNAUTHORIZED_LOG_LAST_MSEC.store(now.max(1), Ordering::Relaxed);
    ngx::ngx_log_error!(
        NGX_LOG_ERR,
        log,
        "otel export: {} batch rejected — authentication/authorization failed; \
         check exporter credentials (dropping, not retrying)",
        signal
    );
}

/// Injectable clock override for unit tests. Non-zero values replace the
/// `ngx_current_msec` read in `now_monotonic_msec()`, allowing tests to
/// simulate pre-send and post-send clock advances without a real nginx event
/// loop. Zero (the default) is a no-op: the real nginx global is read instead.
///
/// Tests that touch this field MUST reset it to 0 before returning so that
/// sibling tests that rely on `ngx_current_msec == 0` (the test-process
/// default) are not disturbed.
#[cfg(test)]
static TEST_CLOCK_MSEC: AtomicU64 = AtomicU64::new(0);

/// Read the current monotonic millisecond basis used for defer timestamps.
/// Reuses nginx's cached `CLOCK_MONOTONIC` (`ngx_current_msec`, updated by the
/// event loop the exporter runs on) — the SAME basis `liveness` uses. No new
/// clock is introduced.
///
/// # Safety
/// `ngx_current_msec` is an nginx global updated by the event loop in this
/// single-threaded exporter process; a plain read is well-defined.
#[inline]
fn now_monotonic_msec() -> u64 {
    // In test builds an injectable override lets unit tests simulate the
    // pre-send/post-send clock advance without a real nginx event loop.
    #[cfg(test)]
    {
        let t = TEST_CLOCK_MSEC.load(Ordering::Relaxed);
        if t != 0 {
            return t;
        }
    }
    // SAFETY: `ngx_current_msec` is an nginx global updated by the event loop
    // in this single-threaded exporter process; a plain read is well-defined.
    unsafe { nginx_sys::ngx_current_msec as u64 }
}

/// Separate named entry point for the post-send clock read in each fresh-send
/// lane. All three lanes (metrics / logs / spans) call THIS function — not an
/// inline `now_monotonic_msec()` — so the naming convention makes the
/// post-send timing contract visible in code review, and tests can exercise
/// the correct-vs-stale split without reaching into the async loop.
#[inline]
fn post_send_backoff_basis() -> u64 {
    now_monotonic_msec()
}

// ── Retry-drain abstraction ───────────────────────────────────────────────────
// `RetrySend` is a minimal send-one-batch trait used exclusively by
// `drain_retry_queue_once`.  The trait exists to make the helper testable
// (test code supplies `MockAlwaysErr` instead of a real transport) while
// keeping the production path zero-overhead — each impl is monomorphised away.
//
// The three production wrappers and the test mock are the only implementations.
// Do NOT generalise this trait to cover other send paths.

trait RetrySend {
    async fn send_batch(
        &mut self,
        bytes: std::vec::Vec<u8>,
    ) -> Result<crate::transport::DeliveryOutcome, crate::transport::TransportError>;
}

/// Logs retry sender — wraps `ExportTransport::send_logs`.
struct LogsRetry<'t>(&'t mut ExportTransport);
impl RetrySend for LogsRetry<'_> {
    async fn send_batch(
        &mut self,
        bytes: std::vec::Vec<u8>,
    ) -> Result<crate::transport::DeliveryOutcome, crate::transport::TransportError> {
        self.0.send_logs(bytes).await
    }
}

/// Spans retry sender — wraps `ExportTransport::send_traces`.
struct SpansRetry<'t>(&'t mut ExportTransport);
impl RetrySend for SpansRetry<'_> {
    async fn send_batch(
        &mut self,
        bytes: std::vec::Vec<u8>,
    ) -> Result<crate::transport::DeliveryOutcome, crate::transport::TransportError> {
        self.0.send_traces(bytes).await
    }
}

/// Metrics retry sender — wraps `ExportTransport::send`.
struct MetricsRetry<'t>(&'t mut ExportTransport);
impl RetrySend for MetricsRetry<'_> {
    async fn send_batch(
        &mut self,
        bytes: std::vec::Vec<u8>,
    ) -> Result<crate::transport::DeliveryOutcome, crate::transport::TransportError> {
        self.0.send(bytes).await
    }
}

/// Per-batch retry-drain helper shared by all three signal lanes.
///
/// Drains `queue` by attempting to send each batch via `sender.send_batch`.
/// On permanent 4xx rejection: drops the batch, bumps `failure_counter`, ERR-logs.
/// On transient error: re-enqueues (bounded by `retry_buffer_depth`), ERR-logs,
/// and stops attempting sends for the rest of this drain pass.
///
/// Called by:
///   logs lane    — src/export/mod.rs (logs retry drain, `&LOGS_SEND_FAILURES`)
///   spans lane   — src/export/mod.rs (spans retry drain, `&TRACES_SEND_FAILURES`)
///   metrics lane — src/export/mod.rs (metrics retry drain, `&SEND_FAILURES`)
///
/// # Safety
/// `log` must point to a valid `ngx_log_t` or be `null_mut()`.  All log calls
/// are guarded; passing `null_mut()` silently omits output (used in tests).
async fn drain_retry_queue_once<S: RetrySend>(
    queue: &mut VecDeque<(std::vec::Vec<u8>, u64)>,
    retry_buffer_depth: usize,
    log: *mut nginx_sys::ngx_log_t,
    failure_counter: &AtomicU64,
    signal: &'static str,
    sender: &mut S,
    backoff: &mut SignalBackoff,
) {
    // Production timer: the NGINX-event-loop-driven sleep. Factored as a
    // closure so the inner generic helper can also be driven by a deterministic
    // runtime-free timer in unit tests (see `f_h3f3_periodic_send_deadline`).
    drain_retry_queue_once_with_timer(
        queue,
        retry_buffer_depth,
        log,
        failure_counter,
        signal,
        sender,
        backoff,
        now_monotonic_msec(),
        || ngx::async_::sleep(PERIODIC_SEND_BUDGET),
    )
    .await;
}

/// Inner generic body of [`drain_retry_queue_once`], parameterised over the
/// per-send deadline timer so unit tests can inject a deterministic timer.
///
/// `mk_timer` produces a fresh timer future for each send attempt; the send is
/// raced against it via [`with_deadline`]/[`WithDeadline`]. Production supplies
/// `|| ngx::async_::sleep(PERIODIC_SEND_BUDGET)`.
///
/// # Safety
/// `log` must point to a valid `ngx_log_t` or be `null_mut()` (all log calls
/// are null-guarded).
#[allow(clippy::too_many_arguments)]
async fn drain_retry_queue_once_with_timer<S, Mk, T>(
    queue: &mut VecDeque<(std::vec::Vec<u8>, u64)>,
    retry_buffer_depth: usize,
    log: *mut nginx_sys::ngx_log_t,
    failure_counter: &AtomicU64,
    signal: &'static str,
    sender: &mut S,
    backoff: &mut SignalBackoff,
    now_msec: u64,
    mut mk_timer: Mk,
) where
    S: RetrySend,
    Mk: FnMut() -> T,
    T: Future<Output = ()>,
{
    let mut snapshot = core::mem::take(queue);
    let mut drain_failed = false;
    while let Some((bytes, n)) = snapshot.pop_front() {
        if drain_failed {
            enqueue_with_eviction(queue, bytes, n, retry_buffer_depth, log);
            continue;
        }
        // Cap each retry send at PERIODIC_SEND_BUDGET. A deadline expiry
        // (hung collector) is a TRANSIENT failure — identical path to a transport
        // error: bump the failure counter, ERR-log, re-enqueue, and stop draining
        // for the rest of this pass (the transport is likely wedged).
        let send = WithDeadline { fut: sender.send_batch(bytes.clone()), timer: mk_timer() };
        match send.await {
            // Outcome-driven policy, written ONCE against `DeliveryOutcome`.
            Ok(Ok(ref outcome)) => {
                match apply_delivery_outcome(outcome, backoff, now_msec, log, signal) {
                    // Accepted / PartialReject → release this batch; keep draining.
                    OutcomeAction::Release => {}
                    // Retryable → re-queue into the bounded buffer and stop the
                    // pass; the next drain of this signal is deferred (the defer
                    // is recorded in `backoff`, honored by the caller's gate).
                    OutcomeAction::Requeue => {
                        failure_counter.fetch_add(1, Ordering::Relaxed);
                        if !log.is_null() {
                            ngx::ngx_log_error!(
                                NGX_LOG_ERR,
                                log,
                                "otel export: {} retry send retryable; re-queuing and \
                                 deferring next drain",
                                signal
                            );
                        }
                        enqueue_with_eviction(queue, bytes, n, retry_buffer_depth, log);
                        drain_failed = true;
                    }
                    // Permanent / Unauthorized → drop this batch (no retry); the
                    // dedicated counter was bumped inside `apply_delivery_outcome`.
                    // Keep draining: each batch carries its own verdict.
                    OutcomeAction::Drop => {
                        if !log.is_null() {
                            ngx::ngx_log_error!(
                                NGX_LOG_ERR,
                                log,
                                "otel export: dropping {} retry batch — non-retryable verdict",
                                signal
                            );
                        }
                    }
                }
            }
            Ok(Err(ref e)) => {
                failure_counter.fetch_add(1, Ordering::Relaxed);
                if is_permanent_rejection(e) {
                    if !log.is_null() {
                        ngx::ngx_log_error!(
                            NGX_LOG_ERR,
                            log,
                            "otel export: dropping {} batch — permanent rejection ({})",
                            signal,
                            e
                        );
                    }
                    drain_failed = true;
                    continue;
                }
                if !log.is_null() {
                    ngx::ngx_log_error!(
                        NGX_LOG_ERR,
                        log,
                        "otel export: {} retry send failed ({}); re-queuing",
                        signal,
                        e
                    );
                }
                enqueue_with_eviction(queue, bytes, n, retry_buffer_depth, log);
                drain_failed = true;
            }
            Err(DeadlineExceeded) => {
                failure_counter.fetch_add(1, Ordering::Relaxed);
                if !log.is_null() {
                    ngx::ngx_log_error!(
                        NGX_LOG_ERR,
                        log,
                        "otel export: {} retry send timed out after {:?}; re-queuing",
                        signal,
                        PERIODIC_SEND_BUDGET
                    );
                }
                enqueue_with_eviction(queue, bytes, n, retry_buffer_depth, log);
                drain_failed = true;
            }
        }
    }
}

/// Count the total number of data points across all metrics in a batch.
fn count_data_points(batch: &Batch) -> u64 {
    batch
        .metrics
        .iter()
        .map(|m| match &m.data {
            MetricData::Histogram(h) => h.data_points.len() as u64,
            MetricData::ExponentialHistogram(h) => h.data_points.len() as u64,
            MetricData::Sum(s) => s.data_points.len() as u64,
            MetricData::Gauge(g) => g.data_points.len() as u64,
        })
        .sum()
}

/// Unified encode entry point for the `Pdata` pipeline (Step U2).
///
/// Dispatches to the per-signal encoder based on the [`Pdata`] variant.
/// Per-signal encode logic is preserved verbatim — only re-homed here.
/// Guarantees byte-identical OTLP output vs the per-signal entry points.
fn encode_pdata(data: &Pdata) -> std::vec::Vec<u8> {
    use crate::encoder::Encoder as _;
    match data {
        Pdata::Metrics(b) => OtlpHttpEncoder.encode(b),
        Pdata::Logs(b) => OtlpLogsEncoder.encode(b),
        Pdata::Spans(b) => OtlpTracesEncoder.encode(b),
    }
}

/// Count exportable records in a [`Pdata`] payload.
///
/// For metrics: total data points across all instruments.
/// For logs: number of [`LogRecord`]s.
/// For spans: number of [`Span`]s.
fn count_pdata_records(data: &Pdata) -> u64 {
    match data {
        Pdata::Metrics(b) => count_data_points(b),
        Pdata::Logs(b) => b.logs.len() as u64,
        Pdata::Spans(b) => b.spans.len() as u64,
    }
}

/// Build the OTLP `Resource` attribute list for this exporter process.
///
/// Populates in order:
/// 1. `service.name` — from `otel_service_name` (if set).
/// 2. Operator attributes — from `otel_resource_attr` directives (in config order).
/// 3. `service.instance.id` — the master (parent) PID as a decimal string.
///    **Skipped** if the operator already supplied one in step 2 so that
///    operator-provided values always win.
///
/// The master PID is read from [`MASTER_PID`], which is written once at
/// [`export_loop`] startup from `nginx_sys::ngx_parent`.  In unit tests the
/// caller sets `MASTER_PID` directly.
fn build_resource_attrs(amcf: &MainConfig) -> std::vec::Vec<KeyValue> {
    let mut attrs: std::vec::Vec<KeyValue> = std::vec::Vec::new();

    // 1. service.name
    if !amcf.service_name.is_empty() {
        if let Ok(name) = core::str::from_utf8(amcf.service_name.as_bytes()) {
            attrs.push(KeyValue {
                key: "service.name".into(),
                value: AnyValue::String(name.into()),
            });
        }
    }

    // 2. Operator-supplied resource attrs (otel_resource_attr).
    for kv in &amcf.resource_attrs {
        if let (Ok(k), Ok(v)) =
            (core::str::from_utf8(kv.key.as_bytes()), core::str::from_utf8(kv.value.as_bytes()))
        {
            attrs.push(KeyValue { key: k.into(), value: AnyValue::String(v.into()) });
        }
    }

    // 3. service.instance.id — default to master PID unless operator overrode it.
    let has_instance_id = attrs.iter().any(|kv| kv.key == "service.instance.id");
    if !has_instance_id {
        let pid = MASTER_PID.load(Ordering::Relaxed);
        // pid = 0 means export_loop has not yet started (pre-init path).
        // Still emit the attribute so the Resource is always well-formed; the
        // value "0" is a valid sentinel that will not collide with a real PID.
        attrs.push(KeyValue {
            key: "service.instance.id".into(),
            value: AnyValue::String(std::format!("{}", pid)),
        });
    }

    attrs
}

/// Collect from all configured [`MetricSource`]s and assemble a [`Batch`].
///
/// Accepts `&MainConfig` rather than `&'static MainConfig` so it can be
/// called both from the async export loop (which holds `'static`) and from
/// the [`graceful_drain`] path, which holds a shorter-lived reference to the
/// current cycle's config.
fn collect_all_sources(amcf: &MainConfig, worker_start_ns: u64, collector_host: &str) -> Batch {
    let mut metrics = std::vec::Vec::new();

    // 1. NGINX connection / request counters (stub_status equivalents).
    //    Only registered when nginx was built with `--with-http_stub_status_module`
    //    (i.e. `NGX_STAT_STUB` is defined → `ngx_feature = "stat_stub"`, set by
    //    `build.rs::detect_stat_stub`). In a no-flag build the `ngx_stat_*` symbols
    //    do not exist and the source would only ever yield permanent zeros, so we
    //    skip registration entirely — the 7 series become ABSENT
    //    rather than zero. The operator is told why via a one-shot WARN at export
    //    loop startup (see `export_loop`).
    #[cfg(ngx_feature = "stat_stub")]
    metrics.extend(StubStatusSource { start_time_unix_nano: worker_start_ns }.collect());

    // 2. Per-worker shm histograms (http.server.request.duration, etc.).
    if let Some(base) = amcf.shm_base() {
        // SAFETY: `shm_base()` returned `Some`, so the metrics zone is
        // registered and mapped; `amcf.shm_zone` points to a live
        // `ngx_shm_zone_t` valid for the exporter's lifetime. The `&*` borrow
        // does not escape this block; `shm.size` is a plain field read.
        let n_workers = unsafe {
            let zone = &*amcf.shm_zone;
            // zone.shm.size includes the slab-pool header; subtract it to get
            // the usable portion, then divide by slot size to get worker count.
            let avail = zone.shm.size.saturating_sub(crate::shm::data_offset());
            (avail / core::mem::size_of::<crate::shm::WorkerSlots>()).max(1)
        };
        metrics.extend(
            InstrumentedSource {
                base,
                n_workers,
                start_time_unix_nano: worker_start_ns,
                status_code_class_enabled: amcf.status_code_class_enabled(),
                amcf: amcf as *const crate::config::MainConfig,
            }
            .collect(),
        );
    }

    // 3. Self-metrics (dropped_records, send_failures, export_interval).
    metrics.extend(
        SelfMetricsSource {
            interval_ms: amcf.interval_ms(),
            start_time_unix_nano: worker_start_ns,
        }
        .collect(),
    );

    // 4. Error-log event rate metric.
    //    Collected from metrics shm when error_log is enabled and shm is mapped.
    if amcf.error_log_enabled {
        if let Some(base) = amcf.shm_base() {
            // SAFETY: `shm_base()` returned `Some`, so the metrics zone is
            // mapped and `amcf.shm_zone` points to a live `ngx_shm_zone_t`
            // valid for the exporter's lifetime. The `&*` borrow does not
            // escape this block; `shm.size` is a plain field read.
            let n_workers = unsafe {
                let zone = &*amcf.shm_zone;
                let avail = zone.shm.size.saturating_sub(crate::shm::data_offset());
                (avail / core::mem::size_of::<crate::shm::WorkerSlots>()).max(1)
            };
            metrics.push(collect_error_rate_metric(base, n_workers, worker_start_ns));
        }
    }

    // 5. Serving-certificate gauges (TLS cert metrics).
    //    `cert_table` is populated once at postconfiguration and immutable
    //    afterwards; the exporter inherited it at fork. When the table is empty
    //    (no-ssl nginx build, or no `ssl_certificate` configured) the source
    //    yields NO metrics, so the three `ngx_otel.tls.certificate.*` series
    //    are ABSENT — not present-as-zero.
    metrics.extend(ServingCertSource { certs: &amcf.cert_table }.collect());

    // 6. Collector-cert gauge.
    //    Emitted only once the first TLS handshake with the collector has
    //    completed (COLLECTOR_CERT_NOT_AFTER != 0).  Plaintext endpoints and
    //    pre-handshake state → metric ABSENT rather than reported as zero.
    //    The value is stable per exporter generation (same cert per collector
    //    endpoint; each successful handshake writes the same epoch value).
    {
        let not_after = COLLECTOR_CERT_NOT_AFTER.load(Ordering::Relaxed);
        if not_after != 0 {
            let now_ns = crate::util::now_unix_nano();
            metrics.push(collector_cert_gauge(not_after, now_ns, collector_host));
        }
    }

    Batch {
        resource: Resource { attributes: build_resource_attrs(amcf) },
        scope: Scope { name: "ngx-otel-rust".into(), version: env!("CARGO_PKG_VERSION").into() },
        metrics,
    }
}

/// Drain all worker access-log and error-log rings and assemble a [`LogsBatch`].
///
/// Called once per export tick when `any_log_export_enabled()` is true.
/// Drains exception-tail records written for operator-selected requests
/// (access) and error records written by the `ngx_otel_error_writer` hook
/// (error logs).
///
/// Updates `ACCESS_LOGS_DROPPED` from each ring's `drop_count()`.
/// Updates `ERROR_LOGS_DROPPED` from the error ring's `drop_count()`.
///
/// **Orphaned coalesced counts:** after ring drain, any entry in the
/// coalescer `counts_vec` whose `template_hash` was NOT matched by a ring
/// record (meaning the verbatim ring push failed — ring full) gets a
/// synthetic `LogRecord` with `body = "(ring-full: verbatim sample dropped
/// — occurrence count preserved)"`, `nginx.error.template_hash`, and
/// `nginx.error.coalesced_count` attributes.  `ERROR_LOGS_COALESCED_ORPHANED`
/// is incremented by the total orphaned occurrence count.
fn collect_log_records(
    amcf: &MainConfig,
    logs_base: *mut u8,
    n_workers: usize,
    _now_ns: u64,
) -> LogsBatch {
    let now = crate::util::now_unix_nano();

    let mut logs: std::vec::Vec<LogRecord> = std::vec::Vec::new();
    let mut total_dropped: u64 = 0;

    let cap = amcf.log_ring_cap();

    // Per-ring, per-worker drain caps. These are applied INDEPENDENTLY to the
    // access and error loops below (each loop has its own `drained` counter) —
    // there is no shared budget, so a high access volume cannot starve the
    // error drain.
    //
    // Access cap bounds the HTTP POST body: at ~200 bytes/record, 2 500
    // records/worker = ~500 KB/worker → total batch ≤ 2 MB for N ≤ 4 workers,
    // well within the collector's max request body (default 20 MB for
    // otelcol-contrib). Remaining records stay in the ring for the next 250 ms
    // wake; access logs are drop-tolerant by design.
    const MAX_ACCESS_RECORDS_PER_WORKER_PER_DRAIN: usize = 2_500;

    // Error cap is deliberately larger. Error logs are low-volume (the whole
    // point of template coalescing) AND carry an enrichment-coherence
    // constraint the access path does not: the coalescer table is drained and
    // reset once per interval (below), so the verbatim sample for a key must be
    // drained from the ring in the SAME interval its coalescer count is read,
    // or that sample arrives next interval with `coalesced_count == 0` (the
    // record body still ships; only the ×N enrichment is lost). Sizing the cap
    // generously keeps the ring drain ahead of the coalescer reset under any
    // realistic error rate; bounding it at all still guards body size against a
    // pathological error storm.
    const MAX_ERROR_RECORDS_PER_WORKER_PER_DRAIN: usize = 50_000;

    // Drain access rings for all workers.
    for w in 0..n_workers {
        // Safety: zone was sized for n_workers at registration; w < n_workers.
        let ring = unsafe { logs_access_ring(logs_base, w, cap) };

        // Accumulate drop counts.
        total_dropped += ring.drop_count();

        // Drain up to MAX_ACCESS_RECORDS_PER_WORKER_PER_DRAIN records per worker.
        let mut record_buf: std::vec::Vec<u8> = std::vec::Vec::new();
        let mut drained = 0usize;
        while drained < MAX_ACCESS_RECORDS_PER_WORKER_PER_DRAIN && ring.pop_into(&mut record_buf) {
            // Parse the wire format from access.rs:
            // [0] kind(1) [1..9] ts_unix_nano_be [9] ngx_level [10..12] method_len
            // [12..12+method_len] method [12+ml..14+ml] status_u16
            // [14+ml..22+ml] req_len [22+ml..30+ml] resp_bytes
            // [30+ml..32+ml] client_addr_len [32+ml..] client_addr
            if let Some(lr) = parse_access_record(&record_buf, now) {
                logs.push(lr);
            }
            record_buf.clear();
            drained += 1;
        }
    }

    // Update the ACCESS_LOGS_DROPPED self-metric.
    ACCESS_LOGS_DROPPED.store(total_dropped, Ordering::Relaxed);

    // Drain error rings: only when error_log_enabled.
    if amcf.error_log_enabled {
        let mut error_dropped: u64 = 0;
        for w in 0..n_workers {
            // 1. Drain the coalescer table to get (key_hash, severity, count) tuples.
            //    Safety: zone sized for n_workers; w < n_workers; cap correct.
            let coalesce_tbl = unsafe { logs_coalesce_table(logs_base, w, cap) };
            // SAFETY: `coalesce_tbl` is the in-zone coalescer-table pointer just
            // obtained from `logs_coalesce_table`, valid for the zone mapping;
            // the exporter is the single reader/draining process, so the
            // in-place reset performed by `drain_coalesce_table` does not race a
            // concurrent drainer.
            let counts_vec = unsafe { coalesce::drain_coalesce_table(coalesce_tbl) };
            // Build a lookup: key_hash → count (number of occurrences in this interval,
            // including the initial verbatim sample that was already pushed to the ring).
            // Keep `counts_vec` alive for the orphaned-count pass below.
            let counts_map: std::collections::HashMap<u64, u32> =
                counts_vec.iter().map(|&(hash, _sev, count)| (hash, count)).collect();

            // 2. Drain error ring records for this worker.
            //    Safety: same invariants as the access ring drain above.
            let ring = unsafe { logs_error_ring(logs_base, w, cap) };
            error_dropped += ring.drop_count();

            // Track which template_hashes are consumed by ring records so we can
            // detect orphaned coalesced counts (whose verbatim ring push failed).
            // template_hash lives at bytes [10..18] of each error ring record.
            let mut consumed_hashes: std::collections::HashSet<u64> =
                std::collections::HashSet::new();

            let mut record_buf: std::vec::Vec<u8> = std::vec::Vec::new();
            let mut drained = 0usize;
            while drained < MAX_ERROR_RECORDS_PER_WORKER_PER_DRAIN && ring.pop_into(&mut record_buf)
            {
                // Parse FIRST, then mark the template_hash consumed only on a
                // successful parse: a torn/rejected record that fails validation
                // must NOT suppress the synthetic orphaned-coalesced record for the
                // same hash below — otherwise a dropped record silently loses its
                // occurrence count. `parse_error_record_consuming` bundles that
                // ordering: the consumed-hash is `Some` only when the record parsed.
                let (parsed, consumed) =
                    parse_error_record_consuming(&record_buf, now, &counts_map);
                if let Some(lr) = parsed {
                    if let Some(th) = consumed {
                        consumed_hashes.insert(th);
                    }
                    logs.push(lr);
                }
                record_buf.clear();
                drained += 1;
            }

            // Emit a synthetic log record for every counts_vec entry whose
            // verbatim ring push was dropped (ring full) — the template_hash was never
            // seen in any ring record consumed above.  The synthetic record carries
            // the coalesced_count so the backend receives the occurrence total even
            // without the original error message body.
            let mut orphaned_total: u64 = 0;
            for &(hash, severity, count) in &counts_vec {
                if count > 0 && !consumed_hashes.contains(&hash) {
                    let (severity_number, severity_text) = nginx_to_otel(severity as u32);
                    logs.push(LogRecord {
                        time_unix_nano: now,
                        observed_time_unix_nano: now,
                        severity_number,
                        severity_text: std::string::String::from(severity_text),
                        body: AnyValue::String(std::string::String::from(
                            "(ring-full: verbatim sample dropped — occurrence count preserved)",
                        )),
                        attributes: std::vec![
                            KeyValue {
                                key: "nginx.error.template_hash".into(),
                                value: AnyValue::Int(hash as i64),
                            },
                            KeyValue {
                                key: "nginx.error.coalesced_count".into(),
                                value: AnyValue::Int(count as i64),
                            },
                        ],
                        event_name: "nginx.error".into(),
                        trace_id: std::vec::Vec::new(),
                        span_id: std::vec::Vec::new(),
                    });
                    orphaned_total += count as u64;
                }
            }
            if orphaned_total > 0 {
                // Accumulate additively — orphaned counts are per-interval.
                ERROR_LOGS_COALESCED_ORPHANED.fetch_add(orphaned_total, Ordering::Relaxed);
            }
        }
        ERROR_LOGS_DROPPED.store(error_dropped, Ordering::Relaxed);
    }

    LogsBatch {
        resource: Resource { attributes: build_resource_attrs(amcf) },
        scope: Scope { name: "ngx-otel-rust".into(), version: env!("CARGO_PKG_VERSION").into() },
        logs,
    }
}

/// Drain all worker spans rings and assemble a [`SpansBatch`].
///
/// Called once per sub-interval tick (every [`SHUTDOWN_POLL_INTERVAL`])
/// when the spans shm zone is mapped.  Mirrors [`collect_log_records`].
///
/// Updates `TRACES_DROPPED_RECORDS` from each ring's `drop_count()`.
fn collect_span_records(amcf: &MainConfig, spans_base: *mut u8, n_workers: usize) -> SpansBatch {
    let now = crate::util::now_unix_nano();

    let mut spans: std::vec::Vec<Span> = std::vec::Vec::new();
    let mut total_dropped: u64 = 0;

    let cap = DEFAULT_SPAN_RING_CAP;

    // Per-ring span drain cap. Mirrors the access-log cap sizing rationale:
    // at ~200 bytes/record serialised to protobuf, 2 500 records/worker
    // fits comfortably within the collector's default 20 MB request limit
    // for up to ~4 workers. Remaining records stay in the ring for the
    // next SHUTDOWN_POLL_INTERVAL wake.
    const MAX_SPAN_RECORDS_PER_WORKER_PER_DRAIN: usize = 2_500;

    for w in 0..n_workers {
        // SAFETY: spans zone was sized for n_workers at registration; w < n_workers.
        let ring = unsafe { spans_ring(spans_base, w, cap) };

        total_dropped += ring.drop_count();

        let mut record_buf: std::vec::Vec<u8> = std::vec::Vec::new();
        let mut drained = 0usize;
        while drained < MAX_SPAN_RECORDS_PER_WORKER_PER_DRAIN && ring.pop_into(&mut record_buf) {
            if let Some(span) = crate::traces::parse_span_record(&record_buf, now) {
                spans.push(span);
            }
            record_buf.clear();
            drained += 1;
        }
    }

    TRACES_DROPPED_RECORDS.store(total_dropped, Ordering::Relaxed);

    SpansBatch {
        resource: Resource { attributes: build_resource_attrs(amcf) },
        scope: Scope { name: "ngx-otel-rust".into(), version: env!("CARGO_PKG_VERSION").into() },
        spans,
    }
}

/// Parse one access log record from the wire-format bytes produced by
/// `logs::access::emit_access_record`.
///
/// Returns `None` if the buffer is too short to be a valid record.
fn parse_access_record(buf: &[u8], observed_now_ns: u64) -> Option<LogRecord> {
    use crate::data_model::{AnyValue, KeyValue};

    // Minimum: kind(1) + ts(8) + level(1) + method_len(2) + status(2) +
    //          req_len(8) + resp_bytes(8) + client_addr_len(2) = 32 bytes
    if buf.len() < 32 {
        return None;
    }

    let mut pos = 0usize;

    // kind must be KIND_ACCESS (access)
    if buf[pos] != crate::logs::access::KIND_ACCESS {
        return None;
    }
    pos += 1;

    // ts_unix_nano (8 bytes, big-endian)
    let ts = u64::from_be_bytes(buf[pos..pos + 8].try_into().ok()?);
    pos += 8;

    // ngx_level (1 byte) → severity
    let ngx_level = buf[pos] as u32;
    let (severity_number, severity_text) = nginx_to_otel(ngx_level);
    pos += 1;

    // method (2-byte len + bytes)
    let method_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if pos + method_len > buf.len() {
        return None;
    }
    let method = std::string::String::from_utf8_lossy(&buf[pos..pos + method_len]).into_owned();
    pos += method_len;

    // status code (2 bytes)
    if pos + 2 > buf.len() {
        return None;
    }
    let status = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;

    // request_length (8 bytes)
    if pos + 8 > buf.len() {
        return None;
    }
    let req_len = u64::from_be_bytes(buf[pos..pos + 8].try_into().ok()?);
    pos += 8;

    // response_bytes (8 bytes)
    if pos + 8 > buf.len() {
        return None;
    }
    let resp_bytes = u64::from_be_bytes(buf[pos..pos + 8].try_into().ok()?);
    pos += 8;

    // client_address (2-byte len + bytes)
    if pos + 2 > buf.len() {
        return None;
    }
    let addr_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    let client_addr = if pos + addr_len <= buf.len() {
        let s = std::string::String::from_utf8_lossy(&buf[pos..pos + addr_len]).into_owned();
        pos += addr_len;
        s
    } else {
        std::string::String::new()
    };

    // ── Trace context + high-cardinality tail detail ─────────────────────────
    // These follow client_addr in the wire format (see `emit_access_record`).
    // Decode defensively — a truncated/legacy record simply omits them.
    let mut trace_id: std::vec::Vec<u8> = std::vec::Vec::new();
    let mut span_id: std::vec::Vec<u8> = std::vec::Vec::new();
    if pos < buf.len() {
        let has_trace = buf[pos];
        pos += 1;
        if has_trace == 1 && pos + 24 <= buf.len() {
            trace_id = buf[pos..pos + 16].to_vec();
            pos += 16;
            span_id = buf[pos..pos + 8].to_vec();
            pos += 8;
        }
    }
    // url.path then user_agent.original (each: u16 len + bytes). Tail-only,
    // high-cardinality — never promoted to a metric dimension.
    let url_path = read_u16_prefixed(buf, &mut pos);
    let user_agent = read_u16_prefixed(buf, &mut pos);

    // Request duration in µs.
    // Appended after high-cardinality fields; absent in legacy records → None.
    // Last field — `pos` is not incremented (no further reads use it).
    let duration_us: Option<u64> = if pos + 8 <= buf.len() {
        Some(u64::from_be_bytes(buf[pos..pos + 8].try_into().ok()?))
    } else {
        None
    };

    let mut attributes = std::vec![
        KeyValue { key: "http.request.method".into(), value: AnyValue::String(method) },
        KeyValue { key: "http.response.status_code".into(), value: AnyValue::Int(status as i64) },
        KeyValue {
            key: "http.server.request.body.size".into(),
            value: AnyValue::Int(req_len as i64),
        },
        KeyValue {
            key: "http.server.response.body.size".into(),
            value: AnyValue::Int(resp_bytes as i64),
        },
        KeyValue { key: "client.address".into(), value: AnyValue::String(client_addr) },
    ];
    if !url_path.is_empty() {
        attributes.push(KeyValue {
            key: "url.path".into(),
            value: AnyValue::String(std::string::String::from_utf8_lossy(&url_path).into_owned()),
        });
    }
    if !user_agent.is_empty() {
        attributes.push(KeyValue {
            key: "user_agent.original".into(),
            value: AnyValue::String(std::string::String::from_utf8_lossy(&user_agent).into_owned()),
        });
    }
    if let Some(dur_us) = duration_us {
        // OTel semconv unit for request duration is seconds (double).
        // Preserve sub-millisecond precision by converting from µs.
        let dur_secs = dur_us as f64 / 1_000_000.0;
        attributes.push(KeyValue {
            key: "http.server.request.duration".into(),
            value: AnyValue::Double(dur_secs),
        });
    }

    Some(LogRecord {
        time_unix_nano: ts,
        observed_time_unix_nano: observed_now_ns,
        severity_number,
        severity_text: std::string::String::from(severity_text),
        body: AnyValue::String(std::string::String::new()), // body empty for access logs
        attributes,
        event_name: "http.access".into(),
        trace_id,
        span_id,
    })
}

/// Parse one error-log ring record and build a `LogRecord`.
///
/// Wire format (see `logs::error_writer::push_error_record`):
/// ```text
/// [0]      kind = 0x01
/// [1..9]   ts_unix_ns (u64 big-endian)
/// [9]      ngx_level  (u8)
/// [10..18] template_hash (u64 big-endian; 0 = untracked)
/// [18..20] body_len (u16 big-endian)
/// [20..]   body bytes
/// ```
///
/// `counts_map` is the result of draining the coalescer table for this worker
/// (key_hash → total occurrences this interval).  When `template_hash` is present
/// in the map and `count > 1`, the `nginx.error.coalesced_count` attribute is
/// attached to indicate that the verbatim sample represents N occurrences.
///
/// # Error-record invariants (non-negotiable)
/// - NO `trace_id` / `span_id` — request context is unreachable from the writer.
/// - NO `http.route` or `nginx.upstream.zone` attributes.
/// - `event_name = "nginx.error"`
/// - Body carries the full verbatim formatted line (including any `, client:` context).
fn parse_error_record(
    buf: &[u8],
    observed_now_ns: u64,
    counts_map: &std::collections::HashMap<u64, u32>,
) -> Option<LogRecord> {
    use crate::data_model::{AnyValue, KeyValue};
    use crate::logs::error_writer::ERROR_RECORD_HDR as HDR;

    // Minimum length: ERROR_RECORD_HDR (HDR) bytes
    if buf.len() < HDR {
        return None;
    }
    // kind must be 0x01 (error record)
    if buf[0] != crate::logs::error_writer::KIND_ERROR {
        return None;
    }

    let ts = u64::from_be_bytes(buf[1..9].try_into().ok()?);
    let ngx_level = buf[9] as u32;
    let template_hash = u64::from_be_bytes(buf[10..18].try_into().ok()?);
    let body_len = u16::from_be_bytes([buf[18], buf[19]]) as usize;

    if HDR + body_len > buf.len() {
        return None;
    }
    let body_bytes = &buf[HDR..HDR + body_len];
    let body_str = std::string::String::from_utf8_lossy(body_bytes).into_owned();

    let (severity_number, severity_text) = nginx_to_otel(ngx_level);

    // Build attributes: NO route/zone/trace_id.
    let mut attributes: std::vec::Vec<KeyValue> = std::vec::Vec::new();

    // nginx.error.template_hash: carry the hash so backends can group by template.
    // Absent when template_hash == 0 (untracked: high-sev / coalesce-off / table-full).
    if template_hash != 0 {
        attributes.push(KeyValue {
            key: "nginx.error.template_hash".into(),
            value: AnyValue::Int(template_hash as i64),
        });

        // nginx.error.coalesced_count: present when > 1 occurrence was coalesced.
        // Lookup the drain count; absent (not == 0) when count ≤ 1.
        let count = counts_map.get(&template_hash).copied().unwrap_or(0);
        if count > 1 {
            attributes.push(KeyValue {
                key: "nginx.error.coalesced_count".into(),
                value: AnyValue::Int(count as i64),
            });
        }
    }

    Some(LogRecord {
        time_unix_nano: ts,
        observed_time_unix_nano: observed_now_ns,
        severity_number,
        severity_text: std::string::String::from(severity_text),
        body: AnyValue::String(body_str),
        attributes,
        event_name: "nginx.error".into(),
        trace_id: std::vec::Vec::new(), // no trace context on error records
        span_id: std::vec::Vec::new(),  // no trace context on error records
    })
}

/// Parse an error ring record AND, only if it parsed, the non-zero
/// `template_hash` the caller should mark consumed.
///
/// Returns `(parsed_record, consumed_hash)`. The hash is `Some` ONLY when
/// `parse_error_record` returned `Some`: a torn/rejected record that fails
/// validation MUST NOT consume its hash, otherwise it suppresses the synthetic
/// orphaned-coalesced record emitted for the same hash and the occurrence count
/// is silently lost. The `template_hash` lives at bytes `[10..18]` of the
/// record; `None` when the hash is zero (untracked: high-sev / coalesce-off /
/// table-full).
fn parse_error_record_consuming(
    buf: &[u8],
    observed_now_ns: u64,
    counts_map: &std::collections::HashMap<u64, u32>,
) -> (Option<LogRecord>, Option<u64>) {
    match parse_error_record(buf, observed_now_ns, counts_map) {
        Some(lr) => {
            // The record parsed (so it is at least HDR = 20 bytes), so [10..18]
            // is in bounds; extract the hash to consume.
            let th = u64::from_be_bytes(buf[10..18].try_into().unwrap_or([0u8; 8]));
            (Some(lr), (th != 0).then_some(th))
        }
        // Rejected record: do NOT consume any hash.
        None => (None, None),
    }
}

/// Read a `u16`-length-prefixed byte run at `*pos`, advancing `*pos` past it.
/// Returns empty (and leaves `*pos` unmoved past a partial header) on truncation.
fn read_u16_prefixed(buf: &[u8], pos: &mut usize) -> std::vec::Vec<u8> {
    if *pos + 2 > buf.len() {
        return std::vec::Vec::new();
    }
    let len = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]) as usize;
    *pos += 2;
    if *pos + len > buf.len() {
        return std::vec::Vec::new();
    }
    let v = buf[*pos..*pos + len].to_vec();
    *pos += len;
    v
}

/// Build a monotonic cumulative Sum metric carrying a single i64 data point.
///
/// `start_time_unix_nano` must be the time the worker (and therefore the
/// counter) started. OTel cumulative semantics require this so rate
/// computations across collector restarts work correctly; a `0` start time
/// means epoch (1970) and confuses delta-conversion processors.
pub(crate) fn monotonic_sum_metric(
    name: &str,
    desc: &str,
    unit: &str,
    value: i64,
    start_time_ns: u64,
    time_ns: u64,
) -> Metric {
    Metric {
        name: name.into(),
        description: desc.into(),
        unit: unit.into(),
        data: MetricData::Sum(SumData {
            aggregation_temporality: AggregationTemporality::Cumulative,
            is_monotonic: true,
            data_points: std::vec![NumberDataPoint {
                attributes: std::vec![],
                start_time_unix_nano: start_time_ns,
                time_unix_nano: time_ns,
                value: NumberValue::AsInt(value),
            }],
        }),
    }
}

/// Build a Gauge metric carrying a single i64 data point.
fn gauge_metric(name: &str, desc: &str, unit: &str, value: i64, time_ns: u64) -> Metric {
    Metric {
        name: name.into(),
        description: desc.into(),
        unit: unit.into(),
        data: MetricData::Gauge(GaugeData {
            data_points: std::vec![NumberDataPoint {
                attributes: std::vec![],
                start_time_unix_nano: 0,
                time_unix_nano: time_ns,
                value: NumberValue::AsInt(value),
            }],
        }),
    }
}

/// Build the collector-cert Gauge with a single data point.
///
/// `server_address` is the collector hostname or IP-literal (parsed from the
/// configured `otel_exporter` endpoint).  Only one attribute is emitted — per
/// the scope guard — exactly as documented in `TELEMETRY_MODEL.md`.
fn collector_cert_gauge(not_after: i64, time_ns: u64, server_address: &str) -> Metric {
    Metric {
        name: "ngx_otel.tls.collector_cert.not_after".into(),
        description: "Collector TLS certificate notAfter (Unix epoch seconds), \
                      captured post-handshake; absent before the first TLS \
                      handshake and on plaintext (http://) endpoints"
            .into(),
        unit: "s".into(),
        data: MetricData::Gauge(GaugeData {
            data_points: std::vec![NumberDataPoint {
                attributes: std::vec![KeyValue {
                    key: "server.address".into(),
                    value: AnyValue::String(server_address.into()),
                }],
                start_time_unix_nano: 0,
                time_unix_nano: time_ns,
                value: NumberValue::AsInt(not_after),
            }],
        }),
    }
}

/// Build the `ngx_otel.error_log.events` Sum metric.
///
/// Sums `WorkerSlots::error_rate_counters` across all workers, producing one
/// data point per severity class with attribute `severity_class = "fatal"|"error"|…`.
///
/// The counter is monotonically increasing and Cumulative — once started, it
/// always reflects total events since worker startup, not a rate per interval.
///
/// # Safety
/// `base` must point to the start of the metrics shm zone (past the slab header).
/// `n_workers` must be ≤ number of slots the zone was sized for.
fn collect_error_rate_metric(base: *mut u8, n_workers: usize, start_time_ns: u64) -> Metric {
    use crate::shm::{worker_slots, N_SEVERITY_CLASSES, SEVERITY_CLASS_NAMES};
    use core::sync::atomic::Ordering;

    let now = crate::util::now_unix_nano();

    // Sum each severity class across all workers.
    let mut totals = [0i64; N_SEVERITY_CLASSES];
    for w in 0..n_workers {
        // SAFETY: per this fn's contract `base` is the metrics zone start (past
        // the slab header) and `n_workers` is ≤ the slot count the zone was
        // sized for, so `w < n_workers` makes `worker_slots(base, w)` an
        // in-bounds, initialised `WorkerSlots`; the `&*` borrow lives only for
        // this iteration and all reads below go through `AtomicU64` fields.
        let slots = unsafe { &*worker_slots(base, w) };
        for (i, cnt) in slots.error_rate_counters.iter().enumerate() {
            totals[i] = totals[i].saturating_add(counter_to_i64(cnt.load(Ordering::Acquire)));
        }
    }

    // Build one data point per severity class.
    let data_points: std::vec::Vec<NumberDataPoint> = (0..N_SEVERITY_CLASSES)
        .map(|i| NumberDataPoint {
            attributes: std::vec![KeyValue {
                key: "severity_class".into(),
                value: AnyValue::String(SEVERITY_CLASS_NAMES[i].into()),
            }],
            start_time_unix_nano: start_time_ns,
            time_unix_nano: now,
            value: NumberValue::AsInt(totals[i]),
        })
        .collect();

    Metric {
        name: "ngx_otel.error_log.events".into(),
        description: "Error log events counted by severity class".into(),
        unit: "{error}".into(),
        data: MetricData::Sum(SumData {
            aggregation_temporality: AggregationTemporality::Cumulative,
            is_monotonic: true,
            data_points,
        }),
    }
}

// ── exit_process flush ────────────────────────────────────────────────────────

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the retry queue never exceeds the configured depth and that
    /// `DROPPED_RECORDS` is incremented by the correct data-point count when
    /// items are evicted. Exercises the **real** `enqueue_with_eviction` helper
    /// (not an inlined copy) by passing `null_mut()` as the log — the helper
    /// guards against that.
    #[test]
    fn retry_buffer_stays_bounded_and_drops_are_counted() {
        let depth: usize = 4;
        let mut queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();

        // Sum the helper's RETURN value (dropped data-point count) instead of
        // reading the process-global DROPPED_RECORDS: other tests mutate that
        // global concurrently, so an absolute read — or even a before/after
        // delta — is racy. The return value is fully test-local.
        let mut dropped: u64 = 0;
        for i in 0..(depth + 2) as u64 {
            dropped += enqueue_with_eviction(
                &mut queue,
                std::vec![i as u8],
                i + 1,
                depth,
                core::ptr::null_mut(),
            );
        }

        // Queue must be bounded at depth.
        assert_eq!(queue.len(), depth, "retry queue must not exceed configured depth = {}", depth);

        // The two evicted items had n_pts = 1 and n_pts = 2.
        assert_eq!(dropped, 1 + 2, "evicted data-point counts (helper return) must sum to 3");
    }

    /// F6 regression: graceful_drain abort for logs/spans credits DROPPED_RECORDS.
    ///
    /// Pre-fix behaviour: `queues.logs.clear()` / `queues.spans.clear()` were
    /// called without computing `remaining`, so queued records were silently
    /// discarded without incrementing any drop counter.
    ///
    /// This test calls the PRODUCTION `account_drops_and_clear` function
    /// (extracted from `graceful_drain`'s send-failed / timeout arms for both
    /// logs and spans lanes).  Reverting the `fetch_add` inside that function
    /// causes this test to FAIL — ensuring the test is not teethless.
    #[test]
    fn f6_drain_abort_credits_dropped_records_for_logs_and_spans() {
        // Prepare a logs retry queue with 2 entries (13 + 7 = 20 records).
        let mut logs_q: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();
        logs_q.push_back((std::vec![0u8], 13));
        logs_q.push_back((std::vec![0u8], 7));

        // Prepare a spans retry queue with 1 entry (42 records).
        let mut spans_q: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();
        spans_q.push_back((std::vec![0u8], 42));

        // Baseline before the drain-abort accounting runs.
        let before = DROPPED_RECORDS.load(Ordering::Acquire);

        // Call the PRODUCTION function — not an inline reimplementation.
        super::account_drops_and_clear(&mut logs_q, &DROPPED_RECORDS);
        super::account_drops_and_clear(&mut spans_q, &DROPPED_RECORDS);

        let after = DROPPED_RECORDS.load(Ordering::Acquire);
        // Pre-fix: no fetch_add in account_drops_and_clear → after == before
        // Post-fix: 13 + 7 + 42 = 62 records credited
        assert!(
            after >= before + 62,
            "DROPPED_RECORDS must increase by ≥ 62 (13 + 7 + 42); \
             delta = {}",
            after.saturating_sub(before)
        );

        // Both queues must be empty after the abort.
        assert!(logs_q.is_empty(), "logs queue must be empty after drain abort");
        assert!(spans_q.is_empty(), "spans queue must be empty after drain abort");
    }

    /// SelfMetricsSource must produce exactly 13 metrics with the right names
    /// (4 original + 4 log + 1 traces + 1 crash-loop + 3 delivery-outcome).
    #[test]
    fn self_metrics_source_produces_four_metrics() {
        let src = SelfMetricsSource {
            interval_ms: 10_000,
            start_time_unix_nano: 1_700_000_000_000_000_000,
        };
        let metrics = src.collect();
        assert_eq!(
            metrics.len(),
            13,
            "SelfMetricsSource must emit 13 metrics \
             (4 original + 4 log + 1 traces + 1 crash-loop + 3 delivery-outcome); \
             got {}: {names:?}",
            metrics.len(),
            names = metrics.iter().map(|m| m.name.as_str()).collect::<std::vec::Vec<_>>(),
        );

        let names: std::vec::Vec<&str> = metrics.iter().map(|m| m.name.as_str()).collect();
        // Original 4
        assert!(names.contains(&"ngx_otel.dropped_records"));
        assert!(names.contains(&"ngx_otel.send_failures"));
        assert!(names.contains(&"ngx_otel.bidi_backpressure_drops"));
        assert!(names.contains(&"ngx_otel.export_interval"));
        // 4 log metrics (3 original + orphaned-count metric)
        assert!(names.contains(&"ngx_otel.logs.access.dropped_records"));
        assert!(names.contains(&"ngx_otel.logs.error.dropped_records"));
        assert!(names.contains(&"ngx_otel.logs.error.coalesced_orphaned_records"));
        assert!(names.contains(&"ngx_otel.logs.send_failures"));
        // Traces drop metric
        assert!(
            names.contains(&"ngx_otel.traces.dropped_records"),
            "traces.dropped_records must appear in self-metrics; names = {names:?}"
        );
        // Crash-loop restart gauge
        assert!(
            names.contains(&"ngx_otel.exporter.restarts"),
            "exporter.restarts must appear in self-metrics; names = {names:?}"
        );
        // Delivery-outcome monotonic Sums (read the delivery-outcome atomics)
        assert!(
            names.contains(&"ngx_otel.delivery.permanent_rejected"),
            "delivery.permanent_rejected must appear in self-metrics; names = {names:?}"
        );
        assert!(
            names.contains(&"ngx_otel.delivery.partial_rejected"),
            "delivery.partial_rejected must appear in self-metrics; names = {names:?}"
        );
        assert!(
            names.contains(&"ngx_otel.delivery.unauthorized"),
            "delivery.unauthorized must appear in self-metrics; names = {names:?}"
        );
    }

    /// `collect_log_records` with empty rings produces an empty LogsBatch.
    #[test]
    fn logs_drain_handles_empty_rings() {
        use crate::logs::ring::{
            ring_size_bytes, LogsWorkerRingHeader, DEFAULT_LOG_RING_CAP, RING_HEADER_SIZE,
        };
        use crate::shm::logs_slot_size;

        // Allocate one worker slot with default cap.
        let cap = DEFAULT_LOG_RING_CAP;
        let slot_sz = logs_slot_size(cap);
        let layout = std::alloc::Layout::from_size_align(slot_sz, 8).unwrap();
        // SAFETY: `slot_sz = logs_slot_size(cap) > 0`, so the layout is valid and
        // non-zero-sized; `alloc_zeroed` returns a buffer sized for one full logs
        // slot, 8-byte aligned (matching the ring header's alignment).
        let slot_ptr = unsafe { std::alloc::alloc_zeroed(layout) };

        // Stamp cap into both ring headers (mirrors logs_shm_zone_init).
        // SAFETY: `slot_ptr` is the start of the just-zeroed `slot_sz` buffer; the
        // access header lives at offset 0 and the error header one
        // `ring_size_bytes(cap)` in, both within the slot, and `cap` is an
        // `AtomicU64`. The buffer is 8-byte aligned for `LogsWorkerRingHeader`.
        unsafe {
            let access_hdr = slot_ptr.cast::<LogsWorkerRingHeader>();
            (*access_hdr).cap.store(cap as u64, Ordering::Relaxed);
            let error_hdr = slot_ptr.add(ring_size_bytes(cap)).cast::<LogsWorkerRingHeader>();
            (*error_hdr).cap.store(cap as u64, Ordering::Relaxed);
        }

        // Synthesize a minimal config (log_ring_cap() = DEFAULT_LOG_RING_CAP).
        let amcf = crate::config::MainConfig::default();

        let batch = collect_log_records(&amcf, slot_ptr, 1, 0);
        assert!(batch.logs.is_empty(), "empty rings must produce empty LogsBatch");

        // SAFETY: `slot_ptr`/`layout` are the exact pointer and layout returned
        // by the `alloc_zeroed` above and the buffer is no longer referenced.
        unsafe { std::alloc::dealloc(slot_ptr, layout) };
        let _ = RING_HEADER_SIZE; // suppress unused import
    }

    /// `collect_log_records` drains rings and returns parsed LogRecords.
    #[test]
    fn logs_retry_eviction_increments_counter() {
        // Verify the logs retry queue is bounded with the same
        // enqueue_with_eviction helper. Assert on the helper's RETURN value
        // (dropped count), not the process-global DROPPED_RECORDS, which other
        // parallel tests mutate (test isolation).
        let depth: usize = 2;
        let mut queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();
        let mut dropped = 0u64;
        for i in 0..4u64 {
            dropped += enqueue_with_eviction(
                &mut queue,
                std::vec![0u8],
                i + 1,
                depth,
                core::ptr::null_mut(),
            );
        }
        assert_eq!(queue.len(), depth);
        // Evicted items had n=1, n=2 → dropped 3
        assert_eq!(dropped, 1 + 2);
    }

    // ── service.instance.id tests ────────────────────────────────────────────

    /// Helper: look up an attribute by key in a slice.
    fn find_attr<'a>(attrs: &'a [KeyValue], key: &str) -> Option<&'a AnyValue> {
        attrs.iter().find(|kv| kv.key == key).map(|kv| &kv.value)
    }

    /// (a) Metrics Resource and (b) logs Resource both carry `service.instance.id`.
    /// (b) Its value matches the MASTER_PID we set.
    /// (c) Two successive calls produce the same id (stability).
    #[test]
    fn service_instance_id_present_on_metrics_and_logs_resource() {
        use crate::logs::ring::{
            ring_size_bytes, LogsWorkerRingHeader, DEFAULT_LOG_RING_CAP, RING_HEADER_SIZE,
        };
        use crate::shm::logs_slot_size;

        let test_pid: i64 = 99_999;
        MASTER_PID.store(test_pid, Ordering::Relaxed);

        let amcf = crate::config::MainConfig::default();

        // ── (a) Metrics Resource ──────────────────────────────────────────────
        // Pass 1
        let batch1 = collect_all_sources(&amcf, 0, "");
        let id1 = find_attr(&batch1.resource.attributes, "service.instance.id")
            .expect("service.instance.id must be present in metrics Resource (pass 1)");
        assert_eq!(
            *id1,
            AnyValue::String(std::format!("{}", test_pid)),
            "service.instance.id value must equal the master PID (metrics, pass 1)"
        );

        // Pass 2 — stability: same id without changing MASTER_PID
        let batch2 = collect_all_sources(&amcf, 0, "");
        let id2 = find_attr(&batch2.resource.attributes, "service.instance.id")
            .expect("service.instance.id must be present in metrics Resource (pass 2)");
        assert_eq!(id1, id2, "service.instance.id must be stable across successive encode calls");

        // ── (b) Logs Resource ─────────────────────────────────────────────────
        let cap = DEFAULT_LOG_RING_CAP;
        let slot_sz = logs_slot_size(cap);
        let layout = std::alloc::Layout::from_size_align(slot_sz, 8).unwrap();
        // SAFETY: `slot_sz > 0` so the layout is valid and non-zero-sized;
        // `alloc_zeroed` returns a buffer sized for one logs slot, 8-byte aligned.
        let slot_ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        // SAFETY: `slot_ptr` is the start of the just-zeroed `slot_sz` buffer;
        // access header at offset 0, error header one `ring_size_bytes(cap)` in,
        // both within the slot; `cap` is an `AtomicU64` and the buffer is aligned
        // for `LogsWorkerRingHeader`.
        unsafe {
            let access_hdr = slot_ptr.cast::<LogsWorkerRingHeader>();
            (*access_hdr).cap.store(cap as u64, Ordering::Relaxed);
            let error_hdr = slot_ptr.add(ring_size_bytes(cap)).cast::<LogsWorkerRingHeader>();
            (*error_hdr).cap.store(cap as u64, Ordering::Relaxed);
        }
        let logs_batch = collect_log_records(&amcf, slot_ptr, 1, 0);
        // SAFETY: same pointer/layout returned by `alloc_zeroed` above; the
        // buffer is no longer referenced after `collect_log_records` returns.
        unsafe { std::alloc::dealloc(slot_ptr, layout) };
        let _ = RING_HEADER_SIZE;

        let logs_id = find_attr(&logs_batch.resource.attributes, "service.instance.id")
            .expect("service.instance.id must be present in logs Resource");
        assert_eq!(
            *logs_id,
            AnyValue::String(std::format!("{}", test_pid)),
            "service.instance.id value must equal the master PID (logs)"
        );
    }

    /// Inverse of `stub_status::tests::stub_status_produces_seven_metrics`.
    /// In a no-flag build (nginx without `--with-http_stub_status_module`, so
    /// `NGX_STAT_STUB` undefined → no `ngx_feature = "stat_stub"`), the stub_status
    /// `MetricSource` is not registered in `collect_all_sources`, so none of its 7
    /// series are emitted. We assert they are ABSENT from the real collection path —
    /// proving the permanently-zero series are gone, not present-as-zero. This test
    /// only compiles/runs in a no-stub build (e.g. debian-vm scenario-B config).
    #[cfg(not(ngx_feature = "stat_stub"))]
    #[test]
    fn collect_all_sources_omits_stub_status_without_stat_stub() {
        let amcf = crate::config::MainConfig::default();
        let batch = collect_all_sources(&amcf, 0, "");

        let stub_names = [
            "nginx.connections.accepted",
            "nginx.connections.handled",
            "nginx.requests.total",
            "nginx.connections.active",
            "nginx.connections.reading",
            "nginx.connections.writing",
            "nginx.connections.waiting",
        ];
        for m in &batch.metrics {
            assert!(
                !stub_names.contains(&m.name.as_str()),
                "stub_status series {} must be ABSENT in a no-stat_stub build",
                m.name
            );
        }
    }

    /// Registration-level absent-not-zero: with an EMPTY cert table the
    /// three `ngx_otel.tls.certificate.*` series are ABSENT from the real
    /// collection path; with a populated table all three appear. (Source-level
    /// arithmetic/attribute tests live in `metric_source::tls_cert`.)
    #[test]
    fn collect_all_sources_cert_series_absent_when_table_empty() {
        let cert_names = [
            crate::metric_source::tls_cert::NOT_AFTER,
            crate::metric_source::tls_cert::NOT_BEFORE,
            crate::metric_source::tls_cert::TIME_TO_EXPIRATION,
        ];

        // Empty table (the MainConfig default — also the no-ssl-build shape).
        let mut amcf = crate::config::MainConfig::default();
        let batch = collect_all_sources(&amcf, 0, "");
        for m in &batch.metrics {
            assert!(
                !cert_names.contains(&m.name.as_str()),
                "cert series {} must be ABSENT when the cert table is empty",
                m.name
            );
        }

        // Populated table → all three series present.
        amcf.cert_table.push(crate::cert_table::CertInfo {
            file_path: "/etc/ssl/a.crt".into(),
            server_name: "a.example.test".into(),
            not_before_unix: 1_700_000_000,
            not_after_unix: 1_893_456_000,
            subject_cn: "a.example.test".into(),
            issuer_cn: "Test CA".into(),
            serial: "01".into(),
            pubkey_alg: "RSA".into(),
            sig_alg: "RSA-SHA256".into(),
        });
        let batch = collect_all_sources(&amcf, 0, "");
        for name in cert_names {
            assert!(
                batch.metrics.iter().any(|m| m.name == name),
                "cert series {name} must be PRESENT when the cert table is populated"
            );
        }
    }

    /// The gRPC per-signal-endpoint warn predicate (the PRODUCTION
    /// `grpc_ignored_endpoint_names` fn that `export_loop` calls) returns exactly
    /// the names whose endpoint field is non-empty, in metrics/logs/traces order.
    /// Mutation evidence (commit msg): break the predicate (e.g. invert one
    /// `!field.is_empty()` to `field.is_empty()`) → this test FAILS → restore → PASSES.
    #[test]
    fn grpc_ignored_endpoint_names_predicate() {
        use nginx_sys::ngx_str_t;

        // Construct ngx_str_t values: empty == { len: 0, data: null }; set ==
        // pointing at a static byte string. Safety: bytes are 'static; the
        // ngx_str_t values only live for this test and the fn only reads `len`.
        let set_bytes = b"/v1/custom";
        let set = || ngx_str_t { len: set_bytes.len(), data: set_bytes.as_ptr().cast_mut() };
        let empty = || ngx_str_t { len: 0, data: core::ptr::null_mut() };

        // All empty → no warnings.
        assert_eq!(
            super::grpc_ignored_endpoint_names(&empty(), &empty(), &empty()),
            std::vec::Vec::<&str>::new(),
            "no endpoint set → no warning"
        );

        // Only logs set → exactly "logs".
        assert_eq!(
            super::grpc_ignored_endpoint_names(&empty(), &set(), &empty()),
            std::vec!["logs"],
            "only logs_endpoint set → warn for logs only"
        );

        // All set → all three, in metrics/logs/traces order.
        assert_eq!(
            super::grpc_ignored_endpoint_names(&set(), &set(), &set()),
            std::vec!["metrics", "logs", "traces"],
            "all set → warn for all three in order"
        );

        // metrics + traces set, logs empty → preserves order, skips logs.
        assert_eq!(
            super::grpc_ignored_endpoint_names(&set(), &empty(), &set()),
            std::vec!["metrics", "traces"],
            "metrics+traces set, logs empty → warn for metrics, traces"
        );
    }

    /// (d) An operator-supplied `service.instance.id` is NOT overridden.
    #[test]
    fn operator_service_instance_id_is_not_overridden() {
        use crate::config::KvPair;
        use nginx_sys::ngx_str_t;

        let test_pid: i64 = 12_345;
        MASTER_PID.store(test_pid, Ordering::Relaxed);

        // Build a config with an operator-supplied service.instance.id.
        // Construct KvPairs pointing at static byte strings.
        // Safety: the byte strings are `'static`; the KvPairs only live for this test.
        let key_bytes = b"service.instance.id";
        let operator_value = b"my-custom-instance";
        let mut amcf = crate::config::MainConfig::default();
        let kv = KvPair {
            key: ngx_str_t { len: key_bytes.len(), data: key_bytes.as_ptr().cast_mut() },
            value: ngx_str_t {
                len: operator_value.len(),
                data: operator_value.as_ptr().cast_mut(),
            },
        };
        amcf.resource_attrs.push(kv);

        let attrs = build_resource_attrs(&amcf);
        let id =
            find_attr(&attrs, "service.instance.id").expect("service.instance.id must be present");

        assert_eq!(
            *id,
            AnyValue::String("my-custom-instance".into()),
            "operator-provided service.instance.id must not be overridden by the default"
        );

        // Verify there's exactly ONE service.instance.id (no duplication).
        let count = attrs.iter().filter(|kv| kv.key == "service.instance.id").count();
        assert_eq!(count, 1, "service.instance.id must appear exactly once");
    }

    // ── Error-drain tests ────────────────────────────────────────────────────

    /// Helper: build a one-worker logs shm slot with initialised ring headers.
    fn make_logs_slot(cap: usize) -> (std::vec::Vec<u8>, *mut u8) {
        use crate::logs::ring::{ring_size_bytes, LogsWorkerRingHeader};
        use crate::shm::logs_slot_size;

        let slot_sz = logs_slot_size(cap);
        let mut buf = std::vec![0u8; slot_sz];
        let ptr = buf.as_mut_ptr();
        // SAFETY: `ptr` is the start of the just-zeroed `slot_sz`-byte `Vec`
        // buffer (Vec's allocation is suitably aligned for `LogsWorkerRingHeader`
        // here, with `RING_HEADER_SIZE` headroom); the access header sits at
        // offset 0 and the error header one `ring_size_bytes(cap)` in, both
        // within the slot, and `cap` is an `AtomicU64`. `buf` is returned so it
        // outlives every use of `ptr`.
        unsafe {
            let access_hdr = ptr.cast::<LogsWorkerRingHeader>();
            (*access_hdr).cap.store(cap as u64, Ordering::Relaxed);
            let error_hdr = ptr.add(ring_size_bytes(cap)).cast::<LogsWorkerRingHeader>();
            (*error_hdr).cap.store(cap as u64, Ordering::Relaxed);
        }
        (buf, ptr)
    }

    /// Tail LogRecord carries `http.server.request.duration` (double, seconds).
    ///
    /// Push a synthetic access record with a known `duration_us`, drain it, and assert:
    /// (1) the attribute is present, (2) the value is `duration_us / 1_000_000.0` seconds,
    /// (3) it is a `Double` (OTel semconv unit).
    #[test]
    fn access_tail_log_carries_duration_attribute() {
        use crate::logs::access::{emit_access_record, SampledRequest};
        use crate::logs::ring::DEFAULT_LOG_RING_CAP;
        use crate::logs::WorkerRingProducer;
        use crate::shm::logs_access_ring;

        let cap = DEFAULT_LOG_RING_CAP;
        let (mut slot_buf, slot_ptr) = make_logs_slot(cap);
        let _ = &mut slot_buf;

        // Known duration: 1_234_567 µs = 1.234567 seconds.
        let dur_us: u64 = 1_234_567;
        let req = SampledRequest {
            ts_unix_nano: 1_700_000_000_000_000_000,
            trace: None,
            url_path: b"/api/test",
            user_agent: b"TestAgent/1.0",
            duration_us: dur_us,
            combo_idx: 0,
            method: b"GET",
            status: 503,
            request_length: 0,
            response_bytes: 128,
            client_addr: b"10.0.0.1",
        };

        // SAFETY: `slot_ptr` is the one-worker logs slot from `make_logs_slot`
        // (correct `cap`, initialised headers); `worker_id = 0 < 1` worker, so
        // `logs_access_ring` yields a valid in-slot ring view and `push` touches
        // only that view's atomic header + in-bounds payload.
        unsafe {
            let ring = logs_access_ring(slot_ptr, 0, cap);
            let producer = WorkerRingProducer { ring };
            assert!(emit_access_record(&producer, &req), "ring push must succeed");
        }

        let amcf = crate::config::MainConfig::default();
        let batch = collect_log_records(&amcf, slot_ptr, 1, 0);

        assert_eq!(batch.logs.len(), 1, "one access LogRecord expected");
        let rec = &batch.logs[0];
        assert_eq!(rec.event_name, "http.access");

        // Find the duration attribute.
        let dur_attr = rec
            .attributes
            .iter()
            .find(|kv| kv.key == "http.server.request.duration")
            .expect("http.server.request.duration must be present on tail LogRecord");

        // Value must be a Double in seconds — 1_234_567 µs = 1.234567 s.
        let expected = dur_us as f64 / 1_000_000.0;
        match &dur_attr.value {
            AnyValue::Double(v) => {
                assert!(
                    (*v - expected).abs() < 1e-9,
                    "http.server.request.duration must equal {expected:.6} s, got {v:.9}"
                );
            }
            other => panic!("http.server.request.duration must be Double, got {other:?}"),
        }
    }

    /// Error drain alongside access drain — both rings drain into one `LogsBatch`.
    ///
    /// Push one access record and one error record, then call `collect_log_records`.
    /// The resulting batch must contain exactly two `LogRecord`s: one `http.access`
    /// and one `nginx.error`.
    #[test]
    fn error_drain_alongside_access_drain() {
        use crate::logs::error_writer::KIND_ERROR;
        use crate::logs::ring::DEFAULT_LOG_RING_CAP;
        use crate::shm::logs_error_ring;

        let cap = DEFAULT_LOG_RING_CAP;
        let (mut slot_buf, slot_ptr) = make_logs_slot(cap);
        let _ = &mut slot_buf; // keep alive

        // Push one error ring record directly (simulate what the writer does).
        let ts_ns: u64 = 1_700_000_000_000_000_000;
        let body = b"connect() failed (111: Connection refused)";
        let template_hash: u64 = 0xdeadbeef_cafebabe;
        // SAFETY: `slot_ptr` is the one-worker logs slot from `make_logs_slot`
        // (correct `cap`, initialised headers); `worker_id = 0 < 1` worker, so
        // `logs_error_ring` yields a valid in-slot ring view, and `push`
        // operates only on that view's atomic header + in-bounds payload.
        unsafe {
            let error_ring = logs_error_ring(slot_ptr, 0, cap);
            // Build and push the wire record manually.
            use crate::logs::error_writer::ERROR_RECORD_HDR;
            let body_len = body.len();
            let mut record = [0u8; ERROR_RECORD_HDR + 512];
            record[0] = KIND_ERROR;
            record[1..9].copy_from_slice(&ts_ns.to_be_bytes());
            record[9] = 4u8; // NGX_LOG_ERR
            record[10..18].copy_from_slice(&template_hash.to_be_bytes());
            record[18..20].copy_from_slice(&(body_len as u16).to_be_bytes());
            record[ERROR_RECORD_HDR..ERROR_RECORD_HDR + body_len].copy_from_slice(body);
            assert!(
                error_ring.push(&record[..ERROR_RECORD_HDR + body_len]),
                "error ring push must succeed"
            );
        }

        // Note: access ring is empty — we're testing that the error record still lands.
        // Synthesize a MainConfig with error_log_enabled = true.
        let amcf = crate::config::MainConfig {
            error_log_enabled: true,
            ..crate::config::MainConfig::default()
        };

        let batch = collect_log_records(&amcf, slot_ptr, 1, 0);

        // Must have exactly ONE record: the nginx.error entry.
        assert_eq!(batch.logs.len(), 1, "one error record must be drained");
        let rec = &batch.logs[0];
        assert_eq!(rec.event_name, "nginx.error", "event_name must be nginx.error");

        // Body must be the verbatim message.
        assert_eq!(
            rec.body,
            crate::data_model::AnyValue::String(
                std::string::String::from_utf8_lossy(body).into_owned()
            ),
            "body must be the verbatim error message"
        );

        // Severity must be ERROR (mapped from NGX_LOG_ERR = 4).
        assert_eq!(
            rec.severity_number,
            crate::data_model::SeverityNumber::Error,
            "severity must be ERROR for ngx_level=4"
        );

        // NO trace_id, span_id.
        assert!(rec.trace_id.is_empty(), "trace_id must be empty on error records");
        assert!(rec.span_id.is_empty(), "span_id must be empty on error records");

        // NO route / zone attributes.
        let has_route = rec.attributes.iter().any(|kv| kv.key == "http.route");
        let has_zone = rec.attributes.iter().any(|kv| kv.key == "nginx.upstream.zone");
        assert!(!has_route, "http.route must be absent from error records");
        assert!(!has_zone, "nginx.upstream.zone must be absent from error records");
    }

    /// Coalesced flood ⇒ one `LogRecord` with `nginx.error.coalesced_count = N`.
    ///
    /// Simulate a flood of N identical messages that all coalesced into one verbatim
    /// sample in the ring.  The coalescer table holds `count = N`.  After draining,
    /// the single ring record must carry `coalesced_count = N`.
    #[test]
    fn coalesced_count_attached_to_sample() {
        use crate::logs::coalesce::COALESCE_CAPACITY;
        use crate::logs::error_writer::KIND_ERROR;
        use crate::logs::ring::DEFAULT_LOG_RING_CAP;
        use crate::shm::{logs_coalesce_table, logs_error_ring};

        let cap = DEFAULT_LOG_RING_CAP;
        let (mut slot_buf, slot_ptr) = make_logs_slot(cap);
        let _ = &mut slot_buf;

        let template_hash: u64 = 0x1234_5678_9abc_def0;
        let coalesced_n: u32 = 150;

        // 1. Push one verbatim ring record with the given template_hash.
        // SAFETY: `slot_ptr` is the one-worker logs slot from `make_logs_slot`
        // (correct `cap`, initialised headers); `worker_id = 0 < 1` worker, so
        // `logs_error_ring` yields a valid in-slot ring view and `push` touches
        // only that view's atomic header + in-bounds payload.
        unsafe {
            use crate::logs::error_writer::ERROR_RECORD_HDR;
            let error_ring = logs_error_ring(slot_ptr, 0, cap);
            let body = b"no live upstreams while connecting to upstream";
            let body_len = body.len();
            let mut record = [0u8; ERROR_RECORD_HDR + 512];
            record[0] = KIND_ERROR;
            record[1..9].copy_from_slice(&1_700_000_000_000_000_000u64.to_be_bytes());
            record[9] = 4u8; // ERR
            record[10..18].copy_from_slice(&template_hash.to_be_bytes());
            record[18..20].copy_from_slice(&(body_len as u16).to_be_bytes());
            record[ERROR_RECORD_HDR..ERROR_RECORD_HDR + body_len].copy_from_slice(body);
            assert!(error_ring.push(&record[..ERROR_RECORD_HDR + body_len]));
        }

        // 2. Populate the coalescer table slot for this template_hash with count=N.
        //    We directly write the slot to simulate what the writer would have done.
        // SAFETY: `slot_ptr` is the one-worker logs slot from `make_logs_slot`;
        // `logs_coalesce_table(slot_ptr, 0, cap)` returns the in-slot coalescer
        // table base. `slot_idx` is masked by `COALESCE_CAPACITY - 1` (a
        // power-of-two capacity), so `table.add(slot_idx)` stays within the
        // `[CoalesceSlot; COALESCE_CAPACITY]` array; all fields are atomics.
        unsafe {
            let table = logs_coalesce_table(slot_ptr, 0, cap);
            let slot_idx = (template_hash as usize) & (COALESCE_CAPACITY - 1);
            let slot = &*table.add(slot_idx);
            slot.key_hash.store(template_hash, core::sync::atomic::Ordering::Relaxed);
            slot.severity.store(4u8, core::sync::atomic::Ordering::Relaxed);
            slot.count.store(coalesced_n, core::sync::atomic::Ordering::Release);
            slot.sample_emitted.store(true, core::sync::atomic::Ordering::Release);
        }

        // 3. Drain via collect_log_records.
        let amcf = crate::config::MainConfig {
            error_log_enabled: true,
            ..crate::config::MainConfig::default()
        };

        let batch = collect_log_records(&amcf, slot_ptr, 1, 0);

        assert_eq!(batch.logs.len(), 1, "one error record");
        let rec = &batch.logs[0];
        assert_eq!(rec.event_name, "nginx.error");

        // nginx.error.template_hash must be present.
        let hash_attr = rec.attributes.iter().find(|kv| kv.key == "nginx.error.template_hash");
        assert!(hash_attr.is_some(), "nginx.error.template_hash must be present");
        assert_eq!(
            hash_attr.unwrap().value,
            crate::data_model::AnyValue::Int(template_hash as i64),
            "template_hash attribute value must match"
        );

        // nginx.error.coalesced_count must be N (the flood count).
        let count_attr = rec.attributes.iter().find(|kv| kv.key == "nginx.error.coalesced_count");
        assert!(count_attr.is_some(), "nginx.error.coalesced_count must be present for flood");
        assert_eq!(
            count_attr.unwrap().value,
            crate::data_model::AnyValue::Int(coalesced_n as i64),
            "coalesced_count must equal the flood count"
        );

        // Coalescer table must have been reset (count = 0, sample_emitted = false).
        // SAFETY: same in-slot coalescer table as above; `slot_idx` is masked by
        // `COALESCE_CAPACITY - 1`, so `table.add(slot_idx)` is in-bounds, and the
        // reads below go through the slot's `count`/`sample_emitted` atomics.
        unsafe {
            let table = logs_coalesce_table(slot_ptr, 0, cap);
            let slot_idx = (template_hash as usize) & (COALESCE_CAPACITY - 1);
            let slot = &*table.add(slot_idx);
            assert_eq!(
                slot.count.load(core::sync::atomic::Ordering::Acquire),
                0,
                "coalescer count must be reset to 0 after drain"
            );
            assert!(
                !slot.sample_emitted.load(core::sync::atomic::Ordering::Acquire),
                "sample_emitted must be reset to false after drain"
            );
        }
    }

    /// F5 regression: orphaned coalesced count (ring-full verbatim drop) emits
    /// a synthetic log record so the count is not silently discarded.
    ///
    /// Pre-fix behaviour: `collect_log_records` discards any `counts_map` entry
    /// whose template_hash has no matching ring record → the N coalesced
    /// occurrences are silently lost.
    ///
    /// This test FAILS on pre-fix code (batch.logs is empty; no synthetic record).
    #[test]
    fn f5_orphaned_coalesced_count_emits_synthetic_record() {
        use crate::logs::coalesce::COALESCE_CAPACITY;
        use crate::logs::ring::DEFAULT_LOG_RING_CAP;
        use crate::shm::logs_coalesce_table;

        let cap = DEFAULT_LOG_RING_CAP;
        let (mut slot_buf, slot_ptr) = make_logs_slot(cap);
        let _ = &mut slot_buf;

        // Choose a template_hash that won't collide with the "no ring record" slot.
        let template_hash: u64 = 0xdead_beef_cafe_babe;
        let coalesced_n: u32 = 42;

        // 1. Populate the coalescer table slot with count=N, but push NO ring record.
        //    This simulates: the verbatim ring push for this template failed (ring
        //    full), but the coalescer slot accumulated N occurrences.
        // SAFETY: `slot_ptr` is the one-worker logs slot from `make_logs_slot`;
        // `logs_coalesce_table(slot_ptr, 0, cap)` is the in-slot coalescer table
        // base; `slot_idx` is masked by `COALESCE_CAPACITY - 1` (power-of-two),
        // so `table.add(slot_idx)` is in-bounds; all writes go through atomic ops.
        unsafe {
            let table = logs_coalesce_table(slot_ptr, 0, cap);
            let slot_idx = (template_hash as usize) & (COALESCE_CAPACITY - 1);
            let slot = &*table.add(slot_idx);
            slot.key_hash.store(template_hash, core::sync::atomic::Ordering::Relaxed);
            slot.severity.store(4u8, core::sync::atomic::Ordering::Relaxed); // error
            slot.count.store(coalesced_n, core::sync::atomic::Ordering::Release);
            slot.sample_emitted.store(true, core::sync::atomic::Ordering::Release);
        }
        // (No ring record pushed — this is the "ring-full drop" scenario.)

        // 2. Drain via collect_log_records.
        let amcf = crate::config::MainConfig {
            error_log_enabled: true,
            ..crate::config::MainConfig::default()
        };

        // Reset the orphaned counter before the test drain.
        ERROR_LOGS_COALESCED_ORPHANED.store(0, Ordering::Relaxed);

        let batch = collect_log_records(&amcf, slot_ptr, 1, 0);

        // 3. Pre-fix: batch.logs would be empty (orphaned count silently discarded).
        //    Post-fix: one synthetic record is emitted carrying the orphaned count.
        assert_eq!(
            batch.logs.len(),
            1,
            "one synthetic record must be emitted for the orphaned coalesced count"
        );
        let rec = &batch.logs[0];
        assert_eq!(rec.event_name, "nginx.error", "event_name must be nginx.error");

        // Synthetic record must carry template_hash so backends can group by template.
        let hash_attr = rec.attributes.iter().find(|kv| kv.key == "nginx.error.template_hash");
        assert!(
            hash_attr.is_some(),
            "nginx.error.template_hash must be present on synthetic record"
        );
        assert_eq!(
            hash_attr.unwrap().value,
            crate::data_model::AnyValue::Int(template_hash as i64),
            "template_hash must match the orphaned slot's key"
        );

        // Synthetic record must carry coalesced_count = N.
        let count_attr = rec.attributes.iter().find(|kv| kv.key == "nginx.error.coalesced_count");
        assert!(
            count_attr.is_some(),
            "nginx.error.coalesced_count must be present on synthetic record"
        );
        assert_eq!(
            count_attr.unwrap().value,
            crate::data_model::AnyValue::Int(coalesced_n as i64),
            "coalesced_count must equal the orphaned slot count"
        );

        // Body must mention "ring-full" so the record is clearly identifiable.
        let body_str = match &rec.body {
            crate::data_model::AnyValue::String(s) => s.as_str(),
            _ => "",
        };
        assert!(
            body_str.contains("ring-full"),
            "synthetic record body must contain 'ring-full'; got: {body_str:?}"
        );

        // 4. Self-metric must reflect the orphaned count total.
        let orphaned_metric = ERROR_LOGS_COALESCED_ORPHANED.load(Ordering::Acquire);
        assert_eq!(
            orphaned_metric, coalesced_n as u64,
            "ERROR_LOGS_COALESCED_ORPHANED must be incremented by the orphaned count"
        );
    }

    // ── Error-rate metric tests ──────────────────────────────────────────────

    /// Error-rate metric has exactly N_SEVERITY_CLASSES data points, each with a
    /// distinct `severity_class` attribute, and no other attributes.
    #[test]
    fn error_rate_metric_shape() {
        use crate::data_model::MetricData;
        use crate::shm::{N_SEVERITY_CLASSES, SEVERITY_CLASS_NAMES};

        let n_workers = 2usize;
        let zone_sz = crate::shm::zone_size_for(n_workers);
        let mut buf = std::vec![0u8; zone_sz];
        let base = buf.as_mut_ptr();

        // Zero-init the WorkerSlots area.
        let off = crate::shm::data_offset();
        // SAFETY: `buf` is sized `zone_size_for(n_workers)` = `off + n_workers *
        // size_of::<WorkerSlots>()`, so `base + off` is in-bounds and exactly
        // `zone_sz - off` bytes remain after it; the zero-fill stays within the
        // buffer and never touches the simulated slab-header region `[0, off)`.
        unsafe { core::ptr::write_bytes(base.add(off), 0, zone_sz - off) };

        // SAFETY: `base + off` points past the simulated slab header to the
        // WorkerSlots area, satisfying `collect_error_rate_metric`'s contract
        // that `base` be the zone data start; the buffer holds `n_workers` slots.
        let metric = collect_error_rate_metric(unsafe { base.add(off) }, n_workers, 0);

        assert_eq!(metric.name, "ngx_otel.error_log.events");

        let MetricData::Sum(sum) = &metric.data else {
            panic!("error-rate metric must be a Sum");
        };
        assert!(sum.is_monotonic, "error-rate must be monotonic");
        assert_eq!(
            sum.data_points.len(),
            N_SEVERITY_CLASSES,
            "must have one data point per severity class"
        );

        // Each data point has exactly one attribute `severity_class` with a valid name.
        let mut seen_classes = std::collections::HashSet::new();
        for dp in &sum.data_points {
            assert_eq!(dp.attributes.len(), 1, "each dp must have exactly one attribute");
            assert_eq!(dp.attributes[0].key, "severity_class");
            let class_name = match &dp.attributes[0].value {
                AnyValue::String(s) => s.as_str(),
                _ => panic!("severity_class must be a string"),
            };
            assert!(
                SEVERITY_CLASS_NAMES.contains(&class_name),
                "severity_class '{class_name}' must be in SEVERITY_CLASS_NAMES"
            );
            assert!(
                seen_classes.insert(std::string::String::from(class_name)),
                "duplicate severity_class"
            );

            // All zero on fresh-start shm.
            assert_eq!(dp.value, crate::data_model::NumberValue::AsInt(0));
        }
        assert_eq!(seen_classes.len(), N_SEVERITY_CLASSES, "all classes must appear");
    }

    /// Error-rate counters accumulate across workers: two workers each bump
    /// separate severity classes; the metric sums them correctly.
    #[test]
    fn error_rate_counter_increments_per_severity_class() {
        use crate::shm::{severity_class_index, worker_slots};

        let n_workers = 2usize;
        let zone_sz = crate::shm::zone_size_for(n_workers);
        let mut buf = std::vec![0u8; zone_sz];
        let base = buf.as_mut_ptr();

        let off = crate::shm::data_offset();
        // SAFETY: `buf` is sized `zone_size_for(n_workers)` = `off + n_workers *
        // size_of::<WorkerSlots>()`, so `base + off` is in-bounds; the pointer is
        // only formed here for the WorkerSlots data region.
        let data_base = unsafe { base.add(off) };
        // SAFETY: `data_base = base + off` is in-bounds and exactly `zone_sz - off`
        // bytes remain after it, so the zero-fill of the WorkerSlots area stays
        // within the buffer.
        unsafe { core::ptr::write_bytes(data_base, 0, zone_sz - off) };

        // Worker 0 bumps: 10 × error (level 4), 5 × warn (level 5)
        // SAFETY: `data_base` is the WorkerSlots data start of a buffer sized for
        // `n_workers = 2` slots; `0 < n_workers`, so `worker_slots(data_base, 0)`
        // is in-bounds and (post zero-fill) a valid `WorkerSlots`; the bumps go
        // through its `AtomicU64` counters.
        unsafe {
            let slots = &*worker_slots(data_base, 0);
            for _ in 0..10 {
                slots.error_rate_counters[severity_class_index(4)]
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            for _ in 0..5 {
                slots.error_rate_counters[severity_class_index(5)]
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
        }

        // Worker 1 bumps: 3 × fatal (level 1), 10 × error (level 4)
        // SAFETY: `1 < n_workers = 2`, so `worker_slots(data_base, 1)` is the
        // in-bounds second slot (post zero-fill, a valid `WorkerSlots`); the
        // bumps go through its `AtomicU64` counters.
        unsafe {
            let slots = &*worker_slots(data_base, 1);
            for _ in 0..3 {
                slots.error_rate_counters[severity_class_index(1)]
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            for _ in 0..10 {
                slots.error_rate_counters[severity_class_index(4)]
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
        }

        let metric = collect_error_rate_metric(data_base, n_workers, 0);
        let crate::data_model::MetricData::Sum(sum) = &metric.data else { panic!() };

        let find_class = |name: &str| -> i64 {
            sum.data_points.iter().find(|dp| {
                matches!(&dp.attributes[0].value, AnyValue::String(s) if s.as_str() == name)
            })
            .map(|dp| match dp.value { crate::data_model::NumberValue::AsInt(v) => v, _ => 0 })
            .unwrap_or(0)
        };

        assert_eq!(find_class("fatal"), 3, "fatal: 3 from worker 1");
        assert_eq!(find_class("error"), 20, "error: 10 from w0 + 10 from w1 = 20");
        assert_eq!(find_class("warn"), 5, "warn: 5 from worker 0");
        assert_eq!(find_class("info"), 0, "info: no bumps");
        assert_eq!(find_class("debug"), 0, "debug: no bumps");

        // Only severity_class is a metric dimension (no route/zone/trace_id).
        for dp in &sum.data_points {
            assert_eq!(
                dp.attributes.len(),
                1,
                "only severity_class dim; count={}",
                dp.attributes.len()
            );
        }
    }

    /// Mock `RetrySend` that always returns an HTTP error with a fixed status code.
    /// Used exclusively to drive `drain_retry_queue_once` in unit tests without
    /// a real nginx transport.
    struct MockAlwaysErr(u16);
    impl super::RetrySend for MockAlwaysErr {
        async fn send_batch(
            &mut self,
            _bytes: std::vec::Vec<u8>,
        ) -> Result<crate::transport::DeliveryOutcome, crate::transport::TransportError> {
            Err(crate::transport::TransportError::HttpStatus {
                code: self.0,
                message: "mock".into(),
            })
        }
    }

    /// Drives the production `drain_retry_queue_once` helper (the shared path
    /// called by all three export lanes — logs, spans, metrics) with an injected
    /// mock sender (`MockAlwaysErr`).  Neutering the `is_permanent_rejection`
    /// guard inside the helper makes this test fail.
    ///
    /// Earlier this test re-implemented the drain
    /// loop inline and never called production code; the reviewer removed all
    /// three production guard blocks and the test STILL PASSED.  This test calls
    /// the production helper directly — the test cannot pass if the guard is gone.
    ///
    /// Mutation-evidence bar: neuter `drain_retry_queue_once`'s 4xx-drop
    /// branch (classify everything transient) → this test FAILS → restore → PASSES.
    #[tokio::test]
    async fn f_retry_drops_permanent_4xx() {
        // ── 413 case: permanent rejection → dropped, not re-queued, counter bumped ──
        let mut queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();
        queue.push_back((std::vec![1u8, 2u8, 3u8], 42));

        let failure_counter = AtomicU64::new(0);
        // Removing is_permanent_rejection's guard classifies 413 as transient
        // → batch is re-queued → queue.len() == 1 → assertion FAILS.
        // Use the `_with_timer` form with a never-firing timer so the
        // mock's immediate error wins the deadline race — this exercises the
        // identical drain logic while avoiding the real `ngx::async_::sleep`
        // (which derefs the nginx cycle log, null in unit tests).
        super::drain_retry_queue_once_with_timer(
            &mut queue,
            16,
            core::ptr::null_mut(),
            &failure_counter,
            "test",
            &mut MockAlwaysErr(413),
            &mut super::SignalBackoff::default(),
            0,
            || NeverTimer,
        )
        .await;

        assert!(
            queue.is_empty(),
            "413-rejected batch must be dropped, not re-queued; \
             queue depth = {}",
            queue.len()
        );
        assert_eq!(
            failure_counter.load(Ordering::Relaxed),
            1,
            "failure_counter must be bumped on permanent rejection"
        );

        // ── 503 case: transient error → re-queued ─────────────────────────────────
        let mut queue2: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();
        queue2.push_back((std::vec![1u8], 7));

        let failure_counter2 = AtomicU64::new(0);
        super::drain_retry_queue_once_with_timer(
            &mut queue2,
            16,
            core::ptr::null_mut(),
            &failure_counter2,
            "test",
            &mut MockAlwaysErr(503),
            &mut super::SignalBackoff::default(),
            0,
            || NeverTimer,
        )
        .await;

        assert_eq!(queue2.len(), 1, "boundary: 503 is transient — batch must be re-queued");
        assert_eq!(
            failure_counter2.load(Ordering::Relaxed),
            1,
            "failure_counter must be bumped on transient error"
        );
    }

    // ── Periodic-send deadline ─────────────────────────────────────────────────

    /// A `RetrySend` whose send NEVER resolves — models a collector that
    /// accepts the connection but never responds (the hung-collector case the
    /// `PERIODIC_SEND_BUDGET` deadline exists to bound).
    struct MockNeverResolve;
    impl super::RetrySend for MockNeverResolve {
        fn send_batch(
            &mut self,
            _bytes: std::vec::Vec<u8>,
        ) -> impl core::future::Future<
            Output = Result<crate::transport::DeliveryOutcome, crate::transport::TransportError>,
        > {
            // A future that is always `Poll::Pending` and never wakes.
            core::future::poll_fn(|_cx| {
                core::task::Poll::<
                    Result<crate::transport::DeliveryOutcome, crate::transport::TransportError>,
                >::Pending
            })
        }
    }

    /// Runtime-free timer that NEVER fires — `Poll::Pending` forever. Used when
    /// the mock send resolves on its own (e.g. an immediate error), so the
    /// deadline must lose the race. Avoids the real `ngx::async_::sleep`, which
    /// derefs the nginx cycle log (null in unit tests).
    struct NeverTimer;
    impl core::future::Future for NeverTimer {
        type Output = ();
        fn poll(
            self: core::pin::Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<()> {
            core::task::Poll::Pending
        }
    }

    /// Deterministic, runtime-free deadline timer: `Ready(())` on the first poll.
    /// Substitutes for `ngx::async_::sleep` so the test exercises the
    /// deadline-expiry arm without a real wall-clock wait or an nginx event loop.
    struct ReadyTimer;
    impl core::future::Future for ReadyTimer {
        type Output = ();
        fn poll(
            self: core::pin::Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<()> {
            core::task::Poll::Ready(())
        }
    }

    /// Bounded-poll executor: drives `fut` for at most `max_polls` polls,
    /// returning its output. Panics if the future has not completed by then.
    ///
    /// This is the DETERMINISM mechanism for the mutation cycle. With the
    /// production deadline wrap in place, `WithDeadline { fut: never, timer:
    /// ReadyTimer }` resolves to `Err(DeadlineExceeded)` on the FIRST poll, so
    /// the whole drain pass completes in a couple of polls. If the deadline wrap
    /// is removed (mutation), the inner send is the never-resolving future, which
    /// returns `Pending` forever — the poll budget is exhausted and this PANICS,
    /// failing the test deterministically (no timing, no flake).
    fn block_on_bounded<F: core::future::Future>(fut: F, max_polls: u32) -> F::Output {
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        unsafe fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        unsafe fn noop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        // SAFETY: the no-op vtable's clone/wake/drop never dereference the data
        // pointer (all are no-ops or rebuild a null-data RawWaker), so a null
        // data pointer is sound — the standard test-waker pattern.
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = core::pin::pin!(fut);
        for _ in 0..max_polls {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
        panic!(
            "future did not complete within {max_polls} polls — the \
             periodic send was awaited without a deadline (a hung collector \
             would block the export loop, and thus `nginx -s quit`, indefinitely)"
        );
    }

    /// Mutation-evidence: a periodic (retry-drain) send to a hung collector
    /// must be bounded by `PERIODIC_SEND_BUDGET` and the batch must land back in
    /// the retry queue with the failure counter bumped — i.e. a deadline expiry
    /// takes the EXACT transient-failure path.
    ///
    /// Drives the production `drain_retry_queue_once_with_timer` (the shared
    /// helper behind all three lanes' retry drains) with a never-resolving
    /// sender and the deterministic `ReadyTimer` standing in for the real
    /// `ngx::async_::sleep(PERIODIC_SEND_BUDGET)`.
    ///
    /// MUTATION: in `drain_retry_queue_once_with_timer`, replace
    ///   `let send = WithDeadline { fut: sender.send_batch(bytes.clone()), timer: mk_timer() };`
    ///   `match send.await {`
    /// with a bare
    ///   `match sender.send_batch(bytes.clone()).await {`
    /// (dropping the deadline wrap) → the never-resolving send returns `Pending`
    /// forever → `block_on_bounded` exhausts its poll budget → PANIC → test FAILS.
    /// Restore the wrap → the `ReadyTimer` fires first → `Err(DeadlineExceeded)`
    /// → enqueue path runs → test PASSES.
    #[test]
    fn f_h3f3_periodic_send_deadline() {
        let mut queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();
        queue.push_back((std::vec![1u8, 2u8, 3u8], 9));

        let failure_counter = AtomicU64::new(0);

        // Bound: a single batch takes ~2 polls (WithDeadline poll → timer Ready;
        // plus the helper's surrounding awaits). 64 is generous head-room while
        // still tiny vs. the "never completes" mutation. The deadline arm fires
        // on the FIRST poll of WithDeadline, so completion is poll-count-bounded
        // and clock-independent.
        block_on_bounded(
            super::drain_retry_queue_once_with_timer(
                &mut queue,
                16,
                core::ptr::null_mut(),
                &failure_counter,
                "test",
                &mut MockNeverResolve,
                &mut super::SignalBackoff::default(),
                0,
                || ReadyTimer,
            ),
            64,
        );

        assert_eq!(
            queue.len(),
            1,
            "a deadline-expired (hung-collector) batch must be re-queued for retry"
        );
        assert_eq!(
            queue.front().map(|(_, n)| *n),
            Some(9),
            "the re-queued batch must preserve its record count"
        );
        assert_eq!(
            failure_counter.load(Ordering::Relaxed),
            1,
            "a deadline expiry must bump the failure counter (transient-failure path)"
        );
    }

    // ── Outcome-driven policy engine ────────────────────────────────────────────

    use crate::transport::DeliveryOutcome as Outcome;

    /// Serializes the delivery-outcome tests that assert on the process-global
    /// counters (`PARTIAL_REJECTED` / `PERMANENT_REJECTED` / `UNAUTHORIZED_REJECTED`),
    /// since cargo runs unit tests in parallel and another such test could bump
    /// the same static between a before/after read.
    static S4_COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A `RetrySend` that returns a fixed `Ok(DeliveryOutcome)` verdict for every
    /// send — exercises the policy match in `drain_retry_queue_once_with_timer`.
    struct MockVerdict(Outcome);
    impl super::RetrySend for MockVerdict {
        async fn send_batch(
            &mut self,
            _bytes: std::vec::Vec<u8>,
        ) -> Result<crate::transport::DeliveryOutcome, crate::transport::TransportError> {
            Ok(self.0.clone())
        }
    }

    /// `Accepted` → release: batch is dropped (not re-queued), backoff reset.
    #[test]
    fn s4_accepted_releases_and_resets_backoff() {
        let mut backoff = SignalBackoff { not_before_msec: 12_345, consecutive_retryable: 4 };
        let action = apply_delivery_outcome(
            &Outcome::Accepted,
            &mut backoff,
            1_000,
            core::ptr::null_mut(),
            "test",
        );
        assert_eq!(action, OutcomeAction::Release);
        assert_eq!(backoff.consecutive_retryable, 0, "Accepted must reset the failure counter");
        assert_eq!(backoff.not_before_msec, 0, "Accepted must clear any active defer");
    }

    /// `PartialReject{n}` → release + accumulate `n`; backoff reset.
    #[test]
    fn s4_partial_reject_releases_and_counts() {
        let _g = S4_COUNTER_LOCK.lock().unwrap();
        let before = PARTIAL_REJECTED.load(Ordering::Relaxed);
        let mut backoff = SignalBackoff { not_before_msec: 9, consecutive_retryable: 2 };
        let action = apply_delivery_outcome(
            &Outcome::PartialReject { rejected: 7 },
            &mut backoff,
            1_000,
            core::ptr::null_mut(),
            "test",
        );
        assert_eq!(action, OutcomeAction::Release, "PartialReject must release the batch");
        assert_eq!(
            PARTIAL_REJECTED.load(Ordering::Relaxed) - before,
            7,
            "PartialReject must accumulate the rejected count"
        );
        assert_eq!(backoff.consecutive_retryable, 0);
        assert_eq!(backoff.not_before_msec, 0);
    }

    /// `Retryable` WITH a hint → requeue + defer until the hint elapses (the
    /// not-before timestamp equals now + hint, NOT subject to the no-hint cap).
    #[test]
    fn s4_retryable_with_hint_defers_until_hint() {
        let mut backoff = SignalBackoff::default();
        let now = 5_000;
        let hint = Duration::from_millis(2_500);
        let action = apply_delivery_outcome(
            &Outcome::Retryable { retry_after: Some(hint) },
            &mut backoff,
            now,
            core::ptr::null_mut(),
            "test",
        );
        assert_eq!(action, OutcomeAction::Requeue, "Retryable must re-queue (bounded)");
        assert_eq!(
            backoff.not_before_msec,
            now + 2_500,
            "a hint must set the not-before timestamp to now + hint"
        );
        assert!(backoff.is_deferred(now), "drain must be deferred at now");
        assert!(backoff.is_deferred(now + 2_499), "still deferred just before the hint");
        assert!(!backoff.is_deferred(now + 2_500), "no longer deferred once the hint elapses");

        // A hint LARGER than the no-hint cap is honored verbatim (not capped).
        let mut b2 = SignalBackoff::default();
        let big = Duration::from_millis(BACKOFF_CAP_MS + 120_000);
        apply_delivery_outcome(
            &Outcome::Retryable { retry_after: Some(big) },
            &mut b2,
            0,
            core::ptr::null_mut(),
            "test",
        );
        assert_eq!(
            b2.not_before_msec,
            BACKOFF_CAP_MS + 120_000,
            "a peer hint is honored verbatim and is NOT clamped to the no-hint cap"
        );
    }

    /// `Retryable` WITHOUT a hint → exponential backoff: doubling across
    /// consecutive failures, capped, and RESET on the next `Accepted`.
    #[test]
    fn s4_retryable_no_hint_exponential_backoff_and_reset() {
        let mut backoff = SignalBackoff::default();
        let now = 0;

        // 1st failure: base.
        apply_delivery_outcome(
            &Outcome::Retryable { retry_after: None },
            &mut backoff,
            now,
            core::ptr::null_mut(),
            "test",
        );
        assert_eq!(backoff.consecutive_retryable, 1);
        assert_eq!(backoff.not_before_msec, BACKOFF_BASE_MS, "1st no-hint defer = base");

        // 2nd failure: 2× base.
        apply_delivery_outcome(
            &Outcome::Retryable { retry_after: None },
            &mut backoff,
            now,
            core::ptr::null_mut(),
            "test",
        );
        assert_eq!(backoff.consecutive_retryable, 2);
        assert_eq!(backoff.not_before_msec, BACKOFF_BASE_MS * 2, "2nd defer doubles");

        // 3rd failure: 4× base.
        apply_delivery_outcome(
            &Outcome::Retryable { retry_after: None },
            &mut backoff,
            now,
            core::ptr::null_mut(),
            "test",
        );
        assert_eq!(backoff.not_before_msec, BACKOFF_BASE_MS * 4, "3rd defer doubles again");

        // Doubling is capped at BACKOFF_CAP_MS.
        let mut capped = SignalBackoff { not_before_msec: 0, consecutive_retryable: 60 };
        apply_delivery_outcome(
            &Outcome::Retryable { retry_after: None },
            &mut capped,
            now,
            core::ptr::null_mut(),
            "test",
        );
        assert_eq!(
            capped.not_before_msec, BACKOFF_CAP_MS,
            "sustained no-hint retryable must cap at BACKOFF_CAP_MS, never grow unbounded"
        );

        // An Accepted resets the backoff to baseline.
        apply_delivery_outcome(
            &Outcome::Accepted,
            &mut backoff,
            now,
            core::ptr::null_mut(),
            "test",
        );
        assert_eq!(backoff.consecutive_retryable, 0, "Accepted resets consecutive count");
        assert_eq!(backoff.not_before_msec, 0, "Accepted clears the defer");
        // The next no-hint retryable restarts at base, proving the reset.
        apply_delivery_outcome(
            &Outcome::Retryable { retry_after: None },
            &mut backoff,
            now,
            core::ptr::null_mut(),
            "test",
        );
        assert_eq!(
            backoff.not_before_msec, BACKOFF_BASE_MS,
            "after Accepted the backoff restarts at base, not where it left off"
        );
    }

    /// `Permanent` → drop + count, NO retry, no defer.
    #[test]
    fn s4_permanent_drops_and_counts_no_retry() {
        let _g = S4_COUNTER_LOCK.lock().unwrap();
        let before = PERMANENT_REJECTED.load(Ordering::Relaxed);
        let mut backoff = SignalBackoff::default();
        let action = apply_delivery_outcome(
            &Outcome::Permanent,
            &mut backoff,
            1_000,
            core::ptr::null_mut(),
            "test",
        );
        assert_eq!(action, OutcomeAction::Drop, "Permanent must drop, never retry");
        assert_eq!(
            PERMANENT_REJECTED.load(Ordering::Relaxed) - before,
            1,
            "Permanent must bump its own counter"
        );
        assert_eq!(backoff.not_before_msec, 0, "Permanent must NOT set a defer");
    }

    /// `Unauthorized` → drop + DISTINCT counter, NO retry, NO defer/pause.
    #[test]
    fn s4_unauthorized_drops_distinct_counter_no_retry_no_pause() {
        let _g = S4_COUNTER_LOCK.lock().unwrap();
        let before_unauth = UNAUTHORIZED_REJECTED.load(Ordering::Relaxed);
        let before_perm = PERMANENT_REJECTED.load(Ordering::Relaxed);
        let mut backoff = SignalBackoff::default();
        let action = apply_delivery_outcome(
            &Outcome::Unauthorized,
            &mut backoff,
            1_000,
            core::ptr::null_mut(),
            "test",
        );
        assert_eq!(action, OutcomeAction::Drop, "Unauthorized = same action as Permanent (drop)");
        assert_eq!(
            UNAUTHORIZED_REJECTED.load(Ordering::Relaxed) - before_unauth,
            1,
            "Unauthorized must bump its OWN distinct counter"
        );
        assert_eq!(
            PERMANENT_REJECTED.load(Ordering::Relaxed) - before_perm,
            0,
            "Unauthorized must NOT bump the permanent counter"
        );
        assert_eq!(backoff.not_before_msec, 0, "Unauthorized must NOT defer/pause");
        assert_eq!(backoff.consecutive_retryable, 0, "Unauthorized must NOT touch the retry count");
    }

    /// `Unauthorized` on one signal does NOT defer or stop the OTHER signals'
    /// drains — each lane has its own independent backoff state.
    #[test]
    fn s4_unauthorized_does_not_stop_other_signals() {
        let _g = S4_COUNTER_LOCK.lock().unwrap();
        let mut logs_b = SignalBackoff::default();
        let mut spans_b = SignalBackoff { not_before_msec: 0, consecutive_retryable: 0 };
        // logs gets Unauthorized; spans gets Accepted in the same tick.
        apply_delivery_outcome(
            &Outcome::Unauthorized,
            &mut logs_b,
            500,
            core::ptr::null_mut(),
            "logs",
        );
        apply_delivery_outcome(
            &Outcome::Accepted,
            &mut spans_b,
            500,
            core::ptr::null_mut(),
            "spans",
        );
        assert!(!logs_b.is_deferred(500), "Unauthorized lane is not deferred (drop, no pause)");
        assert!(!spans_b.is_deferred(500), "the other lane keeps flowing — independent state");
    }

    /// `backoff_ms` doubling + cap + the `n == 0` edge.
    #[test]
    fn s4_backoff_ms_doubling_and_cap() {
        assert_eq!(backoff_ms(0, 250, 30_000), 250, "n=0 treated as the first failure → base");
        assert_eq!(backoff_ms(1, 250, 30_000), 250);
        assert_eq!(backoff_ms(2, 250, 30_000), 500);
        assert_eq!(backoff_ms(3, 250, 30_000), 1_000);
        assert_eq!(backoff_ms(8, 250, 30_000), 30_000, "doubling saturates at the cap");
        assert_eq!(backoff_ms(1_000, 250, 30_000), 30_000, "huge shift never overflows → cap");
    }

    /// End-to-end through the production drain helper: a `Retryable` verdict
    /// re-queues the batch into the bounded buffer AND records a defer.
    #[tokio::test]
    async fn s4_drain_retryable_requeues_and_defers() {
        let mut queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();
        queue.push_back((std::vec![1u8], 3));
        let failure_counter = AtomicU64::new(0);
        let mut backoff = SignalBackoff::default();
        super::drain_retry_queue_once_with_timer(
            &mut queue,
            16,
            core::ptr::null_mut(),
            &failure_counter,
            "test",
            &mut MockVerdict(Outcome::Retryable { retry_after: None }),
            &mut backoff,
            1_000,
            || NeverTimer,
        )
        .await;
        assert_eq!(queue.len(), 1, "Retryable must re-queue into the bounded buffer");
        assert!(backoff.is_deferred(1_000), "Retryable must defer the next drain");
        assert_eq!(backoff.not_before_msec, 1_000 + BACKOFF_BASE_MS);
    }

    /// End-to-end: a `Permanent` verdict drops the batch via the drain helper
    /// (queue empties; no re-queue).
    #[tokio::test]
    async fn s4_drain_permanent_drops() {
        // Counter-delta assertion lives in `s4_permanent_drops_and_counts_no_retry`
        // (sync, lock-guarded). Here we assert the buffer action through the
        // production drain helper without touching the shared global counter, so
        // no lock is held across the `.await`.
        let mut queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();
        queue.push_back((std::vec![1u8], 3));
        let failure_counter = AtomicU64::new(0);
        let mut backoff = SignalBackoff::default();
        super::drain_retry_queue_once_with_timer(
            &mut queue,
            16,
            core::ptr::null_mut(),
            &failure_counter,
            "test",
            &mut MockVerdict(Outcome::Permanent),
            &mut backoff,
            1_000,
            || NeverTimer,
        )
        .await;
        assert!(queue.is_empty(), "Permanent must drop the batch, not re-queue");
        assert!(!backoff.is_deferred(1_000), "Permanent must not defer");
    }

    /// Bounded-buffer backstop holds under sustained backoff: requeue via the
    /// policy never grows the buffer beyond `max_depth` (oldest evicted).
    #[tokio::test]
    async fn s4_bounded_buffer_evicts_oldest_under_sustained_backoff() {
        // Fill the queue beyond the depth, then drain with a Retryable verdict.
        // Each surviving batch that the helper re-queues is bounded by max_depth.
        let max_depth = 4;
        let mut queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();
        for i in 0..(max_depth as u64 + 5) {
            queue.push_back((std::vec![i as u8], 1));
        }
        let failure_counter = AtomicU64::new(0);
        let mut backoff = SignalBackoff::default();
        // The helper takes a snapshot and re-queues on the first Retryable, then
        // dumps the remainder back via enqueue_with_eviction — all bounded.
        super::drain_retry_queue_once_with_timer(
            &mut queue,
            max_depth,
            core::ptr::null_mut(),
            &failure_counter,
            "test",
            &mut MockVerdict(Outcome::Retryable { retry_after: None }),
            &mut backoff,
            1_000,
            || NeverTimer,
        )
        .await;
        assert!(
            queue.len() <= max_depth,
            "bounded buffer must never exceed max_depth ({}); got {}",
            max_depth,
            queue.len()
        );
    }

    /// Backoff basis freshness (fresh-send path). The fresh-metrics send awaits
    /// can burn up to two `PERIODIC_SEND_BUDGET` windows before the outcome is
    /// applied, so the backoff basis MUST be a clock read taken AFTER the send,
    /// not the pre-send capture used to gate `is_deferred` at the top of the
    /// iteration. With a stale basis and the deferral capped at `BACKOFF_CAP_MS`,
    /// `not_before_msec = stale_basis + cap` can land in the past relative to the
    /// real "now", so `is_deferred(real_now)` returns false and the exporter
    /// hammers a failing collector at full cadence.
    #[test]
    fn fresh_send_backoff_basis_must_be_post_send_now() {
        // Drive the backoff into the capped regime (sustained no-hint retryable),
        // so defer_ms == BACKOFF_CAP_MS and a stale basis is provably in the past.
        let mut backoff = SignalBackoff { not_before_msec: 0, consecutive_retryable: 60 };

        // The iteration captured the pre-send clock here.
        let pre_send_now = 1_000_000u64;
        // Two ~15s send awaits elapsed before the outcome is applied; the real
        // monotonic clock is now well past the pre-send capture.
        let real_now = pre_send_now + 2 * PERIODIC_SEND_BUDGET.as_millis() as u64;

        // CORRECT: basis is a fresh post-send clock read (what the fix passes).
        let mut q: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();
        let fc = AtomicU64::new(0);
        let action = handle_fresh_send_outcome(
            &Outcome::Retryable { retry_after: None },
            &mut backoff,
            real_now, // fresh basis
            &mut q,
            std::vec![0u8],
            1,
            8,
            &fc,
            core::ptr::null_mut(),
            "metrics",
        );
        assert_eq!(action, OutcomeAction::Requeue);
        assert_eq!(
            backoff.not_before_msec,
            real_now + BACKOFF_CAP_MS,
            "fresh basis must defer relative to post-send now"
        );
        assert!(
            backoff.is_deferred(real_now),
            "with a fresh basis the next drain is correctly deferred"
        );

        // Reproduce the bug: had the call site passed the STALE pre-send capture,
        // the deadline would already be in the past at the real clock, so the gate
        // would WRONGLY allow an immediate re-drain of the failing collector.
        let mut stale_backoff = SignalBackoff { not_before_msec: 0, consecutive_retryable: 60 };
        let mut q2: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();
        let fc2 = AtomicU64::new(0);
        handle_fresh_send_outcome(
            &Outcome::Retryable { retry_after: None },
            &mut stale_backoff,
            pre_send_now, // STALE basis (the pre-fix behaviour)
            &mut q2,
            std::vec![0u8],
            1,
            8,
            &fc2,
            core::ptr::null_mut(),
            "metrics",
        );
        assert!(
            !stale_backoff.is_deferred(real_now),
            "a stale basis mis-classifies the deadline as already elapsed — the \
             regression this fix prevents"
        );
    }

    /// Counter→i64 saturation (self-metrics path). A monotonic Sum must never go
    /// negative; a raw `as i64` cast wraps a `u64` past `i64::MAX` to a negative
    /// value. `counter_to_i64` must saturate at `i64::MAX` instead.
    #[test]
    fn counter_to_i64_saturates_past_i64_max() {
        assert_eq!(counter_to_i64(0), 0);
        assert_eq!(counter_to_i64(42), 42);
        assert_eq!(counter_to_i64(i64::MAX as u64), i64::MAX);
        // The boundary the raw cast wraps negative at.
        assert_eq!(
            counter_to_i64(i64::MAX as u64 + 1),
            i64::MAX,
            "one past i64::MAX must saturate, not wrap to i64::MIN"
        );
        assert_eq!(counter_to_i64(u64::MAX), i64::MAX, "u64::MAX must saturate to i64::MAX");
        // The value stays non-negative across the whole high range (Sum invariant).
        for v in [i64::MAX as u64 + 1, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            assert!(counter_to_i64(v) >= 0, "counter value must never be negative");
        }
    }

    /// A torn/rejected error ring record must NOT consume its template_hash: the
    /// hash may only be marked consumed once the record parses into a `LogRecord`.
    /// Otherwise a dropped record suppresses the synthetic orphaned-coalesced
    /// record emitted for the same hash, silently losing the occurrence count.
    #[test]
    fn torn_record_does_not_consume_template_hash() {
        use crate::logs::error_writer::{ERROR_RECORD_HDR as HDR, KIND_ERROR};

        let hash: u64 = 0xABCD_1234_5678_9F00;

        // Build a VALID error record carrying `hash` (body_len = 0).
        let mut valid = std::vec![0u8; HDR];
        valid[0] = KIND_ERROR;
        // [1..9] ts, [9] level, [10..18] template_hash, [18..20] body_len.
        valid[10..18].copy_from_slice(&hash.to_be_bytes());
        // body_len = 0 already (bytes 18,19).
        let (parsed, consumed) =
            parse_error_record_consuming(&valid, 1, &std::collections::HashMap::new());
        assert!(parsed.is_some(), "the valid record must parse");
        assert_eq!(consumed, Some(hash), "a parsed record consumes its non-zero template_hash");

        // A TORN record: same hash bytes at [10..18], but truncated below HDR so
        // `parse_error_record` rejects it (`buf.len() < HDR`). Critically the hash
        // bytes ARE present and well-formed (`len >= 18`), so a naive extractor
        // would still read `hash` — the parse gate is what must suppress it.
        let mut torn = std::vec![0u8; HDR - 2];
        torn[0] = KIND_ERROR;
        torn[10..18].copy_from_slice(&hash.to_be_bytes());
        assert!(torn.len() >= 18, "torn record still carries the hash bytes");

        let (torn_parsed, torn_consumed) =
            parse_error_record_consuming(&torn, 1, &std::collections::HashMap::new());
        assert!(torn_parsed.is_none(), "the torn record must be rejected by validation");
        assert_eq!(
            torn_consumed, None,
            "a torn/rejected record must NOT consume its template_hash (else it \
             suppresses the orphaned-coalesced synthetic record), even though the \
             hash bytes are present"
        );
    }

    /// Call-site wiring guard for all three fresh-send lanes (metrics / logs /
    /// spans). Each lane has a dedicated `apply_{signal}_fresh_send_outcome`
    /// wrapper that reads the monotonic clock internally via
    /// `post_send_backoff_basis()` — the call site cannot accidentally supply a
    /// stale pre-send capture.
    ///
    /// This test uses the `TEST_CLOCK_MSEC` injectable clock to simulate the
    /// clock advancing between the top of the iteration ("pre-send") and the
    /// return of the send await ("post-send"), then calls each wrapper function
    /// directly. Because the wrappers call `post_send_backoff_basis()` (which
    /// reads `TEST_CLOCK_MSEC`) internally, the test observes the EXACT same
    /// clock path the production call site uses.
    ///
    /// Mutation guide (execute manually to verify):
    ///   • Replace `post_send_backoff_basis()` with `0` (or any stale constant)
    ///     inside any of the three `apply_{signal}_fresh_send_outcome` wrappers.
    ///   • Re-run this test: it FAILS on the `is_deferred` assertion for that
    ///     signal because the deadline is placed at `0 + BACKOFF_CAP_MS`, which
    ///     is still less than `real_now`.
    ///   • Restore `post_send_backoff_basis()`: test PASSES again.
    #[test]
    fn fresh_send_backoff_basis_wiring_all_lanes() {
        // Saturated backoff regime: defer_ms == BACKOFF_CAP_MS, making the
        // stale-vs-fresh split deterministic.
        let pre_send_now: u64 = 1_000_000;
        let real_now: u64 = pre_send_now + 2 * PERIODIC_SEND_BUDGET.as_millis() as u64;

        // Inject the post-send clock so that `post_send_backoff_basis()` —
        // called inside each wrapper — returns `real_now`.
        TEST_CLOCK_MSEC.store(real_now, Ordering::Relaxed);

        // ── Metrics lane ──────────────────────────────────────────────────────
        {
            let mut backoff = SignalBackoff { not_before_msec: 0, consecutive_retryable: 60 };
            let mut q = VecDeque::new();
            let fc = AtomicU64::new(0);
            let action = apply_metrics_fresh_send_outcome(
                &Outcome::Retryable { retry_after: None },
                &mut backoff,
                &mut q,
                std::vec![0u8],
                1,
                8,
                &fc,
                core::ptr::null_mut(),
            );
            assert_eq!(action, OutcomeAction::Requeue, "metrics: must Requeue");
            assert!(
                backoff.is_deferred(real_now),
                "metrics: apply_metrics_fresh_send_outcome must place the defer \
                 deadline in the future (post-send clock = {real_now}, \
                 not_before = {}). Mutation: replace post_send_backoff_basis() \
                 with a stale value inside apply_metrics_fresh_send_outcome \
                 and confirm this assertion fails.",
                backoff.not_before_msec
            );
        }

        // ── Logs lane ─────────────────────────────────────────────────────────
        {
            let mut backoff = SignalBackoff { not_before_msec: 0, consecutive_retryable: 60 };
            let mut q = VecDeque::new();
            let fc = AtomicU64::new(0);
            let action = apply_logs_fresh_send_outcome(
                &Outcome::Retryable { retry_after: None },
                &mut backoff,
                &mut q,
                std::vec![0u8],
                1,
                8,
                &fc,
                core::ptr::null_mut(),
            );
            assert_eq!(action, OutcomeAction::Requeue, "logs: must Requeue");
            assert!(
                backoff.is_deferred(real_now),
                "logs: apply_logs_fresh_send_outcome must place the defer deadline \
                 in the future (post-send clock = {real_now}, \
                 not_before = {}). Mutation: replace post_send_backoff_basis() \
                 with a stale value inside apply_logs_fresh_send_outcome \
                 and confirm this assertion fails.",
                backoff.not_before_msec
            );
        }

        // ── Spans lane ────────────────────────────────────────────────────────
        {
            let mut backoff = SignalBackoff { not_before_msec: 0, consecutive_retryable: 60 };
            let mut q = VecDeque::new();
            let fc = AtomicU64::new(0);
            let action = apply_spans_fresh_send_outcome(
                &Outcome::Retryable { retry_after: None },
                &mut backoff,
                &mut q,
                std::vec![0u8],
                1,
                8,
                &fc,
                core::ptr::null_mut(),
            );
            assert_eq!(action, OutcomeAction::Requeue, "spans: must Requeue");
            assert!(
                backoff.is_deferred(real_now),
                "spans: apply_spans_fresh_send_outcome must place the defer deadline \
                 in the future (post-send clock = {real_now}, \
                 not_before = {}). Mutation: replace post_send_backoff_basis() \
                 with a stale value inside apply_spans_fresh_send_outcome \
                 and confirm this assertion fails.",
                backoff.not_before_msec
            );
        }

        // ── Stale-basis documentation (all three lanes, pre-fix behaviour) ────
        // Show that passing `pre_send_now` (the stale pre-send capture) directly
        // to the policy helper places the deadline in the past at `real_now`.
        // This arm is a DOCUMENTATION assertion, not a call-site wiring check:
        // it confirms the regression mode the wrappers above prevent.
        for signal in ["metrics", "logs", "spans"] {
            let mut stale_backoff = SignalBackoff { not_before_msec: 0, consecutive_retryable: 60 };
            let mut q = VecDeque::new();
            let fc = AtomicU64::new(0);
            handle_fresh_send_outcome(
                &Outcome::Retryable { retry_after: None },
                &mut stale_backoff,
                pre_send_now, // stale pre-send capture — the regressed wiring
                &mut q,
                std::vec![0u8],
                1,
                8,
                &fc,
                core::ptr::null_mut(),
                signal,
            );
            assert!(
                !stale_backoff.is_deferred(real_now),
                "{signal}: a stale pre-send basis places the deadline in the past \
                 at real_now ({real_now}), confirming the regression mode. \
                 not_before = {}",
                stale_backoff.not_before_msec
            );
        }

        // Reset the injectable clock so sibling tests that depend on
        // `ngx_current_msec == 0` (the test-process default) are unaffected.
        TEST_CLOCK_MSEC.store(0, Ordering::Relaxed);
    }

    /// When `otel_metrics off` (`metrics_enabled = 0`), `collect_all_sources`
    /// returns only the self-metrics batch (no shm-derived per-worker series, no
    /// stub_status counters, no serving-cert gauges), AND the batch still contains
    /// the self-metric series — confirming that gating metrics off suppresses only
    /// the instrumented/stub/cert sources while the self-metrics source remains
    /// unaffected.
    ///
    /// The production gate in `export_loop` checks `amcf.metrics_enabled()` before
    /// calling `collect_all_sources` at all, so in production the function is not
    /// even called when metrics are disabled.  This test exercises `collect_all_sources`
    /// directly to verify its shm-derived sources are naturally absent when the shm
    /// zone was never registered (shm_zone = null → shm_base() = None).
    #[test]
    fn collect_all_sources_with_metrics_disabled_yields_only_self_metrics() {
        // Simulate `otel_metrics off;` — shm_zone stays null (default), so shm_base() = None.
        // Use struct-update syntax to satisfy clippy::field_reassign_with_default.
        let amcf = crate::config::MainConfig {
            metrics_enabled: 0,
            ..crate::config::MainConfig::default()
        };

        let batch = collect_all_sources(&amcf, 0, "");

        // The self-metrics source always runs; the export-interval series must be present.
        let has_self = batch.metrics.iter().any(|m| m.name == "ngx_otel.export_interval");
        assert!(
            has_self,
            "self-metrics (ngx_otel.export_interval) must be present even when metrics_enabled=0"
        );

        // The per-worker instrumented series requires a mapped shm zone; with
        // shm_zone = null, none of those series appear.
        let has_instrumented =
            batch.metrics.iter().any(|m| m.name.starts_with("http.server.request"));
        assert!(
            !has_instrumented,
            "per-worker http.server.request.* series must be absent when shm_zone is null"
        );
    }
}
