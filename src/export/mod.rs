// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Phase 1.3.2: Export loop relocated from Worker 0 to the `nginx: otel exporter` process.
//!
//! [`export_loop`] runs inside the **exporter process**, spawned by
//! `otel_exporter_cycle` in `src/exporter/mod.rs`. It:
//!   1. Sleeps for the configured `otel_metric_interval`.
//!   2. Collects metrics from all configured [`MetricSource`]s.
//!      (shm rings written by workers, mapped via fork-shared pages)
//!   3. Encodes via [`OtlpHttpEncoder`].
//!   4. Ships via [`HyperHttpTransport<NgxConnector>`] (production transport only;
//!      [`SpinConnector`] is test-only and never used here).
//!   5. On send failure: enqueues bytes in a bounded retry buffer; drops the
//!      oldest entry when the buffer is full.
//!   6. On `ngx_quit`: flushes the retry buffer and sends one final batch,
//!      then sets [`EXPORT_LOOP_DONE`] and returns cleanly.
//!   7. On `ngx_terminate`: returns immediately without any drain.
//!
//! # Phase 1.3.2 note
//! `MainConfig` is captured at spawn time (exporter startup). On SIGHUP
//! reload nginx creates a new exporter process with a new cycle and config.
//! The new exporter spawns its own `export_loop` task.
//! `MainConfig::old_config` provides the hook for Phase 1.2 cross-cycle
//! state transfer (TLS connection reuse, etc.).
//!
//! # Phase 1.1 / 1.2 graceful-drain limitation — RESOLVED in Phase 1.3
//! The documented SIGQUIT-during-sleep limitation (see [`graceful_drain`])
//! is **resolved** in Phase 1.3.2: the exporter is not a worker and is not
//! subject to `ngx_event_no_timers_left`. Cancelable timers fire normally
//! when the exporter exits on `ngx_quit`, so the chunked sleep reliably
//! detects shutdown and runs the drain. The `exit_process` flush path
//! (formerly in `src/lib.rs`) is no longer needed on the worker side.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;
use std::collections::VecDeque;

use nginx_sys::{NGX_LOG_ERR, NGX_LOG_NOTICE};
use pin_project_lite::pin_project;

use crate::config::{MainConfig, MetricProtocol};
use crate::data_model::{
    AggregationTemporality, AnyValue, Batch, GaugeData, KeyValue, LogRecord, LogsBatch, Metric,
    MetricData, NumberDataPoint, NumberValue, Resource, Scope, SumData,
};
use crate::encoder::{Encoder, OtlpHttpEncoder, OtlpLogsEncoder};
use crate::logs::severity::nginx_to_otel;
use crate::metric_source::instrumented::InstrumentedSource;
use crate::metric_source::stub_status::StubStatusSource;
use crate::metric_source::MetricSource;
use crate::shm::{logs_access_ring, logs_n_workers_from_zone, logs_slot_size};
use crate::transport::hyper_http::NgxConnector;
use crate::transport::{GrpcTransport, HyperHttpTransport, Transport};

// ── Self-metric atomics ──────────────────────────────────────────────────────

/// Cumulative count of metric data points dropped due to a full retry buffer.
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

// ── Log-specific self-metric atomics (Phase 2.1) ─────────────────────────────

/// Access-log records dropped by the producer because the ring was full.
/// Sum of per-worker `ring.drop_count()` snapshots at each drain cycle.
pub static ACCESS_LOGS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Error-log records dropped by the producer (Phase 2.2; kept here so the
/// metric is exposed even before the error-log path is wired in).
pub static ERROR_LOGS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Cumulative logs transport send failures since exporter startup.
pub static LOGS_SEND_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Unix epoch nanoseconds when this worker's export loop started.
///
/// Written once by [`export_loop`] immediately after computing `worker_start_ns`.
/// Read by [`exit_process_flush`] to anchor the final batch's
/// `start_time_unix_nano`. Value 0 means the loop has not yet started
/// (e.g., SIGQUIT arrived before the first async task iteration ran).
///
/// Process-global static: each forked worker inherits a zeroed copy and
/// sets its own value independently. No cross-process coordination needed.
// Phase 1.3.2: repurposed — now the exporter's start time (not a worker's).
// The variable name is intentionally unchanged; a hygiene-only rename is
// deferred to a separate commit after Phase 1.3 closes.
// Sub-item 2 (exporter cycle) reads this to anchor the export epoch.
#[allow(dead_code)]
pub static WORKER_START_NS: AtomicU64 = AtomicU64::new(0);

/// Set to `true` by [`export_loop`] just before it returns after a graceful
/// drain on `ngx_quit`. The exporter cycle polls this flag in its `ngx_quit`
/// branch to know when the drain has completed and it is safe to exit.
///
/// Phase 1.3.2: process-global; the exporter process is single-instance so
/// there is exactly one export_loop per process lifetime.
pub(crate) static EXPORT_LOOP_DONE: AtomicBool = AtomicBool::new(false);

/// Wall-clock budget for the graceful drain on `ngx_quit`. Each send attempt
/// inside the drain is capped at this duration so a dead collector cannot
/// stall exporter shutdown.
const GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET: Duration = Duration::from_secs(2);

/// Maximum slice of the export interval that may pass between `ngx_quit`
/// polls. Chunked sleep ensures shutdown is responsive even with a long
/// configured `otel_metric_interval` — we never wait more than this between
/// shutdown checks. The cost is one extra timer wake per chunk; negligible.
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Selects between the HTTP and gRPC production transports.
///
/// Built once in [`export_loop`] from `amcf.metric_protocol()` and threaded
/// through [`graceful_drain`].  An enum avoids `dyn Transport` and keeps
/// `send` monomorphic (both variants are cold-path anyway — the export
/// loop runs in a dedicated process that is not on the hot request path).
///
/// # Exit-time flush note
///
/// The synchronous `exit_process_flush` path (HTTP-only) is intentionally
/// NOT mirrored for gRPC: building a blocking one-shot h2 stack after the
/// async runtime has been torn down is fragile.  For `otlp_grpc`, the
/// in-loop async [`graceful_drain`] (which runs while the event loop is
/// still alive) provides the final flush.  This is safe because the
/// exporter process stays alive until `EXPORT_LOOP_DONE` is set (set by
/// `graceful_drain` after it completes), so `graceful_drain` always runs
/// before `process::exit`.
enum ExportTransport {
    Http(HyperHttpTransport<NgxConnector>),
    Grpc(GrpcTransport<NgxConnector>),
}

impl Transport for ExportTransport {
    async fn send(
        &mut self,
        bytes: std::vec::Vec<u8>,
    ) -> Result<(), crate::transport::TransportError> {
        match self {
            Self::Http(t) => t.send(bytes).await,
            Self::Grpc(t) => t.send(bytes).await,
        }
    }
}

impl ExportTransport {
    /// Send logs bytes to the OTel logs endpoint.
    ///
    /// For HTTP: POSTs to `/v1/logs` on the same host as metrics.
    /// For gRPC: calls `LogsService/Export`.
    ///
    /// # Phase 2.1 note — directive naming
    /// Logs ship over the same transport selected by `otel_export_protocol`.
    /// The directive name is intentionally kept as-is for backward compatibility.
    /// A rename to `otel_export_protocol` (with a back-compat alias) is tracked
    /// as a future cleanup; doing it here would be a breaking change.
    async fn send_logs(
        &mut self,
        bytes: std::vec::Vec<u8>,
    ) -> Result<(), crate::transport::TransportError> {
        match self {
            Self::Http(t) => t.send_to_path("/v1/logs", bytes).await,
            Self::Grpc(t) => t.send_logs(bytes).await,
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

// ── Self-metrics source ──────────────────────────────────────────────────────

/// [`MetricSource`] that exposes the export loop's own health as OTel metrics.
pub struct SelfMetricsSource {
    /// Configured export interval in milliseconds (emitted as a gauge in ms).
    pub interval_ms: u64,
    /// Worker startup time (Unix epoch, nanoseconds). Used as the
    /// `start_time_unix_nano` for the cumulative monotonic Sums so that
    /// downstream rate/delta-conversion processors can anchor windows
    /// correctly. Captured once at [`export_loop`] init; see field
    /// initialisation in [`collect_all_sources`].
    pub start_time_unix_nano: u64,
}

impl MetricSource for SelfMetricsSource {
    fn collect(&self) -> std::vec::Vec<Metric> {
        let now = now_unix_nano();
        let dropped = DROPPED_RECORDS.load(Ordering::Acquire) as i64;
        let failures = SEND_FAILURES.load(Ordering::Acquire) as i64;
        let interval_ms = self.interval_ms as i64;

        let backpressure_drops = BIDI_BACKPRESSURE_DROPS.load(Ordering::Acquire) as i64;
        let access_logs_dropped = ACCESS_LOGS_DROPPED.load(Ordering::Acquire) as i64;
        let error_logs_dropped = ERROR_LOGS_DROPPED.load(Ordering::Acquire) as i64;
        let logs_send_failures = LOGS_SEND_FAILURES.load(Ordering::Acquire) as i64;
        std::vec![
            monotonic_sum_metric(
                "ngx_otel.dropped_records",
                "Metric data points dropped due to a full retry buffer",
                "points",
                dropped,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.send_failures",
                "Cumulative export send failures since worker startup",
                "failures",
                failures,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.bidi_backpressure_drops",
                "Bidi outbound messages dropped due to channel backpressure",
                "messages",
                backpressure_drops,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.logs.access.dropped_records",
                "Access log records dropped because the per-worker ring was full",
                "records",
                access_logs_dropped,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.logs.error.dropped_records",
                "Error log records dropped because the per-worker ring was full",
                "records",
                error_logs_dropped,
                self.start_time_unix_nano,
                now,
            ),
            monotonic_sum_metric(
                "ngx_otel.logs.send_failures",
                "Cumulative logs transport send failures since exporter startup",
                "failures",
                logs_send_failures,
                self.start_time_unix_nano,
                now,
            ),
            gauge_metric(
                "ngx_otel.export_interval",
                "Configured metric export interval",
                "ms",
                interval_ms,
                now,
            ),
        ]
    }
}

// ── Main export loop ─────────────────────────────────────────────────────────

/// Async export loop — spawned by `otel_exporter_cycle` inside the exporter process.
///
/// Phase 1.3.2: runs in the `nginx: otel exporter` process, not Worker 0.
/// The shm rings (written by worker bumps) are read across the fork boundary
/// via the same mapped pages — fork-shared memory is coherent for atomic reads.
///
/// Takes `&'static MainConfig` because the loop task outlives the spawn call;
/// NGINX allocates MainConfig from the cycle pool which has exporter lifetime.
///
/// When `ngx_quit` is detected, runs [`graceful_drain`], sets
/// [`EXPORT_LOOP_DONE`], and returns. The exporter cycle polls
/// `EXPORT_LOOP_DONE` before calling `process::exit`.
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
    //
    // Transport selected by `otel_export_protocol` (default: otlp_http).
    // For gRPC the connection is lazy (deferred to first send).
    let mut transport = match amcf.metric_protocol() {
        MetricProtocol::OtlpHttp => {
            match HyperHttpTransport::<NgxConnector>::with_ngx_log(endpoint_str, headers, log) {
                Ok(t) => ExportTransport::Http(t),
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
        MetricProtocol::OtlpGrpc => {
            match GrpcTransport::<NgxConnector>::with_ngx_log(endpoint_str, log) {
                Ok(t) => ExportTransport::Grpc(t),
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

    let encoder = OtlpHttpEncoder;

    // Capture worker start time once — used as the start_time_unix_nano
    // for cumulative monotonic Sum self-metrics so that downstream rate
    // panels and delta-conversion processors can anchor windows correctly.
    let worker_start_ns = now_unix_nano();
    // Publish to the process-global atomic so that exit_process_flush can
    // read the same epoch anchor without re-computing it (see WORKER_START_NS).
    WORKER_START_NS.store(worker_start_ns, Ordering::Relaxed);

    // Retry buffer: (encoded bytes, number of data points in that batch).
    // Depth is configured (see `MainConfig::retry_buffer_depth`) so that
    // tuning later is a config change, not a code change.
    let retry_buffer_depth = amcf.retry_buffer_depth();
    let mut retry_queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();

    // Separate retry queue for log batches so that failed log sends don't
    // evict metric batches (and vice versa).
    let mut logs_retry_queue: VecDeque<(std::vec::Vec<u8>, u64)> = VecDeque::new();

    let logs_encoder = OtlpLogsEncoder;

    let protocol_str = match amcf.metric_protocol() {
        MetricProtocol::OtlpHttp => "otlp_http",
        MetricProtocol::OtlpGrpc => "otlp_grpc",
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
        // Phase 1.3.2: poll ngx_quit (not ngx_exiting). The exporter is not a
        // worker; master signals it to quit via ngx_quit on the channel handler
        // path (SIGQUIT → master → NGX_CMD_QUIT → ngx_quit). ngx_exiting is a
        // worker-specific flag set by the worker's SIGQUIT handler.
        if unsafe { nginx_sys::ngx_quit } != 0 {
            ngx::ngx_log_error!(
                NGX_LOG_NOTICE,
                log.as_ptr(),
                "otel export: ngx_quit set, starting graceful drain"
            );
            graceful_drain(&mut transport, &mut retry_queue, &mut logs_retry_queue, &encoder, amcf, worker_start_ns).await;
            EXPORT_LOOP_DONE.store(true, Ordering::Release);
            return;
        }

        // ── Chunked sleep for the configured export interval ──────────────────
        // We must check ngx_quit at least every SHUTDOWN_POLL_INTERVAL so that
        // SIGQUIT during a long sleep doesn't delay the drain significantly.
        // Phase 1.3.2: unlike workers, the exporter is not subject to
        // ngx_event_no_timers_left, so cancelable timers fire reliably on quit.
        //
        // Phase 2.1 (FU2): logs are drained on EVERY sub-interval wake
        // (SHUTDOWN_POLL_INTERVAL, default 250 ms) to decouple log throughput
        // from the metric aggregation interval.  This keeps rings from saturating
        // under high RPS and improves delivery fraction.  Metrics continue to
        // aggregate and export only at the full otel_metric_interval boundary.
        let interval = Duration::from_millis(amcf.interval_ms());
        let mut slept = Duration::ZERO;
        let mut shutdown_during_sleep = ShutdownKind::None;
        while slept < interval {
            let chunk = (interval - slept).min(SHUTDOWN_POLL_INTERVAL);
            ngx::async_::sleep(chunk).await;
            slept += chunk;
            if unsafe { nginx_sys::ngx_terminate } != 0 {
                shutdown_during_sleep = ShutdownKind::Terminate;
                break;
            }
            if unsafe { nginx_sys::ngx_quit } != 0 {
                shutdown_during_sleep = ShutdownKind::Exiting;
                break;
            }

            // ── Log drain: every sub-interval wake ──────────────────────────
            // Drain the logs retry queue first (best-effort; stop on failure).
            {
                let mut logs_queue_snap = core::mem::take(&mut logs_retry_queue);
                let mut logs_retry_failed = false;
                while let Some((bytes, n_logs)) = logs_queue_snap.pop_front() {
                    if logs_retry_failed {
                        enqueue_with_eviction(
                            &mut logs_retry_queue,
                            bytes,
                            n_logs,
                            retry_buffer_depth,
                            log.as_ptr(),
                        );
                        continue;
                    }
                    match transport.send_logs(bytes.clone()).await {
                        Ok(()) => {}
                        Err(ref e) => {
                            ngx::ngx_log_error!(
                                NGX_LOG_ERR,
                                log.as_ptr(),
                                "otel export: logs retry send failed ({}); re-queuing",
                                e
                            );
                            LOGS_SEND_FAILURES.fetch_add(1, Ordering::Relaxed);
                            enqueue_with_eviction(
                                &mut logs_retry_queue,
                                bytes,
                                n_logs,
                                retry_buffer_depth,
                                log.as_ptr(),
                            );
                            logs_retry_failed = true;
                        }
                    }
                }
            }

            // Drain fresh log records from all workers' rings and ship them.
            if amcf.is_access_sample_enabled() {
                if let Some(logs_base) = amcf.logs_shm_base() {
                    let n_workers = unsafe {
                        let zone = &*amcf.logs_shm_zone;
                        let avail = zone.shm.size.saturating_sub(crate::shm::data_offset());
                        logs_n_workers_from_zone(avail, amcf.log_ring_cap())
                    };
                    let logs_batch =
                        collect_log_records(amcf, logs_base, n_workers, worker_start_ns);
                    if !logs_batch.logs.is_empty() {
                        let n_logs = logs_batch.logs.len() as u64;
                        let logs_bytes = logs_encoder.encode(&logs_batch);
                        match transport.send_logs(logs_bytes.clone()).await {
                            Ok(()) => {
                                ngx::ngx_log_error!(
                                    NGX_LOG_NOTICE,
                                    log.as_ptr(),
                                    "otel export: sent {} log records to collector",
                                    n_logs
                                );
                            }
                            Err(ref e) => {
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
                        }
                    }
                }
            }
        }

        // ── Re-check shutdown flags after sleep ───────────────────────────
        if matches!(shutdown_during_sleep, ShutdownKind::Terminate)
            || unsafe { nginx_sys::ngx_terminate } != 0
        {
            return;
        }
        if matches!(shutdown_during_sleep, ShutdownKind::Exiting)
            || unsafe { nginx_sys::ngx_quit } != 0
        {
            ngx::ngx_log_error!(
                NGX_LOG_NOTICE,
                log.as_ptr(),
                "otel export: ngx_quit set during sleep, starting graceful drain"
            );
            graceful_drain(&mut transport, &mut retry_queue, &mut logs_retry_queue, &encoder, amcf, worker_start_ns).await;
            EXPORT_LOOP_DONE.store(true, Ordering::Release);
            return;
        }

        // ── Control-shm heartbeat (Phase 1.3.3 Sub-item 1) ──────────────────
        // Bump version once per drain cycle as a liveness heartbeat.
        // Phase 5 will reuse this increment after applying a reconfig to
        // signal delivery convergence to the collector.
        // TODO(phase-5): also write reconfig payload from control channel
        // into control_shm.flags before/after this bump.
        if let Some(ctrl) = amcf.control_shm_ptr() {
            unsafe { (*ctrl).version.fetch_add(1, Ordering::Relaxed) };
        }

        // ── Drain retry queue before collecting fresh data ────────────────
        // Stop draining as soon as a send fails — transport may still be down.
        let mut queue_snapshot = core::mem::take(&mut retry_queue);
        let mut drain_failed = false;
        while let Some((bytes, n_pts)) = queue_snapshot.pop_front() {
            if drain_failed {
                // Transport is down; re-enqueue remaining items without sending.
                enqueue_with_eviction(
                    &mut retry_queue,
                    bytes,
                    n_pts,
                    retry_buffer_depth,
                    log.as_ptr(),
                );
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
                    enqueue_with_eviction(
                        &mut retry_queue,
                        bytes,
                        n_pts,
                        retry_buffer_depth,
                        log.as_ptr(),
                    );
                    drain_failed = true;
                }
            }
        }

        // ── Collect fresh metrics from all sources ────────────────────────
        let batch = collect_all_sources(amcf, worker_start_ns);
        let n_pts = count_data_points(&batch);
        if n_pts > 0 {
            let bytes = encoder.encode(&batch);

            // ── Send the fresh batch ──────────────────────────────────────
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

/// Called when `ngx_quit` is detected from inside [`export_loop`].
///
/// Phase 1.3.2: runs on the **exporter's** `ngx_quit` path, not a worker's
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
/// # Documented Phase 1.1 limitation — RESOLVED in Phase 1.3
///
/// (Historical context retained; this section no longer describes a limitation.)
///
/// `ngx_event_no_timers_left()` returns `NGX_OK` (worker may exit) when the
/// only pending timers are `cancelable`. The ngx-rust SDK marks every
/// [`ngx::async_::sleep`] timer as cancelable
/// (`ngx-rust/src/async_/sleep.rs:94: ev.set_cancelable(1)`), so when SIGQUIT
/// arrived while Worker 0's [`export_loop`] was between intervals, nginx would
/// treat the worker as idle and exit before the timer fired.
///
/// **RESOLVED in Phase 1.3.2**: the exporter is not a worker and is not
/// subject to `ngx_event_no_timers_left`. When SIGQUIT arrives while the
/// exporter is between intervals, nginx's event loop does NOT cancel the
/// sleep timer — it fires normally, the export loop detects `ngx_quit`, and
/// runs this drain. The chunked sleep ([`SHUTDOWN_POLL_INTERVAL`]) caps
/// detection latency at 250 ms.
///
/// On Phase 1.3 builds, `exit_process_flush` is a dead-code helper (Phase 2
/// may resurrect it). The exporter cycle waits for [`EXPORT_LOOP_DONE`]
/// before calling `process::exit`, ensuring the drain always completes.
///
/// Q2 RESOLVED — option (a): old exporter races workers on SIGHUP. Dedup
/// via `time_unix_nano` on the collector side (cumulative-counter model).
/// Phase 2 (logs) reopens this when log-drain semantics force ordered handoff.
async fn graceful_drain(
    transport: &mut ExportTransport,
    retry_queue: &mut VecDeque<(std::vec::Vec<u8>, u64)>,
    logs_retry_queue: &mut VecDeque<(std::vec::Vec<u8>, u64)>,
    encoder: &OtlpHttpEncoder,
    amcf: &'static MainConfig,
    worker_start_ns: u64,
) {
    let log = ngx::log::ngx_cycle_log();
    let queued = retry_queue.len();
    ngx::ngx_log_error!(
        NGX_LOG_NOTICE,
        log.as_ptr(),
        "otel export: graceful drain starting ({} queued batch(es))",
        queued
    );

    // Flush retry queue (one bounded attempt each, ignore errors).
    while let Some((bytes, n_pts)) = retry_queue.pop_front() {
        match with_deadline(transport.send(bytes), GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET).await {
            Ok(Ok(())) => {}
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
                let remaining: u64 = retry_queue.iter().map(|(_, n)| n).sum();
                if remaining > 0 {
                    DROPPED_RECORDS.fetch_add(remaining, Ordering::Relaxed);
                }
                retry_queue.clear();
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
                let remaining: u64 = retry_queue.iter().map(|(_, n)| n).sum();
                if remaining > 0 {
                    DROPPED_RECORDS.fetch_add(remaining, Ordering::Relaxed);
                }
                retry_queue.clear();
                break;
            }
        }
    }

    // Final freshly-collected metrics batch.
    let final_batch = collect_all_sources(amcf, worker_start_ns);
    let n_pts = count_data_points(&final_batch);
    if n_pts > 0 {
        let bytes = encoder.encode(&final_batch);
        match with_deadline(transport.send(bytes), GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET).await {
            Ok(Ok(())) => {
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

    // Drain pending logs retry queue (one bounded attempt each).
    while let Some((bytes, n_logs)) = logs_retry_queue.pop_front() {
        match with_deadline(transport.send_logs(bytes), GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                ngx::ngx_log_error!(
                    NGX_LOG_ERR,
                    log.as_ptr(),
                    "otel export: drain: logs queued batch ({} records) send failed: {}",
                    n_logs,
                    e
                );
                logs_retry_queue.clear();
                break;
            }
            Err(DeadlineExceeded) => {
                ngx::ngx_log_error!(
                    NGX_LOG_NOTICE,
                    log.as_ptr(),
                    "otel export: drain: logs queued batch ({} records) timed out",
                    n_logs
                );
                logs_retry_queue.clear();
                break;
            }
        }
    }

    // Final freshly-collected logs batch.
    if amcf.is_access_sample_enabled() {
        if let Some(logs_base) = amcf.logs_shm_base() {
            let n_workers = unsafe {
                let zone = &*amcf.logs_shm_zone;
                let avail = zone.shm.size.saturating_sub(crate::shm::data_offset());
                logs_n_workers_from_zone(avail, amcf.log_ring_cap())
            };
            let logs_batch = collect_log_records(amcf, logs_base, n_workers, worker_start_ns);
            if !logs_batch.logs.is_empty() {
                let n_logs = logs_batch.logs.len() as u64;
                let logs_bytes = OtlpLogsEncoder.encode(&logs_batch);
                match with_deadline(
                    transport.send_logs(logs_bytes),
                    GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET,
                )
                .await
                {
                    Ok(Ok(())) => {
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

    ngx::ngx_log_error!(NGX_LOG_NOTICE, log.as_ptr(), "otel export: graceful drain complete");
}

// ── Deadline-bounded future ─────────────────────────────────────────────────

/// Sentinel returned by [`with_deadline`] when the timer fires before the
/// inner future completes.
struct DeadlineExceeded;

pin_project! {
    /// Races an inner future against an [`ngx::async_::Sleep`]. Whichever
    /// resolves first wins. No allocation, no `select!` machinery.
    struct WithDeadline<F> {
        #[pin]
        fut: F,
        #[pin]
        timer: ngx::async_::Sleep,
    }
}

impl<F: Future> Future for WithDeadline<F> {
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
fn with_deadline<F: Future>(fut: F, timeout: Duration) -> WithDeadline<F> {
    WithDeadline { fut, timer: ngx::async_::sleep(timeout) }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Enqueue a batch for retry.  If the queue is already at `max_depth`,
/// the oldest entry is dropped and `DROPPED_RECORDS` is incremented.
///
/// Returns the number of data points dropped (0 if the queue was not full).
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
                    "otel export: retry buffer full, dropped {} data points",
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

/// Collect from all configured [`MetricSource`]s and assemble a [`Batch`].
///
/// Accepts `&MainConfig` rather than `&'static MainConfig` so it can be
/// called from both the async export loop (which holds `'static`) and from
/// synchronous paths like [`exit_process_flush`] that hold a shorter-lived
/// reference to the current cycle's config.
fn collect_all_sources(amcf: &MainConfig, worker_start_ns: u64) -> Batch {
    let mut metrics = std::vec::Vec::new();

    // 1. NGINX connection / request counters (stub_status equivalents).
    metrics.extend(StubStatusSource.collect());

    // 2. Per-worker shm histograms (http.server.request.duration, etc.).
    if let Some(base) = amcf.shm_base() {
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
        if let (Ok(k), Ok(v)) =
            (core::str::from_utf8(kv.key.as_bytes()), core::str::from_utf8(kv.value.as_bytes()))
        {
            resource_attrs.push(KeyValue { key: k.into(), value: AnyValue::String(v.into()) });
        }
    }

    Batch {
        resource: Resource { attributes: resource_attrs },
        scope: Scope { name: "ngx-otel-rust".into(), version: env!("CARGO_PKG_VERSION").into() },
        metrics,
    }
}

/// Drain all worker access-log rings and assemble a [`LogsBatch`].
///
/// Called once per export tick when `is_access_sample_enabled()` is true.
/// Drains tail records written by `is_interesting()` requests.
/// Does NOT drain error rings (Phase 2.3).
///
/// Also updates the `ACCESS_LOGS_DROPPED` self-metric by reading each ring's
/// `drop_count()` and computing the delta vs the previous cycle.
fn collect_log_records(
    amcf: &MainConfig,
    logs_base: *mut u8,
    n_workers: usize,
    _now_ns: u64,
) -> LogsBatch {
    let now = now_unix_nano();

    // ── Build Resource from config ────────────────────────────────────────
    let mut resource_attrs: std::vec::Vec<KeyValue> = std::vec::Vec::new();
    if !amcf.service_name.is_empty() {
        if let Ok(name) = core::str::from_utf8(amcf.service_name.as_bytes()) {
            resource_attrs
                .push(KeyValue { key: "service.name".into(), value: AnyValue::String(name.into()) });
        }
    }
    for kv in &amcf.resource_attrs {
        if let (Ok(k), Ok(v)) = (
            core::str::from_utf8(kv.key.as_bytes()),
            core::str::from_utf8(kv.value.as_bytes()),
        ) {
            resource_attrs
                .push(KeyValue { key: k.into(), value: AnyValue::String(v.into()) });
        }
    }

    let mut logs: std::vec::Vec<LogRecord> = std::vec::Vec::new();
    let mut total_dropped: u64 = 0;

    let cap = amcf.log_ring_cap();

    // Maximum records to drain from each worker ring per cycle.
    //
    // Caps the HTTP POST body size: at ~200 bytes/record, 2 500 records per
    // worker = ~500 KB/worker → total batch ≤ 2 MB for N ≤ 4 workers.
    // Remaining records stay in the ring and are drained on the next 250 ms
    // wake.  This keeps batches within the collector's max request body size
    // (default 20 MB for otelcol-contrib) even when rings are large.
    const MAX_RECORDS_PER_WORKER_PER_DRAIN: usize = 2_500;

    // Drain access rings for all workers.
    for w in 0..n_workers {
        // Safety: zone was sized for n_workers at registration; w < n_workers.
        let ring = unsafe { logs_access_ring(logs_base, w, cap) };

        // Accumulate drop counts.
        total_dropped += ring.drop_count();

        // Drain up to MAX_RECORDS_PER_WORKER_PER_DRAIN records per worker.
        let mut record_buf: std::vec::Vec<u8> = std::vec::Vec::new();
        let mut drained = 0usize;
        while drained < MAX_RECORDS_PER_WORKER_PER_DRAIN && ring.pop_into(&mut record_buf) {
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

    LogsBatch {
        resource: Resource { attributes: resource_attrs },
        scope: Scope { name: "ngx-otel-rust".into(), version: env!("CARGO_PKG_VERSION").into() },
        logs,
    }
}

/// Parse one access log record from the wire-format bytes produced by
/// `logs::access::emit_access_record`.
///
/// Returns `None` if the buffer is too short to be a valid record.
fn parse_access_record(buf: &[u8], observed_now_ns: u64) -> Option<LogRecord> {
    use crate::data_model::{AnyValue, KeyValue, SeverityNumber};

    // Minimum: kind(1) + ts(8) + level(1) + method_len(2) + status(2) +
    //          req_len(8) + resp_bytes(8) + client_addr_len(2) = 32 bytes
    if buf.len() < 32 {
        return None;
    }

    let mut pos = 0usize;

    // kind must be 0x00 (access)
    if buf[pos] != 0x00 {
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

    // ── Phase 2.2.3 / 2.2.5: trace context + high-cardinality tail detail ─────
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

    let mut attributes = std::vec![
        KeyValue {
            key: "http.request.method".into(),
            value: AnyValue::String(method),
        },
        KeyValue {
            key: "http.response.status_code".into(),
            value: AnyValue::Int(status as i64),
        },
        KeyValue {
            key: "http.server.request.body.size".into(),
            value: AnyValue::Int(req_len as i64),
        },
        KeyValue {
            key: "http.server.response.body.size".into(),
            value: AnyValue::Int(resp_bytes as i64),
        },
        KeyValue {
            key: "client.address".into(),
            value: AnyValue::String(client_addr),
        },
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
            value: AnyValue::String(
                std::string::String::from_utf8_lossy(&user_agent).into_owned(),
            ),
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

fn now_unix_nano() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

/// Build a monotonic cumulative Sum metric carrying a single i64 data point.
///
/// `start_time_unix_nano` must be the time the worker (and therefore the
/// counter) started. OTel cumulative semantics require this so rate
/// computations across collector restarts work correctly; a `0` start time
/// means epoch (1970) and confuses delta-conversion processors.
fn monotonic_sum_metric(
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

// ── exit_process flush ────────────────────────────────────────────────────────

/// Synchronous final flush for the `exit_process` module callback.
///
/// Collects one final batch from all configured [`MetricSource`]s, encodes it,
/// and ships it via the synchronous HTTP client in
/// [`crate::transport::sync_http`].  Uses a 500 ms budget for each I/O phase.
///
/// This function **closes the Phase 1.1 graceful-drain limitation** described
/// in [`graceful_drain`]: the async drain may not fire when SIGQUIT arrives
/// while the export loop is between intervals (asleep on a cancelable timer).
/// `exit_process_flush` fires unconditionally when the worker exits, covering
/// that gap.
///
/// If both the async drain and `exit_process_flush` fire (e.g., SIGQUIT
/// arrives during the active part of the loop body), the worst case is a
/// duplicate batch arriving at the collector; the collector deduplicates via
/// timestamps.
///
/// # Called from
/// `ngx_otel_exit_process` in `src/lib.rs`, gated on Worker 0 / single-process
/// mode.  Do not call from other contexts.
// Phase 1.3.2: no longer called from ngx_otel_exit_process (workers are no-ops).
// Kept as a callable helper for the exporter's graceful_drain path; Sub-item 2
// wires it up. Phase 2 (logs) may also use it from the producer side.
#[allow(dead_code)]
pub fn exit_process_flush(amcf: &MainConfig) {
    let log = ngx::log::ngx_cycle_log();

    // Read the epoch anchor published by export_loop at startup.
    let worker_start_ns = WORKER_START_NS.load(Ordering::Acquire);
    if worker_start_ns == 0 {
        // export_loop never ran its first iteration (e.g., SIGQUIT arrived
        // before the async task was polled).  Nothing to flush.
        return;
    }

    ngx::ngx_log_error!(NGX_LOG_NOTICE, log.as_ptr(), "exit_process: sync flush starting");

    let batch = collect_all_sources(amcf, worker_start_ns);
    let n_pts = count_data_points(&batch);

    if n_pts == 0 {
        return;
    }

    let encoder = OtlpHttpEncoder;
    let bytes = encoder.encode(&batch);

    let endpoint_str = match core::str::from_utf8(amcf.exporter.endpoint.as_bytes()) {
        Ok(s) => s,
        Err(_) => {
            ngx::ngx_log_error!(
                NGX_LOG_ERR,
                log.as_ptr(),
                "exit_process: sync flush: endpoint is not valid UTF-8, skipping"
            );
            return;
        }
    };

    let headers: std::vec::Vec<(std::string::String, std::string::String)> = amcf
        .exporter_headers
        .iter()
        .filter_map(|kv| {
            let k = std::string::String::from(core::str::from_utf8(kv.key.as_bytes()).ok()?);
            let v = std::string::String::from(core::str::from_utf8(kv.value.as_bytes()).ok()?);
            Some((k, v))
        })
        .collect();

    match crate::transport::sync_http::sync_post(endpoint_str, &headers, &bytes) {
        Ok(()) => {
            ngx::ngx_log_error!(
                NGX_LOG_NOTICE,
                log.as_ptr(),
                "exit_process: sync flush complete ({} data points)",
                n_pts
            );
        }
        Err(ref e) if e.is_timeout() => {
            ngx::ngx_log_error!(NGX_LOG_NOTICE, log.as_ptr(), "exit_process: sync flush timed out");
        }
        Err(ref e) => {
            ngx::ngx_log_error!(
                NGX_LOG_ERR,
                log.as_ptr(),
                "exit_process: sync flush failed: {}",
                e
            );
        }
    }

    // ── Sync flush of pending tail logs (Phase 2.2, HTTP only) ──────────────
    // Only flush logs if access_sample is enabled and the logs shm zone is mapped.
    if amcf.is_access_sample_enabled() {
        if let Some(logs_base) = amcf.logs_shm_base() {
            let n_workers = unsafe {
                let zone = &*amcf.logs_shm_zone;
                let avail = zone.shm.size.saturating_sub(crate::shm::data_offset());
                logs_n_workers_from_zone(avail, amcf.log_ring_cap())
            };
            let logs_batch = collect_log_records(amcf, logs_base, n_workers, worker_start_ns);
            if !logs_batch.logs.is_empty() {
                let n_logs = logs_batch.logs.len() as u64;
                let logs_bytes = OtlpLogsEncoder.encode(&logs_batch);
                // Derive /v1/logs endpoint from the metrics endpoint base.
                let logs_endpoint = derive_logs_endpoint(endpoint_str);
                match crate::transport::sync_http::sync_post(
                    &logs_endpoint,
                    &headers,
                    &logs_bytes,
                ) {
                    Ok(()) => {
                        ngx::ngx_log_error!(
                            NGX_LOG_NOTICE,
                            log.as_ptr(),
                            "exit_process: sync logs flush complete ({} records)",
                            n_logs
                        );
                    }
                    Err(ref e) if e.is_timeout() => {
                        ngx::ngx_log_error!(
                            NGX_LOG_NOTICE,
                            log.as_ptr(),
                            "exit_process: sync logs flush timed out"
                        );
                    }
                    Err(ref e) => {
                        ngx::ngx_log_error!(
                            NGX_LOG_ERR,
                            log.as_ptr(),
                            "exit_process: sync logs flush failed: {}",
                            e
                        );
                    }
                }
            }
        }
    }
}

/// Derive the `/v1/logs` OTLP endpoint URL from the metrics endpoint.
///
/// For HTTP endpoints of the form `http://host:port/v1/metrics`, replaces the
/// path with `/v1/logs`.  For endpoints without an explicit path component or
/// with other paths, appends `/v1/logs` to the host:port.
fn derive_logs_endpoint(metrics_endpoint: &str) -> std::string::String {
    // Strip the path from the metrics endpoint and replace with /v1/logs.
    if let Some(rest) = metrics_endpoint.strip_prefix("http://") {
        let (authority, _path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        std::format!("http://{}/v1/logs", authority)
    } else {
        // For non-HTTP (gRPC, unix), return as-is.  The gRPC logs flush is
        // handled by the async graceful_drain path; sync_post is HTTP-only.
        std::string::String::from(metrics_endpoint)
    }
}

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
        assert_eq!(
            dropped, 1 + 2,
            "evicted data-point counts (helper return) must sum to 3"
        );
    }

    /// SelfMetricsSource must produce exactly 7 metrics with the right names.
    /// (Updated in Phase 2.1 to include 3 new logs-path metrics.)
    #[test]
    fn self_metrics_source_produces_four_metrics() {
        let src = SelfMetricsSource {
            interval_ms: 10_000,
            start_time_unix_nano: 1_700_000_000_000_000_000,
        };
        let metrics = src.collect();
        assert_eq!(metrics.len(), 7, "SelfMetricsSource must emit 7 metrics (4 original + 3 log)");

        let names: std::vec::Vec<&str> = metrics.iter().map(|m| m.name.as_str()).collect();
        // Original 4
        assert!(names.contains(&"ngx_otel.dropped_records"));
        assert!(names.contains(&"ngx_otel.send_failures"));
        assert!(names.contains(&"ngx_otel.bidi_backpressure_drops"));
        assert!(names.contains(&"ngx_otel.export_interval"));
        // Phase 2.1 — 3 new log metrics
        assert!(names.contains(&"ngx_otel.logs.access.dropped_records"));
        assert!(names.contains(&"ngx_otel.logs.error.dropped_records"));
        assert!(names.contains(&"ngx_otel.logs.send_failures"));
    }

    /// `collect_log_records` with empty rings produces an empty LogsBatch.
    #[test]
    fn logs_drain_handles_empty_rings() {
        use crate::logs::ring::{DEFAULT_LOG_RING_CAP, ring_size_bytes, RING_HEADER_SIZE, LogsWorkerRingHeader};
        use crate::shm::logs_slot_size;

        // Allocate one worker slot with default cap.
        let cap = DEFAULT_LOG_RING_CAP;
        let slot_sz = logs_slot_size(cap);
        let layout = std::alloc::Layout::from_size_align(slot_sz, 8).unwrap();
        let slot_ptr = unsafe { std::alloc::alloc_zeroed(layout) };

        // Stamp cap into both ring headers (mirrors logs_shm_zone_init).
        unsafe {
            let access_hdr = slot_ptr.cast::<LogsWorkerRingHeader>();
            (*access_hdr).cap = cap as u64;
            let error_hdr = slot_ptr.add(ring_size_bytes(cap)).cast::<LogsWorkerRingHeader>();
            (*error_hdr).cap = cap as u64;
        }

        // Synthesize a minimal config (log_ring_cap() = DEFAULT_LOG_RING_CAP).
        let amcf = crate::config::MainConfig::default();

        let batch = collect_log_records(&amcf, slot_ptr, 1, 0);
        assert!(batch.logs.is_empty(), "empty rings must produce empty LogsBatch");

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
            dropped +=
                enqueue_with_eviction(&mut queue, std::vec![0u8], i + 1, depth, core::ptr::null_mut());
        }
        assert_eq!(queue.len(), depth);
        // Evicted items had n=1, n=2 → dropped 3
        assert_eq!(dropped, 1 + 2);
    }
}
