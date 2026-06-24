// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Graceful drain on `ngx_quit`, deadline-bounded future, and retry-queue helpers.
//!
//! [`graceful_drain`] is called when the outer drain loop detects `ngx_quit`.
//! It flushes any in-process retry buffers and sends one final freshly-collected
//! batch per signal before allowing the exporter process to exit.
//!
//! [`WithDeadline`] races an inner future against a timer so that a hung
//! collector cannot stall exporter shutdown.  [`enqueue_with_eviction`]
//! maintains the bounded per-signal retry buffers used throughout the drain loop.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::task::{Context, Poll};
use std::collections::VecDeque;

use nginx_sys::{NGX_LOG_ERR, NGX_LOG_NOTICE};
use pin_project_lite::pin_project;

use super::self_metrics::DROPPED_RECORDS;
use super::{
    collect_all_sources, collect_log_records, collect_span_records, count_pdata_records,
    encode_pdata, get_n_workers, ExportTransport, GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET,
};
use crate::config::MainConfig;
use crate::data_model::Pdata;
use crate::processor::Processor;
use crate::shm::{logs_n_workers_from_zone, spans_n_workers_from_zone, DEFAULT_SPAN_RING_CAP};

// ── Deadline-bounded future ─────────────────────────────────────────────────

/// Sentinel returned by [`with_deadline`] when the timer fires before the
/// inner future completes.
pub(super) struct DeadlineExceeded;

pin_project! {
    /// Races an inner future against a timer future. Whichever resolves first
    /// wins. No allocation, no `select!` machinery.
    ///
    /// Generic over the timer type `T` so that production passes
    /// [`ngx::async_::Sleep`] (driven by the NGINX event loop) while unit tests
    /// can inject a deterministic, runtime-free timer (e.g. ready-on-first-poll)
    /// to exercise the deadline-expiry arm without a real wall-clock wait.
    pub(super) struct WithDeadline<F, T> {
        #[pin]
        pub(super) fut: F,
        #[pin]
        pub(super) timer: T,
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
pub(super) fn with_deadline<F: Future>(
    fut: F,
    timeout: core::time::Duration,
) -> WithDeadline<F, ngx::async_::Sleep> {
    WithDeadline { fut, timer: ngx::async_::sleep(timeout) }
}

// ── Retry-queue helpers ──────────────────────────────────────────────────────

/// Enqueue a batch for retry.  If the queue is already at `max_depth`,
/// the oldest entry is evicted and `DROPPED_RECORDS` is incremented (F6:
/// `DROPPED_RECORDS` covers all three signal lanes — metrics, logs, spans).
///
/// Returns the number of records dropped (0 if the queue was not full).
///
/// `log` may be null; the eviction-logging path is guarded against that so the
/// unit test can call this directly without constructing an `ngx_log_t`.
#[inline]
pub(super) fn enqueue_with_eviction(
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

/// Credits `counter` for all pending `(bytes, n_records)` batches in
/// `queue`, then clears it.
///
/// Called from `graceful_drain`'s send-failure and timeout arms for the logs
/// and spans retry queues.  Pre-fix, `clear()` ran without accumulating the
/// count — queued records were silently discarded without incrementing any
/// drop counter.
///
/// Extracted to a named function so the test can call the production logic
/// directly rather than re-implementing the pattern inline.
pub(super) fn account_drops_and_clear(
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
pub(super) fn successor_announced(amcf: &MainConfig, my_gen: u64) -> bool {
    amcf.control_shm_ptr()
        .map(|p| {
            // SAFETY: `control_shm_ptr()` returns `Some` only when the control
            // shm zone is registered and mapped; the raw pointer is valid for
            // this exporter's lifetime (cycle-pool allocated).
            (unsafe { (*p).successor_gen.load(core::sync::atomic::Ordering::Acquire) }) > my_gen
        })
        .unwrap_or(false)
}

// ── Drain queues ─────────────────────────────────────────────────────────────

/// Retry queues for all three signal transports — metrics, logs, and spans.
///
/// Bundled into a single argument to keep [`graceful_drain`]'s signature
/// concise.  Each field is a mutable borrow of the queue owned by
/// `export_loop`, so the queues are drained in-place during the flush.
pub(super) struct DrainQueues<'a> {
    /// Retry queue for OTLP metrics batches.
    pub(super) metrics: &'a mut VecDeque<(std::vec::Vec<u8>, u64)>,
    /// Retry queue for OTLP logs batches.
    pub(super) logs: &'a mut VecDeque<(std::vec::Vec<u8>, u64)>,
    /// Retry queue for OTLP spans batches.
    pub(super) spans: &'a mut VecDeque<(std::vec::Vec<u8>, u64)>,
}

// ── Graceful drain ────────────────────────────────────────────────────────────

/// Called when `ngx_quit` is detected from inside `export_loop`.
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
/// The chunked sleep ([`super::SHUTDOWN_POLL_INTERVAL`]) caps detection latency at
/// 250 ms.
///
/// This async drain is the sole final-flush path. The exporter cycle waits
/// for `EXPORT_LOOP_DONE` before calling `process::exit`, ensuring the
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
pub(super) async fn graceful_drain(
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
            // SAFETY: `logs_shm_base()` returned `Some`, so `logs_shm_zone` is
            // non-null and points to a live, mapped zone for the exporter's
            // lifetime.
            let n_workers = unsafe {
                get_n_workers(&amcf.n_active_workers, amcf.logs_shm_zone, |avail| {
                    logs_n_workers_from_zone(avail, amcf.log_ring_cap())
                })
            };
            // Pdata pipeline: wrap → process → encode → send (Step U2).
            let (logs_batch, logs_drops) =
                collect_log_records(amcf, logs_base, n_workers, worker_start_ns);
            use super::self_metrics::{
                ACCESS_LOGS_DROPPED, ERROR_LOGS_COALESCED_ORPHANED, ERROR_LOGS_DROPPED,
            };
            ACCESS_LOGS_DROPPED.store(logs_drops.access_dropped, Ordering::Relaxed);
            ERROR_LOGS_DROPPED.store(logs_drops.error_dropped, Ordering::Relaxed);
            if logs_drops.error_coalesced_orphaned > 0 {
                ERROR_LOGS_COALESCED_ORPHANED
                    .fetch_add(logs_drops.error_coalesced_orphaned, Ordering::Relaxed);
            }
            let mut logs_pd = Pdata::Logs(logs_batch);
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
            // SAFETY: `spans_shm_base()` returned `Some`, so `spans_shm_zone` is
            // non-null and points to a live, mapped zone for the exporter's
            // lifetime.
            let n_workers = unsafe {
                get_n_workers(&amcf.n_active_workers, amcf.spans_shm_zone, |avail| {
                    spans_n_workers_from_zone(avail, DEFAULT_SPAN_RING_CAP)
                })
            };
            let (spans_batch, spans_dropped) = collect_span_records(amcf, spans_base, n_workers);
            use super::self_metrics::TRACES_DROPPED_RECORDS;
            TRACES_DROPPED_RECORDS.store(spans_dropped, Ordering::Relaxed);
            let mut spans_pd = Pdata::Spans(spans_batch);
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
