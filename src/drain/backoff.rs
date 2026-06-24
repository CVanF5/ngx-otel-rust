// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Per-signal delivery-outcome policy engine and exponential backoff state.
//!
//! The policy is written once against the protocol-agnostic [`crate::transport::DeliveryOutcome`]
//! — the transport adapters already map native HTTP/gRPC status into it, so no
//! HTTP codes or gRPC codes appear here.
//!
//! Defer mechanism: a per-signal "not before" monotonic timestamp + a per-signal
//! consecutive-`Retryable`-failure counter.  Honoring a backoff *defers the next
//! drain* of that signal — it does NOT grow the buffer or add any unbounded store.
//! The bounded per-signal retry buffer with drop-oldest eviction remains the backstop.

use core::sync::atomic::{AtomicU64, Ordering};

use nginx_sys::NGX_LOG_ERR;

use super::graceful::enqueue_with_eviction;
use super::self_metrics::{PARTIAL_REJECTED, PERMANENT_REJECTED, UNAUTHORIZED_REJECTED};
use super::{BACKOFF_BASE_MS, BACKOFF_CAP_MS};

// ── Clock abstraction ─────────────────────────────────────────────────────────

/// Injectable clock override for unit tests. Non-zero values replace the
/// `ngx_current_msec` read in `now_monotonic_msec()`, allowing tests to
/// simulate pre-send and post-send clock advances without a real nginx event
/// loop. Zero (the default) is a no-op: the real nginx global is read instead.
///
/// Tests that touch this field MUST reset it to 0 before returning so that
/// sibling tests that rely on `ngx_current_msec == 0` (the test-process
/// default) are not disturbed.
#[cfg(test)]
pub(super) static TEST_CLOCK_MSEC: AtomicU64 = AtomicU64::new(0);

/// Read the current monotonic millisecond basis used for defer timestamps.
/// Reuses nginx's cached `CLOCK_MONOTONIC` (`ngx_current_msec`, updated by the
/// event loop the exporter runs on) — the SAME basis `liveness` uses. No new
/// clock is introduced.
///
/// # Safety
/// `ngx_current_msec` is an nginx global updated by the event loop in this
/// single-threaded exporter process; a plain read is well-defined.
#[inline]
pub(super) fn now_monotonic_msec() -> u64 {
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
pub(super) fn post_send_backoff_basis() -> u64 {
    now_monotonic_msec()
}

// ── SignalBackoff ─────────────────────────────────────────────────────────────

/// Per-signal backoff/defer state. Lives in `export_loop` locals (one per
/// signal lane) — single-task, exporter-local; never shared across threads.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct SignalBackoff {
    /// Monotonic `ngx_current_msec` value before which this signal must NOT be
    /// drained again. `0` = no active deferral. The drain loop reuses nginx's
    /// existing cached `CLOCK_MONOTONIC` millisecond basis (`ngx_current_msec`)
    /// — no new clock is introduced.
    pub(super) not_before_msec: u64,
    /// Count of consecutive `Retryable` verdicts for this signal since the last
    /// `Accepted`. Drives the no-hint exponential backoff doubling; reset to 0
    /// on the next `Accepted`.
    pub(super) consecutive_retryable: u32,
}

impl SignalBackoff {
    /// Whether a drain of this signal is currently deferred at `now_msec`.
    /// `not_before_msec == 0` means no deferral is active.
    #[inline]
    pub(super) fn is_deferred(&self, now_msec: u64) -> bool {
        self.not_before_msec != 0 && now_msec < self.not_before_msec
    }
}

/// The action the policy engine prescribes for a drained/sent batch. The caller
/// performs the buffer mutation (release = drop the in-hand batch; requeue =
/// `enqueue_with_eviction`; drop = discard); the defer/backoff bookkeeping has
/// already been applied to the `SignalBackoff` by [`apply_delivery_outcome`].
#[derive(Debug, PartialEq, Eq)]
pub(super) enum OutcomeAction {
    /// Release the batch (delivered). Backoff was reset.
    Release,
    /// Re-queue the batch into the bounded buffer; the next drain of this signal
    /// is deferred (see the `SignalBackoff`).
    Requeue,
    /// Drop the batch permanently (Permanent / Unauthorized); do NOT retry.
    Drop,
}

// ── Backoff math ──────────────────────────────────────────────────────────────

/// Compute the no-hint exponential backoff duration (ms) for the
/// `consecutive_retryable`-th consecutive retryable failure: `base << (n-1)`,
/// saturating at `cap`. `n == 0` is treated as the first failure.
#[inline]
pub(super) fn backoff_ms(consecutive_retryable: u32, base_ms: u64, cap_ms: u64) -> u64 {
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

// ── Outcome-driven policy ─────────────────────────────────────────────────────

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
pub(super) fn maybe_log_unauthorized(log: *mut nginx_sys::ngx_log_t, signal: &str) {
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

/// Returns true if the transport error is a permanent 4xx HTTP rejection that
/// must be dropped rather than re-queued.
#[inline]
pub(super) fn is_permanent_rejection(e: &crate::transport::TransportError) -> bool {
    matches!(e, crate::transport::TransportError::HttpStatus { code, .. } if *code >= 400 && *code < 500)
}

/// The outcome-driven policy, written ONCE against `DeliveryOutcome`. Updates
/// `backoff` (defer timestamp + consecutive-failure counter) and the
/// delivery-outcome self-metric counters, and returns the buffer action for the
/// caller to perform.
///
/// `now_msec` is the current monotonic basis (`ngx_current_msec` in production;
/// an injected value in tests). `signal` and `log` are used only for the
/// rate-limited `Unauthorized` "check credentials" log.
pub(super) fn apply_delivery_outcome(
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
pub(super) fn handle_fresh_send_outcome(
    outcome: &crate::transport::DeliveryOutcome,
    backoff: &mut SignalBackoff,
    now_msec: u64,
    queue: &mut std::collections::VecDeque<(std::vec::Vec<u8>, u64)>,
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

/// Apply the send outcome for a **fresh batch** of any signal, re-reading the
/// monotonic clock internally (after the send await) so the backoff deadline is
/// computed from a fresh "now", not a pre-send stale capture.
///
/// The basis is always read here — immediately before delegating to
/// [`handle_fresh_send_outcome`] — so a call site cannot accidentally pass a
/// stale pre-send clock value regardless of which signal lane invokes it.
/// `signal` is the lane name ("metrics" / "logs" / "spans") used only for the
/// diagnostic log wording.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_fresh_send_outcome(
    outcome: &crate::transport::DeliveryOutcome,
    backoff: &mut SignalBackoff,
    queue: &mut std::collections::VecDeque<(std::vec::Vec<u8>, u64)>,
    bytes: std::vec::Vec<u8>,
    n_records: u64,
    retry_buffer_depth: usize,
    failure_counter: &AtomicU64,
    log: *mut nginx_sys::ngx_log_t,
    signal: &'static str,
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
        signal,
    )
}
