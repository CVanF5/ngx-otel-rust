// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Exporter liveness detection (heartbeat-stale alert). Turns a *silent*
//! exporter death (esp. the gen-1 `daemon on` case — see `LIFECYCLE.md`
//! §"Known limitation: gen-1 exporter under `daemon on`") into a prompt,
//! **latched** ALERT in the worker's error log, the only channel still
//! working when the exporter is dead.
//!
//! Design: the **drop is the TRIGGER** (a ring-full drop on the worker's
//! span/access-tail push path — an already-counted symptom, zero added cost
//! on the healthy hot path, no per-request check) and the **heartbeat is the
//! VERDICT** ([`crate::exporter::control_shm::ControlShm::last_beat_msec`]):
//! a saturated-but-alive exporter keeps beating and exporting
//! `*.dropped_records`, so drops alone never alert — only a heartbeat older
//! than [`HEARTBEAT_STALE_THRESHOLD_MS`] does. The beat is bumped by a
//! dedicated timer independent of drain/send progress (a blackholed-collector
//! stall cannot delay beats), and the staleness threshold is derived from the
//! **beat period we own, never from the drain interval**
//! (`otel_metric_interval` is operator-configurable and must not be
//! load-bearing for liveness meaning). Both sides read `ngx_current_msec`
//! (same monotonic basis). The alert latches per worker per exporter
//! generation (`ControlShm::successor_gen`), re-armed only by a SIGHUP reload.

use core::sync::atomic::{AtomicU64, Ordering};

/// How often the dedicated beat timer re-arms and stamps
/// `ControlShm::last_beat_msec`. 1 s: negligible cost, and lets the
/// staleness threshold sit at single-digit seconds.
pub const HEARTBEAT_PERIOD_MS: u64 = 1_000;

/// Staleness threshold, derived from the beat period (5× = 5 s — tolerates
/// jitter/missed beats, still far below operator timescales). Deliberately
/// NOT derived from the drain interval (`otel_metric_interval` is
/// operator-configurable and must not change liveness meaning).
pub const HEARTBEAT_STALE_THRESHOLD_MS: u64 = 5 * HEARTBEAT_PERIOD_MS;

// Hard requirement (b): threshold must be whole seconds, at least 5 s, and a
// strict multiple of the beat period.
const _: () = assert!(HEARTBEAT_STALE_THRESHOLD_MS >= 5_000);
const _: () = assert!(HEARTBEAT_STALE_THRESHOLD_MS % 1_000 == 0);
const _: () = assert!(HEARTBEAT_STALE_THRESHOLD_MS % HEARTBEAT_PERIOD_MS == 0);
const _: () = assert!(HEARTBEAT_STALE_THRESHOLD_MS / HEARTBEAT_PERIOD_MS >= 2);

/// Sentinel for "this worker has not latched an alert yet".
///
/// `successor_gen` starts at 0 and increments once per SIGHUP reload, so it
/// can never realistically reach `u64::MAX`.
pub const LATCH_UNSET: u64 = u64::MAX;

/// Staleness predicate (pure, unit-tested). Both args share the same
/// monotonic basis (`ngx_current_msec`, system-wide, so cross-process
/// comparison is sound).
///
/// `last_beat_msec == 0` (never beaten) → not stale (startup grace, avoids a
/// false alert between worker fork and the exporter's first beat).
/// `last_beat_msec > now_msec` (clocks marginally skewed) → `saturating_sub`
/// yields 0 → not stale.
#[inline]
pub fn heartbeat_is_stale(now_msec: u64, last_beat_msec: u64) -> bool {
    last_beat_msec != 0 && now_msec.saturating_sub(last_beat_msec) > HEARTBEAT_STALE_THRESHOLD_MS
}

/// Latch decision (pure, unit-tested): `true` exactly when stale AND no
/// alert has been emitted for `current_gen` yet. A SIGHUP reload bumps
/// `ControlShm::successor_gen`, so `latched_gen != current_gen` re-arms the
/// latch for the new exporter generation.
#[inline]
pub fn latch_should_alert(latched_gen: u64, current_gen: u64, stale: bool) -> bool {
    stale && latched_gen != current_gen
}

/// Per-worker-process latch: the `successor_gen` already alerted for
/// ([`LATCH_UNSET`] = none). Process-local by construction (statics are not
/// shared after fork); atomic only for Rust's `static` rules — the worker
/// event loop is single-threaded.
static ALERT_LATCHED_GEN: AtomicU64 = AtomicU64::new(LATCH_UNSET);

/// Ring-full drop hook: check exporter liveness and emit ONE latched ALERT.
///
/// Called by the worker LOG-phase handler only when a ring push returned
/// `false` (ring full — the counted symptom path; never on the healthy hot
/// path). `log` must be a valid nginx log.
///
/// The error-ring drop path deliberately does NOT call this: the error-ring
/// producer runs inside the error-log writer chain, so an ALERT from there
/// would re-enter the writer currently executing. The span/access-tail drop
/// paths fire under the same conditions (a dead exporter stops draining ALL
/// rings), so hooking only them avoids the reentrancy hazard entirely.
pub(crate) fn check_exporter_liveness_on_drop(
    amcf: &crate::config::MainConfig,
    log: *mut nginx_sys::ngx_log_t,
) {
    if log.is_null() {
        return;
    }
    let Some(ctrl) = amcf.control_shm_ptr() else {
        return;
    };
    // SAFETY: `control_shm_ptr()` returned `Some`, so `ctrl` points to the
    // live `ControlShm` in the mapped control zone (valid for the worker's
    // lifetime); fields read below are atomics, so cross-process access is
    // well-defined.
    let ctrl = unsafe { &*ctrl };

    // VERDICT: compare the exporter's last beat against our own monotonic
    // clock.  Acquire pairs with the exporter's Release store in
    // `heartbeat_timer_handler`.
    let last_beat = ctrl.last_beat_msec.load(Ordering::Acquire);
    // SAFETY: `ngx_current_msec` is an nginx global updated by this worker's
    // own (single-threaded) event loop; reading it here is the standard nginx
    // cached-time access pattern.
    let now = unsafe { nginx_sys::ngx_current_msec } as u64;
    let stale = heartbeat_is_stale(now, last_beat);

    if !stale {
        return; // saturated-but-alive: drops are normal, no alert.
    }

    let current_gen = ctrl.successor_gen.load(Ordering::Relaxed);
    if !latch_should_alert(ALERT_LATCHED_GEN.load(Ordering::Relaxed), current_gen, stale) {
        return; // already alerted for this exporter generation.
    }
    // Latch BEFORE logging: if the ALERT itself re-enters a drop path (e.g.
    // via the error-log capture chain), the latch is already set.
    ALERT_LATCHED_GEN.store(current_gen, Ordering::Relaxed);

    alert!(
        log,
        "otel exporter heartbeat stale (no beat for >{}ms); telemetry suspended; \
         nginx -s reload restores",
        HEARTBEAT_STALE_THRESHOLD_MS,
    );
}

/* ──────────────────────── unit tests ──────────────────────── */

#[cfg(test)]
mod tests {
    use super::*;

    // ── staleness predicate ──────────────────────────────────────────────

    /// Beat = 0 means the exporter never beat → startup grace, never stale
    /// (even with an arbitrarily large `now`).
    #[test]
    fn never_beaten_is_not_stale() {
        assert!(!heartbeat_is_stale(0, 0));
        assert!(!heartbeat_is_stale(HEARTBEAT_STALE_THRESHOLD_MS * 100, 0));
    }

    /// A beat within the threshold is not stale (saturated-but-alive case).
    #[test]
    fn fresh_beat_is_not_stale() {
        let beat = 1_000_000;
        assert!(!heartbeat_is_stale(beat, beat), "same instant");
        assert!(!heartbeat_is_stale(beat + HEARTBEAT_PERIOD_MS, beat), "one period old");
        assert!(
            !heartbeat_is_stale(beat + HEARTBEAT_STALE_THRESHOLD_MS, beat),
            "exactly at threshold is NOT stale (strict >)"
        );
    }

    /// A beat older than the threshold is stale (silent-exporter case).
    #[test]
    fn old_beat_is_stale() {
        let beat = 1_000_000;
        assert!(heartbeat_is_stale(beat + HEARTBEAT_STALE_THRESHOLD_MS + 1, beat));
        assert!(heartbeat_is_stale(beat + 60_000, beat), "a minute-old beat is stale");
    }

    /// Exporter's cached clock marginally AHEAD of the worker's must not
    /// underflow into a giant elapsed value (false alert).
    #[test]
    fn beat_ahead_of_now_is_not_stale() {
        let now = 1_000_000;
        assert!(!heartbeat_is_stale(now, now + 250));
        assert!(!heartbeat_is_stale(now, u64::MAX));
    }

    /// Threshold invariants: whole seconds, ≥ 5 s, derived from the beat
    /// period (and therefore ≫ it).  (The `const _` asserts at module scope
    /// enforce these at compile time; this test documents and pins the
    /// relationship through runtime evaluation as well.)
    #[test]
    fn threshold_is_derived_from_beat_period() {
        let threshold = HEARTBEAT_STALE_THRESHOLD_MS;
        let period = HEARTBEAT_PERIOD_MS;
        assert_eq!(threshold, 5 * period);
        assert!(threshold >= 5_000);
        assert_eq!(threshold % 1_000, 0, "whole seconds");
        assert!(threshold > period, "threshold must be much greater than the beat period");
    }

    // ── latch logic ──────────────────────────────────────────────────────

    /// Not stale → never alert, latched or not.
    #[test]
    fn latch_no_alert_when_not_stale() {
        assert!(!latch_should_alert(LATCH_UNSET, 0, false));
        assert!(!latch_should_alert(0, 0, false));
        assert!(!latch_should_alert(0, 1, false));
    }

    /// First stale observation on an unlatched worker → alert.
    #[test]
    fn latch_first_stale_alerts() {
        assert!(latch_should_alert(LATCH_UNSET, 0, true), "gen 0, never latched");
        assert!(latch_should_alert(LATCH_UNSET, 3, true), "gen 3, never latched");
    }

    /// Same generation, already latched → suppressed (ONE alert per worker
    /// per generation).
    #[test]
    fn latch_suppresses_repeat_alerts_same_generation() {
        assert!(!latch_should_alert(0, 0, true));
        assert!(!latch_should_alert(7, 7, true));
    }

    /// SIGHUP reload bumps `successor_gen` → latch re-arms for the new
    /// exporter generation.
    #[test]
    fn latch_rearms_on_new_generation() {
        // Latched for gen 0; reload makes current gen 1 → alert again allowed.
        assert!(latch_should_alert(0, 1, true));
        // ...and once latched for gen 1, suppressed again.
        assert!(!latch_should_alert(1, 1, true));
    }

    /// End-to-end latch walk: stale at gen 0 → alert once; still stale → no
    /// repeat; reload to gen 1, stale again → exactly one more alert.
    #[test]
    fn latch_walkthrough() {
        let mut latched = LATCH_UNSET;
        let mut alerts = 0;

        for _ in 0..5 {
            // five drop events while stale at gen 0
            if latch_should_alert(latched, 0, true) {
                latched = 0;
                alerts += 1;
            }
        }
        assert_eq!(alerts, 1, "exactly one alert for gen 0");

        for _ in 0..5 {
            // reload happened: gen 1, exporter dead again
            if latch_should_alert(latched, 1, true) {
                latched = 1;
                alerts += 1;
            }
        }
        assert_eq!(alerts, 2, "exactly one more alert for gen 1");
    }
}
