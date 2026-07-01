// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Control-plane shared-memory zone — scaffold for a future collector-side
//! bidi control channel. Today it carries the crash-loop counter, successor-
//! generation abdication sentinel, and liveness heartbeat; the `flags` word is
//! a placeholder for dynamic reconfiguration, not yet wired up.
//!
//! Layout (relative to `ngx_shm_zone_t.shm.addr`):
//!
//! ```text
//! [ slab-pool header (data_offset() bytes) | ControlShm (64 bytes) | padding ]
//! ```
//!
//! The slab-pool header is written by `ngx_init_zone_pool` before our init
//! callback runs; the first `data_offset()` bytes must not be touched (same
//! constraint as [`crate::shm`]).

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use nginx_sys::{ngx_int_t, ngx_shm_zone_t};
use ngx::core::Status;

/// Control-plane shared-memory zone. Scaffold for a future bidi control
/// channel delivering dynamic reconfiguration from the collector side.
///
/// Mapped at `data_offset()` bytes into the zone, after the slab-pool header
/// `ngx_init_zone_pool` writes (same pattern as [`crate::shm::WorkerSlots`]).
///
/// ## Layout
/// ```text
/// offset  field               width   notes
///   0     version             8 B     monotonic heartbeat / reconfig sentinel
///   8     flags               8 B     reserved (fast-path reconfiguration)
///  16     crash_count         8 B     exporter restarts within crash window
///  24     window_start_unix   8 B     UNIX seconds: start of the current crash window
///  32     successor_gen       8 B     reload successor generation counter
///  40     last_beat_msec      8 B     liveness beat (exporter ngx_current_msec)
///  48     _reserved[0..2]    16 B     reserved payload budget
/// ```
/// Total: 8 × AtomicU64 = 64 bytes. `#[repr(C)]` layout is pinned by the
/// `control_shm_struct_size` unit test.
#[repr(C)]
pub struct ControlShm {
    /// Monotonic version counter. Exporter increments once per drain cycle as
    /// a liveness heartbeat and as a future reconfig-convergence sentinel.
    pub version: AtomicU64,
    /// Reserved flag word for a future dynamic-reconfig fast-path check.
    /// Workers load it on the hot path but currently discard the value.
    pub flags: AtomicU64,
    /// Crash-loop backoff counter: exporter starts within the current
    /// `window_start_unix` + `CRASH_WINDOW_SECS` window.
    ///
    /// Written by the exporter at startup (before any risky init); compared
    /// against `MAX_CRASH_RESTARTS`. Zeroed on fresh start and on SIGHUP
    /// reload so a legitimate operator reload clears prior crash history.
    pub crash_count: AtomicU64,
    /// Unix timestamp (seconds) marking the start of the current crash
    /// window. `now − window_start_unix > CRASH_WINDOW_SECS` resets the
    /// counter. Zero means no window established yet (treat as expired).
    pub window_start_unix: AtomicU64,
    /// Reload successor generation counter — drives the old exporter's
    /// ring-drain abdication decision on reload.
    ///
    /// **Written only by the master**, `fetch_add(1, Release)` on each SIGHUP
    /// reload, before `ngx_spawn_process` forks the new exporter; the
    /// `NGX_CMD_QUIT` channel message to the old exporter is the
    /// happens-before edge (by the time its channel handler sets `ngx_quit`,
    /// the master's `Release` store is visible).
    ///
    /// **Read by the old exporter** at `ngx_quit`: if `current > my_gen`
    /// (its startup snapshot) a successor exists and it abdicates the mutating
    /// ring drains (log/span `pop_into`, coalesce-table reset) to the new
    /// exporter; if `current == my_gen` (pure shutdown) it performs a full
    /// drain as sole consumer.
    ///
    /// **Read by the new exporter** at startup to set its own `my_gen`.
    ///
    /// Reload reuses the same physical shm pages, so old/new exporters agree
    /// on the value; on USR2 binary upgrade the new master maps fresh pages
    /// and each exporter is sole consumer of its own zone.
    pub successor_gen: AtomicU64,
    /// Exporter liveness heartbeat timestamp.
    ///
    /// **Written by the exporter** from a self-rearming `ngx_event_t` timer
    /// (`heartbeat_timer_handler`) every [`crate::liveness::HEARTBEAT_PERIOD_MS`]
    /// ms, storing `ngx_current_msec` (monotonic, `CLOCK_MONOTONIC`-based —
    /// not wall-clock). Independent of drain/send progress: a blackholed send
    /// only parks its future; the event loop keeps expiring timers.
    ///
    /// **Read by workers** only on the ring-full drop path (never
    /// per-request), comparing against their own `ngx_current_msec` on the
    /// same clock basis. See [`crate::liveness::heartbeat_is_stale`].
    ///
    /// `0` means the exporter has never beaten (fresh zone); treated as
    /// not-stale (startup grace before the first beat).
    pub last_beat_msec: AtomicU64,
    /// Reserved payload budget for forward-compatible additions: 2 × AtomicU64.
    pub _reserved: [AtomicU64; 2],
}

impl ControlShm {
    /// Zone size: one OS page. Generous overhead for forward-compatible growth.
    pub const ZONE_SIZE: usize = 4096;

    /// Byte extent past `data_offset()` written by the SIGHUP-reload branch of
    /// [`control_shm_zone_init`] (`crash_count` + `window_start_unix`). The
    /// reload guard checks this full extent, not just `size > offset`, so a
    /// smaller-than-expected zone cannot produce an OOB store.
    pub const RELOAD_WRITE_EXTENT: usize = 32;

    /// Announce a reload successor: bump `successor_gen` (Release) so the old
    /// exporter abdicates ring draining once the new one starts. Called by the
    /// master in `ngx_otel_init_module` before `ngx_spawn_process` — the fork
    /// is the happens-before edge for the child's snapshot.
    pub fn announce_successor(&self) {
        self.successor_gen.fetch_add(1, Ordering::Release);
    }

    /// Roll back a successor announcement after a FAILED reload-spawn.
    ///
    /// If `ngx_spawn_process` fails (`NGX_INVALID_PID`), no successor exists,
    /// so the old exporter must stay sole consumer. Leaving `successor_gen`
    /// bumped would make it observe `current > my_gen` and abdicate ring pops
    /// permanently (telemetry loss). This restores the pre-reload value —
    /// [`announce_successor`] + this call is an exact round-trip.
    ///
    /// [`announce_successor`]: Self::announce_successor
    pub fn rollback_successor(&self) {
        self.successor_gen.fetch_sub(1, Ordering::Release);
    }
}

/// Zone initialisation callback, called by nginx on each (re)start. Mirrors
/// [`crate::shm::otel_shm_zone_init`] for the control zone.
///
/// - Fresh start: zero the `ControlShm` area (`version`/`flags` start at 0).
/// - SIGHUP reload (`old_data != null`): carry over existing values so
///   `version` keeps incrementing monotonically with no heartbeat gap.
///
/// # IMPORTANT — do NOT touch the slab-pool header
///
/// nginx calls `ngx_init_zone_pool` immediately before this callback,
/// writing an `ngx_slab_pool_t` header at `shm.addr[0..]` that the master's
/// SIGCHLD handler later dereferences (`ngx_unlock_mutexes`). Our data begins
/// at `data_offset()` bytes past `shm.addr`, safely beyond the header.
///
/// # Safety
/// nginx guarantees the callback args are valid non-null pointers.
pub unsafe extern "C" fn control_shm_zone_init(
    shm_zone: *mut ngx_shm_zone_t,
    old_data: *mut core::ffi::c_void,
) -> ngx_int_t {
    if !old_data.is_null() {
        // SIGHUP reload: same physical pages re-mapped; `version`/`flags`
        // carry over unchanged. Reset `crash_count`/`window_start_unix` so a
        // legitimate operator reload doesn't inherit a stale crash-loop
        // disable from the previous cycle.
        // SAFETY: `shm_zone` is a valid non-null `ngx_shm_zone_t` (fn contract);
        // the same zone is re-mapped on reload, so `shm.addr` is the live mapping.
        let zone = unsafe { &*shm_zone };
        let offset = crate::shm::data_offset();
        // Guard the FULL write extent (not merely `size > offset`): a
        // smaller-than-expected zone must not pass and produce an OOB store.
        if zone.shm.size >= offset + ControlShm::RELOAD_WRITE_EXTENT {
            // SAFETY: `offset == data_offset()` past the slab-pool header;
            // `zone.shm.size >= offset + RELOAD_WRITE_EXTENT` was checked above,
            // so the two stores stay in-bounds. The cast is valid because the
            // zone has at least `data_offset() + sizeof(ControlShm)` bytes
            // (enforced by the `zone_size_fits_struct` unit test).
            let ctrl = unsafe { &*zone.shm.addr.cast::<u8>().add(offset).cast::<ControlShm>() };
            ctrl.crash_count.store(0, Ordering::Relaxed);
            ctrl.window_start_unix.store(0, Ordering::Relaxed);
        }
        return Status::NGX_OK.into();
    }

    // Fresh start: zero the ControlShm area only — never the slab-pool header.
    // Explicit zeroing (not just relying on OS zero-filled mmap) because the
    // same zone can be reused (e.g. binary upgrade) with `old_data` null yet
    // pages recycled.
    // SAFETY: nginx invokes this callback with a valid, non-null
    // `ngx_shm_zone_t` (fn contract); the reference does not outlive the call.
    let zone = unsafe { &*shm_zone };
    let offset = crate::shm::data_offset();
    if zone.shm.size > offset {
        // SAFETY: `offset == data_offset()` and we checked `zone.shm.size >
        // offset`, so `addr + offset` is within the mapped zone (past the
        // slab-pool header).
        let base: *mut u8 = unsafe { zone.shm.addr.cast::<u8>().add(offset) };
        let size = zone.shm.size - offset;
        // SAFETY: `base` is within the zone and `size = zone.shm.size - offset`
        // bytes remain after it, so the zero-fill stays in-bounds and never
        // touches the slab-pool header in [0, offset) (zeroing it would crash
        // the master — see the doc above).
        unsafe { ptr::write_bytes(base, 0, size) };
    }

    Status::NGX_OK.into()
}

/* ──────────────────────── unit tests ──────────────────────── */

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;
    use core::sync::atomic::Ordering;

    /// Allocate a `ControlShm` on the heap (simulating a fresh shm
    /// mapping), verify all fields start at 0, increment `version`,
    /// and assert the read-back value is correct.
    #[test]
    fn control_shm_init_and_increment() {
        let buf = std::vec![0u8; mem::size_of::<ControlShm>()];
        // SAFETY: `buf` is a freshly-allocated, zero-initialised `Vec<u8>` sized
        // to exactly hold a `ControlShm`; the global allocator over-aligns it,
        // and zero is the valid initial state for its `AtomicU64` fields. The
        // shared reference lives only for the test.
        let ctrl = unsafe { &*buf.as_ptr().cast::<ControlShm>() };

        // Fresh-allocated buffer zeroed by vec! — simulating zone init.
        assert_eq!(ctrl.version.load(Ordering::Relaxed), 0, "version must start at 0");
        assert_eq!(ctrl.flags.load(Ordering::Relaxed), 0, "flags must start at 0");
        assert_eq!(ctrl.crash_count.load(Ordering::Relaxed), 0, "crash_count must start at 0");
        assert_eq!(
            ctrl.window_start_unix.load(Ordering::Relaxed),
            0,
            "window_start_unix must start at 0"
        );
        assert_eq!(ctrl.successor_gen.load(Ordering::Relaxed), 0, "successor_gen must start at 0");
        assert_eq!(
            ctrl.last_beat_msec.load(Ordering::Relaxed),
            0,
            "last_beat_msec must start at 0 (= exporter never beaten)"
        );
        for (i, r) in ctrl._reserved.iter().enumerate() {
            assert_eq!(r.load(Ordering::Relaxed), 0, "_reserved[{}] must start at 0", i);
        }

        // Increment version once (simulates one exporter drain cycle).
        ctrl.version.fetch_add(1, Ordering::Relaxed);
        assert_eq!(
            ctrl.version.load(Ordering::Relaxed),
            1,
            "version must be 1 after one increment"
        );

        assert_eq!(ctrl.flags.load(Ordering::Relaxed), 0, "flags must be unaffected");
        assert_eq!(ctrl.crash_count.load(Ordering::Relaxed), 0, "crash_count unaffected");
        assert_eq!(ctrl.last_beat_msec.load(Ordering::Relaxed), 0, "last_beat_msec unaffected");
        assert_eq!(
            ctrl.window_start_unix.load(Ordering::Relaxed),
            0,
            "window_start_unix unaffected"
        );
        assert_eq!(
            ctrl.successor_gen.load(Ordering::Relaxed),
            0,
            "successor_gen must be unaffected by version increment"
        );
    }

    /// `ZONE_SIZE` must accommodate the slab-pool header plus the
    /// `ControlShm` struct.
    #[test]
    fn zone_size_fits_struct() {
        let offset = crate::shm::data_offset();
        let struct_size = mem::size_of::<ControlShm>();
        let needed = offset + struct_size;
        assert!(
            ControlShm::ZONE_SIZE >= needed,
            "ZONE_SIZE={} must be ≥ data_offset({}) + sizeof(ControlShm)({}) = {}",
            ControlShm::ZONE_SIZE,
            offset,
            struct_size,
            needed
        );
    }

    /// Pins the `#[repr(C)]` size at 8 × AtomicU64 so a future field addition
    /// is flagged at compile time.
    #[test]
    fn control_shm_struct_size() {
        assert_eq!(
            mem::size_of::<ControlShm>(),
            8 * mem::size_of::<AtomicU64>(),
            "ControlShm must be exactly 8 × AtomicU64 bytes"
        );
    }

    /// Pins the `successor_gen` sentinel semantics that drive `graceful_drain`
    /// abdication decisions.
    #[test]
    fn b1_successor_gen_abdication_logic() {
        let buf = std::vec![0u8; mem::size_of::<ControlShm>()];
        // SAFETY: zero-initialised buffer of exactly the right size.
        let ctrl = unsafe { &*buf.as_ptr().cast::<ControlShm>() };

        // Fresh start: my_gen = 0, current = 0 → no successor → full drain.
        let my_gen: u64 = 0;
        let current = ctrl.successor_gen.load(Ordering::Relaxed);
        assert!(current <= my_gen, "no successor on fresh start");

        // Reload: master increments successor_gen before QUIT.
        ctrl.successor_gen.fetch_add(1, Ordering::Relaxed);
        let current = ctrl.successor_gen.load(Ordering::Relaxed);
        assert!(current > my_gen, "successor announced after reload increment");

        // New exporter snapshots my_gen = 1 at startup.
        let new_exporter_gen: u64 = ctrl.successor_gen.load(Ordering::Relaxed);
        // Second reload: master increments again.
        ctrl.successor_gen.fetch_add(1, Ordering::Relaxed);
        let current2 = ctrl.successor_gen.load(Ordering::Relaxed);
        assert!(current2 > new_exporter_gen, "successor announced on second reload");

        // Pure shutdown: successor_gen stays at 2, new exporter's my_gen = 2.
        // No further increment → equal → full drain.
        let shutdown_gen: u64 = ctrl.successor_gen.load(Ordering::Relaxed);
        let current3 = ctrl.successor_gen.load(Ordering::Relaxed);
        assert!(current3 <= shutdown_gen, "no successor on pure shutdown");
    }

    /// Regression: a FAILED reload-spawn (fork returns `NGX_INVALID_PID`) must
    /// NOT leave the old exporter abdicating ring drains forever — models the
    /// announce → failed-spawn → rollback round-trip from `ngx_otel_init_module`.
    #[test]
    fn failed_reload_spawn_rolls_back_successor_gen() {
        let buf = std::vec![0u8; mem::size_of::<ControlShm>()];
        // SAFETY: zero-initialised buffer of exactly the right size.
        let ctrl = unsafe { &*buf.as_ptr().cast::<ControlShm>() };

        // Old exporter snapshot at its startup.
        let old_my_gen: u64 = ctrl.successor_gen.load(Ordering::Acquire);

        // Master announces the successor before forking (matches
        // `ngx_otel_init_module`; same production helper).
        ctrl.announce_successor();
        assert!(
            ctrl.successor_gen.load(Ordering::Acquire) > old_my_gen,
            "during a reload-in-progress the announcement is visible"
        );

        // Fork fails → roll back (the spawn-error path in `ngx_otel_init_module`;
        // same production helper).
        ctrl.rollback_successor();

        // The old exporter's abdication decision is `current > my_gen`.  After
        // rollback the counter is back to its pre-reload value, so the old
        // exporter stays the sole consumer and keeps draining the rings.
        let current = ctrl.successor_gen.load(Ordering::Acquire);
        assert_eq!(
            current, old_my_gen,
            "rollback must restore successor_gen to its pre-reload value"
        );
        // The old exporter abdicates iff `current > my_gen`; after rollback it
        // must not (the `<=` is that decision, negated).
        assert!(
            current <= old_my_gen,
            "after a failed-spawn rollback the old exporter must NOT abdicate"
        );
    }

    /// Regression: the reload-branch bound (`RELOAD_WRITE_EXTENT`) must cover
    /// the FULL byte extent the branch writes.
    ///
    /// The reload branch of `control_shm_zone_init` stores `crash_count` and
    /// `window_start_unix`; its guard must require
    /// `size >= offset + RELOAD_WRITE_EXTENT`, not merely `size > offset`,
    /// otherwise a smaller-than-expected zone would pass the guard yet store
    /// out of bounds.  Pin the constant to the actual max-written field extent.
    #[test]
    fn reload_write_extent_covers_written_fields() {
        let crash_end = mem::offset_of!(ControlShm, crash_count) + mem::size_of::<AtomicU64>();
        let window_end =
            mem::offset_of!(ControlShm, window_start_unix) + mem::size_of::<AtomicU64>();
        let max_written = crash_end.max(window_end);
        assert_eq!(
            ControlShm::RELOAD_WRITE_EXTENT,
            max_written,
            "RELOAD_WRITE_EXTENT must equal the highest byte the reload branch writes"
        );
        // And the guard must be `>=` (full extent), so the smallest zone that
        // passes is exactly `offset + RELOAD_WRITE_EXTENT` bytes from `addr`.
        assert!(
            ControlShm::RELOAD_WRITE_EXTENT
                >= mem::offset_of!(ControlShm, window_start_unix) + mem::size_of::<AtomicU64>(),
            "extent must include window_start_unix"
        );
    }

    // ── Crash-backoff decision logic (pure function tests) ────────────────────

    /// Helper: simulate the crash-counter startup logic as a pure function over
    /// `{crash_count, window_start, now_secs}`.
    ///
    /// Returns `(new_count, action)` where `action` is:
    /// - `"exit"` if `new_count > MAX_CRASH_RESTARTS`
    /// - `"backoff(Nms)"` if backoff applies
    /// - `"ok"` if no action needed (first start)
    #[derive(Debug, PartialEq)]
    enum StartupAction {
        Exit,
        Backoff(u64),
        Ok,
    }

    fn simulate_startup(
        crash_count: u64,
        window_start: u64,
        now: u64,
        window_secs: u64,
        max_restarts: u64,
        backoff_base_ms: u64,
        backoff_cap_ms: u64,
    ) -> (u64, StartupAction) {
        // Reset window if expired, then increment, then give-up or backoff.
        let (effective_count, effective_window) =
            if window_start == 0 || now.saturating_sub(window_start) > window_secs {
                (0u64, now)
            } else {
                (crash_count, window_start)
            };
        let _ = effective_window; // used for state update in real code

        let new_count = effective_count + 1;

        if new_count > max_restarts {
            return (new_count, StartupAction::Exit);
        }
        if new_count > 1 {
            let shift = (new_count - 1).min(31);
            let backoff = backoff_base_ms.saturating_mul(1u64 << shift).min(backoff_cap_ms);
            return (new_count, StartupAction::Backoff(backoff));
        }
        (new_count, StartupAction::Ok)
    }

    /// First start with no window established → count=1, no backoff, no exit.
    #[test]
    fn crash_logic_first_start() {
        let (count, action) = simulate_startup(0, 0, 1_000, 60, 5, 100, 5_000);
        assert_eq!(count, 1);
        assert_eq!(action, StartupAction::Ok);
    }

    /// Second start within window (first crash restart) → count=2, backoff=200ms.
    /// Formula: `BASE * 2^(count-1)` = `100 * 2^1` = 200ms.
    #[test]
    fn crash_logic_second_restart_within_window() {
        let (count, action) = simulate_startup(1, 900, 950, 60, 5, 100, 5_000);
        assert_eq!(count, 2);
        assert_eq!(action, StartupAction::Backoff(200));
    }

    /// Third restart → backoff doubles to 400ms.
    /// Formula: `BASE * 2^(count-1)` = `100 * 2^2` = 400ms.
    #[test]
    fn crash_logic_third_restart_backoff_doubles() {
        let (count, action) = simulate_startup(2, 900, 950, 60, 5, 100, 5_000);
        assert_eq!(count, 3);
        assert_eq!(action, StartupAction::Backoff(400));
    }

    /// Sixth restart within window → count>MAX_RESTARTS (5) → exit.
    #[test]
    fn crash_logic_exceeds_max_restarts() {
        let (count, action) = simulate_startup(5, 900, 950, 60, 5, 100, 5_000);
        assert_eq!(count, 6);
        assert_eq!(action, StartupAction::Exit);
    }

    /// Window expired (now - window_start = 120 > 60s) → counter resets → count=1, no backoff.
    #[test]
    fn crash_logic_window_expired_resets_counter() {
        let (count, action) = simulate_startup(4, 800, 920, 60, 5, 100, 5_000);
        assert_eq!(count, 1, "counter must reset after window expires");
        assert_eq!(action, StartupAction::Ok);
    }

    /// Backoff is capped at `backoff_cap_ms`.
    #[test]
    fn crash_logic_backoff_capped() {
        // count=5 (5th restart): backoff = 100 * 2^4 = 1600ms — under cap.
        let (_, action5) = simulate_startup(4, 900, 950, 60, 10, 100, 5_000);
        assert_eq!(action5, StartupAction::Backoff(1600));

        // count=8 (8th restart): 100 * 2^7 = 12800ms → capped at 5000ms.
        let (_, action8) = simulate_startup(7, 900, 950, 60, 10, 100, 5_000);
        assert_eq!(action8, StartupAction::Backoff(5_000));
    }

    /// Cross-check: `simulate_startup`'s inline backoff formula must agree with
    /// the REAL `crash_backoff_ms()` in `exporter/mod.rs` across every count
    /// from 1 to MAX_CRASH_RESTARTS + 2.
    ///
    /// This prevents the "duplicate-logic masking" pattern: if `crash_backoff_ms`
    /// is silently changed (or its constants drift), this test catches it.
    #[test]
    fn simulate_startup_backoff_matches_real_crash_backoff_ms() {
        use crate::exporter::{
            crash_backoff_ms, CRASH_BACKOFF_BASE_MS, CRASH_BACKOFF_CAP_MS, CRASH_WINDOW_SECS,
            MAX_CRASH_RESTARTS,
        };

        // Test every count from 2 (first restart) through MAX_CRASH_RESTARTS + 2.
        // count=1 is first start (no backoff for either); skip count=0 (window reset).
        for prior_count in 1..=(MAX_CRASH_RESTARTS + 2) {
            // simulate_startup with an unexpired window so it doesn't reset.
            let (new_count, action) = simulate_startup(
                prior_count,
                900,
                950,
                CRASH_WINDOW_SECS,
                MAX_CRASH_RESTARTS + 99, // set max_restarts artificially high so Exit is not triggered
                CRASH_BACKOFF_BASE_MS,
                CRASH_BACKOFF_CAP_MS,
            );
            // new_count = prior_count + 1 (no reset because window is unexpired).
            let expected_backoff = crash_backoff_ms(new_count);
            match action {
                StartupAction::Backoff(ms) => {
                    assert_eq!(
                        ms, expected_backoff,
                        "simulate_startup backoff for count={} differs from crash_backoff_ms: \
                         simulate={ms}ms real={expected_backoff}ms",
                        new_count,
                    );
                }
                StartupAction::Ok => {
                    // count=1 → Ok is only valid if new_count == 1 (first start,
                    // no backoff). crash_backoff_ms(1) == 0.
                    assert_eq!(
                        new_count, 1,
                        "simulate_startup returned Ok for count={} (expected only at count=1)",
                        new_count,
                    );
                    assert_eq!(
                        expected_backoff, 0,
                        "crash_backoff_ms must return 0 at count=1 to match simulate_startup Ok",
                    );
                }
                StartupAction::Exit => {
                    // Should not happen — we set max_restarts artificially high.
                    panic!(
                        "simulate_startup returned Exit for count={} with artificially high max_restarts",
                        new_count
                    );
                }
            }
        }
    }
}
