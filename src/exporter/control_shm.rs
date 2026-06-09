// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Control-plane shared-memory zone — Phase 1.3.3 scaffold.
//!
//! This zone is the plumbing for Phase 5's dynamic reconfiguration
//! delivered via the bidi control channel from the collector side.
//! Phase 1.3.3 establishes the zone registration, heartbeat counter,
//! and hot-path load placeholder; Phase 5 wires the control channel
//! into it for real dynamic-reconfig delivery.
//!
//! Layout (relative to `ngx_shm_zone_t.shm.addr`):
//!
//! ```text
//! [ slab-pool header (data_offset() bytes) | ControlShm (64 bytes) | padding ]
//! ```
//!
//! The slab-pool header is written by `ngx_init_zone_pool` before our
//! init callback runs. We must not touch the first `data_offset()` bytes
//! (same constraint as in [`crate::shm`]).

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use nginx_sys::{ngx_int_t, ngx_shm_zone_t};
use ngx::core::Status;

/// Control-plane shared-memory zone. Phase 1.3.3 establishes the
/// plumbing; Phase 5 wires the bidi control channel to it for dynamic
/// reconfiguration delivered from the collector side.
///
/// Mapped at `data_offset()` bytes into the zone (after the slab-pool
/// header that `ngx_init_zone_pool` writes — same pattern as
/// [`crate::shm::WorkerSlots`]).
///
/// ## Layout
/// ```text
/// offset  field               width   notes
///   0     version             8 B     monotonic heartbeat / reconfig sentinel
///   8     flags               8 B     reserved (Phase 5 fast-path reconfiguration)
///  16     crash_count         8 B     exporter restarts within crash window
///  24     window_start_unix   8 B     UNIX seconds: start of the current crash window
///  32     _reserved[0..4]    32 B     Phase 5 payload budget
/// ```
/// Total: 8 × AtomicU64 = 64 bytes. `#[repr(C)]` layout is pinned by the
/// `control_shm_struct_size` unit test.
#[repr(C)]
pub struct ControlShm {
    /// Monotonic version counter. Exporter increments once per drain
    /// cycle as a liveness heartbeat AND as Phase 5's reconfig-delivery
    /// sentinel (after applying a reconfig the exporter increments so
    /// the collector can observe convergence).
    pub version: AtomicU64,
    /// Reserved flag word; layout TBD in Phase 5. Workers load this on
    /// the hot path (Sub-item 2) but discard the value in Phase 1.3.3 —
    /// it is the placeholder for Phase 5's dynamic-reconfig fast-path
    /// checks.
    pub flags: AtomicU64,
    /// Crash-loop backoff counter: number of times the exporter has started
    /// within the current [`window_start_unix`] + `CRASH_WINDOW_SECS` window.
    ///
    /// Written by the exporter at startup (before any risky init); read and
    /// compared against `MAX_CRASH_RESTARTS`. Cross-process: master maps the
    /// zone before fork; exporter writes here after fork. Zeroed on fresh start
    /// and on SIGHUP reload (so a legitimate operator reload clears the state).
    pub crash_count: AtomicU64,
    /// Unix timestamp (seconds) of the start of the current crash window.
    /// When `now − window_start_unix > CRASH_WINDOW_SECS` the counter resets,
    /// clearing transient crash history for a long-lived healthy exporter.
    /// Zero means no window has been established yet (treat as "window expired").
    pub window_start_unix: AtomicU64,
    /// Reserved padding for forward-compatible additions.
    /// Phase 5 payload budget: 4 × AtomicU64 = 32 bytes.
    pub _reserved: [AtomicU64; 4],
}

impl ControlShm {
    /// Zone size: one OS page. Generous overhead; Phase 5 will not exceed.
    pub const ZONE_SIZE: usize = 4096;
}

/// Zone initialisation callback, called by nginx on each (re)start.
///
/// Mirrors [`crate::shm::otel_shm_zone_init`] for the control zone.
///
/// - On a fresh start: zero the `ControlShm` area so `version` and
///   `flags` start at 0, preserving the heartbeat integration test
///   assertion that `V_AFTER > V_INITIAL` starting from a known baseline.
/// - On a SIGHUP reload (`old_data != null`): carry over existing values.
///   The new exporter inherits the zone and continues incrementing
///   `version` monotonically — no gap in the heartbeat timeline.
///
/// # IMPORTANT — do NOT touch the slab-pool header
///
/// nginx calls `ngx_init_zone_pool` immediately before this callback,
/// writing an `ngx_slab_pool_t` header at `shm.addr[0..]`. When any
/// worker exits, the master's SIGCHLD handler calls `ngx_unlock_mutexes`
/// which dereferences `sp->mutex.lock`. Our data begins at `data_offset()`
/// bytes past `shm.addr`, safely beyond the header.
///
/// # Safety
/// nginx guarantees the callback args are valid non-null pointers.
pub unsafe extern "C" fn control_shm_zone_init(
    shm_zone: *mut ngx_shm_zone_t,
    old_data: *mut core::ffi::c_void,
) -> ngx_int_t {
    if !old_data.is_null() {
        // SIGHUP reload: same physical pages re-mapped. Carry over `version`
        // and `flags` so the heartbeat counter remains monotonically increasing.
        //
        // Reset `crash_count` and `window_start_unix` so a legitimate operator
        // reload does NOT inherit a crash-loop disable from the previous cycle.
        // Without this reset a reloaded exporter would see the old crash_count
        // and self-disable even though the crash loop ended when the old
        // exporter exited with code 2 (which disables automatic respawn).
        // SAFETY: `shm_zone` is a valid non-null `ngx_shm_zone_t` (fn contract);
        // the same zone is re-mapped on reload, so `shm.addr` is the live mapping.
        let zone = unsafe { &*shm_zone };
        let offset = crate::shm::data_offset();
        if zone.shm.size > offset {
            // SAFETY: `offset == data_offset()` past the slab-pool header;
            // `zone.shm.size > offset` was checked above. The cast is valid
            // because the zone has at least `data_offset() + sizeof(ControlShm)`
            // bytes (enforced by the `zone_size_fits_struct` unit test).
            let ctrl = unsafe { &*zone.shm.addr.cast::<u8>().add(offset).cast::<ControlShm>() };
            ctrl.crash_count.store(0, Ordering::Relaxed);
            ctrl.window_start_unix.store(0, Ordering::Relaxed);
        }
        return Status::NGX_OK.into();
    }

    // Fresh start: zero the ControlShm area only — never the slab-pool header.
    // Explicit zeroing (rather than relying on the OS zero-filling fresh mmap
    // pages) because the same zone can be reused — e.g. across a binary upgrade
    // where `old_data` is null yet the pages are recycled.
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

        // crash_count, flags, and _reserved must be unaffected by the version increment.
        assert_eq!(ctrl.flags.load(Ordering::Relaxed), 0, "flags must be unaffected");
        assert_eq!(ctrl.crash_count.load(Ordering::Relaxed), 0, "crash_count unaffected");
        assert_eq!(
            ctrl.window_start_unix.load(Ordering::Relaxed),
            0,
            "window_start_unix unaffected"
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

    /// The `ControlShm` struct is `#[repr(C)]` with 8 × AtomicU64 = 64
    /// bytes. This test pins that expectation so a future field addition
    /// is flagged at compile time.
    #[test]
    fn control_shm_struct_size() {
        // 8 × AtomicU64 (version + flags + crash_count + window_start_unix +
        // 4 × _reserved) = 64 bytes.
        assert_eq!(
            mem::size_of::<ControlShm>(),
            8 * mem::size_of::<AtomicU64>(),
            "ControlShm must be exactly 8 × AtomicU64 bytes"
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
        // Step 1: reset window if expired.
        let (effective_count, effective_window) =
            if window_start == 0 || now.saturating_sub(window_start) > window_secs {
                (0u64, now)
            } else {
                (crash_count, window_start)
            };
        let _ = effective_window; // used for state update in real code

        // Step 2: increment.
        let new_count = effective_count + 1;

        // Step 3: give-up or backoff.
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

    /// Window expired → counter resets → count=1, no backoff.
    #[test]
    fn crash_logic_window_expired_resets_counter() {
        // count=4 restarts but window expired (now - window_start = 120 > 60s).
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
}
