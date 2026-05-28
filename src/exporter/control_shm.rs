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
use core::sync::atomic::AtomicU64;

use nginx_sys::{ngx_int_t, ngx_shm_zone_t};
use ngx::core::Status;

/// Control-plane shared-memory zone. Phase 1.3.3 establishes the
/// plumbing; Phase 5 wires the bidi control channel to it for dynamic
/// reconfiguration delivered from the collector side.
///
/// Mapped at `data_offset()` bytes into the zone (after the slab-pool
/// header that `ngx_init_zone_pool` writes — same pattern as
/// [`crate::shm::WorkerSlots`]).
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
    /// Reserved padding for forward-compatible additions.
    /// Phase 5 payload budget: 6 × AtomicU64 = 48 bytes.
    pub _reserved: [AtomicU64; 6],
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
        // SIGHUP reload: same physical pages re-mapped. Carry over values
        // so `version` remains monotonically increasing across reloads.
        return Status::NGX_OK.into();
    }

    // Fresh start: zero the ControlShm area only — never the slab-pool
    // header.  The OS already zero-fills new mmap regions, but we zero
    // explicitly for clarity and to handle edge cases (zone reuse paths).
    let zone = unsafe { &*shm_zone };
    let offset = crate::shm::data_offset();
    if zone.shm.size > offset {
        let base: *mut u8 = unsafe { zone.shm.addr.cast::<u8>().add(offset) };
        let size = zone.shm.size - offset;
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
        let ctrl = unsafe { &*buf.as_ptr().cast::<ControlShm>() };

        // Fresh-allocated buffer zeroed by vec! — simulating zone init.
        assert_eq!(
            ctrl.version.load(Ordering::Relaxed),
            0,
            "version must start at 0"
        );
        assert_eq!(
            ctrl.flags.load(Ordering::Relaxed),
            0,
            "flags must start at 0"
        );
        for (i, r) in ctrl._reserved.iter().enumerate() {
            assert_eq!(
                r.load(Ordering::Relaxed),
                0,
                "_reserved[{}] must start at 0",
                i
            );
        }

        // Increment version once (simulates one exporter drain cycle).
        ctrl.version.fetch_add(1, Ordering::Relaxed);
        assert_eq!(
            ctrl.version.load(Ordering::Relaxed),
            1,
            "version must be 1 after one increment"
        );

        // flags and _reserved must be unaffected by the version increment.
        assert_eq!(
            ctrl.flags.load(Ordering::Relaxed),
            0,
            "flags must be unaffected by version increment"
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
        // 8 × AtomicU64 (version + flags + 6 × _reserved) = 64 bytes.
        assert_eq!(
            mem::size_of::<ControlShm>(),
            8 * mem::size_of::<AtomicU64>(),
            "ControlShm must be exactly 8 × AtomicU64 bytes"
        );
    }
}
