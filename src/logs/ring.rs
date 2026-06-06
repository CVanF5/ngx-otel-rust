// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Per-worker SPSC (single-producer, single-consumer) byte ring buffer.
//!
//! # Design
//!
//! One ring per worker per signal type (access, error) lives in the logs shm
//! zone.  Each ring is split into a fixed-size header and a variable-length
//! payload region that immediately follows in memory:
//!
//! ```text
//! [ LogsWorkerRingHeader (32 bytes) ][ payload (cap bytes) ]
//! ```
//!
//! `LogsWorkerRingHeader` carries the three atomic counters plus the runtime
//! `cap` field.  The `cap` is set once at zone-init time (from the configured
//! `otel_log_ring_size`), then read by both push and pop on every call.
//!
//! [`LogsWorkerRing`] is a lightweight view (a pointer to the header) obtained
//! from a raw shm pointer; it is NOT a container and does not own memory.
//!
//! # Default capacity
//!
//! `DEFAULT_LOG_RING_CAP` is 512 KiB per ring.  Memory = `cap × 2 × N` where
//! `N` = worker count (one access ring + one error ring per worker).  Operators
//! who need more capacity can raise it via `otel_log_ring_size`.
//!
//! # Wire format per record
//! `[u32 record_len big-endian][payload bytes...]`
//!
//! # Invariants
//! - NO allocation on the producer path.
//! - NO locks on the producer path — atomic-only.
//! - `push` never blocks; increments `dropped` on full.
//! - Read/write offsets are **monotonically increasing `u64`** stored in the
//!   header in shm, so a fresh exporter resumes across SIGHUP (gotcha #6).

use core::sync::atomic::{AtomicU64, Ordering};

/// Default ring capacity in bytes per worker per signal type.
///
/// 512 KiB.  Memory = `cap × 2 × N` workers.
/// Raise with `otel_log_ring_size` if rings fill under your load.
pub const DEFAULT_LOG_RING_CAP: usize = 512 * 1024;

/// Kept for backward compat with tests/code that still reference the old name.
#[allow(dead_code)]
pub const LOG_RING_CAP: usize = DEFAULT_LOG_RING_CAP;

/// Fixed-size header for a per-worker log ring.
///
/// Immediately followed in shm by `cap` bytes of payload.
/// `#[repr(C)]` ensures deterministic layout across worker processes and the
/// exporter process.
#[repr(C)]
pub struct LogsWorkerRingHeader {
    /// Monotonically increasing byte count written by the producer.
    pub write_offset: AtomicU64,
    /// Monotonically increasing byte count consumed by the exporter.
    pub read_offset: AtomicU64,
    /// Number of records dropped because the ring was full.
    pub dropped: AtomicU64,
    /// Ring payload capacity in bytes (set once at zone-init from
    /// `otel_log_ring_size`, before any worker forks).
    ///
    /// `AtomicU64` rather than a plain `u64`: the header lives in cross-process
    /// shm and `cap` is read on every push/pop.  The write happens-before the
    /// fork so there is no live race, but the atomic closes the memory-model
    /// hole (a shared field read on the hot path) at zero runtime cost.
    pub cap: AtomicU64,
}

/// Size of the header alone (without payload).
pub const RING_HEADER_SIZE: usize = core::mem::size_of::<LogsWorkerRingHeader>();

/// Total bytes required for one ring with the given capacity.
#[inline]
pub fn ring_size_bytes(cap: usize) -> usize {
    RING_HEADER_SIZE + cap
}

/// A lightweight view over a per-worker log ring in shm.
///
/// Does NOT own the memory — it is a pointer to a [`LogsWorkerRingHeader`]
/// that lives in the logs shm zone.  The payload immediately follows the
/// header.
///
/// `Copy + Clone` because it is just a pointer — copying it produces a second
/// view into the same ring, which is intentional (worker writes via one view,
/// exporter reads via another view of the same shm region).
///
/// # Safety invariant
/// Only one writer and one reader may operate concurrently (SPSC).
#[derive(Clone, Copy)]
pub struct LogsWorkerRing {
    header: *mut LogsWorkerRingHeader,
}

// SAFETY: `LogsWorkerRing` is just a pointer into shared memory accessible from
// multiple processes (workers + exporter). All header fields it touches are
// atomics, and the caller upholds the SPSC single-writer/single-reader
// invariant, so it is sound to move across threads/processes.
unsafe impl Send for LogsWorkerRing {}
// SAFETY: as for the `Send` impl above — shared access goes through atomic
// header fields under the SPSC invariant, so concurrent `&LogsWorkerRing` use
// is sound.
unsafe impl Sync for LogsWorkerRing {}

impl LogsWorkerRing {
    /// Obtain a view over the ring at `ptr`.
    ///
    /// # Safety
    /// `ptr` must point to a valid `LogsWorkerRingHeader` followed by
    /// at least `header.cap` bytes of payload (all in shm).
    #[inline]
    pub unsafe fn from_shm_ptr(ptr: *mut u8) -> Self {
        Self { header: ptr.cast() }
    }

    #[inline]
    fn cap(&self) -> usize {
        // SAFETY: `self.header` points to a valid `LogsWorkerRingHeader` in the
        // logs shm zone for this view's lifetime (the `from_shm_ptr` contract);
        // `cap` is an `AtomicU64`, so the load is well-defined under concurrent
        // cross-process access.
        unsafe { (*self.header).cap.load(Ordering::Relaxed) as usize }
    }

    #[inline]
    fn payload_ptr(&self) -> *mut u8 {
        // Payload immediately follows the header.
        // SAFETY: `self.header` is a valid header pointer; `.add(1)` yields the
        // address one past the header, i.e. the start of the `cap`-byte payload
        // region the `from_shm_ptr` contract guarantees follows it. The pointer
        // is only formed here, not dereferenced.
        unsafe { self.header.add(1).cast() }
    }

    /// Push one length-prefixed record into the ring.
    ///
    /// Returns `true` on success, `false` when the ring is full (dropped
    /// counter incremented).  No allocation, no locks, no syscalls.
    pub fn push(&self, record: &[u8]) -> bool {
        let cap = self.cap();
        if cap == 0 {
            return false;
        }
        let record_len = record.len();
        let total = 4 + record_len;

        // SAFETY: valid header pointer (from_shm_ptr contract), live for this
        // view. This is the single producer (SPSC), so the shared `&` reference
        // to the atomic header fields never aliases a concurrent `&mut`.
        let hdr = unsafe { &*self.header };
        let write_off = hdr.write_offset.load(Ordering::Relaxed);
        let read_off = hdr.read_offset.load(Ordering::Acquire);

        let used = write_off.wrapping_sub(read_off) as usize;
        if used + total > cap {
            hdr.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let base = self.payload_ptr();
        let len_bytes = (record_len as u32).to_be_bytes();
        write_wrap(base, cap, write_off as usize, &len_bytes);
        write_wrap(base, cap, write_off as usize + 4, record);

        hdr.write_offset.store(write_off + total as u64, Ordering::Release);
        true
    }

    /// Pop the next record from the ring into `out`.
    ///
    /// Returns `true` and appends the record bytes to `out` when a record is
    /// available.  Returns `false` (and leaves `out` unchanged) when empty.
    pub fn pop_into(&self, out: &mut std::vec::Vec<u8>) -> bool {
        let cap = self.cap();
        if cap == 0 {
            return false;
        }
        // SAFETY: valid header pointer (from_shm_ptr contract), live for this
        // view. This is the single consumer (SPSC), so the shared `&` reference
        // to the atomic header fields never aliases a concurrent `&mut`.
        let hdr = unsafe { &*self.header };
        let write_off = hdr.write_offset.load(Ordering::Acquire);
        let read_off = hdr.read_offset.load(Ordering::Relaxed);

        let available = write_off.wrapping_sub(read_off) as usize;
        if available < 4 {
            return false;
        }

        let base = self.payload_ptr();
        let mut len_buf = [0u8; 4];
        read_wrap(base, cap, read_off as usize, &mut len_buf);
        let record_len = u32::from_be_bytes(len_buf) as usize;

        if available < 4 + record_len {
            return false;
        }

        let old_len = out.len();
        out.resize(old_len + record_len, 0);
        read_wrap(base, cap, read_off as usize + 4, &mut out[old_len..]);

        hdr.read_offset.store(read_off + 4 + record_len as u64, Ordering::Release);
        true
    }

    /// Number of records dropped because the ring was full.
    #[inline]
    pub fn drop_count(&self) -> u64 {
        // SAFETY: valid header pointer (from_shm_ptr contract); `dropped` is an
        // `AtomicU64`, so the concurrent load is well-defined.
        unsafe { (*self.header).dropped.load(Ordering::Acquire) }
    }
}

// ── Ring I/O helpers (wrapping byte access) ──────────────────────────────────

#[inline]
fn write_wrap(base: *mut u8, cap: usize, offset: usize, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let start = offset % cap;
    let end_space = cap - start;
    // SAFETY: `base` is the start of the `cap`-byte payload region (callers pass
    // `payload_ptr()` with the matching `cap`). `start < cap`, and each copy
    // length is bounded by `end_space` or `data.len() - end_space`, so both
    // copies stay within `[base, base + cap)`; `data` is a valid readable slice.
    // The split implements ring wrap-around.
    unsafe {
        if data.len() <= end_space {
            core::ptr::copy_nonoverlapping(data.as_ptr(), base.add(start), data.len());
        } else {
            core::ptr::copy_nonoverlapping(data.as_ptr(), base.add(start), end_space);
            core::ptr::copy_nonoverlapping(
                data.as_ptr().add(end_space),
                base,
                data.len() - end_space,
            );
        }
    }
}

#[inline]
fn read_wrap(base: *const u8, cap: usize, offset: usize, dst: &mut [u8]) {
    if dst.is_empty() {
        return;
    }
    let start = offset % cap;
    let end_space = cap - start;
    // SAFETY: `base` is the start of the `cap`-byte payload region (callers pass
    // `payload_ptr()` with the matching `cap`). `start < cap`, and each copy
    // length is bounded by `end_space` or `dst.len() - end_space`, so both reads
    // stay within `[base, base + cap)`; `dst` is a valid writable slice. The
    // split implements ring wrap-around.
    unsafe {
        if dst.len() <= end_space {
            core::ptr::copy_nonoverlapping(base.add(start), dst.as_mut_ptr(), dst.len());
        } else {
            core::ptr::copy_nonoverlapping(base.add(start), dst.as_mut_ptr(), end_space);
            core::ptr::copy_nonoverlapping(
                base,
                dst.as_mut_ptr().add(end_space),
                dst.len() - end_space,
            );
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::boxed::Box;

    const TEST_CAP: usize = 1024;

    /// Allocate a ring with the given capacity on the heap.
    ///
    /// Simulates what the shm zone-init path does: allocates space for the
    /// header + payload, zero-inits, and sets `header.cap`.
    pub fn make_ring_with_cap(cap: usize) -> (Box<[u8]>, LogsWorkerRing) {
        let total = ring_size_bytes(cap);
        let mut buf = vec![0u8; total].into_boxed_slice();
        let ptr = buf.as_mut_ptr();
        // SAFETY: `ptr` is the start of a freshly-allocated, zero-initialised
        // `ring_size_bytes(cap)` buffer. The global allocator returns memory
        // aligned well above `LogsWorkerRingHeader`'s 8-byte requirement, so the
        // cast and atomic store are well-defined in this test helper (the
        // production path lives in 8-byte-aligned slab memory).
        unsafe {
            let hdr = ptr.cast::<LogsWorkerRingHeader>();
            (*hdr).cap.store(cap as u64, Ordering::Relaxed);
        }
        // SAFETY: `ptr` points to that header followed by `cap` payload bytes,
        // satisfying `from_shm_ptr`'s contract; `buf` outlives the returned ring.
        let ring = unsafe { LogsWorkerRing::from_shm_ptr(ptr) };
        (buf, ring)
    }

    /// Create a standard small test ring (1024-byte cap).
    pub fn make_ring_small() -> (Box<[u8]>, LogsWorkerRing) {
        make_ring_with_cap(TEST_CAP)
    }

    #[test]
    fn push_then_pop_roundtrips_record() {
        let (_buf, ring) = make_ring_small();
        let data = b"hello logs";

        assert!(ring.push(data), "push must succeed on an empty ring");

        let mut out = std::vec::Vec::new();
        assert!(ring.pop_into(&mut out), "pop must succeed after a push");
        assert_eq!(out.as_slice(), data.as_slice());

        let mut out2 = std::vec::Vec::new();
        assert!(!ring.pop_into(&mut out2), "ring must be empty after draining");
    }

    #[test]
    fn push_when_full_drops_and_increments_counter() {
        let (_buf, ring) = make_ring_small();
        let payload = [0xABu8; 80];
        for _ in 0..20 {
            ring.push(&payload);
        }
        assert!(ring.drop_count() > 0, "drop counter must be non-zero after overflow");
    }

    #[test]
    fn wrap_around_works() {
        let (_buf, ring) = make_ring_small();

        // Advance past ring boundary.
        let short = [0x55u8; 1];
        for _ in 0..204 {
            assert!(ring.push(&short));
        }
        let mut out = std::vec::Vec::new();
        let mut count = 0u32;
        while ring.pop_into(&mut out) {
            count += 1;
            out.clear();
        }
        assert_eq!(count, 204);

        // Push a spanning record.
        let spanning: [u8; 10] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22];
        assert!(ring.push(&spanning), "spanning push must succeed");

        let mut out = std::vec::Vec::new();
        assert!(ring.pop_into(&mut out), "spanning pop must succeed");
        assert_eq!(out.as_slice(), spanning.as_slice());
    }

    #[test]
    fn two_producers_same_thread_serialise_correctly() {
        let (_buf, ring) = make_ring_small();
        let r1 = b"record_one";
        let r2 = b"record_two";

        assert!(ring.push(r1));
        assert!(ring.push(r2));

        let mut out = std::vec::Vec::new();
        assert!(ring.pop_into(&mut out));
        assert_eq!(out.as_slice(), r1.as_slice());
        out.clear();
        assert!(ring.pop_into(&mut out));
        assert_eq!(out.as_slice(), r2.as_slice());
        out.clear();
        assert!(!ring.pop_into(&mut out));
    }

    #[test]
    fn non_default_cap_round_trips() {
        let cap = 4096;
        let (_buf, ring) = make_ring_with_cap(cap);
        let data = b"non-default cap test";
        assert!(ring.push(data));
        let mut out = std::vec::Vec::new();
        assert!(ring.pop_into(&mut out));
        assert_eq!(out.as_slice(), data.as_slice());
    }
}
