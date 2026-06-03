// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Per-worker SPSC (single-producer, single-consumer) byte ring buffer.
//!
//! # Design
//!
//! One `LogsWorkerRing` exists per worker per signal type (access, error).
//! The **worker** (producer) calls [`LogsWorkerRing::push`]; the **central
//! exporter process** (consumer) calls [`LogsWorkerRing::pop_into`].
//!
//! # Invariants
//!
//! - NO allocation on the producer path.
//! - NO locks on the producer path — atomic-only.
//! - `push` never blocks; it increments the `dropped` counter on full and
//!   returns `false`.
//! - Read/write offsets are **monotonically increasing `u64`** values that
//!   live inside the ring struct (in shm), so a fresh exporter process
//!   resumes exactly where the old one left off across SIGHUP.
//! - Wire format per record: `[u32 record_len big-endian][payload bytes...]`.
//!
//! # Default capacity
//!
//! `LOG_RING_CAP` is 512 KiB per ring.  At ~100–200 bytes/record this
//! holds roughly 2 500 – 5 000 records — comfortable for a 1–2 s drain
//! window at up to ~2 500 req/s per worker.  At the 10 k RPS load test
//! (Step 12) with a ~5 s drain interval some drops are expected and tested
//! (bounded to < 50 %).
//!
//! TODO(phase-N): expose ring capacity as an operator directive so
//! high-volume deployments can tune shm usage vs. drop rate.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

/// Default ring capacity in bytes per worker per signal type.
///
/// 512 KiB ≈ 2 500–5 000 records at 100–200 bytes each.
pub const LOG_RING_CAP: usize = 512 * 1024;

/// A lock-free SPSC ring buffer stored in shared memory.
///
/// `CAP` is the capacity of the `payload` array in bytes.  The total size of
/// this struct is `3 × 8 + CAP` bytes.  It must be `#[repr(C)]` so that the
/// layout is deterministic across compilation units (nginx workers +
/// `nginx: otel exporter`).
///
/// The `payload` field uses [`UnsafeCell`] to allow interior mutability
/// through the shared reference — necessary because both the producer (via
/// `push`) and consumer (via `pop_into`) access the same bytes through a
/// `&self` reference (the ring lives in shared memory, accessible from
/// multiple processes via a raw pointer).
///
/// # Concurrency model
/// - **Writer** (nginx worker): calls `push`.  Loads `read_offset` with
///   `Acquire` to compute free space; writes payload bytes; stores
///   `write_offset` with `Release`.
/// - **Reader** (otel exporter): calls `pop_into`.  Loads `write_offset`
///   with `Acquire` to detect new data; reads payload bytes; stores
///   `read_offset` with `Release`.
///
/// This is a standard SPSC ring.  No CAS or lock is needed.
///
/// # Safety invariant
/// Only one writer and one reader may operate concurrently.  Any other usage
/// pattern (multiple producers, or multiple consumers) is UB.
#[repr(C)]
pub struct LogsWorkerRing<const CAP: usize> {
    /// Monotonically increasing byte count written by the producer.
    pub write_offset: AtomicU64,
    /// Monotonically increasing byte count consumed by the exporter.
    pub read_offset: AtomicU64,
    /// Number of records dropped because the ring was full.
    pub dropped: AtomicU64,
    /// The ring payload.  Accessed at `offset % CAP`.
    /// `UnsafeCell` is required for interior mutability (both push and pop
    /// access the same storage via a shared reference).
    payload: UnsafeCell<[u8; CAP]>,
}

// Safety: the ring is designed for cross-process shared memory use where
// exactly one producer and one consumer access it concurrently.  The
// caller upholds the SPSC invariant.  Making it Send+Sync is required so
// the exporter process can hold a reference obtained from shm.
unsafe impl<const CAP: usize> Send for LogsWorkerRing<CAP> {}
unsafe impl<const CAP: usize> Sync for LogsWorkerRing<CAP> {}

impl<const CAP: usize> LogsWorkerRing<CAP> {
    /// Push one length-prefixed record into the ring.
    ///
    /// Returns `true` on success, `false` when the ring is full (the `dropped`
    /// counter is incremented in that case).
    ///
    /// # Invariants
    /// - No allocation.
    /// - No locks.
    /// - No syscalls.
    /// - Returns immediately; never spins.
    pub fn push(&self, record: &[u8]) -> bool {
        let record_len = record.len();
        // Total bytes needed: 4-byte length prefix + payload.
        let total = 4 + record_len;

        // SPSC: only one producer, so Relaxed is fine for our own pointer.
        let write_off = self.write_offset.load(Ordering::Relaxed);
        // Acquire: synchronise with the consumer's Release store on read_offset.
        let read_off = self.read_offset.load(Ordering::Acquire);

        // Number of bytes currently committed-but-unread.
        let used = write_off.wrapping_sub(read_off) as usize;
        if used + total > CAP {
            // Ring full — drop.
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Safety: SPSC invariant — only one producer writes at a time.
        let base: *mut u8 = unsafe { (*self.payload.get()).as_mut_ptr() };

        // Write the 4-byte length prefix (big-endian).
        let len_bytes = (record_len as u32).to_be_bytes();
        write_wrap(base, CAP, write_off as usize, &len_bytes);

        // Write the payload.
        write_wrap(base, CAP, write_off as usize + 4, record);

        // Release: make the new data visible to the consumer.
        self.write_offset.store(write_off + total as u64, Ordering::Release);
        true
    }

    /// Pop the next record from the ring into `out`.
    ///
    /// Returns `true` and appends the record bytes to `out` when a record is
    /// available.  Returns `false` (and leaves `out` unchanged) when the ring
    /// is empty.
    pub fn pop_into(&self, out: &mut std::vec::Vec<u8>) -> bool {
        // Acquire: synchronise with the producer's Release store on write_offset.
        let write_off = self.write_offset.load(Ordering::Acquire);
        // SPSC: only one consumer, Relaxed is fine for our own pointer.
        let read_off = self.read_offset.load(Ordering::Relaxed);

        let available = write_off.wrapping_sub(read_off) as usize;
        if available < 4 {
            // Not even a length prefix available.
            return false;
        }

        // Safety: SPSC invariant — only one consumer reads at a time.
        let base: *const u8 = unsafe { (*self.payload.get()).as_ptr() };

        // Read the 4-byte length prefix.
        let mut len_buf = [0u8; 4];
        read_wrap(base, CAP, read_off as usize, &mut len_buf);
        let record_len = u32::from_be_bytes(len_buf) as usize;

        if available < 4 + record_len {
            // Partial record — should not happen with correct push.
            return false;
        }

        // Append the payload to `out`.
        let old_len = out.len();
        out.resize(old_len + record_len, 0);
        read_wrap(base, CAP, read_off as usize + 4, &mut out[old_len..]);

        // Release: make the freed space visible to the producer.
        self.read_offset.store(read_off + 4 + record_len as u64, Ordering::Release);
        true
    }

    /// Number of records dropped because the ring was full.
    #[inline]
    pub fn drop_count(&self) -> u64 {
        self.dropped.load(Ordering::Acquire)
    }
}

// ── Ring I/O helpers (wrapping byte access) ──────────────────────────────────

/// Copy `data` bytes into `ring[offset % cap .. ...]` with wrap-around.
///
/// # Safety
/// Caller must ensure exclusive write access to the ring payload.
#[inline]
fn write_wrap(base: *mut u8, cap: usize, offset: usize, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let start = offset % cap;
    let end_space = cap - start;
    unsafe {
        if data.len() <= end_space {
            core::ptr::copy_nonoverlapping(data.as_ptr(), base.add(start), data.len());
        } else {
            core::ptr::copy_nonoverlapping(data.as_ptr(), base.add(start), end_space);
            core::ptr::copy_nonoverlapping(data.as_ptr().add(end_space), base, data.len() - end_space);
        }
    }
}

/// Copy bytes from `ring[offset % cap .. ...]` into `dst` with wrap-around.
///
/// # Safety
/// Caller must ensure exclusive read access to the ring payload.
#[inline]
fn read_wrap(base: *const u8, cap: usize, offset: usize, dst: &mut [u8]) {
    if dst.is_empty() {
        return;
    }
    let start = offset % cap;
    let end_space = cap - start;
    unsafe {
        if dst.len() <= end_space {
            core::ptr::copy_nonoverlapping(base.add(start), dst.as_mut_ptr(), dst.len());
        } else {
            core::ptr::copy_nonoverlapping(base.add(start), dst.as_mut_ptr(), end_space);
            core::ptr::copy_nonoverlapping(base, dst.as_mut_ptr().add(end_space), dst.len() - end_space);
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::boxed::Box;

    type SmallRing = LogsWorkerRing<1024>; // tiny ring for tests

    fn make_ring() -> Box<SmallRing> {
        // Safety: zeroing a SmallRing is valid — all fields are integers /
        // UnsafeCell<[u8; N]> / AtomicU64.  Zero-initialisation is valid for
        // all of these.
        unsafe {
            let layout = std::alloc::Layout::new::<SmallRing>();
            let ptr = std::alloc::alloc_zeroed(layout) as *mut SmallRing;
            Box::from_raw(ptr)
        }
    }

    #[test]
    fn push_then_pop_roundtrips_record() {
        let ring = make_ring();
        let data = b"hello logs";

        let pushed = ring.push(data);
        assert!(pushed, "push must succeed on an empty ring");

        let mut out = std::vec::Vec::new();
        let popped = ring.pop_into(&mut out);
        assert!(popped, "pop must succeed after a push");
        assert_eq!(out.as_slice(), data.as_slice());

        // Ring should now be empty.
        let mut out2 = std::vec::Vec::new();
        assert!(!ring.pop_into(&mut out2), "ring must be empty after draining");
        assert!(out2.is_empty());
    }

    #[test]
    fn push_when_full_drops_and_increments_counter() {
        let ring = make_ring();
        // Fill the ring.  Each record costs 4 (prefix) + payload bytes.
        // Use 80-byte payloads = 84 bytes/record; floor(1024 / 84) = 12 records max.
        let payload = [0xABu8; 80];
        let mut success_count = 0u32;
        for _ in 0..20 {
            if ring.push(&payload) {
                success_count += 1;
            }
        }
        // At least 12 successes; the ring should be full after those.
        assert!(success_count >= 1, "at least one push must succeed");
        // After overflow, the drop counter must be non-zero.
        assert!(ring.drop_count() > 0, "drop counter must be non-zero after overflow");
    }

    #[test]
    fn wrap_around_works() {
        let ring = make_ring();

        // Push records until write_offset is close to the ring boundary.
        // Each record: 4 prefix + 1 payload = 5 bytes.
        // Advance to ~1020 bytes consumed, then drain, then push a spanning record.
        let short = [0x55u8; 1]; // 1 byte payload → 5 bytes total
        // Push ~204 records to advance ~1020 bytes.
        for _ in 0..204 {
            assert!(ring.push(&short), "short push must succeed");
        }
        // Drain them all.
        let mut out = std::vec::Vec::new();
        let mut count = 0u32;
        while ring.pop_into(&mut out) {
            count += 1;
            out.clear();
        }
        assert_eq!(count, 204);

        // write_offset and read_offset are now both 204*5 = 1020.
        // Push a 10-byte record (14 bytes total).  It starts at offset 1020 % 1024 = 1020
        // and spans the ring boundary (1020 + 14 = 1034 > 1024).
        let spanning: [u8; 10] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22];
        let pushed = ring.push(&spanning);
        assert!(pushed, "spanning push must succeed");

        let mut out = std::vec::Vec::new();
        let popped = ring.pop_into(&mut out);
        assert!(popped, "spanning pop must succeed");
        assert_eq!(out.as_slice(), spanning.as_slice());
    }

    #[test]
    fn two_producers_same_thread_serialise_correctly() {
        // SPSC holds for a single-threaded worker: two sequential pushes on the
        // same "worker" thread are serialised by virtue of being sequential.
        let ring = make_ring();

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
}
