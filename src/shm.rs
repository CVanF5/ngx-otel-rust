// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Shared memory zone with per-worker atomic counter slots.
//!
//! Layout
//! ------
//! The shared memory zone is a flat array of `WorkerSlots`, indexed by worker ID:
//!
//!   `[ WorkerSlots[0] | WorkerSlots[1] | ... | WorkerSlots[N-1] ]`
//!
//! Each worker writes **only** to `WorkerSlots[ngx_worker]`, using
//! `Ordering::Relaxed` stores (intra-slot coherence is not required because no
//! other core reads the same slot while a worker is writing it).
//!
//! The designated export worker sums all slots using `Ordering::Acquire` loads.
//!
//! Hard constraint: NO allocation on the request path. Every counter lives in
//! pre-allocated shared memory.

use core::sync::atomic::{AtomicU64, Ordering};
use core::{mem, ptr};

use nginx_sys::{ngx_conf_t, ngx_int_t, ngx_shared_memory_add, ngx_shm_zone_t};
use ngx::core::Status;

/// Duration histogram bucket boundaries in **milliseconds**.
///
/// These match the default OTel HTTP server latency boundaries (seconds × 1000).
pub const DURATION_BOUNDS_MS: [u64; 14] =
    [5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000];

/// Number of duration histogram buckets (14 boundaries + 1 overflow).
pub const N_DURATION_BUCKETS: usize = 15;

/// Byte-count histogram bucket boundaries.
pub const BYTES_BOUNDS: [u64; 6] = [128, 512, 4096, 65536, 524288, 4194304];

/// Number of byte-count histogram buckets (6 boundaries + 1 overflow).
pub const N_BYTES_BUCKETS: usize = 7;

/// A fixed-width explicit-boundary histogram stored entirely in atomic counters.
///
/// `BUCKETS` = number of explicit-boundary buckets + 1 overflow bucket.
/// Writes: `Ordering::Relaxed`; reads: `Ordering::Acquire`.
#[repr(C)]
pub struct Histogram<const BUCKETS: usize> {
    /// Per-bucket cumulative count (bucket[i] counts values <= boundary[i-1]).
    pub bucket: [AtomicU64; BUCKETS],
    /// Sum of all observed values.
    pub sum: AtomicU64,
    /// Total observation count.
    pub count: AtomicU64,
}

impl<const BUCKETS: usize> Histogram<BUCKETS> {
    /// Record one observation in the histogram.
    ///
    /// `value` is the observed measurement; `bounds` is the sorted boundary
    /// array (must have length `BUCKETS - 1`).
    ///
    /// # Constraint: no allocation
    /// This function does not allocate.
    #[inline]
    pub fn record(&self, value: u64, bounds: &[u64]) {
        debug_assert_eq!(bounds.len(), BUCKETS - 1);
        let idx = bounds.partition_point(|&b| value > b);
        self.bucket[idx].fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Read all bucket counts, sum, and count for export.
    /// Uses `Ordering::Acquire` to synchronise with worker writes.
    pub fn snapshot(&self) -> ([u64; BUCKETS], u64, u64) {
        let mut counts = [0u64; BUCKETS];
        for (i, c) in self.bucket.iter().enumerate() {
            counts[i] = c.load(Ordering::Acquire);
        }
        let sum = self.sum.load(Ordering::Acquire);
        let count = self.count.load(Ordering::Acquire);
        (counts, sum, count)
    }
}

/// Per-worker slot block.
///
/// One of these exists per nginx worker process, mapped at a fixed offset in
/// the shared memory zone. A worker only ever writes to its own slot
/// (`ngx_worker`-indexed); the export worker reads from all slots.
#[repr(C)]
pub struct WorkerSlots {
    /// `http.server.request.duration` (ms)
    pub request_duration_ms: Histogram<N_DURATION_BUCKETS>,
    /// `http.server.request.body.size` (bytes)
    pub request_body_bytes: Histogram<N_BYTES_BUCKETS>,
    /// `http.server.response.body.size` (bytes)
    pub response_body_bytes: Histogram<N_BYTES_BUCKETS>,
    /// Status code class counters
    pub status_1xx: AtomicU64,
    pub status_2xx: AtomicU64,
    pub status_3xx: AtomicU64,
    pub status_4xx: AtomicU64,
    pub status_5xx: AtomicU64,
    /// `http.server.upstream.response.duration` (ms)
    pub upstream_response_ms: Histogram<N_DURATION_BUCKETS>,
    /// `http.server.upstream.header.duration` (ms)
    pub upstream_header_ms: Histogram<N_DURATION_BUCKETS>,
    /// `http.server.upstream.connect.duration` (ms)
    pub upstream_connect_ms: Histogram<N_DURATION_BUCKETS>,
    /// `http.server.upstream.bytes.received` (bytes)
    pub upstream_bytes_received: Histogram<N_BYTES_BUCKETS>,
}

impl WorkerSlots {
    /// Zero-initialise a slot block.
    ///
    /// This is called on the pre-allocated shared memory; `zeroed()` correctly
    /// initialises all `AtomicU64` fields to 0.
    ///
    /// # Safety
    /// The caller must ensure the memory at `ptr` is valid for a `WorkerSlots`.
    pub unsafe fn init_at(ptr: *mut WorkerSlots) {
        unsafe { ptr::write_bytes(ptr, 0, 1) };
    }
}

/// Obtain a reference to the slot block for the given `worker_id`.
///
/// # Safety
/// - `base_addr` must point to the start of the shared memory zone.
/// - `worker_id` must be < the number of workers the zone was sized for.
/// - The returned reference must not outlive the zone mapping.
#[inline]
pub unsafe fn worker_slots(base_addr: *mut u8, worker_id: usize) -> *mut WorkerSlots {
    let offset = worker_id * mem::size_of::<WorkerSlots>();
    unsafe { base_addr.add(offset).cast() }
}

/// Minimum zone size for `n_workers` worker processes.
#[inline]
pub fn zone_size_for(n_workers: usize) -> usize {
    n_workers * mem::size_of::<WorkerSlots>()
}

/// Register the shared memory zone with nginx from `postconfiguration`.
///
/// Returns the `ngx_shm_zone_t` pointer on success.
///
/// # Safety
/// `cf` and `module` must be valid pointers.
pub unsafe fn register_zone(
    cf: *mut ngx_conf_t,
    name: &mut nginx_sys::ngx_str_t,
    size: usize,
    module: *mut nginx_sys::ngx_module_t,
) -> Option<*mut ngx_shm_zone_t> {
    let zone = unsafe { ngx_shared_memory_add(cf, name, size, module.cast()) };
    if zone.is_null() { None } else { Some(zone) }
}

/// Zone initialisation callback, called by nginx on each (re)start.
///
/// # Safety
/// nginx guarantees the callback args are valid non-null pointers.
pub unsafe extern "C" fn otel_shm_zone_init(
    shm_zone: *mut ngx_shm_zone_t,
    old_data: *mut core::ffi::c_void,
) -> ngx_int_t {
    let zone = unsafe { &mut *shm_zone };
    let base: *mut u8 = zone.shm.addr.cast();
    let size = zone.shm.size;

    if !old_data.is_null() {
        // SIGHUP reload: shm was re-mapped; the zone data pointer is already valid.
        // Counter values carry over automatically because the same physical pages are
        // re-mapped into the new address space. No re-initialisation needed.
        return Status::NGX_OK.into();
    }

    // Fresh start: zero every byte in the zone.
    unsafe { ptr::write_bytes(base, 0, size) };

    Status::NGX_OK.into()
}

/* ──────────────────────── unit tests ──────────────────────── */

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that two "workers" write exclusively to their own slots and
    /// a third "reader" can sum them without cross-contamination.
    #[test]
    fn two_workers_isolated_slots() {
        // Allocate space for 2 workers on the heap (simulates shm).
        let n_workers: usize = 2;
        let zone_size = zone_size_for(n_workers);
        let mut buffer = std::vec![0u8; zone_size];
        let base = buffer.as_mut_ptr();

        // Init slots
        for i in 0..n_workers {
            unsafe { WorkerSlots::init_at(worker_slots(base, i)) };
        }

        // Worker 0 records 3 requests of 100 ms each.
        let slot0 = unsafe { &*worker_slots(base, 0) };
        for _ in 0..3 {
            slot0.request_duration_ms.record(100, &DURATION_BOUNDS_MS);
        }

        // Worker 1 records 2 requests of 500 ms each.
        let slot1 = unsafe { &*worker_slots(base, 1) };
        for _ in 0..2 {
            slot1.request_duration_ms.record(500, &DURATION_BOUNDS_MS);
        }

        // Verify slot 0: 3 observations summing to 300 ms.
        let (_, sum0, count0) = slot0.request_duration_ms.snapshot();
        assert_eq!(count0, 3, "worker 0 count");
        assert_eq!(sum0, 300, "worker 0 sum");

        // Verify slot 1: 2 observations summing to 1000 ms.
        let (_, sum1, count1) = slot1.request_duration_ms.snapshot();
        assert_eq!(count1, 2, "worker 1 count");
        assert_eq!(sum1, 1000, "worker 1 sum");

        // Reader sums both.
        let total_count = count0 + count1;
        let total_sum = sum0 + sum1;
        assert_eq!(total_count, 5);
        assert_eq!(total_sum, 1300);

        // Confirm slot 0 has zero data in slot 1's range (no cross-write).
        let (buckets0, _, _) = slot0.request_duration_ms.snapshot();
        let (buckets1, _, _) = slot1.request_duration_ms.snapshot();

        // 100 ms falls into bucket at index where bound >= 100; first bound >= 100 is bounds[5]=100
        // partition_point returns first index where value <= bound → index 5 (bound=100)
        // Actually: record uses value > b, so partition_point gives first b where !(value > b)
        // i.e. first b >= value. For value=100, bounds[5]=100 >= 100, so idx=5.
        let bucket_100ms = DURATION_BOUNDS_MS.partition_point(|&b| 100 > b);
        let bucket_500ms = DURATION_BOUNDS_MS.partition_point(|&b| 500 > b);

        assert_eq!(buckets0[bucket_100ms], 3, "worker 0 bucket for 100ms");
        assert_eq!(buckets1[bucket_500ms], 2, "worker 1 bucket for 500ms");

        // No other worker wrote to slot 0's 500ms bucket.
        assert_eq!(buckets0[bucket_500ms], 0, "slot 0 not written by worker 1");
        // No other worker wrote to slot 1's 100ms bucket.
        assert_eq!(buckets1[bucket_100ms], 0, "slot 1 not written by worker 0");
    }

    #[test]
    fn zone_size_alignment() {
        // Zone size must accommodate the expected slot count.
        assert!(zone_size_for(4) == 4 * mem::size_of::<WorkerSlots>());
        assert!(zone_size_for(1) >= mem::size_of::<WorkerSlots>());
    }

    #[test]
    fn histogram_overflow_bucket() {
        let mut buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        let slot = unsafe { &*buf.as_mut_ptr().cast::<WorkerSlots>() };

        // Record a value beyond the last boundary (10_000 ms → overflow bucket).
        let very_large = 99_999u64;
        slot.request_duration_ms.record(very_large, &DURATION_BOUNDS_MS);

        let (buckets, sum, count) = slot.request_duration_ms.snapshot();
        assert_eq!(count, 1);
        assert_eq!(sum, very_large);
        // Overflow bucket is the last one.
        assert_eq!(buckets[N_DURATION_BUCKETS - 1], 1);
        // All other buckets should be 0.
        for b in &buckets[..N_DURATION_BUCKETS - 1] {
            assert_eq!(*b, 0);
        }
    }
}
