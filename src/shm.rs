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

use nginx_sys::{ngx_conf_t, ngx_int_t, ngx_shared_memory_add, ngx_shm_zone_t, ngx_slab_pool_t};
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

// ── Closed cardinality dimension enums (fix3b, FU4a) ────────────────────────
//
// Attribute keys MUST be drawn from OTel HTTP semconv ONLY (proposal §6.4).
// All variants are WithinU8 cardinality so the OTAP classifier can
// dictionary-encode every per-point column at u8 key width.

/// OTel `http.request.method` — 7 standard values + catch-all.
///
/// `N_HTTP_METHODS` = 8.  Computed from `r.method_name` bytes in the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HttpMethod {
    Get = 0,
    Head = 1,
    Post = 2,
    Put = 3,
    Delete = 4,
    Patch = 5,
    Options = 6,
    Other = 7,
}

pub const N_HTTP_METHODS: usize = 8;

impl HttpMethod {
    #[inline]
    pub fn from_bytes(method: &[u8]) -> Self {
        match method {
            b"GET" => Self::Get,
            b"HEAD" => Self::Head,
            b"POST" => Self::Post,
            b"PUT" => Self::Put,
            b"DELETE" => Self::Delete,
            b"PATCH" => Self::Patch,
            b"OPTIONS" => Self::Options,
            _ => Self::Other,
        }
    }

    /// OTel attribute string value for this method.
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Options => "OPTIONS",
            Self::Other => "_OTHER",
        }
    }
}

/// HTTP response status class (s1xx–s5xx).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatusClass {
    S1xx = 0,
    S2xx = 1,
    S3xx = 2,
    S4xx = 3,
    S5xx = 4,
}

pub const N_STATUS_CLASSES: usize = 5;

impl StatusClass {
    #[inline]
    pub fn from_status(status: u16) -> Self {
        match status {
            100..=199 => Self::S1xx,
            200..=299 => Self::S2xx,
            300..=399 => Self::S3xx,
            400..=499 => Self::S4xx,
            _ => Self::S5xx,
        }
    }

    /// OTel attribute integer value for this status class.
    #[inline]
    pub fn representative_status(self) -> i64 {
        match self {
            Self::S1xx => 100,
            Self::S2xx => 200,
            Self::S3xx => 300,
            Self::S4xx => 400,
            Self::S5xx => 500,
        }
    }
}

/// OTel `network.protocol.version` — 4 buckets.
///
/// HTTP/1.0 and HTTP/1.1 are separate (both common; grouping loses information).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtoVersion {
    Http10 = 0,
    Http11 = 1,
    Http2 = 2,
    Http3 = 3,
}

pub const N_PROTO_VERSIONS: usize = 4;

impl ProtoVersion {
    /// Map a nginx `r.http_version` value to `ProtoVersion`.
    ///
    /// nginx constants (`ngx_http_request.h:23-26`):
    ///   `NGX_HTTP_VERSION_10 = 1000`, `NGX_HTTP_VERSION_11 = 1001`,
    ///   `NGX_HTTP_VERSION_20 = 2000`, `NGX_HTTP_VERSION_30 = 3000`.
    #[inline]
    pub fn from_ngx(http_version: core::ffi::c_uint) -> Self {
        match http_version {
            1000 => Self::Http10,
            1001 => Self::Http11,
            2000 => Self::Http2,
            3000 => Self::Http3,
            // Unrecognised version → bucket as HTTP/1.1 (most common).
            _ => Self::Http11,
        }
    }

    /// OTel attribute string value for `network.protocol.version`.
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "1.0",
            Self::Http11 => "1.1",
            Self::Http2 => "2",
            Self::Http3 => "3",
        }
    }
}

// ── Route and upstream-zone dimensions (DP-E, Phase 2.2.2a) ─────────────────
//
// These cap the `http.route` (matched location name) and
// `nginx.upstream.zone` (upstream zone name) dimensions.  Slots beyond the
// cap land in a fixed `"other"` overflow bucket.  The caps are compile-time
// constants; they determine the `WorkerSlots` size and are checked by the
// compile-time `const_assert!` below.
//
// `otel_metric_route_cap` / `otel_metric_upstream_cap` directives are
// reserved for a future phase where operator-visible memory trade-offs are
// exposed; for now the defaults are used and documented here.

/// Maximum number of named `http.route` slots (matched location blocks).
/// Named routes receive indices 0..ROUTE_CAP-1; anything beyond → ROUTE_CAP.
///
/// Default 16: covers the vast majority of production nginx deployments.
/// TODO(phase-N): expose as `otel_metric_route_cap` directive; raise the
/// compile-time constant when a larger default is needed.
pub const ROUTE_CAP: usize = 16;

/// Total route slots: `0..ROUTE_CAP-1` = named, `ROUTE_CAP` = `"other"`.
pub const N_ROUTES: usize = ROUTE_CAP + 1;

/// Maximum number of named upstream-zone slots.
/// Indices 0..UPSTREAM_CAP-1 = named zones; UPSTREAM_CAP = `"(none)"` (no
/// upstream); UPSTREAM_CAP+1 = `"other"` (over cap).
///
/// Default 8: covers the vast majority of production nginx deployments.
pub const UPSTREAM_CAP: usize = 8;

/// Total upstream slots: named + `"(none)"` + `"other"`.
pub const N_UPSTREAMS: usize = UPSTREAM_CAP + 2;

/// Reserved upstream slot index for requests with **no upstream**.
pub const UPSTREAM_IDX_NONE: usize = UPSTREAM_CAP;

/// Reserved upstream slot index for requests whose upstream zone is **over cap**.
pub const UPSTREAM_IDX_OTHER: usize = UPSTREAM_CAP + 1;

/// Total number of `{method × status_class × protocol × route × upstream}` combinations.
///
/// Each combination maps to one [`Histogram`] slot in `WorkerSlots::request_duration_combos`.
/// Default: 8 × 5 × 4 × 17 × 10 = 27,200.
pub const N_COMBOS: usize = N_HTTP_METHODS * N_STATUS_CLASSES * N_PROTO_VERSIONS
    * N_ROUTES * N_UPSTREAMS;

/// Memory budget for `request_duration_combos` in `WorkerSlots`.
///
/// The compile-time assert below guarantees the combined combo array fits
/// within this budget at the default caps.  Raising ROUTE_CAP / UPSTREAM_CAP
/// beyond what the budget permits is an explicit, memory-visible decision.
pub const SLOT_BUDGET: usize = 4 * 1024 * 1024; // 4 MiB per worker

// Compile-time budget check.  With defaults ROUTE_CAP=16 / UPSTREAM_CAP=8,
// 27,200 combos × 136 bytes/Histogram<15> = 3,699,200 bytes < 4 MiB.
const _: () = assert!(
    N_COMBOS * core::mem::size_of::<Histogram<N_DURATION_BUCKETS>>() <= SLOT_BUDGET,
    "request_duration_combos exceeds SLOT_BUDGET — reduce ROUTE_CAP / UPSTREAM_CAP or raise SLOT_BUDGET"
);

/// Compute the combination index from all five bounded dimensions.
///
/// Returns a value in `0 .. N_COMBOS`.  The mapping is:
/// ```
/// idx = method   × N_STATUS_CLASSES × N_PROTO_VERSIONS × N_ROUTES × N_UPSTREAMS
///     + sc        × N_PROTO_VERSIONS × N_ROUTES × N_UPSTREAMS
///     + proto     × N_ROUTES × N_UPSTREAMS
///     + route_idx × N_UPSTREAMS
///     + upstream_idx
/// ```
///
/// `route_idx` must be in `0..N_ROUTES` (ROUTE_CAP = "other");
/// `upstream_idx` must be in `0..N_UPSTREAMS` (UPSTREAM_CAP = "(none)",
/// UPSTREAM_CAP+1 = "other").
#[inline]
pub fn combo_index(
    method: HttpMethod,
    status_class: StatusClass,
    proto: ProtoVersion,
    route_idx: usize,
    upstream_idx: usize,
) -> usize {
    debug_assert!(route_idx < N_ROUTES);
    debug_assert!(upstream_idx < N_UPSTREAMS);
    (method as usize) * (N_STATUS_CLASSES * N_PROTO_VERSIONS * N_ROUTES * N_UPSTREAMS)
        + (status_class as usize) * (N_PROTO_VERSIONS * N_ROUTES * N_UPSTREAMS)
        + (proto as usize) * (N_ROUTES * N_UPSTREAMS)
        + route_idx * N_UPSTREAMS
        + upstream_idx
}

/// Per-worker slot block.
///
/// One of these exists per nginx worker process, mapped at a fixed offset in
/// the shared memory zone. A worker only ever writes to its own slot
/// (`ngx_worker`-indexed); the export worker reads from all slots.
///
/// **Phase 2.2 DP-E**: `request_duration_ms` is now multi-dimensional — one
/// `Histogram` per `{method × status_class × protocol × http.route × upstream-zone}`
/// combination (`N_COMBOS` = 27,200 with default caps).  The flat array is
/// indexed via [`combo_index`].  Route and upstream-zone indices are resolved
/// at config time (`MainConfig::route_table` / `upstream_table`) via a linear
/// scan of at most `ROUTE_CAP` / `UPSTREAM_CAP` entries — O(cap) but branchless
/// and cache-hot for realistic configs.
///
/// Phase 2.2 DP-F switches the per-combo store from `Histogram<15>` to
/// `ExpHistogramSlot` (exponential histogram, native OTAP type).
///
/// The five `status_Nxx` counters have been removed — their information is
/// captured by the per-combination histograms.
#[repr(C)]
pub struct WorkerSlots {
    /// `http.server.request.duration` (ms), broken down by
    /// `{method × status_class × protocol}` — `N_COMBOS` slots total.
    /// Index with [`combo_index`].
    pub request_duration_combos: [Histogram<N_DURATION_BUCKETS>; N_COMBOS],
    /// `http.server.request.body.size` (bytes)
    pub request_body_bytes: Histogram<N_BYTES_BUCKETS>,
    /// `http.server.response.body.size` (bytes)
    pub response_body_bytes: Histogram<N_BYTES_BUCKETS>,
    /// `http.server.upstream.response.duration` (ms)
    pub upstream_response_ms: Histogram<N_DURATION_BUCKETS>,
    /// `http.server.upstream.header.duration` (ms)
    pub upstream_header_ms: Histogram<N_DURATION_BUCKETS>,
    /// `http.server.upstream.connect.duration` (ms)
    pub upstream_connect_ms: Histogram<N_DURATION_BUCKETS>,
    /// `http.server.upstream.bytes.received` (bytes)
    pub upstream_bytes_received: Histogram<N_BYTES_BUCKETS>,
    /// `http.server.upstream.bytes.sent` (bytes)
    pub upstream_bytes_sent: Histogram<N_BYTES_BUCKETS>,
}

impl WorkerSlots {
    /// Zero-initialise a slot block.
    ///
    /// This is called on the pre-allocated shared memory; `zeroed()` correctly
    /// initialises all `AtomicU64` fields to 0.
    ///
    /// # Safety
    /// The caller must ensure the memory at `ptr` is valid for a `WorkerSlots`.
    #[cfg(test)] // only used by in-crate unit tests; production zeroes the zone via nginx
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

/// Byte offset from `shm.addr` to the start of our WorkerSlots data.
///
/// nginx calls `ngx_init_zone_pool` before our zone-init callback, placing
/// an `ngx_slab_pool_t` header at the very beginning of every shared-memory
/// zone.  `ngx_unlock_mutexes` (called on every worker exit from within the
/// master's SIGCHLD handler) dereferences `((ngx_slab_pool_t*)shm.addr)->mutex.lock`.
/// If we zero those bytes our module would null-ptr-crash the master.
///
/// We therefore place our WorkerSlots array **after** the slab-pool header and
/// never touch the first `data_offset()` bytes of the zone.
#[inline]
pub fn data_offset() -> usize {
    mem::size_of::<ngx_slab_pool_t>()
}

/// Minimum zone size for `n_workers` worker processes (including slab pool header).
#[inline]
pub fn zone_size_for(n_workers: usize) -> usize {
    data_offset() + n_workers * mem::size_of::<WorkerSlots>()
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
    if zone.is_null() {
        None
    } else {
        Some(zone)
    }
}

/// Zone initialisation callback, called by nginx on each (re)start.
///
/// # Safety
/// nginx guarantees the callback args are valid non-null pointers.
///
/// # IMPORTANT — do NOT touch the slab-pool header
///
/// nginx calls `ngx_init_zone_pool` immediately *before* this callback.
/// That function writes an `ngx_slab_pool_t` header at `shm.addr[0..]`
/// and initialises its mutex (`sp->mutex.lock = &sp->lock`).  When any
/// worker later exits the master's SIGCHLD handler calls
/// `ngx_unlock_mutexes` → `ngx_shmtx_force_unlock(&sp->mutex, pid)`
/// which dereferences `sp->mutex.lock`.  If we zero the header we null
/// that pointer and crash the master process.
///
/// Our WorkerSlots data lives at `data_offset()` bytes past `shm.addr`,
/// safely beyond the slab-pool header.
pub unsafe extern "C" fn otel_shm_zone_init(
    shm_zone: *mut ngx_shm_zone_t,
    old_data: *mut core::ffi::c_void,
) -> ngx_int_t {
    if !old_data.is_null() {
        // SIGHUP reload: the same physical shm pages are re-mapped.
        // Counter values carry over automatically; no re-initialisation needed.
        return Status::NGX_OK.into();
    }

    // Fresh start: zero only the WorkerSlots area — never the slab-pool header.
    // (The OS provides zero-filled pages for new mmap regions, but we zero
    //  explicitly here for clarity and to handle edge cases.)
    let zone = unsafe { &*shm_zone };
    let offset = data_offset();
    if zone.shm.size > offset {
        let base: *mut u8 = unsafe { zone.shm.addr.cast::<u8>().add(offset) };
        let size = zone.shm.size - offset;
        unsafe { ptr::write_bytes(base, 0, size) };
    }

    Status::NGX_OK.into()
}

// ── Logs shm zone (Phase 2.1) ─────────────────────────────────────────────

use crate::logs::ring::{LogsWorkerRing, ring_size_bytes, LogsWorkerRingHeader, RING_HEADER_SIZE};

/// Bytes occupied by one worker's logs slot (access ring + error ring).
///
/// Both rings use the same `cap` for Phase 2.1.
/// Memory per worker = `cap × 2 + 2 × RING_HEADER_SIZE`.
/// Total logs shm = `slab_pool_header + n_workers × logs_slot_size(cap)`.
#[inline]
pub fn logs_slot_size(cap: usize) -> usize {
    2 * ring_size_bytes(cap)
}

/// Minimum logs zone size for `n_workers` worker processes with ring `cap`.
#[inline]
pub fn logs_zone_size_for(n_workers: usize, cap: usize) -> usize {
    data_offset() + n_workers * logs_slot_size(cap)
}

/// Infer worker count from the logs zone metadata.
///
/// Used by the exporter when it must compute `n_workers` from the zone itself.
/// `cap` must match the value used at zone registration.
#[inline]
pub fn logs_n_workers_from_zone(zone_data_bytes: usize, cap: usize) -> usize {
    let slot = logs_slot_size(cap);
    if slot == 0 {
        0
    } else {
        (zone_data_bytes / slot).max(1)
    }
}

/// Obtain a [`LogsWorkerRing`] view of the **access** ring for `worker_id`.
///
/// Layout per slot (base = `shm.addr + data_offset()`):
/// ```text
/// slot_i = base + i × logs_slot_size(cap)
/// access_ring_header = slot_i + 0
/// access_ring_payload = slot_i + RING_HEADER_SIZE
/// error_ring_header   = slot_i + ring_size_bytes(cap)
/// error_ring_payload  = slot_i + ring_size_bytes(cap) + RING_HEADER_SIZE
/// ```
///
/// # Safety
/// - `base_addr` must point past the slab-pool header (`shm.addr + data_offset()`).
/// - `worker_id < n_workers` and `cap` must match the zone registration.
/// - The returned ring must not outlive the zone mapping.
#[inline]
pub unsafe fn logs_access_ring(base_addr: *mut u8, worker_id: usize, cap: usize) -> LogsWorkerRing {
    let slot_off = worker_id * logs_slot_size(cap);
    unsafe { LogsWorkerRing::from_shm_ptr(base_addr.add(slot_off)) }
}

/// Obtain a [`LogsWorkerRing`] view of the **error** ring for `worker_id`.
///
/// Error ring follows immediately after the access ring within the same slot.
#[inline]
pub unsafe fn logs_error_ring(base_addr: *mut u8, worker_id: usize, cap: usize) -> LogsWorkerRing {
    let slot_off = worker_id * logs_slot_size(cap);
    let error_off = slot_off + ring_size_bytes(cap);
    unsafe { LogsWorkerRing::from_shm_ptr(base_addr.add(error_off)) }
}

/// Zone initialisation callback for the logs shm zone.
///
/// On a fresh start, zeros the slot area and sets `cap` in every ring header
/// so that subsequent push/pop calls know the ring capacity.  On SIGHUP
/// (`old_data` is non-null) the same physical pages are re-mapped; ring offsets
/// carry over automatically — do NOT zero them (gotcha #6 in the plan).
///
/// The configured `cap` is stored in `(*zone).data` as a `usize` cast to
/// `*mut c_void` (tagged pointer pattern; safe because usize fits in a pointer
/// on all supported arches).
///
/// # Safety
/// nginx guarantees the callback args are valid non-null pointers.
pub unsafe extern "C" fn logs_shm_zone_init(
    shm_zone: *mut ngx_shm_zone_t,
    old_data: *mut core::ffi::c_void,
) -> ngx_int_t {
    if !old_data.is_null() {
        // SIGHUP: same physical pages re-mapped.  Ring offsets survive.
        return Status::NGX_OK.into();
    }

    let zone = unsafe { &*shm_zone };
    let offset = data_offset();
    let zone_data_bytes = zone.shm.size.saturating_sub(offset);
    if zone_data_bytes == 0 {
        return Status::NGX_OK.into();
    }

    let base: *mut u8 = unsafe { zone.shm.addr.cast::<u8>().add(offset) };

    // Recover `cap` from the tagged-pointer stored in zone.data.
    // `register_logs_zone` stores `cap` as `usize` → `*mut c_void`.
    let cap = zone.data as usize;
    let slot_sz = logs_slot_size(cap);
    if slot_sz == 0 {
        return Status::NGX_OK.into();
    }

    // Zero the whole slot area first.
    unsafe { ptr::write_bytes(base, 0, zone_data_bytes) };

    // Then stamp `cap` into every ring header so push/pop know the capacity.
    let n_workers = (zone_data_bytes / slot_sz).max(1);
    for w in 0..n_workers {
        let slot_off = w * slot_sz;
        // Access ring header.
        let access_hdr = unsafe { base.add(slot_off).cast::<LogsWorkerRingHeader>() };
        unsafe { (*access_hdr).cap = cap as u64 };
        // Error ring header.
        let error_hdr =
            unsafe { base.add(slot_off + ring_size_bytes(cap)).cast::<LogsWorkerRingHeader>() };
        unsafe { (*error_hdr).cap = cap as u64 };
    }

    Status::NGX_OK.into()
}

/* ──────────────────────── unit tests ──────────────────────── */

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that two "workers" write exclusively to their own slots and
    /// a third "reader" can sum them without cross-contamination.
    ///
    /// Uses the GET/2xx/HTTP1.1 combination slot (combo 0×5×4+1×4+1=9 — but we
    /// use combo_index directly for clarity).
    #[test]
    fn two_workers_isolated_slots() {
        let n_workers: usize = 2;
        let zone_size = zone_size_for(n_workers);
        let mut buffer = std::vec![0u8; zone_size];
        let base = buffer.as_mut_ptr();

        for i in 0..n_workers {
            unsafe { WorkerSlots::init_at(worker_slots(base, i)) };
        }

        // Use GET/2xx/HTTP1.1 combo, route_idx=0 ("other"), upstream_idx=UPSTREAM_IDX_NONE.
        let combo = combo_index(HttpMethod::Get, StatusClass::S2xx, ProtoVersion::Http11, ROUTE_CAP, UPSTREAM_IDX_NONE);

        let slot0 = unsafe { &*worker_slots(base, 0) };
        for _ in 0..3 {
            slot0.request_duration_combos[combo].record(100, &DURATION_BOUNDS_MS);
        }

        let slot1 = unsafe { &*worker_slots(base, 1) };
        for _ in 0..2 {
            slot1.request_duration_combos[combo].record(500, &DURATION_BOUNDS_MS);
        }

        let (_, sum0, count0) = slot0.request_duration_combos[combo].snapshot();
        assert_eq!(count0, 3, "worker 0 count");
        assert_eq!(sum0, 300, "worker 0 sum");

        let (_, sum1, count1) = slot1.request_duration_combos[combo].snapshot();
        assert_eq!(count1, 2, "worker 1 count");
        assert_eq!(sum1, 1000, "worker 1 sum");

        let total_count = count0 + count1;
        let total_sum = sum0 + sum1;
        assert_eq!(total_count, 5);
        assert_eq!(total_sum, 1300);

        // Confirm no cross-write between slots.
        let (buckets0, _, _) = slot0.request_duration_combos[combo].snapshot();
        let (buckets1, _, _) = slot1.request_duration_combos[combo].snapshot();

        let bucket_100ms = DURATION_BOUNDS_MS.partition_point(|&b| 100 > b);
        let bucket_500ms = DURATION_BOUNDS_MS.partition_point(|&b| 500 > b);

        assert_eq!(buckets0[bucket_100ms], 3, "worker 0 bucket for 100ms");
        assert_eq!(buckets1[bucket_500ms], 2, "worker 1 bucket for 500ms");
        assert_eq!(buckets0[bucket_500ms], 0, "slot 0 not written by worker 1");
        assert_eq!(buckets1[bucket_100ms], 0, "slot 1 not written by worker 0");
    }

    /// Combo index mapping: all N_COMBOS combinations must be distinct.
    #[test]
    fn combo_index_all_unique() {
        let mut seen = std::vec![false; N_COMBOS];
        for m in 0..N_HTTP_METHODS {
            for sc in 0..N_STATUS_CLASSES {
                for p in 0..N_PROTO_VERSIONS {
                    for r in 0..N_ROUTES {
                        for u in 0..N_UPSTREAMS {
                            let method = [
                                HttpMethod::Get, HttpMethod::Head, HttpMethod::Post, HttpMethod::Put,
                                HttpMethod::Delete, HttpMethod::Patch, HttpMethod::Options, HttpMethod::Other,
                            ][m];
                            let status = [
                                StatusClass::S1xx, StatusClass::S2xx, StatusClass::S3xx,
                                StatusClass::S4xx, StatusClass::S5xx,
                            ][sc];
                            let proto = [
                                ProtoVersion::Http10, ProtoVersion::Http11,
                                ProtoVersion::Http2, ProtoVersion::Http3,
                            ][p];
                            let idx = combo_index(method, status, proto, r, u);
                            assert!(!seen[idx], "duplicate combo index {}", idx);
                            seen[idx] = true;
                        }
                    }
                }
            }
        }
        assert!(seen.iter().all(|&v| v), "all N_COMBOS combinations must be reachable");
    }

    /// Route and upstream dimensions are included and distinct.
    #[test]
    fn combo_index_includes_route_and_upstream() {
        let m = HttpMethod::Get;
        let sc = StatusClass::S2xx;
        let p = ProtoVersion::Http11;

        let base_idx = combo_index(m, sc, p, 0, 0);
        let route1_idx = combo_index(m, sc, p, 1, 0);
        let upstream1_idx = combo_index(m, sc, p, 0, 1);
        let other_route = combo_index(m, sc, p, ROUTE_CAP, 0);  // "other" route slot
        let none_upstream = combo_index(m, sc, p, 0, UPSTREAM_IDX_NONE);  // "(none)" upstream
        let other_upstream = combo_index(m, sc, p, 0, UPSTREAM_IDX_OTHER);  // "other" upstream

        assert_ne!(base_idx, route1_idx, "different routes must have different indices");
        assert_ne!(base_idx, upstream1_idx, "different upstreams must have different indices");
        assert_ne!(route1_idx, upstream1_idx);
        assert_ne!(base_idx, other_route, "over-cap route must have distinct index");
        assert_ne!(base_idx, none_upstream, "no-upstream must have distinct index");
        assert_ne!(none_upstream, other_upstream, "(none) vs other must differ");

        // All must be within range.
        for &idx in &[base_idx, route1_idx, upstream1_idx, other_route, none_upstream, other_upstream] {
            assert!(idx < N_COMBOS, "combo index {} out of range [0, {})", idx, N_COMBOS);
        }
    }

    /// The compile-time budget assert passes at default caps.
    ///
    /// This test documents the expected size; if it fails, raise SLOT_BUDGET or
    /// lower the caps.  The real check is the `const _: ()` assert above.
    #[test]
    fn worker_slots_within_memory_budget() {
        let combos_bytes = N_COMBOS * core::mem::size_of::<Histogram<N_DURATION_BUCKETS>>();
        assert!(
            combos_bytes <= SLOT_BUDGET,
            "request_duration_combos ({} bytes) exceeds SLOT_BUDGET ({} bytes)",
            combos_bytes,
            SLOT_BUDGET,
        );
    }

    #[test]
    fn zone_size_alignment() {
        let slab = data_offset();
        assert!(slab > 0, "slab pool offset must be positive");
        assert_eq!(zone_size_for(4), slab + 4 * mem::size_of::<WorkerSlots>());
        assert!(zone_size_for(1) >= slab + mem::size_of::<WorkerSlots>());
    }

    #[test]
    fn histogram_overflow_bucket() {
        let mut buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        let slot = unsafe { &*buf.as_mut_ptr().cast::<WorkerSlots>() };

        // Record a large value in the GET/2xx/HTTP1.1 combo (other route, no upstream).
        let combo = combo_index(HttpMethod::Get, StatusClass::S2xx, ProtoVersion::Http11, ROUTE_CAP, UPSTREAM_IDX_NONE);
        let very_large = 99_999u64;
        slot.request_duration_combos[combo].record(very_large, &DURATION_BOUNDS_MS);

        let (buckets, sum, count) = slot.request_duration_combos[combo].snapshot();
        assert_eq!(count, 1);
        assert_eq!(sum, very_large);
        assert_eq!(buckets[N_DURATION_BUCKETS - 1], 1);
        for b in &buckets[..N_DURATION_BUCKETS - 1] {
            assert_eq!(*b, 0);
        }
    }
}
