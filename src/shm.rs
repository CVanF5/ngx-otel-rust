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

use nginx_sys::{
    ngx_conf_t, ngx_core_conf_t, ngx_cycle_t, ngx_int_t, ngx_shared_memory_add, ngx_shm_zone_t,
    ngx_slab_pool_t,
};
use ngx::core::Status;

use crate::logs::access::SampledRequest;

/// Duration histogram bucket boundaries in **milliseconds**.
///
/// These are the default OTel HTTP server latency boundaries (seconds × 1000).
/// Used for the upstream explicit-boundary histograms — nginx reports upstream
/// timings in ms so the worker records raw ms values against these bounds;
/// the exporter publishes the same thresholds expressed in seconds (see
/// `DURATION_BOUNDS_S`) and converts the scalar sum by ÷1000 at export.
pub const DURATION_BOUNDS_MS: [u64; 14] =
    [5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000];

/// Duration histogram bucket boundaries expressed in **seconds** (f64).
///
/// These are `DURATION_BOUNDS_MS ÷ 1000`, used exclusively in the exporter
/// when publishing the `nginx.upstream.*.duration` histograms with unit `"s"`.
/// The worker still records raw ms values against `DURATION_BOUNDS_MS`; the
/// bucket counts are unchanged — only the published boundary scale and the
/// scalar sum (÷1000) change at export.
pub const DURATION_BOUNDS_S: [f64; 14] =
    [0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0];

/// Number of duration histogram buckets (14 boundaries + 1 overflow).
pub const N_DURATION_BUCKETS: usize = 15;

// ── Exponential-histogram constants ─────────────────────────

/// OTel exponential histogram scale for `request_duration_combos`.
///
/// **Resolution:** scale 3 → base = 2^(2^-3) = 2^0.125 ≈ 1.091
/// → 8 buckets per power-of-2.  The metric is published in **seconds**
/// (`http.server.request.duration`, semconv unit `s`), so a duration of
/// ~150µs (≈ p50) resolves to ~13µs near that point — seconds is the unit,
/// not the resolution.
/// <https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exponentialhistogram>
pub const EXP_HISTOGRAM_SCALE: i32 = 3;

/// Number of positive-range bucket slots in each `ExpHistogramSlot`.
///
/// At scale 3, 192 buckets covers ~24 octaves [~1µs, ~16.7s) of request
/// duration.  Durations ≥ ~16.7s clamp to the last bucket (191).  A
/// duration of 0 µs goes to `zero_count` (should not occur in practice).
/// The array size is unchanged from the prior µs-indexed scheme; only the
/// per-bucket meaning (now seconds) and the published offset change.
pub const N_EXP_BUCKETS: usize = 192;

/// Fixed bucket offset (OTel `positive.offset` field in the wire format).
///
/// The histogram is published in **seconds**.  The OTel exponential-histogram
/// bucket index for a value `v` (seconds) at scale 3 is `ceil(log2(v)·8) − 1`
/// (upper-inclusive).  Internal bucket `0` is the lowest covered seconds
/// bucket, holding the smallest non-zero observation of `1µs = 1e-6 s`:
/// `ceil(log2(1e-6)·8) − 1 = −160`.  The encoder emits this value verbatim as
/// `positive.offset` so consumers interpret bucket counts in seconds.
/// <https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exponentialhistogram>
pub const EXP_HISTOGRAM_BUCKET_OFFSET: i32 = -160;

/// Per-bucket **upper bound in integer microseconds** for the seconds-indexed
/// exponential histogram (scale 3).
///
/// `SECONDS_BUCKET_UPPER_US[i] = floor(1e6 · 2^((i + EXP_HISTOGRAM_BUCKET_OFFSET + 1) / 8))`
/// — the exact integer µs threshold below which a duration falls into internal
/// bucket `i` (spec index `i − 160`).  A duration `value_us` lands in the
/// smallest `i` with `value_us ≤ SECONDS_BUCKET_UPPER_US[i]` (upper-inclusive;
/// see [`ExpHistogramSlot::record`]).  Monotonically non-decreasing (the lowest
/// sub-µs spec buckets collapse to threshold 1, unreachable above 0 µs); the
/// integer-µs octave boundaries `15625 … 16000000` appear verbatim at indices
/// `111, 119, …, 191`.
///
/// Generated (and re-verified in `exp_histogram_seconds_bucket_exact`) with:
/// `python3 -c "from decimal import Decimal as D, getcontext; getcontext().prec=80;
/// print([int(D(10)**6*(D(2)**(D(i-159)/D(8)))) for i in range(192)])"`.
const SECONDS_BUCKET_UPPER_US: [u64; N_EXP_BUCKETS] = [
    1, 1, 1, 1, 1, 1, 1, 1, //
    2, 2, 2, 2, 2, 3, 3, 3, //
    4, 4, 4, 5, 5, 6, 6, 7, //
    8, 9, 9, 10, 11, 12, 13, 15, //
    16, 18, 19, 21, 23, 25, 27, 30, //
    33, 36, 39, 43, 47, 51, 55, 61, //
    66, 72, 79, 86, 94, 102, 111, 122, //
    133, 145, 158, 172, 188, 205, 223, 244, //
    266, 290, 316, 345, 376, 410, 447, 488, //
    532, 580, 633, 690, 753, 821, 895, 976, //
    1064, 1161, 1266, 1381, 1506, 1642, 1791, 1953, //
    2129, 2322, 2532, 2762, 3012, 3284, 3582, 3906, //
    4259, 4645, 5065, 5524, 6024, 6569, 7164, 7812, //
    8519, 9290, 10131, 11048, 12048, 13139, 14328, 15625, // 15625 = 2⁻⁶ s
    17039, 18581, 20263, 22097, 24097, 26278, 28656, 31250, //
    34078, 37162, 40526, 44194, 48194, 52556, 57312, 62500, //
    68156, 74325, 81052, 88388, 96388, 105112, 114625, 125000, //
    136313, 148650, 162104, 176776, 192776, 210224, 229251, 250000, //
    272626, 297301, 324209, 353553, 385552, 420448, 458502, 500000, //
    545253, 594603, 648419, 707106, 771105, 840896, 917004, 1000000, // 1000000 = 1 s
    1090507, 1189207, 1296839, 1414213, 1542210, 1681792, 1834008, 2000000, //
    2181015, 2378414, 2593679, 2828427, 3084421, 3363585, 3668016, 4000000, //
    4362030, 4756828, 5187358, 5656854, 6168843, 6727171, 7336032, 8000000, //
    8724061, 9513656, 10374716, 11313708, 12337686, 13454342, 14672064, 16000000, // 16 s
];

/// An OTel **exponential histogram** slot stored entirely in atomic counters.
///
/// The published metric is in **seconds** (`http.server.request.duration`).
/// The worker receives durations as integer microseconds and buckets them
/// directly into the seconds spec mapping (see [`ExpHistogramSlot::record`])
/// so the histogram is exact and single-sourced — the exporter is a faithful
/// pass-through, not a second aggregation stage.
///
/// **Resolution (scale 3):** internal bucket `i` maps to spec index
/// `i + EXP_HISTOGRAM_BUCKET_OFFSET` (= `i − 160`); bucket boundaries are
/// `2^(spec/8)` seconds (base = 2^(2^-3) ≈ 1.091).  All durations are positive
/// so `negative` is empty.
///
/// The record function computes the seconds bucket index with an integer
/// binary search over a precomputed boundary table + one `fetch_add` —
/// alloc-free, lock-free, no float, no `log()`, no syscall on the hot path.
///
/// Size: `(N_EXP_BUCKETS + 3) × 8 = 195 × 8 = 1560 bytes`.
#[repr(C)]
pub struct ExpHistogramSlot {
    /// Bucket `i` counts durations in the seconds spec bucket
    /// `i + EXP_HISTOGRAM_BUCKET_OFFSET`.
    /// `buckets[N_EXP_BUCKETS-1]` is the overflow bucket (≥ ~16.7s).
    pub buckets: [AtomicU64; N_EXP_BUCKETS],
    /// Count of durations = 0 µs (should not occur with µs-precision timing).
    pub zero_count: AtomicU64,
    /// Sum of all observed durations in **µs** (raw; divided by 1e6 to seconds
    /// once at export — the lossless scalar conversion lives in the exporter).
    pub sum: AtomicU64,
    /// Total observation count.
    pub count: AtomicU64,
}

impl ExpHistogramSlot {
    /// Record one duration observation on the hot path.
    ///
    /// `value_us` is the duration in **microseconds**.  The published metric is
    /// in **seconds**; the worker buckets the seconds value `v = value_us / 1e6`
    /// into the OTel exponential-histogram bucket directly so the histogram is
    /// exact and single-sourced.
    ///
    /// # Constraint: no allocation, no lock, no float
    ///
    /// The OTel exp-histogram mapping is **upper-inclusive**: the bucket (spec)
    /// index for a value `v` at scale 3 is `ceil(log2(v)·8) − 1`, i.e. `v` lands
    /// in spec bucket `i` iff `2^(i/8) < v ≤ 2^((i+1)/8)`.  A value exactly on a
    /// bucket boundary goes to the **lower** bucket.
    /// <https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exponentialhistogram>
    ///
    /// We bucket integer microseconds against the seconds mapping using a
    /// precomputed integer-µs upper-bound table.  Internal bucket `i` (spec
    /// index `i + EXP_HISTOGRAM_BUCKET_OFFSET`) has upper bound
    /// `UB_us[i] = floor(1e6 · 2^((i + OFFSET + 1)/8))`.  The seconds bucket
    /// edges in µs are generally non-integer, EXCEPT the octave edges
    /// `1e6 · 2^k` which are exact integer µs (`15625` = 2⁻⁶s, `31250`, …,
    /// `1000000` = 1s, …, `16000000` = 16s) because `1e6 = 2⁶·5⁶` — a naïve
    /// `floor` seconds scheme would mis-bucket exactly those common operating
    /// points.  Flooring the (mostly irrational) upper bound is exact for the
    /// upper-inclusive test on integer input: `value_us ≤ UB ⇔ value_us ≤
    /// floor(UB)` (and at the integer octave edges `floor(UB) = UB` exactly, so
    /// the boundary value `value_us = UB_us[i]` satisfies `≤` and lands in the
    /// lower bucket `i` — upper-inclusive, handled by construction).
    ///
    /// The bucket is the smallest `i` with `value_us ≤ UB_us[i]` =
    /// `partition_point(|t| t < value_us)`, clamped to the overflow bucket — an
    /// integer binary search, no float / `log()` / syscall / alloc / lock.
    ///
    /// **Correctness:** verified exact for all `v ∈ [1, 2^14]` and a
    /// deterministic sample of `[1, 2^24]` (incl. every integer-µs octave
    /// boundary) against `ceil(log2(value_us/1e6)·8) − 1` — see
    /// `exp_histogram_seconds_bucket_exact`.
    #[inline]
    pub fn record(&self, value_us: u64) {
        if value_us == 0 {
            self.zero_count.fetch_add(1, Ordering::Relaxed);
        } else {
            // partition_point returns the index of the first element NOT
            // satisfying the predicate, i.e. the smallest `i` with
            // SECONDS_BUCKET_UPPER_US[i] >= value_us — the spec upper-inclusive
            // bucket.  Clamp to the overflow bucket for durations ≥ ~16.7s.
            let idx = SECONDS_BUCKET_UPPER_US.partition_point(|&t| t < value_us);
            self.buckets[idx.min(N_EXP_BUCKETS - 1)].fetch_add(1, Ordering::Relaxed);
        }
        self.sum.fetch_add(value_us, Ordering::Relaxed);
        // F3 fix: Release on count so snapshot()'s Acquire(count) establishes
        // a happens-before edge that covers all prior bucket/sum writes in this
        // record() call.  Pre-fix this was Relaxed, pairing with no Release →
        // count > Σbuckets observable on weakly-ordered hardware (ARM64).
        self.count.fetch_add(1, Ordering::Release);
    }

    /// Snapshot all bucket counts, zero_count, sum, and count for export.
    ///
    /// F3 fix: `count` is read **first** with `Acquire`, pairing with the
    /// `Release` store in `record()`.  Since all `record()` calls on this slot
    /// originate from the same single worker thread, by transitivity the
    /// Acquire on count=N ensures all N bucket/sum/zero_count writes from
    /// completed record() calls are visible.  The snapshot invariant
    /// `Σbuckets + zero_count ≥ count` therefore holds.  Pre-fix code read
    /// count **last** with an Acquire that had no paired Release → count >
    /// Σbuckets was observable.
    ///
    /// Bucket/sum/zero_count loads use `Relaxed` — they are already ordered by
    /// the `Acquire` load of count that precedes them.
    pub fn snapshot(&self) -> ([u64; N_EXP_BUCKETS], u64, u64, u64) {
        // Read count FIRST to anchor the happens-before with record()'s Release.
        let count = self.count.load(Ordering::Acquire);
        let mut buckets = [0u64; N_EXP_BUCKETS];
        for (i, b) in self.buckets.iter().enumerate() {
            buckets[i] = b.load(Ordering::Relaxed);
        }
        let zero_count = self.zero_count.load(Ordering::Relaxed);
        let sum = self.sum.load(Ordering::Relaxed);
        (buckets, zero_count, sum, count)
    }
}

/// Byte-count histogram bucket boundaries.
pub const BYTES_BOUNDS: [u64; 6] = [128, 512, 4096, 65536, 524288, 4194304];

/// Number of byte-count histogram buckets (6 boundaries + 1 overflow).
pub const N_BYTES_BUCKETS: usize = 7;

/// A fixed-width explicit-boundary histogram stored entirely in atomic counters.
///
/// `BUCKETS` = number of explicit-boundary buckets + 1 overflow bucket.
///
/// Write protocol: all fields written `Relaxed`; `count` written `Release`
/// (last in `record()`).  Read protocol: `count` read `Acquire` (first in
/// `snapshot()`), remaining fields `Relaxed`.  The Acquire-Release pair on
/// `count` establishes the snapshot invariant `Σbuckets ≥ count`.
#[repr(C)]
pub struct Histogram<const BUCKETS: usize> {
    /// Per-bucket cumulative count (`bucket[i]` counts values <= `boundary[i-1]`).
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
        // F3 fix: Release on count (mirrors ExpHistogramSlot::record).
        self.count.fetch_add(1, Ordering::Release);
    }

    /// Read all bucket counts, sum, and count for export.
    ///
    /// F3 fix: `count` is read **first** with `Acquire`, pairing with the
    /// `Release` store in `record()`.  All bucket/sum loads use `Relaxed` —
    /// they are ordered by the preceding `Acquire` on count.  This mirrors
    /// the `ExpHistogramSlot::snapshot` ordering invariant.
    pub fn snapshot(&self) -> ([u64; BUCKETS], u64, u64) {
        // Read count FIRST to anchor the happens-before with record()'s Release.
        let count = self.count.load(Ordering::Acquire);
        let mut counts = [0u64; BUCKETS];
        for (i, c) in self.bucket.iter().enumerate() {
            counts[i] = c.load(Ordering::Relaxed);
        }
        let sum = self.sum.load(Ordering::Relaxed);
        (counts, sum, count)
    }
}

// ── Closed cardinality dimension enums ──────────────────────────────────────
//
// Attribute keys MUST be drawn from OTel HTTP semconv ONLY (see TELEMETRY_MODEL.md).
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

    /// Inverse of the `repr(u8)` index — rebuilds the variant from a combo loop index.
    #[inline]
    pub fn from_index(idx: usize) -> Self {
        match idx {
            0 => Self::Get,
            1 => Self::Head,
            2 => Self::Post,
            3 => Self::Put,
            4 => Self::Delete,
            5 => Self::Patch,
            6 => Self::Options,
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

    /// Inverse of the `repr(u8)` index — rebuilds the variant from a combo loop index.
    #[inline]
    pub fn from_index(idx: usize) -> Self {
        match idx {
            0 => Self::S1xx,
            1 => Self::S2xx,
            2 => Self::S3xx,
            3 => Self::S4xx,
            _ => Self::S5xx,
        }
    }

    /// OTel attribute integer value for this status class.
    ///
    /// Retained for completeness; the exported metric attribute uses
    /// `as_str()` with key `http.response.status_class` instead (F6).
    #[allow(dead_code)]
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

    /// String value for the `http.response.status_class` metric attribute.
    ///
    /// The key `http.response.status_class` carries a self-describing string
    /// (`"2xx"`, etc.) rather than the class representative integer (200, …),
    /// so the key is never mistaken for the actual `http.response.status_code`.
    /// <https://opentelemetry.io/docs/specs/semconv/http/http-metrics/>
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::S1xx => "1xx",
            Self::S2xx => "2xx",
            Self::S3xx => "3xx",
            Self::S4xx => "4xx",
            Self::S5xx => "5xx",
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

    /// Inverse of the `repr(u8)` index — rebuilds the variant from a combo loop index.
    #[inline]
    pub fn from_index(idx: usize) -> Self {
        match idx {
            0 => Self::Http10,
            1 => Self::Http11,
            2 => Self::Http2,
            _ => Self::Http3,
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

// ── Route and upstream-zone dimensions (DECOMPOSED) ─────────────────────────
//
// **Decomposed, not cross-producted**: route and upstream are now
// *separate* histogram tables alongside the base `method × status-class ×
// protocol` (160 combos), not multiplied into it.  This:
//   • Restores the intended caps (64/32) — the prior attempt shrunk them 4×
//     to fit the cross-product budget.
//   • Keeps the two independent latency views (per-route + per-upstream).
//   • Drops the joint route×upstream cell that inflated memory.
//
// Memory: (160 + 65 + 33) × 136 bytes ≈ 34 KB per worker — easily within budget.

/// Maximum number of named `http.route` slots (matched location blocks).
/// Named routes receive indices 0..ROUTE_CAP-1; anything beyond → ROUTE_CAP.
/// Default 64: covers typical production nginx deployments.
pub const ROUTE_CAP: usize = 64;

/// Total route histogram slots: `0..ROUTE_CAP-1` = named, `ROUTE_CAP` = `"other"`.
pub const N_ROUTE_SLOTS: usize = ROUTE_CAP + 1;

/// Maximum number of named upstream-zone slots.
/// Indices 0..UPSTREAM_CAP-1 = named zones; UPSTREAM_CAP = `"other"` (over-cap
/// or no-upstream — requests with no upstream don't bump this table).
/// Default 32: covers typical production nginx deployments.
pub const UPSTREAM_CAP: usize = 32;

/// Total upstream histogram slots: named + `"other"` / skip.
pub const N_UPSTREAM_SLOTS: usize = UPSTREAM_CAP + 1;

/// Total number of `{method × status_class × protocol}` base combinations.
/// Each combination maps to one [`ExpHistogramSlot`] in
/// `WorkerSlots::request_duration_combos` (160).
pub const N_COMBOS: usize = N_HTTP_METHODS * N_STATUS_CLASSES * N_PROTO_VERSIONS;

/// Memory budget for all three histogram arrays in `WorkerSlots`.
///
/// With default caps 64/32 and N_EXP_BUCKETS=192 (scale 3):
///   `size_of::<ExpHistogramSlot>()` = (192 + 3) × 8 = 1560 bytes
///   total = (160 + 65 + 33) × 1560 = 403,920 bytes ≈ 395 KB ≪ 4 MiB.
pub const SLOT_BUDGET: usize = 4 * 1024 * 1024; // 4 MiB per worker

// Compile-time budget check — passes at ROUTE_CAP=64, UPSTREAM_CAP=32, N_EXP_BUCKETS=192.
const _: () = assert!(
    (N_COMBOS + N_ROUTE_SLOTS + N_UPSTREAM_SLOTS) * core::mem::size_of::<ExpHistogramSlot>()
        <= SLOT_BUDGET,
    "histogram arrays exceed SLOT_BUDGET"
);

/// Compute the combination index for the base `{method × status_class × protocol}` table.
///
/// Returns a value in `0 .. N_COMBOS` (= 160).
/// Route and upstream indices are handled by separate tables (decomposed).
#[inline]
pub fn combo_index(method: HttpMethod, status_class: StatusClass, proto: ProtoVersion) -> usize {
    (method as usize) * N_STATUS_CLASSES * N_PROTO_VERSIONS
        + (status_class as usize) * N_PROTO_VERSIONS
        + proto as usize
}

// Keep UPSTREAM_IDX_NONE / UPSTREAM_IDX_OTHER as aliases for the "other" slot
// index used in config.rs lookups.  Both map to N_UPSTREAM_SLOTS-1 = UPSTREAM_CAP.
/// Upstream slot index for over-cap or no-upstream requests (the "other" bucket).
pub const UPSTREAM_IDX_OTHER: usize = UPSTREAM_CAP;

// ── Error-rate severity classes ─────────────────────────────────────────────

/// Number of severity classes for the companion error-rate metric.
///
/// WithinU8 cardinality — 5 classes map nginx levels 1–8 to coarse buckets:
/// `fatal` (1–3), `error` (4), `warn` (5), `info` (6–7), `debug` (8).
pub const N_SEVERITY_CLASSES: usize = 5;

/// Human-readable name for each severity class (used as the `severity_class`
/// attribute value in the error-rate metric data points).
///
/// Index with `severity_class_index(ngx_level)`.
pub const SEVERITY_CLASS_NAMES: [&str; N_SEVERITY_CLASSES] =
    ["fatal", "error", "warn", "info", "debug"];

/// Map a nginx log level (1–8) to a severity-class index (0-based).
///
/// | Class | Index | nginx levels | meaning              |
/// |-------|-------|-------------|----------------------|
/// | fatal |   0   | 1-3          | emerg, alert, crit   |
/// | error |   1   | 4            | error                |
/// | warn  |   2   | 5            | warn                 |
/// | info  |   3   | 6-7          | notice, info         |
/// | debug |   4   | 8            | debug                |
///
/// Out-of-range levels clamp to 0 (`fatal`) — conservative, never out-of-bounds.
#[inline]
pub fn severity_class_index(ngx_level: u8) -> usize {
    match ngx_level {
        1..=3 => 0, // fatal: emerg / alert / crit
        4 => 1,     // error
        5 => 2,     // warn
        6 | 7 => 3, // info: notice / info
        8 => 4,     // debug
        _ => 0,     // clamp unknown to fatal (conservative; never OOB)
    }
}

/// Per-worker slot block.
///
/// One of these exists per nginx worker process, mapped at a fixed offset in
/// the shared memory zone. A worker only ever writes to its own slot
/// (`ngx_worker`-indexed); the export worker reads from all slots.
///
/// **Decomposed dimensions**: three independent histogram arrays:
/// 1. `request_duration_combos[160]`: base `{method × status_class × protocol}`.
/// 2. `route_duration_combos[65]`: per-route (`http.route` = location name).
/// 3. `upstream_duration_combos[33]`: per-upstream zone (`nginx.upstream.zone`).
///
/// Each request bumps ONE slot in each of the three arrays.  The joint
/// route×upstream cell is intentionally dropped.
///
/// Each slot is an `ExpHistogramSlot` (exponential histogram).
///
/// The five `status_Nxx` counters have been removed — their information is
/// captured by the per-combination histograms.
#[repr(C)]
pub struct WorkerSlots {
    /// Base duration histogram: `{method × status_class × protocol}` — 160 slots.
    pub request_duration_combos: [ExpHistogramSlot; N_COMBOS],
    /// Per-`http.route` duration histogram: 65 slots (64 named + "other").
    /// Bumped unconditionally; index from `MainConfig::route_idx_for_clcf`.
    pub route_duration_combos: [ExpHistogramSlot; N_ROUTE_SLOTS],
    /// Per-`nginx.upstream.zone` duration histogram: 33 slots (32 named + "other").
    /// Bumped only when a request has an upstream; skip when no upstream.
    pub upstream_duration_combos: [ExpHistogramSlot; N_UPSTREAM_SLOTS],
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
    /// Per-data-point exemplar reservoirs — one small reservoir per base
    /// `combo_idx` (`request_duration_combos` data point).  Each reservoir holds
    /// up to `EXEMPLAR_RESERVOIR_SIZE` uniformly-sampled exemplars for that data
    /// point, reset every export cycle.  Exemplars are attached to the base
    /// `http.server.request.duration` series only (the decomposed by_route /
    /// by_upstream series carry none).
    pub exemplar_reservoirs: [ExemplarReservoir; N_COMBOS],
    /// Per-severity-class error-log event counters.
    ///
    /// `error_rate_counters[severity_class_index(ngx_level)]` is bumped by the
    /// worker's error-log writer on EVERY floor-passing event (independent of
    /// coalescing — counts the true event volume, not just verbatim samples).
    ///
    /// Written with `Relaxed` by the writer; read with `Acquire` by the exporter,
    /// which sums across all `WorkerSlots[0..n_workers]`.
    ///
    /// Zeroed on fresh start by `otel_shm_zone_init` (all-zeros = valid initial state
    /// for `AtomicU64`). Size = `N_SEVERITY_CLASSES × 8 = 40 bytes` per worker.
    pub error_rate_counters: [AtomicU64; N_SEVERITY_CLASSES],
}

// ── Exemplar reservoir ─────────────────────────────

/// Per-data-point exemplar reservoir size.
///
/// OTel's `SimpleFixedSizeExemplarReservoir` defaults its size to the
/// number of concurrent threads/CPUs purely as a *contention* heuristic for
/// multi-threaded SDKs where many threads offer to one shared reservoir; that
/// does not bind us — nginx workers are single-threaded event loops and we
/// already keep one reservoir per worker (≈ one per CPU), so the per-CPU
/// spreading is achieved at the worker level.  The remaining choice is "how
/// many example traces per data point per interval is useful", which is a
/// small number.  We lock this at 2.
/// <https://opentelemetry.io/docs/specs/otel/metrics/sdk/#exemplar-defaults>
pub const EXEMPLAR_RESERVOIR_SIZE: usize = 2;

/// A single exemplar entry in a per-data-point reservoir.
///
/// Written on the hot path with `Ordering::Relaxed` stores.  The fields are
/// the canonical OTel exemplar payload — `value`, `time_unix_nano`,
/// `trace_id`, `span_id`.  No `filtered_attributes` are stored: `url.path` /
/// `user_agent` were a misuse of that field (they are not metric-measurement
/// attributes) and a redaction hazard, and the linked trace already carries
/// `url.path`.
/// <https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exemplars>
///
/// There is no per-entry commit barrier: the reservoir `count` is the only
/// synchronisation point and the individual fields are written `Relaxed`, so a
/// concurrent cross-process reader can observe a *torn* exemplar (a value
/// paired with the wrong trace_id).  This is an intentional hot-path
/// trade-off: exemplars are sampling hints for drill-down, not an
/// authoritative record (see TELEMETRY_MODEL.md "Exemplars are best-effort
/// hints").
///
/// Size: 5 × AtomicU64 + AtomicU32 + AtomicU8 + 3 pad = 40 + 4 + 1 + 3 = 48 bytes.
#[repr(C)]
pub struct ExemplarEntry {
    /// Observed request duration in µs (matches the exp-histogram `us` unit).
    pub value_us: AtomicU64,
    /// Lower 8 bytes of the W3C trace_id (bytes 0–7).
    pub trace_id_lo: AtomicU64,
    /// Upper 8 bytes of the W3C trace_id (bytes 8–15).
    pub trace_id_hi: AtomicU64,
    /// W3C span_id (parent_id) — 8 bytes.
    pub span_id: AtomicU64,
    /// Unix epoch timestamp of the request in nanoseconds.
    pub ts_unix_nano: AtomicU64,
    /// Combo index (identifies the histogram data point this belongs to).
    ///
    /// Redundant now that there is one reservoir per data point (the reservoir
    /// array index is the combo), but kept on the snapshot so the exporter's
    /// per-combo match path is unchanged.
    pub combo_idx: core::sync::atomic::AtomicU32,
    /// 1 if `trace_id` / `span_id` are valid; 0 if absent.
    pub has_trace: core::sync::atomic::AtomicU8,
    _pad: [u8; 3],
}

/// Per-data-point exemplar reservoir — a fixed-capacity pool of
/// [`ExemplarEntry`] filled by uniform `SimpleFixedSizeExemplarReservoir`
/// sampling.
///
/// # Sampling discipline
///
/// Each candidate calls `seen.fetch_add(1)` to obtain `n` (the number of
/// measurements seen this cycle, 0-based).  Following OTel's
/// `SimpleFixedSizeExemplarReservoir`: when `n < size` the candidate is written
/// to slot `n` (fill phase); otherwise `bucket = rand_index(n)` in `0..=n` and
/// the candidate is written to slot `bucket` only if `bucket < size`.
///
/// Every measurement therefore has equal probability of being retained
/// (uniform), not the recency bias of a `n % size` ring.  The "random" index
/// is a cheap alloc-free, lock-free integer hash of `n` (no `rand`/`Math.random`
/// on the hot path); over a cycle it is uniform enough for sampling hints.
/// The single `fetch_add` IS the one permitted hot-path write.
/// <https://opentelemetry.io/docs/specs/otel/metrics/sdk/#exemplar-defaults>
///
/// # Reset (one cross-process write)
/// The exporter calls [`ExemplarReservoir::reset`] after [`ExemplarReservoir::snapshot`]
/// every collection cycle, storing `0` into `seen` (the spec's
/// `num_measurements_seen` reset).  `seen` is only ever touched atomically —
/// `fetch_add(Relaxed)` by the worker, `store(0, Release)` by the exporter — so
/// the store-vs-RMW interleaving is well-defined (no data race).  A worker
/// write landing in the same instant the exporter zeroes is a benign
/// lost-update, consistent with the best-effort-hint semantics above.
#[repr(C)]
pub struct ExemplarReservoir {
    /// `num_measurements_seen` this collection cycle (OTel spec name).  Reset to
    /// 0 by the exporter after each snapshot.
    pub seen: AtomicU64,
    pub entries: [ExemplarEntry; EXEMPLAR_RESERVOIR_SIZE],
}

impl ExemplarReservoir {
    /// Write one exemplar entry on the hot path from a `SampledRequest`.
    ///
    /// # Hot-path note
    /// One `fetch_add` + a branch + ≤ 6 `Relaxed` stores.  Alloc-free,
    /// lock-free, no syscall.
    #[inline]
    pub fn write(&self, req: &SampledRequest<'_>) {
        let n = self.seen.fetch_add(1, Ordering::Relaxed);
        let size = EXEMPLAR_RESERVOIR_SIZE as u64;
        // SimpleFixedSizeExemplarReservoir slot selection.
        let bucket = if n < size {
            n
        } else {
            // rand_index in 0..=n; cheap integer hash (SplitMix64 finaliser) of
            // `n` mapped into the inclusive range, in lieu of an RNG.
            Self::rand_index(n) % (n + 1)
        };
        if bucket >= size {
            return; // measurement not retained (uniform eviction)
        }
        let e = &self.entries[bucket as usize];
        e.value_us.store(req.duration_us, Ordering::Relaxed);
        e.ts_unix_nano.store(req.ts_unix_nano, Ordering::Relaxed);
        e.combo_idx.store(req.combo_idx, Ordering::Relaxed);
        if let Some((tid, sid)) = req.trace {
            let lo = u64::from_be_bytes(tid[0..8].try_into().unwrap_or([0u8; 8]));
            let hi = u64::from_be_bytes(tid[8..16].try_into().unwrap_or([0u8; 8]));
            e.trace_id_lo.store(lo, Ordering::Relaxed);
            e.trace_id_hi.store(hi, Ordering::Relaxed);
            e.span_id.store(u64::from_be_bytes(sid), Ordering::Relaxed);
            e.has_trace.store(1, Ordering::Relaxed);
        } else {
            e.has_trace.store(0, Ordering::Relaxed);
        }
    }

    /// Cheap deterministic integer hash of `n` (SplitMix64 finaliser) — a
    /// stand-in for an RNG so the hot path stays alloc-free and dependency-free.
    /// Distributes successive `n` across the output range uniformly enough for
    /// sampling-hint selection.
    #[inline]
    fn rand_index(n: u64) -> u64 {
        let mut z = n.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Snapshot the active entries of this reservoir.
    ///
    /// Occupancy is the reservoir's own `seen` count clamped to the reservoir
    /// size (`filled = seen.min(size)`).  This replaces the old
    /// `combo_idx == 0 && ts == 0` sentinel, which is invalid now that combo 0
    /// is a legitimate data point with its own reservoir.
    pub fn snapshot(&self) -> std::vec::Vec<ExemplarSnapshot> {
        let seen = self.seen.load(Ordering::Acquire) as usize;
        let filled = seen.min(EXEMPLAR_RESERVOIR_SIZE);

        let mut out = std::vec::Vec::with_capacity(filled);
        for i in 0..filled {
            let e = &self.entries[i];
            let value_us = e.value_us.load(Ordering::Acquire);
            let combo_idx = e.combo_idx.load(Ordering::Acquire);
            let has_trace = e.has_trace.load(Ordering::Acquire) != 0;
            let ts_ns = e.ts_unix_nano.load(Ordering::Acquire);
            let lo = e.trace_id_lo.load(Ordering::Acquire).to_be_bytes();
            let hi = e.trace_id_hi.load(Ordering::Acquire).to_be_bytes();
            let mut trace_id = [0u8; 16];
            trace_id[0..8].copy_from_slice(&lo);
            trace_id[8..16].copy_from_slice(&hi);
            let span_id = e.span_id.load(Ordering::Acquire).to_be_bytes();
            out.push(ExemplarSnapshot {
                value_us,
                combo_idx,
                has_trace,
                trace_id,
                span_id,
                ts_unix_nano: ts_ns,
            });
        }
        out
    }

    /// Reset the sampling state (the OTel `num_measurements_seen` count) after a
    /// collection cycle.  This is the single cross-process write into the
    /// reservoir; see the struct doc for its race semantics.
    ///
    /// The stale entry payloads are intentionally NOT zeroed — once `seen` is 0
    /// the next snapshot reports `filled = 0`, and the fill phase overwrites the
    /// slots before they can be observed again.
    pub fn reset(&self) {
        self.seen.store(0, Ordering::Release);
    }
}

/// Snapshot result from `ExemplarReservoir::snapshot`.
pub struct ExemplarSnapshot {
    pub value_us: u64,
    pub combo_idx: u32,
    pub has_trace: bool,
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub ts_unix_nano: u64,
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
        // SAFETY: the caller guarantees `ptr` is valid for a `WorkerSlots` (fn
        // contract); `write_bytes(_, 0, 1)` zero-initialises exactly one, the
        // correct initial state for all its `AtomicU64` fields.
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
    // SAFETY: per the fn contract `base_addr` is the zone start and `worker_id`
    // is < the worker count the zone was sized for, so `offset` lands within the
    // zone. The pointer is only formed here, not dereferenced.
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
pub const fn data_offset() -> usize {
    mem::size_of::<ngx_slab_pool_t>()
}

/// Minimum zone size for `n_workers` worker processes (including slab pool header).
#[inline]
pub fn zone_size_for(n_workers: usize) -> usize {
    data_offset() + n_workers * mem::size_of::<WorkerSlots>()
}

/// Number of `WorkerSlots` the metrics zone was sized for, derived from the
/// total zone size (including the slab-pool header at offset 0).
///
/// Returns 0 when `zone_size <= data_offset()` (zone too small to hold any slot).
/// The result is the CAPACITY of the zone, not necessarily the current worker count.
#[inline]
pub fn n_workers_from_zone_size(zone_size: usize) -> usize {
    let slot = mem::size_of::<WorkerSlots>();
    zone_size.saturating_sub(data_offset()) / slot
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
    // SAFETY: per the fn contract `cf` and `module` are valid; this is a plain
    // FFI call into nginx's shared-memory registration with valid arguments.
    let zone = unsafe { ngx_shared_memory_add(cf, name, size, module.cast()) };
    if zone.is_null() {
        None
    } else {
        Some(zone)
    }
}

// ── Zone-init data + active-worker helper ────────────────────────────────────

/// Data threaded through `ngx_shm_zone_t.data` to our zone-init callbacks.
///
/// Stored as a field of `MainConfig` (nginx config pool) so the pointer in
/// `zone->data` stays valid from postconfiguration through the zone-init
/// callbacks (which nginx fires from within the same `ngx_init_cycle` call).
pub struct ZoneInitData {
    /// Per-worker ring capacity in bytes.  `0` for the metrics zone (no ring).
    pub ring_cap: usize,
    /// Address of the `ngx_cycle_t` being built, stored as `usize` so
    /// `ZoneInitData` remains `Send` without an unsafe impl.
    /// Cast to `*const ngx_cycle_t` before use.
    pub cycle_addr: usize,
}

/// Read the final `worker_processes` from a `ngx_cycle_t`.
///
/// Called from zone-init callbacks after `ngx_core_module_init_conf` has run,
/// so `worker_processes` is guaranteed ≥ 1 by that point.  Returns `None`
/// only on unexpected failures (null cycle, unreachable conf_ctx, etc.).
///
/// # Safety
/// `cycle` must be a valid, non-null `ngx_cycle_t` pointer (or null — null
/// is handled gracefully by returning `None`).
unsafe fn wp_from_cycle(cycle: *const ngx_cycle_t) -> Option<usize> {
    if cycle.is_null() {
        return None;
    }
    // SAFETY: caller guarantees `cycle` is valid.
    let cycle_ref = unsafe { &*cycle };
    // SAFETY: nginx fills conf_ctx before zone-init callbacks fire.
    let raw_conf: *mut *mut *mut core::ffi::c_void =
        unsafe { *cycle_ref.conf_ctx.add(nginx_sys::ngx_core_module.index) };
    let core_conf = raw_conf.cast::<ngx_core_conf_t>();
    if core_conf.is_null() {
        return None;
    }
    // SAFETY: core_conf is non-null per above check.
    let wp = unsafe { (*core_conf).worker_processes };
    if wp >= 1 {
        Some(wp as usize)
    } else {
        None
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
///
/// # F1 — reload partial-zero helper
///
/// `route_duration_combos` and `upstream_duration_combos` are indexed by position
/// in `route_table` / `upstream_table`, which are rebuilt on every SIGHUP reload
/// (new `ngx_http_core_loc_conf_t*` and `ngx_shm_zone_t*` values; traversal order
/// may differ if locations are added/removed/reordered).  Any count accumulated
/// under the old index assignment would be re-attributed to whichever route/upstream
/// now owns that slot number.  To prevent this, `otel_shm_zone_init` zeros ONLY
/// these two arrays on reload.
///
/// Fields that CARRY OVER on reload (indices are config-stable):
///   - `request_duration_combos` (method × status_class × protocol — no config dependency)
///   - `request_body_bytes`, `response_body_bytes` (global aggregates)
///   - `upstream_response_ms`, `upstream_header_ms`, `upstream_connect_ms`,
///     `upstream_bytes_received`, `upstream_bytes_sent` (global upstream aggregates)
///   - `exemplar_reservoirs` (indexed by base `combo_idx`, which refs
///     `request_duration_combos` — config-stable)
///   - `error_rate_counters` (severity class — config-stable)
///
/// `start_time_unix_nano` resets per-reload (export/mod.rs:487 — new exporter process
/// calls `now_unix_nano()`), so zeroing the route/upstream slots produces a valid
/// OTLP cumulative reset at the reload boundary.
///
/// Dying old workers may write a few more counts into just-zeroed slots in the seconds
/// before they exit.  Each word is zeroed via AtomicU64::store(Relaxed), so concurrent
/// fetch_add from old workers is well-defined; the stale counts vanish with the old
/// workers and are negligible versus incoming new traffic.  Accepted.
///
/// # Safety
/// `base` must point to at least `n_slots` contiguous `WorkerSlots` objects within
/// a mapped shm zone.  `n_slots * size_of::<WorkerSlots>()` must not exceed the
/// available zone bytes past `data_offset()`.
unsafe fn zero_route_upstream_histograms(base: *mut u8, n_slots: usize) {
    const ROUTE_OFF: usize = core::mem::offset_of!(WorkerSlots, route_duration_combos);
    const ROUTE_SZ: usize = mem::size_of::<[ExpHistogramSlot; N_ROUTE_SLOTS]>();
    const UPSTREAM_OFF: usize = core::mem::offset_of!(WorkerSlots, upstream_duration_combos);
    const UPSTREAM_SZ: usize = mem::size_of::<[ExpHistogramSlot; N_UPSTREAM_SLOTS]>();
    // ExpHistogramSlot consists entirely of AtomicU64 fields; both arrays must be
    // multiples of 8 bytes so every word can be zeroed via AtomicU64::store(Relaxed).
    // ptr::write_bytes would race with concurrent fetch_add from dying old-generation
    // workers during SIGHUP reload (non-atomic write vs. atomic RMW = UB).
    const _: () =
        assert!(ROUTE_SZ % 8 == 0, "ROUTE_SZ must be a multiple of 8 for AtomicU64 zeroing");
    const _: () =
        assert!(UPSTREAM_SZ % 8 == 0, "UPSTREAM_SZ must be a multiple of 8 for AtomicU64 zeroing");
    let slot_bytes = mem::size_of::<WorkerSlots>();
    for i in 0..n_slots {
        // SAFETY: `i < n_slots` (fn contract) → `i * slot_bytes < n_slots * slot_bytes ≤`
        // zone bytes past data_offset() (fn contract).  ROUTE_OFF and UPSTREAM_OFF are
        // compile-time offset_of! values within WorkerSlots (< slot_bytes); adding their
        // respective sizes also stays within slot_bytes.  Each word is zeroed via
        // AtomicU64::store(Relaxed) to avoid RMW races with concurrent old-worker writes.
        unsafe {
            let slot_base: *mut u8 = base.add(i * slot_bytes);
            let route_ptr = slot_base.add(ROUTE_OFF) as *mut AtomicU64;
            for w in 0..(ROUTE_SZ / 8) {
                (*route_ptr.add(w)).store(0, Ordering::Relaxed);
            }
            let upstream_ptr = slot_base.add(UPSTREAM_OFF) as *mut AtomicU64;
            for w in 0..(UPSTREAM_SZ / 8) {
                (*upstream_ptr.add(w)).store(0, Ordering::Relaxed);
            }
        }
    }
}

pub unsafe extern "C" fn otel_shm_zone_init(
    shm_zone: *mut ngx_shm_zone_t,
    old_data: *mut core::ffi::c_void,
) -> ngx_int_t {
    if !old_data.is_null() {
        // SIGHUP reload: the same physical shm pages are re-mapped.
        //
        // Most WorkerSlots fields carry over correctly (see the doc-comment on
        // `zero_route_upstream_histograms` above for the full list).  The two
        // exceptions are route_duration_combos and upstream_duration_combos: their
        // slot indices come from build_route_table / build_upstream_table, which
        // rebuilds with new clcf_ptr / shm_zone_ptr values on every reload.  Any
        // location add/remove/reorder shifts the index, silently re-attributing old
        // counts to a different route/upstream name in the next export.
        //
        // zero ALL reserved slots, not just the new active count.  On a
        // scale-down reload (e.g. worker_processes 4→1) the old higher-numbered
        // slots retain counts recorded under the OLD route-index assignment.  The
        // exporter always sums all reserved slots, so those stale counts get
        // attributed to whichever route now owns that index — silent misattribution.
        // Zeroing all reserved slots is safe: they are already atomic (H2F2) and the
        // memory is already mapped (same physical shm pages), so no new page faults.
        // SAFETY: nginx invokes this callback with a valid, non-null `ngx_shm_zone_t`
        // (fn contract); the reference does not outlive the call.
        let zone = unsafe { &*shm_zone };
        let offset = data_offset();
        if zone.shm.size <= offset {
            return Status::NGX_OK.into();
        }
        let slot_bytes = mem::size_of::<WorkerSlots>();
        // n_reserved may be 0 if the zone is too small for even one slot;
        // zero_route_upstream_histograms(_, 0) is a safe no-op.
        let n_reserved = (zone.shm.size - offset) / slot_bytes;
        // SAFETY: offset == data_offset(), zone.shm.size > offset (checked above).
        // n_reserved = (zone.shm.size - offset) / slot_bytes — fn contract met.
        let base: *mut u8 = unsafe { zone.shm.addr.cast::<u8>().add(offset) };
        // SAFETY: base and n_reserved meet zero_route_upstream_histograms' contract.
        unsafe { zero_route_upstream_histograms(base, n_reserved) };
        return Status::NGX_OK.into();
    }

    // zero only the ACTIVE WorkerSlots — reserved-but-inactive slots
    // from the ncpu-headroom reservation are OS-zeroed anonymous pages and
    // must not be touched here (doing so would fault them in, wasting RAM).
    // SAFETY: nginx invokes this callback with a valid, non-null
    // `ngx_shm_zone_t` (fn contract); the reference does not outlive the call.
    let zone = unsafe { &*shm_zone };
    let offset = data_offset();
    if zone.shm.size <= offset {
        return Status::NGX_OK.into();
    }

    // Derive the active worker count from the ZoneInitData stored in zone->data.
    // `cycle_addr` was written at postconfiguration from `cf->cycle`; the
    // same cycle pointer remains valid through the zone-init call (same
    // ngx_init_cycle invocation).
    // SAFETY: zone->data is either null (legacy / test) or points at a `ZoneInitData`
    // stored in amcf (nginx conf pool, which outlives this zone-init callback).
    let n_active = if let Some(zid) = unsafe { zone.data.cast::<ZoneInitData>().as_ref() } {
        let cycle = zid.cycle_addr as *const ngx_cycle_t;
        // SAFETY: cycle is non-null (set from cf->cycle, which is non-null at
        // postconfiguration) and valid for the duration of ngx_init_cycle.
        unsafe { wp_from_cycle(cycle) }.unwrap_or(1)
    } else {
        1
    };

    let slot_bytes = mem::size_of::<WorkerSlots>();
    let n_reserved = (zone.shm.size - offset) / slot_bytes;
    let n_init = n_active.min(n_reserved).max(1);

    // SAFETY: `offset == data_offset()` and we checked `zone.shm.size > offset`.
    let base: *mut u8 = unsafe { zone.shm.addr.cast::<u8>().add(offset) };
    let size = n_init * slot_bytes;
    // SAFETY: `base` starts past the slab-pool header; `size = n_init * slot_bytes`
    // with `n_init ≤ n_reserved = (zone.shm.size - offset) / slot_bytes`, so the
    // write stays within the mapped zone.
    unsafe { ptr::write_bytes(base, 0, size) };

    Status::NGX_OK.into()
}

// ── Logs shm zone ─────────────────────────────────────────────

use crate::logs::ring::{ring_size_bytes, LogsWorkerRing, LogsWorkerRingHeader};

// ── Compile-time alignment guards ───────────────────────────────────────
//
// The logs shm slot layout is:
//   [0, ring_size_bytes(cap))                 — access ring header + payload
//   [ring_size_bytes(cap), 2*rbs)             — error ring header + payload
//   [2*ring_size_bytes(cap), 2*rbs+tbl)       — CoalesceSlot table
//
// `LogsWorkerRingHeader` contains four `AtomicU64` fields → alignment = 8 bytes.
// `CoalesceSlot` contains an `AtomicU64` at offset 0 → alignment = 8 bytes.
//
// For both sub-structures to land at aligned addresses:
//   1. RING_HEADER_SIZE % 8 == 0  (so header + 8-aligned cap → rbs % 8 == 0)
//   2. coalesce_table_bytes() % 8 == 0  (so slot stride is 8-aligned)
//   3. data_offset() % 8 == 0  (so slot 0 starts 8-aligned inside the mmap zone)
//
// cap % 8 == 0 is enforced at config-parse time by `cmd_set_log_ring_size`.
const _: () = assert!(
    crate::logs::ring::RING_HEADER_SIZE % 8 == 0,
    "LogsWorkerRingHeader size must be a multiple of 8: error-ring header alignment depends on this",
);
const _: () = assert!(
    crate::logs::coalesce::coalesce_table_bytes() % 8 == 0,
    "coalesce table byte count must be a multiple of 8 for CoalesceSlot (AtomicU64) alignment",
);
const _: () = assert!(
    data_offset() % 8 == 0,
    "data_offset (= size_of::<ngx_slab_pool_t>()) must be 8-aligned so ring headers start aligned",
);

/// Bytes occupied by one worker's logs slot (access ring + error ring + coalescer table).
///
/// Layout within a slot:
/// ```text
/// offset 0:                    access ring header + payload  (ring_size_bytes(cap))
/// offset ring_size_bytes(cap): error ring header + payload   (ring_size_bytes(cap))
/// offset 2*ring_size_bytes(cap): coalescer table             (coalesce_table_bytes())
/// ```
///
/// Memory per worker = `cap × 2 + 2 × RING_HEADER_SIZE + COALESCE_CAPACITY × 24`.
/// At default ring_cap=4096: 2×4128 + 6144 = 14400 bytes/worker — negligible.
/// Total logs shm = `slab_pool_header + n_workers × logs_slot_size(cap)`.
#[inline]
pub fn logs_slot_size(cap: usize) -> usize {
    2 * ring_size_bytes(cap) + crate::logs::coalesce::coalesce_table_bytes()
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
    (zone_data_bytes.checked_div(slot).unwrap_or(0)).max(1)
}

/// Obtain a [`LogsWorkerRing`] view of the **access** ring for `worker_id`.
///
/// Layout per slot (base = `shm.addr + data_offset()`):
/// ```text
/// slot_i = base + i × logs_slot_size(cap)
/// access_ring_header   = slot_i + 0
/// access_ring_payload  = slot_i + RING_HEADER_SIZE
/// error_ring_header    = slot_i + ring_size_bytes(cap)
/// error_ring_payload   = slot_i + ring_size_bytes(cap) + RING_HEADER_SIZE
/// coalescer_table      = slot_i + 2 * ring_size_bytes(cap)
/// ```
///
/// # Safety
/// - `base_addr` must point past the slab-pool header (`shm.addr + data_offset()`).
/// - `worker_id < n_workers` and `cap` must match the zone registration.
/// - The returned ring must not outlive the zone mapping.
#[inline]
pub unsafe fn logs_access_ring(base_addr: *mut u8, worker_id: usize, cap: usize) -> LogsWorkerRing {
    // cap must be a multiple of 8 so that ring headers and the coalescer
    // table land at 8-byte-aligned addresses within the slot.  Enforced at
    // config parse time by `cmd_set_log_ring_size`; catch stale callers here.
    debug_assert_eq!(cap % 8, 0, "ring cap must be a multiple of 8 for AtomicU64 alignment");
    let slot_off = worker_id * logs_slot_size(cap);
    // SAFETY: per the fn contract `base_addr` is `shm.addr + data_offset()`,
    // `worker_id < n_workers`, and `cap` matches registration, so `slot_off` is
    // within the zone. The access ring header begins at slot offset 0,
    // satisfying `from_shm_ptr`'s contract.
    unsafe { LogsWorkerRing::from_shm_ptr(base_addr.add(slot_off)) }
}

/// Obtain a [`LogsWorkerRing`] view of the **error** ring for `worker_id`.
///
/// Error ring follows immediately after the access ring within the same slot.
#[inline]
pub unsafe fn logs_error_ring(base_addr: *mut u8, worker_id: usize, cap: usize) -> LogsWorkerRing {
    // same cap alignment requirement as `logs_access_ring`.
    debug_assert_eq!(cap % 8, 0, "ring cap must be a multiple of 8 for AtomicU64 alignment");
    let slot_off = worker_id * logs_slot_size(cap);
    let error_off = slot_off + ring_size_bytes(cap);
    // SAFETY: same contract as `logs_access_ring`; the error ring header begins
    // one `ring_size_bytes(cap)` past the access ring within the same in-zone
    // slot, satisfying `from_shm_ptr`'s contract.
    unsafe { LogsWorkerRing::from_shm_ptr(base_addr.add(error_off)) }
}

/// Return the raw `*mut u8` of the **error** ring for `worker_id`.
///
/// Unlike [`logs_error_ring`] this returns the raw pointer suitable for stashing in
/// `OtelErrorWriterState::error_ring_ptr`.  The writer reconstructs a
/// [`LogsWorkerRing`] view via `LogsWorkerRing::from_shm_ptr` on each hot-path call.
///
/// Called by `init_process` once per worker after the logs zone is mapped.
///
/// # Safety
/// Same as [`logs_error_ring`].
#[inline]
pub unsafe fn logs_error_ring_ptr(base_addr: *mut u8, worker_id: usize, cap: usize) -> *mut u8 {
    let slot_off = worker_id * logs_slot_size(cap);
    let error_off = slot_off + ring_size_bytes(cap);
    // SAFETY: same contract as `logs_error_ring`; `error_off` is within the
    // zone, so the pointer is in-bounds. It is only formed here, not
    // dereferenced (the writer rebuilds a view via `from_shm_ptr`).
    unsafe { base_addr.add(error_off) }
}

/// Obtain a raw pointer to the **coalescer table** for `worker_id` in the logs shm zone.
///
/// The coalescer table occupies the last `coalesce_table_bytes()` bytes of the slot,
/// after the access ring and error ring.  It is a `[CoalesceSlot; COALESCE_CAPACITY]`
/// array; on fresh start the slot area is zeroed, giving `key_hash == 0` (empty) for
/// every slot — the correct initial state.
///
/// Called by `init_process` to pre-compute the table pointer and stash
/// it in `OtelErrorWriterState::coalesce_table`, so the hot path is a single
/// null-guarded dereference.
///
/// # Safety
/// - `base_addr` must point past the slab-pool header (`shm.addr + data_offset()`).
/// - `worker_id < n_workers` and `cap` must match the zone registration.
/// - The returned pointer must not outlive the zone mapping.
#[inline]
pub unsafe fn logs_coalesce_table(
    base_addr: *mut u8,
    worker_id: usize,
    cap: usize,
) -> *mut crate::logs::coalesce::CoalesceSlot {
    let slot_off = worker_id * logs_slot_size(cap);
    let coalesce_off = slot_off + 2 * ring_size_bytes(cap);
    // SAFETY: same contract as `logs_access_ring`; the coalescer table occupies
    // the slot region after both rings (`2 * ring_size_bytes(cap)` in), still
    // within the zone. The pointer is only formed here, not dereferenced.
    unsafe { base_addr.add(coalesce_off).cast() }
}

/// Zone initialisation callback for the logs shm zone.
///
/// On a fresh start, zeros the slot area and sets `cap` in every ring header
/// so that subsequent push/pop calls know the ring capacity.  On SIGHUP
/// (`old_data` is non-null) the same physical pages are re-mapped; **log ring
/// head/tail offsets** carry over — do NOT zero them (gotcha #6 in the plan).
/// This is the logs-ring zone only; the metrics zone (`otel_shm_zone_init`)
/// handles route/upstream histogram resets separately on reload.
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
        // SIGHUP: same physical pages re-mapped.  Ring offsets carry over.
        // H2F3: On scale-up reload, new worker slots are OS-zeroed (cap==0).
        // Stamp cap into ALL active-slot ring headers (idempotent for existing
        // slots; required for new slots added by the worker_processes increase).
        //
        // SAFETY: nginx guarantees shm_zone is a valid non-null pointer (fn contract).
        // zone.data was written by register_logs_zone to point at a ZoneInitData in
        // amcf (nginx conf pool, outlives reload); cycle is from cf->cycle at
        // postconfiguration; shm.addr is the mapped zone base.
        // slot_off = w * slot_sz with w < n_active ≤ n_reserved = zone_data_bytes / slot_sz,
        // so both ring header accesses are within the mapped zone.
        let ret = unsafe {
            let zone = &*shm_zone;
            let offset = data_offset();
            let zone_data_bytes = zone.shm.size.saturating_sub(offset);
            let Some(zid) = zone.data.cast::<ZoneInitData>().as_ref() else {
                return Status::NGX_OK.into();
            };
            let cap = zid.ring_cap;
            let cycle = zid.cycle_addr as *const ngx_cycle_t;
            let slot_sz = logs_slot_size(cap);
            if slot_sz == 0 || zone_data_bytes == 0 {
                return Status::NGX_OK.into();
            }
            let n_reserved = zone_data_bytes / slot_sz;
            let n_active = wp_from_cycle(cycle).unwrap_or(n_reserved).min(n_reserved).max(1);
            let base: *mut u8 = zone.shm.addr.cast::<u8>().add(offset);
            for w in 0..n_active {
                let slot_off = w * slot_sz;
                (*base.add(slot_off).cast::<LogsWorkerRingHeader>())
                    .cap
                    .store(cap as u64, Ordering::Relaxed);
                (*base.add(slot_off + ring_size_bytes(cap)).cast::<LogsWorkerRingHeader>())
                    .cap
                    .store(cap as u64, Ordering::Relaxed);
            }
            Status::NGX_OK.into()
        };
        return ret;
    }

    // SAFETY: nginx invokes this callback with a valid, non-null
    // `ngx_shm_zone_t` (fn contract); the reference does not outlive the call.
    let zone = unsafe { &*shm_zone };
    let offset = data_offset();
    let zone_data_bytes = zone.shm.size.saturating_sub(offset);
    if zone_data_bytes == 0 {
        return Status::NGX_OK.into();
    }

    // SAFETY: `zone_data_bytes > 0` implies `zone.shm.size > offset`, so
    // `addr + offset` is within the mapped zone (past the slab-pool header).
    let base: *mut u8 = unsafe { zone.shm.addr.cast::<u8>().add(offset) };

    // recover cap and cycle from ZoneInitData stored in zone->data.
    // `register_logs_zone` now stores `*mut ZoneInitData` instead of a tagged cap.
    // SAFETY: zone->data was written by `register_logs_zone` to point at a
    // `ZoneInitData` in amcf (nginx conf pool, outlives this callback); or null
    // for a legacy caller — handled by the `else` branch.
    let Some(zid) = (unsafe { zone.data.cast::<ZoneInitData>().as_ref() }) else {
        return Status::NGX_OK.into();
    };
    let cap = zid.ring_cap;
    let cycle = zid.cycle_addr as *const ngx_cycle_t;

    let slot_sz = logs_slot_size(cap);
    if slot_sz == 0 {
        return Status::NGX_OK.into();
    }

    let n_reserved = zone_data_bytes / slot_sz;
    // only initialise ACTIVE worker slots — reserved-but-inactive slots
    // are OS-zeroed anonymous pages and must not be touched here.
    // `wp_from_cycle` returns the final value after `ngx_core_module_init_conf`.
    // SAFETY: cycle is non-null (set from cf->cycle at postconfiguration) and
    // valid for the duration of this ngx_init_cycle call.
    let n_active = unsafe { wp_from_cycle(cycle) }.unwrap_or(n_reserved).min(n_reserved).max(1);

    // Zero the ACTIVE slot area only.
    // SAFETY: `base` is past the slab-pool header; `n_active * slot_sz ≤ zone_data_bytes`.
    unsafe { ptr::write_bytes(base, 0, n_active * slot_sz) };

    // Stamp `cap` into the ring headers of active slots only.
    for w in 0..n_active {
        let slot_off = w * slot_sz;
        // Access ring header.
        // SAFETY: `slot_off = w * slot_sz` with `w < n_active ≤ n_reserved`,
        // so `base + slot_off` is within the just-zeroed active slot area.
        let access_hdr = unsafe { base.add(slot_off).cast::<LogsWorkerRingHeader>() };
        // SAFETY: valid just-zeroed header; exclusive init-time write.
        unsafe { (*access_hdr).cap.store(cap as u64, Ordering::Relaxed) };
        // Error ring header (immediately follows the access ring payload).
        // SAFETY: the error header sits one `ring_size_bytes(cap)` past the
        // access header, still within the same in-bounds slot.
        let error_hdr =
            unsafe { base.add(slot_off + ring_size_bytes(cap)).cast::<LogsWorkerRingHeader>() };
        // SAFETY: as above — valid just-zeroed header, exclusive init-time write.
        unsafe { (*error_hdr).cap.store(cap as u64, Ordering::Relaxed) };
    }

    Status::NGX_OK.into()
}

// ── Spans shm zone ───────────────────────────────────────────────
//
// The spans shm zone holds one `LogsWorkerRing` per worker (one ring per slot,
// unlike the logs zone which holds two rings + a coalescer table per slot).
// The ring is the same `LogsWorkerRingHeader` + payload layout reused from logs.
//
// Layout per worker slot:
//   slot_i = base + i × spans_slot_size(cap)
//   spans_ring_header  = slot_i + 0
//   spans_ring_payload = slot_i + RING_HEADER_SIZE
//
// Memory per worker = `cap + RING_HEADER_SIZE` bytes.
// Total spans shm = `slab_pool_header + n_workers × spans_slot_size(cap)`.

/// Default spans ring capacity per worker in bytes.
///
/// 256 KiB per worker — spans are small records (~100 bytes), so this handles
/// ~2 500 queued spans per worker before dropping.  Raise via a future
/// `otel_trace_ring_size` directive if needed.
pub const DEFAULT_SPAN_RING_CAP: usize = 256 * 1024;

/// Total bytes required for one spans slot with ring capacity `cap`.
#[inline]
pub fn spans_slot_size(cap: usize) -> usize {
    ring_size_bytes(cap)
}

/// Minimum spans zone size for `n_workers` worker processes with ring `cap`.
#[inline]
pub fn spans_zone_size_for(n_workers: usize, cap: usize) -> usize {
    data_offset() + n_workers * spans_slot_size(cap)
}

/// Infer worker count from the spans zone metadata.
///
/// `cap` must match the value used at zone registration.
#[inline]
pub fn spans_n_workers_from_zone(zone_data_bytes: usize, cap: usize) -> usize {
    let slot = spans_slot_size(cap);
    (zone_data_bytes.checked_div(slot).unwrap_or(0)).max(1)
}

/// Obtain a [`LogsWorkerRing`] view of the spans ring for `worker_id`.
///
/// Reuses the same ring type as the logs zone (same `LogsWorkerRingHeader`
/// layout and atomic SPSC semantics).
///
/// # Safety
/// - `base_addr` must point past the slab-pool header (`shm.addr + data_offset()`).
/// - `worker_id < n_workers` and `cap` must match the zone registration.
/// - The returned ring must not outlive the zone mapping.
#[inline]
pub unsafe fn spans_ring(base_addr: *mut u8, worker_id: usize, cap: usize) -> LogsWorkerRing {
    let slot_off = worker_id * spans_slot_size(cap);
    // SAFETY: per the fn contract `base_addr` is `shm.addr + data_offset()`,
    // `worker_id < n_workers`, and `cap` matches registration, so `slot_off` is
    // within the zone.  The spans ring header begins at slot offset 0.
    unsafe { LogsWorkerRing::from_shm_ptr(base_addr.add(slot_off)) }
}

/// NGINX zone-init callback for the spans shm zone.
///
/// Called by nginx when the spans zone is first mapped (fresh start).  On
/// SIGHUP (old_data non-null) the pages are re-used as-is — ring offsets survive.
///
/// Stores `cap` (recovered from `zone.data`) into every ring header.
///
/// # Safety
/// Follows the same contract as `logs_shm_zone_init` (called by nginx with a
/// valid `ngx_shm_zone_t*`; single exclusive caller at zone-init time before
/// any worker forks).
pub unsafe extern "C" fn spans_shm_zone_init(
    shm_zone: *mut ngx_shm_zone_t,
    old_data: *mut core::ffi::c_void,
) -> ngx_int_t {
    if !old_data.is_null() {
        // SIGHUP: same physical pages re-mapped; ring offsets carry over.
        // H2F3: On scale-up reload, new worker slots are OS-zeroed (cap==0).
        // Stamp cap into ALL active-slot ring headers (idempotent for existing
        // slots; required for new slots added by the worker_processes increase).
        //
        // SAFETY: nginx guarantees shm_zone is a valid non-null pointer (fn contract).
        // zone.data was written by register_spans_zone to point at a ZoneInitData in
        // amcf (nginx conf pool, outlives reload); cycle is from cf->cycle at
        // postconfiguration; shm.addr is the mapped zone base.
        // slot_off = w * slot_sz with w < n_active ≤ zone_data_bytes / slot_sz.
        let ret = unsafe {
            let zone = &*shm_zone;
            let offset = data_offset();
            let zone_data_bytes = zone.shm.size.saturating_sub(offset);
            let Some(zid) = zone.data.cast::<ZoneInitData>().as_ref() else {
                return Status::NGX_OK.into();
            };
            let cap = zid.ring_cap;
            let cycle = zid.cycle_addr as *const ngx_cycle_t;
            let slot_sz = spans_slot_size(cap);
            if slot_sz == 0 || zone_data_bytes == 0 {
                return Status::NGX_OK.into();
            }
            let n_reserved = zone_data_bytes / slot_sz;
            let n_active = wp_from_cycle(cycle).unwrap_or(n_reserved).min(n_reserved).max(1);
            let base: *mut u8 = zone.shm.addr.cast::<u8>().add(offset);
            for w in 0..n_active {
                let slot_off = w * slot_sz;
                (*base.add(slot_off).cast::<LogsWorkerRingHeader>())
                    .cap
                    .store(cap as u64, Ordering::Relaxed);
            }
            Status::NGX_OK.into()
        };
        return ret;
    }

    // SAFETY: nginx calls this with a valid non-null `ngx_shm_zone_t`.
    let zone = unsafe { &*shm_zone };
    let offset = data_offset();
    let zone_data_bytes = zone.shm.size.saturating_sub(offset);
    if zone_data_bytes == 0 {
        return Status::NGX_OK.into();
    }

    // SAFETY: `zone_data_bytes > 0` implies the mapped region covers `offset`
    // bytes, so `addr + offset` is within the zone.
    let base: *mut u8 = unsafe { zone.shm.addr.cast::<u8>().add(offset) };

    // recover cap and cycle from ZoneInitData stored in zone->data.
    // SAFETY: zone->data was written by `register_spans_zone` to point at a
    // `ZoneInitData` in amcf (nginx conf pool, outlives this callback); or null
    // for a legacy caller — handled by the `else` branch.
    let Some(zid) = (unsafe { zone.data.cast::<ZoneInitData>().as_ref() }) else {
        return Status::NGX_OK.into();
    };
    let cap = zid.ring_cap;
    let cycle = zid.cycle_addr as *const ngx_cycle_t;

    let slot_sz = spans_slot_size(cap);
    if slot_sz == 0 {
        return Status::NGX_OK.into();
    }

    let n_reserved = zone_data_bytes / slot_sz;
    // only initialise ACTIVE worker slots — same rationale as logs_shm_zone_init.
    // SAFETY: cycle is non-null and valid (set from cf->cycle at postconfiguration).
    let n_active = unsafe { wp_from_cycle(cycle) }.unwrap_or(n_reserved).min(n_reserved).max(1);

    // Zero the ACTIVE slot area only.
    // SAFETY: `base` is past the slab-pool header; `n_active * slot_sz ≤ zone_data_bytes`.
    unsafe { ptr::write_bytes(base, 0, n_active * slot_sz) };

    // Stamp `cap` into ring headers of active slots only.
    for w in 0..n_active {
        let slot_off = w * slot_sz;
        // SAFETY: `slot_off = w * slot_sz` with `w < n_active ≤ n_reserved`,
        // so `base + slot_off` is within the just-zeroed active slot area.
        let hdr = unsafe { base.add(slot_off).cast::<LogsWorkerRingHeader>() };
        // SAFETY: valid just-zeroed header; exclusive init-time write.
        unsafe { (*hdr).cap.store(cap as u64, Ordering::Relaxed) };
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
            // SAFETY: `base` is sized via `zone_size_for(n_workers)` and `i <
            // n_workers`, so `worker_slots` yields an in-bounds slot pointer;
            // `init_at` zero-initialises it.
            unsafe { WorkerSlots::init_at(worker_slots(base, i)) };
        }

        // Use GET/2xx/HTTP1.1 base combo (decomposed: 3-arg only).
        let combo = combo_index(HttpMethod::Get, StatusClass::S2xx, ProtoVersion::Http11);

        // SAFETY: `base` is sized for `n_workers` slots and 0 < n_workers, so
        // the pointer is in-bounds and (after `init_at`) valid for this test.
        let slot0 = unsafe { &*worker_slots(base, 0) };
        for _ in 0..3 {
            slot0.request_duration_combos[combo].record(100);
        }

        // SAFETY: as for slot0 — 1 < n_workers, in-bounds, init'd slot.
        let slot1 = unsafe { &*worker_slots(base, 1) };
        for _ in 0..2 {
            slot1.request_duration_combos[combo].record(500);
        }

        let (_, _, sum0, count0) = slot0.request_duration_combos[combo].snapshot();
        assert_eq!(count0, 3, "worker 0 count");
        assert_eq!(sum0, 300, "worker 0 sum");

        let (_, _, sum1, count1) = slot1.request_duration_combos[combo].snapshot();
        assert_eq!(count1, 2, "worker 1 count");
        assert_eq!(sum1, 1000, "worker 1 sum");

        let total_count = count0 + count1;
        let total_sum = sum0 + sum1;
        assert_eq!(total_count, 5);
        assert_eq!(total_sum, 1300);

        // Confirm no cross-write between slots.
        // Seconds spec mapping (scale 3, upper-inclusive): the INTERNAL bucket is
        // `ceil(log2(value_us/1e6)·8) − 1 − EXP_HISTOGRAM_BUCKET_OFFSET`.
        //   100µs = 1e-4 s: ceil(log2(1e-4)·8)−1 = −107 → internal −107−(−160) = 53
        //   500µs = 5e-4 s: ceil(log2(5e-4)·8)−1 = −88  → internal −88 −(−160) = 72
        let (buckets0, _, _, _) = slot0.request_duration_combos[combo].snapshot();
        let (buckets1, _, _, _) = slot1.request_duration_combos[combo].snapshot();

        // Expected bucket indices — hand-computed above, NOT recomputed via the same
        // formula under test (a self-referential helper never validates).
        const BUCKET_100: usize = 53;
        const BUCKET_500: usize = 72;
        const _: () = assert!(BUCKET_100 != BUCKET_500, "100 and 500 must be in distinct buckets");

        assert_eq!(buckets0[BUCKET_100], 3, "worker 0 bucket for 100");
        assert_eq!(buckets1[BUCKET_500], 2, "worker 1 bucket for 500");
        assert_eq!(buckets0[BUCKET_500], 0, "slot 0 not written by worker 1");
        assert_eq!(buckets1[BUCKET_100], 0, "slot 1 not written by worker 0");
    }

    /// Base combo index mapping: all N_COMBOS (160) combinations must be distinct.
    /// Decomposed: combo_index is 3-arg (method × sc × proto only).
    #[test]
    fn combo_index_all_unique() {
        let mut seen = std::vec![false; N_COMBOS];
        for m in 0..N_HTTP_METHODS {
            for sc in 0..N_STATUS_CLASSES {
                for p in 0..N_PROTO_VERSIONS {
                    let method = [
                        HttpMethod::Get,
                        HttpMethod::Head,
                        HttpMethod::Post,
                        HttpMethod::Put,
                        HttpMethod::Delete,
                        HttpMethod::Patch,
                        HttpMethod::Options,
                        HttpMethod::Other,
                    ][m];
                    let status = [
                        StatusClass::S1xx,
                        StatusClass::S2xx,
                        StatusClass::S3xx,
                        StatusClass::S4xx,
                        StatusClass::S5xx,
                    ][sc];
                    let proto = [
                        ProtoVersion::Http10,
                        ProtoVersion::Http11,
                        ProtoVersion::Http2,
                        ProtoVersion::Http3,
                    ][p];
                    let idx = combo_index(method, status, proto);
                    assert!(!seen[idx], "duplicate combo index {}", idx);
                    seen[idx] = true;
                }
            }
        }
        assert!(seen.iter().all(|&v| v), "all N_COMBOS combinations must be reachable");
    }

    /// Decomposed: route and upstream use separate independent tables.
    /// A request updates base + route-table + upstream-table independently.
    #[test]
    fn decomposed_route_upstream_tables() {
        // Route slot 5 and upstream slot 3 are independent of each other and of the base.
        let base = combo_index(HttpMethod::Get, StatusClass::S2xx, ProtoVersion::Http11);
        let route_idx = 5usize;
        let upstream_idx = 3usize;

        // All three indices are within their respective table bounds.
        assert!(base < N_COMBOS, "base index in range");
        assert!(route_idx < N_ROUTE_SLOTS, "route index in range");
        assert!(upstream_idx < N_UPSTREAM_SLOTS, "upstream index in range");

        // The "other" slot for each table.
        let route_other = ROUTE_CAP;
        let upstream_other = UPSTREAM_IDX_OTHER; // = UPSTREAM_CAP
        assert!(route_other < N_ROUTE_SLOTS, "route other in range");
        assert!(upstream_other < N_UPSTREAM_SLOTS, "upstream other in range");

        // Slot 0 and slot 1 in the route table produce different route indices.
        assert_ne!(0, 1); // trivially, different routes go to different slots
        assert_ne!(route_other, upstream_other); // different table sizes → different "other" idxs
    }

    /// The compile-time budget assert passes at restored default caps (64/32).
    #[test]
    fn worker_slots_within_memory_budget() {
        // Three separate tables, scale 3, N_EXP_BUCKETS=192.
        let total_slots = N_COMBOS + N_ROUTE_SLOTS + N_UPSTREAM_SLOTS;
        let slot_size = core::mem::size_of::<ExpHistogramSlot>();
        let total_bytes = total_slots * slot_size;
        assert!(
            total_bytes <= SLOT_BUDGET,
            "histogram arrays ({} bytes, {} slots × {} bytes) exceeds SLOT_BUDGET ({} bytes)",
            total_bytes,
            total_slots,
            slot_size,
            SLOT_BUDGET,
        );
        // 195 AtomicU64 = 1560 bytes per slot.
        assert_eq!(slot_size, (N_EXP_BUCKETS + 3) * 8, "(N_EXP_BUCKETS+3)×8 bytes per slot");
    }

    #[test]
    fn zone_size_alignment() {
        let slab = data_offset();
        assert!(slab > 0, "slab pool offset must be positive");
        assert_eq!(zone_size_for(4), slab + 4 * mem::size_of::<WorkerSlots>());
        assert!(zone_size_for(1) >= slab + mem::size_of::<WorkerSlots>());
    }

    /// `n_workers_from_zone_size` is the exact inverse of `zone_size_for`.
    ///
    /// This test FAILS on the pre-fix code (before `n_workers_from_zone_size`
    /// existed) because that function did not exist.  After the fix it must
    /// pass to confirm the zone-capacity round-trip is correct, which is the
    /// prerequisite for the `shm_n_workers()` bounds guard.
    #[test]
    fn a1_zone_capacity_round_trip() {
        for n in [1usize, 2, 4, 8, 16, 32] {
            let size = zone_size_for(n);
            let recovered = n_workers_from_zone_size(size);
            assert_eq!(
                recovered, n,
                "n_workers_from_zone_size(zone_size_for({n})) should equal {n}, got {recovered}"
            );
        }
        // Under-sized zone (smaller than one full slot) → 0 capacity.
        assert_eq!(
            n_workers_from_zone_size(data_offset()),
            0,
            "zone with only slab header → 0 workers capacity"
        );
        // Zone sized for 1 but queried as if it were 4 → capacity = 1.
        let size_1 = zone_size_for(1);
        let cap = n_workers_from_zone_size(size_1);
        assert_eq!(cap, 1, "zone sized for 1 worker → capacity 1");

        // Directive-ordering scenario: zone sized for 1 worker, actual
        // worker_id=3.  The bounds guard `worker_id >= n_workers_from_zone_size(size)`
        // must fire (3 >= 1).  Before the fix, no such check existed.
        let worker_id: usize = 3;
        assert!(
            worker_id >= cap,
            "worker_id {worker_id} must be >= zone capacity {cap} \
             (bounds guard must fire for the over-count directive-ordering case)"
        );
    }

    #[test]
    fn histogram_overflow_bucket() {
        let mut buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        // SAFETY: `buf` is a freshly-allocated, zero-initialised `Vec<u8>` sized
        // to exactly hold a `WorkerSlots`; the global allocator over-aligns it,
        // and zero is the valid initial state for its atomic fields. The shared
        // reference lives only for the test.
        let slot = unsafe { &*buf.as_mut_ptr().cast::<WorkerSlots>() };

        // Record a very large value in the GET/2xx/HTTP1.1 base combo (µs).
        let combo = combo_index(HttpMethod::Get, StatusClass::S2xx, ProtoVersion::Http11);
        // 99_999_999_999µs ≈ 27.8h ≫ 16.7s → above the last seconds bucket's upper
        // bound (16_000_000µs) → clamped to the overflow bucket 191.
        let very_large = 99_999_999_999u64;
        slot.request_duration_combos[combo].record(very_large);

        let (buckets, zero_count, sum, count) = slot.request_duration_combos[combo].snapshot();
        assert_eq!(count, 1);
        assert_eq!(sum, very_large);
        assert_eq!(zero_count, 0);
        assert_eq!(buckets[N_EXP_BUCKETS - 1], 1, "large value lands in overflow bucket");
        for b in &buckets[..N_EXP_BUCKETS - 1] {
            assert_eq!(*b, 0, "non-overflow bucket must be zero");
        }
    }

    /// Low-end (small-duration) **internal** bucket placement, seconds mapping.
    ///
    /// Internal bucket `i` = `ceil(log2(value_us/1e6)·8) − 1 −
    /// EXP_HISTOGRAM_BUCKET_OFFSET` (= spec seconds index minus the −160 offset).
    /// Hand-computed expectations spanning octave-aligned values and a
    /// mid-octave value whose **upper-inclusive `ceil`** placement differs from
    /// the old lower-inclusive `floor` scheme (90µs: floor → 51, ceil → 52).
    ///
    /// All expected indices are hard-coded literals from independent calculation
    /// (Python `ceil(log2(v/1e6)*8)-1 + 160`) — never recomputed from the
    /// implementation under test.
    #[test]
    fn exp_histogram_low_end_bucket_placement() {
        // (value_us, expected INTERNAL bucket = ceil(log2(value_us/1e6)*8)-1 + 160)
        //
        // Octave-aligned values (powers of two µs; offset −160 is a multiple of
        // 8 so these coincide with the old floor indices — regression guard):
        //   1  = 2^0 µs  → internal 0    (spec −160)
        //   2  = 2^1 µs  → internal 8    (spec −152)
        //   4  = 2^2 µs  → internal 16
        //   8  = 2^3 µs  → internal 24
        //   15           → internal 31
        //   16 = 2^4 µs  → internal 32
        //
        // Mid-octave (upper-inclusive ceil mapping):
        //   90  = 9e-5 s : ceil(log2(9e-5)·8)−1 = −108 → internal 52  (floor scheme: 51)
        //   100 = 1e-4 s : −107 → internal 53
        //   200 = 2e-4 s : −99  → internal 61
        //   400 = 4e-4 s : −91  → internal 69
        let cases = [
            // octave-aligned
            (1u64, 0usize),
            (2, 8),
            (4, 16),
            (8, 24),
            (15, 31),
            (16, 32),
            // mid-octave (upper-inclusive ceil; 90 differs from the old floor scheme)
            (90, 52),
            (100, 53),
            (200, 61),
            (400, 69),
        ];
        for (value, expected) in cases {
            let mut buf = std::vec![0u8; mem::size_of::<ExpHistogramSlot>()];
            // SAFETY: `buf` is a freshly-allocated, zero-initialised `Vec<u8>` sized
            // to exactly hold an `ExpHistogramSlot`; the global allocator over-aligns
            // it, and zero is the valid initial state for its atomic fields. The
            // shared reference lives only for the test.
            let slot = unsafe { &*buf.as_mut_ptr().cast::<ExpHistogramSlot>() };
            slot.record(value);
            let (buckets, zero, sum, count) = slot.snapshot();
            assert_eq!(count, 1, "value {value}: count");
            assert_eq!(sum, value, "value {value}: sum");
            assert_eq!(zero, 0, "value {value}: nonzero must not hit zero_count");
            assert_eq!(buckets[expected], 1, "value {value} must land in bucket {expected}");
            assert_eq!(buckets.iter().sum::<u64>(), 1, "value {value}: exactly one bucket set");
        }
    }

    /// **Exhaustive exactness proof for the seconds bucketing (Option A).**
    ///
    /// For every `value_us` in `[1, 2^14]` and a deterministic geometric sample
    /// up to `2^24` — explicitly including every integer-µs octave boundary
    /// (`15625`, `31250`, …, `1000000` = 1s, …, `16000000` = 16s) — the worker's
    /// emitted **spec** bucket index (`internal_idx + EXP_HISTOGRAM_BUCKET_OFFSET`)
    /// must equal the OTel upper-inclusive reference
    /// `ceil((value_us as f64 / 1e6).log2() * 8.0) as i64 − 1`, computed here in
    /// f64 (independent of the integer table under test).  Indices that would
    /// exceed the array clamp to the overflow bucket `N_EXP_BUCKETS − 1`.
    ///
    /// This is the proof that the integer boundary-table construction is
    /// spec-exact at ALL boundaries — the point a naïve `floor` scheme fails: it
    /// mis-buckets the 15625-µs boundary, the lowest integer-µs seconds-octave edge.
    #[test]
    fn exp_histogram_seconds_bucket_exact() {
        let offset = EXP_HISTOGRAM_BUCKET_OFFSET as i64;

        // f64 reference: the OTel upper-inclusive spec bucket index in seconds.
        let spec_ref = |value_us: u64| -> i64 {
            let v_s = value_us as f64 / 1_000_000.0;
            (v_s.log2() * 8.0).ceil() as i64 - 1
        };

        // Run one value through record() and return the spec index it landed in.
        let recorded_spec = |value_us: u64| -> i64 {
            let mut buf = std::vec![0u8; mem::size_of::<ExpHistogramSlot>()];
            // SAFETY: zero-init buffer sized to one ExpHistogramSlot; zero is the
            // valid initial state for its atomics; ref lives only for the call.
            let slot = unsafe { &*buf.as_mut_ptr().cast::<ExpHistogramSlot>() };
            slot.record(value_us);
            let (buckets, zero, _sum, count) = slot.snapshot();
            assert_eq!(count, 1, "value {value_us}: exactly one observation");
            assert_eq!(zero, 0, "value {value_us}: nonzero must not hit zero_count");
            let set: std::vec::Vec<usize> =
                buckets.iter().enumerate().filter(|(_, &c)| c == 1).map(|(i, _)| i).collect();
            assert_eq!(set.len(), 1, "value {value_us}: exactly one bucket set, got {set:?}");
            set[0] as i64 + offset
        };

        // Compare with clamping to the overflow bucket's spec index.
        let max_internal = (N_EXP_BUCKETS - 1) as i64;
        let check = |value_us: u64| {
            let want = spec_ref(value_us).clamp(offset, max_internal + offset);
            let got = recorded_spec(value_us);
            assert_eq!(
                got, want,
                "value_us {value_us}: emitted spec bucket {got} != reference {want}"
            );
        };

        // Full exhaustive sweep [1, 2^14].
        for value_us in 1u64..=(1 << 14) {
            check(value_us);
        }

        // Deterministic geometric sample to 2^24 (every ~2^0.5 step).
        let mut v = (1u64 << 14) + 1;
        while v <= (1 << 24) {
            check(v);
            v = v + (v >> 1) + 1; // ~1.5× growth, deterministic
        }

        // The integer-µs octave boundaries — the exact points a `floor` scheme
        // mis-buckets — must each land in the LOWER (upper-inclusive) bucket.
        for &boundary in &[
            15625u64, 31250, 62500, 125000, 250000, 500000, 1_000_000, 2_000_000, 4_000_000,
            8_000_000, 16_000_000,
        ] {
            check(boundary);
            // And one µs above each boundary lands one spec bucket higher — except
            // 16_000_000 = 16s, whose upper bucket is already the overflow bucket
            // (N_EXP_BUCKETS−1), so `boundary+1` clamps to the same bucket.
            if boundary < SECONDS_BUCKET_UPPER_US[N_EXP_BUCKETS - 1] {
                assert_eq!(
                    recorded_spec(boundary + 1),
                    recorded_spec(boundary) + 1,
                    "boundary {boundary}: value just above must be one spec bucket higher"
                );
            }
        }
    }

    /// value 0 increments `zero_count`, never a positive bucket.
    #[test]
    fn exp_histogram_zero_goes_to_zero_count() {
        let mut buf = std::vec![0u8; mem::size_of::<ExpHistogramSlot>()];
        // SAFETY: `buf` is a freshly-allocated, zero-initialised `Vec<u8>` sized
        // to exactly hold an `ExpHistogramSlot`; the global allocator over-aligns
        // it, and zero is the valid initial state for its atomic fields. The
        // shared reference lives only for the test.
        let slot = unsafe { &*buf.as_mut_ptr().cast::<ExpHistogramSlot>() };
        slot.record(0);
        let (buckets, zero, sum, count) = slot.snapshot();
        assert_eq!(zero, 1);
        assert_eq!(count, 1);
        assert_eq!(sum, 0);
        assert_eq!(buckets.iter().sum::<u64>(), 0);
    }

    /// Build a minimal sampled request for the reservoir tests.  Only the fields
    /// the slimmed exemplar entry consumes (value/ts/combo/trace) carry meaning;
    /// the rest are the canonical tail fields, irrelevant to the reservoir.
    #[cfg(test)]
    fn sampled<'a>(
        combo_idx: u32,
        duration_us: u64,
        ts_unix_nano: u64,
        trace: Option<([u8; 16], [u8; 8])>,
    ) -> SampledRequest<'a> {
        SampledRequest {
            ts_unix_nano,
            trace,
            url_path: b"",
            user_agent: b"",
            duration_us,
            combo_idx,
            method: b"GET",
            status: 200,
            request_length: 0,
            response_bytes: 0,
            client_addr: b"127.0.0.1",
        }
    }

    /// The slimmed exemplar entry is 48 bytes (canonical fields only — no
    /// url.path / user_agent buffers), and the per-combo reservoir array is the
    /// only exemplar storage in `WorkerSlots`.
    #[test]
    fn exemplar_entry_is_slim() {
        assert_eq!(
            core::mem::size_of::<ExemplarEntry>(),
            48,
            "ExemplarEntry must be 48 bytes (5×u64 + u32 + u8 + 3 pad)"
        );
        // Per-combo reservoir array sized by EXEMPLAR_RESERVOIR_SIZE × N_COMBOS.
        assert_eq!(EXEMPLAR_RESERVOIR_SIZE, 2);
        let one = core::mem::size_of::<ExemplarReservoir>();
        // seen(u64) + size × entry(48) = 8 + 2×48 = 104.
        assert_eq!(one, 8 + EXEMPLAR_RESERVOIR_SIZE * 48, "reservoir = seen + entries");
        assert_eq!(core::mem::size_of::<[ExemplarReservoir; N_COMBOS]>(), one * N_COMBOS);
    }

    /// A reservoir of size 2 fed N > size sampled candidates retains at most
    /// `size` exemplars (uniform fixed-size reservoir, NOT N).
    #[test]
    fn exemplar_reservoir_bounded() {
        let mut buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        // SAFETY: zero-init buffer sized to a WorkerSlots; zero is the valid
        // initial state for its atomics; reference lives only for the test.
        let slot = unsafe { &*buf.as_mut_ptr().cast::<WorkerSlots>() };
        let reservoir = &slot.exemplar_reservoirs[5];

        let tid = [
            0x4bu8, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
            0x47, 0x36,
        ];
        let sid = [0x00u8, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7];

        for i in 0..50u64 {
            reservoir.write(&sampled(5, 100 + i, 1_000 + i, Some((tid, sid))));
        }

        assert_eq!(reservoir.seen.load(Ordering::Acquire), 50, "all candidates seen");
        let snap = reservoir.snapshot();
        assert_eq!(
            snap.len(),
            EXEMPLAR_RESERVOIR_SIZE,
            "snapshot returns at most reservoir size, NOT the flood of 50"
        );
        for e in &snap {
            assert_eq!(e.combo_idx, 5);
            assert!(e.has_trace);
        }
    }

    /// The reservoir resets every collection cycle: after `reset()` an idle
    /// reservoir's next snapshot is empty (occupancy is count-based, not the old
    /// `combo_idx == 0` sentinel).
    #[test]
    fn exemplar_reservoir_resets_after_snapshot() {
        let mut buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        // SAFETY: as above.
        let slot = unsafe { &*buf.as_mut_ptr().cast::<WorkerSlots>() };
        let reservoir = &slot.exemplar_reservoirs[0]; // combo 0 is a VALID combo now

        for i in 0..10u64 {
            reservoir.write(&sampled(0, 200 + i, 5_000 + i, None));
        }
        let snap = reservoir.snapshot();
        assert_eq!(snap.len(), EXEMPLAR_RESERVOIR_SIZE, "filled before reset");
        // Combo 0 with a real value must be reported (no false sentinel skip).
        assert!(snap.iter().any(|e| e.combo_idx == 0 && e.value_us >= 200));

        // Exporter resets the sampling state after the snapshot.
        reservoir.reset();
        let snap_after = reservoir.snapshot();
        assert_eq!(snap_after.len(), 0, "idle reservoir reports 0 after reset");
    }

    /// Per-data-point isolation: an exemplar written into combo A's reservoir
    /// never appears under combo B.
    #[test]
    fn exemplar_reservoirs_are_per_data_point() {
        let mut buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        // SAFETY: as above.
        let slot = unsafe { &*buf.as_mut_ptr().cast::<WorkerSlots>() };

        slot.exemplar_reservoirs[7].write(&sampled(7, 700, 7_000, None));
        // Combo 8 untouched.
        let a = slot.exemplar_reservoirs[7].snapshot();
        let b = slot.exemplar_reservoirs[8].snapshot();
        assert_eq!(a.len(), 1, "combo 7 reservoir has its one exemplar");
        assert_eq!(a[0].combo_idx, 7);
        assert_eq!(a[0].value_us, 700);
        assert_eq!(b.len(), 0, "combo 8 reservoir is empty — no cross-combo bleed");
    }

    /// Uniform sampling sanity: the `SimpleFixedSizeExemplarReservoir` algorithm
    /// (1) fills both slots during the fill phase, (2) lets *every* measurement
    /// be a replacement candidate (its eviction probability is 1/(n+1), so
    /// replacements legitimately thin out as n grows — that is the uniform
    /// property, not a defect), and (3) directs evictions across BOTH slots over
    /// many cycles rather than collapsing onto one.
    /// <https://opentelemetry.io/docs/specs/otel/metrics/sdk/#exemplar-defaults>
    #[test]
    fn exemplar_reservoir_uniform_distribution() {
        let mut buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        // SAFETY: as above.
        let slot = unsafe { &*buf.as_mut_ptr().cast::<WorkerSlots>() };
        let reservoir = &slot.exemplar_reservoirs[3];

        // (1) Fill phase: the first `size` writes land in slots 0..size in order.
        reservoir.write(&sampled(3, 10, 1, None)); // → slot 0
        reservoir.write(&sampled(3, 20, 1, None)); // → slot 1
        assert_eq!(reservoir.entries[0].value_us.load(Ordering::Acquire), 10);
        assert_eq!(reservoir.entries[1].value_us.load(Ordering::Acquire), 20);

        // (3) Across many short cycles (each ~16 candidates, reset between),
        // post-fill evictions must reach BOTH slots — a constant/mod-0 index
        // would freeze one slot forever.
        let mut slot0_evictions = 0u64;
        let mut slot1_evictions = 0u64;
        for cycle in 0..200u64 {
            reservoir.reset();
            let base = 1_000 + cycle * 100;
            let before0 = u64::MAX; // force first-write detection per cycle
            let mut prev0 = before0;
            let mut prev1 = u64::MAX;
            for j in 0..16u64 {
                reservoir.write(&sampled(3, base + j, 1, None));
                let v0 = reservoir.entries[0].value_us.load(Ordering::Acquire);
                let v1 = reservoir.entries[1].value_us.load(Ordering::Acquire);
                // Count post-fill replacements (j >= size means an eviction roll).
                if j >= EXEMPLAR_RESERVOIR_SIZE as u64 {
                    if v0 != prev0 {
                        slot0_evictions += 1;
                    }
                    if v1 != prev1 {
                        slot1_evictions += 1;
                    }
                }
                prev0 = v0;
                prev1 = v1;
            }
        }
        assert!(
            slot0_evictions > 0 && slot1_evictions > 0,
            "uniform eviction must reach both slots over many cycles \
             (slot0={slot0_evictions}, slot1={slot1_evictions})"
        );
    }

    /// Guard: verify that the histogram combo set remains
    /// `method × status_class × protocol × route × upstream` and that url.path,
    /// user_agent, and client.address appear ONLY on tail/exemplar records —
    /// NOT as metric dimensions.
    ///
    /// This test asserts structural invariants at the TYPE level.
    /// Sub-ms values (90µs, 150µs, 200µs) must land in distinct buckets.
    /// This directly tests the "scale 3 resolves the ~90–200µs regime" claim.
    /// Rejects the prior scale-0+ms design where all three would be zero_count.
    #[test]
    fn sub_ms_values_land_in_distinct_buckets() {
        let mut buf = std::vec![0u8; core::mem::size_of::<ExpHistogramSlot>()];
        // SAFETY: `buf` is a freshly-allocated, zero-initialised `Vec<u8>` sized
        // to exactly hold an `ExpHistogramSlot`; the global allocator over-aligns
        // it, and zero is the valid initial state for its atomic fields. The
        // shared reference lives only for the test.
        let slot = unsafe { &*buf.as_mut_ptr().cast::<ExpHistogramSlot>() };

        slot.record(90); // 90 µs
        slot.record(150); // 150 µs
        slot.record(200); // 200 µs

        let (buckets, zero_count, _sum, count) = slot.snapshot();
        assert_eq!(count, 3, "three observations");
        assert_eq!(zero_count, 0, "none are zero");

        // Find the non-zero buckets.
        let nonempty: std::vec::Vec<usize> =
            buckets.iter().enumerate().filter(|(_, &c)| c > 0).map(|(i, _)| i).collect();

        assert_eq!(
            nonempty.len(),
            3,
            "90µs, 150µs, 200µs must each land in a distinct bucket (scale 3)"
        );

        // Spot-check expected INTERNAL indices (seconds mapping, upper-inclusive:
        // ceil(log2(value_us/1e6)·8) − 1 + 160):
        // 90µs  = 9e-5 s → internal 52
        // 150µs = 1.5e-4 s → internal 58
        // 200µs = 2e-4 s → internal 61
        assert_eq!(buckets[52], 1, "90µs → internal bucket 52");
        assert_eq!(buckets[58], 1, "150µs → internal bucket 58");
        assert_eq!(buckets[61], 1, "200µs → internal bucket 61");
    }

    #[test]
    fn high_cardinality_only_on_tail_not_metric() {
        // 1. N_COMBOS is the base 160 (method × sc × proto) ONLY.
        //    Route and upstream are separate tables (decomposed) — NOT multiplied in.
        assert_eq!(
            N_COMBOS,
            N_HTTP_METHODS * N_STATUS_CLASSES * N_PROTO_VERSIONS,
            "N_COMBOS must be method × sc × proto (route/upstream are separate tables)"
        );

        // 2. url.path / user_agent caps are single-homed in `logs::access` and
        //    appear on the exception-tail LogRecord ONLY — never as a metric
        //    dimension, and (as of exemplar standardization) no longer in the
        //    exemplar entry either (the linked trace carries url.path).
        let _url_max: usize = crate::logs::access::MAX_URL_PATH;
        let _ua_max: usize = crate::logs::access::MAX_USER_AGENT;

        // 3. combo_index is 3-arg (no url/ua/route/upstream) — route and upstream
        //    use separate WorkerSlots fields (route_duration_combos / upstream_duration_combos).
        let _ = combo_index(HttpMethod::Get, StatusClass::S2xx, ProtoVersion::Http11);
    }

    /// Ring-size alignment regression test: enforce, don't comment.
    ///
    /// Before this fix, `otel_log_ring_size 4097` was stored as-is.
    /// `ring_size_bytes(4097) = 32 + 4097 = 4129`; 4129 % 8 = 1 → the error
    /// ring header landed at an unaligned address (UB / SIGBUS on aarch64).
    /// The fix rounds cap up to the next multiple of 8 at config-parse time.
    #[test]
    fn a2_ring_cap_alignment() {
        use crate::logs::coalesce::coalesce_table_bytes;
        use crate::logs::ring::{ring_size_bytes, RING_HEADER_SIZE};

        // ── Demonstrate the pre-fix bug ───────────────────────────────────────
        let cap_raw = 4097usize;
        let rbs_raw = ring_size_bytes(cap_raw); // 32 + 4097 = 4129
        assert_eq!(rbs_raw, 4129);
        assert_ne!(
            rbs_raw % 8,
            0,
            "without rounding: error-ring header at offset rbs_raw is NOT 8-aligned (pre-fix bug)"
        );

        // ── After the fix: round up to next multiple of 8 ────────────────────
        let cap = cap_raw.next_multiple_of(8); // 4104
        assert_eq!(cap, 4104);

        let rbs = ring_size_bytes(cap); // 32 + 4104 = 4136
        assert_eq!(rbs, 4136);
        assert_eq!(rbs % 8, 0, "ring_size_bytes(rounded cap) must be 8-aligned");

        // Access-ring header: at slot_base + 0 — aligned by mmap (page-aligned base)
        // Error-ring header:  at slot_base + rbs — aligned iff rbs % 8 == 0
        assert_eq!(rbs % 8, 0, "error-ring header offset is 8-aligned");

        // Coalescer table:    at slot_base + 2*rbs — aligned iff rbs % 8 == 0
        assert_eq!((2 * rbs) % 8, 0, "coalescer table offset is 8-aligned");

        // Slot stride must also be 8-aligned for workers i > 0.
        let slot = logs_slot_size(cap); // 2*rbs + 6144
        assert_eq!(slot % 8, 0, "logs_slot_size must be 8-aligned");

        // ── Structural invariants (pinned by the const-asserts in shm.rs) ─────
        assert_eq!(RING_HEADER_SIZE % 8, 0, "RING_HEADER_SIZE must be a multiple of 8");
        assert_eq!(coalesce_table_bytes() % 8, 0, "coalesce_table_bytes must be a multiple of 8");

        // ── Powers-of-two defaults are fine either way ────────────────────────
        for &default_cap in &[512 * 1024usize, 256 * 1024usize, 4096usize] {
            assert_eq!(default_cap % 8, 0, "default cap {} is already aligned", default_cap);
        }
    }

    // ── F1: reload must zero route/upstream histograms ───────────────────────

    /// F1 regression: `zero_route_upstream_histograms` must zero ONLY
    /// `route_duration_combos` and `upstream_duration_combos`, leaving all other
    /// `WorkerSlots` fields untouched.
    ///
    /// Pre-fix: `otel_shm_zone_init` returned `NGX_OK` immediately on reload
    /// without zeroing any fields.  After a reload the route/upstream tables are
    /// rebuilt (new clcf_ptr / shm_zone_ptr values; any location add/remove/reorder
    /// shifts the slot index).  Counts recorded pre-reload under route X ended up
    /// attributed to whichever route now owned that index — silent misattribution.
    ///
    /// Post-fix: `zero_route_upstream_histograms` is called on reload for each
    /// active WorkerSlot.  This test verifies:
    /// 1. route_duration_combos and upstream_duration_combos are zeroed (no
    ///    misattribution from old indices).
    /// 2. request_duration_combos is NOT zeroed (stable method×status×protocol
    ///    index; clearing it would lose correct data).
    ///
    /// Fail-before proof: without calling `zero_route_upstream_histograms`, the
    /// route/upstream counts remain non-zero — the `assert_eq!(..., 0)` assertions
    /// below would fail.
    #[test]
    fn f1_zero_route_upstream_histograms_on_reload() {
        // Allocate a zero-initialised buffer sized for one WorkerSlots.
        let mut buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        // SAFETY: `buf` is a freshly-allocated, zero-initialised `Vec<u8>` sized to
        // exactly hold a `WorkerSlots`.  The global allocator over-aligns for the
        // element type, and zero is the valid initial state for all atomic fields.
        let slot = unsafe { &*buf.as_mut_ptr().cast::<WorkerSlots>() };

        // Simulate pre-reload state: record traffic into route and upstream slots.
        slot.route_duration_combos[0].record(1_000); // route index 0, pre-reload
        slot.upstream_duration_combos[0].record(2_000); // upstream index 0, pre-reload
        slot.request_duration_combos[0].record(3_000); // stable, must survive reload

        let (_, _, _, pre_route) = slot.route_duration_combos[0].snapshot();
        let (_, _, _, pre_up) = slot.upstream_duration_combos[0].snapshot();
        let (_, _, _, pre_combo) = slot.request_duration_combos[0].snapshot();
        assert!(pre_route > 0, "precondition: route count must be non-zero before reload");
        assert!(pre_up > 0, "precondition: upstream count must be non-zero before reload");
        assert!(pre_combo > 0, "precondition: combo count must be non-zero before reload");

        // Simulate reload: call the helper that otel_shm_zone_init invokes.
        // SAFETY: buf is aligned and sized for exactly one WorkerSlots; n_slots=1.
        unsafe { super::zero_route_upstream_histograms(buf.as_mut_ptr(), 1) };

        // Post-reload assertions.
        let (_, _, _, post_route) = slot.route_duration_combos[0].snapshot();
        assert_eq!(
            post_route, 0,
            "F1: route_duration_combos[0] must be zeroed on reload — \
             pre-fix code leaves old counts that get re-attributed to \
             whichever route now owns index 0 after the route_table rebuild"
        );

        let (_, _, _, post_up) = slot.upstream_duration_combos[0].snapshot();
        assert_eq!(
            post_up, 0,
            "F1: upstream_duration_combos[0] must be zeroed on reload — \
             pre-fix code leaves old counts that get re-attributed to \
             whichever upstream now owns index 0 after the upstream_table rebuild"
        );

        // request_duration_combos must NOT be zeroed — index is config-stable.
        let (_, _, _, post_combo) = slot.request_duration_combos[0].snapshot();
        assert_eq!(
            post_combo, pre_combo,
            "F1: zero_route_upstream_histograms must NOT touch request_duration_combos"
        );
    }

    // ── Scale-down reload must zero ALL reserved slots ──────────────────────

    /// Regression: on a scale-down SIGHUP reload (worker_processes 2→1),
    /// slot indices above the new active count must be zeroed.
    ///
    /// Pre-fix: `otel_shm_zone_init` called `zero_route_upstream_histograms`
    /// with `n_zero = n_active.min(n_reserved).max(1)` — only the NEW active
    /// worker count.  On scale-down the higher-numbered slots retained counts
    /// recorded under the OLD route-index assignment.  The exporter sums ALL
    /// reserved slots, so those stale counts were attributed to whichever route
    /// now owns that index — silent misattribution.
    ///
    /// Post-fix: `n_zero = n_reserved`, zeroing all reserved slots on reload.
    ///
    /// Fail-before proof: restore `n_active.min(n_reserved).max(1)` in
    /// `otel_shm_zone_init` — the assertion on slot 1 below will fail because
    /// its route/upstream counts are never zeroed.
    #[test]
    fn h3f4_scale_down_reload_zeros_all_reserved_slots() {
        use nginx_sys::ngx_shm_zone_t;

        // Two reserved slots (n_reserved=2).  cycle_addr=0 → wp_from_cycle
        // returns None → old code used unwrap_or(1) → n_active=1 → only slot 0
        // would be zeroed.  Slot 1 is the "stale higher-numbered slot" from a
        // scale-down scenario.
        let slot_bytes = mem::size_of::<WorkerSlots>();
        let n_slots = 2usize;
        let data_off = data_offset();
        let zone_sz = data_off + n_slots * slot_bytes;

        let mut zone_mem: std::vec::Vec<u8> = std::vec![0u8; zone_sz];
        let zone_addr = zone_mem.as_mut_ptr();

        // cycle_addr=0 → wp_from_cycle returns None → old code: n_active=1.
        let zid = ZoneInitData { ring_cap: 0, cycle_addr: 0 };

        // SAFETY: ngx_shm_zone_t is repr(C); zero is valid for all fields we don't set.
        let mut fake_zone: ngx_shm_zone_t = unsafe { core::mem::zeroed() };
        fake_zone.data = &raw const zid as *mut core::ffi::c_void;
        fake_zone.shm.addr = zone_addr.cast();
        fake_zone.shm.size = zone_sz;

        // ── (1) Populate stale counts in slot 1 (above the new active count) ─────
        // SAFETY: zone_mem is live; slot 1 starts at data_off + slot_bytes.
        let base = unsafe { zone_addr.add(data_off) };
        // SAFETY: zone_mem reserves n_reserved (≥2) full WorkerSlots starting at
        // data_off, so base + slot_bytes is in-bounds and properly aligned.
        let slot1 = unsafe { &*(base.add(slot_bytes) as *const WorkerSlots) };
        slot1.route_duration_combos[0].record(5_000); // stale pre-reload count
        slot1.upstream_duration_combos[0].record(7_000); // stale pre-reload count

        let (_, _, _, pre_route) = slot1.route_duration_combos[0].snapshot();
        let (_, _, _, pre_up) = slot1.upstream_duration_combos[0].snapshot();
        assert!(pre_route > 0, "precondition: slot 1 route count must be non-zero before reload");
        assert!(pre_up > 0, "precondition: slot 1 upstream count must be non-zero before reload");

        // ── (2) Simulate scale-down reload (old_data non-null) ───────────────────
        // SAFETY: fake_zone is a valid ngx_shm_zone_t with shm backing; old_data
        // non-null triggers the reload path.
        let ret = unsafe {
            otel_shm_zone_init(&raw mut fake_zone, core::ptr::dangling_mut::<core::ffi::c_void>())
        };
        assert_eq!(ret, ngx_int_t::from(Status::NGX_OK), "reload must return NGX_OK");

        // ── (3) Slot 1 must be zeroed by the scale-down fix ──────────────────────
        let (_, _, _, post_route) = slot1.route_duration_combos[0].snapshot();
        assert_eq!(
            post_route, 0,
            "slot 1 route_duration_combos[0] must be zeroed on scale-down reload — \
             pre-fix code only zeros n_active slots, leaving stale counts in slot 1 \
             that get misattributed to the new route owning index 0"
        );
        let (_, _, _, post_up) = slot1.upstream_duration_combos[0].snapshot();
        assert_eq!(
            post_up, 0,
            "slot 1 upstream_duration_combos[0] must be zeroed on scale-down reload — \
             pre-fix code only zeros n_active slots, leaving stale counts in slot 1"
        );
    }

    /// F3 regression: `snapshot()` must never observe `count > Σbuckets + zero_count`.
    ///
    /// Pre-fix: `record()` wrote `count` last with `Ordering::Relaxed` (no Release);
    /// `snapshot()` read `count` last with `Acquire` that had no paired Release.
    /// On weakly-ordered hardware (ARM64) a concurrent snapshot could see `count`
    /// incremented while the corresponding bucket write had not yet propagated →
    /// `count > Σbuckets` is observable.
    ///
    /// Post-fix: `record()` writes `count` last with `Release`; `snapshot()` reads
    /// `count` first with `Acquire`.  The Acquire-Release pair on `count` establishes
    /// a happens-before edge covering all prior bucket/sum writes from completed
    /// `record()` calls, so `Σbuckets + zero_count ≥ count` always holds.
    ///
    /// This test FAILS on pre-fix code on weakly-ordered hardware (ARM64) because the
    /// stress loop will observe violations.  On strongly-ordered hardware (x86) the
    /// violation may be rare but the fix is still correct (it eliminates a data race
    /// in the C++ / Rust memory model sense, independent of hardware).
    #[test]
    fn f3_snapshot_count_le_bucket_sum_concurrent() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        // Allocate a zero-initialised buffer for one ExpHistogramSlot.
        let mut buf = std::vec![0u8; mem::size_of::<ExpHistogramSlot>()];
        let buf_ptr: *mut u8 = buf.as_mut_ptr();

        // SAFETY: `buf_ptr` points to a freshly-zeroed heap Vec of exactly
        // `sizeof(ExpHistogramSlot)`.  Zero is the valid initial state for all
        // AtomicU64 fields.  The Vec is kept alive until after `writer.join()`.
        // Only two concurrent accessors exist: the writer thread and the reader
        // (this thread), each via `&ExpHistogramSlot` (mutations are through
        // atomics, which require only a shared reference).
        let slot_ref: &ExpHistogramSlot = unsafe { &*buf_ptr.cast::<ExpHistogramSlot>() };
        // SAFETY: `buf` is not moved/dropped until after `writer.join()` below.
        let slot_static: &'static ExpHistogramSlot = unsafe {
            core::mem::transmute::<&ExpHistogramSlot, &'static ExpHistogramSlot>(slot_ref)
        };

        let running = Arc::new(AtomicBool::new(true));
        let running_w = Arc::clone(&running);

        // Writer thread: continuous record() calls with varying values.
        let writer = std::thread::spawn(move || {
            let mut v: u64 = 1;
            while running_w.load(Ordering::Relaxed) {
                slot_static.record(v);
                // stay ≥ 1 so we exercise the bucket path, not just zero_count
                v = v.wrapping_add(1).max(1);
            }
        });

        // Reader: take snapshots and enforce the snapshot invariant.
        let mut violations: u64 = 0;
        for _ in 0..500_000 {
            let (buckets, zero_count, _, count) = slot_ref.snapshot();
            let bucket_sum: u64 = buckets.iter().sum::<u64>() + zero_count;
            if count > bucket_sum {
                violations += 1;
            }
        }

        running.store(false, Ordering::Relaxed);
        writer.join().unwrap();
        // `buf` is explicitly kept alive here; the above `join()` ensures the writer
        // has stopped before `buf` could be dropped.
        drop(buf);

        assert_eq!(violations, 0, "F3: count > Σbuckets observed {violations} times — pre-fix code (count written Relaxed, read last) is the root cause; post-fix Release+Acquire on count makes this invariant unconditional");
    }

    /// H2F2 regression: `zero_route_upstream_histograms` must use AtomicU64::store(Relaxed),
    /// not ptr::write_bytes, to avoid UB when old-generation workers concurrently fetch_add
    /// the same words during SIGHUP reload.
    ///
    /// This test spawns a thread doing fetch_add in a tight loop on one AtomicU64 inside
    /// route_duration_combos while the main thread calls zero_route_upstream_histograms.
    /// The point is that it compiles and runs without TSAN/sanitizer warnings — not that
    /// a particular value is observed after the race (the race outcome is intentionally
    /// "stale counts vanish with old workers", which is accepted).
    ///
    /// **TSAN-guard caveat:** This test is inert on non-sanitizer builds.
    /// `AtomicU64::store` makes no runtime assertion without `-Zsanitizer=thread`;
    /// the test will pass on macOS / release / debug builds whether the H2F2 fix
    /// is present or not.  A green macOS run is NOT race coverage.
    /// The real evidence lives in `tests/RESULTS-tsan-2026-06-11-h2fu.txt`
    /// (commit 841827c): the test passes under TSAN with 42 `__tsan_*` symbols
    /// loaded and zero ThreadSanitizer warnings in the full make-tsan-test run.
    ///
    /// Guarded by #[cfg(not(miri))] because Miri is single-threaded and would deadlock.
    #[test]
    #[cfg(not(miri))]
    fn f_shm_atomic_zero() {
        use core::sync::atomic::AtomicBool;
        use std::sync::Arc;

        // SAFETY: WorkerSlots contains only atomic types; all-zeros is a valid initial state.
        let mut buf: std::boxed::Box<WorkerSlots> =
            unsafe { std::boxed::Box::new_zeroed().assume_init() };
        let slot_ptr: *mut WorkerSlots = &raw mut *buf;
        // Pick the AtomicU64 at the start of route_duration_combos[0].buckets[0].
        // SAFETY: offset is within the live Box<WorkerSlots>; we keep `buf` alive.
        let atomic_ptr: *mut AtomicU64 = unsafe {
            (slot_ptr as *mut u8).add(core::mem::offset_of!(WorkerSlots, route_duration_combos))
                as *mut AtomicU64
        };
        // SAFETY: atomic_ptr points into a live Box<WorkerSlots>; we keep `buf` alive
        // for the duration of the test and join the writer thread before dropping.
        let atomic_ref: &'static AtomicU64 = unsafe { &*atomic_ptr };

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let writer = std::thread::spawn(move || {
            while running_clone.load(Ordering::Relaxed) {
                atomic_ref.fetch_add(1, Ordering::Relaxed);
            }
        });

        // Call zero_route_upstream_histograms concurrently with the writer thread.
        // SAFETY: buf is a valid single WorkerSlots object; n_slots=1.
        unsafe {
            zero_route_upstream_histograms(slot_ptr as *mut u8, 1);
        }

        running.store(false, Ordering::Relaxed);
        writer.join().unwrap();
        // Keep buf alive until after join so the writer's atomic_ref is valid.
        drop(buf);
        // If we reach here without TSAN/sanitizer complaints the test passes.
    }

    /// H2F3 regression: after a SIGHUP reload that increases worker_processes,
    /// new worker slots (which are OS-zeroed) must have cap stamped by the reload
    /// path of logs_shm_zone_init.
    ///
    /// Pre-fix: the reload path returned NGX_OK immediately — cap remained 0 for
    ///   new slots → every push from new workers returned false (dropped silently).
    /// Post-fix: reload path stamps cap for all active slots (idempotent for
    ///   existing slots, required for new slots).
    ///
    /// Fail-before proof: comment out the H2F3 reload block in logs_shm_zone_init
    /// and this test's assertion on step (4) will fail.
    #[test]
    fn b1_cap_survives_reload() {
        use crate::logs::ring::{ring_size_bytes, LogsWorkerRingHeader};
        use nginx_sys::ngx_shm_zone_t;

        const CAP: usize = 512;
        let slot_sz = logs_slot_size(CAP);
        let n_slots = 2usize;
        let data_off = data_offset();
        let zone_sz = data_off + n_slots * slot_sz;

        let mut zone_mem: std::vec::Vec<u8> = std::vec![0u8; zone_sz];
        let zone_addr = zone_mem.as_mut_ptr();

        // cycle_addr=0 → wp_from_cycle returns None → n_active = n_reserved (2).
        let zid = ZoneInitData { ring_cap: CAP, cycle_addr: 0 };

        // SAFETY: ngx_shm_zone_t is repr(C); zero is valid for all fields we don't set.
        let mut fake_zone: ngx_shm_zone_t = unsafe { core::mem::zeroed() };
        fake_zone.data = &raw const zid as *mut core::ffi::c_void;
        fake_zone.shm.addr = zone_addr.cast();
        fake_zone.shm.size = zone_sz;

        // ── (1) Fresh init ───────────────────────────────────────────────────────
        // SAFETY: fake_zone is a valid ngx_shm_zone_t with shm region backing it;
        // old_data=null triggers the fresh-init path.
        let ret = unsafe { logs_shm_zone_init(&raw mut fake_zone, core::ptr::null_mut()) };
        assert_eq!(ret, ngx_int_t::from(Status::NGX_OK), "fresh init must return NGX_OK");

        // SAFETY: data_off < zone_sz; zone_mem is live for the whole test.
        let base = unsafe { zone_addr.add(data_off) };
        for w in 0..n_slots {
            let off = w * slot_sz;
            // SAFETY: off = w * slot_sz < n_slots * slot_sz ≤ zone_sz - data_off.
            let access_cap = unsafe {
                (*base.add(off).cast::<LogsWorkerRingHeader>()).cap.load(Ordering::Relaxed)
            };
            // SAFETY: same bounds; error header follows access ring payload.
            let error_cap = unsafe {
                (*base.add(off + ring_size_bytes(CAP)).cast::<LogsWorkerRingHeader>())
                    .cap
                    .load(Ordering::Relaxed)
            };
            assert_eq!(access_cap, CAP as u64, "fresh init: slot {w} access cap must be stamped");
            assert_eq!(error_cap, CAP as u64, "fresh init: slot {w} error cap must be stamped");
        }

        // ── (2) Simulate new-worker slot (OS-zeroed, never stamped) ─────────────
        let off1 = slot_sz;
        // SAFETY: off1 < n_slots * slot_sz ≤ zone_sz - data_off.
        unsafe {
            (*base.add(off1).cast::<LogsWorkerRingHeader>()).cap.store(0, Ordering::Relaxed);
            (*base.add(off1 + ring_size_bytes(CAP)).cast::<LogsWorkerRingHeader>())
                .cap
                .store(0, Ordering::Relaxed);
        }
        // SAFETY: same bounds as above.
        let cap_check =
            unsafe { (*base.add(off1).cast::<LogsWorkerRingHeader>()).cap.load(Ordering::Relaxed) };
        assert_eq!(cap_check, 0, "sanity: slot 1 access cap must be 0 before reload");

        // ── (3) Reload ───────────────────────────────────────────────────────────
        // SAFETY: fake_zone is valid; old_data non-null triggers the reload path.
        let ret2 = unsafe {
            logs_shm_zone_init(&raw mut fake_zone, core::ptr::dangling_mut::<core::ffi::c_void>())
        };
        assert_eq!(ret2, ngx_int_t::from(Status::NGX_OK), "reload must return NGX_OK");

        // ── (4) Assert slot 1 has cap stamped (the H2F3 fix) ────────────────────
        // SAFETY: same bounds as step (2).
        let access_cap1 =
            unsafe { (*base.add(off1).cast::<LogsWorkerRingHeader>()).cap.load(Ordering::Relaxed) };
        // SAFETY: same bounds.
        let error_cap1 = unsafe {
            (*base.add(off1 + ring_size_bytes(CAP)).cast::<LogsWorkerRingHeader>())
                .cap
                .load(Ordering::Relaxed)
        };
        assert_eq!(
            access_cap1, CAP as u64,
            "H2F3: reload must stamp cap on new worker slot (access ring)"
        );
        assert_eq!(
            error_cap1, CAP as u64,
            "H2F3: reload must stamp cap on new worker slot (error ring)"
        );

        // SAFETY: base points into zone_mem; slot 0 is at offset 0.
        let access_cap0 =
            unsafe { (*base.cast::<LogsWorkerRingHeader>()).cap.load(Ordering::Relaxed) };
        assert_eq!(access_cap0, CAP as u64, "H2F3: reload must not corrupt slot 0 cap");
    }

    /// H2F3 regression: spans_shm_zone_init must stamp `cap` into new-worker
    /// slots on SIGHUP reload (scale-up path).
    ///
    /// Each spans slot contains ONE `LogsWorkerRingHeader` at slot base
    /// (spans_slot_size = ring_size_bytes; no separate error ring).
    /// Also asserts read_offset / write_offset are untouched by the reload
    /// path (reload stamps cap only; offsets survive from the old generation).
    ///
    /// Fail-before proof: comment out the H2F3 reload block in spans_shm_zone_init
    /// and this test's assertion on step (4) will fail.
    #[test]
    fn b1_spans_cap_survives_reload() {
        use crate::logs::ring::LogsWorkerRingHeader;
        use nginx_sys::ngx_shm_zone_t;

        const CAP: usize = 512;
        let slot_sz = spans_slot_size(CAP);
        let n_slots = 2usize;
        let data_off = data_offset();
        let zone_sz = data_off + n_slots * slot_sz;

        let mut zone_mem: std::vec::Vec<u8> = std::vec![0u8; zone_sz];
        let zone_addr = zone_mem.as_mut_ptr();

        // cycle_addr=0 → wp_from_cycle returns None → n_active = n_reserved (2).
        let zid = ZoneInitData { ring_cap: CAP, cycle_addr: 0 };

        // SAFETY: ngx_shm_zone_t is repr(C); zero is valid for all fields we don't set.
        let mut fake_zone: ngx_shm_zone_t = unsafe { core::mem::zeroed() };
        fake_zone.data = &raw const zid as *mut core::ffi::c_void;
        fake_zone.shm.addr = zone_addr.cast();
        fake_zone.shm.size = zone_sz;

        // ── (1) Fresh init ───────────────────────────────────────────────────────
        // SAFETY: fake_zone is a valid ngx_shm_zone_t with shm region backing it;
        // old_data=null triggers the fresh-init path.
        let ret = unsafe { spans_shm_zone_init(&raw mut fake_zone, core::ptr::null_mut()) };
        assert_eq!(ret, ngx_int_t::from(Status::NGX_OK), "fresh init must return NGX_OK");

        // SAFETY: data_off < zone_sz; zone_mem is live for the whole test.
        let base = unsafe { zone_addr.add(data_off) };
        for w in 0..n_slots {
            let off = w * slot_sz;
            // SAFETY: off = w * slot_sz < n_slots * slot_sz ≤ zone_sz - data_off.
            let cap = unsafe {
                (*base.add(off).cast::<LogsWorkerRingHeader>()).cap.load(Ordering::Relaxed)
            };
            assert_eq!(cap, CAP as u64, "fresh init: slot {w} cap must be stamped");
        }

        // ── (2) Simulate new-worker slot (OS-zeroed, never stamped) ─────────────
        let off1 = slot_sz; // byte offset of slot 1 from base
                            // SAFETY: off1 = slot_sz < n_slots * slot_sz ≤ zone_sz - data_off.
        unsafe {
            let hdr1 = base.add(off1).cast::<LogsWorkerRingHeader>();
            (*hdr1).cap.store(0, Ordering::Relaxed);
            // Set NON-ZERO sentinel offsets so step (5) can detect a re-zeroing
            // regression: the reload path must stamp cap only and leave the
            // surviving-generation offsets untouched. Asserting `== 0` after
            // setting `0` could not catch a stray offset store in the reload
            // path; asserting these sentinels are PRESERVED can.
            (*hdr1).read_offset.store(7, Ordering::Relaxed);
            (*hdr1).write_offset.store(13, Ordering::Relaxed);
        }
        // SAFETY: off1 = slot_sz < n_slots * slot_sz ≤ zone_sz - data_off.
        let cap_check =
            unsafe { (*base.add(off1).cast::<LogsWorkerRingHeader>()).cap.load(Ordering::Relaxed) };
        assert_eq!(cap_check, 0, "sanity: slot 1 cap must be 0 before reload");

        // ── (3) Reload ───────────────────────────────────────────────────────────
        // SAFETY: fake_zone is valid; old_data non-null triggers the reload path.
        let ret2 = unsafe {
            spans_shm_zone_init(&raw mut fake_zone, core::ptr::dangling_mut::<core::ffi::c_void>())
        };
        assert_eq!(ret2, ngx_int_t::from(Status::NGX_OK), "reload must return NGX_OK");

        // ── (4) Assert slot 1 has cap stamped (the H2F3 fix) ────────────────────
        // SAFETY: same bounds as step (2).
        let cap1 =
            unsafe { (*base.add(off1).cast::<LogsWorkerRingHeader>()).cap.load(Ordering::Relaxed) };
        assert_eq!(cap1, CAP as u64, "H2F3: spans reload must stamp cap on new worker slot");

        // ── (5) Assert read_offset / write_offset PRESERVED ─────────────────────
        // The reload path stamps cap only; offsets survive from the old
        // generation. Step (2) seeded non-zero sentinels (7/13); a stray offset
        // store in the reload path would clobber them — assert they are preserved.
        // SAFETY: same bounds as step (2).
        let ro = unsafe {
            (*base.add(off1).cast::<LogsWorkerRingHeader>()).read_offset.load(Ordering::Relaxed)
        };
        // SAFETY: same bounds as step (2).
        let wo = unsafe {
            (*base.add(off1).cast::<LogsWorkerRingHeader>()).write_offset.load(Ordering::Relaxed)
        };
        assert_eq!(ro, 7, "H2F3: spans reload must not touch read_offset (sentinel preserved)");
        assert_eq!(wo, 13, "H2F3: spans reload must not touch write_offset (sentinel preserved)");

        // SAFETY: base points into zone_mem; slot 0 header is at offset 0.
        let cap0 = unsafe { (*base.cast::<LogsWorkerRingHeader>()).cap.load(Ordering::Relaxed) };
        assert_eq!(cap0, CAP as u64, "H2F3: reload must not corrupt slot 0 cap");
    }
}
