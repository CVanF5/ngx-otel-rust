// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Histogram types and constants shared between workers and the exporter.

use core::sync::atomic::{AtomicU64, Ordering};

/// Default OTel HTTP server latency boundaries, in **milliseconds** — the
/// worker records raw upstream ms values against these (nginx reports
/// upstream timings in ms); the exporter republishes them via
/// `DURATION_BOUNDS_S` and divides the scalar sum by 1000.
pub const DURATION_BOUNDS_MS: [u64; 14] =
    [5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000];

/// `DURATION_BOUNDS_MS ÷ 1000` — used only by the exporter when publishing
/// `nginx.upstream.*.duration` with unit `"s"`; bucket counts are unchanged.
pub const DURATION_BOUNDS_S: [f64; 14] =
    [0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0];

/// Number of duration histogram buckets (14 boundaries + 1 overflow).
pub const N_DURATION_BUCKETS: usize = 15;

// ── Exponential-histogram constants ─────────────────────────

/// OTel exponential histogram scale for `request_duration_combos`: base =
/// 2^(2^-3) ≈ 1.091 → 8 buckets per power-of-2. Metric unit is seconds
/// (`http.server.request.duration`, semconv unit `s`).
/// <https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exponentialhistogram>
pub const EXP_HISTOGRAM_SCALE: i32 = 3;

/// Positive-range bucket count: at scale 3, 192 buckets covers ~24 octaves
/// [~1µs, ~16.7s). Durations ≥ ~16.7s clamp to the last bucket (191); 0µs
/// goes to `zero_count`.
pub const N_EXP_BUCKETS: usize = 192;

/// Fixed bucket offset (OTel `positive.offset` field in the wire format).
/// Internal bucket `0` is the lowest covered seconds bucket, holding the
/// smallest non-zero observation `1µs = 1e-6 s`: `ceil(log2(1e-6)·8) − 1 =
/// −160`. Emitted verbatim as `positive.offset`.
/// <https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exponentialhistogram>
pub const EXP_HISTOGRAM_BUCKET_OFFSET: i32 = -160;

/// Per-bucket **upper bound in integer microseconds** for the seconds-indexed
/// exponential histogram (scale 3).
///
/// `SECONDS_BUCKET_UPPER_US[i] = floor(1e6 · 2^((i + EXP_HISTOGRAM_BUCKET_OFFSET + 1) / 8))`.
/// A duration `value_us` lands in the smallest `i` with `value_us ≤
/// SECONDS_BUCKET_UPPER_US[i]` (upper-inclusive; see [`ExpHistogramSlot::record`]).
/// Integer-µs octave boundaries (`15625 … 16000000`) land exactly on indices
/// `111, 119, …, 191`.
///
/// Generated (and re-verified in `exp_histogram_seconds_bucket_exact`) with:
/// `python3 -c "from decimal import Decimal as D, getcontext; getcontext().prec=80;
/// print([int(D(10)**6*(D(2)**(D(i-159)/D(8)))) for i in range(192)])"`.
pub(super) const SECONDS_BUCKET_UPPER_US: [u64; N_EXP_BUCKETS] = [
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
/// Published metric unit is **seconds** (`http.server.request.duration`); the
/// worker receives µs durations and buckets them directly into the seconds
/// spec mapping (see [`ExpHistogramSlot::record`]) so the exporter is a
/// faithful pass-through, not a second aggregation stage.
///
/// **Resolution (scale 3):** internal bucket `i` maps to spec index `i +
/// EXP_HISTOGRAM_BUCKET_OFFSET` (= `i − 160`); boundaries are `2^(spec/8)`
/// seconds. All durations are positive so `negative` is empty.
///
/// `record` computes the bucket via integer binary search over a precomputed
/// boundary table + one `fetch_add` — alloc-free, lock-free, no float/`log()`,
/// no syscall on the hot path.
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
    /// Record one duration observation (µs) on the hot path.
    ///
    /// # Constraint: no allocation, no lock, no float
    ///
    /// The OTel exp-histogram mapping is **upper-inclusive**: the spec bucket
    /// index for a value `v` (seconds) at scale 3 is `ceil(log2(v)·8) − 1`, i.e.
    /// `v` lands in spec bucket `i` iff `2^(i/8) < v ≤ 2^((i+1)/8)`. A value
    /// exactly on a boundary goes to the **lower** bucket.
    /// <https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exponentialhistogram>
    ///
    /// We bucket integer µs directly against `SECONDS_BUCKET_UPPER_US`, whose
    /// entries are `floor(1e6 · 2^((i+OFFSET+1)/8))`. Flooring is exact for the
    /// upper-inclusive test on integer input (`value_us ≤ UB ⇔ value_us ≤
    /// floor(UB)`), and at the integer-µs octave edges (`1e6 = 2⁶·5⁶`,
    /// e.g. 15625, 1000000, 16000000) `floor(UB) = UB` exactly, so a naïve
    /// non-table `floor` scheme would otherwise mis-bucket exactly those points.
    ///
    /// Bucket = smallest `i` with `value_us ≤ UB_us[i]` =
    /// `partition_point(|t| t < value_us)`, clamped to the overflow bucket —
    /// integer binary search, no float/`log()`/syscall/alloc/lock.
    ///
    /// **Correctness:** verified exact for all `v ∈ [1, 2^14]` plus a
    /// deterministic sample to `[1, 2^24]` (incl. every integer-µs octave
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
    /// `count` is read **first** with `Acquire`, pairing with the `Release`
    /// store in `record()`. Since all `record()` calls on a slot originate
    /// from one worker thread, the Acquire on count=N transitively makes all N
    /// prior bucket/sum/zero_count writes visible, so `Σbuckets + zero_count ≥
    /// count` always holds. Bucket/sum/zero_count loads use `Relaxed` — they
    /// are already ordered by the preceding Acquire on count.
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
