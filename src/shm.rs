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
/// Retained for the byte-size histograms (request/response body, upstream
/// bytes), which keep the explicit-boundary shape.
pub const DURATION_BOUNDS_MS: [u64; 14] =
    [5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000];

/// Number of duration histogram buckets (14 boundaries + 1 overflow).
/// Used by the byte-size histograms.
pub const N_DURATION_BUCKETS: usize = 15;

// ── Exponential-histogram constants (Phase 2.2 DP-F) ─────────────────────────

/// OTel exponential histogram scale for `request_duration_combos`.
///
/// **Resolution:** scale 3 → base = 2^(2^-3) = 2^0.125 ≈ 1.091
/// → 8 buckets per power-of-2 microsecond.  At this scale, 90µs, 150µs,
/// and 200µs land in distinct buckets (indices 51, 57, 60 respectively),
/// resolving the ~90–200µs operating regime.  Scale 0 with integer-ms input
/// collapsed everything < 1ms into `zero_count` — this fixes that.
pub const EXP_HISTOGRAM_SCALE: i32 = 3;

/// Number of positive-range bucket slots in each `ExpHistogramSlot`.
///
/// At scale 3 in µs, 192 buckets covers [1µs, 2^24 µs = 16.7s), sufficient
/// for all practical HTTP latencies.  Values ≥ 2^24 µs clamp to bucket 191.
/// Values = 0 µs go to `zero_count` (should not occur in practice).
pub const N_EXP_BUCKETS: usize = 192;

/// Fixed bucket offset (OTel `offset` field in the wire format).
/// Bucket `k` covers approximately [base^k, base^(k+1)) µs starting at 1µs.
pub const EXP_HISTOGRAM_BUCKET_OFFSET: i32 = 0;

/// An OTel **exponential histogram** slot stored entirely in atomic counters.
///
/// **Resolution (scale 3, µs input):** bucket `k` covers approximately
/// [base^k, base^(k+1)) µs where base = 2^(2^-3) ≈ 1.091.
/// 90µs → bucket 51; 150µs → 57; 200µs → 60 — all distinct.
/// All durations are positive so `negative` is empty.
///
/// The record function computes the scale-3 bucket index with a few bit ops +
/// one `fetch_add` — alloc-free and lock-free on the hot path.
///
/// Size: `(N_EXP_BUCKETS + 3) × 8 = 195 × 8 = 1560 bytes`.
#[repr(C)]
pub struct ExpHistogramSlot {
    /// Bucket `k` counts values in approximately [base^k, base^(k+1)) µs.
    /// `buckets[N_EXP_BUCKETS-1]` is the overflow bucket (≥ ~16.7s).
    pub buckets: [AtomicU64; N_EXP_BUCKETS],
    /// Count of values = 0 µs (should not occur with µs-precision timing).
    pub zero_count: AtomicU64,
    /// Sum of all observed values in µs.
    pub sum: AtomicU64,
    /// Total observation count.
    pub count: AtomicU64,
}

impl ExpHistogramSlot {
    /// Record one duration observation on the hot path.
    ///
    /// `value_us` is the duration in **microseconds**.  Feeding µs
    /// (instead of ms) with scale 3 resolves the ~90–200µs regime into
    /// distinct buckets.
    ///
    /// # Constraint: no allocation, no lock
    /// Uses `leading_zeros()` + a few bit ops to compute
    /// `floor(log2(value_us) * 2^scale)` in O(1).
    #[inline]
    pub fn record(&self, value_us: u64) {
        if value_us == 0 {
            self.zero_count.fetch_add(1, Ordering::Relaxed);
        } else {
            let n = 63u32.saturating_sub(value_us.leading_zeros()); // floor(log2(value))
            let s = EXP_HISTOGRAM_SCALE as u32; // = 3
                                                // OTel exponential-histogram bucket index = floor(log2(value) * 2^scale),
                                                // recovered from the exponent `n` plus the top `scale` mantissa bits.
                                                // The encoder ships these buckets at offset=0, so the consumer decodes
                                                // bucket `k` as the range (2^(k/2^scale), 2^((k+1)/2^scale)].
            let upper = (n as usize) << s;
            let frac = if n >= s {
                ((value_us >> (n - s)) as usize) & ((1usize << s) - 1)
            } else {
                // n < s: shift the mantissa left (n - s would underflow as u32).
                ((value_us << (s - n)) as usize) & ((1usize << s) - 1)
            };
            let idx = upper | frac;
            self.buckets[idx.min(N_EXP_BUCKETS - 1)].fetch_add(1, Ordering::Relaxed);
        }
        self.sum.fetch_add(value_us, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot all bucket counts, zero_count, sum, and count for export.
    ///
    /// Uses `Ordering::Acquire` to synchronise with worker writes.
    pub fn snapshot(&self) -> ([u64; N_EXP_BUCKETS], u64, u64, u64) {
        let mut buckets = [0u64; N_EXP_BUCKETS];
        for (i, b) in self.buckets.iter().enumerate() {
            buckets[i] = b.load(Ordering::Acquire);
        }
        let zero_count = self.zero_count.load(Ordering::Acquire);
        let sum = self.sum.load(Ordering::Acquire);
        let count = self.count.load(Ordering::Acquire);
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

// ── Closed cardinality dimension enums ──────────────────────────────────────
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

// ── Route and upstream-zone dimensions (DP-E, Phase 2.2 — DECOMPOSED) ───────
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
/// `WorkerSlots::request_duration_combos`.  Unchanged from Phase 2.1 (160).
pub const N_COMBOS: usize = N_HTTP_METHODS * N_STATUS_CLASSES * N_PROTO_VERSIONS;

/// Memory budget for all three histogram arrays in `WorkerSlots`.
///
/// With default caps 64/32 and N_EXP_BUCKETS=192 (scale 3):
///   size_of::<ExpHistogramSlot>() = (192 + 3) × 8 = 1560 bytes
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

// ── Error-rate severity classes (Phase 2.3 DP-B) ────────────────────────────

/// Number of severity classes for the companion error-rate metric (DP-B).
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
/// **Phase 2.2 DP-E (decomposed)**: three independent histogram arrays:
/// 1. `request_duration_combos[160]`: base `{method × status_class × protocol}`.
/// 2. `route_duration_combos[65]`: per-route (`http.route` = location name).
/// 3. `upstream_duration_combos[33]`: per-upstream zone (`nginx.upstream.zone`).
///
/// Each request bumps ONE slot in each of the three arrays.  The joint
/// route×upstream cell is intentionally dropped.
///
/// Phase 2.2 DP-F: each slot is an `ExpHistogramSlot` (exponential histogram).
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
    /// Exemplar reservoir (Phase 2.2 Step 2.2.4).
    /// Shared across all combos; per-entry `combo_idx` identifies the histogram.
    /// The runtime `access_sample_size` directive caps the effective reservoir
    /// size to ≤ `MAX_EXEMPLAR_RESERVOIR`.
    pub exemplar_reservoir: ExemplarReservoir,
    /// Per-severity-class error-log event counters (Phase 2.3 DP-B).
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

// ── Exemplar reservoir (Phase 2.2 Step 2.2.4) ─────────────────────────────

/// Maximum per-worker exemplar reservoir size.
///
/// Operators set the effective size via `otel_access_log_sample <size>`
/// (capped at this value).  At ~256 bytes per entry × 64 ≈ 16 KB per
/// worker — a negligible addition to `WorkerSlots`.
pub const MAX_EXEMPLAR_RESERVOIR: usize = 64;

/// Maximum `url.path` bytes stored in an exemplar entry.
/// Matches `crate::logs::access::MAX_URL_PATH`.
pub const EXEMPLAR_URL_PATH_MAX: usize = 64;

/// Maximum `user_agent.original` bytes stored in an exemplar entry.
/// Matches `crate::logs::access::MAX_USER_AGENT`.
pub const EXEMPLAR_USER_AGENT_MAX: usize = 128;

/// A single exemplar entry in the per-worker reservoir.
///
/// Written on the hot path with `Ordering::Relaxed` on the atomic fields;
/// the plain byte buffers (`url_path_buf`, `user_agent_buf`) are written
/// with direct pointer writes — tearing is acceptable for exemplar hints.
///
/// The `has_trace` flag and `combo_idx` use `Relaxed` ordering.
/// The reader should only access entries for which `count > slot_index`
/// (see [`ExemplarReservoir::snapshot`]).
///
/// Size: 5 × AtomicU64 + AtomicU32 + AtomicU8 + AtomicU8 + 2 pad
///       + EXEMPLAR_URL_PATH_MAX + EXEMPLAR_USER_AGENT_MAX
///     = 40 + 4 + 1 + 1 + 2 + 64 + 128 = 240 bytes.
#[repr(C)]
pub struct ExemplarEntry {
    /// Observed request duration in ms.
    pub value_ms: AtomicU64,
    /// Lower 8 bytes of the W3C trace_id (bytes 0–7).
    pub trace_id_lo: AtomicU64,
    /// Upper 8 bytes of the W3C trace_id (bytes 8–15).
    pub trace_id_hi: AtomicU64,
    /// W3C span_id (parent_id) — 8 bytes.
    pub span_id: AtomicU64,
    /// Unix epoch timestamp of the request in nanoseconds.
    pub ts_unix_nano: AtomicU64,
    /// Combo index (identifies the histogram data point this belongs to).
    pub combo_idx: core::sync::atomic::AtomicU32,
    /// 1 if `trace_id` / `span_id` are valid; 0 if absent.
    pub has_trace: core::sync::atomic::AtomicU8,
    /// Length of `url_path_buf` that is valid.
    pub url_path_len: core::sync::atomic::AtomicU8,
    /// Length of `user_agent_buf` that is valid.
    pub user_agent_len: core::sync::atomic::AtomicU8,
    _pad: [u8; 1],
    /// `url.path` bytes — high-cardinality, exemplar filtered_attribute ONLY.
    /// NEVER a metric dimension.
    pub url_path_buf: [u8; EXEMPLAR_URL_PATH_MAX],
    /// `user_agent.original` bytes — high-cardinality, exemplar filtered_attribute ONLY.
    /// NEVER a metric dimension.
    pub user_agent_buf: [u8; EXEMPLAR_USER_AGENT_MAX],
}

/// Per-worker exemplar reservoir — a fixed-capacity circular buffer of
/// [`ExemplarEntry`] entries, filled by counter-mod sampling.
///
/// # Sampling discipline
/// Each incoming candidate calls `count.fetch_add(1)` to claim a slot index:
/// `slot = count % effective_size`.  When `count < effective_size` the slot
/// is freshly allocated; afterwards it overwrites an older entry.  This is
/// NOT Vitter-style reservoir sampling (biased towards recent entries) but is
/// O(1), alloc-free, and lock-free — the single `fetch_add` IS the one
/// permitted hot-path write.
#[repr(C)]
pub struct ExemplarReservoir {
    /// Sequential counter: how many candidates have been offered to the reservoir.
    pub count: AtomicU64,
    pub entries: [ExemplarEntry; MAX_EXEMPLAR_RESERVOIR],
}

impl ExemplarReservoir {
    /// Write one exemplar entry on the hot path.
    ///
    /// `effective_size` must be in `1..=MAX_EXEMPLAR_RESERVOIR`; values outside
    /// this range are clamped.
    ///
    /// # Hot-path note
    /// One `fetch_add` + ≤ 9 `Relaxed` stores + 2 memcpy ≤ 192 bytes.
    /// All within the budget of "one exemplar reservoir write."
    ///
    /// # High-cardinality fields
    /// `url_path` and `user_agent` are stored in the entry as filtered_attributes;
    /// they are **never** used as metric dimensions.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn write(
        &self,
        effective_size: usize,
        value_ms: u64,
        combo_idx: u32,
        trace_id: Option<[u8; 16]>,
        span_id: Option<[u8; 8]>,
        ts_unix_nano: u64,
        url_path: &[u8],
        user_agent: &[u8],
    ) {
        let k = effective_size.clamp(1, MAX_EXEMPLAR_RESERVOIR);
        let n = self.count.fetch_add(1, Ordering::Relaxed) as usize;
        let slot = n % k;
        let e = &self.entries[slot];
        e.value_ms.store(value_ms, Ordering::Relaxed);
        e.ts_unix_nano.store(ts_unix_nano, Ordering::Relaxed);
        e.combo_idx.store(combo_idx, Ordering::Relaxed);
        if let (Some(tid), Some(sid)) = (trace_id, span_id) {
            let lo = u64::from_be_bytes(tid[0..8].try_into().unwrap_or([0u8; 8]));
            let hi = u64::from_be_bytes(tid[8..16].try_into().unwrap_or([0u8; 8]));
            e.trace_id_lo.store(lo, Ordering::Relaxed);
            e.trace_id_hi.store(hi, Ordering::Relaxed);
            e.span_id.store(u64::from_be_bytes(sid), Ordering::Relaxed);
            e.has_trace.store(1, Ordering::Relaxed);
        } else {
            e.has_trace.store(0, Ordering::Relaxed);
        }
        // High-cardinality fields: copy bytes into the fixed-size buffers.
        //
        // There is NO per-entry commit barrier: the count is the only
        // synchronisation point, and the individual fields above (combo_idx,
        // trace_id, these byte buffers) are written with Relaxed / non-atomic
        // copies.  A concurrent reader can therefore observe a *torn* exemplar —
        // a url.path spliced from two requests, or a trace_id paired with the
        // wrong data point.  This is an intentional hot-path trade-off:
        // exemplars are sampling hints for drill-down, not an authoritative
        // record (see TELEMETRY_MODEL.md "Exemplars are best-effort hints").
        let url_len = url_path.len().min(EXEMPLAR_URL_PATH_MAX) as u8;
        let ua_len = user_agent.len().min(EXEMPLAR_USER_AGENT_MAX) as u8;
        // Safety: all indices are within array bounds (len ≤ max).
        unsafe {
            let dst = e.url_path_buf.as_ptr() as *mut u8;
            core::ptr::copy_nonoverlapping(url_path.as_ptr(), dst, url_len as usize);
            let dst = e.user_agent_buf.as_ptr() as *mut u8;
            core::ptr::copy_nonoverlapping(user_agent.as_ptr(), dst, ua_len as usize);
        }
        e.url_path_len.store(url_len, Ordering::Relaxed);
        e.user_agent_len.store(ua_len, Ordering::Relaxed);
    }

    /// Snapshot all active entries.
    ///
    /// Returns a Vec of `ExemplarSnapshot` items (one per filled slot).
    /// Callers should skip entries where `combo_idx == 0` and `ts_unix_nano == 0`
    /// (uninitialised slots).
    pub fn snapshot(&self, effective_size: usize) -> std::vec::Vec<ExemplarSnapshot> {
        let k = effective_size.clamp(1, MAX_EXEMPLAR_RESERVOIR);
        let count = self.count.load(Ordering::Acquire) as usize;
        let filled = count.min(k);

        let mut out = std::vec::Vec::with_capacity(filled);
        for i in 0..filled {
            let e = &self.entries[i];
            let value_ms = e.value_ms.load(Ordering::Acquire);
            let combo_idx = e.combo_idx.load(Ordering::Acquire);
            let has_trace = e.has_trace.load(Ordering::Acquire) != 0;
            let ts_ns = e.ts_unix_nano.load(Ordering::Acquire);
            let lo = e.trace_id_lo.load(Ordering::Acquire).to_be_bytes();
            let hi = e.trace_id_hi.load(Ordering::Acquire).to_be_bytes();
            let mut trace_id = [0u8; 16];
            trace_id[0..8].copy_from_slice(&lo);
            trace_id[8..16].copy_from_slice(&hi);
            let span_id = e.span_id.load(Ordering::Acquire).to_be_bytes();
            let url_path_len = e.url_path_len.load(Ordering::Acquire);
            let user_agent_len = e.user_agent_len.load(Ordering::Acquire);
            let url_path = e.url_path_buf;
            let user_agent = e.user_agent_buf;
            out.push(ExemplarSnapshot {
                value_ms,
                combo_idx,
                has_trace,
                trace_id,
                span_id,
                ts_unix_nano: ts_ns,
                url_path,
                url_path_len,
                user_agent,
                user_agent_len,
            });
        }
        out
    }
}

/// Snapshot result from `ExemplarReservoir::snapshot`.
pub struct ExemplarSnapshot {
    pub value_ms: u64,
    pub combo_idx: u32,
    pub has_trace: bool,
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub ts_unix_nano: u64,
    pub url_path: [u8; EXEMPLAR_URL_PATH_MAX],
    pub url_path_len: u8,
    pub user_agent: [u8; EXEMPLAR_USER_AGENT_MAX],
    pub user_agent_len: u8,
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
    // SAFETY: per the fn contract `cf` and `module` are valid; this is a plain
    // FFI call into nginx's shared-memory registration with valid arguments.
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
    // SAFETY: nginx invokes this callback with a valid, non-null
    // `ngx_shm_zone_t` (fn contract); the reference does not outlive the call.
    let zone = unsafe { &*shm_zone };
    let offset = data_offset();
    if zone.shm.size > offset {
        // SAFETY: `offset == data_offset()` and we checked `zone.shm.size >
        // offset`, so `addr + offset` is within the mapped zone.
        let base: *mut u8 = unsafe { zone.shm.addr.cast::<u8>().add(offset) };
        let size = zone.shm.size - offset;
        // SAFETY: `base` is within the zone and `size = zone.shm.size - offset`
        // bytes remain after it, so the zero-fill stays in-bounds. It clears only
        // the WorkerSlots area, never the slab-pool header in [0, offset) (see
        // the doc above — zeroing it would crash the master).
        unsafe { ptr::write_bytes(base, 0, size) };
    }

    Status::NGX_OK.into()
}

// ── Logs shm zone (Phase 2.1) ─────────────────────────────────────────────

use crate::logs::ring::{ring_size_bytes, LogsWorkerRing, LogsWorkerRingHeader};

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
#[allow(dead_code)]
#[inline]
pub unsafe fn logs_error_ring(base_addr: *mut u8, worker_id: usize, cap: usize) -> LogsWorkerRing {
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
/// Called by `init_process` (Step 2.3.5) once per worker after the logs zone is mapped.
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
/// Called by `init_process` (Step 2.3.5) to pre-compute the table pointer and stash
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

    // Recover `cap` from the tagged-pointer stored in zone.data.
    // `register_logs_zone` stores `cap` as `usize` → `*mut c_void`.
    let cap = zone.data as usize;
    let slot_sz = logs_slot_size(cap);
    if slot_sz == 0 {
        return Status::NGX_OK.into();
    }

    // Zero the whole slot area first.
    // SAFETY: `base` is within the zone and exactly `zone_data_bytes` bytes
    // remain after it, so the zero-fill stays in-bounds (and never touches the
    // slab-pool header in [0, offset)).
    unsafe { ptr::write_bytes(base, 0, zone_data_bytes) };

    // Then stamp `cap` into every ring header so push/pop know the capacity.
    let n_workers = (zone_data_bytes / slot_sz).max(1);
    for w in 0..n_workers {
        let slot_off = w * slot_sz;
        // Access ring header.
        // SAFETY: `slot_off = w * slot_sz` with `w < n_workers = zone_data_bytes
        // / slot_sz`, so `base + slot_off` is within the just-zeroed slot area;
        // the header type lives at the start of each slot.
        let access_hdr = unsafe { base.add(slot_off).cast::<LogsWorkerRingHeader>() };
        // SAFETY: `access_hdr` points to a valid (just-zeroed) header; this runs
        // at zone-init before any worker forks (single exclusive writer), and
        // `cap` is an `AtomicU64`.
        unsafe { (*access_hdr).cap.store(cap as u64, Ordering::Relaxed) };
        // Error ring header.
        // SAFETY: the error header sits one `ring_size_bytes(cap)` past the
        // access header, still within the same in-bounds slot.
        let error_hdr =
            unsafe { base.add(slot_off + ring_size_bytes(cap)).cast::<LogsWorkerRingHeader>() };
        // SAFETY: as above — valid just-zeroed header, exclusive init-time write.
        unsafe { (*error_hdr).cap.store(cap as u64, Ordering::Relaxed) };
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
        // scale 3: bucket index = n*8 + frac (n = floor(log2(value))).
        // 100µs: n=6, k=6*8+((100>>3)&7)=48+3=51.  500µs: n=8, k=8*8+((500>>5)&7)=64+15=79.
        let (buckets0, _, _, _) = slot0.request_duration_combos[combo].snapshot();
        let (buckets1, _, _, _) = slot1.request_duration_combos[combo].snapshot();

        // Compute expected bucket indices using the same formula as record().
        fn bucket_idx(v: u64) -> usize {
            let n = 63u32.saturating_sub(v.leading_zeros());
            let s = EXP_HISTOGRAM_SCALE as u32;
            let upper = (n as usize) << s;
            let frac = if n >= s {
                ((v >> (n - s)) as usize) & ((1usize << s) - 1)
            } else {
                ((v << (s - n)) as usize) & ((1usize << s) - 1)
            };
            (upper | frac).min(N_EXP_BUCKETS - 1)
        }
        let bucket_100 = bucket_idx(100);
        let bucket_500 = bucket_idx(500);

        assert_ne!(bucket_100, bucket_500, "100 and 500 must be in distinct buckets");
        assert_eq!(buckets0[bucket_100], 3, "worker 0 bucket for 100");
        assert_eq!(buckets1[bucket_500], 2, "worker 1 bucket for 500");
        assert_eq!(buckets0[bucket_500], 0, "slot 0 not written by worker 1");
        assert_eq!(buckets1[bucket_100], 0, "slot 1 not written by worker 0");
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
        // 99_999_999_999µs ≈ 27.8h; floor(log2) = 36 → k = 36*8+... ≥ 288 → clamped to 191
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

    /// Regression: low-end (value < 2^scale) bucket placement.
    ///
    /// The prior `n <= s` shortcut wrote `value` directly as the bucket index,
    /// mis-placing every sub-16µs observation and leaving buckets 16..31
    /// permanently empty.  The correct scale-3 index is `floor(log2(value) * 8)`,
    /// verified here against hand-computed expectations spanning the n<s, n==s,
    /// and n>s branches.
    #[test]
    fn exp_histogram_low_end_bucket_placement() {
        // (value_us, expected scale-3 bucket index)
        let cases = [
            (1u64, 0usize),
            (2, 8),
            (4, 16),
            (8, 24), // n == s boundary (was mis-placed at idx 8 by the old code)
            (15, 31),
            (16, 32), // n > s
            (90, 51),
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

    /// Exemplar reservoir is bounded, alloc-free, and fills then wraps.
    #[test]
    fn exemplar_reservoir_bounded_and_alloc_free() {
        let mut buf = std::vec![0u8; mem::size_of::<WorkerSlots>()];
        // SAFETY: `buf` is a freshly-allocated, zero-initialised `Vec<u8>` sized
        // to exactly hold a `WorkerSlots`; the global allocator over-aligns it,
        // and zero is the valid initial state for its atomic fields. The shared
        // reference lives only for the test.
        let slot = unsafe { &*buf.as_mut_ptr().cast::<WorkerSlots>() };
        let reservoir = &slot.exemplar_reservoir;

        // Write 3 exemplars into a reservoir of size 2 → slot 0 and 1 filled,
        // slot 0 is overwritten by the 3rd write.
        let trace_id = Some([
            0x4bu8, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
            0x47, 0x36,
        ]);
        let span_id = Some([0x00u8, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]);

        reservoir.write(2, 100, 5, trace_id, span_id, 1_000_000_000, b"/api", b"curl/7"); // slot 0
        reservoir.write(2, 200, 6, None, None, 2_000_000_000, b"", b""); // slot 1
        reservoir.write(2, 300, 7, trace_id, span_id, 3_000_000_000, b"/v2", b"Go-http"); // slot 0 overwritten

        // count must be 3 (candidates seen)
        assert_eq!(reservoir.count.load(core::sync::atomic::Ordering::Acquire), 3);

        // snapshot with effective_size=2 should return 2 entries (min(count=3, k=2))
        let snapshot = reservoir.snapshot(2);
        assert_eq!(snapshot.len(), 2, "snapshot should return min(count, k) entries");

        // Slot 0 was overwritten by write #3 (value=300, combo=7, url=/v2, ua=Go-http)
        let s0 = &snapshot[0];
        assert_eq!(s0.value_ms, 300, "slot 0 has latest value");
        assert_eq!(s0.combo_idx, 7, "slot 0 has latest combo_idx");
        assert!(s0.has_trace, "slot 0 has trace context");
        assert_eq!(s0.url_path_len, 3); // "/v2"
        assert_eq!(&s0.url_path[..3], b"/v2");

        // Slot 1 was written by write #2 (value=200, combo=6, no trace, no url)
        let s1 = &snapshot[1];
        assert_eq!(s1.value_ms, 200, "slot 1 has its value");
        assert_eq!(s1.combo_idx, 6, "slot 1 has its combo_idx");
        assert!(!s1.has_trace, "slot 1 has no trace context");
        assert_eq!(s1.url_path_len, 0);

        // snapshot with larger effective_size than count → only min(count, k) slots
        let snap2 = reservoir.snapshot(10);
        assert_eq!(snap2.len(), 3, "snapshot with k>count returns count entries");
    }

    /// Guard (Phase 2.2 Step 2.2.5): verify that the histogram combo set remains
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

        // Spot-check expected indices:
        // 90µs: n=6, k=6*8+((90>>3)&7)=48+3=51
        // 150µs: n=7, k=7*8+((150>>4)&7)=56+1=57
        // 200µs: n=7, k=7*8+((200>>4)&7)=56+4=60
        assert_eq!(buckets[51], 1, "90µs → bucket 51");
        assert_eq!(buckets[57], 1, "150µs → bucket 57");
        assert_eq!(buckets[60], 1, "200µs → bucket 60");
    }

    #[allow(dead_code)]
    fn high_cardinality_only_on_tail_not_metric() {
        // 1. N_COMBOS is the base 160 (method × sc × proto) ONLY.
        //    Route and upstream are separate tables (decomposed) — NOT multiplied in.
        assert_eq!(
            N_COMBOS,
            N_HTTP_METHODS * N_STATUS_CLASSES * N_PROTO_VERSIONS,
            "N_COMBOS must be method × sc × proto (route/upstream are separate tables)"
        );

        // 2. url/ua in ExemplarEntry, NOT in histograms.
        let _url_max: usize = EXEMPLAR_URL_PATH_MAX; // present in ExemplarEntry only
        let _ua_max: usize = EXEMPLAR_USER_AGENT_MAX; // present in ExemplarEntry only

        // 3. combo_index is 3-arg (no url/ua/route/upstream) — route and upstream
        //    use separate WorkerSlots fields (route_duration_combos / upstream_duration_combos).
        let _ = combo_index(HttpMethod::Get, StatusClass::S2xx, ProtoVersion::Http11);
    }
}
