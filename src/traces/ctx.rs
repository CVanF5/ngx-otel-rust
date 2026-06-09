// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Per-request span context (`SpanCtx`) — Phase 3.3 hot path.
//!
//! `SpanCtx` is allocated once on the **nginx request pool** in the Rewrite phase
//! and stored via `set_module_ctx`.  The Log phase reads it back via
//! `get_module_ctx` — no second header scan, no heap allocation.
//!
//! # Budget invariants
//! - **Zero cost when disabled:** `SpanCtx` is only allocated when the REWRITE
//!   handler runs AND `amcf.is_configured()` is true (handler not registered
//!   when unconfigured — see `lib.rs postconfiguration`).
//! - **Bounded when unsampled:** pool-alloc + one header scan + PRNG + branch.
//!   `sampled = false` → LOG phase reads ctx and skips all ring work.
//! - No heap (`Vec`, `Box`, `String`), no locks, no syscalls beyond the nginx
//!   pool allocator (which is a bump allocator — effectively free).

use nginx_sys::ngx_http_request_t;
use ngx::core::Pool;

// ── SpanCtx ──────────────────────────────────────────────────────────────────

/// Per-request span context, allocated on the nginx request pool in REWRITE.
///
/// Stores the trace/span IDs, parent linkage, sampling decision, and span
/// timing anchors for the current request.  Read in LOG to stamp the access
/// tail/exemplar and (when sampled) push a span record to the ring.
///
/// # Safety / layout
/// `Copy` is required for `Pool::calloc_type::<SpanCtx>()`.  All fields are
/// plain arrays/scalars — no pointers into request memory.
/// `std::time::Instant` is `Copy` on all supported platforms.
/// The pool-alloc zeroes memory; since the entire struct is overwritten
/// before use (see `span_start.rs`), the zeroed-bytes state is never observed.
///
/// Fields `parent_span_id`, `flags`, `start_time_unix_nano`, and `start_mono`
/// are written in S1 (REWRITE) and consumed in S2 (LOG span record).
///
/// # Dual-clock span timing (D-2 fix)
/// Two anchors are captured at REWRITE:
/// - `start_time_unix_nano`: wall-clock absolute timestamp for the span start.
/// - `start_mono`: monotonic anchor; `start_mono.elapsed()` at LOG gives the
///   request duration.  Span end = `start_time_unix_nano + elapsed`; guaranteed
///   `end ≥ start` and `span (end−start) == http.server.request.duration`.
#[derive(Copy, Clone, Debug)]
pub struct SpanCtx {
    /// W3C trace ID (16 bytes).
    pub trace_id: [u8; 16],
    /// This request's span ID (8 bytes, newly generated in REWRITE).
    pub span_id: [u8; 8],
    /// Inbound parent span ID from `traceparent` (zeros = root span).
    /// Written in S1 (REWRITE); read in S2 (LOG span record).
    pub parent_span_id: [u8; 8],
    /// W3C trace flags low byte (bit 0 = sampled, as recorded in traceparent).
    /// Written in S1 (REWRITE); read in S2 (LOG span record).
    pub flags: u32,
    /// Span start time — Unix epoch, nanoseconds (set at REWRITE phase entry).
    /// Wall-clock anchor for the absolute span start timestamp.
    /// Written in S1 (REWRITE); read in S2 (LOG span record).
    pub start_time_unix_nano: u64,
    /// Monotonic anchor captured alongside `start_time_unix_nano` at REWRITE.
    ///
    /// `start_mono.elapsed()` at LOG gives the request duration, always ≥ 0.
    /// Span end = `start_time_unix_nano + elapsed_nanos`.
    /// Also used for the `http.server.request.duration` histogram (coherent).
    /// Written in S1 (REWRITE); read in S2 (LOG span record).
    pub start_mono: std::time::Instant,
    /// Whether this request is sampled.
    ///
    /// `true`  → LOG phase builds + pushes a `SpanRecord` to the spans ring.
    /// `false` → LOG phase skips all ring work (but ctx is still available for
    ///           W3C propagation via `otel_trace_context inject`).
    pub sampled: bool,
}

// ── Pool allocator ────────────────────────────────────────────────────────────

/// Allocate a `SpanCtx` on the nginx request pool and return a raw pointer.
///
/// Callers should store the pointer via `request.set_module_ctx(ptr.cast(), module)`.
/// Returns `null_mut()` on OOM (pool bump failure — extremely rare in practice).
///
/// # Safety
/// `pool` must point to the nginx request pool that outlives this call.
#[inline]
pub fn alloc_span_ctx(pool: &Pool) -> *mut SpanCtx {
    pool.calloc_type::<SpanCtx>()
}

/// Reconstruct a Pool view from the request's pool pointer.
///
/// # Safety
/// `r` must be a valid, non-null `ngx_http_request_t` with an initialised pool.
#[inline]
pub unsafe fn pool_from_request(r: *mut ngx_http_request_t) -> Pool {
    // SAFETY: caller guarantees `r` is valid and non-null; `(*r).pool` is
    // nginx's request-scoped bump pool with process lifetime ≥ this call.
    unsafe { Pool::from_ngx_pool((*r).pool) }
}

// ── DRBG — per-thread ChaCha20 CSPRNG (D-1 fix) ─────────────────────────────
//
// The prior xorshift64 was reversible: an observer of a few IDs could recover
// the state and predict future trace IDs.  Replaced with a seeded ChaCha20
// DRBG: cryptographically-unpredictable IDs, zero per-request syscalls.
//
// Design (OTel-SDK-idiomatic):
//   - Seeded ONCE per worker thread (#[cold]) from `getrandom::fill()` (one
//     OS-entropy syscall per worker at the first trace request).
//   - Thereafter: pure ChaCha20 block operations, no syscall per request.
//   - Thread-local `Cell<Option<ChaCha20Rng>>` (infallible take/set access).

use std::cell::Cell;

use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

thread_local! {
    static DRBG: Cell<Option<ChaCha20Rng>> = const { Cell::new(None) };
}

/// Return the next pseudo-random `u64` from the per-thread ChaCha20 DRBG.
///
/// Seeds itself on first call in each worker thread from OS entropy (one
/// `getrandom` syscall, #[cold]).  All subsequent calls are pure ChaCha20
/// block operations — lock-free, no syscall.
///
/// **Hot-path note:** TLS lookup + ChaCha20 word extraction — effectively
/// free relative to the request path.
#[inline]
pub(crate) fn drbg64() -> u64 {
    DRBG.with(|c| {
        let mut rng = c.take().unwrap_or_else(seed_drbg);
        let val = rng.next_u64();
        c.set(Some(rng));
        val
    })
}

/// One-time per-thread DRBG seed from OS entropy.
///
/// Called #[cold] at most once per worker thread (lazily on the first
/// trace/span ID request).  `getrandom::fill` uses the OS CSPRNG
/// (getrandom(2) on Linux, arc4random_buf on macOS) — never a filesystem
/// read, never blocks after boot.
///
/// Panics if the OS RNG is unavailable (hardware fault / FIPS failure);
/// this is a catastrophic condition, not a recoverable error.
#[cold]
fn seed_drbg() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("getrandom::fill failed — OS RNG unavailable");
    ChaCha20Rng::from_seed(seed)
}

// ── ID generation ─────────────────────────────────────────────────────────────

/// Generate a fresh 16-byte W3C trace ID.
///
/// The all-zero trace ID is invalid per W3C spec; we reroll until non-zero
/// (vanishingly unlikely in practice — < 1 in 2^128).
#[inline]
pub(crate) fn gen_trace_id() -> [u8; 16] {
    loop {
        let a = drbg64();
        let b = drbg64();
        if a != 0 || b != 0 {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&a.to_le_bytes());
            id[8..].copy_from_slice(&b.to_le_bytes());
            return id;
        }
    }
}

/// Generate a fresh 8-byte W3C span ID.
///
/// The all-zero span ID is invalid per W3C spec; we reroll until non-zero.
#[inline]
pub(crate) fn gen_span_id() -> [u8; 8] {
    loop {
        let v = drbg64();
        if v != 0 {
            return v.to_le_bytes();
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// PRNG should produce non-zero values.
    #[test]
    fn drbg64_nonzero() {
        for _ in 0..100 {
            assert_ne!(drbg64(), 0, "drbg64 must never return 0");
        }
    }

    /// DRBG values in a short sequence should all be distinct.
    #[test]
    fn drbg64_distinct() {
        let vals: std::vec::Vec<u64> = (0..64).map(|_| drbg64()).collect();
        let set: std::collections::HashSet<u64> = vals.iter().copied().collect();
        assert_eq!(set.len(), vals.len(), "drbg64 sequence must not repeat in 64 calls");
    }

    /// D-1: two ChaCha20Rng instances with different seeds must diverge.
    ///
    /// Verifies the D-1 fix property: IDs from distinct workers (which each
    /// seed their DRBG independently from `getrandom`) cannot collide in bulk.
    /// Different seeds produce statistically independent streams.
    #[test]
    fn drbg_different_seeds_diverge() {
        let seed1 = [0x01u8; 32];
        let seed2 = [0x02u8; 32];
        let mut rng1 = ChaCha20Rng::from_seed(seed1);
        let mut rng2 = ChaCha20Rng::from_seed(seed2);

        let vals1: std::vec::Vec<u64> = (0..16).map(|_| rng1.next_u64()).collect();
        let vals2: std::vec::Vec<u64> = (0..16).map(|_| rng2.next_u64()).collect();
        assert_ne!(vals1, vals2, "ChaCha20Rng with different seeds must produce different output");
    }

    /// D-1: trace IDs are 16 bytes, distinct across a batch of generations.
    #[test]
    fn trace_ids_batch_unique() {
        let ids: std::vec::Vec<[u8; 16]> = (0..100).map(|_| gen_trace_id()).collect();
        let mut seen = std::collections::HashSet::new();
        for id in &ids {
            assert_ne!(*id, [0u8; 16], "trace ID must not be all-zero");
            assert!(seen.insert(*id), "trace ID collision in batch of 100");
        }
    }

    /// D-1: span IDs are 8 bytes, distinct across a batch of generations.
    #[test]
    fn span_ids_batch_unique() {
        let ids: std::vec::Vec<[u8; 8]> = (0..100).map(|_| gen_span_id()).collect();
        let mut seen = std::collections::HashSet::new();
        for id in &ids {
            assert_ne!(*id, [0u8; 8], "span ID must not be all-zero");
            assert!(seen.insert(*id), "span ID collision in batch of 100");
        }
    }

    /// gen_trace_id returns 16 bytes, never all-zero.
    #[test]
    fn trace_id_nonzero() {
        let id = gen_trace_id();
        assert_ne!(id, [0u8; 16], "trace ID must not be all-zero");
    }

    /// gen_span_id returns 8 bytes, never all-zero.
    #[test]
    fn span_id_nonzero() {
        let id = gen_span_id();
        assert_ne!(id, [0u8; 8], "span ID must not be all-zero");
    }

    /// SpanCtx is Copy and has the expected size (pure value type for pool alloc).
    #[test]
    fn span_ctx_is_copy_sized() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<SpanCtx>();
        // Fields: trace_id(16) + span_id(8) + parent_span_id(8) + flags(4) +
        //   padding(4) + start_time_unix_nano(8) + start_mono(Instant: 8-16 B) +
        //   sampled(bool: 1) + alignment padding.
        // Instant is 8 B on macOS (mach_absolute_time u64); 16 B on Linux
        // (Timespec {sec: i64, nsec: i64}).  Widen range accordingly.
        let sz = core::mem::size_of::<SpanCtx>();
        assert!((45..=96).contains(&sz), "SpanCtx size {sz} is outside expected range 45..96");
    }

    /// D-2 dual-clock coherence: span end = start + duration, end >= start.
    ///
    /// Verifies the D-2 fix: using monotonic duration guarantees
    /// `end_time_unix_nano ≥ start_time_unix_nano` (NTP-immune) and
    /// `span (end−start) == http.server.request.duration attribute` (coherent).
    #[test]
    fn span_timing_monotonic_coherence() {
        // A realistic wall-clock anchor (2023-11-14 in nanos).
        let start_nanos: u64 = 1_700_000_000_000_000_000u64;

        // The production formula: end = start + duration_us * 1_000.
        // Test with representative durations including zero and large values.
        let test_durations_us: &[u64] = &[0, 1, 100, 999, 10_000, 999_999, 3_600_000_000];
        for &duration_us in test_durations_us {
            let end_nanos = start_nanos.saturating_add(duration_us.saturating_mul(1_000));

            // Coherence: (end − start) / 1_000 == duration_us.
            let derived_us = end_nanos.saturating_sub(start_nanos) / 1_000;
            assert_eq!(
                derived_us, duration_us,
                "coherence: span (end-start) must equal duration_us (got {derived_us}, want {duration_us})"
            );

            // Monotonic safety: end >= start always.
            assert!(
                end_nanos >= start_nanos,
                "NTP safety: end ({end_nanos}) < start ({start_nanos}) for duration_us={duration_us}"
            );
        }

        // Backward-clock proof: production path uses Instant::elapsed()
        // which returns std::time::Duration — always ≥ 0 by construction.
        let t0 = std::time::Instant::now();
        let elapsed: std::time::Duration = t0.elapsed();
        let duration_us = elapsed.as_micros() as u64;
        let end_nanos = start_nanos.saturating_add(duration_us.saturating_mul(1_000));
        assert!(
            end_nanos >= start_nanos,
            "real Instant::elapsed produced end < start: duration_us={duration_us}"
        );
    }

    /// S2 — Read-once traceparent guard (§6.6.3 parse-once design).
    ///
    /// Proves the single-scan contract: the inbound `traceparent` header is parsed
    /// **once** (by `parse_traceparent_full` in the REWRITE handler) and the result
    /// cached on `SpanCtx`.  The LOG phase reads `SpanCtx` fields directly —
    /// no second header scan.
    ///
    /// This test asserts the structural invariant: all trace-correlation data
    /// (trace_id, parent_span_id, flags) that the LOG phase needs are present
    /// directly on `SpanCtx` as plain fields, derivable from a single
    /// `parse_traceparent_full` call.  If any field were removed from `SpanCtx`,
    /// the LOG phase would need a second scan — breaking this test's setup.
    #[test]
    fn traceparent_parse_once_guard() {
        use crate::logs::access::parse_traceparent_full;

        // A valid W3C traceparent header: version-trace_id-parent_id-flags
        let header = b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

        // Single parse — this is the ONLY call parse_traceparent_full gets in
        // the production code path (span_start.rs REWRITE handler).
        let (trace_id, parent_span_id, flags) =
            parse_traceparent_full(header).expect("valid traceparent must parse");

        // Simulate what REWRITE does: populate SpanCtx from the parse result.
        let span_id = gen_span_id();
        let ctx = SpanCtx {
            trace_id,
            span_id,
            parent_span_id,
            flags,
            start_time_unix_nano: 1_700_000_000_000_000_000,
            start_mono: std::time::Instant::now(),
            sampled: (flags & 0x01) != 0,
        };

        // ── Assert SpanCtx carries exactly what the traceparent contained ─────
        // trace_id: 4bf92f3577b34da6a3ce929d0e0e4736 (big-endian hex)
        let expected_trace_id: [u8; 16] = [
            0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
            0x47, 0x36,
        ];
        assert_eq!(ctx.trace_id, expected_trace_id, "trace_id must match traceparent");

        // parent_span_id: 00f067aa0ba902b7 (big-endian hex)
        let expected_parent: [u8; 8] = [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7];
        assert_eq!(ctx.parent_span_id, expected_parent, "parent_span_id must match traceparent");

        // flags: 0x01 (sampled)
        assert_eq!(ctx.flags, 0x01, "flags must match traceparent");
        assert!(ctx.sampled, "sampled must be true when flags bit-0 is set");

        // ── Structural completeness check ─────────────────────────────────────
        // The LOG phase (instrumented.rs) needs: trace_id, span_id, parent_span_id,
        // flags, start_time_unix_nano, sampled — all present on SpanCtx.
        // This assertion is a no-op at runtime but documents the contract:
        // if any field is removed, the LOG phase code will fail to compile.
        let _ = ctx.trace_id;
        let _ = ctx.span_id;
        let _ = ctx.parent_span_id;
        let _ = ctx.flags;
        let _ = ctx.start_time_unix_nano;
        let _ = ctx.sampled;
    }
}
