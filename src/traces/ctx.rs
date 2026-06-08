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
/// Stores the trace/span IDs, parent linkage, and sampling decision for the
/// current request.  Read in LOG to stamp the access tail/exemplar and
/// (when sampled) push a span record to the ring.
///
/// # Safety / layout
/// `Copy` is required for `Pool::calloc_type::<SpanCtx>()`.  All fields are
/// plain arrays/scalars — no pointers into request memory.
/// Per-request span context, allocated on the nginx request pool in REWRITE.
///
/// Stores the trace/span IDs, parent linkage, and sampling decision for the
/// current request.  Read in LOG to stamp the access tail/exemplar and
/// (when sampled) push a span record to the ring.
///
/// # Safety / layout
/// `Copy` is required for `Pool::calloc_type::<SpanCtx>()`.  All fields are
/// plain arrays/scalars — no pointers into request memory.
///
/// Fields `parent_span_id`, `flags`, and `start_time_unix_nano` are written
/// in S1 (REWRITE) and consumed in S2 (LOG span record) — the gap between
/// steps means they are technically unused until S2 lands.
#[derive(Copy, Clone, Debug)]
pub struct SpanCtx {
    /// W3C trace ID (16 bytes).
    pub trace_id: [u8; 16],
    /// This request's span ID (8 bytes, newly generated in REWRITE).
    pub span_id: [u8; 8],
    /// Inbound parent span ID from `traceparent` (zeros = root span).
    /// Used in S2 (span end) to fill the span record's parent_span_id field.
    // `#[allow(dead_code)]` guards the S1→S2 gap; removed when S2 reads this.
    #[allow(dead_code)]
    pub parent_span_id: [u8; 8],
    /// W3C trace flags low byte (bit 0 = sampled, as recorded in traceparent).
    /// Used in S2 (span end) to fill the span record's flags field.
    // `#[allow(dead_code)]` guards the S1→S2 gap; removed when S2 reads this.
    #[allow(dead_code)]
    pub flags: u32,
    /// Span start time — Unix epoch, nanoseconds (set at REWRITE phase entry).
    /// Used in S2 (span end) as the span's start timestamp.
    // `#[allow(dead_code)]` guards the S1→S2 gap; removed when S2 reads this.
    #[allow(dead_code)]
    pub start_time_unix_nano: u64,
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

// ── PRNG — per-thread xorshift64 ─────────────────────────────────────────────

use std::cell::Cell;

thread_local! {
    static PRNG: Cell<u64> = const { Cell::new(0) };
}

/// Return the next pseudo-random `u64` from the per-thread xorshift64 PRNG.
///
/// Seeds itself on first call in each thread from `SystemTime::now()` XOR
/// the stack address of the local (adds per-worker address-space entropy) XOR
/// a Fibonacci-hashing constant.
///
/// **Hot-path note:** TLS segment lookup + 3 bit ops — lock-free, no syscall.
#[inline]
pub(crate) fn prng64() -> u64 {
    PRNG.with(|c| {
        let mut x = c.get();
        if x == 0 {
            x = seed_prng();
        }
        // xorshift64 (period 2^64 − 1; passes BigCrush)
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        c.set(x);
        x
    })
}

/// One-time per-thread seed for the PRNG.
///
/// Combines `SystemTime::now()` (varies per process/thread start time) with
/// the stack address of a local (varies per address-space layout — ASLR) and a
/// golden-ratio constant, then runs through `splitmix64` to whiten the bits.
#[cold]
fn seed_prng() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
    // Use the address of a stack variable as additional per-ASLR-instance entropy.
    let stack_addr: u64 = {
        let local: u64 = t;
        core::ptr::addr_of!(local) as u64
    };
    splitmix64(t ^ stack_addr ^ 0x9e3779b97f4a7c15u64)
}

/// Avalanche hash used to whiten the seed bits (Vigna's splitmix64 step).
#[inline(always)]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

// ── ID generation ─────────────────────────────────────────────────────────────

/// Generate a fresh 16-byte W3C trace ID.
///
/// The all-zero trace ID is invalid per W3C spec; we reroll until non-zero
/// (vanishingly unlikely in practice — < 1 in 2^128).
#[inline]
pub(crate) fn gen_trace_id() -> [u8; 16] {
    loop {
        let a = prng64();
        let b = prng64();
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
        let v = prng64();
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
    fn prng64_nonzero() {
        for _ in 0..100 {
            assert_ne!(prng64(), 0, "prng64 must never return 0");
        }
    }

    /// PRNG values in a short sequence should all be distinct.
    #[test]
    fn prng64_distinct() {
        let vals: std::vec::Vec<u64> = (0..64).map(|_| prng64()).collect();
        let set: std::collections::HashSet<u64> = vals.iter().copied().collect();
        assert_eq!(set.len(), vals.len(), "prng64 sequence must not repeat in 64 calls");
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
        // 16 + 8 + 8 + 4 + 8 + 1 (bool) + alignment padding
        // Actual size depends on alignment; just assert it's reasonable.
        let sz = core::mem::size_of::<SpanCtx>();
        assert!((45..=64).contains(&sz), "SpanCtx size {sz} is outside expected range 45..64");
    }
}
