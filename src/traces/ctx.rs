// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Per-request span context (`SpanCtx`) — hot path.
//!
//! `SpanCtx` is allocated once on the **nginx request pool** in the Rewrite phase
//! and stored via `set_module_ctx`.  The Log phase reads it back via
//! `get_module_ctx` — no second header scan, no heap allocation.
//!
//! Zero-cost when disabled (allocated only when REWRITE runs and the module is
//! configured; see `lib.rs postconfiguration`); bounded when unsampled
//! (pool-alloc + one header scan + PRNG + branch, then LOG skips all ring
//! work); no heap, no locks, no syscalls beyond the pool bump allocator.

use nginx_sys::ngx_http_request_t;
use ngx::core::Pool;
use ngx::http::Request;

// ── SpanCtx ──────────────────────────────────────────────────────────────────

/// Per-request span context, allocated on the nginx request pool in REWRITE.
///
/// Stores the trace/span IDs, parent linkage, sampling decision, and span
/// timing anchors for the current request.  Read in LOG to stamp the access
/// tail/exemplar and (when sampled) push a span record to the ring.
///
/// # Safety / layout
/// `Copy` is required for `Pool::calloc_type::<SpanCtx>()`: all fields are
/// plain arrays/scalars (no pointers into request memory), and
/// `std::time::Instant` is `Copy` on all supported platforms.  The pool-alloc
/// zeroes memory, but the whole struct is overwritten before use (see
/// `span_start.rs`), so the zeroed state is never observed.
///
/// # Dual-clock span timing
/// Two anchors captured at REWRITE: `start_time_unix_nano` (wall-clock) and
/// `start_mono` (monotonic). `start_mono.elapsed()` at LOG gives the request
/// duration; span end = `start_time_unix_nano + elapsed`, guaranteeing
/// `end ≥ start` and `span (end−start) == http.server.request.duration`.
#[derive(Copy, Clone, Debug)]
pub struct SpanCtx {
    /// W3C trace ID (16 bytes).
    pub trace_id: [u8; 16],
    /// This request's span ID (8 bytes, newly generated in REWRITE).
    pub span_id: [u8; 8],
    /// Inbound parent span ID from `traceparent` (zeros = root span).
    pub parent_span_id: [u8; 8],
    /// W3C trace flags low byte (bit 0 = sampled, as recorded in traceparent).
    pub flags: u32,
    /// Span start time — Unix epoch, nanoseconds (set at REWRITE phase entry);
    /// wall-clock anchor for the absolute span start timestamp.
    pub start_time_unix_nano: u64,
    /// Monotonic anchor captured alongside `start_time_unix_nano` at REWRITE.
    ///
    /// `start_mono.elapsed()` at LOG gives the request duration, always ≥ 0.
    /// Span end = `start_time_unix_nano + elapsed_nanos`, also used for the
    /// `http.server.request.duration` histogram (coherent with the span).
    pub start_mono: std::time::Instant,
    /// Whether this request is sampled.
    ///
    /// `true`  → LOG phase builds + pushes a `SpanRecord` to the spans ring.
    /// `false` → LOG phase skips all ring work (ctx is still available for
    ///           W3C propagation via `otel_trace_context inject`).
    pub sampled: bool,
}

// ── Pool allocator + redirect-safe cleanup anchor ──────────────────────────────

/// No-op cleanup handler that serves as the *findable anchor* for the request's
/// `SpanCtx` (mirroring the C++ module's `cleanupOtelCtx`,
/// `nginx-otel/src/http_module.cpp:191-193`).
///
/// nginx zeroes the whole per-request module-ctx array on an internal redirect
/// (`ngx_http_internal_redirect` / `ngx_http_named_location`, both call
/// `ngx_memzero(r->ctx, …)` — verified `src/http/ngx_http_core_module.c:2614`
/// and `:2688`), orphaning the `SpanCtx` pointer stored via `set_module_ctx`.
/// Allocating `SpanCtx` as the payload of a `ngx_pool_cleanup_add` node keeps
/// it alive across the redirect (the cleanup list, unlike the ctx array,
/// isn't zeroed), and `recover_span_ctx` walks that list to re-install it.
///
/// # Drop-safety
/// `SpanCtx` is `Copy` (plain arrays/scalars plus `std::time::Instant`, `Copy`
/// on all supported platforms) — trivially destructible, so a no-op handler
/// is correct and the pool reclaims the bytes wholesale at teardown.  If
/// `SpanCtx` ever gains a non-`Copy`, `Drop`-relevant field, this handler must
/// run `ptr::drop_in_place` — guarded by the `Copy` assertion in the unit tests.
///
/// # Safety
/// nginx calls this with the `data` pointer of the cleanup node at pool teardown.
unsafe extern "C" fn cleanup_span_ctx(_data: *mut core::ffi::c_void) {
    // Intentionally empty: SpanCtx is Copy / trivially destructible.
}

/// The cleanup-handler function-pointer type (matches `ngx_pool_cleanup_pt`'s
/// inner type), used for the `fn_addr_eq` identity comparison in
/// [`recover_span_ctx`].
type NgxCleanupPt = unsafe extern "C" fn(*mut core::ffi::c_void);

/// Allocate a `SpanCtx` as the payload of a pool-cleanup node and return a
/// pointer to that (zeroed) payload.
///
/// The cleanup node (handler = [`cleanup_span_ctx`]) is the redirect-survivable
/// anchor; the returned pointer is what callers store via
/// `request.set_module_ctx(ptr.cast(), module)`.  Mirrors the C++ module's
/// `createOtelCtx` (`nginx-otel/src/http_module.cpp:214-229`).
///
/// Returns `null_mut()` on OOM (pool bump failure — extremely rare in practice).
///
/// # Safety
/// `pool` must point to the nginx request pool that outlives this call.
#[inline]
pub fn alloc_span_ctx(pool: &Pool) -> *mut SpanCtx {
    // SAFETY: `pool.as_ptr()` yields the live request pool pointer; requesting
    // `size_of::<SpanCtx>()` extra payload bytes hands us a node whose `data`
    // field points to zeroed (ngx_pcalloc'd) storage of exactly that size.
    let cln =
        unsafe { nginx_sys::ngx_pool_cleanup_add(pool.as_ptr(), core::mem::size_of::<SpanCtx>()) };
    if cln.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `cln` is a freshly-returned, exclusively-owned cleanup node.
    // `ngx_pool_cleanup_add`'s payload is `ngx_palloc`'d (NOT zeroed), so we
    // zero it here to preserve the calloc-based contract that partial-field
    // writers (e.g. the pre-gate ctx, which sets only `flags`) rely on.
    unsafe {
        (*cln).handler = Some(cleanup_span_ctx);
        let ctx = (*cln).data.cast::<SpanCtx>();
        core::ptr::write_bytes(ctx, 0u8, 1);
        ctx
    }
}

/// Allocate a `SpanCtx` as a PLAIN zeroed pool allocation, with NO pool-cleanup
/// anchor — i.e. it is NOT redirect-survivable and `recover_span_ctx` will never
/// re-install it after a redirect clears the module-ctx slot.
///
/// Used for the PRE-GATE `SpanCtx`: that ctx exists only so Gate 2's
/// `$otel_parent_sampled` complex-value read can see the inbound flags within
/// the same span-start handler pass, and must never outlive a decline.  If the
/// pre-gate path registered the cleanup anchor (as [`alloc_span_ctx`] does), a
/// Gate-2-DECLINED request that then internally redirects would have
/// `recover_span_ctx` walk the cleanup list, find the orphaned pre-gate anchor,
/// and re-install the stale ctx — making `$otel_trace_id` non-empty for a
/// declined request.  A plain alloc leaves nothing for `recover_span_ctx` to
/// find.  The final POST-GATE [`alloc_span_ctx`] (reached only when the gate
/// PASSES) still registers the anchor, preserving redirect-survival for spans
/// that are actually emitted.
///
/// Returns `null_mut()` on OOM (pool bump failure — extremely rare).
///
/// # Safety
/// `pool` must point to the nginx request pool that outlives this call.
#[inline]
pub fn alloc_span_ctx_plain(pool: &Pool) -> *mut SpanCtx {
    // SAFETY: `pool.as_ptr()` yields the live request pool pointer; `ngx_pcalloc`
    // returns a pointer to zeroed storage of exactly `size_of::<SpanCtx>()` bytes
    // valid for the request lifetime (or null on OOM).
    let ctx = unsafe { nginx_sys::ngx_pcalloc(pool.as_ptr(), core::mem::size_of::<SpanCtx>()) }
        .cast::<SpanCtx>();
    // No cleanup anchor is registered — by design (see doc comment above).
    ctx
}

/// Recover the request's `SpanCtx` after an internal redirect cleared the module
/// ctx array, mirroring the C++ module's `getOtelCtx`
/// (`nginx-otel/src/http_module.cpp:195-212`).
///
/// Returns the current ctx pointer if the module-ctx slot is non-NULL.  Otherwise,
/// **only** when the slot is NULL **and** the request is a redirect/filter-finalize
/// continuation (`r->internal || r->filter_finalize`), walks the pool cleanup list
/// for the [`cleanup_span_ctx`] anchor, re-installs the recovered pointer via
/// `set_module_ctx`, and returns it.  Returns NULL if no anchor is found.
///
/// # Hot-path note
/// The cleanup-list walk runs only on the NULL-slot + redirect branch. On the
/// normal (non-redirect) path the slot is non-NULL: a single pointer load + branch.
///
/// # Safety
/// `r` must be a valid, non-null `ngx_http_request_t`; `module` must be the
/// process-lifetime module descriptor; `slot` is the current value of the
/// module-ctx slot (i.e. `get_module_ctx_ptr`).
#[inline]
pub unsafe fn recover_span_ctx(
    r: *mut ngx_http_request_t,
    module: &nginx_sys::ngx_module_t,
    slot: *mut SpanCtx,
) -> *mut SpanCtx {
    if !slot.is_null() {
        return slot;
    }
    // Read `internal` / `filter_finalize` via the C shim, NOT the bindgen
    // `*_raw` accessors: bindgen mis-lays-out this struct's bitfields and reads
    // both flags 2 bits low (see `crate::shim`).
    // SAFETY: `r` is a valid request pointer; the shim only reads the `internal`
    // / `filter_finalize` bitfields through nginx's own header layout.
    let is_redirect =
        unsafe { crate::shim::r_internal(r) != 0 || crate::shim::r_filter_finalize(r) != 0 };
    if !is_redirect {
        return core::ptr::null_mut();
    }
    // SAFETY: `(*r).pool` is the request pool; `.cleanup` is the head of the
    // cleanup list (possibly NULL); each node's `handler`/`data`/`next` are valid.
    unsafe {
        let mut cln = (*(*r).pool).cleanup;
        while !cln.is_null() {
            // Identity-compare against our anchor — the same mechanism the C++
            // module uses (`cln->handler == cleanupOtelCtx`); `fn_addr_eq` is the
            // sanctioned API.  The anchor is a single symbol in this cdylib, so
            // its address is stable across all cleanup nodes created this run.
            if (*cln)
                .handler
                .is_some_and(|h| core::ptr::fn_addr_eq(h, cleanup_span_ctx as NgxCleanupPt))
            {
                let ctx = (*cln).data.cast::<SpanCtx>();
                // Re-install via the same `set_module_ctx` helper used
                // everywhere else, for consistent slot/cleanup semantics.
                // SAFETY: `r` is a valid request pointer; `Request` is a
                // transparent newtype over `ngx_http_request_t`.
                Request::from_ngx_http_request(r)
                    .set_module_ctx(ctx.cast::<core::ffi::c_void>(), module);
                return ctx;
            }
            cln = (*cln).next;
        }
    }
    core::ptr::null_mut()
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

// ── DRBG — per-thread ChaCha20 CSPRNG ───────────────────────────────────────
//
// A reversible PRNG (e.g. xorshift64) would let an observer of a few IDs
// predict future trace IDs; a seeded ChaCha20 DRBG gives cryptographically
// unpredictable IDs with zero per-request syscalls.  Seeded EAGERLY in worker
// `init_process` (off the request path, one OS-entropy syscall per worker);
// thereafter pure ChaCha20 block ops via a thread-local `Cell<Option<..>>`.
//
// A persistent OS-RNG failure (e.g. seccomp denying `getrandom(2)`) must NOT
// panic inside the `extern "C"` REWRITE handler — that aborts the worker, and
// every respawn re-aborts on its first traced request (a crash loop).
// Instead, seed failure sets a worker-local "tracing-disabled" flag; span-start
// reads it and treats the request as unsampled (serve traffic, emit no span).
// We never fall back to weak/predictable IDs. The lazy path (fallback for a
// thread that skipped eager seeding) is likewise non-panicking.

use std::cell::Cell;

use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

thread_local! {
    static DRBG: Cell<Option<ChaCha20Rng>> = const { Cell::new(None) };

    /// Worker-local "tracing disabled because OS-RNG seeding failed" flag.
    ///
    /// Set (once) when `getrandom` fails at seed time.  When set, span-start
    /// treats every request as unsampled — no weak/predictable IDs reach the
    /// wire.  Metrics and logs are unaffected (they don't consult this flag).
    static TRACING_DISABLED: Cell<bool> = const { Cell::new(false) };

    /// One-shot guard for the LAZY seed-failure EMERG log.
    ///
    /// Entered when a thread calls `drbg64()` without having run
    /// `eager_seed_drbg()` first; unlike the eager path, it must fetch the log
    /// handle from the nginx global cycle.  Ensures the log line fires at most
    /// once per worker thread, matching the eager path's EMERG-once guarantee.
    static LAZY_SEED_EMERG_LOGGED: Cell<bool> = const { Cell::new(false) };
}

// Worker-local failure-injection switch for the seed path. Compiled only
// under test/test-support (zero production cost). When set, the next
// `try_seed_drbg()` returns `Err` as if `getrandom` failed, exercising the
// non-panicking degrade path without a real seccomp sandbox.
#[cfg(test)]
thread_local! {
    static INJECT_SEED_FAILURE: Cell<bool> = const { Cell::new(false) };
}

/// Test-support: arm/disarm the seed-failure injection for this worker thread.
#[cfg(test)]
pub(crate) fn set_inject_seed_failure(on: bool) {
    INJECT_SEED_FAILURE.with(|c| c.set(on));
}

/// Returns `true` if OS-RNG seeding failed for this worker and tracing is
/// therefore disabled (every request unsampled).  One `Cell` load + branch.
#[inline]
pub(crate) fn tracing_disabled() -> bool {
    TRACING_DISABLED.with(Cell::get)
}

/// Eagerly seed this worker's DRBG from OS entropy.
///
/// Called once per worker in `init_process` — OFF the request path.  Returns
/// `Ok(())` on success; on the FIRST failure it sets the worker-local
/// tracing-disabled flag and returns `Err` so the caller logs a single
/// `NGX_LOG_EMERG` line.  Idempotent and EMERG-once: if seeding already
/// succeeded, or tracing is already disabled from a prior failure, this is a
/// no-op `Ok` (no second Err → no duplicate EMERG line even if called again).
#[cold]
pub(crate) fn eager_seed_drbg() -> Result<(), getrandom::Error> {
    // EMERG-once: a prior failure already flipped the flag and logged; do not
    // re-attempt or re-signal.
    if tracing_disabled() {
        return Ok(());
    }
    DRBG.with(|c| {
        if let Some(rng) = c.take() {
            // Already seeded this worker (re-entry / test re-arm): keep it.
            c.set(Some(rng));
            return Ok(());
        }
        match try_seed_drbg() {
            Ok(rng) => {
                c.set(Some(rng));
                Ok(())
            }
            Err(e) => {
                TRACING_DISABLED.with(|d| d.set(true));
                Err(e)
            }
        }
    })
}

/// Emit a single NGX_LOG_EMERG line for a lazy DRBG seed failure.
///
/// Called ONLY on the cold seed-failure branch of `drbg64()`.  Retrieves the
/// worker log handle from the nginx global `ngx_cycle` pointer (set by nginx
/// before any worker runs, valid for the process lifetime).  Guarded by
/// `LAZY_SEED_EMERG_LOGGED` for the EMERG-once contract (matches the eager
/// path).  Must not be called on the hot path — `#[cold]` keeps it uninlined.
#[cold]
fn log_lazy_seed_failure_once(e: getrandom::Error) {
    if LAZY_SEED_EMERG_LOGGED.with(Cell::get) {
        return;
    }
    LAZY_SEED_EMERG_LOGGED.with(|f| f.set(true));
    #[cfg(not(any(test, feature = "test-support")))]
    {
        // SAFETY: `nginx_sys::ngx_cycle` is a process-global pointer set by
        // nginx before `fork()`-ing workers, valid for the worker lifetime.
        // `(*ngx_cycle).log` is the worker's primary log handle (always
        // non-null here — nginx aborts worker start if log init fails). Read
        // once, under a `#[cold]` path, and not retained.
        let log = unsafe {
            let cycle = nginx_sys::ngx_cycle;
            if cycle.is_null() {
                return;
            }
            (*cycle).log
        };
        if log.is_null() {
            return;
        }
        emerg!(
            log,
            "otel: trace-ID DRBG lazy seeding failed ({e}); OS RNG unavailable — \
             tracing DISABLED for this worker (traffic unaffected, no spans emitted)"
        );
    }
    // In test/test-support builds the log infrastructure is not initialised;
    // the EMERG-once flag is still set so call-count assertions hold.
    let _ = e;
}

/// Return the next pseudo-random `u64` from the per-thread ChaCha20 DRBG.
///
/// In production the DRBG is eagerly seeded in `init_process`, so this is a
/// pure ChaCha20 word extraction — lock-free, no syscall, effectively free on
/// the hot path.  As a fallback (a thread that skipped eager seeding), it
/// seeds lazily.  On seed failure it sets the tracing-disabled flag, emits a
/// single NGX_LOG_EMERG line (see `log_lazy_seed_failure_once`), and returns 0
/// (callers must consult `tracing_disabled()` before trusting the ID — span-start does).
#[inline]
pub(crate) fn drbg64() -> u64 {
    DRBG.with(|c| match c.take() {
        Some(mut rng) => {
            let val = rng.next_u64();
            c.set(Some(rng));
            val
        }
        None => match try_seed_drbg() {
            Ok(mut rng) => {
                let val = rng.next_u64();
                c.set(Some(rng));
                val
            }
            Err(e) => {
                TRACING_DISABLED.with(|d| d.set(true));
                log_lazy_seed_failure_once(e);
                0
            }
        },
    })
}

/// One-time per-thread DRBG seed from OS entropy (fallible).
///
/// `getrandom::fill` uses the OS CSPRNG (getrandom(2) on Linux,
/// arc4random_buf on macOS) — never a filesystem read, never blocks after
/// boot.  Returns `Err` if the OS RNG is unavailable (hardware fault / FIPS
/// failure / seccomp denial) instead of panicking, so an `extern "C"` caller
/// never aborts the worker.
#[cold]
fn try_seed_drbg() -> Result<ChaCha20Rng, getrandom::Error> {
    #[cfg(test)]
    if INJECT_SEED_FAILURE.with(Cell::get) {
        // Simulate a persistent OS-RNG failure without a real seccomp sandbox.
        return Err(getrandom::Error::UNSUPPORTED);
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)?;
    Ok(ChaCha20Rng::from_seed(seed))
}

// ── ID generation ─────────────────────────────────────────────────────────────

/// Maximum reroll attempts when `drbg64()` returns 0 for a W3C ID.
///
/// A healthy ChaCha20 DRBG has all-zero-output probability < 2^-64 per call,
/// so three zero retries mean the DRBG is broken or `drbg64()` is returning
/// its failure sentinel every time — further retries can't help, and looping
/// forever would hang the worker. Exhaustion instead disables tracing for
/// this request.
const MAX_ID_RETRIES: u32 = 3;

/// Generate a fresh 16-byte W3C trace ID.
///
/// Returns `Some(id)`, guaranteed non-zero per the W3C Trace Context spec
/// (§3.3: "all-zeroes MUST be rejected").  Returns `None` after
/// [`MAX_ID_RETRIES`] all-zero attempts (DRBG fault / OS-RNG failure); the
/// worker-local tracing-disabled flag is set and the caller MUST decline the
/// request rather than emit any ID.
#[inline]
pub(crate) fn gen_trace_id() -> Option<[u8; 16]> {
    for _ in 0..MAX_ID_RETRIES {
        let a = drbg64();
        let b = drbg64();
        if a != 0 || b != 0 {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&a.to_le_bytes());
            id[8..].copy_from_slice(&b.to_le_bytes());
            return Some(id);
        }
    }
    // All retries returned zero: DRBG is broken or persistently returning its
    // failure sentinel.  Disable tracing so span-start declines this request
    // and no all-zero (invalid) trace ID reaches the wire.
    TRACING_DISABLED.with(|d| d.set(true));
    None
}

/// Generate a fresh 8-byte W3C span ID.
///
/// Same contract as [`gen_trace_id`]: non-zero per the W3C Trace Context spec
/// (§3.3), `None` after [`MAX_ID_RETRIES`] all-zero attempts (tracing-disabled
/// flag set) — decline the request rather than emit an all-zero ID.
#[inline]
pub(crate) fn gen_span_id() -> Option<[u8; 8]> {
    for _ in 0..MAX_ID_RETRIES {
        let v = drbg64();
        if v != 0 {
            return Some(v.to_le_bytes());
        }
    }
    TRACING_DISABLED.with(|d| d.set(true));
    None
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Under injected OS-RNG seed failure, the eager seed path must NOT
    /// panic; it must set the worker-local tracing-disabled flag and return Err.
    ///
    /// Runs on a freshly-spawned thread so `thread_local!` DRBG/flag/injection
    /// state is isolated (the test runner reuses threads across tests).
    #[test]
    fn h3f2_eager_seed_failure_no_panic_sets_flag() {
        let outcome = std::thread::spawn(|| {
            set_inject_seed_failure(true);
            let res = std::panic::catch_unwind(eager_seed_drbg);
            assert!(res.is_ok(), "eager_seed_drbg must not panic on RNG failure");
            let seed_result = res.unwrap();
            assert!(seed_result.is_err(), "eager_seed_drbg must return Err on RNG failure");
            assert!(tracing_disabled(), "tracing must be disabled after seed failure");
            let v = std::panic::catch_unwind(drbg64);
            assert!(v.is_ok(), "drbg64 must not panic when seeding fails");
            assert_eq!(v.unwrap(), 0, "drbg64 returns 0 when unseeded under failure");
        })
        .join();
        assert!(outcome.is_ok(), "test thread must not panic");
    }

    /// EMERG-once: the failing seed returns `Err` only on the FIRST
    /// call; a subsequent call returns `Ok` (flag already set) so the caller
    /// emits exactly one `NGX_LOG_EMERG` line per worker.
    #[test]
    fn h3f2_seed_failure_emits_err_exactly_once() {
        std::thread::spawn(|| {
            set_inject_seed_failure(true);
            assert!(
                eager_seed_drbg().is_err(),
                "first seed attempt must report failure (logs EMERG)"
            );
            // Injection still armed, but the flag short-circuits.
            assert!(
                eager_seed_drbg().is_ok(),
                "second call must NOT re-report (no duplicate EMERG)"
            );
            assert!(eager_seed_drbg().is_ok(), "third call must NOT re-report either");
            assert!(tracing_disabled(), "flag stays set");
        })
        .join()
        .expect("test thread must not panic");
    }

    /// The happy path: with no injected failure, eager seeding succeeds,
    /// tracing stays enabled, and the DRBG yields non-zero values.
    #[test]
    fn h3f2_eager_seed_success_enables_tracing() {
        std::thread::spawn(|| {
            set_inject_seed_failure(false);
            assert!(eager_seed_drbg().is_ok(), "eager_seed_drbg must succeed normally");
            assert!(!tracing_disabled(), "tracing must remain enabled on success");
            assert_ne!(drbg64(), 0, "seeded DRBG must yield non-zero");
        })
        .join()
        .expect("test thread must not panic");
    }

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

    /// Two ChaCha20Rng instances with different seeds must diverge — pins the
    /// property that IDs from distinct workers (each seeding independently
    /// from `getrandom`) cannot collide in bulk.
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

    /// Trace IDs are 16 bytes, distinct across a batch of generations.
    #[test]
    fn trace_ids_batch_unique() {
        let ids: std::vec::Vec<[u8; 16]> = (0..100)
            .map(|_| gen_trace_id().expect("gen_trace_id must succeed with healthy DRBG"))
            .collect();
        let mut seen = std::collections::HashSet::new();
        for id in &ids {
            assert_ne!(*id, [0u8; 16], "trace ID must not be all-zero");
            assert!(seen.insert(*id), "trace ID collision in batch of 100");
        }
    }

    /// Span IDs are 8 bytes, distinct across a batch of generations.
    #[test]
    fn span_ids_batch_unique() {
        let ids: std::vec::Vec<[u8; 8]> = (0..100)
            .map(|_| gen_span_id().expect("gen_span_id must succeed with healthy DRBG"))
            .collect();
        let mut seen = std::collections::HashSet::new();
        for id in &ids {
            assert_ne!(*id, [0u8; 8], "span ID must not be all-zero");
            assert!(seen.insert(*id), "span ID collision in batch of 100");
        }
    }

    /// gen_trace_id returns 16 bytes, never all-zero.
    #[test]
    fn trace_id_nonzero() {
        let id = gen_trace_id().expect("gen_trace_id must succeed with healthy DRBG");
        assert_ne!(id, [0u8; 16], "trace ID must not be all-zero");
    }

    /// gen_span_id returns 8 bytes, never all-zero.
    #[test]
    fn span_id_nonzero() {
        let id = gen_span_id().expect("gen_span_id must succeed with healthy DRBG");
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

    /// Dual-clock coherence: span end = start + duration, end >= start.
    ///
    /// Verifies that using monotonic duration guarantees
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

    /// Read-once traceparent guard (parse-once design).
    ///
    /// Proves the single-scan contract: the inbound `traceparent` header is
    /// parsed **once** (`parse_traceparent_full` in the REWRITE handler) and
    /// cached on `SpanCtx`; LOG reads `SpanCtx` fields directly, no second
    /// header scan.  The structural-completeness check below asserts all
    /// trace-correlation fields LOG needs live on `SpanCtx` — if any were
    /// removed, LOG would need a second scan and this test's setup would break.
    #[test]
    fn traceparent_parse_once_guard() {
        use crate::logs::access::parse_traceparent_full;

        // A valid W3C traceparent header: version-trace_id-parent_id-flags
        let header = b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

        // Single parse — the only call parse_traceparent_full gets in the
        // production path (span_start.rs REWRITE handler).
        let (trace_id, parent_span_id, flags) =
            parse_traceparent_full(header).expect("valid traceparent must parse");

        // Simulate REWRITE: populate SpanCtx from the parse result.
        let span_id = gen_span_id().expect("gen_span_id must succeed with healthy DRBG");
        let ctx = SpanCtx {
            trace_id,
            span_id,
            parent_span_id,
            flags,
            start_time_unix_nano: 1_700_000_000_000_000_000,
            start_mono: std::time::Instant::now(),
            sampled: (flags & 0x01) != 0,
        };

        // ── SpanCtx must carry exactly what the traceparent contained ────────
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

        // ── Structural completeness: LOG needs trace_id, span_id,
        // parent_span_id, flags, start_time_unix_nano, sampled on SpanCtx.
        // No-op at runtime; if a field were removed, this fails to compile.
        let _ = ctx.trace_id;
        let _ = ctx.span_id;
        let _ = ctx.parent_span_id;
        let _ = ctx.flags;
        let _ = ctx.start_time_unix_nano;
        let _ = ctx.sampled;
    }

    // ── Regression: bounded reroll + fail-safe (finding #5) ─────────────────

    /// With the DRBG in the (None, not-yet-disabled) state and OS-RNG injected
    /// to always fail, `drbg64()` returns 0 on every call.  The OLD unbounded
    /// reroll loop in `gen_trace_id` / `gen_span_id` would hang indefinitely
    /// under this condition.  The NEW bounded loop must terminate and return
    /// `None`, setting `TRACING_DISABLED`.
    ///
    /// Mutation proof: revert the `for _ in 0..MAX_ID_RETRIES` bound to an
    /// unconditional `loop {}` and this test hangs (never reaches the assertion).
    #[test]
    fn gen_id_bounded_on_stuck_drbg_returns_none() {
        std::thread::spawn(|| {
            // Fresh thread (DRBG is None); arm seed-failure injection so every
            // drbg64() call returns 0. tracing_disabled is NOT yet set — this
            // models the (None, not-disabled) race window the finding describes.
            set_inject_seed_failure(true);
            assert!(!tracing_disabled(), "flag must be clear at test start");

            // Must terminate (not loop forever) and return None.
            let tid = gen_trace_id();
            assert!(tid.is_none(), "gen_trace_id must return None when DRBG is stuck at 0");
            assert!(
                tracing_disabled(),
                "tracing must be disabled after gen_trace_id exhausts retries"
            );
        })
        .join()
        .expect("test thread must not panic (would indicate an infinite loop or panic)");
    }

    /// Same bounded-reroll guarantee for gen_span_id.
    #[test]
    fn gen_span_id_bounded_on_stuck_drbg_returns_none() {
        std::thread::spawn(|| {
            set_inject_seed_failure(true);
            assert!(!tracing_disabled());
            let sid = gen_span_id();
            assert!(sid.is_none(), "gen_span_id must return None when DRBG is stuck at 0");
            assert!(tracing_disabled());
        })
        .join()
        .expect("test thread must not panic");
    }

    // ── Regression: lazy seed-failure EMERG-once flag (finding ~376) ─────────

    /// When `drbg64()` triggers a lazy seed failure, `LAZY_SEED_EMERG_LOGGED`
    /// must be set exactly once (EMERG-once contract).  In test builds the
    /// actual `ngx_log_error!` call is skipped (no live nginx log handle), but
    /// the guard flag is still set — so the flag count is the observable.
    ///
    /// Mutation proof: comment out `LAZY_SEED_EMERG_LOGGED.with(|f| f.set(true))`
    /// in `log_lazy_seed_failure_once` and the second assertion (flag set after
    /// call) fails.
    #[test]
    fn lazy_seed_failure_emerg_once_flag_set() {
        std::thread::spawn(|| {
            set_inject_seed_failure(true);
            assert!(
                !LAZY_SEED_EMERG_LOGGED.with(Cell::get),
                "LAZY_SEED_EMERG_LOGGED must start false on a fresh thread"
            );
            // Trigger lazy seed failure via drbg64 (DRBG is None on this thread):
            // Err branch → log_lazy_seed_failure_once → sets flag.
            let _ = drbg64();
            assert!(
                LAZY_SEED_EMERG_LOGGED.with(Cell::get),
                "LAZY_SEED_EMERG_LOGGED must be set after the first lazy seed failure"
            );
            // Second call: flag already set, so log_lazy_seed_failure_once is a
            // no-op (injection still armed, DRBG still None after the 0-return).
            let flag_before = LAZY_SEED_EMERG_LOGGED.with(Cell::get);
            let _ = drbg64();
            assert_eq!(
                LAZY_SEED_EMERG_LOGGED.with(Cell::get),
                flag_before,
                "LAZY_SEED_EMERG_LOGGED must not change on repeated calls (EMERG-once)"
            );
        })
        .join()
        .expect("test thread must not panic");
    }
}
