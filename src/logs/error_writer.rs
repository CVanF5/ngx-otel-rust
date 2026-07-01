// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! OTel error-log writer — `ngx_log_writer_pt` implementation.
//!
//! # Architecture
//!
//! The writer is inserted into nginx's `cycle->new_log` chain as a
//! writer-only node (no `file`). `ngx_log_error_core` formats the full line
//! once, walks the chain, and calls each writer; the core file node
//! (operator's own `error_log`) still writes since the chain walk continues
//! after ours returns.
//!
//! ## Hot-path disciplines (non-negotiable)
//! - **Alloc-free / lock-free** — no heap allocation; all shared state is atomic.
//! - **Re-entrancy-safe** — the busy-flag swap drops re-entrant calls; the
//!   writer fires from signal handlers and OOM paths.
//! - **No logging from the writer** — would cause re-entrancy.
//! - **No request-context deref** — `log->wdata` is our own `OtelErrorWriterState`,
//!   not a request context.
//!
//! ## Multi-origin guard
//! The writer is woven into the chain before workers fork. A process-role
//! guard (`exporter::ngx_process() == Worker`) makes it a no-op in
//! master/config-load/exporter contexts.
//!
//! ## Verbatim opt-out (`otel_error_log_coalesce off`)
//! Best-effort, NOT guaranteed delivery: verbatim mode pushes every
//! level-passing line to the bounded ring; under load the ring drops-newest
//! (accounted in `dropped_records`). The guaranteed full-fidelity transcript
//! is nginx's own (untouched) `error_log` file.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use nginx_sys::{ngx_shm_zone_t, ngx_uint_t};

use crate::logs::coalesce::{self, CoalesceResult, CoalesceSlot};
use crate::logs::ring::WorkerSignalRing;

// ── RAII busy-flag guard ──────────────────────────────────────────────────────

/// RAII guard that clears the `busy` flag on drop.
///
/// Created after successfully acquiring `busy` (`busy.swap(true, Acquire)`
/// returned `false`). Guarantees the flag is released on BOTH the normal
/// return path AND on a caught panic — preventing a permanent wedge that
/// would silence all future error-log emissions from this worker.
///
/// Without this guard, a panic inside the writer body (`unsafe extern "C"`
/// context) would either unwind across the FFI boundary (UB per Rust
/// Reference §"FFI and unwinding" / RFC 2945) or abort the process (only if
/// `panic = "abort"`, which this crate does NOT set).
///
/// Used together with `std::panic::catch_unwind` to contain future panics
/// safely (see `ngx_otel_error_writer`). Declared before the writer so the
/// compiler can verify the `Drop` impl is reachable from that closure.
struct BusyGuard(*mut AtomicBool);

// SAFETY: `BusyGuard` holds a raw pointer that is only ever created pointing
// at an `AtomicBool` field inside an `OtelErrorWriterState` (pool-allocated,
// never moved). The guard is created, used, and dropped entirely within the
// single `ngx_otel_error_writer` call, single-threaded per the re-entrancy
// guard, so the raw-pointer access from `Drop::drop` is sound.
unsafe impl Send for BusyGuard {}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid `*mut AtomicBool` pointing into
        // `OtelErrorWriterState::busy` (invariant upheld by the single
        // constructor call site in `ngx_otel_error_writer`).
        unsafe { (*self.0).store(false, Ordering::Release) };
    }
}

// ── Error-ring wire-format constants ─────────────────────────────────────────

/// Kind byte for error-log ring records (0x01; access records use 0x00).
pub const KIND_ERROR: u8 = 0x01;

/// Fixed header size for an error-log ring record, in bytes: 1(kind) +
/// 8(ts_unix_nano) + 1(ngx_level) + 8(template_hash) + 2(body_len) = 20.
/// Single-homed here; the exporter's `parse_error_record` min-length guard and
/// the two test helpers both import this constant.
pub const ERROR_RECORD_HDR: usize = 20; // 1 + 8 + 1 + 8 + 2

/// Maximum bytes of error-message body stored per ring record. Nginx error
/// messages (client address, request line, upstream address) are well under
/// 512 bytes in practice; this cap prevents pathological messages from
/// blowing out the ring.
pub const MAX_ERROR_BODY_LEN: usize = 512;

// ── OtelErrorWriterState ──────────────────────────────────────────────────────

/// Per-writer state allocated from `cf->pool` by `cmd_set_error_log`.
///
/// Lives for the lifetime of the nginx cycle (pool-allocated, never freed
/// while nginx is running). Zeroed by `ngx_pcalloc`; `false`/`null`/`0`
/// defaults are correct.
///
/// # Safety invariants
/// - `logs_zone` is null until `init_process` maps the logs shm; the writer
///   checks non-null before touching the zone.
/// - `busy` and `cleanup` are only ever set/cleared atomically.
/// - The struct must NOT be moved after allocation (raw pointer in `log->wdata`).
#[repr(C)]
pub struct OtelErrorWriterState {
    /// Re-entrancy guard: set while the writer is executing.
    /// A concurrent or re-entrant call (signal handler, OOM path) that
    /// finds `busy == true` drops immediately without touching shared state.
    pub busy: AtomicBool,
    /// Cycle-teardown flag: set via `set_cleanup_flag` on the exit path BEFORE
    /// `cycle->log` is torn down.  Late emissions after teardown are dropped.
    pub cleanup: AtomicBool,
    /// Effective severity floor (from the directive or mirrored from core).
    /// nginx levels are inverted: 1=emerg, 2=alert, 3=crit, 4=error,
    /// 5=warn, 6=notice, 7=info, 8=debug.
    /// `level > level_floor` ⇒ less severe than the threshold ⇒ drop.
    pub level_floor: ngx_uint_t,
    /// The logs shm zone pointer (set by `init_process`; null until then).
    /// Used by the coalescer and error-rate metric.
    pub logs_zone: *mut ngx_shm_zone_t,
    /// Pre-computed pointer to this worker's coalescer table within the logs
    /// shm zone. Set by `init_process` alongside `coalesce_enabled`; the
    /// coalescer path is a no-op until this is non-null.
    pub coalesce_table: *mut CoalesceSlot,
    /// Mirrors `MainConfig::error_log_coalesce`. Set by `init_process`;
    /// default false ("no coalescing") until then.
    pub coalesce_enabled: bool,
    /// Pre-computed pointer to the start of the **error ring** header for this
    /// worker (within the logs shm zone). Set by `init_process` alongside
    /// `coalesce_table`; null until then, writer silently skips the ring push.
    ///
    /// SAFETY invariant: non-null ⇒ valid for `ring_size_bytes(cap)` bytes in
    /// the logs shm zone, lives at least as long as the worker process.
    pub error_ring_ptr: *mut u8,
    /// Pre-computed pointer to `WorkerSlots::error_rate_counters[0]` for this
    /// worker in the metrics shm zone. Set by `init_process`; null until
    /// then (metric bump is a no-op). Array has `N_SEVERITY_CLASSES`
    /// elements, indexed by `crate::shm::severity_class_index(ngx_level as u8)`.
    ///
    /// SAFETY invariant: non-null ⇒ valid for `N_SEVERITY_CLASSES × 8` bytes,
    /// aligned to 8 bytes, in the metrics shm zone.
    pub error_rate_ptr: *mut AtomicU64,
}

// SAFETY: OtelErrorWriterState lives in nginx-managed pool memory and is
// accessed only from within the nginx event loop or from signal handlers
// (which the busy-flag already guards). The raw pointer field (`logs_zone`)
// is set once before workers start and never moved.
unsafe impl Send for OtelErrorWriterState {}
// SAFETY: as for the `Send` impl above — access is confined to the
// single-threaded event loop and busy-flag-guarded signal handlers, and the
// shared state is atomics, so concurrent `&` access is sound.
unsafe impl Sync for OtelErrorWriterState {}

// ── Error-log writer ──────────────────────────────────────────────────────────

/// `ngx_log_writer_pt` callback: our node in the `cycle->log` chain.
///
/// Called by `ngx_log_error_core` after it has formatted the full error line
/// into `buf[..len]`:
/// ```text
/// <cached-time> [<level>] <pid>#<tid>: [*<conn>] <core-msg>(<errno>)[, client:/request:/upstream:/host:]
/// ```
/// (ngx_log.c:155–188, ngx_http_request.c:4058–4086)
///
/// # Filter order (cheapest first)
/// 1. Cleanup flag — drop if cycle is tearing down.
/// 2. Busy flag — drop re-entrant / concurrent calls.
/// 3. Severity floor — drop if `level > level_floor`.
/// 4. Process-role guard: Worker + logs shm mapped.
/// 5. Error-rate metric bump: every floor-passing event.
/// 6. Coalescer / verbatim push.
///
/// # Safety
/// `log` must be a non-null pointer to an `ngx_log_t` whose `wdata` is a
/// non-null pointer to an `OtelErrorWriterState` allocated by `cmd_set_error_log`.
pub unsafe extern "C" fn ngx_otel_error_writer(
    log: *mut nginx_sys::ngx_log_t,
    level: ngx_uint_t,
    buf: *mut nginx_sys::u_char,
    len: usize,
) {
    let state = (*log).wdata as *mut OtelErrorWriterState;

    // 1. Cycle teardown guard: drop late emissions after cleanup.
    //    Checked before busy so a late post-cleanup call never sets busy.
    if (*state).cleanup.load(Ordering::Acquire) {
        return;
    }

    // 2. Re-entrancy guard: drop if already executing (signal handler / OOM).
    //    `swap(true, Acquire)` returns the OLD value; `true` ⇒ already busy.
    if (*state).busy.swap(true, Ordering::Acquire) {
        return;
    }

    // RAII guard: clears `busy` on drop regardless of how this scope exits,
    // including a caught panic (see `catch_unwind` below).
    //
    // SAFETY: `state` is a valid, non-null `*mut OtelErrorWriterState` for the
    // duration of this call (pool-allocated, never freed while nginx runs).
    // `busy` is a field of that struct; the raw pointer into it is valid for
    // the same lifetime.
    let _guard = BusyGuard(core::ptr::addr_of_mut!((*state).busy));

    // Wrap the writer body in `catch_unwind`: an unexpected panic unwinding
    // across the `extern "C"` boundary is UB (Rust Reference "Unwinding" §;
    // RFC 2945 "C-unwind ABI"). `AssertUnwindSafe` is sound here because all
    // shared state is accessed through atomics (no `&mut` aliases), and a
    // panic is already a logic error — dropping the record is the
    // least-bad safe outcome (the operator's own `error_log` is unaffected;
    // the core chain node runs after us). `_guard` drops when this function
    // returns, releasing `busy`.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: all pointer dereferences below are safe within this closure
        // because `state` points to an `OtelErrorWriterState` that is valid for
        // the duration of this call, and `buf` is valid for `len` bytes per
        // the `ngx_log_error_core` caller contract.
        unsafe {
            // 3. Severity floor: nginx levels are inverted (1=emerg..8=debug),
            //    so `level > level_floor` means less severe than configured ⇒ drop.
            if level > (*state).level_floor {
                return;
            }

            // 4. Process-role guard: the chain node is inserted before fork, so
            //    the writer fires in EVERY context (master, config-load, workers,
            //    exporter helper), but only Worker has the logs shm mapped and
            //    should touch the ring/coalescer. The exporter is
            //    NGX_PROCESS_HELPER + IS_OTEL_EXPORTER (not Worker) despite also
            //    mapping the shm, so a shm-presence check alone would not exclude it.
            if !matches!(crate::exporter::ngx_process(), crate::exporter::NgxProcess::Worker(_))
                || (*state).logs_zone.is_null()
            {
                return;
            }

            // 4a. Companion error-rate metric: fires for every floor-passing
            //     event independent of coalescing, counting true event volume
            //     rather than just verbatim samples. No-op until init_process
            //     wires error_rate_ptr.
            let error_rate = (*state).error_rate_ptr;
            if !error_rate.is_null() {
                let idx = crate::shm::severity_class_index(level as u8);
                // Relaxed: no ordering needed vs. the ring push; the exporter
                // reads this counter independently with Acquire.
                (*error_rate.add(idx)).fetch_add(1, Ordering::Relaxed);
            }

            // 5. Coalescer: exact-hash dedup with verbatim exception tail.
            //    No-op (falls through) until init_process sets coalesce_table.
            let coalesce_table = (*state).coalesce_table;
            if !coalesce_table.is_null() {
                // SAFETY: buf is valid for `len` bytes per ngx_log_error_core contract.
                let buf_slice = core::slice::from_raw_parts(buf as *const u8, len);
                match coalesce::coalesce(
                    coalesce_table,
                    level as u8,
                    buf_slice,
                    (*state).coalesce_enabled,
                ) {
                    CoalesceResult::Coalesced => {
                        // Duplicate suppressed; the coalescer already bumped the count.
                    }
                    CoalesceResult::EmitVerbatim { template_hash } => {
                        // error_ring_ptr is null until init_process — skip silently.
                        let ring_ptr = (*state).error_ring_ptr;
                        if !ring_ptr.is_null() {
                            // OTel timestamps are Unix-epoch nanoseconds. Use nginx's
                            // cached WALL-CLOCK (`ngx_cached_time`), NOT `ngx_current_msec`:
                            // the latter is monotonic (boot-relative), so a freshness-windowed
                            // OTLP backend (e.g. Loki rejects entries older than ~1 week) reads
                            // it as 1970 and 400s the whole batch, dropping good records with it.
                            // Mirrors the access path (instrumented.rs: start_sec).
                            // SAFETY: ngx_cached_time is a valid nginx global pointing at the
                            // cached `ngx_time_t`; reading it is signal-safe (cached globals, no
                            // syscall) — same profile as the previous ngx_current_msec read.
                            let ts_ns = cached_unix_nanos(nginx_sys::ngx_cached_time);
                            push_error_record(
                                ring_ptr,
                                ts_ns,
                                level as u8,
                                template_hash,
                                buf_slice,
                            );
                        }
                    }
                }
            }
        } // end unsafe
    })); // end catch_unwind; `_guard` drops here, releasing `busy`
}

/// Unix-epoch nanoseconds from nginx's cached wall-clock (`ngx_time_t`).
///
/// MUST be sourced from `ngx_cached_time` (wall-clock), NOT `ngx_current_msec`
/// (monotonic/boot-relative) — see the call site for the full rationale
/// (a boot-relative value reads as 1970 to a freshness-windowed OTLP backend).
///
/// Returns 0 when `tp` is null (early init / tests with the zeroed stub).
#[inline]
fn cached_unix_nanos(tp: *const nginx_sys::ngx_time_t) -> u64 {
    if tp.is_null() {
        return 0;
    }
    // SAFETY: caller passes a valid `ngx_time_t` pointer — the nginx global in
    // production, or a stack value in tests.
    let tp = unsafe { &*tp };
    (tp.sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add((tp.msec as u64).saturating_mul(1_000_000))
}

// ── Error-ring record push ────────────────────────────────────────────────────

/// Push one error-log record into the per-worker error ring.
///
/// # Wire format
/// ```text
/// [0]      kind      = KIND_ERROR (0x01)
/// [1..9]   ts_ns     u64 big-endian  — Unix-epoch ns from ngx_cached_time
/// [9]      ngx_level u8              — nginx severity level (1=emerg … 8=debug)
/// [10..18] template_hash u64 be     — 0 when untracked (high-sev / coalesce-off /
///                                      table-full)
/// [18..20] body_len  u16 big-endian — capped at MAX_ERROR_BODY_LEN
/// [20..]   body bytes               — the verbatim formatted log line
/// ```
///
/// The stack buffer is 532 bytes (20-byte header + 512-byte body cap); safe on
/// the worker's main stack (≥ 8 MB) and on signal-handler callers, since nginx
/// does not install a sigaltstack for worker processes.
///
/// # Safety
/// `ring_ptr` must be a valid pointer to an initialised `WorkerSignalRingHeader`
/// in the logs shm zone, valid for the duration of this call.
pub unsafe fn push_error_record(
    ring_ptr: *mut u8,
    ts_ns: u64,
    ngx_level: u8,
    template_hash: u64,
    body: &[u8],
) {
    // SAFETY: ring_ptr points to an initialised WorkerSignalRingHeader in shm.
    let ring = unsafe { WorkerSignalRing::from_shm_ptr(ring_ptr) };
    let body_len = body.len().min(MAX_ERROR_BODY_LEN);

    // Build the full wire record on the stack (no heap allocation).
    let mut record = [0u8; ERROR_RECORD_HDR + MAX_ERROR_BODY_LEN];
    record[0] = KIND_ERROR;
    record[1..9].copy_from_slice(&ts_ns.to_be_bytes());
    record[9] = ngx_level;
    record[10..18].copy_from_slice(&template_hash.to_be_bytes());
    record[18..20].copy_from_slice(&(body_len as u16).to_be_bytes());
    record[20..20 + body_len].copy_from_slice(&body[..body_len]);

    // push() returns false on ring-full (accounted in the ring's drop counter).
    ring.push(&record[..ERROR_RECORD_HDR + body_len]);
}

// ── Cleanup-flag wiring ───────────────────────────────────────────────────────

/// Walk the `cycle->new_log` chain and set `cleanup = true` on every
/// `OtelErrorWriterState` node (identified by `writer == ngx_otel_error_writer`).
///
/// Called from `ngx_otel_exit_process` to stop new emissions before the nginx
/// cycle tears down its log infrastructure. After this returns, any call to
/// the writer exits immediately at the cleanup-flag check without touching
/// the ring or the coalescer.
///
/// # Safety
/// `cycle` must be a valid non-null pointer to the current nginx cycle.
pub unsafe fn set_cleanup_flag(cycle: *const nginx_sys::ngx_cycle_t) {
    if cycle.is_null() {
        return;
    }
    // new_log is an *embedded* ngx_log_t (chain head); take a raw pointer so
    // we can walk it via ->next.
    let mut log_ptr: *mut nginx_sys::ngx_log_t = core::ptr::addr_of!((*cycle).new_log) as *mut _;

    // Compare as usize to identify our writer node: direct fn-pointer equality
    // triggers `unpredictable_function_pointer_comparisons`; the fn-pointer
    // binding also avoids the "direct cast of function item" lint.
    let our_writer: unsafe extern "C" fn(
        *mut nginx_sys::ngx_log_t,
        ngx_uint_t,
        *mut nginx_sys::u_char,
        usize,
    ) = ngx_otel_error_writer;
    let our_writer_addr = our_writer as usize;

    while !log_ptr.is_null() {
        let log = &*log_ptr;
        // Identify our node by the writer function-pointer address.
        if log.writer.map(|f| f as usize) == Some(our_writer_addr) {
            let state = log.wdata as *mut OtelErrorWriterState;
            if !state.is_null() {
                // Release: pair with the Acquire load at the top of ngx_otel_error_writer.
                (*state).cleanup.store(true, Ordering::Release);
            }
        }
        log_ptr = log.next;
    }
}

// ── Init-process wiring ──────────────────────────────────────────────────────

/// Walk `cycle->new_log` and populate `OtelErrorWriterState` with the three
/// pre-computed shm pointers (coalescer table, error ring, error-rate counter
/// base) plus the runtime `coalesce_enabled` flag.
///
/// Called from `ngx_otel_init_process` in `lib.rs` after verifying the process
/// is a `Worker` and the logs shm zone is mapped. The pointers are null until
/// this call; the writer silently skips the affected paths while null
/// (belt-and-suspenders for the process-role guard, which also gates them).
///
/// # Pointer meanings
/// - `logs_zone`: the `ngx_shm_zone_t *` for the logs shm; stored so the
///   process-role guard can confirm the zone is live.
/// - `coalesce_table`: `*mut CoalesceSlot` for this worker's 256-entry table.
/// - `error_ring_ptr`: `*mut u8` pointing to the error ring header for this worker.
/// - `error_rate_ptr`: `*mut AtomicU64` = `&WorkerSlots::error_rate_counters[0]`
///   for this worker in the metrics shm zone.
/// - `coalesce_enabled`: mirrors `MainConfig::error_log_coalesce`.
///
/// # Safety
/// - `cycle` must be a valid, non-null pointer to the current nginx cycle.
/// - All pointer arguments must be valid for the lifetime of the worker process.
/// - Must be called at most once per worker per cycle (nginx init_process contract).
pub unsafe fn wire_error_writer_state(
    cycle: *const nginx_sys::ngx_cycle_t,
    logs_zone: *mut nginx_sys::ngx_shm_zone_t,
    coalesce_table: *mut crate::logs::coalesce::CoalesceSlot,
    error_ring_ptr: *mut u8,
    error_rate_ptr: *mut core::sync::atomic::AtomicU64,
    coalesce_enabled: bool,
) {
    if cycle.is_null() {
        return;
    }
    let our_writer: unsafe extern "C" fn(
        *mut nginx_sys::ngx_log_t,
        ngx_uint_t,
        *mut nginx_sys::u_char,
        usize,
    ) = ngx_otel_error_writer;
    let our_writer_addr = our_writer as usize;

    let mut log_ptr: *mut nginx_sys::ngx_log_t = core::ptr::addr_of!((*cycle).new_log) as *mut _;
    while !log_ptr.is_null() {
        let log = &*log_ptr;
        if log.writer.map(|f| f as usize) == Some(our_writer_addr) {
            let state = log.wdata as *mut OtelErrorWriterState;
            if !state.is_null() {
                (*state).logs_zone = logs_zone;
                (*state).coalesce_table = coalesce_table;
                (*state).error_ring_ptr = error_ring_ptr;
                (*state).error_rate_ptr = error_rate_ptr;
                (*state).coalesce_enabled = coalesce_enabled;
            }
        }
        log_ptr = log.next;
    }
}

// ── Chain insertion ───────────────────────────────────────────────────────────

/// Insert `new_log` into the log chain rooted at `head`, sorted descending
/// by `log_level`.
///
/// Rust equivalent of nginx's `static ngx_log_insert` (`ngx_log.c:677–707`),
/// which is not accessible from our module; we replicate its exact logic.
///
/// The head address is kept stable: when `new_log.log_level > head.log_level`,
/// we swap the two nodes' *contents* (not pointers) and update `head->next` —
/// exactly what nginx's own `ngx_log_insert` does, since the head is an
/// embedded value in `ngx_cycle_t::new_log` whose address must not move.
///
/// # Safety
/// - `head` must be a valid, non-null pointer to the chain head (an embedded
///   `ngx_log_t` value in `ngx_cycle_t::new_log`, never null).
/// - `new_log` must be a valid, non-null pointer to a freshly `ngx_pcalloc`'d
///   `ngx_log_t`, not yet part of any chain (`next` is null).
pub unsafe fn otel_log_insert(head: *mut nginx_sys::ngx_log_t, new_log: *mut nginx_sys::ngx_log_t) {
    if (*new_log).log_level > (*head).log_level {
        // New node has higher level: it should be the new head.
        // The head address is permanent (it's an embedded value in ngx_cycle_t),
        // so we swap the *contents* and set head->next to old-head memory.
        core::ptr::swap(head, new_log);
        (*head).next = new_log;
        return;
    }
    // Walk the chain to find the insertion point.
    let mut log = head;
    while !(*log).next.is_null() {
        if (*new_log).log_level > (*(*log).next).log_level {
            (*new_log).next = (*log).next;
            (*log).next = new_log;
            return;
        }
        log = (*log).next;
    }
    // Append at tail.
    (*log).next = new_log;
}

// ── Level parsing ─────────────────────────────────────────────────────────────

/// Parse a nginx log-level name (e.g. `"warn"`) into its `ngx_uint_t` value.
///
/// Matches nginx's `err_levels[]` table (`ngx_log.c:75–85`):
/// emerg=1, alert=2, crit=3, error=4, warn=5, notice=6, info=7, debug=8.
///
/// Returns `None` when the string is not a recognised level name.
pub fn parse_error_log_level(s: &[u8]) -> Option<ngx_uint_t> {
    match s {
        b"emerg" => Some(nginx_sys::NGX_LOG_EMERG as ngx_uint_t),
        b"alert" => Some(nginx_sys::NGX_LOG_ALERT as ngx_uint_t),
        b"crit" => Some(nginx_sys::NGX_LOG_CRIT as ngx_uint_t),
        b"error" => Some(nginx_sys::NGX_LOG_ERR as ngx_uint_t),
        b"warn" => Some(nginx_sys::NGX_LOG_WARN as ngx_uint_t),
        b"notice" => Some(nginx_sys::NGX_LOG_NOTICE as ngx_uint_t),
        b"info" => Some(nginx_sys::NGX_LOG_INFO as ngx_uint_t),
        b"debug" => Some(nginx_sys::NGX_LOG_DEBUG as ngx_uint_t),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicBool;

    /// Build a zeroed `ngx_log_t` and a heap-allocated `OtelErrorWriterState` for testing.
    /// Returns the state (boxed for stable address) and a log node pointing to it.
    fn make_writer_state(
        level_floor: ngx_uint_t,
    ) -> (std::boxed::Box<OtelErrorWriterState>, nginx_sys::ngx_log_t) {
        let state = std::boxed::Box::new(OtelErrorWriterState {
            busy: AtomicBool::new(false),
            cleanup: AtomicBool::new(false),
            level_floor,
            logs_zone: core::ptr::null_mut(),
            // coalesce_table null: coalescer path is dormant in unit tests
            // (no shm available; init_process wires this).
            coalesce_table: core::ptr::null_mut(),
            coalesce_enabled: false,
            // error_ring_ptr null: ring-push path is dormant in unit tests
            // (no logs shm available; init_process wires this).
            error_ring_ptr: core::ptr::null_mut(),
            // error_rate_ptr null: metric-bump path is dormant in unit tests
            // (no metrics shm available; init_process wires this).
            error_rate_ptr: core::ptr::null_mut(),
        });
        // SAFETY: `ngx_log_t` is a plain C struct, so an all-zero bit pattern is
        // a valid initial value (fields are then set explicitly below).
        let mut log: nginx_sys::ngx_log_t = unsafe { core::mem::zeroed() };
        log.writer = Some(ngx_otel_error_writer);
        log.wdata = state.as_ref() as *const _ as *mut core::ffi::c_void;
        (state, log)
    }

    /// A re-entrant call (busy flag already set) returns immediately without
    /// changing state; busy must remain set (caller's responsibility).
    #[test]
    fn busy_flag_blocks_reentry() {
        let (state, mut log) = make_writer_state(nginx_sys::NGX_LOG_DEBUG as ngx_uint_t);
        // Simulate an in-progress writer call.
        state.busy.store(true, Ordering::SeqCst);

        let mut dummy_buf = [0u8; 8];
        // SAFETY: `log` is a valid stack `ngx_log_t` whose `wdata` points to the
        // test's `OtelErrorWriterState` (set in make_writer_state); `dummy_buf` is
        // a valid buffer of `dummy_buf.len()` bytes — satisfies the writer's FFI
        // contract. Single-threaded test.
        unsafe {
            ngx_otel_error_writer(
                &raw mut log,
                nginx_sys::NGX_LOG_ERR as ngx_uint_t,
                dummy_buf.as_mut_ptr(),
                dummy_buf.len(),
            );
        }

        // The busy flag must still be true — re-entrant call did NOT clear it.
        // (The original "caller" owns the flag and will clear it on exit.)
        assert!(state.busy.load(Ordering::SeqCst), "busy flag must stay set");
    }

    /// A below-threshold level is dropped without touching shared state: with
    /// `level_floor = WARN (5)`, an `info (7)` call must exit at the floor check.
    #[test]
    fn level_floor_drops_below_threshold() {
        let (state, mut log) = make_writer_state(nginx_sys::NGX_LOG_WARN as ngx_uint_t);

        let mut dummy_buf = [0u8; 8];
        // SAFETY: `log` is a valid stack `ngx_log_t` whose `wdata` points to the
        // test's `OtelErrorWriterState` (set in make_writer_state); `dummy_buf` is
        // a valid buffer of `dummy_buf.len()` bytes — satisfies the writer's FFI
        // contract. Single-threaded test.
        unsafe {
            ngx_otel_error_writer(
                &raw mut log,
                nginx_sys::NGX_LOG_INFO as ngx_uint_t, // level 7 > floor 5 ⇒ drop
                dummy_buf.as_mut_ptr(),
                dummy_buf.len(),
            );
        }

        // The busy flag must be false: writer entered, hit the floor, released busy.
        assert!(!state.busy.load(Ordering::SeqCst), "busy must be released after floor drop");
    }

    /// The cleanup flag causes an early return before acquiring busy.
    #[test]
    fn cleanup_flag_drops_before_busy() {
        let (state, mut log) = make_writer_state(nginx_sys::NGX_LOG_DEBUG as ngx_uint_t);
        state.cleanup.store(true, Ordering::SeqCst);

        let mut dummy_buf = [0u8; 8];
        // SAFETY: `log` is a valid stack `ngx_log_t` whose `wdata` points to the
        // test's `OtelErrorWriterState` (set in make_writer_state); `dummy_buf` is
        // a valid buffer of `dummy_buf.len()` bytes — satisfies the writer's FFI
        // contract. Single-threaded test.
        unsafe {
            ngx_otel_error_writer(
                &raw mut log,
                nginx_sys::NGX_LOG_EMERG as ngx_uint_t,
                dummy_buf.as_mut_ptr(),
                dummy_buf.len(),
            );
        }

        // Busy must NOT have been set: cleanup check fires before busy swap.
        assert!(
            !state.busy.load(Ordering::SeqCst),
            "busy must not be set when cleanup fires first"
        );
    }

    /// A level equal to the floor IS accepted (not dropped).
    #[test]
    fn level_at_floor_passes() {
        let (state, mut log) = make_writer_state(nginx_sys::NGX_LOG_WARN as ngx_uint_t);

        let mut dummy_buf = [0u8; 8];
        // SAFETY: `log` is a valid stack `ngx_log_t` whose `wdata` points to the
        // test's `OtelErrorWriterState` (set in make_writer_state); `dummy_buf` is
        // a valid buffer of `dummy_buf.len()` bytes — satisfies the writer's FFI
        // contract. Single-threaded test.
        unsafe {
            ngx_otel_error_writer(
                &raw mut log,
                nginx_sys::NGX_LOG_WARN as ngx_uint_t, // level == floor ⇒ pass
                dummy_buf.as_mut_ptr(),
                dummy_buf.len(),
            );
        }

        // The writer passed the floor and released busy normally.
        assert!(!state.busy.load(Ordering::SeqCst), "busy must be released after pass-through");
    }

    /// Regression: a caught panic inside the writer body MUST NOT leave `busy`
    /// stuck. Without the `BusyGuard` + `catch_unwind` fix, a panic unwinds
    /// across the `extern "C"` boundary (UB per Rust Reference "Unwinding")
    /// and leaves `busy` permanently set, silencing all future error-log
    /// emissions from this worker.
    ///
    /// Mirrors the exact pattern in `ngx_otel_error_writer`: acquire `busy` →
    /// create `BusyGuard` in the OUTER scope → run a panicking closure under
    /// `catch_unwind(AssertUnwindSafe(...))` (no unwind escapes) → guard drops
    /// at function-scope end, clearing `busy` — asserted AFTER the explicit
    /// `drop(guard)`. The guard need not live inside the closure: it lives in
    /// the enclosing scope that runs after `catch_unwind` returns regardless
    /// of whether the closure panicked. See `busy_stuck_without_guard_on_panic`
    /// for the pre-fix evidence (stuck `busy`).
    #[test]
    fn busy_guard_releases_on_panic() {
        use core::sync::atomic::{AtomicBool, Ordering};
        use std::panic::{self, AssertUnwindSafe};

        let busy = AtomicBool::new(false);

        let was_busy = busy.swap(true, Ordering::Acquire);
        assert!(!was_busy, "precondition: busy was free");

        // Guard pointing at `busy` in the outer scope — same pattern as
        // `ngx_otel_error_writer`.
        // SAFETY: `busy` is a local `AtomicBool` that outlives this block;
        // the pointer is valid for the duration of the test.
        let guard = super::BusyGuard(core::ptr::addr_of!(busy) as *mut AtomicBool);

        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            panic!("simulated writer panic");
        }));

        assert!(result.is_err(), "catch_unwind must catch the panic");

        // Still true: the guard hasn't dropped yet.
        assert!(busy.load(Ordering::Acquire), "busy must still be set before the guard drops");

        drop(guard); // mirrors the end of `ngx_otel_error_writer`

        assert!(
            !busy.load(Ordering::Acquire),
            "busy must be released by BusyGuard drop even after a caught panic"
        );
    }

    /// Pre-fix failure mode as mutation evidence: WITHOUT a guard, a panic
    /// leaves `busy` permanently set — if `BusyGuard` is removed from
    /// `ngx_otel_error_writer`, the writer wedges after any internal panic.
    #[test]
    fn busy_stuck_without_guard_on_panic() {
        use core::sync::atomic::{AtomicBool, Ordering};
        use std::panic::{self, AssertUnwindSafe};

        let busy = AtomicBool::new(false);
        busy.swap(true, Ordering::Acquire);

        // Simulate the PRE-FIX pattern: no guard, manual clear only on normal path.
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            panic!("simulated writer panic");
            #[allow(unreachable_code)]
            busy.store(false, Ordering::Release); // never reached without a guard
        }));

        assert!(result.is_err(), "catch_unwind must catch the panic");

        // Still true: the manual clear was bypassed by the panic — the bug BusyGuard fixes.
        assert!(
            busy.load(Ordering::Acquire),
            "pre-fix: busy remains stuck when the manual store is bypassed by a panic"
        );
    }

    /// `parse_error_log_level` maps all nginx level names correctly.
    #[test]
    fn parse_level_all_names() {
        assert_eq!(parse_error_log_level(b"emerg"), Some(1));
        assert_eq!(parse_error_log_level(b"alert"), Some(2));
        assert_eq!(parse_error_log_level(b"crit"), Some(3));
        assert_eq!(parse_error_log_level(b"error"), Some(4));
        assert_eq!(parse_error_log_level(b"warn"), Some(5));
        assert_eq!(parse_error_log_level(b"notice"), Some(6));
        assert_eq!(parse_error_log_level(b"info"), Some(7));
        assert_eq!(parse_error_log_level(b"debug"), Some(8));
        assert_eq!(parse_error_log_level(b"bogus"), None);
        assert_eq!(parse_error_log_level(b""), None);
    }

    /// Verify `otel_log_insert` produces a chain sorted descending by `log_level`.
    ///
    /// Replicates nginx's expectation: the chain head is an embedded value whose
    /// address is stable; inserting a node at any position must keep the chain
    /// sorted without disturbing other nodes.
    #[test]
    fn log_insert_sorted_chain() {
        // SAFETY: all operations are on stack-local `ngx_log_t` values (zeroed C
        // POD) linked via `otel_log_insert`; the pointers are valid for the test
        // scope and access is single-threaded.
        unsafe {
            let mut head: nginx_sys::ngx_log_t = core::mem::zeroed();
            let mut mid: nginx_sys::ngx_log_t = core::mem::zeroed();
            let mut tail: nginx_sys::ngx_log_t = core::mem::zeroed();

            head.log_level = 5;

            mid.log_level = 3;

            // Chain is sorted largest-log_level-first (nginx's own convention:
            // higher log_level = wider threshold = processed first). Reset to
            // head=3(crit), then insert 5(warn) and 8(debug), each higher than
            // the current head, so each becomes the new head in turn.
            head.log_level = 3;
            mid.log_level = 5;
            tail.log_level = 8;

            otel_log_insert(&raw mut head, &raw mut mid);
            assert_eq!(head.log_level, 5, "head should become warn (5 > 3)");

            otel_log_insert(&raw mut head, &raw mut tail);
            assert_eq!(head.log_level, 8, "head should become debug (8 > 5)");

            let next1 = head.next;
            assert!(!next1.is_null(), "chain must have a second node");
            assert_eq!((*next1).log_level, 5, "second node must be warn (5)");

            let next2 = (*next1).next;
            assert!(!next2.is_null(), "chain must have a third node");
            assert_eq!((*next2).log_level, 3, "third node must be crit (3)");

            assert!((*next2).next.is_null(), "chain must end after crit");
        }
    }

    /// The process-role guard fires before the metric bump and coalescer: when
    /// `logs_zone` is null (or `ngx_process()` returns non-Worker), a
    /// floor-passing event must NOT touch `error_rate_ptr` or the coalescer.
    ///
    /// In unit tests `ngx_process()` always returns `Single`, so the guard
    /// fires on the first condition regardless of `logs_zone`; we still
    /// supply a real `AtomicU64` array so a spurious bump would be visible.
    #[test]
    fn process_role_guard_does_not_reach_metric_or_coalescer() {
        use crate::shm::N_SEVERITY_CLASSES;
        // Allocate a real counter array — a bump would be visible.
        let counters: std::vec::Vec<AtomicU64> =
            (0..N_SEVERITY_CLASSES).map(|_| AtomicU64::new(0)).collect();
        let counter_ptr = counters[0].as_ptr() as *mut AtomicU64;

        let (state, mut log) = make_writer_state(nginx_sys::NGX_LOG_DEBUG as ngx_uint_t);
        // Wire the counter pointer into state; logs_zone stays null.
        // SAFETY: `log.wdata` was set to the test's `OtelErrorWriterState` in
        // make_writer_state, so the cast + field write target valid state;
        // single-threaded test.
        unsafe {
            let s = log.wdata as *mut OtelErrorWriterState;
            (*s).error_rate_ptr = counter_ptr;
        }

        let mut buf = *b"connect() failed";
        // SAFETY: `log` is a valid stack `ngx_log_t` whose `wdata` points to the
        // test's `OtelErrorWriterState` (set in make_writer_state); `buf` is a
        // valid buffer of `buf.len()` bytes — satisfies the writer's FFI contract.
        // Single-threaded test.
        unsafe {
            ngx_otel_error_writer(
                &raw mut log,
                nginx_sys::NGX_LOG_ERR as ngx_uint_t, // passes the debug floor
                buf.as_mut_ptr(),
                buf.len(),
            );
        }

        // Guard fired (Single != Worker OR logs_zone == null) → no metric bump.
        let total: u64 = counters.iter().map(|c| c.load(Ordering::SeqCst)).sum();
        assert_eq!(total, 0, "metric must not be bumped when process-role guard fires");
        // busy was released by the guard's early-return path.
        assert!(!state.busy.load(Ordering::SeqCst), "busy must be released by guard");
        // state pointer is used above — keep state alive via explicit drop.
        drop(state);
    }

    /// Regression test for the error-log timestamp bug (found 2026-06-06 via the
    /// Grafana demo): the writer must stamp records with WALL-CLOCK Unix-epoch
    /// nanoseconds, not the monotonic `ngx_current_msec`. A boot-relative value is
    /// read by Loki (and any freshness-windowed OTLP backend) as ~1970 and the
    /// whole batch is rejected (HTTP 400). This asserts the conversion math and,
    /// crucially, that the result is a *plausible wall-clock* value — the hard
    /// assert the original test suite lacked (it ran against a file exporter
    /// that never validated timestamps).
    #[test]
    fn cached_unix_nanos_is_wall_clock_not_monotonic() {
        // Null pointer → 0 (early-init / stub).
        assert_eq!(super::cached_unix_nanos(core::ptr::null()), 0);

        // A realistic cached wall-clock: 2023-11-14T22:13:20Z + 500 ms.
        let tp = nginx_sys::ngx_time_t { sec: 1_700_000_000, msec: 500, gmtoff: 0 };
        let ns = super::cached_unix_nanos(&raw const tp);
        assert_eq!(ns, 1_700_000_000_500_000_000, "must be sec*1e9 + msec*1e6 (Unix-epoch ns)");

        // The bug's signature: a monotonic uptime (~a few days of seconds) read as
        // epoch lands in Jan 1970. Assert our value is firmly past 2020, i.e. it
        // could NOT have come from a boot-relative clock.
        const Y2020_NS: u64 = 1_577_836_800_000_000_000; // 2020-01-01T00:00:00Z
        assert!(
            ns > Y2020_NS,
            "wall-clock ns must be past 2020 — a monotonic source would be near epoch"
        );
    }
}
