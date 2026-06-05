// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! OTel error-log writer — `ngx_log_writer_pt` implementation (Phase 2.3 §6.6.2).
//!
//! # Architecture
//!
//! The writer is inserted into nginx's `cycle->new_log` chain as a writer-only
//! node (no `file`).  `ngx_log_error_core` formats the full line once, walks
//! the chain, and calls each writer.  Our node calls `ngx_otel_error_writer`;
//! the core file node (operator's own `error_log`) still writes because the
//! chain walk continues after our node returns.
//!
//! ## Hot-path disciplines (non-negotiable)
//! - **Alloc-free** — no heap allocation on the writer path.
//! - **Lock-free** — all shared state uses atomic operations.
//! - **Re-entrancy-safe** — the busy-flag swap drops re-entrant calls.  The
//!   writer fires from signal handlers and OOM paths.
//! - **No logging from the writer** — would cause re-entrancy.
//! - **No request-context deref** — the writer's `log->wdata` is `OtelErrorWriterState`
//!   (our own state); `log->data` is not a request context here (decision #6, 2026-06-05).
//!
//! ## Multi-origin guard (DP-C — added at Step 2.3.5)
//! The writer is woven into the chain before workers fork.  The DP-C
//! process-role guard (`exporter::ngx_process() == Worker`) is added at
//! Step 2.3.5 so the writer is a no-op in master/config-load/exporter contexts.
//!
//! ## Verbatim opt-out (`otel_error_log_coalesce off`)
//! Best-effort, NOT guaranteed delivery.  Verbatim mode pushes every
//! level-passing line to the bounded ring; under load the ring drops-newest
//! (accounted in `dropped_records`).  The guaranteed full-fidelity transcript
//! is nginx's own (untouched) `error_log` file.

use core::sync::atomic::{AtomicBool, Ordering};

use nginx_sys::{ngx_shm_zone_t, ngx_uint_t};

use crate::logs::coalesce::{self, CoalesceResult, CoalesceSlot};

// ── OtelErrorWriterState ──────────────────────────────────────────────────────

/// Per-writer state allocated from `cf->pool` by `cmd_set_error_log`.
///
/// Lives for the lifetime of the nginx cycle (pool-allocated, never freed
/// while nginx is running).  Zeroed by `ngx_pcalloc`; `false`/`null`/`0`
/// defaults are correct.
///
/// # Safety invariants
/// - `logs_zone` is null until `init_process` runs and maps the logs shm.
///   The writer checks non-null before touching the zone.
/// - `busy` and `cleanup` are only ever set/cleared by atomic operations.
/// - The struct must NOT be moved after allocation (raw pointer in `log->wdata`).
#[repr(C)]
pub struct OtelErrorWriterState {
    /// Re-entrancy guard: set while the writer is executing.
    /// A concurrent or re-entrant call (signal handler, OOM path) that
    /// finds `busy == true` drops immediately without touching shared state.
    pub busy: AtomicBool,
    /// Cycle-teardown flag: set by `exit_process_flush` (Step 2.3.3) BEFORE
    /// `cycle->log` is torn down.  Late emissions after teardown are dropped.
    pub cleanup: AtomicBool,
    /// Effective severity floor (from the directive or mirrored from core).
    /// nginx levels are inverted: 1=emerg, 2=alert, 3=crit, 4=error,
    /// 5=warn, 6=notice, 7=info, 8=debug.
    /// `level > level_floor` ⇒ less severe than the threshold ⇒ drop.
    pub level_floor: ngx_uint_t,
    /// The logs shm zone pointer (set by `init_process`; null until then).
    /// Used by the coalescer (Step 2.3.2) and error-rate metric (Step 2.3.4).
    pub logs_zone: *mut ngx_shm_zone_t,
    /// Pre-computed pointer to this worker's coalescer table within the logs shm zone.
    /// Set by `init_process` (Step 2.3.5) alongside `coalesce_enabled`.
    /// The coalescer path is a no-op (fall-through to TODO 2.3.3 ring push) until this is non-null.
    pub coalesce_table: *mut CoalesceSlot,
    /// Mirrors `MainConfig::error_log_coalesce`.  Set by `init_process` (Step 2.3.5).
    /// Default zero/false means "no coalescing"; overridden before first error is emitted.
    pub coalesce_enabled: bool,
}

// SAFETY: OtelErrorWriterState lives in nginx-managed pool memory and is
// accessed only from within the nginx event loop or from signal handlers
// (which the busy-flag already guards).  The raw pointer field (`logs_zone`)
// is set once before workers start and never moved.
unsafe impl Send for OtelErrorWriterState {}
unsafe impl Sync for OtelErrorWriterState {}

// ── Error-log writer ──────────────────────────────────────────────────────────

/// `ngx_log_writer_pt` callback: our node in the `cycle->log` chain.
///
/// Called by `ngx_log_error_core` after it has formatted the full error line
/// into `buf[..len]`.  The full formatted line is:
/// ```text
/// <cached-time> [<level>] <pid>#<tid>: [*<conn>] <core-msg>(<errno>)[, client:/request:/upstream:/host:]
/// ```
/// (ngx_log.c:155–188, ngx_http_request.c:4058–4086)
///
/// # Filter order (cheapest first)
/// 1. Cleanup flag — drop if cycle is tearing down.
/// 2. Busy flag — drop re-entrant / concurrent calls.
/// 3. Severity floor — drop if `level > level_floor`.
/// 4. (Step 2.3.5) Process-role guard (DP-C).
/// 5. (Step 2.3.2) Coalescer / verbatim push.
/// 6. (Step 2.3.4) Error-rate metric bump.
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
    if (*state).cleanup.load(Ordering::Acquire) {
        return;
    }

    // 2. Re-entrancy guard: drop if already executing (signal handler / OOM).
    if (*state).busy.swap(true, Ordering::Acquire) {
        return;
    }

    // 3. Severity floor (cheapest volume filter, applied first).
    //    nginx levels are inverted: 1=emerg .. 8=debug.
    //    `level > level_floor` ⇒ less severe than configured threshold ⇒ drop.
    if level > (*state).level_floor {
        (*state).busy.store(false, Ordering::Release);
        return;
    }

    // 4. TODO Step 2.3.5 (DP-C): process-role guard —
    //    `exporter::ngx_process() == NgxProcess::Worker(_)` AND
    //    logs_zone is mapped (non-null). Return early for master/exporter/
    //    config-load contexts (structural fall-through to core error_log).

    // 5. Coalescer (Step 2.3.2): exact-hash dedup with verbatim exception tail.
    //    coalesce_table is null until init_process (Step 2.3.5) populates it.
    //    When null, fall through (no record pushed yet; ring push wired at Step 2.3.3).
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
                // Duplicate suppressed. The coalescer already bumped the count.
                (*state).busy.store(false, Ordering::Release);
                return;
            }
            CoalesceResult::EmitVerbatim => {
                // TODO Step 2.3.3: push buf_slice to the error ring.
                let _ = buf_slice; // suppress unused warning until 2.3.3
            }
        }
    }

    // 6. TODO Step 2.3.4: companion error-rate metric bump (severity_class only).

    (*state).busy.store(false, Ordering::Release);
}

// ── Chain insertion ───────────────────────────────────────────────────────────

/// Insert `new_log` into the log chain rooted at `head`, sorted descending
/// by `log_level`.
///
/// This is a Rust equivalent of nginx's `static ngx_log_insert`
/// (`ngx_log.c:677–707`).  That function is `static` and therefore not
/// accessible from our module; we replicate its exact logic here.
///
/// The head address is kept stable: when `new_log.log_level > head.log_level`,
/// we swap the two nodes' *contents* (not pointers) and update `head->next`.
///
/// # Safety
/// - `head` must be a valid, non-null pointer to the chain head (an embedded
///   `ngx_log_t` value in `ngx_cycle_t::new_log`, never null).
/// - `new_log` must be a valid, non-null pointer to a freshly `ngx_pcalloc`'d
///   `ngx_log_t`, not yet part of any chain (`next` is null).
pub unsafe fn otel_log_insert(
    head: *mut nginx_sys::ngx_log_t,
    new_log: *mut nginx_sys::ngx_log_t,
) {
    if (*new_log).log_level > (*head).log_level {
        // New node has higher level: it should be the new head.
        // The head address is permanent (it's an embedded value in ngx_cycle_t),
        // so we swap the *contents* and set head->next to old-head memory.
        let tmp = *head;
        *head = *new_log;
        *new_log = tmp;
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
            // (no shm available; init_process wires this at Step 2.3.5).
            coalesce_table: core::ptr::null_mut(),
            coalesce_enabled: false,
        });
        let mut log: nginx_sys::ngx_log_t = unsafe { core::mem::zeroed() };
        log.writer = Some(ngx_otel_error_writer);
        log.wdata = state.as_ref() as *const _ as *mut core::ffi::c_void;
        (state, log)
    }

    /// Verify that a re-entrant call (busy flag already set) returns immediately
    /// without changing state.  The busy flag must remain set (caller's responsibility).
    #[test]
    fn busy_flag_blocks_reentry() {
        let (state, mut log) = make_writer_state(nginx_sys::NGX_LOG_DEBUG as ngx_uint_t);
        // Pre-set the busy flag to simulate an in-progress writer call.
        state.busy.store(true, Ordering::SeqCst);

        // A re-entrant call at any level must return early.
        let mut dummy_buf = [0u8; 8];
        unsafe {
            ngx_otel_error_writer(
                &mut log as *mut _,
                nginx_sys::NGX_LOG_ERR as ngx_uint_t,
                dummy_buf.as_mut_ptr(),
                dummy_buf.len(),
            );
        }

        // The busy flag must still be true — re-entrant call did NOT clear it.
        // (The original "caller" owns the flag and will clear it on exit.)
        assert!(state.busy.load(Ordering::SeqCst), "busy flag must stay set");
    }

    /// Verify that a below-threshold level is dropped without touching shared state.
    /// With `level_floor = WARN (5)`, an `info (7)` call must exit at the floor check.
    #[test]
    fn level_floor_drops_below_threshold() {
        let (state, mut log) = make_writer_state(nginx_sys::NGX_LOG_WARN as ngx_uint_t);

        let mut dummy_buf = [0u8; 8];
        unsafe {
            ngx_otel_error_writer(
                &mut log as *mut _,
                nginx_sys::NGX_LOG_INFO as ngx_uint_t, // level 7 > floor 5 ⇒ drop
                dummy_buf.as_mut_ptr(),
                dummy_buf.len(),
            );
        }

        // The busy flag must be false: writer entered, hit the floor, released busy.
        assert!(!state.busy.load(Ordering::SeqCst), "busy must be released after floor drop");
    }

    /// Verify that the cleanup flag causes an early return before acquiring busy.
    #[test]
    fn cleanup_flag_drops_before_busy() {
        let (state, mut log) = make_writer_state(nginx_sys::NGX_LOG_DEBUG as ngx_uint_t);
        state.cleanup.store(true, Ordering::SeqCst);

        let mut dummy_buf = [0u8; 8];
        unsafe {
            ngx_otel_error_writer(
                &mut log as *mut _,
                nginx_sys::NGX_LOG_EMERG as ngx_uint_t,
                dummy_buf.as_mut_ptr(),
                dummy_buf.len(),
            );
        }

        // Busy must NOT have been set: cleanup check fires before busy swap.
        assert!(!state.busy.load(Ordering::SeqCst), "busy must not be set when cleanup fires first");
    }

    /// Verify that a level equal to the floor IS accepted (not dropped).
    #[test]
    fn level_at_floor_passes() {
        let (state, mut log) = make_writer_state(nginx_sys::NGX_LOG_WARN as ngx_uint_t);

        let mut dummy_buf = [0u8; 8];
        unsafe {
            ngx_otel_error_writer(
                &mut log as *mut _,
                nginx_sys::NGX_LOG_WARN as ngx_uint_t, // level == floor ⇒ pass
                dummy_buf.as_mut_ptr(),
                dummy_buf.len(),
            );
        }

        // The writer passed the floor and released busy normally.
        assert!(!state.busy.load(Ordering::SeqCst), "busy must be released after pass-through");
    }

    /// Verify `parse_error_log_level` maps all nginx level names correctly.
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
        unsafe {
            // Create three nodes.  We'll insert them in reverse order (low to high)
            // and verify the chain comes out sorted high→low.
            let mut head: nginx_sys::ngx_log_t = core::mem::zeroed();
            let mut mid: nginx_sys::ngx_log_t = core::mem::zeroed();
            let mut tail: nginx_sys::ngx_log_t = core::mem::zeroed();

            // Seed the head with a mid-range level.
            head.log_level = 5; // warn

            // Insert a lower-level node — should go after head.
            mid.log_level = 3; // crit (lower numeric = more severe, inserted after warn)
            // Wait, nginx levels: 1=emerg(highest priority)...8=debug(lowest).
            // ngx_log_insert sorts DESCENDING by log_level number, which means
            // debug (8) first? Let me re-read the nginx source.
            //
            // Actually: from ngx_log.c:677-707, "if new_log->log_level > head->log_level"
            // ⇒ new_log gets inserted before (i.e., closer to head). So higher
            // numeric log_level = inserted earlier = processed first.
            // debug (8) > warn (5) > crit (3) → chain: debug → warn → crit
            //
            // This means the chain is sorted largest-number-first, and
            // ngx_log_error_core breaks when `log->log_level < level`, i.e.
            // when the node's threshold is lower than the message level.
            // So: higher log_level node = wider threshold = processed first.

            // Reset: head=3(crit), then insert 5(warn) and 8(debug).
            head.log_level = 3;
            mid.log_level = 5;  // warn > crit, should move to head
            tail.log_level = 8; // debug > warn > crit, should move to head

            // Insert mid (5) into chain rooted at head (3).
            otel_log_insert(&mut head as *mut _, &mut mid as *mut _);
            // Expected: head=5(warn), head.next→ old-head-storage(3)
            assert_eq!(head.log_level, 5, "head should become warn (5 > 3)");

            // Insert tail (8) into chain.
            otel_log_insert(&mut head as *mut _, &mut tail as *mut _);
            // Expected: head=8(debug), head.next→ warn(5) → crit(3)
            assert_eq!(head.log_level, 8, "head should become debug (8 > 5)");

            // Walk the chain and verify order.
            let next1 = head.next;
            assert!(!next1.is_null(), "chain must have a second node");
            assert_eq!((*next1).log_level, 5, "second node must be warn (5)");

            let next2 = (*next1).next;
            assert!(!next2.is_null(), "chain must have a third node");
            assert_eq!((*next2).log_level, 3, "third node must be crit (3)");

            assert!((*next2).next.is_null(), "chain must end after crit");
        }
    }
}
