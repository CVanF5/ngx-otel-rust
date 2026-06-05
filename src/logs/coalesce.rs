// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Producer-side exact-hash coalescer for the OTel error-log writer (Phase 2.3, DP-A).
//!
//! # Purpose
//! Nginx error floods: one `connect() failed (111: Connection refused)` per failed
//! request.  A naïve per-event ring would emit 1000 `LogRecord`s for a 1000-req
//! flood — the same §6.5 serialisation-point hazard the access log had.  The
//! coalescer collapses them at the producer: *seen this (severity, core-hash) this
//! interval? bump a count; else emit one verbatim sample to the ring and remember.*
//!
//! # DP-A decisions (ratified 2026-06-05)
//! - **Exact-hash only.** No producer-side IP/number normalisation; that is an
//!   optional backend enhancement (§6.4.6, undepended-on).
//! - **Subsystem dim dropped.** Key = `(severity × stable_core_hash)` only.
//! - **Stable-core extraction.** The writer's `buf` is the FULL formatted line
//!   (`<cached-time> [<level>] <pid>#<tid>: [*<conn>] <msg>[, client:…]\n`);
//!   hashing it verbatim collapses nothing (timestamp/conn/client all vary).
//!   The stable core is extracted by skipping the variable prefix and cutting at
//!   the handler-context boundary (` while ` / `, client:`).
//!
//! # Hot-path disciplines
//! - **Alloc-free**: the table lives in shm; the hash/extraction operate on
//!   stack-local bytes only.
//! - **Lock-free**: the table is write-only on the writer path (busy-flag in
//!   `OtelErrorWriterState` serialises writer calls); count/sample_emitted are
//!   `Atomic*` for the drain (exporter) to read + reset concurrently.
//! - **Bounded**: fixed-capacity open-addressed table; table-full degrades to
//!   verbatim (accounted but never blocks).
//! - **Re-entrancy-safe**: the coalescer itself is called only after the busy-flag
//!   swap in the writer; it does no logging and no allocation.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ── CoalesceSlot ──────────────────────────────────────────────────────────────

/// Capacity of the per-worker coalescer table (number of slots).
///
/// Must be a power of two (used as hash modulo via `& (COALESCE_CAPACITY - 1)`).
/// 256 slots × 24 bytes = 6 KiB per worker; negligible relative to the rings.
pub const COALESCE_CAPACITY: usize = 256;

/// One entry in the per-worker coalescer table.
///
/// Allocated in shm (zeroed on init); zero ≡ empty slot (`key_hash == 0`).
///
/// # Memory layout (`#[repr(C)]`, 24 bytes)
/// ```text
/// offset 0:  key_hash:       u64  (8)   — stable until evicted (never cleared)
/// offset 8:  severity:       u8   (1)   — written once with key_hash
/// offset 9:  _pad:           [u8; 3]
/// offset 12: count:          AtomicU32  — bumped by writer; swap-to-0 by drain
/// offset 16: sample_emitted: AtomicBool — set by writer; swap-to-false by drain
/// offset 17: _pad2:          [u8; 7]
/// ```
///
/// # Concurrency
/// The writer (single-threaded per worker via the busy-flag) reads/writes all
/// fields.  The drain (exporter process) atomically reads-and-resets `count` and
/// `sample_emitted` only; it NEVER modifies `key_hash` or `severity`.
#[repr(C)]
pub struct CoalesceSlot {
    /// FNV-1a hash of `severity_byte ++ stable_core_bytes`.
    /// `0` means the slot is empty.
    pub key_hash: u64,
    /// Nginx severity level (1=emerg … 8=debug) at time of first insertion.
    pub severity: u8,
    pub _pad: [u8; 3],
    /// Number of times this template was seen this interval (including the initial
    /// verbatim sample that was pushed to the ring on first insertion).
    pub count: AtomicU32,
    /// `true` when the verbatim sample for this slot was pushed to the ring this
    /// interval.  Reset by the drain so the next interval re-emits a fresh sample.
    pub sample_emitted: AtomicBool,
    pub _pad2: [u8; 7],
}

// Verify the layout is exactly 24 bytes (no hidden padding).
const _: () = assert!(core::mem::size_of::<CoalesceSlot>() == 24);

// ── CoalesceResult ────────────────────────────────────────────────────────────

/// Result returned by [`coalesce`] to the writer.
pub enum CoalesceResult {
    /// The template was found; count was bumped.  Do NOT push bytes to the ring.
    Coalesced,
    /// Push the full `buf` verbatim to the error ring.
    /// Covers: novel template, high-severity (≤ crit), table-full, coalesce-off.
    ///
    /// `template_hash` is the coalescer slot key for this template (non-zero when
    /// the coalescer assigned a slot), or `0` when the record is untracked
    /// (high-severity exception tail, `coalesce=off`, or table-full fallback).
    /// The writer stores this in the ring record so the drain can join the
    /// verbatim sample to its coalescer count without re-computing the hash.
    EmitVerbatim { template_hash: u64 },
}

// ── Stable-core extraction ────────────────────────────────────────────────────

/// Extract the stable core message from a full nginx error-log line.
///
/// The writer receives `buf` = the FULL formatted line:
/// ```text
/// <cached-time> [<level>] <pid>#<tid>: [*<conn> ]<core-message>[ while ...]\n
/// <cached-time> [<level>] <pid>#<tid>: [*<conn> ]<core-message>[, client:...]\n
/// ```
/// (`ngx_log.c:155–188`, `ngx_http_request.c:4058–4086`)
///
/// Hashing this verbatim collapses nothing (timestamp/conn/client all vary per
/// call).  This function returns a subslice containing only the stable core —
/// everything after the variable prefix and before the handler-context boundary.
///
/// # Extraction algorithm (bounded forward-scan, no alloc)
/// 1. Skip past `] ` to advance past `[<level>]`.
/// 2. Skip past `: ` to advance past `<pid>#<tid>`.
/// 3. Skip optional `*<digits> ` (connection context).
/// 4. Return the subslice up to the first ` while ` or `, client:`.
///
/// # Fallback
/// If any marker is not found (malformed or truncated line), returns the largest
/// reasonable subslice (avoids empty keys, which would all hash to the same slot).
pub fn stable_core(buf: &[u8]) -> &[u8] {
    let mut pos = 0;
    let len = buf.len();

    // 1. Find `] ` — end of `[level]` bracket.
    while pos + 1 < len {
        if buf[pos] == b']' && buf[pos + 1] == b' ' {
            pos += 2;
            break;
        }
        pos += 1;
    }

    // 2. Find `: ` — end of `<pid>#<tid>`.
    while pos + 1 < len {
        if buf[pos] == b':' && buf[pos + 1] == b' ' {
            pos += 2;
            break;
        }
        pos += 1;
    }

    // 3. Skip optional `*<digits> ` — connection context.
    //    Detected by a literal `*` at the current position.
    //    nginx messages do not start with `*`; this is safe.
    if pos < len && buf[pos] == b'*' {
        pos += 1; // skip '*'
        while pos < len && buf[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos < len && buf[pos] == b' ' {
            pos += 1; // skip ' '
        }
    }

    let core_start = pos;

    // 4. Find the handler-context boundary (cut before it).
    //    Remove trailing newline first.
    let mut end = len;
    if end > 0 && buf[end - 1] == b'\n' {
        end -= 1;
    }

    let mut i = core_start;
    while i < end {
        // ` while ` (7 bytes) — `ngx_http_request.c:4064`
        if i + 7 <= end && &buf[i..i + 7] == b" while " {
            end = i;
            break;
        }
        // `, client:` (9 bytes) — `ngx_http_request.c:4072`
        if i + 9 <= end && &buf[i..i + 9] == b", client:" {
            end = i;
            break;
        }
        i += 1;
    }

    &buf[core_start..end]
}

// ── FNV-1a hash ───────────────────────────────────────────────────────────────

/// FNV-1a 64-bit hash (no alloc, no std).
///
/// Standard constants per <https://www.isthe.com/chongo/tech/comp/fnv/>.
/// Used in unit tests; production code uses the inlined [`coalesce_key`].
#[allow(dead_code)]
#[inline(always)]
pub fn fnv1a(data: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 14695981039346656037;
    const PRIME: u64 = 1099511628211;
    let mut h = OFFSET_BASIS;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// Compute the coalescer key: FNV-1a over `[severity_byte] ++ stable_core_bytes`.
///
/// Severity is included in the key so the same message text at different
/// severities gets distinct table entries (e.g. `[error]` vs `[warn]`).
/// Returns 1 (not 0) if the hash happens to land on 0 (0 = empty sentinel).
#[inline]
pub fn coalesce_key(severity: u8, core: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 14695981039346656037;
    const PRIME: u64 = 1099511628211;
    let mut h = OFFSET_BASIS;
    h ^= severity as u64;
    h = h.wrapping_mul(PRIME);
    for &b in core {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    // Avoid the empty-slot sentinel (0).
    if h == 0 { 1 } else { h }
}

// ── Coalescer main entry point ────────────────────────────────────────────────

/// High-severity threshold (DP-A): crit/alert/emerg (levels 1–3) always verbatim.
pub const HIGH_SEVERITY_THRESHOLD: u8 = nginx_sys::NGX_LOG_CRIT as u8; // 3

/// Decide how to handle an incoming error message.
///
/// Called by [`super::error_writer::ngx_otel_error_writer`] after the severity
/// floor and process-role guards pass.  The writer passes `coalesce_enabled`
/// from `MainConfig::error_log_coalesce`.
///
/// # Arguments
/// - `table`: pointer to the first slot of the `COALESCE_CAPACITY`-slot table
///   for the current worker (in the logs shm zone).
/// - `severity`: nginx severity level (1=emerg … 8=debug) — must have passed
///   the severity floor already.
/// - `buf`: the full formatted error-log line (as received by the writer).
/// - `coalesce_enabled`: from `MainConfig::error_log_coalesce` (directive flag).
///
/// # Returns
/// `Coalesced` — count was bumped; do NOT push to ring.
/// `EmitVerbatim` — push the full `buf` to the error ring.
///
/// # Safety
/// `table` must be a valid, non-null pointer to a `[CoalesceSlot; COALESCE_CAPACITY]`
/// in the logs shm zone, aligned to `align_of::<CoalesceSlot>()`, valid for the
/// duration of this call.
pub unsafe fn coalesce(
    table: *mut CoalesceSlot,
    severity: u8,
    buf: &[u8],
    coalesce_enabled: bool,
) -> CoalesceResult {
    // Verbatim opt-out: bypass the table entirely.
    // template_hash = 0: no coalescer slot assigned; the drain will not find a count.
    if !coalesce_enabled {
        return CoalesceResult::EmitVerbatim { template_hash: 0 };
    }

    // High-severity exception tail: emerg/alert/crit always verbatim.
    // template_hash = 0: these are never tracked in the coalescer table.
    if severity <= HIGH_SEVERITY_THRESHOLD {
        return CoalesceResult::EmitVerbatim { template_hash: 0 };
    }

    // Compute the dedup key from the stable core (alloc-free, stack-only).
    let core = stable_core(buf);
    let key = coalesce_key(severity, core);

    // Open-addressed linear probe.
    let start = (key as usize) & (COALESCE_CAPACITY - 1);
    let mut probe = start;
    let mut probes = 0usize;

    loop {
        let slot = unsafe { &*table.add(probe) };
        let slot_key = slot.key_hash;

        if slot_key == 0 {
            // Empty slot — this template is novel.  Insert and emit one verbatim sample.
            // Write key_hash and severity first (both stable; never changed after).
            // Use addr_of_mut! to obtain *mut T from a field projection through a
            // raw pointer — avoids the &T → *mut T cast that triggers lint
            // `invalid_reference_casting`.
            // SAFETY: writer is single-threaded (busy flag); no concurrent writer.
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!((*table.add(probe)).key_hash),
                    key,
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!((*table.add(probe)).severity),
                    severity,
                );
            }
            // Release ordering: the key_hash/severity writes above must be visible
            // to the drain before it reads count > 0.  The drain does an AcqRel swap
            // on count; the Acquire half synchronises with this Release store.
            slot.count.store(1, Ordering::Release);
            slot.sample_emitted.store(true, Ordering::Release);
            // Return the assigned key so the ring record can carry it for the drain join.
            return CoalesceResult::EmitVerbatim { template_hash: key };
        }

        if slot_key == key && slot.severity == severity {
            // Existing entry — bump the count.  Do NOT emit again this interval
            // UNLESS sample_emitted is false (drain reset it; re-emit one sample).
            let already_emitted = slot.sample_emitted.load(Ordering::Acquire);
            slot.count.fetch_add(1, Ordering::Relaxed);
            if already_emitted {
                return CoalesceResult::Coalesced;
            } else {
                // Drain reset sample_emitted in the previous interval; re-emit.
                // The existing key is slot_key (== key); carry it for the drain join.
                slot.sample_emitted.store(true, Ordering::Release);
                return CoalesceResult::EmitVerbatim { template_hash: key };
            }
        }

        // Collision — advance probe.
        probe = (probe + 1) & (COALESCE_CAPACITY - 1);
        probes += 1;

        // Table-full guard: if we've probed the entire table, fall back to verbatim.
        // template_hash = 0: no slot assigned; drain will not find a count for this record.
        if probes >= COALESCE_CAPACITY {
            return CoalesceResult::EmitVerbatim { template_hash: 0 };
        }

        // Cycle detection: if we're back to where we started, table is full.
        if probe == start {
            return CoalesceResult::EmitVerbatim { template_hash: 0 };
        }
    }
}

/// Byte size of the coalescer table (for shm layout calculations).
#[inline]
pub const fn coalesce_table_bytes() -> usize {
    COALESCE_CAPACITY * core::mem::size_of::<CoalesceSlot>()
}

/// Drain the per-worker coalescer table for one export interval.
///
/// Called by the exporter's `collect_log_records` once per drain cycle.
/// Sweeps all occupied slots, atomically reads-and-resets `count`, and
/// returns `(key_hash, severity, count)` for every slot that had `count > 0`.
/// Also resets `sample_emitted` so the next interval emits a fresh verbatim
/// sample (the writer path sees `!already_emitted` and calls `EmitVerbatim`).
///
/// # Ownership of key_hash / severity
/// These fields are NEVER cleared by the drain — evicted templates persist in
/// the table until their slot is probed-over by a new insert (impossible at 256
/// slots since the table never shrinks entries; the drain only zeroes `count`
/// and flips `sample_emitted`).
///
/// # Memory ordering
/// The `count.swap(0, AcqRel)` Acquire half synchronises with the `count.store(1,
/// Release)` in the writer's novel-insert path, ensuring `key_hash` and
/// `severity` (written before that Release) are visible here.
///
/// # Safety
/// `table` must be a valid, non-null pointer to a `[CoalesceSlot; COALESCE_CAPACITY]`
/// in the logs shm zone, aligned to `align_of::<CoalesceSlot>()`.
pub unsafe fn drain_coalesce_table(table: *mut CoalesceSlot) -> std::vec::Vec<(u64, u8, u32)> {
    let mut out = std::vec::Vec::new();
    for i in 0..COALESCE_CAPACITY {
        let slot = unsafe { &*table.add(i) };
        // Cheap pre-filter: a zero key_hash means the slot was never written.
        // (key_hash is only written once, before count; if count > 0 then
        //  key_hash is definitely non-zero, so this skips all empty slots.)
        if slot.key_hash == 0 {
            continue;
        }
        // AcqRel: the Acquire half synchronises with the Release count.store(1)
        // on the writer's novel-insert path, making key_hash/severity visible.
        let count = slot.count.swap(0, Ordering::AcqRel);
        if count > 0 {
            // Read key_hash and severity AFTER the Acquire swap for correct ordering.
            let key_hash = slot.key_hash;
            let severity = slot.severity;
            // Reset sample_emitted so the next interval re-emits a fresh sample.
            // The Release ensures the reset is visible to the writer before it
            // loads sample_emitted with Acquire.
            slot.sample_emitted.store(false, Ordering::Release);
            out.push((key_hash, severity, count));
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── stable_core tests ─────────────────────────────────────────────────────

    /// THE load-bearing extraction test (DP-A).
    ///
    /// Two raw `buf`s with the SAME core message but different timestamp, `*conn`,
    /// and `, client:/request:` context must hash to the **same** key.
    /// Without correct extraction, dedup is a no-op.
    #[test]
    fn stable_core_ignores_prefix_and_context() {
        // Simulated nginx error log line with connection context.
        let line1 = b"2024/01/01 12:00:01 [error] 1234#5678: *1 connect() failed (111: Connection refused) while connecting to upstream, client: 1.2.3.4, request: GET / HTTP/1.1\n";
        // Same core, different timestamp, different conn ID, different client.
        let line2 = b"2024/01/01 12:00:02 [error] 1234#5678: *2 connect() failed (111: Connection refused) while connecting to upstream, client: 5.6.7.8, request: GET /api HTTP/1.1\n";

        let core1 = stable_core(line1);
        let core2 = stable_core(line2);

        assert_eq!(core1, core2, "same core message must extract identically");
        assert_eq!(
            core1,
            b"connect() failed (111: Connection refused)",
            "core must be the message up to ' while '"
        );

        let key1 = coalesce_key(4, core1); // severity 4 = error
        let key2 = coalesce_key(4, core2);
        assert_eq!(key1, key2, "same core+severity must produce same key");
    }

    /// Lines with no handler context (non-HTTP errors) should still extract correctly.
    #[test]
    fn stable_core_no_handler_context() {
        let line = b"2024/01/01 12:00:00 [warn] 1234#5678: signaling process failed\n";
        let core = stable_core(line);
        assert_eq!(core, b"signaling process failed");
    }

    /// Line without connection field (`*<conn>`).
    #[test]
    fn stable_core_no_connection_field() {
        let line = b"2024/01/01 12:00:00 [error] 1234#5678: connect() failed, client: 1.2.3.4\n";
        let core = stable_core(line);
        assert_eq!(core, b"connect() failed");
    }

    /// Cut at `, client:` when ` while ` is absent.
    #[test]
    fn stable_core_client_boundary() {
        let line = b"2024/01/01 12:00:00 [error] 1234#5678: *42 no live upstreams, client: 10.0.0.1, request: GET /\n";
        let core = stable_core(line);
        assert_eq!(core, b"no live upstreams");
    }

    // ── fnv1a / key tests ────────────────────────────────────────────────────

    /// FNV-1a test vector: empty input.
    #[test]
    fn fnv1a_empty() {
        assert_eq!(fnv1a(b""), 14695981039346656037);
    }

    /// FNV-1a basic: different inputs produce different hashes.
    #[test]
    fn fnv1a_distinct_inputs() {
        assert_ne!(fnv1a(b"foo"), fnv1a(b"bar"));
    }

    /// coalesce_key: zero is remapped to 1 (avoid empty-slot sentinel).
    #[test]
    fn coalesce_key_no_zero() {
        // Run through all single-byte inputs to verify no zero output.
        // For the FNV-1a parameters, a zero result is extremely rare but
        // we guard against it explicitly.
        for sev in 1u8..=8 {
            for core_byte in 0u8..=255u8 {
                let k = coalesce_key(sev, &[core_byte]);
                assert_ne!(k, 0, "coalesce_key must never return 0");
            }
        }
    }

    // ── coalesce() table tests ────────────────────────────────────────────────

    /// Allocate a zeroed coalescer table on the heap for testing.
    fn make_table() -> std::boxed::Box<[CoalesceSlot; COALESCE_CAPACITY]> {
        // SAFETY: CoalesceSlot is repr(C) + all-zero is valid (key_hash=0 = empty).
        unsafe {
            let layout = std::alloc::Layout::new::<[CoalesceSlot; COALESCE_CAPACITY]>();
            let ptr = std::alloc::alloc_zeroed(layout) as *mut [CoalesceSlot; COALESCE_CAPACITY];
            std::boxed::Box::from_raw(ptr)
        }
    }

    /// N identical messages ⇒ 1 verbatim record + count = N.
    #[test]
    fn flood_collapses_to_one_sample() {
        let mut table = make_table();
        let ptr = table.as_mut_ptr() as *mut CoalesceSlot;

        let msg = b"2024/01/01 12:00:00 [error] 1#1: *1 connect() failed, client: 1.2.3.4\n";

        // First call: novel → EmitVerbatim.
        let r1 = unsafe { coalesce(ptr, 4, msg, true) };
        assert!(matches!(r1, CoalesceResult::EmitVerbatim { .. }), "first call must emit verbatim");

        // Subsequent calls: coalesced → count bumped.
        let n = 99;
        for _ in 0..n {
            let r = unsafe { coalesce(ptr, 4, msg, true) };
            assert!(matches!(r, CoalesceResult::Coalesced), "flood must coalesce");
        }

        // Verify slot: count = 1 (initial) + n bumps = n + 1.
        let core = stable_core(msg);
        let key = coalesce_key(4, core);
        let start = (key as usize) & (COALESCE_CAPACITY - 1);
        assert_eq!(table[start].count.load(Ordering::Relaxed), (n + 1) as u32);
        assert!(table[start].sample_emitted.load(Ordering::Relaxed));
    }

    /// K distinct messages ⇒ K verbatim records in the table.
    #[test]
    fn distinct_templates_each_sampled() {
        let mut table = make_table();
        let ptr = table.as_mut_ptr() as *mut CoalesceSlot;

        // 5 distinct messages.
        let msgs: &[&[u8]] = &[
            b"2024/01/01 12:00:00 [error] 1#1: connect() failed\n",
            b"2024/01/01 12:00:00 [error] 1#1: recv() failed\n",
            b"2024/01/01 12:00:00 [error] 1#1: send() failed\n",
            b"2024/01/01 12:00:00 [error] 1#1: no live upstreams\n",
            b"2024/01/01 12:00:00 [error] 1#1: upstream timed out\n",
        ];

        let mut emitted = 0usize;
        for msg in msgs {
            let r = unsafe { coalesce(ptr, 4, msg, true) };
            if matches!(r, CoalesceResult::EmitVerbatim { .. }) {
                emitted += 1;
            }
        }
        assert_eq!(emitted, msgs.len(), "each distinct template must emit one verbatim sample");
    }

    /// emerg/alert/crit always emit verbatim even when repeated.
    #[test]
    fn high_severity_never_coalesced() {
        let mut table = make_table();
        let ptr = table.as_mut_ptr() as *mut CoalesceSlot;

        let msg = b"2024/01/01 12:00:00 [crit] 1#1: accept() failed\n";
        // severity 3 = crit (≤ HIGH_SEVERITY_THRESHOLD)

        for _ in 0..10 {
            let r = unsafe { coalesce(ptr, 3, msg, true) };
            assert!(
                matches!(r, CoalesceResult::EmitVerbatim { .. }),
                "crit must always emit verbatim"
            );
        }
        // Also emerg (1) and alert (2).
        let msg_emerg = b"2024/01/01 12:00:00 [emerg] 1#1: worker process exited\n";
        let r = unsafe { coalesce(ptr, 1, msg_emerg, true) };
        assert!(matches!(r, CoalesceResult::EmitVerbatim { .. }), "emerg must always emit verbatim");
    }

    /// Table-full degrades to verbatim, never panics.
    ///
    /// We fill the table with `COALESCE_CAPACITY` distinct entries, then inject one
    /// more novel message and verify it returns `EmitVerbatim` (not a panic or incorrect
    /// `Coalesced`).
    #[test]
    fn table_full_falls_back_to_verbatim() {
        let mut table = make_table();
        let ptr = table.as_mut_ptr() as *mut CoalesceSlot;

        // Fill the table with COALESCE_CAPACITY distinct entries by
        // fabricating unique "messages" with distinct hash keys.
        // We do this by directly populating table slots.
        for i in 0..COALESCE_CAPACITY {
            // Fill every slot with a non-zero key_hash so the table appears full.
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!((*ptr.add(i)).key_hash),
                    (i + 1) as u64,
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!((*ptr.add(i)).severity),
                    4u8,
                );
            }
            table[i].count.store(1, Ordering::Relaxed);
            table[i].sample_emitted.store(true, Ordering::Relaxed);
        }

        // A message that doesn't match any existing slot — table-full path.
        // The key for this message is unlikely to match any of the fabricated keys.
        let novel = b"2024/01/01 12:00:00 [error] 1#1: a truly novel message that is unique xyz\n";
        let r = unsafe { coalesce(ptr, 4, novel, true) };
        // Must fall back to verbatim — no panic, no silent discard.
        assert!(
            matches!(r, CoalesceResult::EmitVerbatim { .. }),
            "table-full must degrade to verbatim emit, never panic"
        );
    }

    /// With `error_log_coalesce == false`, N identical messages ⇒ N EmitVerbatim
    /// (table bypassed entirely, no dedup).
    #[test]
    fn coalesce_off_emits_every_line() {
        let mut table = make_table();
        let ptr = table.as_mut_ptr() as *mut CoalesceSlot;

        let msg = b"2024/01/01 12:00:00 [error] 1#1: connect() failed, client: 1.2.3.4\n";

        let n = 20;
        for _ in 0..n {
            let r = unsafe { coalesce(ptr, 4, msg, false) }; // coalesce disabled
            assert!(
                matches!(r, CoalesceResult::EmitVerbatim { .. }),
                "coalesce=off must always emit verbatim"
            );
        }

        // Table should be untouched (all zeros) — the bypass skips table writes.
        let core = stable_core(msg);
        let key = coalesce_key(4, core);
        let slot_idx = (key as usize) & (COALESCE_CAPACITY - 1);
        assert_eq!(
            table[slot_idx].key_hash, 0,
            "coalesce=off must not write to the table"
        );
    }
}
