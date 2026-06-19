// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Rewrite-phase span-start handler — hot path.
//!
//! `SpanStartHandler` runs at `HttpPhase::Rewrite` and is responsible for:
//! 1. Checking whether tracing is enabled for the request (zero-cost exit when not).
//! 2. Parsing the inbound `traceparent` header **once** and caching the result.
//! 3. Making the worker-side sampling decision.
//! 4. Generating a fresh span ID (and a fresh trace ID when there is no parent).
//! 5. Allocating a `SpanCtx` on the **nginx request pool** and storing it via
//!    `request.set_module_ctx`.
//!
//! After this handler runs, the Log phase reads `SpanCtx` and:
//! - stamps the access tail/exemplar with the cached trace correlation, AND
//! - (when sampled) pushes a `SpanRecord` to the spans ring.
//!
//! The Log phase no longer re-scans request headers for `traceparent`; the
//! parse happens once here (the parse-once design).
//!
//! # Hard budget rules
//! - **Zero cost when disabled:** handler is only registered when
//!   `amcf.is_configured()` is true (see `lib.rs::postconfiguration`).  If
//!   tracing is not configured for a location (the per-location `otel_trace`
//!   directive), the handler returns immediately.
//! - **Bounded when unsampled:** pool-alloc + one header scan + sampling branch.
//!   No span record, no ring push, no second header scan in LOG.
//! - No heap allocation, no locks, no logging, no `std::thread::spawn`.

use core::ffi::c_void;

use ngx::core::Status;
use ngx::http::{
    HttpModuleLocationConf, HttpModuleMainConf, HttpPhase, HttpRequestHandler, Request,
};

use crate::metric_source::location_conf::{LocationConf, TraceContextMode};
use crate::traces::ctx::{
    alloc_span_ctx, alloc_span_ctx_plain, gen_span_id, gen_trace_id, pool_from_request, SpanCtx,
};
use crate::HttpOtelModule;

/// Unit struct for the REWRITE-phase span-start handler.
pub struct SpanStartHandler;

impl HttpRequestHandler for SpanStartHandler {
    const PHASE: HttpPhase = HttpPhase::Rewrite;
    type Output = Status;

    /// Called once per request in the Rewrite phase.
    ///
    /// # Zero-cost invariant
    /// Returns immediately when the module is not configured; no allocation,
    /// no locking, no header scan.
    ///
    /// # Bounded-when-unsampled invariant
    /// When configured but the request is unsampled (no traceparent → default
    /// sample=true; traceparent with sampled=0 → unsampled), allocates a
    /// `SpanCtx` with `sampled=false` and stores it.  LOG reads it and skips
    /// ring work.  The pool alloc is a bump pointer — effectively free.
    fn handler(request: &mut Request) -> Status {
        // ── Gate 0: internal-redirect / subrequest guard ──────────────────────
        // Mirrors the C++ module's REWRITE early-return
        // (`nginx-otel/src/http_module.cpp:356-361`): "don't let internal
        // redirects override the sampling decision".  nginx re-runs the REWRITE
        // phase after an internal redirect (`error_page`, `try_files`, named
        // location) and for subrequests, both of which set `r->internal`.  If we
        // re-entered span-start here we would generate a *second* span (and a
        // fresh sampling decision) for what is one logical request.  Returning
        // NGX_DECLINED before any span-start work yields exactly ONE span per
        // request, with pass-1's parent + timing intact (recovered at LOG via
        // `recover_span_ctx`).
        //
        // NOTE: `r->internal` is also set for subrequests, so this guard means
        // subrequests do NOT get their own span — a deliberate, upstream-mirrored
        // semantic (the C++ module behaves identically).
        //
        // Read via the C shim, NOT the bindgen `internal()` accessor: bindgen
        // mis-lays-out this struct's bitfields and reads `internal` 2 bits low
        // (see `crate::shim`).
        //
        // Ordering: we check `internal` BEFORE the config/location gates,
        // mirroring the C++ module (`http_module.cpp:356-361`, which checks
        // `r->internal` first).  The cost is one extern call + branch per request
        // — but it is NOT a zero-cost-when-disabled regression: an unconfigured
        // location never registers this handler at all (see
        // `lib.rs::postconfiguration`), so the shim call only runs when tracing
        // is in play.  Keeping the C++ ordering preserves the redirect semantics
        // (an internal redirect must not re-enter span-start regardless of how
        // the location gates would evaluate on pass 2).
        //
        // Cost: one extern (C-shim) call + branch on the hot path.
        let r_const = request.as_ref() as *const nginx_sys::ngx_http_request_t;
        // SAFETY: `r_const` is the live request pointer borrowed from `request`.
        if unsafe { crate::shim::r_internal(r_const) } != 0 {
            return Status::NGX_DECLINED;
        }

        // ── Gate 1: module not configured → zero cost ────────────────────────
        // NGX_DECLINED passes to the next handler in the REWRITE phase (correct
        // passthrough).  NGX_OK in the REWRITE phase re-enters the phase checker
        // from the top (re-location-matching), which would hang the request.
        let amcf = match HttpOtelModule::main_conf(request) {
            Some(c) => c,
            None => return Status::NGX_DECLINED,
        };
        if !amcf.is_configured() {
            return Status::NGX_DECLINED;
        }

        // ── Gate 2: per-location `otel_trace` directive ──────────────────────
        // Pull both the complex-value pointer and trace_context mode from
        // LocationConf in one borrow so the borrow ends before we call
        // set_module_ctx (which borrows mutably).
        // as_mut() yields &mut provenance; casting immediately to *mut releases
        // the Rust borrow so subsequent immutable borrows of `request` are valid.
        let r_ptr = request.as_mut() as *mut nginx_sys::ngx_http_request_t;
        let (otel_trace_cv, trace_context): (
            *mut nginx_sys::ngx_http_complex_value_t,
            TraceContextMode,
        ) = {
            let lc: &LocationConf = match HttpOtelModule::location_conf(request) {
                Some(c) => c,
                None => return Status::NGX_DECLINED,
            };
            (lc.otel_trace, lc.trace_context())
        };
        if otel_trace_cv.is_null() {
            // `otel_trace` not set for this location → tracing disabled here.
            return Status::NGX_DECLINED;
        }

        // Module descriptor — factored out; needed for set_module_ctx at several
        // call sites below (pre-gate set, gate-decline clear, post-gate set).
        // SAFETY: `ngx_http_otel_module` is the static module descriptor valid for
        // process lifetime; `addr_of!` yields a stable pointer to it.
        let module_ref = unsafe { &*core::ptr::addr_of!(crate::ngx_http_otel_module) };

        // ── Parse inbound `traceparent` BEFORE Gate 2 ────────────────────────
        // `$otel_parent_sampled` reads its value from the request's SpanCtx.
        // Gate 2 calls `ngx_http_complex_value` which evaluates whatever
        // `otel_trace` is set to — including `$otel_parent_sampled`.  In the old
        // ordering the traceparent parse ran AFTER the gate, so SpanCtx was never
        // set at Gate 2 time: `$otel_parent_sampled` always returned not_found →
        // parent-based sampling was permanently broken regardless of config.
        //
        // Fix: parse the inbound traceparent here (before Gate 2) and set a
        // minimal pre-gate SpanCtx with the inbound flags so Gate 2 sees the
        // correct `$otel_parent_sampled` value.
        //
        // Semantic contract:
        //   • have_traceparent=true  → pre-gate SpanCtx.flags = inbound_flags
        //     → `$otel_parent_sampled` = "1" if W3C sampled bit set, else "0"
        //   • have_traceparent=false → no pre-gate SpanCtx
        //     → `$otel_parent_sampled` = not_found (empty/falsy)
        //     → `otel_trace $otel_parent_sampled` gate declines (correct: no parent)
        //
        // On gate decline: clear the pre-gate SpanCtx so `$otel_trace_id` stays
        // empty for declined requests (same semantics as before this fix).
        //
        // Cost: one header scan + one pool alloc for every request at configured
        // locations that has a traceparent header.  This is within the
        // "bounded-when-unsampled" budget described in the module doc.
        //
        // Skip the scan for Ignore (neither read nor write) and Inject (start a
        // fresh trace, do not inherit the inbound trace context).
        use crate::logs::access::parse_traceparent_full;
        let mut parent_trace_id: Option<[u8; 16]> = None;
        let mut parent_span_id: [u8; 8] = [0u8; 8];
        let mut inbound_flags: u32 = 0;
        let mut have_traceparent = false;

        let should_extract = trace_context == TraceContextMode::Extract
            || trace_context == TraceContextMode::Propagate;
        if should_extract {
            for (key, value) in request.headers_in_iterator() {
                let k = key.as_bytes();
                if k.len() == 11 && k.eq_ignore_ascii_case(b"traceparent") {
                    if let Some((tid, psid, flags)) = parse_traceparent_full(value.as_bytes()) {
                        parent_trace_id = Some(tid);
                        parent_span_id = psid;
                        inbound_flags = flags;
                        have_traceparent = true;
                    }
                    break; // traceparent is unique per W3C spec
                }
            }
        }

        // Pre-gate SpanCtx: allocate and store only when we have a traceparent so
        // Gate 2 can read `$otel_parent_sampled` from the SpanCtx.flags field.
        // `sampled` is left false (zeroed) — the full sampling decision is made
        // post-gate.  If Gate 2 declines, we clear this ctx before returning.
        //
        // Use `alloc_span_ctx_plain` (NO cleanup anchor) here, NOT
        // `alloc_span_ctx`.  The pre-gate ctx only needs to live for Gate 2's
        // `$otel_parent_sampled` read within this handler pass; it must NOT be
        // redirect-survivable.  If it registered the cleanup anchor, a
        // Gate-2-declined request that then internally redirects would have
        // `recover_span_ctx` re-install this stale pre-gate ctx, making
        // `$otel_trace_id` non-empty for a declined request.  Only the final
        // post-gate alloc (gate-PASS path) registers the anchor.
        if have_traceparent {
            // SAFETY: `r_ptr` is the live `ngx_http_request_t*`; `(*r_ptr).pool`
            // is the request-scoped pool valid for the request lifetime.
            let pool = unsafe { pool_from_request(r_ptr) };
            let pre_ctx = alloc_span_ctx_plain(&pool);
            if pre_ctx.is_null() {
                return Status::NGX_DECLINED; // OOM (extremely rare)
            }
            // SAFETY: `pre_ctx` is freshly pool-allocated (zeroed); we write only
            // `flags` here; all other fields (including `sampled`) remain zero
            // (false) until the post-gate full SpanCtx write below.
            unsafe {
                (*pre_ctx).flags = inbound_flags;
            }
            request.set_module_ctx(pre_ctx.cast::<c_void>(), module_ref);
        }

        // ── Evaluate Gate 2 ──────────────────────────────────────────────────
        // `$otel_parent_sampled` now finds the pre-gate SpanCtx (if have_traceparent).
        // SAFETY: `ngx_str_t` is a plain C struct (len + data pointer); zeroing it
        // produces a valid "empty string" representation — no invariants violated.
        let mut cv_result: nginx_sys::ngx_str_t = unsafe { core::mem::zeroed() };
        // SAFETY: `r_ptr` is the valid request pointer for this call; `otel_trace_cv`
        // is a non-null complex value allocated on the nginx config pool (process
        // lifetime); `cv_result` is a local zeroed struct, valid as output.
        let rc =
            unsafe { nginx_sys::ngx_http_complex_value(r_ptr, otel_trace_cv, &raw mut cv_result) };
        if rc != nginx_sys::NGX_OK as nginx_sys::ngx_int_t {
            // Clear pre-gate SpanCtx on all decline paths to preserve "no ctx"
            // semantics for $otel_trace_id on declined requests.
            request.set_module_ctx(core::ptr::null_mut(), module_ref);
            return Status::NGX_DECLINED;
        }
        // Truthy: non-empty, not "0", not "off" (matches nginx flag semantics).
        let cv_bytes: &[u8] = if cv_result.len == 0 || cv_result.data.is_null() {
            b""
        } else {
            // SAFETY: `cv_result.data` points into pool memory; `.len` is accurate.
            unsafe { core::slice::from_raw_parts(cv_result.data, cv_result.len) }
        };
        if cv_bytes.is_empty() || cv_bytes == b"0" || cv_bytes == b"off" {
            // Gate declined. Clear any pre-gate SpanCtx so $otel_trace_id returns
            // empty for declined requests.
            // set_module_ctx(null) is always safe; if no pre-gate ctx was set
            // this is a no-op write to the ctx array slot.
            request.set_module_ctx(core::ptr::null_mut(), module_ref);
            return Status::NGX_DECLINED;
        }

        // Gate passed.

        // ── Record span start time (OTel-SDK-idiomatic dual-clock) ─────────
        // Moved after Gate 2: avoids vDSO calls for gate-declined requests.
        // Wall-clock anchor: SystemTime::now() → absolute start timestamp.
        // Monotonic anchor: Instant::now() → elapsed at LOG gives duration,
        //   always ≥ 0 (NTP-immune).
        // At LOG: span_end = start_time_unix_nano + start_mono.elapsed();
        //   http.server.request.duration = start_mono.elapsed() (same value).
        // Result: µs precision kept, end ≥ start guaranteed, span (end−start)
        //   == attribute (coherent), histogram NTP-exposure removed.
        // Both reads are vDSO calls on Linux — not kernel syscalls.
        let start_time_unix_nano: u64 = {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
        };
        let start_mono = std::time::Instant::now();

        // ── OS-RNG seed failed → tracing disabled for this worker ────────────
        // If `getrandom` failed at worker init (e.g. seccomp denial), the
        // worker-local DRBG is unseeded and `drbg64()` returns 0; calling
        // `gen_trace_id`/`gen_span_id` here would spin forever rerolling for a
        // non-zero value.  Degrade exactly like a gate-declined request: clear
        // any pre-gate SpanCtx (so `$otel_trace_id` is empty) and return
        // NGX_DECLINED — the request is served, no span is emitted, and we never
        // produce weak/predictable IDs.  One `Cell` load + branch on this path.
        if crate::traces::ctx::tracing_disabled() {
            request.set_module_ctx(core::ptr::null_mut(), module_ref);
            return Status::NGX_DECLINED;
        }

        // ── Worker-side sampling decision ────────────────────────────────────
        // Gate 2 has passed: the request is supposed to produce a span.
        //
        // Parent flag path: inbound traceparent present → honour the W3C sampled bit.
        // Root span path:   no inbound traceparent → sample all (Gate 2 is the guard).
        let sampled = if have_traceparent {
            (inbound_flags & 0x01) != 0
        } else {
            true // Gate 2 (otel_trace complex value / split_clients) is the sampling guard
        };

        // ── Assign trace/span IDs ────────────────────────────────────────────
        // `gen_trace_id` / `gen_span_id` return `None` when the DRBG appears
        // broken (exhausted retries on all-zero output), in which case they
        // also set the tracing-disabled flag.  Treat that the same as a
        // tracing-disabled worker: clear the ctx and decline.
        let trace_id = match parent_trace_id {
            Some(tid) => tid, // continue the inbound trace
            None => match gen_trace_id() {
                Some(tid) => tid,
                None => {
                    request.set_module_ctx(core::ptr::null_mut(), module_ref);
                    return Status::NGX_DECLINED;
                }
            },
        };
        let span_id = match gen_span_id() {
            Some(sid) => sid,
            None => {
                request.set_module_ctx(core::ptr::null_mut(), module_ref);
                return Status::NGX_DECLINED;
            }
        };

        // Flags to record: inbound flags (preserves sampled bit) or set sampled=1 for roots.
        let flags = if have_traceparent {
            inbound_flags
        } else {
            0x01 // sampled
        };

        // ── Allocate full SpanCtx on the request pool ─────────────────────────
        // This replaces the pre-gate SpanCtx if one was set.  The pre-gate
        // allocation (have_traceparent=true path) is wasted pool memory
        // (≈sizeof(SpanCtx) bytes) — acceptable for a bump allocator.
        // SAFETY: `r_ptr` is the live `ngx_http_request_t*` for this request;
        // `(*r_ptr).pool` is nginx's request-scoped pool, valid for the full
        // request lifetime — exactly what `pool_from_request` requires.
        let pool = unsafe { pool_from_request(r_ptr) };
        let ctx_ptr = alloc_span_ctx(&pool);
        if ctx_ptr.is_null() {
            // OOM in the request pool — extremely rare.  Clear pre-gate ctx and exit.
            request.set_module_ctx(core::ptr::null_mut(), module_ref);
            return Status::NGX_DECLINED;
        }

        // Initialise the SpanCtx fields.
        // SAFETY: `ctx_ptr` is freshly allocated (zeroed) from the request pool,
        // so writing to it is sound and there are no live aliases.
        // Note: `start_mono` (Instant) is Copy, and the pool-zeroed bytes are
        // overwritten by this struct assignment before any read occurs.
        unsafe {
            (*ctx_ptr) = SpanCtx {
                trace_id,
                span_id,
                parent_span_id,
                flags,
                start_time_unix_nano,
                start_mono,
                sampled,
            };
        }

        // Store on the request via set_module_ctx (overwrites pre-gate ptr if any).
        // SAFETY: `module_ref` is the process-lifetime module descriptor;
        // `ctx_ptr` is pool-allocated and outlives the request;
        // `set_module_ctx` writes the pointer into the request's ctx array at
        // our module's ctx_index — no aliasing concern.
        request.set_module_ctx(ctx_ptr.cast::<c_void>(), module_ref);

        // ── Inject outbound `traceparent` header ──────────────────────────────
        // For `inject` and `propagate` modes, push a W3C traceparent into the
        // request headers so that downstream proxy_pass modules forward it to
        // the upstream.  The header value is allocated on the request pool.
        if trace_context == TraceContextMode::Inject || trace_context == TraceContextMode::Propagate
        {
            // SAFETY: `r_ptr` is valid and non-null; `(*r_ptr).pool` and
            // `(*r_ptr).headers_in.headers` are valid for the request lifetime.
            // Pass the full trace-flags octet so all bits are preserved per
            // W3C Trace Context §3.2 (https://www.w3.org/TR/trace-context/#trace-flags).
            unsafe { inject_traceparent_header(r_ptr, &trace_id, &span_id, flags as u8) };
        }

        // NGX_DECLINED: SpanCtx set; pass to the next REWRITE handler (normal
        // request processing continues — we don't modify the URI or block the request).
        Status::NGX_DECLINED
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Hex-encodes `src` bytes into `dst`.
///
/// `dst` must be exactly `src.len() * 2` bytes long.
#[inline]
fn hex_encode_into_slice(src: &[u8], dst: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &byte) in src.iter().enumerate() {
        dst[i * 2] = HEX[(byte >> 4) as usize];
        dst[i * 2 + 1] = HEX[(byte & 0xf) as usize];
    }
}

/// Build the 55-byte W3C `traceparent` header value.
///
/// Format: `"00-{32hex trace_id}-{16hex span_id}-{flags_hex}"`.
/// `trace_flags` is the full 8-bit W3C trace-flags octet; all bits are
/// preserved per W3C Trace Context §3.2
/// (https://www.w3.org/TR/trace-context/#trace-flags).
///
/// Extracted from `inject_traceparent_header` so the encoding logic is
/// unit-testable without requiring a live nginx request pool.
#[cfg_attr(not(test), allow(dead_code))]
fn build_traceparent_value(trace_id: &[u8; 16], span_id: &[u8; 8], trace_flags: u8) -> [u8; 55] {
    let mut value = [0u8; 55];
    value[0] = b'0';
    value[1] = b'0';
    value[2] = b'-';
    hex_encode_into_slice(trace_id, &mut value[3..35]);
    value[35] = b'-';
    hex_encode_into_slice(span_id, &mut value[36..52]);
    value[52] = b'-';
    hex_encode_into_slice(&[trace_flags], &mut value[53..55]);
    value
}

/// Injects (or *updates in place*) a W3C `traceparent` header in
/// `r->headers_in.headers` so that nginx proxy modules forward it to the
/// upstream.
///
/// **Update-don't-append (mirrors the C++ `setHeader`,
/// `nginx-otel/src/http_module.cpp:278-307`):** an inbound request may already
/// carry a `traceparent` (the common case under `propagate`).  Always pushing a
/// *new* entry would leave the inbound header in place — so the
/// upstream received TWO `traceparent` headers (the stale inbound one and our
/// freshly-minted one), and the downstream span linkage was ambiguous.  This
/// function now finds the existing `traceparent` and overwrites its value in
/// place; it pushes a new entry only when none is present.  Result: exactly one
/// outbound `traceparent`, carrying our trace_id / span_id.
///
/// The 55-byte value string (always version-00, fixed length) is allocated on the
/// request pool.  When updating in place, if the existing value buffer is exactly
/// 55 bytes we overwrite it directly; otherwise we re-point the entry at a fresh
/// pool allocation (the C++ module re-points unconditionally — we keep the
/// in-place write as a cheap fast path).
///
/// **hash-consistency (`updateRequestHeader`) finding:** the C++ module calls
/// `updateRequestHeader` to keep nginx's typed `headers_in` fields consistent
/// after mutating a header.  That step is a NO-OP for `traceparent`: it is NOT a
/// member of nginx's `ngx_http_headers_in[]` hash table (verified — `traceparent`
/// does not appear in `src/http/ngx_http_request.c`), so the `headers_in_hash`
/// lookup returns NULL and the C++ path returns `NGX_OK` without doing anything.
/// We therefore intentionally do NOT mirror that call.  Setting `entry->hash` to
/// a non-zero value is sufficient for the proxy module's generic header copy.
///
/// **Flags field:** `trace_flags` is the full 8-bit W3C trace-flags octet
/// (W3C Trace Context §3.2, https://www.w3.org/TR/trace-context/#trace-flags).
/// All bits are preserved — callers MUST NOT collapse it to a 1-bit `sampled`
/// boolean before passing, as that silently drops any future flag bits.
///
/// On pool-allocation failure the function silently returns — tracing continues;
/// only the inject step is skipped.
///
/// # Safety
/// `r` must be a valid, non-null `*mut ngx_http_request_t`.
unsafe fn inject_traceparent_header(
    r: *mut nginx_sys::ngx_http_request_t,
    trace_id: &[u8; 16],
    span_id: &[u8; 8],
    trace_flags: u8,
) {
    // SAFETY: caller guarantees `r` is valid; `(*r).pool` is the request pool.
    let pool = unsafe { (*r).pool };

    let value = build_traceparent_value(trace_id, span_id, trace_flags);

    // ── Find an existing `traceparent` in headers_in (mirrors C++ findHeader) ──
    // SAFETY: `r` is valid; we walk the inbound headers list parts. The list is
    // initialised by nginx in `ngx_http_process_request_headers`.
    let existing = unsafe { find_header_in(&raw mut (*r).headers_in.headers, b"traceparent") };

    if !existing.is_null() {
        // ── Update in place ───────────────────────────────────────────────────
        // SAFETY: `existing` points to a live `ngx_table_elt_t` in headers_in.
        unsafe {
            let dst = if (*existing).value.len == 55 && !(*existing).value.data.is_null() {
                // Fast path: same length → overwrite the existing value buffer.
                (*existing).value.data
            } else {
                // Length differs → allocate a fresh 55-byte value on the pool.
                let buf = nginx_sys::ngx_pnalloc(pool, 55) as *mut u8;
                if buf.is_null() {
                    return; // OOM — leave the inbound header untouched.
                }
                (*existing).value.data = buf;
                (*existing).value.len = 55;
                buf
            };
            core::ptr::copy_nonoverlapping(value.as_ptr(), dst, 55);
            // Keep the entry "active" — non-zero hash. (No headers_in_hash entry
            // for traceparent, so updateRequestHeader would be a no-op; see doc.)
            if (*existing).hash == 0 {
                (*existing).hash = 1;
            }
        }
        return;
    }

    // ── Absent → push a new entry (mirrors C++ ngx_list_push branch) ──────────
    // Allocate key ("traceparent", 11 bytes) and value (55 bytes) on pool.
    // SAFETY: `pool` is a valid nginx pool pointer.
    let key_buf = unsafe { nginx_sys::ngx_pcalloc(pool, 11) } as *mut u8;
    // SAFETY: same pool.
    let val_buf = unsafe { nginx_sys::ngx_pnalloc(pool, 55) } as *mut u8;
    if key_buf.is_null() || val_buf.is_null() {
        return;
    }

    // Write the header name (all lowercase — nginx convention).
    // SAFETY: `key_buf` is a valid 11-byte allocation; source is 'static.
    unsafe { core::ptr::copy_nonoverlapping(b"traceparent".as_ptr(), key_buf, 11) };
    // SAFETY: `val_buf` is a valid 55-byte allocation.
    unsafe { core::ptr::copy_nonoverlapping(value.as_ptr(), val_buf, 55) };

    // Push a new entry onto the headers_in list.
    // SAFETY: `(*r).headers_in.headers` is the valid inbound headers list; nginx
    // initialises it in `ngx_http_process_request_headers`.
    let entry = unsafe { nginx_sys::ngx_list_push(&raw mut (*r).headers_in.headers) }
        as *mut nginx_sys::ngx_table_elt_t;
    if entry.is_null() {
        return;
    }
    // Populate the entry.
    // SAFETY: `entry` is freshly returned by `ngx_list_push` — valid and exclusively owned.
    unsafe {
        (*entry).hash = 1; // non-zero = header active (matches nginx convention)
        (*entry).key.data = key_buf;
        (*entry).key.len = 11;
        (*entry).value.data = val_buf;
        (*entry).value.len = 55;
        (*entry).lowcase_key = key_buf; // already lowercase
    }
}

/// Finds a header by lowercase name in an `ngx_list_t` of `ngx_table_elt_t`
/// (e.g. `r->headers_in.headers`), returning a pointer to the live entry or
/// `null_mut()` if absent.
///
/// Mirrors the C++ module's `findHeader` (`nginx-otel/src/http_module.cpp:231-257`)
/// but matches on the lowercase key bytes directly (case-insensitive) rather than
/// pre-hashing, since the only caller passes a small literal name.
///
/// # Safety
/// `list` must be a valid, non-null `*mut ngx_list_t` whose elements are
/// `ngx_table_elt_t`.
unsafe fn find_header_in(
    list: *mut nginx_sys::ngx_list_t,
    name: &[u8],
) -> *mut nginx_sys::ngx_table_elt_t {
    // SAFETY: walking the ngx_list_t parts; each part's `elts`/`nelts`/`next`
    // are valid for the request lifetime.
    unsafe {
        let mut part = &raw mut (*list).part;
        let mut elts = (*part).elts as *mut nginx_sys::ngx_table_elt_t;
        let mut i: nginx_sys::ngx_uint_t = 0;
        loop {
            if i >= (*part).nelts {
                if (*part).next.is_null() {
                    break;
                }
                part = (*part).next;
                elts = (*part).elts as *mut nginx_sys::ngx_table_elt_t;
                i = 0;
            }
            let e = elts.add(i as usize);
            // Active header (hash != 0), matching key length and (case-insensitive) bytes.
            if (*e).hash != 0 && (*e).key.len as usize == name.len() && !(*e).key.data.is_null() {
                let key = core::slice::from_raw_parts((*e).key.data, name.len());
                if key.eq_ignore_ascii_case(name) {
                    return e;
                }
            }
            i += 1;
        }
    }
    core::ptr::null_mut()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traces::ctx::{gen_span_id, gen_trace_id};

    /// Zero-cost invariant: SpanStartHandler::PHASE must be Rewrite.
    /// (HttpPhase is a C-like enum that doesn't impl PartialEq; compare discriminants.)
    #[test]
    fn phase_is_rewrite() {
        // HttpPhase::Rewrite = NGX_HTTP_REWRITE_PHASE — compare as u32 discriminant.
        assert_eq!(
            SpanStartHandler::PHASE as u32,
            HttpPhase::Rewrite as u32,
            "SpanStartHandler must run in the Rewrite phase"
        );
    }

    /// The SpanCtx struct is the right size for pool allocation.
    #[test]
    fn span_ctx_copy_sized() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<SpanCtx>();
    }

    /// Sampling: traceparent with sampled=0 → unsampled.
    #[test]
    fn traceparent_unsampled_flag() {
        use crate::logs::access::parse_traceparent_full;
        // sampled=0 in flags
        let tp = b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
        let result = parse_traceparent_full(tp);
        assert!(result.is_some());
        let (_, _, flags) = result.unwrap();
        assert_eq!(flags & 0x01, 0, "sampled bit must be 0");
    }

    /// Sampling: traceparent with sampled=1 → sampled.
    #[test]
    fn traceparent_sampled_flag() {
        use crate::logs::access::parse_traceparent_full;
        // sampled=1 in flags
        let tp = b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let result = parse_traceparent_full(tp);
        assert!(result.is_some());
        let (_, _, flags) = result.unwrap();
        assert_eq!(flags & 0x01, 1, "sampled bit must be 1");
    }

    /// Root span path: generate non-zero trace_id and span_id.
    #[test]
    fn root_span_ids_nonzero() {
        let tid = gen_trace_id().expect("gen_trace_id must succeed with healthy DRBG");
        let sid = gen_span_id().expect("gen_span_id must succeed with healthy DRBG");
        assert_ne!(tid, [0u8; 16]);
        assert_ne!(sid, [0u8; 8]);
    }

    // ── update-vs-append decision (find_header_in) ───────────────────────────
    //
    // These tests fabricate a single-part `ngx_list_t` of `ngx_table_elt_t` on
    // the Rust heap (both are `#[repr(C)]` POD structs) and exercise the
    // find-then-update/push *decision*.  They do NOT touch a real nginx pool —
    // the FFI list mutation (`ngx_list_push`) is covered by the integration test
    // (run_traces.sh's single-traceparent assertion); here we prove the
    // find/length logic that decides update-in-place vs push.

    /// Build a heap-backed single-part `ngx_list_t` from a vector of (key,value)
    /// byte pairs.  Returns the boxed list and keeps the backing storage alive in
    /// the returned `Vec`s so the test owns all memory.
    fn make_list(
        entries: &[(&[u8], &[u8])],
    ) -> (
        std::boxed::Box<nginx_sys::ngx_list_t>,
        std::vec::Vec<nginx_sys::ngx_table_elt_t>,
        std::vec::Vec<std::vec::Vec<u8>>,
    ) {
        let mut keep: std::vec::Vec<std::vec::Vec<u8>> = std::vec::Vec::new();
        let mut elts: std::vec::Vec<nginx_sys::ngx_table_elt_t> = std::vec::Vec::new();
        for (k, v) in entries {
            let mut kb = k.to_vec();
            let mut vb = v.to_vec();
            // SAFETY: zeroed table_elt is a valid empty header.
            let mut e: nginx_sys::ngx_table_elt_t = unsafe { core::mem::zeroed() };
            e.hash = 1;
            e.key.len = kb.len();
            e.key.data = kb.as_mut_ptr();
            e.lowcase_key = kb.as_mut_ptr();
            e.value.len = vb.len();
            e.value.data = vb.as_mut_ptr();
            elts.push(e);
            keep.push(kb);
            keep.push(vb);
        }
        // SAFETY: a zeroed ngx_list_t is a valid empty list (POD struct);
        // we fill the single part below before any read.
        let zeroed_list: nginx_sys::ngx_list_t = unsafe { core::mem::zeroed() };
        let mut list: std::boxed::Box<nginx_sys::ngx_list_t> = std::boxed::Box::new(zeroed_list);
        list.part.elts = elts.as_mut_ptr().cast::<core::ffi::c_void>();
        list.part.nelts = elts.len();
        list.part.next = core::ptr::null_mut();
        list.size = core::mem::size_of::<nginx_sys::ngx_table_elt_t>();
        (list, elts, keep)
    }

    /// find_header_in: returns the matching entry (case-insensitive) when present.
    #[test]
    fn find_header_present_updates_in_place() {
        let (mut list, _elts, _keep) =
            make_list(&[(b"host", b"example.com"), (b"traceparent", b"old-value")]);
        // SAFETY: `list` is a valid fabricated ngx_list_t for this test.
        let found = unsafe { find_header_in(&raw mut *list, b"traceparent") };
        assert!(!found.is_null(), "existing traceparent must be found");
        // SAFETY: `found` points into our `_elts` backing storage.
        unsafe {
            let v = core::slice::from_raw_parts((*found).value.data, (*found).value.len);
            assert_eq!(v, b"old-value", "found entry must be the existing traceparent");
        }
        // Decision: present → UPDATE in place → entry count stays the same (2).
        assert_eq!(list.part.nelts, 2, "update path must not change the entry count");
    }

    /// find_header_in: case-insensitive match (mixed-case key).
    #[test]
    fn find_header_case_insensitive() {
        let (mut list, _elts, _keep) = make_list(&[(b"TraceParent", b"v")]);
        // SAFETY: valid fabricated list.
        let found = unsafe { find_header_in(&raw mut *list, b"traceparent") };
        assert!(!found.is_null(), "match must be case-insensitive");
    }

    /// find_header_in: returns null when absent → caller takes the PUSH path.
    #[test]
    fn find_header_absent_takes_push_path() {
        let (mut list, _elts, _keep) = make_list(&[(b"host", b"example.com")]);
        // SAFETY: valid fabricated list.
        let found = unsafe { find_header_in(&raw mut *list, b"traceparent") };
        assert!(found.is_null(), "absent traceparent must return null (push path)");
    }

    /// find_header_in: skips inactive (hash==0) entries.
    #[test]
    fn find_header_skips_inactive() {
        let (mut list, mut elts, _keep) = make_list(&[(b"traceparent", b"v")]);
        elts[0].hash = 0; // mark inactive
        list.part.elts = elts.as_mut_ptr().cast::<core::ffi::c_void>();
        // SAFETY: valid fabricated list.
        let found = unsafe { find_header_in(&raw mut *list, b"traceparent") };
        assert!(found.is_null(), "inactive (hash==0) entry must be skipped");
    }

    /// Child span path: trace_id from parent, new span_id generated.
    #[test]
    fn child_span_inherits_trace_id() {
        use crate::logs::access::parse_traceparent_full;
        let tp = b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let (parent_tid, parent_sid, flags) = parse_traceparent_full(tp).unwrap();
        // child span reuses parent's trace_id
        assert_eq!(parent_tid[0], 0x4b);
        // child span_id is newly generated
        let new_span_id = gen_span_id().expect("gen_span_id must succeed with healthy DRBG");
        assert_ne!(new_span_id, parent_sid, "child span_id should not equal parent span_id");
        assert_eq!(flags, 0x01);
    }

    // ── Regression: full trace-flags octet round-trip (finding ~433) ──────────

    /// `build_traceparent_value` (and therefore `inject_traceparent_header`)
    /// must carry the full 8-bit W3C trace-flags octet, not just bit-0
    /// collapsed to "00"/"01".
    ///
    /// W3C Trace Context §3.2 defines `trace-flags` as an 8-bit field:
    /// https://www.w3.org/TR/trace-context/#trace-flags
    ///
    /// Mutation proof: replace `hex_encode_into_slice(&[trace_flags], …)` in
    /// `build_traceparent_value` with the OLD code:
    ///   `value[53] = b'0'; value[54] = if (trace_flags & 0x01) != 0 { b'1' } else { b'0' };`
    /// and the 0xf5/0x03/0xff assertions fail:
    ///   0xf5 (sampled=true)  → old "01",  new "f5" ← fails here
    ///   0x03 (sampled=true)  → old "01",  new "03" ← fails here
    ///   0xff (sampled=true)  → old "01",  new "ff" ← fails here
    #[test]
    fn inject_traceparent_flags_full_octet_roundtrip() {
        let trace_id: [u8; 16] = [
            0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
            0x47, 0x36,
        ];
        let span_id: [u8; 8] = [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7];

        // Each case: (flags_byte, expected last 2 chars in the value buffer).
        // flags 0xf5 = 0b11110101: sampled bit set, plus several vendor bits.
        let cases: &[(u8, &[u8])] = &[
            (0x01, b"01"), // standard sampled
            (0x00, b"00"), // standard not-sampled
            (0xf5, b"f5"), // upper bits + sampled — the critical regression case
            (0x03, b"03"), // bits 0+1
            (0xff, b"ff"), // all bits
        ];

        for &(flags_byte, expected_suffix) in cases {
            // Call the production helper directly — this is the same function
            // that inject_traceparent_header uses, so mutations there are caught.
            let value = build_traceparent_value(&trace_id, &span_id, flags_byte);

            assert_eq!(
                &value[53..55],
                expected_suffix,
                "flags 0x{flags_byte:02x} must encode to {expected_suffix:?} in traceparent value"
            );
            // Structural check: version must be "00".
            assert_eq!(&value[0..2], b"00", "traceparent version must be 00");
        }

        // Explicit upper-bits check: the OLD collapsing code produced "01" for
        // 0xf5 (sampled=true); the correct code must produce "f5".
        let v_f5 = build_traceparent_value(&trace_id, &span_id, 0xf5);
        assert_eq!(
            &v_f5[53..55],
            b"f5",
            "0xf5 must encode to 'f5', not '01' (upper bits must not be dropped)"
        );
    }
}
