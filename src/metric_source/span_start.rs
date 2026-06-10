// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Rewrite-phase span-start handler — Phase 3.3 hot path.
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
//! - (when sampled) pushes a `SpanRecord` to the spans ring (Phase 3.4, Step S2).
//!
//! The Log phase no longer re-scans request headers for `traceparent`; this
//! closes the §6.6.3 parse-once plan item.
//!
//! # Hard budget rules
//! - **Zero cost when disabled:** handler is only registered when
//!   `amcf.is_configured()` is true (see `lib.rs::postconfiguration`).  If
//!   tracing is not configured for a location (Phase 3.5 will add the per-location
//!   `otel_trace` directive), the handler returns immediately.
//! - **Bounded when unsampled:** pool-alloc + one header scan + sampling branch.
//!   No span record, no ring push, no second header scan in LOG.
//! - No heap allocation, no locks, no logging, no `std::thread::spawn`.

use core::ffi::c_void;

use ngx::core::Status;
use ngx::http::{
    HttpModuleLocationConf, HttpModuleMainConf, HttpPhase, HttpRequestHandler, Request,
};

use crate::metric_source::location_conf::{LocationConf, TraceContextMode};
use crate::traces::ctx::{alloc_span_ctx, gen_span_id, gen_trace_id, pool_from_request, SpanCtx};
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

        // ── D1 fix: parse inbound `traceparent` BEFORE Gate 2 ────────────────
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
        if have_traceparent {
            // SAFETY: `r_ptr` is the live `ngx_http_request_t*`; `(*r_ptr).pool`
            // is the request-scoped pool valid for the request lifetime.
            let pool = unsafe { pool_from_request(r_ptr) };
            let pre_ctx = alloc_span_ctx(&pool);
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
            // empty for declined requests (same semantics as before D1 fix).
            // set_module_ctx(null) is always safe; if no pre-gate ctx was set
            // this is a no-op write to the ctx array slot.
            request.set_module_ctx(core::ptr::null_mut(), module_ref);
            return Status::NGX_DECLINED;
        }

        // Gate passed.

        // ── Record span start time (OTel-SDK-idiomatic dual-clock, D-2) ─────
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
        let trace_id = match parent_trace_id {
            Some(tid) => tid,       // continue the inbound trace
            None => gen_trace_id(), // root span: start a new trace
        };
        let span_id = gen_span_id();

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
            unsafe { inject_traceparent_header(r_ptr, &trace_id, &span_id, sampled) };
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

/// Injects a W3C `traceparent` header into `r->headers_in.headers` so that
/// nginx proxy modules forward it to the upstream.
///
/// The 55-byte value string and the 11-byte key string are allocated on the
/// request pool (lifetime = request).
///
/// On pool-allocation failure the function silently returns — tracing
/// continues; only the inject step is skipped.
///
/// # Safety
/// `r` must be a valid, non-null `*mut ngx_http_request_t`.
unsafe fn inject_traceparent_header(
    r: *mut nginx_sys::ngx_http_request_t,
    trace_id: &[u8; 16],
    span_id: &[u8; 8],
    sampled: bool,
) {
    // SAFETY: caller guarantees `r` is valid; `(*r).pool` is the request pool.
    let pool = unsafe { (*r).pool };

    // Allocate key ("traceparent", 11 bytes) and value (55 bytes) on pool.
    // SAFETY: `pool` is a valid nginx pool pointer.
    let key_buf = unsafe { nginx_sys::ngx_pcalloc(pool, 11) } as *mut u8;
    // SAFETY: same pool.
    let val_buf = unsafe { nginx_sys::ngx_pcalloc(pool, 55) } as *mut u8;
    if key_buf.is_null() || val_buf.is_null() {
        return;
    }

    // Write the header name (all lowercase — nginx convention).
    // SAFETY: `key_buf` is a valid 11-byte allocation; source is 'static.
    unsafe { core::ptr::copy_nonoverlapping(b"traceparent".as_ptr(), key_buf, 11) };

    // Build value: "00-{32hex trace_id}-{16hex span_id}-{flags}"  (55 bytes)
    // SAFETY: `val_buf` is a valid 55-byte allocation.
    let s = unsafe { core::slice::from_raw_parts_mut(val_buf, 55) };
    s[0] = b'0';
    s[1] = b'0';
    s[2] = b'-';
    hex_encode_into_slice(trace_id, &mut s[3..35]);
    s[35] = b'-';
    hex_encode_into_slice(span_id, &mut s[36..52]);
    s[52] = b'-';
    s[53] = b'0';
    s[54] = if sampled { b'1' } else { b'0' };

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
        let tid = gen_trace_id();
        let sid = gen_span_id();
        assert_ne!(tid, [0u8; 16]);
        assert_ne!(sid, [0u8; 8]);
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
        let new_span_id = gen_span_id();
        assert_ne!(new_span_id, parent_sid, "child span_id should not equal parent span_id");
        assert_eq!(flags, 0x01);
    }
}
