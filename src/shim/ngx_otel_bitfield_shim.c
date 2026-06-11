/*
 * Copyright (c) F5, Inc.
 *
 * This source code is licensed under the Apache License, Version 2.0 license
 * found in the LICENSE file in the root directory of this source tree.
 *
 * ngx_otel_bitfield_shim.c — module-side C accessors for ngx_http_request_t
 * bitfields that rust-bindgen reads at the WRONG bit offset.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * rust-bindgen mis-lays-out the bitfields of `ngx_http_request_t`.  The struct
 * has a non-bitfield member, `in_port_t port` (an `unsigned short`), that shares
 * the leading 4-byte allocation unit with the first `unsigned int` bitfield.
 * Per the platform ABI's no-straddle rule, the C compiler inserts 2 pad bits
 * before `uri_changes` (so that bitfield does not straddle the 4-byte container
 * boundary) — and it computes that padding in STRUCT-ABSOLUTE coordinates.
 * bindgen instead re-packs the bitfields densely into a fresh `_bitfield_1`
 * unit and applies the straddle rule in UNIT-LOCAL coordinates, ignoring the 16
 * bits `port` consumes in the shared leading unit.  The result: every accessor
 * AT OR AFTER `uri_changes` is generated 2 bits too low.
 *
 *   - `internal`        true layout = bit 86; bindgen accessor reads bit 84.
 *   - `filter_finalize` (and every later bitfield) is likewise 2 bits low.
 *   - `header_only`     true layout = bit 80; bindgen accessor reads bit 78.
 *
 * Because bindgen's accessors silently read adjacent bits, the Rust-side reads
 * of these flags are WRONG on every platform — verified against gcc-14 DWARF
 * (DW_AT_data_bit_offset), clang-19 `-fdump-record-layouts`, and Apple clang
 * DWARF on arm64; the compiled ABI is identical across all three.  No bindgen
 * version or flag fixes it; this is the allocation-unit-sharing bug class
 * tracked upstream as rust-bindgen issues #111 / #743 / #1132.  Full evidence
 * and the reduced minimal repro are in BINDGEN_BITFIELD_ISSUE_DRAFT.md at the
 * repo-parent root.
 *
 * WHY THE C COMPILER IS AUTHORITATIVE
 * -----------------------------------
 * These accessors are compiled by OUR build (build.rs, via the `cc` crate)
 * against the REAL nginx headers, using the same include paths and -D defines
 * nginx-sys used to build nginx.  The C compiler OWNS the struct layout: a
 * `r->internal` read here resolves to the exact same bits the rest of nginx
 * (compiled by the same toolchain) reads.  This is correct by construction —
 * there is no second, divergent layout model the way bindgen introduces one.
 *
 * This is a module-side .c (compiled here), NOT a change to the ngx-rust fork:
 * the fork stays frozen.
 *
 * RULE FOR FUTURE MAINTAINERS
 * ---------------------------
 * Any NEW read of an `ngx_http_request_t` bitfield that lives AT OR AFTER
 * `uri_changes` in the struct (`uri_changes`, `blocked`, `aio`, ... `internal`,
 * `error_page`, `filter_finalize`, ... `done`, and every later flag) MUST go
 * through a shim accessor added here — it CANNOT be read through the bindgen
 * accessor, which will be 2 bits low.  Bitfields BEFORE `uri_changes` are
 * unaffected.  (Item H3F10 completed the exhaustive call-site audit — see the
 * H3F10 AUDIT block below; this file shims every BROKEN request-bitfield read
 * found.)
 *
 * H3F10 AUDIT (2026-06-11; enumeration completed in the follow-up)
 * ----------------------------------------------------------------
 * ENUMERATION METHOD: every bitfield-accessor name (getters, setters, and
 * `*_raw` forms) was extracted from the generated `bindings.rs` (each
 * `pub fn NAME` whose body touches `_bitfield_1`; 1246 names), intersected with
 * every call site in src/ (both the `.NAME(` method-call form and the
 * `NAME_raw(` free form), the stdlib-colliding names filtered out by reading
 * each receiver, and the receiver TYPE resolved for every survivor.  Four nginx
 * structs are reached through a bindgen bitfield accessor in src/.  Each was
 * classified against authoritative clang `-fdump-record-layouts` output on
 * debian-vm (Debian clang 19.1.7, aarch64); see
 * tests/RESULTS-h3f10-clang-record-layouts-2026-06-11.txt for the full layout
 * dumps, the bindgen-vs-clang per-field bit comparison, and the reproduce line.
 *
 *   - `ngx_http_request_t` — BROKEN at/after `uri_changes` (this bug; the only
 *       struct carrying the trigger).  Reads routed through this shim:
 *       `r_internal` (span_start.rs, ctx.rs), `r_filter_finalize` (ctx.rs),
 *       `r_header_only` (lib.rs:1133, test/test-support).
 *   - `ngx_event_t` — SAFE.  `.timedout()`/`.active()`/`.timer_set()` in
 *       src/transport/hyper_http.rs AND `.timer_set()` on the stack
 *       `backstop_ev` in src/exporter/mod.rs:515.  The bitfield region begins
 *       container-aligned at byte 8, right after the leading `void *data`
 *       pointer; NO non-bitfield member shares its leading allocation unit, so
 *       the no-straddle trigger is absent.  active/timedout/timer_set match
 *       bindgen bit-for-bit (unit-local 3/10/11).  Left on the bindgen accessors.
 *   - `ngx_variable_value_t` — SAFE.  The SETTERS `set_len`/`set_valid`/
 *       `set_no_cacheable`/`set_not_found` in the production variable handlers
 *       `otel_var_get_trace_id` / `otel_var_get_parent_sampled` (src/lib.rs:644,
 *       650-653, 657, 708-711, 715).  `_bitfield_1` is the FIRST member of the
 *       struct, so no non-bitfield member shares its leading unit and bindgen's
 *       packing equals the C ABI (len@0/valid@28/no_cacheable@29/not_found@30/
 *       escape@31).  Setters write the correct bits.
 *   - `ngx_buf_t` — SAFE.  `set_last_buf`/`set_last_in_chain` at src/lib.rs:1145
 *       (test/test-support otel_status content handler, via the ngx-rust Buffer
 *       wrapper).  The bitfield region begins at byte 72 right after the pointer
 *       `shadow`; no non-bitfield member shares its leading unit; last_buf@7 /
 *       last_in_chain@8 match bindgen exactly.
 *
 * NO OTHER SITE: this enumeration is exhaustive over src/ as of the audited
 * HEAD (aa9606b) — there is no other bindgen bitfield-accessor read or write,
 * and no `*_raw` call site, anywhere in src/ (the two `_raw` tokens in
 * src/shim/mod.rs are doc comments).  The per-struct verdict -> evidence record
 * lives in the committed layout file named above.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * Return r->internal (0 or 1).  Used by the REWRITE-phase span-start guard and
 * by recover_span_ctx to detect internal-redirect / subrequest re-entry.
 */
unsigned
ngx_otel_shim_r_internal(const ngx_http_request_t *r)
{
    return (unsigned) r->internal;
}

/*
 * Return r->filter_finalize (0 or 1).  Used by recover_span_ctx alongside
 * r->internal to detect a redirect/filter-finalize continuation.
 */
unsigned
ngx_otel_shim_r_filter_finalize(const ngx_http_request_t *r)
{
    return (unsigned) r->filter_finalize;
}

/*
 * Return r->header_only (0 or 1).  `header_only` lives after `uri_changes`
 * (true layout bit 80; bindgen reads bit 78), so it MUST go through this shim.
 * Used by the otel_status_endpoint content handler to skip the body on HEAD.
 */
unsigned
ngx_otel_shim_r_header_only(const ngx_http_request_t *r)
{
    return (unsigned) r->header_only;
}
