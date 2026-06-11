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
 * unaffected.  (Item H3F10 audits the remaining call-sites and extends this
 * shim accordingly; this file currently covers H3F1's needs only.)
 *
 * H3F10 AUDIT (2026-06-11)
 * ------------------------
 * Every bindgen bitfield-accessor read across src/ production code was
 * enumerated and classified against authoritative DWARF
 * (DW_AT_data_bit_offset / pahole) on debian-vm:
 *
 *   - `ngx_http_request_t` — BROKEN at/after `uri_changes` (this bug).
 *       Production/test reads routed through this shim: `r_internal`,
 *       `r_filter_finalize`, `r_header_only`.
 *   - `ngx_event_t` (`.timedout()`, `.active()`, `.timer_set()` in
 *       src/transport/hyper_http.rs) — SAFE: the bitfield unit begins on its
 *       own 4-byte-aligned offset right after the leading `void *data`
 *       pointer; NO non-bitfield member shares the leading allocation unit,
 *       all fields are single-bit and live in the first 32-bit container, so
 *       the no-straddle trigger does not exist.  Verified bit-exact vs DWARF.
 *       Left on the bindgen accessors.
 *
 * See the audit table in the H3F10 commit message for the full struct ->
 * verdict -> evidence record.
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
