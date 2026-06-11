// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Module-side C shim for `ngx_http_request_t` bitfields that rust-bindgen
//! reads at the **wrong bit offset**.
//!
//! rust-bindgen mis-lays-out `ngx_http_request_t`'s bitfields: a non-bitfield
//! member (`in_port_t port`) shares the leading 4-byte allocation unit with the
//! first bitfield, so the C compiler's struct-absolute no-straddle padding lands
//! 2 bits higher than bindgen's unit-local model.  Every bindgen accessor **at
//! or after `uri_changes`** therefore reads 2 bits low (`internal()` reads bit
//! 84, the real flag is bit 86).  This is the allocation-unit-sharing bug class
//! (rust-bindgen #111 / #743 / #1132), reproduced on gcc-14, clang-19, and Apple
//! clang — see `BINDGEN_BITFIELD_ISSUE_DRAFT.md` and
//! `src/shim/ngx_otel_bitfield_shim.c` for the full evidence.
//!
//! The shim functions are compiled by `build.rs` (via the `cc` crate) against
//! the real nginx headers, so they read exactly the bits nginx itself reads —
//! correct by construction.
//!
//! **Maintainer rule:** any NEW read of an `ngx_http_request_t` bitfield at or
//! after `uri_changes` MUST go through a wrapper here, never a bindgen accessor.
//! (H3F10 audits the remaining call-sites and extends this shim.)

use nginx_sys::ngx_http_request_t;

extern "C" {
    /// C accessor for `r->internal` — see module docs / the `.c` header.
    /// bindgen's `internal()`/`internal_raw()` read 2 bits low; this does not.
    fn ngx_otel_shim_r_internal(r: *const ngx_http_request_t) -> core::ffi::c_uint;
    /// C accessor for `r->filter_finalize` — see module docs / the `.c` header.
    /// bindgen's `filter_finalize_raw()` reads 2 bits low; this does not.
    fn ngx_otel_shim_r_filter_finalize(r: *const ngx_http_request_t) -> core::ffi::c_uint;
}

/// Read `r->internal` (0 or 1) via the C shim.
///
/// # Safety
/// `r` must be a valid, non-null `*const ngx_http_request_t`.
#[inline]
pub unsafe fn r_internal(r: *const ngx_http_request_t) -> core::ffi::c_uint {
    // SAFETY: caller guarantees `r` is a valid request pointer; the C shim only
    // reads the `internal` bitfield through nginx's own header layout.
    unsafe { ngx_otel_shim_r_internal(r) }
}

/// Read `r->filter_finalize` (0 or 1) via the C shim.
///
/// # Safety
/// `r` must be a valid, non-null `*const ngx_http_request_t`.
#[inline]
pub unsafe fn r_filter_finalize(r: *const ngx_http_request_t) -> core::ffi::c_uint {
    // SAFETY: caller guarantees `r` is a valid request pointer; the C shim only
    // reads the `filter_finalize` bitfield through nginx's own header layout.
    unsafe { ngx_otel_shim_r_filter_finalize(r) }
}
