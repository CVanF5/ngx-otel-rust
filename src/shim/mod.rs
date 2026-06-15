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
//! clang.  The full evidence (DWARF layout vs. bindgen output, three-compiler
//! comparison) is recorded in `src/shim/ngx_otel_bitfield_shim.c`.
//!
//! The shim functions are compiled by `build.rs` (via the `cc` crate) against
//! the real nginx headers, so they read exactly the bits nginx itself reads —
//! correct by construction.
//!
//! **Maintainer rule:** any NEW read of an `ngx_http_request_t` bitfield at or
//! after `uri_changes` MUST go through a wrapper here, never a bindgen accessor.
//!
//! An exhaustive audit of every bindgen bitfield accessor
//! (getters AND setters AND `*_raw` forms) called anywhere in src/ found four
//! nginx structs reached — `ngx_http_request_t` (BROKEN, shimmed here),
//! `ngx_event_t`, `ngx_variable_value_t` (setters), and `ngx_buf_t`, the latter
//! three all SAFE (bindgen layout matches the C ABI bit-for-bit). The full
//! enumeration method and per-field bindgen-vs-clang comparison are recorded in
//! the audit block in `ngx_otel_bitfield_shim.c`.

use nginx_sys::ngx_http_request_t;

extern "C" {
    /// C accessor for `r->internal` — see module docs / the `.c` header.
    /// bindgen's `internal()`/`internal_raw()` read 2 bits low; this does not.
    fn ngx_otel_shim_r_internal(r: *const ngx_http_request_t) -> core::ffi::c_uint;
    /// C accessor for `r->filter_finalize` — see module docs / the `.c` header.
    /// bindgen's `filter_finalize_raw()` reads 2 bits low; this does not.
    fn ngx_otel_shim_r_filter_finalize(r: *const ngx_http_request_t) -> core::ffi::c_uint;
}

// `r_header_only`'s only caller is the `otel_status_endpoint` content handler,
// which is gated on `cfg(any(test, feature = "test-support"))`; gate the shim
// accessor identically so the production cdylib does not carry an unused FFI
// import (the C symbol is always compiled by build.rs, but the Rust import is
// dead in a plain release build). The misread it corrects is real on all
// platforms — see the audit note in `ngx_otel_bitfield_shim.c`.
#[cfg(any(test, feature = "test-support"))]
extern "C" {
    /// C accessor for `r->header_only` — see module docs / the `.c` header.
    /// bindgen's `header_only()` reads bit 78 (real layout bit 80); this does not.
    fn ngx_otel_shim_r_header_only(r: *const ngx_http_request_t) -> core::ffi::c_uint;
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

/// Read `r->header_only` (0 or 1) via the C shim.
///
/// `header_only` lives after `uri_changes` in `ngx_http_request_t`, so the
/// bindgen `header_only()` accessor reads 2 bits low; this reads the real flag.
///
/// Gated to the test / test-support builds that carry its only caller (the
/// `otel_status_endpoint` content handler); see the gated `extern` block above.
///
/// # Safety
/// `r` must be a valid, non-null `*const ngx_http_request_t`.
#[cfg(any(test, feature = "test-support"))]
#[inline]
pub unsafe fn r_header_only(r: *const ngx_http_request_t) -> core::ffi::c_uint {
    // SAFETY: caller guarantees `r` is a valid request pointer; the C shim only
    // reads the `header_only` bitfield through nginx's own header layout.
    unsafe { ngx_otel_shim_r_header_only(r) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locate the single set bit inside an `ngx_http_request_t`'s `_bitfield_1`
    /// allocation unit, returned as a (byte, bit-in-byte) pair, by diffing a
    /// zeroed request against one mutated by a closure.  Returns `None` if no
    /// byte changed.  Layout-define-independent: it discovers wherever bindgen
    /// or nginx actually placed the bit, rather than hard-coding an offset.
    fn find_changed_bit(mutate: impl FnOnce(&mut ngx_http_request_t)) -> Option<(usize, u8)> {
        // SAFETY: `ngx_http_request_t` is a `#[repr(C)]` POD aggregate; an all-
        // zero bit pattern is a valid (empty) instance for the purpose of
        // reading/writing its bitfield bytes — we never dereference its
        // pointer members.
        let base: ngx_http_request_t = unsafe { core::mem::zeroed() };
        let mut mutated = base;
        mutate(&mut mutated);
        // SAFETY: viewing the fully-initialised `repr(C)` value as its own bytes;
        // `base` lives for the whole borrow and the length is its exact size.
        let a = unsafe {
            core::slice::from_raw_parts(
                (&raw const base).cast::<u8>(),
                core::mem::size_of::<ngx_http_request_t>(),
            )
        };
        // SAFETY: same — `mutated` is initialised and outlives this byte view.
        let b = unsafe {
            core::slice::from_raw_parts(
                (&raw const mutated).cast::<u8>(),
                core::mem::size_of::<ngx_http_request_t>(),
            )
        };
        for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
            let diff = x ^ y;
            if diff != 0 {
                return Some((i, diff.trailing_zeros() as u8));
            }
        }
        None
    }

    /// Bitfield mutation-anchor test.
    ///
    /// Proves (1) the bindgen `header_only()` accessor and the C shim
    /// `r_header_only` read DIFFERENT bits, and (2) the shim follows the REAL
    /// `header_only` flag while the bindgen accessor reads 2 bits low.
    ///
    /// Method is layout-define-independent: we discover the bit bindgen's
    /// `set_header_only` writes, set the bit two positions HIGHER (the true
    /// nginx layout, per the allocation-unit-sharing bug), and assert the shim
    /// reads 1 while the bindgen getter reads 0.
    ///
    /// MUTATION: replace `r_header_only(rp)` below with `(*rp).header_only()`
    /// (the bindgen accessor) → the `shim must read the REAL bit` assertion
    /// fails, because the bindgen getter reads the cleared low bit.
    #[test]
    fn h3f10_header_only_shim_reads_real_bit_not_bindgen() {
        // (1) Discover where bindgen's setter writes `header_only`.
        let bindgen_bit = find_changed_bit(|r| r.set_header_only(1))
            .expect("set_header_only(1) must flip exactly one bit");
        let (byte, bit) = bindgen_bit;

        // The true nginx layout places `header_only` two bits HIGHER than the
        // bindgen accessor (the documented +2 shift for fields at/after
        // `uri_changes`).  Compute that real bit position.
        let real_linear = byte * 8 + bit as usize + 2;
        let (real_byte, real_bit) = (real_linear / 8, (real_linear % 8) as u8);

        // (2) Build a request with ONLY the real bit set (bindgen's bit clear).
        // SAFETY: zeroed `#[repr(C)]` POD; we touch only its raw bytes.
        let mut req: ngx_http_request_t = unsafe { core::mem::zeroed() };
        {
            // SAFETY: `req` is an initialised `repr(C)` value; we view it as its
            // own bytes (exact size) to flip one bit in its bitfield region.
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    (&raw mut req).cast::<u8>(),
                    core::mem::size_of::<ngx_http_request_t>(),
                )
            };
            bytes[real_byte] |= 1 << real_bit;
        }
        let rp = &raw const req;

        // Sanity: the bit we set must NOT be the one bindgen reads.
        assert_ne!(
            (real_byte, real_bit),
            (byte, bit),
            "real header_only bit must differ from the bindgen accessor bit"
        );

        // The bindgen getter reads its (cleared, 2-bits-low) bit → 0.
        // SAFETY: `rp` points to our live, fully-initialised request bytes.
        let via_bindgen = unsafe { (*rp).header_only() };
        // The shim reads nginx's real layout → 1.
        // SAFETY: same; the C shim only reads the bitfield.
        let via_shim = unsafe { r_header_only(rp) };

        assert_eq!(via_bindgen, 0, "bindgen header_only() must read the (cleared) 2-bits-low bit");
        assert_eq!(
            via_shim, 1,
            "shim must read the REAL header_only bit (this fails if the call site uses the bindgen accessor)"
        );
    }
}
