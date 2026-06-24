// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Parsing helpers for nginx configuration directives.
//!
//! These functions parse the textual forms that nginx directive values take
//! (time strings, size strings, decimal integers) into Rust numeric types.
//! They have no dependency on nginx FFI and are unit-tested in `config/mod.rs`.

/// Parse duration strings → milliseconds.
///
/// Accepted forms match the nginx `ngx_parse_time(value, /*is_sec=*/0)` grammar
/// (millisecond mode): `500ms`, `5s`, `5m`, `2h`, `1d`, or a bare integer
/// treated as **seconds** (e.g. `5` → 5000 ms).  This is the same grammar that
/// the C++ `nginx-otel` `interval` directive uses via `ngx_conf_set_msec_slot`.
pub(crate) fn parse_duration_ms(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    // Check for the two-character `ms` suffix first.
    if s.ends_with(b"ms") {
        let n = parse_u64_ascii(&s[..s.len() - 2])?;
        return n.checked_mul(1); // already in milliseconds
    }
    let (num_bytes, suffix) = match s.last() {
        Some(b's') => (&s[..s.len() - 1], 1_000u64),
        Some(b'm') => (&s[..s.len() - 1], 60_000u64),
        Some(b'h') => (&s[..s.len() - 1], 3_600_000u64),
        Some(b'd') => (&s[..s.len() - 1], 86_400_000u64),
        _ => (s, 1_000u64), // bare integer treated as seconds
    };
    let n = parse_u64_ascii(num_bytes)?;
    n.checked_mul(suffix)
}

/// Parse a size string like `1024`, `10k`, `5m`, `2g` → bytes.
pub(crate) fn parse_size_bytes(s: &[u8]) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let (num_bytes, mult) = match s.last() {
        Some(&c) if c.is_ascii_alphabetic() => {
            let m = match c.to_ascii_lowercase() {
                b'k' => 1024usize,
                b'm' => 1024 * 1024,
                b'g' => 1024 * 1024 * 1024,
                _ => return None,
            };
            (&s[..s.len() - 1], m)
        }
        _ => (s, 1usize),
    };
    let n = parse_u64_ascii(num_bytes)?;
    // Use `try_from` to avoid silent truncation on 32-bit targets where
    // `n as usize` would silently discard the high 32 bits for values > u32::MAX,
    // producing a wrong (smaller) size without an error.
    let n_usize = usize::try_from(n).ok()?;
    n_usize.checked_mul(mult)
}

/// Round `n` up to the nearest multiple of 8, returning `None` if the result
/// would overflow `usize`.
///
/// The log-ring-size directive stores three contiguous sections in shared
/// memory at offsets that are multiples of `ring_size_bytes(cap)`; for
/// `AtomicU64` alignment at each boundary `cap` must be a multiple of 8.
/// Values near `usize::MAX` where rounding up would overflow are rejected
/// here so the caller can surface an error rather than panic.
pub(crate) fn align_ring_size(n: usize) -> Option<usize> {
    n.checked_next_multiple_of(8)
}

/// Parse a decimal ASCII string → u64.
pub(crate) fn parse_u64_ascii(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(v)
}
