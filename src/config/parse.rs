// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Parsing helpers for nginx configuration directive values (time strings,
//! size strings, decimal integers) into Rust numeric types. No nginx FFI
//! dependency; unit-tested in `config/mod.rs`.

/// Parses duration strings to milliseconds, matching the nginx
/// `ngx_parse_time(value, /*is_sec=*/0)` grammar: `500ms`, `5s`, `5m`, `2h`,
/// `1d`, or a bare integer treated as seconds — the same grammar the C++
/// `nginx-otel` `interval` directive uses via `ngx_conf_set_msec_slot`.
pub(crate) fn parse_duration_ms(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
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

/// Parses a size string like `1024`, `10k`, `5m`, `2g` to bytes.
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
    // `try_from` (not `as usize`) avoids silently truncating values > u32::MAX
    // on 32-bit targets into a wrong, smaller size.
    let n_usize = usize::try_from(n).ok()?;
    n_usize.checked_mul(mult)
}

/// Rounds `n` up to the nearest multiple of 8 (`None` on `usize` overflow).
/// `otel_log_ring_size` needs this because the log ring's three shm sections
/// sit at offsets that are multiples of `ring_size_bytes(cap)`, and each must
/// be `AtomicU64`-aligned. Test-support only; production uses the auto-default.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn align_ring_size(n: usize) -> Option<usize> {
    n.checked_next_multiple_of(8)
}

/// Parses a decimal ASCII string to u64.
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
