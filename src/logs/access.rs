// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Access-record formatter.
//!
//! Formats a fixed-shape HTTP access log record **on the stack** (no heap
//! allocation) and pushes it into the calling worker's per-worker ring via
//! a [`LogProducer`].
//!
//! # Wire format (inside the ring's 4-byte length prefix)
//!
//! ```text
//! [u8  kind       = 0x00 (access)]
//! [u64 ts_unix_nano  big-endian  ]
//! [u8  ngx_level  = 7  (info)    ]
//! [u16 method_len big-endian     ]
//! [method_len bytes of method    ]
//! [u16 status_code big-endian    ] (u16: range 0–65535; HTTP status fits)
//! [u64 request_length big-endian ]
//! [u64 response_bytes big-endian ]
//! [u16 client_addr_len big-endian]
//! [client_addr_len bytes         ]
//! --- W3C trace correlation ---
//! [u8  has_trace  = 0|1          ]  (1 = valid traceparent was present)
//! if has_trace == 1:
//!   [16 bytes trace_id            ]
//!   [8  bytes span_id (parent_id) ]
//! --- high-cardinality detail ---
//! [u16 url_path_len big-endian   ]
//! [url_path_len bytes of url.path]
//! [u16 user_agent_len big-endian ]
//! [user_agent_len bytes          ]
//! --- request duration ---
//! [u64 duration_us big-endian    ]  (µs; same unit as exp-histogram)
//! ```
//!
//! The `has_trace = 0` case costs nothing beyond one extra byte in the record.
//! Absent/malformed `traceparent` ⇒ `has_trace = 0`.  The exporter attaches
//! trace context to exemplars and tail `LogRecord`s from these fields.
//!
//! # Constraint: no allocation
//! The entire record is formatted into a fixed-size stack buffer
//! `[u8; MAX_ACCESS_RECORD]`; fields that would overflow it are truncated.

use super::LogProducer;

/// Maximum size of a formatted access record in bytes.
///
/// Worst case (all fields at cap, `has_trace = 1`): kind(1) + ts(8) +
/// level(1) + method(2+16) + status(2) + req_len(8) + resp(8) +
/// client_addr(2+46) + trace(1+16+8) + url_path(2+64) + user_agent(2+128) +
/// duration_us(8) = **323 bytes**, rounded up to 336 (16-byte aligned).
/// The compile-time guard `ACCESS_RECORD_WORST_CASE ≤ MAX_ACCESS_RECORD` below
/// turns any future field/cap bump that would overflow this into a **build
/// failure**, not a latent panic.
pub const MAX_ACCESS_RECORD: usize = 336;

/// Maximum `url.path` bytes stored in the record.
/// Single-homed here; `shm.rs` imports this constant for the exemplar reservoir.
pub const MAX_URL_PATH: usize = 64;
/// Maximum `user_agent.original` bytes stored in the record.
/// Single-homed here; `shm.rs` imports this constant for the exemplar reservoir.
pub const MAX_USER_AGENT: usize = 128;
/// Maximum `client.address` bytes stored in the record.
pub const MAX_CLIENT_ADDR: usize = 46;
/// Maximum `http.request.method` bytes stored in the record.
/// Single-homed here so the doc arithmetic above and the wire layout stay in sync.
pub const MAX_METHOD: usize = 16;

/// Worst-case access record length, derived from the named caps above
/// (see `MAX_ACCESS_RECORD` for the field-by-field breakdown).
pub const ACCESS_RECORD_WORST_CASE: usize = 1
    + 8
    + 1
    + (2 + MAX_METHOD)
    + 2
    + 8
    + 8
    + (2 + MAX_CLIENT_ADDR)
    + (1 + 16 + 8)
    + (2 + MAX_URL_PATH)
    + (2 + MAX_USER_AGENT)
    + 8;

/// Compile-time overflow guard (see `MAX_ACCESS_RECORD` doc).
const _: () = assert!(
    ACCESS_RECORD_WORST_CASE <= MAX_ACCESS_RECORD,
    "ACCESS_RECORD_WORST_CASE exceeds MAX_ACCESS_RECORD — bump MAX_ACCESS_RECORD"
);

/// Canonical producer-side sampled-request record.
///
/// Built **once** on the stack at the exception-tail / exemplar gate in
/// `metric_source/instrumented.rs`; projected into both sinks
/// (`emit_access_record` → log ring; `ExemplarReservoir::write` → exemplar
/// reservoir) without a second gather pass. All byte-slice fields borrow
/// nginx request memory — no allocation.
pub struct SampledRequest<'a> {
    // ── shared by both sinks ──────────────────────────────────────────────
    /// Unix epoch nanoseconds at request start.
    pub ts_unix_nano: u64,
    /// Optional W3C trace context: `(trace_id[16], span_id[8])`.
    pub trace: Option<([u8; 16], [u8; 8])>,
    /// `url.path` — high-cardinality, tail/exemplar only.
    pub url_path: &'a [u8],
    /// `user_agent.original` — high-cardinality, tail/exemplar only.
    pub user_agent: &'a [u8],
    /// Request duration in microseconds — exemplar value + log attribute.
    pub duration_us: u64,
    /// Base `{method × status_class × protocol}` combo index — histogram join key.
    pub combo_idx: u32,
    // ── log ring only ─────────────────────────────────────────────────────
    /// HTTP request method bytes (e.g. `b"GET"`).
    pub method: &'a [u8],
    /// HTTP response status code.
    pub status: u16,
    /// Request body size in bytes.
    pub request_length: u64,
    /// Response bytes sent.
    pub response_bytes: u64,
    /// Client address string (e.g. `b"127.0.0.1"`).
    pub client_addr: &'a [u8],
    // route_idx/upstream_idx: deferred.
}

/// HTTP access record kind byte.
///
/// `pub` so the exporter's `parse_access_record` can reference the same constant
/// rather than an independent `0x00` literal — binding producer and parser by name.
pub const KIND_ACCESS: u8 = 0x00;

/// nginx info level (7) — all access records use this severity.
const NGX_LEVEL_INFO: u8 = 7;

/// Emit one HTTP access log record into the producer's ring.
///
/// Serialises the fields of `req` into a fixed-size stack buffer and pushes it.
///
/// Returns `true` if the record was pushed; `false` if the ring was full.
///
/// # No allocation
/// All formatting is done into a fixed-size stack buffer; never calls
/// `Vec::new`, `Box::new`, or any heap allocator.
///
/// # High-cardinality fields stay OFF the metric
/// `url_path`, `user_agent`, and `client_addr` appear ONLY in this tail record
/// and in exemplar `filtered_attributes`; NEVER as metric dimensions.
#[inline]
pub fn emit_access_record(producer: &dyn LogProducer, req: &SampledRequest<'_>) -> bool {
    let mut buf = [0u8; MAX_ACCESS_RECORD];
    let mut pos = 0usize;

    macro_rules! write_u8 {
        ($v:expr) => {
            buf[pos] = $v;
            pos += 1;
        };
    }
    macro_rules! write_u16_be {
        ($v:expr) => {
            let b = ($v as u16).to_be_bytes();
            buf[pos] = b[0];
            buf[pos + 1] = b[1];
            pos += 2;
        };
    }
    macro_rules! write_u64_be {
        ($v:expr) => {
            let b = ($v as u64).to_be_bytes();
            buf[pos..pos + 8].copy_from_slice(&b);
            pos += 8;
        };
    }
    macro_rules! write_bytes_with_u16_len {
        ($data:expr, $max:expr) => {
            let len = $data.len().min($max);
            write_u16_be!(len as u16);
            buf[pos..pos + len].copy_from_slice(&$data[..len]);
            pos += len;
        };
    }

    write_u8!(KIND_ACCESS);
    write_u64_be!(req.ts_unix_nano);
    write_u8!(NGX_LEVEL_INFO);
    // http.request.method
    write_bytes_with_u16_len!(req.method, MAX_METHOD);
    // http.response.status_code
    write_u16_be!(req.status);
    // http.server.request.body.size
    write_u64_be!(req.request_length);
    // http.server.response.body.size
    write_u64_be!(req.response_bytes);
    // client.address
    write_bytes_with_u16_len!(req.client_addr, MAX_CLIENT_ADDR);

    match req.trace {
        Some((trace_id, span_id)) => {
            write_u8!(1u8); // has_trace = 1
            buf[pos..pos + 16].copy_from_slice(&trace_id);
            pos += 16;
            buf[pos..pos + 8].copy_from_slice(&span_id);
            pos += 8;
        }
        None => {
            write_u8!(0u8); // has_trace = 0
        }
    }

    // High-cardinality detail — on tail/exemplar records ONLY.
    // NEVER promoted to metric dimensions (keeps the combo index within a u8).
    write_bytes_with_u16_len!(req.url_path, MAX_URL_PATH);
    write_bytes_with_u16_len!(req.user_agent, MAX_USER_AGENT);

    // Request duration: carries µs duration so the tail LogRecord can surface
    // `http.server.request.duration` without a second time read on the export
    // path.
    write_u64_be!(req.duration_us);

    producer.push(&buf[..pos])
}

/// Parse a W3C `traceparent` header value and return `(trace_id[16], span_id[8])`.
///
/// Format: `{version}-{trace_id_hex32}-{parent_id_hex16}-{flags_hex2}`; only
/// the `00` version (the only standardised one) is handled. Returns `None`
/// for absent, malformed, or non-`00`-version headers. No allocation.
///
/// Used by tests and as the simplified accessor when flags are not needed;
/// the production hot path uses [`parse_traceparent_full`] instead.
#[allow(dead_code)]
pub fn parse_traceparent(header: &[u8]) -> Option<([u8; 16], [u8; 8])> {
    parse_traceparent_full(header).map(|(tid, sid, _)| (tid, sid))
}

/// Parse a W3C `traceparent` header value and return `(trace_id[16], parent_span_id[8], flags)`.
///
/// Extends `parse_traceparent` with the trace-flags byte (offset 52); bit 0 of
/// flags is the W3C `sampled` flag. Returns `None` for absent, malformed, or
/// non-`00`-version headers. No allocation.
pub fn parse_traceparent_full(header: &[u8]) -> Option<([u8; 16], [u8; 8], u32)> {
    // Minimum: "00-" + 32 hex + "-" + 16 hex + "-" + 2 hex = 55 bytes
    if header.len() < 55 {
        return None;
    }
    // Version must be "00"
    if header[0] != b'0' || header[1] != b'0' || header[2] != b'-' {
        return None;
    }
    // trace_id: 32 hex chars at offset 3..35
    let mut trace_id = [0u8; 16];
    if !decode_hex16(&header[3..3 + 32], &mut trace_id) {
        return None;
    }
    if header[35] != b'-' {
        return None;
    }
    // parent span_id: 16 hex chars at offset 36..52
    let mut parent_span_id = [0u8; 8];
    if !decode_hex8(&header[36..36 + 16], &mut parent_span_id) {
        return None;
    }
    if header[52] != b'-' {
        return None;
    }
    // flags: 2 hex chars at offset 53..55
    let hi = hex_nibble(header[53])?;
    let lo = hex_nibble(header[54])?;
    let flags = ((hi << 4) | lo) as u32;
    // Version 00 MUST NOT have trailing characters (W3C §3.3: "the implementation
    // MUST NOT allow trailing characters after trace-flags for version 00").
    if header.len() != 55 {
        return None;
    }
    // All-zero trace-id is invalid per spec (W3C §3.3).
    if trace_id == [0u8; 16] {
        return None;
    }
    // All-zero parent-id is invalid per spec (W3C §3.3: "All zeroes MUST be
    // rejected" for parent-id).
    if parent_span_id == [0u8; 8] {
        return None;
    }
    Some((trace_id, parent_span_id, flags))
}

/// Decode 32 hex characters into 16 bytes.  Returns false on invalid input.
fn decode_hex16(hex: &[u8], out: &mut [u8; 16]) -> bool {
    if hex.len() < 32 {
        return false;
    }
    for i in 0..16 {
        let hi = hex_nibble(hex[i * 2]);
        let lo = hex_nibble(hex[i * 2 + 1]);
        match (hi, lo) {
            (Some(h), Some(l)) => out[i] = (h << 4) | l,
            _ => return false,
        }
    }
    true
}

/// Decode 16 hex characters into 8 bytes.  Returns false on invalid input.
fn decode_hex8(hex: &[u8], out: &mut [u8; 8]) -> bool {
    if hex.len() < 16 {
        return false;
    }
    for i in 0..8 {
        let hi = hex_nibble(hex[i * 2]);
        let lo = hex_nibble(hex[i * 2 + 1]);
        match (hi, lo) {
            (Some(h), Some(l)) => out[i] = (h << 4) | l,
            _ => return false,
        }
    }
    true
}

/// Convert a single ASCII hex character to its nibble value (0–15).
///
/// Only lowercase hex is accepted: W3C Trace Context §3.3 defines `HEXDIGLC`
/// (`0`–`9`, `a`–`f`) as the required alphabet, and uppercase MUST be
/// rejected — accepting it would let non-canonical headers through that a
/// strict downstream re-parse might reject, breaking trace correlation.
#[inline]
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::ring::tests::make_ring_with_cap;
    use crate::logs::WorkerRingProducer;

    #[test]
    fn access_record_pushes_bytes_to_ring() {
        let (_buf, ring) = make_ring_with_cap(4096);
        // WorkerSignalRing is Copy, so we can use it for both the producer and drain.
        let producer = WorkerRingProducer { ring };

        let req = SampledRequest {
            ts_unix_nano: 1_700_000_000_000_000_000,
            trace: None,
            url_path: b"/health",
            user_agent: b"curl/7.0",
            duration_us: 0,
            combo_idx: 0,
            method: b"GET",
            status: 200,
            request_length: 0,
            response_bytes: 512,
            client_addr: b"127.0.0.1",
        };
        let pushed = emit_access_record(&producer, &req);
        assert!(pushed, "push must succeed on an empty ring");

        let mut record = std::vec::Vec::new();
        assert!(ring.pop_into(&mut record), "expected a record in the ring");
        assert_eq!(record[0], KIND_ACCESS);
        // ngx_level at byte 9 (1 kind + 8 ts).
        assert_eq!(record[9], NGX_LEVEL_INFO);
        // method length at bytes 10-11, value at 12..12+len.
        let method_len = u16::from_be_bytes([record[10], record[11]]) as usize;
        assert_eq!(method_len, 3);
        assert_eq!(&record[12..12 + method_len], b"GET");
        // status code at 12 + method_len.
        let sc_off = 12 + method_len;
        let status = u16::from_be_bytes([record[sc_off], record[sc_off + 1]]);
        assert_eq!(status, 200);
    }

    /// A valid `traceparent` header ⇒ trace_id and span_id land in the record.
    /// Absent ⇒ `has_trace = 0`.
    #[test]
    fn traceparent_roundtrips() {
        let header = b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let tc = parse_traceparent(header);
        assert!(tc.is_some(), "valid traceparent must parse");
        let (trace_id, span_id) = tc.unwrap();
        assert_eq!(trace_id[0], 0x4b);
        assert_eq!(trace_id[1], 0xf9);
        assert_eq!(trace_id[15], 0x36);
        assert_eq!(span_id[0], 0x00);
        assert_eq!(span_id[1], 0xf0);
        assert_eq!(span_id[7], 0xb7);

        // has_trace = 1 in the byte stream when trace context is present.
        let (_buf, ring) = make_ring_with_cap(4096);
        let producer = WorkerRingProducer { ring };
        emit_access_record(
            &producer,
            &SampledRequest {
                ts_unix_nano: 0,
                trace: Some((trace_id, span_id)),
                url_path: b"/api/v1",
                user_agent: b"Mozilla/5.0",
                duration_us: 0,
                combo_idx: 0,
                method: b"GET",
                status: 200,
                request_length: 0,
                response_bytes: 0,
                client_addr: b"127.0.0.1",
            },
        );
        let mut rec = std::vec::Vec::new();
        assert!(ring.pop_into(&mut rec));
        // Find the has_trace byte: after kind(1)+ts(8)+level(1)+method_len(2)+method(3)+status(2)+reqlen(8)+respbytes(8)+addrlen(2)+addr(9)
        let method_len = u16::from_be_bytes([rec[10], rec[11]]) as usize;
        let addr_off = 12 + method_len + 2 + 8 + 8;
        let addr_len = u16::from_be_bytes([rec[addr_off], rec[addr_off + 1]]) as usize;
        let has_trace_off = addr_off + 2 + addr_len;
        assert_eq!(rec[has_trace_off], 1, "has_trace must be 1 when trace context present");
        // trace_id at has_trace_off+1
        assert_eq!(
            &rec[has_trace_off + 1..has_trace_off + 17],
            &trace_id[..],
            "trace_id round-trips"
        );
        // span_id at has_trace_off+17
        assert_eq!(
            &rec[has_trace_off + 17..has_trace_off + 25],
            &span_id[..],
            "span_id round-trips"
        );

        // has_trace = 0 when no trace context.
        let (_buf2, ring2) = make_ring_with_cap(4096);
        let producer2 = WorkerRingProducer { ring: ring2 };
        emit_access_record(
            &producer2,
            &SampledRequest {
                ts_unix_nano: 0,
                trace: None,
                url_path: b"",
                user_agent: b"",
                duration_us: 0,
                combo_idx: 0,
                method: b"GET",
                status: 200,
                request_length: 0,
                response_bytes: 0,
                client_addr: b"127.0.0.1",
            },
        );
        let mut rec2 = std::vec::Vec::new();
        assert!(ring2.pop_into(&mut rec2));
        let m2 = u16::from_be_bytes([rec2[10], rec2[11]]) as usize;
        let a2_off = 12 + m2 + 2 + 8 + 8;
        let a2_len = u16::from_be_bytes([rec2[a2_off], rec2[a2_off + 1]]) as usize;
        let ht_off2 = a2_off + 2 + a2_len;
        assert_eq!(rec2[ht_off2], 0, "has_trace must be 0 when no trace context");

        // Absent/malformed headers → None.
        assert!(parse_traceparent(b"").is_none(), "empty header → None");
        assert!(
            parse_traceparent(b"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").is_none(),
            "non-00 version → None"
        );
        assert!(
            parse_traceparent(b"00-00000000000000000000000000000000-00f067aa0ba902b7-01").is_none(),
            "all-zero trace_id → None"
        );
        assert!(
            parse_traceparent(b"00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01").is_none(),
            "invalid hex → None"
        );
    }

    /// Table-driven W3C traceparent parser: strict rejection per spec (§3.3):
    /// `HEXDIGLC` is lowercase-only (uppercase MUST reject), version-00 MUST
    /// reject trailing characters, and parent-id/trace-id all-zeros MUST reject.
    ///
    /// Regression: `hex_nibble` previously accepted `A-F`; `parse_traceparent_full`
    /// previously accepted len > 55 and all-zero parent-id — this test FAILS on
    /// pre-fix code for those rows.
    #[test]
    fn f7_traceparent_parser_strict() {
        // Canonical valid header, used as the mutation base.
        let valid: &[u8] = b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

        struct Case {
            header: &'static [u8],
            expect_some: bool,
            desc: &'static str,
        }

        let cases: &[Case] = &[
            // ── Valid cases ───────────────────────────────────────────────────
            Case {
                header: b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                expect_some: true,
                desc: "valid canonical",
            },
            Case {
                header: b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
                expect_some: true,
                desc: "valid flags=00 (unsampled)",
            },
            Case {
                header: b"00-ffffffffffffffffffffffffffffffff-ffffffffffffffff-ff",
                expect_some: true,
                desc: "valid all-f",
            },
            // ── Uppercase hex — MUST reject (HEXDIGLC is lowercase only) ─────
            Case {
                header: b"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
                expect_some: false,
                desc: "uppercase trace-id MUST be rejected",
            },
            Case {
                header: b"00-4bf92f3577b34da6a3ce929d0e0e4736-00F067AA0BA902B7-01",
                expect_some: false,
                desc: "uppercase parent-id MUST be rejected",
            },
            Case {
                header: b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0F",
                expect_some: false,
                desc: "uppercase flags MUST be rejected",
            },
            // ── All-zero parent-id — MUST reject (W3C §3.3) ──────────────────
            Case {
                header: b"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
                expect_some: false,
                desc: "all-zero parent-id MUST be rejected",
            },
            // ── All-zero trace-id — MUST reject (W3C §3.3) ───────────────────
            Case {
                header: b"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
                expect_some: false,
                desc: "all-zero trace-id MUST be rejected",
            },
            // ── Version-00 trailing garbage — MUST reject (W3C §3.3) ─────────
            Case {
                header: b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
                expect_some: false,
                desc: "version-00 trailing garbage MUST be rejected",
            },
            Case {
                header: b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 ",
                expect_some: false,
                desc: "version-00 trailing space MUST be rejected",
            },
            // ── Non-00 version — MUST reject (we only implement version 00) ──
            Case {
                header: b"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                expect_some: false,
                desc: "version 01 MUST be rejected",
            },
            Case {
                header: b"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                expect_some: false,
                desc: "version ff MUST be rejected",
            },
            // ── Truncated headers ─────────────────────────────────────────────
            Case { header: b"", expect_some: false, desc: "empty MUST be rejected" },
            Case {
                header: b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
                expect_some: false,
                desc: "missing flags MUST be rejected",
            },
            Case {
                header: b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0",
                expect_some: false,
                desc: "flags truncated to 1 hex digit MUST be rejected",
            },
            // ── Invalid hex characters ────────────────────────────────────────
            Case {
                header: b"00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01",
                expect_some: false,
                desc: "invalid hex in trace-id MUST be rejected",
            },
            Case {
                header: b"00-4bf92f3577b34da6a3ce929d0e0e4736-zzzzzzzzzzzzzzzz-01",
                expect_some: false,
                desc: "invalid hex in parent-id MUST be rejected",
            },
        ];

        // The valid base header must parse; verify the mutation baseline is correct.
        assert!(
            parse_traceparent_full(valid).is_some(),
            "baseline valid header must parse — test setup error"
        );

        for case in cases {
            let got = parse_traceparent_full(case.header);
            let is_some = got.is_some();
            assert_eq!(
                is_some,
                case.expect_some,
                "case {:?}: expected {}, got {} — {}",
                std::str::from_utf8(case.header).unwrap_or("<non-utf8>"),
                if case.expect_some { "Some" } else { "None" },
                if is_some { "Some" } else { "None" },
                case.desc
            );
        }
    }

    /// Root spans export empty parent_span_id; child spans export 8 bytes.
    ///
    /// OTLP `Span.parent_span_id` is a `bytes` field: empty = root span,
    /// 8 bytes = child span.  The ring wire format stores [0u8;8] for root spans;
    /// `parse_span_record` must map that to `Vec::new()`.
    ///
    /// Regression: pre-fix code returned `vec![0u8;8]` for root spans,
    /// signalling a non-existent parent to OTLP backends.
    #[test]
    fn f7_root_span_exports_empty_parent_span_id() {
        use crate::data_model::{SpanKind, StatusCode};
        use crate::traces::{emit_span_record, parse_span_record, SpanRecord};

        struct VecProducer(std::sync::Mutex<std::vec::Vec<u8>>);
        impl crate::logs::LogProducer for VecProducer {
            fn push(&self, data: &[u8]) -> bool {
                let mut v = self.0.lock().unwrap();
                let len = data.len() as u32;
                v.extend_from_slice(&len.to_be_bytes());
                v.extend_from_slice(data);
                true
            }
        }

        // Root span: parent_span_id all zeros.
        let root_rec = SpanRecord {
            trace_id: [0xaa_u8; 16],
            span_id: [0xbb_u8; 8],
            parent_span_id: [0x00_u8; 8],
            flags: 0x01,
            start_time_unix_nano: 1_000_000_000,
            end_time_unix_nano: 2_000_000_000,
            status_code: StatusCode::Unset as u8,
            kind: SpanKind::Server as u8,
            name: b"GET /root",
            method: b"GET",
            http_status: 200,
            url_path: b"/root",
            duration_us: 1_000_000,
            proto: 1, // ProtoVersion::Http11
            scheme_https: false,
            server_port: 0,
            client_port: 0,
            peer_port: 0,
            req_body_size: 0,
            resp_body_size: 0,
            url_query: b"",
            route: b"",
            user_agent: b"",
            server_address: b"",
            client_address: b"",
            peer_address: b"",
            extra_attrs: &[],
        };

        // Child span: non-zero parent_span_id.
        let child_parent: [u8; 8] = [0xcc; 8];
        let child_rec = SpanRecord {
            trace_id: [0xaa_u8; 16],
            span_id: [0xdd_u8; 8],
            parent_span_id: child_parent,
            flags: 0x01,
            start_time_unix_nano: 1_100_000_000,
            end_time_unix_nano: 1_900_000_000,
            status_code: StatusCode::Unset as u8,
            kind: SpanKind::Server as u8,
            name: b"GET /child",
            method: b"GET",
            http_status: 200,
            url_path: b"/child",
            duration_us: 800_000,
            proto: 1, // ProtoVersion::Http11
            scheme_https: false,
            server_port: 0,
            client_port: 0,
            peer_port: 0,
            req_body_size: 0,
            resp_body_size: 0,
            url_query: b"",
            route: b"",
            user_agent: b"",
            server_address: b"",
            client_address: b"",
            peer_address: b"",
            extra_attrs: &[],
        };

        let prod = VecProducer(std::sync::Mutex::new(std::vec::Vec::new()));

        assert!(emit_span_record(&prod, &root_rec), "root span push must succeed");
        assert!(emit_span_record(&prod, &child_rec), "child span push must succeed");

        let raw = prod.0.lock().unwrap();

        // Parse root span (first record).
        let root_len = u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize;
        let root_span = parse_span_record(&raw[4..4 + root_len], 0).expect("root span must parse");
        assert!(
            root_span.parent_span_id.is_empty(),
            "root span MUST export empty parent_span_id, got {:?}",
            root_span.parent_span_id
        );

        // Parse child span (second record).
        let child_off = 4 + root_len;
        let child_len =
            u32::from_be_bytes(raw[child_off..child_off + 4].try_into().unwrap()) as usize;
        let child_span = parse_span_record(&raw[child_off + 4..child_off + 4 + child_len], 0)
            .expect("child span must parse");
        assert_eq!(
            child_span.parent_span_id,
            child_parent.to_vec(),
            "child span MUST export the 8-byte parent_span_id"
        );
    }

    #[test]
    fn access_record_long_method_truncated() {
        let (_buf, ring) = make_ring_with_cap(4096);
        let producer = WorkerRingProducer { ring };
        let long_method = b"VERYLONGMETHODNAME_EXCEEDS_LIMIT";
        emit_access_record(
            &producer,
            &SampledRequest {
                ts_unix_nano: 0,
                trace: None,
                url_path: b"",
                user_agent: b"",
                duration_us: 0,
                combo_idx: 0,
                method: long_method,
                status: 200,
                request_length: 0,
                response_bytes: 0,
                client_addr: b"127.0.0.1",
            },
        );
        let mut record = std::vec::Vec::new();
        assert!(ring.pop_into(&mut record));
        let method_len = u16::from_be_bytes([record[10], record[11]]) as usize;
        assert!(method_len <= MAX_METHOD, "method must be truncated to MAX_METHOD bytes");
    }

    /// Worst-case `SampledRequest` (every field at its cap, has_trace=1) must
    /// not panic, must stay within `MAX_ACCESS_RECORD`, and must land exactly
    /// at `ACCESS_RECORD_WORST_CASE` bytes.
    ///
    /// Regression guard: `MAX_ACCESS_RECORD = 320` once let a 323-byte
    /// worst-case record trigger an index-out-of-bounds panic.
    #[test]
    fn access_record_worst_case_fits_in_buffer() {
        let (_buf, ring) = make_ring_with_cap(4096);
        let producer = WorkerRingProducer { ring };
        let method = [b'X'; MAX_METHOD];
        let client = [b'c'; MAX_CLIENT_ADDR];
        let url = [b'/'; MAX_URL_PATH];
        let ua = [b'A'; MAX_USER_AGENT];
        let req = SampledRequest {
            ts_unix_nano: u64::MAX,
            trace: Some(([0xaa_u8; 16], [0xbb_u8; 8])),
            url_path: &url,
            user_agent: &ua,
            duration_us: u64::MAX,
            combo_idx: 0,
            method: &method,
            status: 500,
            request_length: u64::MAX,
            response_bytes: u64::MAX,
            client_addr: &client,
        };
        let pushed = emit_access_record(&producer, &req);
        assert!(pushed, "worst-case record must push without panic");

        let mut record = std::vec::Vec::new();
        assert!(ring.pop_into(&mut record));
        assert!(
            record.len() <= MAX_ACCESS_RECORD,
            "record len {} must not exceed MAX_ACCESS_RECORD {}",
            record.len(),
            MAX_ACCESS_RECORD
        );
        assert_eq!(
            record.len(),
            ACCESS_RECORD_WORST_CASE,
            "worst-case record must be exactly ACCESS_RECORD_WORST_CASE bytes"
        );
    }
}
