// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Access-record formatter (Phase 2.1).
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
//! --- Phase 2.2 Step 2.2.3: W3C trace correlation ---
//! [u8  has_trace  = 0|1          ]  (1 = valid traceparent was present)
//! if has_trace == 1:
//!   [16 bytes trace_id            ]
//!   [8  bytes span_id (parent_id) ]
//! --- Phase 2.2 Step 2.2.5: high-cardinality detail ---
//! [u16 url_path_len big-endian   ]
//! [url_path_len bytes of url.path]
//! [u16 user_agent_len big-endian ]
//! [user_agent_len bytes          ]
//! --- Phase 2 S2: request duration ---
//! [u64 duration_us big-endian    ]  (µs; same unit as exp-histogram)
//! ```
//!
//! The `has_trace = 0` case costs nothing beyond one extra byte in the record.
//! Absent/malformed `traceparent` ⇒ `has_trace = 0`.  The exporter attaches
//! trace context to exemplars and tail `LogRecord`s from these fields.
//!
//! # Constraint: no allocation
//! The entire record is formatted into a fixed-size stack buffer
//! `[u8; MAX_ACCESS_RECORD]`.  If the formatted record would exceed the
//! buffer (very long client address string), the field is silently truncated.

use super::LogProducer;

/// Maximum size of a formatted access record in bytes.
///
/// Breakdown:
/// - 1  (kind)
/// - 8  (ts_unix_nano)
/// - 1  (ngx_level)
/// - 2  (method_len) + 8 (method, e.g. "OPTIONS")
/// - 2  (status_code)
/// - 8  (request_length)
/// - 8  (response_bytes)
/// - 2  (client_addr_len) + 46 (max IPv6 with brackets + port)
/// - 1  (has_trace)
/// - 16 (trace_id, only when has_trace = 1)
/// - 8  (span_id,  only when has_trace = 1)
///
/// Phase 2.2 Step 2.2.5 — high-cardinality detail:
///
/// - 2  (url_path_len) + 64 (url.path, truncated to 64 bytes)
/// - 2  (user_agent_len) + 128 (user_agent.original, truncated to 128 bytes)
///
/// Phase 2 S2 — request duration:
///
/// - 8  (duration_us, big-endian u64 — µs precision, same unit as exp-histogram)
///
/// Total worst case: 95 + 2+64 + 2+128 + 8 = 299 bytes → round to 320.
pub const MAX_ACCESS_RECORD: usize = 320;

/// Maximum `url.path` bytes stored in the record.
/// Single-homed here; `shm.rs` imports this constant for the exemplar reservoir.
pub const MAX_URL_PATH: usize = 64;
/// Maximum `user_agent.original` bytes stored in the record.
/// Single-homed here; `shm.rs` imports this constant for the exemplar reservoir.
pub const MAX_USER_AGENT: usize = 128;
/// Maximum `client.address` bytes stored in the record.
pub const MAX_CLIENT_ADDR: usize = 46;

/// Canonical producer-side sampled-request record.
///
/// Built **once** on the stack from nginx request fields at the exception-tail /
/// exemplar gate in `metric_source/instrumented.rs`; projected into both sinks
/// (`emit_access_record` → log ring; `ExemplarReservoir::write` → exemplar
/// reservoir) without a second gather pass.
///
/// All byte-slice fields borrow nginx request memory — no allocation.
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
    /// Request duration in microseconds — exemplar value + log attribute (decision #3).
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
    // route_idx/upstream_idx: deferred to Phase 3 — see PHASE_3_NOTES.md
}

/// HTTP access record kind byte.
const KIND_ACCESS: u8 = 0x00;

/// nginx info level (7) — all access records use this severity.
const NGX_LEVEL_INFO: u8 = 7;

/// Emit one HTTP access log record into the producer's ring.
///
/// Serialises the fields of `req` into a fixed-size stack buffer and pushes it.
///
/// Returns `true` if the record was pushed; `false` if the ring was full.
///
/// # No allocation
/// All formatting is done into a fixed-size stack buffer.  This function
/// never calls `Vec::new`, `Box::new`, or any heap allocator.
///
/// # High-cardinality fields stay OFF the metric
/// `url_path`, `user_agent`, and `client_addr` appear ONLY in this tail record
/// and in exemplar `filtered_attributes`; they are NEVER used as metric dimensions.
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

    // kind
    write_u8!(KIND_ACCESS);
    // timestamp
    write_u64_be!(req.ts_unix_nano);
    // ngx_level (info)
    write_u8!(NGX_LEVEL_INFO);
    // http.request.method
    write_bytes_with_u16_len!(req.method, 16); // max method = 16 bytes
                                               // http.response.status_code
    write_u16_be!(req.status);
    // http.server.request.body.size
    write_u64_be!(req.request_length);
    // http.server.response.body.size
    write_u64_be!(req.response_bytes);
    // client.address
    write_bytes_with_u16_len!(req.client_addr, MAX_CLIENT_ADDR);

    // W3C trace correlation (Phase 2.2.3).
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

    // High-cardinality detail (Phase 2.2.5) — on tail/exemplar records ONLY.
    // NEVER promoted to metric dimensions (plan §DP-E; keeps combo index WithinU8).
    write_bytes_with_u16_len!(req.url_path, MAX_URL_PATH);
    write_bytes_with_u16_len!(req.user_agent, MAX_USER_AGENT);

    // Request duration (Phase 2 S2 — decision #3): carries µs duration so the
    // tail LogRecord can surface `http.server.request.duration` without a second
    // time read on the export path.
    write_u64_be!(req.duration_us);

    producer.push(&buf[..pos])
}

/// Parse a W3C `traceparent` header value and return `(trace_id[16], span_id[8])`.
///
/// The format is: `{version}-{trace_id_hex32}-{parent_id_hex16}-{flags_hex2}`
/// This function only handles the `00` version (the only standardised version).
///
/// Returns `None` for absent, malformed, or non-`00`-version headers.
///
/// # No allocation
/// Operates entirely on the `&[u8]` slice; no heap operations.
pub fn parse_traceparent(header: &[u8]) -> Option<([u8; 16], [u8; 8])> {
    // Minimum: "00-" + 32 hex + "-" + 16 hex + "-" + 2 hex = 55 bytes
    if header.len() < 55 {
        return None;
    }
    // Version must be "00"
    if header[0] != b'0' || header[1] != b'0' || header[2] != b'-' {
        return None;
    }
    // trace_id: 32 hex chars starting at offset 3
    let mut trace_id = [0u8; 16];
    if !decode_hex16(&header[3..3 + 32], &mut trace_id) {
        return None;
    }
    // dash after trace_id
    if header[35] != b'-' {
        return None;
    }
    // span_id (parent_id): 16 hex chars starting at offset 36
    let mut span_id = [0u8; 8];
    if !decode_hex8(&header[36..36 + 16], &mut span_id) {
        return None;
    }
    // All-zero trace_id is invalid per spec
    if trace_id == [0u8; 16] {
        return None;
    }
    Some((trace_id, span_id))
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
#[inline]
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
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
        // LogsWorkerRing is Copy, so we can use it for both the producer and drain.
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
        // Check kind byte.
        assert_eq!(record[0], KIND_ACCESS);
        // Check ngx_level (at byte 9, after 1 kind + 8 ts).
        assert_eq!(record[9], NGX_LEVEL_INFO);
        // Check method length (bytes 10-11) and value (bytes 12-14).
        let method_len = u16::from_be_bytes([record[10], record[11]]) as usize;
        assert_eq!(method_len, 3);
        assert_eq!(&record[12..12 + method_len], b"GET");
        // Check status code (at 12 + method_len).
        let sc_off = 12 + method_len;
        let status = u16::from_be_bytes([record[sc_off], record[sc_off + 1]]);
        assert_eq!(status, 200);
    }

    /// A valid `traceparent` header ⇒ trace_id and span_id land in the record.
    /// Absent ⇒ `has_trace = 0`.
    #[test]
    fn traceparent_roundtrips() {
        // Valid traceparent: version 00, 32-char trace_id, 16-char span_id
        let header = b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let tc = parse_traceparent(header);
        assert!(tc.is_some(), "valid traceparent must parse");
        let (trace_id, span_id) = tc.unwrap();
        // Expected trace_id bytes: 4bf92f35 77b34da6 a3ce929d 0e0e4736
        assert_eq!(trace_id[0], 0x4b);
        assert_eq!(trace_id[1], 0xf9);
        assert_eq!(trace_id[15], 0x36);
        // Expected span_id bytes: 00f067aa 0ba902b7
        assert_eq!(span_id[0], 0x00);
        assert_eq!(span_id[1], 0xf0);
        assert_eq!(span_id[7], 0xb7);

        // Emit record with trace context → has_trace = 1 in the byte stream.
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

        // Emit record without trace context → has_trace = 0.
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

    #[test]
    fn access_record_long_method_truncated() {
        let (_buf, ring) = make_ring_with_cap(4096);
        let producer = WorkerRingProducer { ring };
        // Method longer than 16 bytes should be truncated.
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
        assert!(method_len <= 16, "method must be truncated to 16 bytes");
    }
}
