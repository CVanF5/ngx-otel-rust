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
//! ```
//!
//! The format is intentionally minimal for Phase 2.1.  Trace correlation
//! (`trace_id`/`span_id`) and URL path are deferred to later phases.
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
///
/// Total = 86 bytes, rounded to 128 for headroom.
pub const MAX_ACCESS_RECORD: usize = 128;

/// HTTP access record kind byte.
const KIND_ACCESS: u8 = 0x00;

/// nginx info level (7) — all access records use this severity.
const NGX_LEVEL_INFO: u8 = 7;

/// Emit one HTTP access log record into the producer's ring.
///
/// # Arguments
/// - `producer`       — the calling worker's ring producer.
/// - `method`         — HTTP method string (e.g. `b"GET"`).
/// - `status`         — HTTP response status code.
/// - `request_length` — request body size in bytes.
/// - `response_bytes` — response bytes sent.
/// - `client_addr`    — client address string (e.g. `b"127.0.0.1"`).
/// - `ts_unix_nano`   — timestamp of the request (Unix epoch, nanoseconds).
///
/// Returns `true` if the record was pushed; `false` if the ring was full.
///
/// # No allocation
/// All formatting is done into a fixed-size stack buffer.  This function
/// never calls `Vec::new`, `Box::new`, or any heap allocator.
#[inline]
pub fn emit_access_record(
    producer: &dyn LogProducer,
    method: &[u8],
    status: u16,
    request_length: u64,
    response_bytes: u64,
    client_addr: &[u8],
    ts_unix_nano: u64,
) -> bool {
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
    write_u64_be!(ts_unix_nano);
    // ngx_level (info)
    write_u8!(NGX_LEVEL_INFO);
    // http.request.method
    write_bytes_with_u16_len!(method, 16); // max method = 16 bytes
    // http.response.status_code
    write_u16_be!(status);
    // http.server.request.body.size
    write_u64_be!(request_length);
    // http.server.response.body.size
    write_u64_be!(response_bytes);
    // client.address
    write_bytes_with_u16_len!(client_addr, 46); // max IPv6 = 46 chars

    producer.push(&buf[..pos])
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::{ring::LogsWorkerRing, WorkerRingProducer};

    type TestRing = LogsWorkerRing<{ 4 * 1024 }>;

    fn make_ring() -> std::boxed::Box<TestRing> {
        unsafe {
            let layout = std::alloc::Layout::new::<TestRing>();
            let ptr = std::alloc::alloc_zeroed(layout) as *mut TestRing;
            std::boxed::Box::from_raw(ptr)
        }
    }

    fn drain_one(ring: &TestRing) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::new();
        let ok = ring.pop_into(&mut out);
        assert!(ok, "expected a record in the ring");
        out
    }

    #[test]
    fn access_record_pushes_bytes_to_ring() {
        let ring = make_ring();
        let producer = WorkerRingProducer { ring: ring.as_ref() };

        let pushed = emit_access_record(
            &producer,
            b"GET",
            200,
            0,
            512,
            b"127.0.0.1",
            1_700_000_000_000_000_000,
        );
        assert!(pushed, "push must succeed on an empty ring");

        let record = drain_one(&ring);
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

    #[test]
    fn access_record_long_method_truncated() {
        let ring = make_ring();
        let producer = WorkerRingProducer { ring: ring.as_ref() };
        // Method longer than 16 bytes should be truncated.
        let long_method = b"VERYLONGMETHODNAME_EXCEEDS_LIMIT";
        emit_access_record(&producer, long_method, 200, 0, 0, b"127.0.0.1", 0);
        let record = drain_one(&ring);
        let method_len = u16::from_be_bytes([record[10], record[11]]) as usize;
        assert!(method_len <= 16, "method must be truncated to 16 bytes");
    }
}
