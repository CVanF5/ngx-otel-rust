// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Span record wire format (worker → exporter) — Phase 3.2 cold-path.
//!
//! # Wire format
//!
//! ```text
//! [16] trace_id            (raw bytes, W3C trace ID)
//! [8]  span_id             (raw bytes, W3C span ID)
//! [8]  parent_span_id      (raw bytes, 0x00×8 for root spans)
//! [4]  flags               (W3C trace-flags, big-endian u32)
//! [8]  start_time_unix_nano (big-endian u64, Unix epoch, nanos)
//! [8]  end_time_unix_nano   (big-endian u64, Unix epoch, nanos)
//! [1]  status_code         (StatusCode as u8: 0=Unset 1=Ok 2=Error)
//! [1]  kind                (SpanKind as u8)
//! [2]  name_len            (big-endian u16, ≤ MAX_SPAN_NAME)
//! [name_len] name          (UTF-8 span name)
//! [2]  method_len          (big-endian u16, ≤ MAX_SPAN_METHOD)
//! [method_len] method      (http.request.method)
//! [2]  status_code_http    (big-endian u16, HTTP status code, 0 if absent)
//! [2]  url_path_len        (big-endian u16, ≤ MAX_SPAN_URL_PATH)
//! [url_path_len] url_path  (url.path)
//! [8]  duration_us         (big-endian u64, request duration in µs)
//! ```
//!
//! **Hot-path rule**: no allocation, no heap, no locks, no logging.
//! `emit_span_record` serialises into a fixed-size stack buffer
//! `[u8; MAX_SPAN_RECORD]`.  Fields exceeding their caps are silently truncated.
//!
//! # Compile-time size guard (C1 pattern)
//!
//! `SPAN_RECORD_WORST_CASE ≤ MAX_SPAN_RECORD` is a `const assert!` so that
//! any future cap increase that would overflow the buffer is a **build failure**
//! rather than a latent runtime panic.

use crate::logs::LogProducer;

// ── Named field caps ──────────────────────────────────────────────────────────

/// Maximum span name bytes stored in the record.
pub const MAX_SPAN_NAME: usize = 64;
/// Maximum `http.request.method` bytes stored in the record.
pub const MAX_SPAN_METHOD: usize = 16;
/// Maximum `url.path` bytes stored in the record.
pub const MAX_SPAN_URL_PATH: usize = 64;

// ── Wire-format field sizes ───────────────────────────────────────────────────

/// Size of the fixed header (everything before variable-length fields).
///
/// trace_id(16) + span_id(8) + parent_span_id(8) + flags(4)
/// + start_ns(8) + end_ns(8) + status_code(1) + kind(1)
pub const SPAN_RECORD_FIXED_HDR: usize = 16 + 8 + 8 + 4 + 8 + 8 + 1 + 1;

/// Worst-case span record length, derived from named caps.
///
/// Fixed header + name(2+MAX_SPAN_NAME) + method(2+MAX_SPAN_METHOD)
/// + http_status(2) + url_path(2+MAX_SPAN_URL_PATH) + duration_us(8)
pub const SPAN_RECORD_WORST_CASE: usize = SPAN_RECORD_FIXED_HDR
    + (2 + MAX_SPAN_NAME)
    + (2 + MAX_SPAN_METHOD)
    + 2
    + (2 + MAX_SPAN_URL_PATH)
    + 8;

/// Maximum bytes for a serialised span record (stack-buffer size).
///
/// Rounded up from `SPAN_RECORD_WORST_CASE` to the next 16-byte alignment.
pub const MAX_SPAN_RECORD: usize = (SPAN_RECORD_WORST_CASE + 15) & !15;

/// Compile-time overflow guard: any cap bump that would break the stack buffer
/// turns into a **build failure** here rather than a latent runtime panic.
const _: () = assert!(
    SPAN_RECORD_WORST_CASE <= MAX_SPAN_RECORD,
    "SPAN_RECORD_WORST_CASE exceeds MAX_SPAN_RECORD — bump MAX_SPAN_RECORD"
);

// ── `SpanRecord` — the producer-side span descriptor ─────────────────────────

/// Descriptor for a completed server span, built at span-end in the Log phase.
///
/// All byte-slice fields borrow nginx request memory — no allocation.
/// Phase 3 cold-path: synthetic records are constructed for S2 testing;
/// real records arrive in Loop 2.
///
/// Loop 2 (hot-path) will construct this struct from request context.
/// `#[allow(dead_code)]` guards the S2→Loop-2 gap.
#[allow(dead_code)]
pub struct SpanRecord<'a> {
    /// 16-byte W3C trace ID.
    pub trace_id: [u8; 16],
    /// 8-byte W3C span ID.
    pub span_id: [u8; 8],
    /// 8-byte parent span ID (zeros = root span).
    pub parent_span_id: [u8; 8],
    /// W3C trace flags (low 8 bits of W3C flags field).
    pub flags: u32,
    /// Span start time (Unix epoch, nanoseconds).
    pub start_time_unix_nano: u64,
    /// Span end time (Unix epoch, nanoseconds).
    pub end_time_unix_nano: u64,
    /// OTel StatusCode (Unset=0, Ok=1, Error=2).
    pub status_code: u8,
    /// OTel SpanKind (Server=2).
    pub kind: u8,
    /// Operation name (e.g. `b"GET /health"`).
    pub name: &'a [u8],
    /// `http.request.method` bytes.
    pub method: &'a [u8],
    /// HTTP response status code (0 if absent).
    pub http_status: u16,
    /// `url.path` bytes.
    pub url_path: &'a [u8],
    /// Request duration in microseconds.
    pub duration_us: u64,
}

// ── Wire encoder ─────────────────────────────────────────────────────────────

/// Emit one span record into the producer's ring.
///
/// Serialises `rec` into a fixed-size stack buffer and calls
/// `producer.push()`.  Returns `true` on success; `false` when the ring is full.
///
/// # No allocation
/// All formatting is done into a `[u8; MAX_SPAN_RECORD]` stack buffer.
/// No `Vec`, no `Box`, no heap use.
///
/// Loop 2 (hot-path) will call this from the log phase.
/// `#[allow(dead_code)]` guards the S2→Loop-2 gap.
#[allow(dead_code)]
#[inline]
pub fn emit_span_record(producer: &dyn LogProducer, rec: &SpanRecord<'_>) -> bool {
    let mut buf = [0u8; MAX_SPAN_RECORD];
    let mut pos = 0usize;

    macro_rules! write_bytes {
        ($b:expr) => {
            let b = $b;
            buf[pos..pos + b.len()].copy_from_slice(b);
            pos += b.len();
        };
    }

    macro_rules! write_u8 {
        ($v:expr) => {
            buf[pos] = $v;
            pos += 1;
        };
    }

    macro_rules! write_u16_be {
        ($v:expr) => {
            let v: u16 = $v;
            buf[pos..pos + 2].copy_from_slice(&v.to_be_bytes());
            pos += 2;
        };
    }

    macro_rules! write_u32_be {
        ($v:expr) => {
            let v: u32 = $v;
            buf[pos..pos + 4].copy_from_slice(&v.to_be_bytes());
            pos += 4;
        };
    }

    macro_rules! write_u64_be {
        ($v:expr) => {
            let v: u64 = $v;
            buf[pos..pos + 8].copy_from_slice(&v.to_be_bytes());
            pos += 8;
        };
    }

    macro_rules! write_capped {
        ($slice:expr, $max:expr, $len_field:ty) => {
            let raw = $slice;
            let trimmed = if raw.len() > $max { &raw[..$max] } else { raw };
            write_u16_be!(trimmed.len() as u16);
            write_bytes!(trimmed);
        };
    }

    // Fixed header.
    write_bytes!(&rec.trace_id);
    write_bytes!(&rec.span_id);
    write_bytes!(&rec.parent_span_id);
    write_u32_be!(rec.flags);
    write_u64_be!(rec.start_time_unix_nano);
    write_u64_be!(rec.end_time_unix_nano);
    write_u8!(rec.status_code);
    write_u8!(rec.kind);

    // Variable-length fields.
    write_capped!(rec.name, MAX_SPAN_NAME, u16);
    write_capped!(rec.method, MAX_SPAN_METHOD, u16);
    write_u16_be!(rec.http_status);
    write_capped!(rec.url_path, MAX_SPAN_URL_PATH, u16);
    write_u64_be!(rec.duration_us);

    producer.push(&buf[..pos])
}

// ── Wire decoder (exporter side) ─────────────────────────────────────────────

/// Parse a span record from the ring wire format back into a [`crate::data_model::Span`].
///
/// Returns `None` if the buffer is too short or malformed.
/// Called by `collect_span_records` in the exporter.
pub fn parse_span_record(buf: &[u8], observed_ns: u64) -> Option<crate::data_model::Span> {
    use crate::data_model::{AnyValue, KeyValue, Span, SpanKind, SpanStatus, StatusCode};

    if buf.len() < SPAN_RECORD_FIXED_HDR + 2 {
        return None;
    }
    let mut pos = 0usize;

    let trace_id = buf[pos..pos + 16].to_vec();
    pos += 16;
    let span_id = buf[pos..pos + 8].to_vec();
    pos += 8;
    let parent_span_id = buf[pos..pos + 8].to_vec();
    pos += 8;
    let flags = u32::from_be_bytes(buf[pos..pos + 4].try_into().ok()?);
    pos += 4;
    let start_time_unix_nano = u64::from_be_bytes(buf[pos..pos + 8].try_into().ok()?);
    pos += 8;
    let end_time_unix_nano = u64::from_be_bytes(buf[pos..pos + 8].try_into().ok()?);
    pos += 8;
    let status_raw = buf[pos];
    pos += 1;
    let kind_raw = buf[pos];
    pos += 1;

    let status_code = match status_raw {
        1 => StatusCode::Ok,
        2 => StatusCode::Error,
        _ => StatusCode::Unset,
    };

    let kind = match kind_raw {
        1 => SpanKind::Internal,
        2 => SpanKind::Server,
        3 => SpanKind::Client,
        4 => SpanKind::Producer,
        5 => SpanKind::Consumer,
        _ => SpanKind::Unspecified,
    };

    // Variable-length: name
    if pos + 2 > buf.len() {
        return None;
    }
    let name_len = u16::from_be_bytes(buf[pos..pos + 2].try_into().ok()?) as usize;
    pos += 2;
    if pos + name_len > buf.len() {
        return None;
    }
    let name = std::string::String::from_utf8_lossy(&buf[pos..pos + name_len]).into_owned();
    pos += name_len;

    // Variable-length: method
    if pos + 2 > buf.len() {
        return None;
    }
    let method_len = u16::from_be_bytes(buf[pos..pos + 2].try_into().ok()?) as usize;
    pos += 2;
    if pos + method_len > buf.len() {
        return None;
    }
    let method = std::string::String::from_utf8_lossy(&buf[pos..pos + method_len]).into_owned();
    pos += method_len;

    // HTTP status code
    if pos + 2 > buf.len() {
        return None;
    }
    let http_status = u16::from_be_bytes(buf[pos..pos + 2].try_into().ok()?);
    pos += 2;

    // Variable-length: url.path
    if pos + 2 > buf.len() {
        return None;
    }
    let url_path_len = u16::from_be_bytes(buf[pos..pos + 2].try_into().ok()?) as usize;
    pos += 2;
    if pos + url_path_len > buf.len() {
        return None;
    }
    let url_path = std::string::String::from_utf8_lossy(&buf[pos..pos + url_path_len]).into_owned();
    pos += url_path_len;

    // duration_us
    if pos + 8 > buf.len() {
        return None;
    }
    let duration_us = u64::from_be_bytes(buf[pos..pos + 8].try_into().ok()?);

    // Build OTel attributes from decoded HTTP fields.
    let mut attributes = std::vec::Vec::new();
    if !method.is_empty() {
        attributes
            .push(KeyValue { key: "http.request.method".into(), value: AnyValue::String(method) });
    }
    if http_status > 0 {
        attributes.push(KeyValue {
            key: "http.response.status_code".into(),
            value: AnyValue::Int(http_status as i64),
        });
    }
    if !url_path.is_empty() {
        attributes.push(KeyValue { key: "url.path".into(), value: AnyValue::String(url_path) });
    }
    if duration_us > 0 {
        attributes.push(KeyValue {
            key: "http.server.request.duration".into(),
            value: AnyValue::Double(duration_us as f64 / 1_000.0),
        });
    }

    // Use observed_ns as the span time stamp (used for de-dup / ordering).
    // The actual start/end are preserved in the span struct.
    let _ = observed_ns;

    Some(Span {
        trace_id,
        span_id,
        parent_span_id,
        flags,
        name,
        kind,
        start_time_unix_nano,
        end_time_unix_nano,
        attributes,
        events: std::vec::Vec::new(),
        links: std::vec::Vec::new(),
        status: SpanStatus { code: status_code, message: std::string::String::new() },
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify MAX_SPAN_RECORD is correctly sized (compile-time guard smoke-test).
    /// Verify the named caps produce expected absolute sizes.
    /// The compile-time guard (`const _: ()`) already catches overflow;
    /// this test pins the concrete values so a future cap change is
    /// intentional (not silent).
    #[test]
    fn span_record_size_constants() {
        // SPAN_RECORD_FIXED_HDR = 16+8+8+4+8+8+1+1 = 54
        assert_eq!(SPAN_RECORD_FIXED_HDR, 54);
        // WORST_CASE = 54 + (2+64) + (2+16) + 2 + (2+64) + 8
        //            = 54 + 66 + 18 + 2 + 66 + 8 = 214
        assert_eq!(SPAN_RECORD_WORST_CASE, 214);
        // MAX_SPAN_RECORD = round_up(214, 16) = 224
        assert_eq!(MAX_SPAN_RECORD, 224);
        // The compile-time `const _: ()` guard covers the overflow relationship;
        // the eq assertions above are sufficient to pin any accidental change.
    }

    /// Push a synthetic span record via a Vec-backed mock producer, then parse it.
    #[test]
    fn span_record_roundtrip() {
        use crate::data_model::{SpanKind, StatusCode};

        // A simple in-memory LogProducer mock.
        struct VecProducer(std::sync::Mutex<std::vec::Vec<u8>>);
        impl LogProducer for VecProducer {
            fn push(&self, data: &[u8]) -> bool {
                let mut v = self.0.lock().unwrap();
                let len = data.len() as u32;
                v.extend_from_slice(&len.to_be_bytes());
                v.extend_from_slice(data);
                true
            }
        }

        let producer = VecProducer(std::sync::Mutex::new(std::vec::Vec::new()));

        let rec = SpanRecord {
            trace_id: [0x01u8; 16],
            span_id: [0x02u8; 8],
            parent_span_id: [0x03u8; 8],
            flags: 0x01,
            start_time_unix_nano: 1_700_000_000_000_000_000,
            end_time_unix_nano: 1_700_000_000_001_000_000,
            status_code: StatusCode::Ok as u8,
            kind: SpanKind::Server as u8,
            name: b"GET /health",
            method: b"GET",
            http_status: 200,
            url_path: b"/health",
            duration_us: 1000,
        };

        assert!(emit_span_record(&producer, &rec), "push must succeed");

        // Extract payload from the length-prefixed bytes.
        let raw = producer.0.lock().unwrap();
        let len = u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize;
        let payload = &raw[4..4 + len];

        let span = parse_span_record(payload, 0).expect("parse must succeed");

        assert_eq!(span.trace_id, std::vec![0x01u8; 16]);
        assert_eq!(span.span_id, std::vec![0x02u8; 8]);
        assert_eq!(span.parent_span_id, std::vec![0x03u8; 8]);
        assert_eq!(span.flags, 0x01);
        assert_eq!(span.name, "GET /health");
        assert_eq!(span.kind, SpanKind::Server);
        assert_eq!(span.status.code, StatusCode::Ok);
        assert_eq!(span.start_time_unix_nano, 1_700_000_000_000_000_000);
        assert_eq!(span.end_time_unix_nano, 1_700_000_000_001_000_000);
        // Verify HTTP attributes are reconstructed.
        let keys: std::vec::Vec<&str> = span.attributes.iter().map(|kv| kv.key.as_str()).collect();
        assert!(keys.contains(&"http.request.method"));
        assert!(keys.contains(&"http.response.status_code"));
        assert!(keys.contains(&"url.path"));
    }
}
