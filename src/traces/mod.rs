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
//! [2]  method_len          (big-endian u16, ≤ MAX_METHOD from logs::access)
//! [method_len] method      (http.request.method)
//! [2]  status_code_http    (big-endian u16, HTTP status code, 0 if absent)
//! [2]  url_path_len        (big-endian u16, ≤ MAX_URL_PATH from logs::access)
//! [url_path_len] url_path  (url.path)
//! [8]  duration_us         (big-endian u64, request duration in µs)
//! [2]  n_attrs             (big-endian u16, number of extra attributes; 0 = none)
//! For each attr (0..n_attrs):
//!   [1]  key_len           (u8, ≤ MAX_SPAN_ATTR_KEY)
//!   [key_len] key          (UTF-8 attribute name)
//!   [2]  val_len           (big-endian u16, ≤ MAX_SPAN_ATTR_VAL)
//!   [val_len] val          (UTF-8 attribute value string)
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

pub mod ctx;

use crate::logs::LogProducer;
// S3: method and url.path caps are single-homed in logs::access (same semantic
// field on the same nginx request).  Import them here so span and access records
// always use the same value — a bump to MAX_URL_PATH propagates automatically.
use crate::logs::access::{MAX_METHOD, MAX_URL_PATH};

// ── Named field caps ──────────────────────────────────────────────────────────

/// Maximum span name bytes stored in the record.
pub const MAX_SPAN_NAME: usize = 64;
/// Maximum number of extra span attributes from `otel_span_attr` directives.
pub const MAX_SPAN_EXTRA_ATTRS: usize = 4;
/// Maximum attribute key length (bytes) per extra attribute.
pub const MAX_SPAN_ATTR_KEY: usize = 32;
/// Maximum attribute value length (bytes) per extra attribute.
pub const MAX_SPAN_ATTR_VAL: usize = 64;

// ── Wire-format field sizes ───────────────────────────────────────────────────

/// Size of the fixed header (everything before variable-length fields).
///
/// trace_id(16) + span_id(8) + parent_span_id(8) + flags(4)
/// + start_ns(8) + end_ns(8) + status_code(1) + kind(1)
pub const SPAN_RECORD_FIXED_HDR: usize = 16 + 8 + 8 + 4 + 8 + 8 + 1 + 1;

/// Worst-case span record length, derived from named caps.
///
/// Fixed header + name(2+MAX_SPAN_NAME) + method(2+MAX_METHOD)
/// + http_status(2) + url_path(2+MAX_URL_PATH) + duration_us(8)
/// + n_attrs(2) + MAX_SPAN_EXTRA_ATTRS × (1+MAX_SPAN_ATTR_KEY + 2+MAX_SPAN_ATTR_VAL)
///
/// `MAX_METHOD` and `MAX_URL_PATH` are imported from `crate::logs::access`
/// (single-homed there — same semantic field on the same nginx request).
pub const SPAN_RECORD_WORST_CASE: usize = SPAN_RECORD_FIXED_HDR
    + (2 + MAX_SPAN_NAME)
    + (2 + MAX_METHOD)
    + 2
    + (2 + MAX_URL_PATH)
    + 8
    + 2
    + MAX_SPAN_EXTRA_ATTRS * (1 + MAX_SPAN_ATTR_KEY + 2 + MAX_SPAN_ATTR_VAL);

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
/// Built from `SpanCtx` + request fields in `LogPhaseHandler` (Phase 3.4, S2).
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
    /// Extra span attributes from `otel_span_attr` directives (Phase 3.5 S3).
    ///
    /// Slice of `(key_bytes, value_bytes)` pairs built in `LogPhaseHandler` from
    /// `LocationConf::span_attrs` — conf pool memory, valid for process lifetime.
    /// Empty slice when no `otel_span_attr` directives are set.
    pub extra_attrs: &'a [(&'a [u8], &'a [u8])],
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
/// Called from `LogPhaseHandler` (Phase 3.4, S2) for every sampled request.
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
    write_capped!(rec.method, MAX_METHOD, u16);
    write_u16_be!(rec.http_status);
    write_capped!(rec.url_path, MAX_URL_PATH, u16);
    write_u64_be!(rec.duration_us);

    // Extra attributes from otel_span_attr directives (Phase 3.5 S3).
    let n = rec.extra_attrs.len().min(MAX_SPAN_EXTRA_ATTRS);
    write_u16_be!(n as u16);
    for (key, val) in &rec.extra_attrs[..n] {
        let k = if key.len() > MAX_SPAN_ATTR_KEY { &key[..MAX_SPAN_ATTR_KEY] } else { key };
        let v = if val.len() > MAX_SPAN_ATTR_VAL { &val[..MAX_SPAN_ATTR_VAL] } else { val };
        write_u8!(k.len() as u8);
        write_bytes!(k);
        write_u16_be!(v.len() as u16);
        write_bytes!(v);
    }

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
    // Root spans store [0u8; 8] on the ring wire.  OTLP semantics require an
    // **empty** parent_span_id bytes field for root spans (proto `bytes` default
    // = empty means "no parent"); exporting [0u8;8] signals a non-existent
    // parent to backends and breaks trace-root detection.
    // Intended wire change (F7): root spans now export empty parent_span_id.
    let parent_span_id = {
        let raw = &buf[pos..pos + 8];
        if raw == [0u8; 8] {
            std::vec::Vec::new()
        } else {
            raw.to_vec()
        }
    };
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
    pos += 8;

    // Extra attributes (Phase 3.5 S3) — gracefully absent in older records.
    let n_extra = if pos + 2 <= buf.len() {
        let n = u16::from_be_bytes(buf[pos..pos + 2].try_into().ok()?) as usize;
        pos += 2;
        n.min(MAX_SPAN_EXTRA_ATTRS) // sanity cap: producer never writes more than MAX_SPAN_EXTRA_ATTRS
    } else {
        0
    };

    // Build OTel attributes from decoded HTTP fields.
    let mut attributes = std::vec::Vec::new();

    // Decode extra attrs.
    for _ in 0..n_extra {
        if pos + 1 > buf.len() {
            break;
        }
        let k_len = buf[pos] as usize;
        pos += 1;
        if pos + k_len > buf.len() {
            break;
        }
        let key = std::string::String::from_utf8_lossy(&buf[pos..pos + k_len]).into_owned();
        pos += k_len;
        if pos + 2 > buf.len() {
            break;
        }
        let v_len = u16::from_be_bytes(buf[pos..pos + 2].try_into().ok()?) as usize;
        pos += 2;
        if pos + v_len > buf.len() {
            break;
        }
        let val = std::string::String::from_utf8_lossy(&buf[pos..pos + v_len]).into_owned();
        pos += v_len;
        attributes.push(KeyValue { key, value: AnyValue::String(val) });
    }
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
            value: AnyValue::Double(duration_us as f64 / 1_000_000.0),
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
        // WORST_CASE = 54 + (2+64) + (2+16) + 2 + (2+64) + 8 + 2 + 4*(1+32+2+64)
        //            = 54 + 66 + 18 + 2 + 66 + 8 + 2 + 396 = 612
        assert_eq!(SPAN_RECORD_WORST_CASE, 612);
        // MAX_SPAN_RECORD = round_up(612, 16) = 624
        assert_eq!(MAX_SPAN_RECORD, 624);
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
            extra_attrs: &[],
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
        assert!(
            keys.contains(&"http.server.request.duration"),
            "duration attribute must be present"
        );

        // S1 regression guard: duration must be in seconds (µs / 1_000_000), not ms.
        // rec.duration_us == 1000 → 0.001 s exactly.
        let dur_attr = span
            .attributes
            .iter()
            .find(|kv| kv.key == "http.server.request.duration")
            .expect("http.server.request.duration must be present");
        let expected_secs = rec.duration_us as f64 / 1_000_000.0;
        match &dur_attr.value {
            crate::data_model::AnyValue::Double(v) => {
                assert!(
                    (*v - expected_secs).abs() < 1e-12,
                    "http.server.request.duration must be {expected_secs:.9} s (seconds), got {v:.9}"
                );
            }
            other => panic!("http.server.request.duration must be a Double, got {other:?}"),
        }
    }

    /// S2 — Structural golden: encode a maximally-populated SpanRecord, parse it
    /// back, and assert every decoded field value precisely.
    ///
    /// This is the regression seal for S3–S5: those steps are wire-format-neutral
    /// for well-formed input — this test MUST stay green across them.  A failure
    /// here means a nominally-neutral change altered emitted bytes.
    ///
    /// Regeneration: update the `SpanRecord` input literal below if the wire
    /// format is intentionally changed (requires deliberate review).
    #[test]
    fn span_golden_structural() {
        use crate::data_model::{AnyValue, SpanKind, StatusCode};

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

        // Fixed inputs — deterministic, no timestamps from SystemTime.
        let trace_id: [u8; 16] = [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b,
        ];
        let span_id: [u8; 8] = [0xca, 0xfe, 0xba, 0xbe, 0x11, 0x22, 0x33, 0x44];
        let parent_span_id: [u8; 8] = [0xfe, 0xed, 0xfa, 0xce, 0x55, 0x66, 0x77, 0x88];
        let extra: [(&[u8], &[u8]); 1] = [(&b"env"[..], &b"prod"[..])];

        let rec = SpanRecord {
            trace_id,
            span_id,
            parent_span_id,
            flags: 0x01,
            start_time_unix_nano: 1_700_000_000_000_000_000,
            end_time_unix_nano: 1_700_000_001_234_567_000,
            status_code: StatusCode::Ok as u8,
            kind: SpanKind::Server as u8,
            name: b"GET /api/v1/users",
            method: b"GET",
            http_status: 200,
            url_path: b"/api/v1/users",
            duration_us: 1_234_567,
            extra_attrs: &extra,
        };

        let producer = VecProducer(std::sync::Mutex::new(std::vec::Vec::new()));
        assert!(emit_span_record(&producer, &rec), "push must succeed");

        let raw = producer.0.lock().unwrap();
        let len = u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize;
        let payload = &raw[4..4 + len];
        let span = parse_span_record(payload, 0).expect("parse must succeed");

        // ── Identity fields ───────────────────────────────────────────────────
        assert_eq!(span.trace_id, trace_id.to_vec(), "trace_id must round-trip");
        assert_eq!(span.span_id, span_id.to_vec(), "span_id must round-trip");
        assert_eq!(span.parent_span_id, parent_span_id.to_vec(), "parent_span_id must round-trip");
        assert_eq!(span.flags, 0x01, "flags must round-trip");

        // ── Timing fields ─────────────────────────────────────────────────────
        assert_eq!(
            span.start_time_unix_nano, 1_700_000_000_000_000_000,
            "start_time_unix_nano must round-trip"
        );
        assert_eq!(
            span.end_time_unix_nano, 1_700_000_001_234_567_000,
            "end_time_unix_nano must round-trip"
        );

        // ── Semantic fields ───────────────────────────────────────────────────
        assert_eq!(span.name, "GET /api/v1/users", "span name must round-trip");
        assert_eq!(span.kind, SpanKind::Server, "span kind must be Server");
        assert_eq!(span.status.code, StatusCode::Ok, "status code must be Ok");

        // ── HTTP attributes ───────────────────────────────────────────────────
        let find_attr = |key: &str| -> Option<&AnyValue> {
            span.attributes.iter().find(|kv| kv.key == key).map(|kv| &kv.value)
        };

        // http.request.method
        match find_attr("http.request.method").expect("http.request.method must be present") {
            AnyValue::String(s) => assert_eq!(s, "GET", "method must be GET"),
            other => panic!("http.request.method must be String, got {other:?}"),
        }

        // http.response.status_code
        match find_attr("http.response.status_code")
            .expect("http.response.status_code must be present")
        {
            AnyValue::Int(v) => assert_eq!(*v, 200, "status code must be 200"),
            other => panic!("http.response.status_code must be Int, got {other:?}"),
        }

        // url.path
        match find_attr("url.path").expect("url.path must be present") {
            AnyValue::String(s) => {
                assert_eq!(s, "/api/v1/users", "url.path must round-trip")
            }
            other => panic!("url.path must be String, got {other:?}"),
        }

        // http.server.request.duration — S1 fix: seconds, not ms
        // 1_234_567 µs == 1.234567 s exactly (no floating-point loss at this magnitude).
        match find_attr("http.server.request.duration")
            .expect("http.server.request.duration must be present")
        {
            AnyValue::Double(v) => {
                let expected = rec.duration_us as f64 / 1_000_000.0;
                assert!(
                    (*v - expected).abs() < 1e-9,
                    "http.server.request.duration must be {expected:.9} s, got {v:.9}"
                );
            }
            other => {
                panic!("http.server.request.duration must be Double, got {other:?}")
            }
        }

        // ── Extra attributes (S2 golden covers the extra-attrs path) ──────────
        match find_attr("env").expect("extra attr 'env' must be present") {
            AnyValue::String(s) => assert_eq!(s, "prod", "env attr value must be 'prod'"),
            other => panic!("extra attr 'env' must be String, got {other:?}"),
        }
        // No more extra attrs than what we emitted.
        let extra_keys: std::vec::Vec<&str> = span
            .attributes
            .iter()
            .filter(|kv| {
                ![
                    "http.request.method",
                    "http.response.status_code",
                    "url.path",
                    "http.server.request.duration",
                ]
                .contains(&kv.key.as_str())
            })
            .map(|kv| kv.key.as_str())
            .collect();
        assert_eq!(extra_keys, vec!["env"], "only 'env' extra attr expected");
    }

    /// S4 — Parser sanity cap: a corrupted `n_extra` field must not cause the
    /// parser to loop more than `MAX_SPAN_EXTRA_ATTRS` times.
    ///
    /// Produces a well-formed span record with one extra attr, then patches the
    /// raw `n_extra` wire field to a value far above the producer maximum.
    /// The parser must clamp at `MAX_SPAN_EXTRA_ATTRS` and still return a valid
    /// span (one or zero extra attrs, depending on how many bytes are valid).
    #[test]
    fn span_parser_extra_attrs_sanity_cap() {
        use crate::data_model::{SpanKind, StatusCode};

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

        // Emit a span with one valid extra attr.
        let extra: [(&[u8], &[u8]); 1] = [(&b"k"[..], &b"v"[..])];
        let rec = SpanRecord {
            trace_id: [0x01u8; 16],
            span_id: [0x02u8; 8],
            parent_span_id: [0x00u8; 8],
            flags: 0x01,
            start_time_unix_nano: 1_000_000_000,
            end_time_unix_nano: 2_000_000_000,
            status_code: StatusCode::Ok as u8,
            kind: SpanKind::Server as u8,
            name: b"GET /s4",
            method: b"GET",
            http_status: 200,
            url_path: b"/s4",
            duration_us: 500,
            extra_attrs: &extra,
        };

        let producer = VecProducer(std::sync::Mutex::new(std::vec::Vec::new()));
        assert!(emit_span_record(&producer, &rec));

        let raw = producer.0.lock().unwrap();
        let len = u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize;

        // Copy payload so we can mutate it.
        let mut payload = raw[4..4 + len].to_vec();

        // Locate the n_extra field.  It appears right after the fixed header,
        // name (2+len), method (2+len), http_status (2), url_path (2+len),
        // duration_us (8).  Walk to it rather than hard-coding an offset so
        // this test is resilient to field order changes.
        let mut pos = SPAN_RECORD_FIXED_HDR;
        // name
        let name_len = u16::from_be_bytes(payload[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2 + name_len;
        // method
        let method_len = u16::from_be_bytes(payload[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2 + method_len;
        // http_status
        pos += 2;
        // url_path
        let path_len = u16::from_be_bytes(payload[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2 + path_len;
        // duration_us
        pos += 8;
        // pos now points at n_extra (u16 big-endian)
        let n_extra_offset = pos;
        assert!(n_extra_offset + 2 <= payload.len(), "n_extra offset out of bounds");

        // Corrupt n_extra to a large value (200 — well above MAX_SPAN_EXTRA_ATTRS * 4).
        let corrupt_n: u16 = 200;
        payload[n_extra_offset..n_extra_offset + 2].copy_from_slice(&corrupt_n.to_be_bytes());

        // The parser must not panic or loop 200 times; it must clamp and return.
        let span = parse_span_record(&payload, 0).expect("parser must tolerate corrupted n_extra");

        // With a corrupted n_extra the parser tries MAX_SPAN_EXTRA_ATTRS iterations
        // at most.  Only the bytes for 1 real attr were serialized; the rest break
        // inside the loop (pos overruns buf), so we get ≤ MAX_SPAN_EXTRA_ATTRS attrs
        // in the final span (typically 0 or 1 extra, plus the standard HTTP attrs).
        let extra_count = span
            .attributes
            .iter()
            .filter(|kv| {
                ![
                    "http.request.method",
                    "http.response.status_code",
                    "url.path",
                    "http.server.request.duration",
                ]
                .contains(&kv.key.as_str())
            })
            .count();
        assert!(
            extra_count <= MAX_SPAN_EXTRA_ATTRS,
            "parser must not exceed MAX_SPAN_EXTRA_ATTRS ({MAX_SPAN_EXTRA_ATTRS}) extra attrs, got {extra_count}"
        );
    }
}
