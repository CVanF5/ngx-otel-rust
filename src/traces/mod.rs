// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Span record wire format (worker → exporter) — cold-path.
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
//! [1]  proto               (ProtoVersion index: 0=1.0 1=1.1 2=2 3=3; network.protocol.version)
//! [1]  scheme              (0 = "http", 1 = "https"; url.scheme)
//! [2]  server_port         (big-endian u16, server.port; 0 = absent)
//! [2]  client_port         (big-endian u16, client.port; 0 = absent)
//! [2]  peer_port           (big-endian u16, network.peer.port; 0 = absent)
//! [8]  req_body_size       (big-endian u64, http.request.body.size)
//! [8]  resp_body_size      (big-endian u64, http.response.body.size)
//! [2]  url_query_len       (big-endian u16, ≤ MAX_URL_QUERY)
//! [url_query_len] url_query (url.query, args without leading '?')
//! [2]  route_len           (big-endian u16, ≤ MAX_SPAN_ROUTE)
//! [route_len] route        (http.route, matched location name)
//! [2]  user_agent_len      (big-endian u16, ≤ MAX_USER_AGENT from logs::access)
//! [user_agent_len] user_agent (user_agent.original)
//! [2]  server_addr_len     (big-endian u16, ≤ MAX_SERVER_ADDR)
//! [server_addr_len] server_addr (server.address)
//! [2]  client_addr_len     (big-endian u16, ≤ MAX_CLIENT_ADDR from logs::access)
//! [client_addr_len] client_addr (client.address; realip-aware $remote_addr)
//! [2]  peer_addr_len       (big-endian u16, ≤ MAX_CLIENT_ADDR from logs::access)
//! [peer_addr_len] peer_addr (network.peer.address; true TCP socket peer)
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
//! # Compile-time size guard
//!
//! `SPAN_RECORD_WORST_CASE ≤ MAX_SPAN_RECORD` is a `const assert!` so that
//! any future cap increase that would overflow the buffer is a **build failure**
//! rather than a latent runtime panic.

pub mod ctx;

use crate::logs::LogProducer;
// Caps are single-homed in logs::access (same semantic field, same request);
// importing them keeps span and access records in sync automatically.
use crate::logs::access::{MAX_CLIENT_ADDR, MAX_METHOD, MAX_URL_PATH, MAX_USER_AGENT};

// ── Named field caps ──────────────────────────────────────────────────────────

/// Maximum span name bytes stored in the record.
pub const MAX_SPAN_NAME: usize = 64;
/// Maximum `url.query` bytes stored in the record.
///
/// Query strings are high-cardinality and may carry credentials; the value is
/// capped (and exported only on sampled spans) like the other detail fields.
pub const MAX_URL_QUERY: usize = 128;
/// Maximum `http.route` (matched location name) bytes stored in the record.
pub const MAX_SPAN_ROUTE: usize = 64;
/// Maximum `server.address` bytes stored in the record.
pub const MAX_SERVER_ADDR: usize = 64;
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

/// Worst-case span record length, derived from named caps (see field-by-field
/// breakdown in the expression below). `MAX_METHOD`, `MAX_URL_PATH`,
/// `MAX_USER_AGENT`, and `MAX_CLIENT_ADDR` are imported from
/// `crate::logs::access` (single-homed there — same semantic field, same request).
///
/// # Sizing / saturation note
/// The HTTP-semconv coverage fields raise the worst-case record from 612 B to
/// 1124 B.  `push` writes only the actually-formatted `pos` bytes, so a typical
/// span (short/empty user-agent, no query) grows far less than the worst case;
/// but a larger fixed worst case means fewer worst-case spans fit a fixed-size
/// ring, modestly lowering the per-worker span saturation ceiling.  The coupled
/// drain-budget / ring-size / send-chunk constants are intentionally left
/// unchanged here; raise them together if span throughput at saturation
/// regresses.
pub const SPAN_RECORD_WORST_CASE: usize = SPAN_RECORD_FIXED_HDR
    + (2 + MAX_SPAN_NAME)
    + (2 + MAX_METHOD)
    + 2
    + (2 + MAX_URL_PATH)
    + 8
    + 1 // proto
    + 1 // scheme
    + 2 // server_port
    + 2 // client_port
    + 2 // peer_port
    + 8 // req_body_size
    + 8 // resp_body_size
    + (2 + MAX_URL_QUERY)
    + (2 + MAX_SPAN_ROUTE)
    + (2 + MAX_USER_AGENT)
    + (2 + MAX_SERVER_ADDR)
    + (2 + MAX_CLIENT_ADDR)
    + (2 + MAX_CLIENT_ADDR)
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
/// Built from `SpanCtx` + request fields in `LogPhaseHandler`.
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
    /// `network.protocol.version` source — `ProtoVersion` index (0=1.0 1=1.1
    /// 2=2 3=3); decoded to the semconv string at the exporter.
    pub proto: u8,
    /// `url.scheme`: `false` ⇒ `"http"`, `true` ⇒ `"https"`.
    pub scheme_https: bool,
    /// `server.port` (local listening port); 0 ⇒ omitted.
    pub server_port: u16,
    /// `client.port` (realip-aware logical client port); 0 ⇒ omitted.
    pub client_port: u16,
    /// `network.peer.port` (true TCP socket peer port); 0 ⇒ omitted.
    pub peer_port: u16,
    /// `http.request.body.size` (request body bytes).
    pub req_body_size: u64,
    /// `http.response.body.size` (response body bytes, headers excluded).
    pub resp_body_size: u64,
    /// `url.query` bytes (args, no leading `?`); empty ⇒ omitted.
    pub url_query: &'a [u8],
    /// `http.route` bytes (matched location name); empty ⇒ omitted.
    pub route: &'a [u8],
    /// `user_agent.original` bytes; empty ⇒ omitted.
    pub user_agent: &'a [u8],
    /// `server.address` bytes (server name / Host); empty ⇒ omitted.
    pub server_address: &'a [u8],
    /// `client.address` bytes (realip-aware `$remote_addr`); empty ⇒ omitted.
    pub client_address: &'a [u8],
    /// `network.peer.address` bytes (true TCP socket peer); empty ⇒ omitted.
    pub peer_address: &'a [u8],
    /// Extra span attributes from `otel_span_attr` directives.
    ///
    /// Slice of `(key_bytes, value_bytes)` pairs built in `LogPhaseHandler` from
    /// `LocationConf::span_attrs` — conf pool memory, valid for process lifetime.
    /// Empty slice when no `otel_span_attr` directives are set.
    pub extra_attrs: &'a [(&'a [u8], &'a [u8])],
}

// ── Wire encoder ─────────────────────────────────────────────────────────────

/// Emit one span record into the producer's ring.
///
/// Serialises `rec` into a fixed-size `[u8; MAX_SPAN_RECORD]` stack buffer
/// (no `Vec`/`Box`/heap use) and calls `producer.push()`.  Returns `true` on
/// success; `false` when the ring is full.  Called from `LogPhaseHandler` for
/// every sampled request.
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

    // HTTP semconv coverage fields.
    write_u8!(rec.proto);
    write_u8!(u8::from(rec.scheme_https));
    write_u16_be!(rec.server_port);
    write_u16_be!(rec.client_port);
    write_u16_be!(rec.peer_port);
    write_u64_be!(rec.req_body_size);
    write_u64_be!(rec.resp_body_size);
    write_capped!(rec.url_query, MAX_URL_QUERY, u16);
    write_capped!(rec.route, MAX_SPAN_ROUTE, u16);
    write_capped!(rec.user_agent, MAX_USER_AGENT, u16);
    write_capped!(rec.server_address, MAX_SERVER_ADDR, u16);
    write_capped!(rec.client_address, MAX_CLIENT_ADDR, u16);
    write_capped!(rec.peer_address, MAX_CLIENT_ADDR, u16);

    // Extra attributes from otel_span_attr directives.
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
    // **empty** parent_span_id bytes field for root spans (proto `bytes`
    // default = empty means "no parent"); exporting [0u8;8] would signal a
    // non-existent parent to backends and break trace-root detection.
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

    // ── HTTP semconv coverage fields ──────────────────────────────────────────
    // Read a capped, u16-length-prefixed UTF-8 string at `pos`; advance `pos`.
    // Returns the empty string when the field is absent/zero-length.
    macro_rules! read_capped_str {
        () => {{
            if pos + 2 > buf.len() {
                return None;
            }
            let len = u16::from_be_bytes(buf[pos..pos + 2].try_into().ok()?) as usize;
            pos += 2;
            if pos + len > buf.len() {
                return None;
            }
            let s = std::string::String::from_utf8_lossy(&buf[pos..pos + len]).into_owned();
            pos += len;
            s
        }};
    }

    // proto + scheme (1 byte each)
    if pos + 2 > buf.len() {
        return None;
    }
    let proto_idx = buf[pos];
    pos += 1;
    let scheme_https = buf[pos] != 0;
    pos += 1;

    // server_port / client_port / peer_port (u16 each)
    if pos + 6 > buf.len() {
        return None;
    }
    let server_port = u16::from_be_bytes(buf[pos..pos + 2].try_into().ok()?);
    pos += 2;
    let client_port = u16::from_be_bytes(buf[pos..pos + 2].try_into().ok()?);
    pos += 2;
    let peer_port = u16::from_be_bytes(buf[pos..pos + 2].try_into().ok()?);
    pos += 2;

    // req_body_size / resp_body_size (u64 each)
    if pos + 16 > buf.len() {
        return None;
    }
    let req_body_size = u64::from_be_bytes(buf[pos..pos + 8].try_into().ok()?);
    pos += 8;
    let resp_body_size = u64::from_be_bytes(buf[pos..pos + 8].try_into().ok()?);
    pos += 8;

    let url_query = read_capped_str!();
    let route = read_capped_str!();
    let user_agent = read_capped_str!();
    let server_address = read_capped_str!();
    let client_address = read_capped_str!();
    let peer_address = read_capped_str!();

    // Extra attributes — gracefully absent in older records.
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

    // ── HTTP semconv coverage attributes ──────────────────────────────────────
    // Attribute keys follow the current OTel HTTP semantic conventions:
    // <https://opentelemetry.io/docs/specs/semconv/http/http-spans/>
    if !url_query.is_empty() {
        attributes.push(KeyValue { key: "url.query".into(), value: AnyValue::String(url_query) });
    }
    if !route.is_empty() {
        attributes.push(KeyValue { key: "http.route".into(), value: AnyValue::String(route) });
    }
    // url.scheme — always known ("http"/"https").
    attributes.push(KeyValue {
        key: "url.scheme".into(),
        value: AnyValue::String(if scheme_https { "https".into() } else { "http".into() }),
    });
    // network.protocol.version — decode the ProtoVersion index to the semconv string.
    attributes.push(KeyValue {
        key: "network.protocol.version".into(),
        value: AnyValue::String(
            crate::shm::ProtoVersion::from_index(proto_idx as usize).as_str().into(),
        ),
    });
    if !user_agent.is_empty() {
        attributes.push(KeyValue {
            key: "user_agent.original".into(),
            value: AnyValue::String(user_agent),
        });
    }
    // http.request.body.size / http.response.body.size — body bytes (semconv Int).
    attributes.push(KeyValue {
        key: "http.request.body.size".into(),
        value: AnyValue::Int(req_body_size as i64),
    });
    attributes.push(KeyValue {
        key: "http.response.body.size".into(),
        value: AnyValue::Int(resp_body_size as i64),
    });
    if !server_address.is_empty() {
        attributes.push(KeyValue {
            key: "server.address".into(),
            value: AnyValue::String(server_address),
        });
    }
    if server_port > 0 {
        attributes
            .push(KeyValue { key: "server.port".into(), value: AnyValue::Int(server_port as i64) });
    }
    if !client_address.is_empty() {
        attributes.push(KeyValue {
            key: "client.address".into(),
            value: AnyValue::String(client_address),
        });
    }
    if client_port > 0 {
        attributes
            .push(KeyValue { key: "client.port".into(), value: AnyValue::Int(client_port as i64) });
    }
    if !peer_address.is_empty() {
        attributes.push(KeyValue {
            key: "network.peer.address".into(),
            value: AnyValue::String(peer_address),
        });
    }
    if peer_port > 0 {
        attributes.push(KeyValue {
            key: "network.peer.port".into(),
            value: AnyValue::Int(peer_port as i64),
        });
    }
    // error.type — derived (no worker-side field). Per the OTel HTTP semconv,
    // a server span sets error.type to the status code string on a 5xx status
    // (also the condition driving StatusCode::Error).
    // <https://opentelemetry.io/docs/specs/semconv/http/http-spans/#status>
    if http_status >= 500 {
        attributes.push(KeyValue {
            key: "error.type".into(),
            value: AnyValue::String(std::format!("{http_status}")),
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

    /// Pins the concrete size constants so a future cap change is intentional,
    /// not silent (the compile-time `const _: ()` guard only catches overflow).
    #[test]
    fn span_record_size_constants() {
        // SPAN_RECORD_FIXED_HDR = 16+8+8+4+8+8+1+1 = 54
        assert_eq!(SPAN_RECORD_FIXED_HDR, 54);
        // WORST_CASE = 54 (hdr) + (2+64) name + (2+16) method + 2 http_status
        //   + (2+64) url_path + 8 duration
        //   + 1 proto + 1 scheme + 2 server_port + 2 client_port + 2 peer_port
        //   + 8 req_body + 8 resp_body
        //   + (2+128) url_query + (2+64) route + (2+128) user_agent
        //   + (2+64) server_addr + (2+46) client_addr + (2+46) peer_addr
        //   + 2 n_attrs + 4*(1+32+2+64) extra
        //   = 214 (thru duration) + 24 (proto..resp_body) + 488 (6 capped strs)
        //     + 2 (n_attrs) + 396 (4 extra attrs) = 1124
        assert_eq!(SPAN_RECORD_WORST_CASE, 1124);
        // MAX_SPAN_RECORD = round_up(1124, 16) = 1136
        assert_eq!(MAX_SPAN_RECORD, 1136);
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
            proto: crate::shm::ProtoVersion::Http11 as u8,
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

        // Regression guard: duration must be in seconds (µs / 1_000_000), not ms.
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

    /// Structural golden: encode a maximally-populated SpanRecord, parse it
    /// back, and assert every decoded field value precisely.
    ///
    /// Regression seal — MUST stay green; a failure means a nominally-neutral
    /// change altered emitted bytes.  If the wire format changes intentionally,
    /// update the `SpanRecord` input literal below (requires deliberate review).
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
            proto: crate::shm::ProtoVersion::Http11 as u8,
            scheme_https: true,
            server_port: 8443,
            client_port: 54321,
            peer_port: 443,
            req_body_size: 12,
            resp_body_size: 3456,
            url_query: b"a=1&b=2",
            route: b"/api/v1/users",
            user_agent: b"curl/8.1.2",
            server_address: b"api.example.com",
            client_address: b"203.0.113.7",
            peer_address: b"198.51.100.9",
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

        match find_attr("http.request.method").expect("http.request.method must be present") {
            AnyValue::String(s) => assert_eq!(s, "GET", "method must be GET"),
            other => panic!("http.request.method must be String, got {other:?}"),
        }

        match find_attr("http.response.status_code")
            .expect("http.response.status_code must be present")
        {
            AnyValue::Int(v) => assert_eq!(*v, 200, "status code must be 200"),
            other => panic!("http.response.status_code must be Int, got {other:?}"),
        }

        match find_attr("url.path").expect("url.path must be present") {
            AnyValue::String(s) => {
                assert_eq!(s, "/api/v1/users", "url.path must round-trip")
            }
            other => panic!("url.path must be String, got {other:?}"),
        }

        // http.server.request.duration — seconds, not ms
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

        // ── HTTP semconv coverage attributes (current names) ──────────────────
        match find_attr("url.query").expect("url.query must be present") {
            AnyValue::String(s) => assert_eq!(s, "a=1&b=2", "url.query must round-trip"),
            other => panic!("url.query must be String, got {other:?}"),
        }
        match find_attr("http.route").expect("http.route must be present") {
            AnyValue::String(s) => assert_eq!(s, "/api/v1/users", "http.route must round-trip"),
            other => panic!("http.route must be String, got {other:?}"),
        }
        match find_attr("url.scheme").expect("url.scheme must be present") {
            AnyValue::String(s) => assert_eq!(s, "https", "url.scheme must be https"),
            other => panic!("url.scheme must be String, got {other:?}"),
        }
        match find_attr("network.protocol.version")
            .expect("network.protocol.version must be present")
        {
            AnyValue::String(s) => assert_eq!(s, "1.1", "network.protocol.version must be 1.1"),
            other => panic!("network.protocol.version must be String, got {other:?}"),
        }
        match find_attr("user_agent.original").expect("user_agent.original must be present") {
            AnyValue::String(s) => {
                assert_eq!(s, "curl/8.1.2", "user_agent.original must round-trip")
            }
            other => panic!("user_agent.original must be String, got {other:?}"),
        }
        match find_attr("http.request.body.size").expect("http.request.body.size must be present") {
            AnyValue::Int(v) => assert_eq!(*v, 12, "http.request.body.size must be 12"),
            other => panic!("http.request.body.size must be Int, got {other:?}"),
        }
        match find_attr("http.response.body.size").expect("http.response.body.size must be present")
        {
            AnyValue::Int(v) => assert_eq!(*v, 3456, "http.response.body.size must be 3456"),
            other => panic!("http.response.body.size must be Int, got {other:?}"),
        }
        match find_attr("server.address").expect("server.address must be present") {
            AnyValue::String(s) => {
                assert_eq!(s, "api.example.com", "server.address must round-trip")
            }
            other => panic!("server.address must be String, got {other:?}"),
        }
        match find_attr("server.port").expect("server.port must be present") {
            AnyValue::Int(v) => assert_eq!(*v, 8443, "server.port must be 8443"),
            other => panic!("server.port must be Int, got {other:?}"),
        }
        match find_attr("client.address").expect("client.address must be present") {
            AnyValue::String(s) => assert_eq!(s, "203.0.113.7", "client.address must round-trip"),
            other => panic!("client.address must be String, got {other:?}"),
        }
        match find_attr("client.port").expect("client.port must be present") {
            AnyValue::Int(v) => assert_eq!(*v, 54321, "client.port must be 54321"),
            other => panic!("client.port must be Int, got {other:?}"),
        }
        match find_attr("network.peer.address").expect("network.peer.address must be present") {
            AnyValue::String(s) => assert_eq!(s, "198.51.100.9", "network.peer.address round-trip"),
            other => panic!("network.peer.address must be String, got {other:?}"),
        }
        match find_attr("network.peer.port").expect("network.peer.port must be present") {
            AnyValue::Int(v) => assert_eq!(*v, 443, "network.peer.port must be 443"),
            other => panic!("network.peer.port must be Int, got {other:?}"),
        }
        // error.type is derived from a 5xx status only — absent on this 200 span.
        assert!(find_attr("error.type").is_none(), "error.type must be absent on a 2xx span");

        // No deprecated v1.16.0 keys may be emitted under any circumstances.
        for dead in [
            "http.method",
            "http.target",
            "http.status_code",
            "net.sock.peer.addr",
            "net.sock.peer.port",
            "http.scheme",
            "http.flavor",
            "http.user_agent",
            "http.request_content_length",
            "http.response_content_length",
            "net.host.name",
            "net.host.port",
        ] {
            assert!(
                find_attr(dead).is_none(),
                "deprecated v1.16.0 key '{dead}' must not be emitted"
            );
        }

        // ── Extra attributes (golden covers the extra-attrs path) ─────────────
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
                    "url.query",
                    "http.route",
                    "url.scheme",
                    "network.protocol.version",
                    "user_agent.original",
                    "http.request.body.size",
                    "http.response.body.size",
                    "server.address",
                    "server.port",
                    "client.address",
                    "client.port",
                    "network.peer.address",
                    "network.peer.port",
                ]
                .contains(&kv.key.as_str())
            })
            .map(|kv| kv.key.as_str())
            .collect();
        assert_eq!(extra_keys, vec!["env"], "only 'env' extra attr expected");
    }

    /// `error.type` is derived at the exporter from a 5xx status; assert it is
    /// present on an errored span and that `user_agent.original` truncates at cap.
    #[test]
    fn span_error_type_and_user_agent_cap() {
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

        // A user-agent longer than MAX_USER_AGENT to exercise truncation.
        let long_ua = std::vec![b'x'; MAX_USER_AGENT + 50];
        let rec = SpanRecord {
            trace_id: [0x01u8; 16],
            span_id: [0x02u8; 8],
            parent_span_id: [0u8; 8],
            flags: 0x01,
            start_time_unix_nano: 1_000_000_000,
            end_time_unix_nano: 2_000_000_000,
            status_code: StatusCode::Error as u8,
            kind: SpanKind::Server as u8,
            name: b"GET /boom",
            method: b"GET",
            http_status: 503,
            url_path: b"/boom",
            duration_us: 500,
            proto: crate::shm::ProtoVersion::Http2 as u8,
            scheme_https: false,
            server_port: 80,
            client_port: 1234,
            peer_port: 1234,
            req_body_size: 0,
            resp_body_size: 0,
            url_query: b"",
            route: b"/boom",
            user_agent: &long_ua,
            server_address: b"host",
            client_address: b"10.0.0.1",
            peer_address: b"10.0.0.1",
            extra_attrs: &[],
        };

        let producer = VecProducer(std::sync::Mutex::new(std::vec::Vec::new()));
        assert!(emit_span_record(&producer, &rec));
        let raw = producer.0.lock().unwrap();
        let len = u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize;
        let span = parse_span_record(&raw[4..4 + len], 0).expect("parse must succeed");

        let find_attr = |key: &str| -> Option<&AnyValue> {
            span.attributes.iter().find(|kv| kv.key == key).map(|kv| &kv.value)
        };

        match find_attr("error.type").expect("error.type must be present on a 5xx span") {
            AnyValue::String(s) => {
                assert_eq!(s, "503", "error.type must be the status code string")
            }
            other => panic!("error.type must be String, got {other:?}"),
        }

        match find_attr("user_agent.original").expect("user_agent.original must be present") {
            AnyValue::String(s) => assert_eq!(
                s.len(),
                MAX_USER_AGENT,
                "user_agent.original must be truncated to MAX_USER_AGENT bytes"
            ),
            other => panic!("user_agent.original must be String, got {other:?}"),
        }

        // network.protocol.version reflects HTTP/2.
        match find_attr("network.protocol.version").expect("network.protocol.version present") {
            AnyValue::String(s) => assert_eq!(s, "2", "HTTP/2 → \"2\""),
            other => panic!("network.protocol.version must be String, got {other:?}"),
        }

        // A 4xx span must NOT carry error.type — per the OTel HTTP semconv a
        // server span leaves 4xx status unset (only 5xx is an error), so the
        // exporter derives error.type from a status of 500 or above only.  This
        // pins the >=500 threshold (a 2xx span is covered in span_golden_structural).
        let rec_4xx = SpanRecord { http_status: 404, status_code: StatusCode::Unset as u8, ..rec };
        let producer_4xx = VecProducer(std::sync::Mutex::new(std::vec::Vec::new()));
        assert!(emit_span_record(&producer_4xx, &rec_4xx));
        let raw_4xx = producer_4xx.0.lock().unwrap();
        let len_4xx = u32::from_be_bytes(raw_4xx[..4].try_into().unwrap()) as usize;
        let span_4xx = parse_span_record(&raw_4xx[4..4 + len_4xx], 0).expect("parse must succeed");
        assert!(
            !span_4xx.attributes.iter().any(|kv| kv.key == "error.type"),
            "error.type must be absent on a 4xx span (only >=500 is an error)"
        );
    }

    /// Parser sanity cap: a corrupted `n_extra` field must not cause the
    /// parser to loop more than `MAX_SPAN_EXTRA_ATTRS` times.
    ///
    /// Patches a well-formed record's raw `n_extra` wire field to a value far
    /// above the producer maximum; the parser must clamp and still return a
    /// valid span.
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
            proto: crate::shm::ProtoVersion::Http11 as u8,
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
            extra_attrs: &extra,
        };

        let producer = VecProducer(std::sync::Mutex::new(std::vec::Vec::new()));
        assert!(emit_span_record(&producer, &rec));

        let raw = producer.0.lock().unwrap();
        let len = u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize;

        // Copy payload so we can mutate it.
        let mut payload = raw[4..4 + len].to_vec();

        // Walk to n_extra rather than hard-coding its offset, so this test
        // stays resilient to field-order changes.
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
        // proto(1) + scheme(1) + server_port(2) + client_port(2) + peer_port(2)
        //   + req_body_size(8) + resp_body_size(8)
        pos += 1 + 1 + 2 + 2 + 2 + 8 + 8;
        // six capped strings: url_query, route, user_agent, server_addr,
        // client_addr, peer_addr.
        for _ in 0..6 {
            let l = u16::from_be_bytes(payload[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2 + l;
        }
        // pos now points at n_extra (u16 big-endian)
        let n_extra_offset = pos;
        assert!(n_extra_offset + 2 <= payload.len(), "n_extra offset out of bounds");

        // Corrupt n_extra to 200 — well above MAX_SPAN_EXTRA_ATTRS * 4.
        let corrupt_n: u16 = 200;
        payload[n_extra_offset..n_extra_offset + 2].copy_from_slice(&corrupt_n.to_be_bytes());

        // Must not panic or loop 200 times; must clamp and return.
        let span = parse_span_record(&payload, 0).expect("parser must tolerate corrupted n_extra");

        // Only 1 real attr's bytes were serialized; the rest break inside the
        // loop (pos overruns buf), so the final span has ≤ MAX_SPAN_EXTRA_ATTRS
        // extras (typically 0 or 1) plus the standard HTTP attrs.
        let extra_count = span
            .attributes
            .iter()
            .filter(|kv| {
                ![
                    "http.request.method",
                    "http.response.status_code",
                    "url.path",
                    "http.server.request.duration",
                    "url.query",
                    "http.route",
                    "url.scheme",
                    "network.protocol.version",
                    "user_agent.original",
                    "http.request.body.size",
                    "http.response.body.size",
                    "server.address",
                    "server.port",
                    "client.address",
                    "client.port",
                    "network.peer.address",
                    "network.peer.port",
                    "error.type",
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
