// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! OTLP/gRPC status → `DeliveryOutcome` adapter.
//!
//! This module provides two reusable, testable free functions:
//!
//! - `extract_grpc_retry_hint` — reads both `RetryInfo` detail **and** the
//!   `grpc-retry-pushback-ms` trailer from a `tonic::Status`, returning the
//!   strongest hint available as a `Duration`.
//!
//! - `grpc_code_to_outcome` — maps a `tonic::Code` + an optional retry hint
//!   to a [`DeliveryOutcome`].
//!
//! They are kept separate so that a future OTAP adapter can reuse
//! `grpc_code_to_outcome` with its own hint-extraction path (OTAP may surface
//! the pushback hint differently from OTLP/gRPC).
//!
//! # gRPC code space
//!
//! Both OTLP/gRPC and OTAP's `BatchStatus.StatusCode` use the **same** gRPC
//! code space (`arrow_service.proto:132`: *"Values match the gRPC code space"*),
//! so `grpc_code_to_outcome` is the shared core for both transports.
//!
//! # Retryable set (spec-mandated)
//!
//! `CANCELLED`, `DEADLINE_EXCEEDED`, `ABORTED`, `OUT_OF_RANGE`, `UNAVAILABLE`,
//! `DATA_LOSS` → unconditionally `Retryable`.
//!
//! `RESOURCE_EXHAUSTED` → `Retryable` **only** when a recoverability hint is
//! present (either a `RetryInfo` detail or `grpc-retry-pushback-ms` trailer);
//! with no hint → `Permanent`.
//!
//! # Hint extraction priority
//!
//! Both `RetryInfo.retry_delay` and `grpc-retry-pushback-ms` are read.  When
//! both are present, **`grpc-retry-pushback-ms` wins** (it is the live
//! backpressure mechanism used by the OTAP receiver in
//! `otel-arrow crates/otap/src/memory_pressure_layer.rs:31-42`, and it conveys
//! a more recent, wire-level signal than the proto detail).  `RetryInfo` is
//! used when `grpc-retry-pushback-ms` is absent.

use core::time::Duration;

use crate::transport::DeliveryOutcome;

// ── Minimal google.rpc proto decode types ────────────────────────────────────
//
// These are the minimum structures needed to decode `google.rpc.RetryInfo`
// from the binary payload in `tonic::Status::details()`.
//
// The `status.details()` bytes are the raw encoding of a `google.rpc.Status`
// proto (field 3 = `repeated google.protobuf.Any details`; each `Any` has
// field 1 = `type_url: string` and field 2 = `value: bytes`).
//
// We hand-write these with `#[derive(prost::Message)]` rather than adding a
// full `googleapis` proto dependency: the structs below are structurally
// identical to the generated forms, and the `prost_types` crate (already a
// transitive dep) provides `prost_types::Duration` for the `retry_delay` field.

// Field-number source pins:
//   google.rpc.Status:    https://github.com/googleapis/googleapis/blob/master/google/rpc/status.proto
//     field 1  code    int32
//     field 2  message string
//     field 3  details repeated google.protobuf.Any   ← the only field we decode
//   google.protobuf.Any:  https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/any.proto
//     field 1  type_url string
//     field 2  value    bytes
//   google.rpc.RetryInfo: https://github.com/googleapis/googleapis/blob/master/google/rpc/error_details.proto
//     field 1  retry_delay google.protobuf.Duration
//   google.protobuf.Duration: https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/duration.proto
//     field 1  seconds int64
//     field 2  nanos   int32

/// Minimal decode of `google.protobuf.Any` (field layout is canonical protobuf).
///
/// Used to iterate the `details` array inside `google.rpc.Status`.
#[derive(Clone, ::prost::Message)]
struct ProtoAny {
    /// `string type_url = 1;` — fully-qualified type URL, e.g.
    /// `type.googleapis.com/google.rpc.RetryInfo`.
    /// Field number pinned to `google.protobuf.Any.type_url = 1` per
    /// <https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/any.proto>.
    #[prost(string, tag = "1")]
    type_url: ::prost::alloc::string::String,
    /// `bytes value = 2;` — protobuf encoding of the wrapped message.
    /// Field number pinned to `google.protobuf.Any.value = 2` per the same source.
    #[prost(bytes = "vec", tag = "2")]
    value: ::prost::alloc::vec::Vec<u8>,
}

/// Minimal decode of `google.rpc.Status`.
///
/// We only need field 3 (`details`); fields 1 (`code: int32`) and 2
/// (`message: string`) are intentionally omitted — proto3 unknown fields are
/// silently skipped on decode, so omitting them is safe.
#[derive(Clone, ::prost::Message)]
struct RpcStatus {
    /// `repeated google.protobuf.Any details = 3;`
    /// Field number pinned to `google.rpc.Status.details = 3` per
    /// <https://github.com/googleapis/googleapis/blob/master/google/rpc/status.proto>.
    #[prost(message, repeated, tag = "3")]
    details: ::prost::alloc::vec::Vec<ProtoAny>,
}

/// Minimal decode of `google.rpc.RetryInfo`.
///
/// Layout matches the canonical proto definition:
/// ```proto
/// message RetryInfo { google.protobuf.Duration retry_delay = 1; }
/// ```
/// where `google.protobuf.Duration` = `prost_types::Duration`.
#[derive(Clone, ::prost::Message)]
struct RetryInfo {
    /// `google.protobuf.Duration retry_delay = 1;`
    /// Field number pinned to `google.rpc.RetryInfo.retry_delay = 1` per
    /// <https://github.com/googleapis/googleapis/blob/master/google/rpc/error_details.proto>.
    #[prost(message, optional, tag = "1")]
    retry_delay: ::core::option::Option<::prost_types::Duration>,
}

// ── Type-URL suffix for RetryInfo ─────────────────────────────────────────────

/// The canonical suffix (after the last `/`) of a `google.rpc.RetryInfo`
/// type URL.  We match the suffix so both
/// `type.googleapis.com/google.rpc.RetryInfo` and a bare
/// `google.rpc.RetryInfo` are accepted (different senders may omit the scheme
/// prefix).
const RETRY_INFO_TYPE_SUFFIX: &str = "google.rpc.RetryInfo";

// ── Hint extraction ───────────────────────────────────────────────────────────

/// Extract a retry-after hint from a `tonic::Status`, reading both sources:
///
/// 1. **`grpc-retry-pushback-ms`** trailer (ASCII metadata key): a decimal
///    millisecond count, e.g. `"500"`.  This is the live backpressure mechanism
///    used by the OTAP receiver (`otel-arrow/crates/otap/memory_pressure_layer.rs`).
///
/// 2. **`RetryInfo.retry_delay`** detail: a `google.rpc.RetryInfo` embedded as
///    a `google.protobuf.Any` inside `status.details()` (`google.rpc.Status`
///    encoding).
///
/// **Priority:** when both are present, `grpc-retry-pushback-ms` wins (it is
/// the more recent, wire-level signal).  When only one is present, that one is
/// used.  Returns `None` when neither is found or parseable.
///
/// Negative or zero pushback values are treated as `None` (no useful hint).
pub(crate) fn extract_grpc_retry_hint(status: &tonic::Status) -> Option<Duration> {
    // ── Source 1: grpc-retry-pushback-ms ─────────────────────────────────
    let pushback = status
        .metadata()
        .get("grpc-retry-pushback-ms")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<i64>().ok())
        .and_then(|ms| {
            if ms > 0 {
                Some(Duration::from_millis(ms as u64))
            } else {
                None // zero/negative = no actionable hint
            }
        });

    if pushback.is_some() {
        return pushback;
    }

    // ── Source 2: RetryInfo detail (google.rpc.Status.details) ───────────
    //
    // status.details() = raw bytes of a google.rpc.Status proto.
    // We decode only field 3 (repeated Any) via RpcStatus.
    extract_retry_info_from_details(status.details())
}

/// Decode a `RetryInfo.retry_delay` from the raw `google.rpc.Status` bytes
/// stored in `tonic::Status::details()`.
///
/// Returns `None` when:
/// - the bytes are empty or malformed (proto decode fails → best-effort),
/// - no `RetryInfo` detail is present,
/// - `retry_delay` is absent or zero,
/// - seconds + nanos are both non-positive (invalid hint).
fn extract_retry_info_from_details(raw: &[u8]) -> Option<Duration> {
    if raw.is_empty() {
        return None;
    }

    use prost::Message as _;

    let rpc_status = RpcStatus::decode(raw).ok()?;

    for any in &rpc_status.details {
        // Match by suffix: both "type.googleapis.com/google.rpc.RetryInfo"
        // and a bare "google.rpc.RetryInfo" are valid type URLs in practice.
        if !any.type_url.ends_with(RETRY_INFO_TYPE_SUFFIX) {
            continue;
        }
        let retry_info = RetryInfo::decode(any.value.as_slice()).ok()?;
        if let Some(d) = retry_info.retry_delay {
            return proto_duration_to_std(d);
        }
    }

    None
}

/// Convert a `prost_types::Duration` to `std::time::Duration`.
///
/// Returns `None` when the proto duration is non-positive (negative or zero
/// delay is not a useful backoff hint) or out of range for `Duration`.
fn proto_duration_to_std(d: prost_types::Duration) -> Option<Duration> {
    // Combine seconds and nanos into a single signed nanosecond total before
    // judging the sign. Per the google.protobuf.Duration contract, for a
    // duration of one second or more a non-zero `nanos` MUST carry the same
    // sign as `seconds` (e.g. 1.5s = {seconds: 1, nanos: 500_000_000} and
    // -1.5s = {seconds: -1, nanos: -500_000_000}); a non-normalized value such
    // as {seconds: 1, nanos: -900_000_000} still denotes 0.1s. Clamping nanos
    // to >= 0 (the previous behaviour) would read that as 1.0s — a ~10x
    // over-estimate of the retry hint. Summing the signed parts handles both
    // normalized and non-normalized encodings correctly.
    // <https://protobuf.dev/reference/protobuf/google.protobuf/#duration>
    let total_nanos = (d.seconds as i128) * 1_000_000_000 + (d.nanos as i128);

    if total_nanos <= 0 {
        return None; // non-positive → no useful hint
    }

    let secs = (total_nanos / 1_000_000_000) as u64;
    let nanos = (total_nanos % 1_000_000_000) as u32;
    Some(Duration::new(secs, nanos))
}

// ── Pure gRPC code classifier ─────────────────────────────────────────────────

/// Map a `tonic::Code` + an optional retry hint to a [`DeliveryOutcome`].
///
/// This function encodes the OTLP/gRPC retry classification mandated by the
/// OTLP specification's failure-handling rules
/// (<https://opentelemetry.io/docs/specs/otlp/#failures>):
///
/// - `OK` → `Accepted` (the caller handles `partial_success`; this function is
///   only called on error paths — see `grpc_status_to_outcome` for the full
///   flow).
///
/// - Retryable set (unconditional): `CANCELLED`, `DEADLINE_EXCEEDED`,
///   `ABORTED`, `OUT_OF_RANGE`, `UNAVAILABLE`, `DATA_LOSS` →
///   `Retryable { retry_after: hint }`.
///
/// - `RESOURCE_EXHAUSTED` → `Retryable { retry_after: hint }` **only** when
///   `hint.is_some()`; with no hint → `Permanent` (spec: retryable only when
///   the server signals recoverability).
///
/// - `INVALID_ARGUMENT`, `INTERNAL`, `UNIMPLEMENTED` → `Permanent`.
///
/// - `UNAUTHENTICATED`, `PERMISSION_DENIED` → `Unauthorized` (non-retryable;
///   same drop action as `Permanent`, distinct counter + "check credentials"
///   log).
///
/// - All other codes (unknown, failed_precondition, not_found, etc.) →
///   `Permanent` (conservative: unknown codes are not retried).
///
/// # Reusability for OTAP
///
/// OTAP's `BatchStatus.StatusCode` uses the **same gRPC code space**
/// (`arrow_service.proto:132`).  A future OTAP adapter can call this function
/// with the mapped `tonic::Code` and its own hint (e.g. from a different
/// source), so no changes to this function are needed for OTAP.
///
/// The hint is intentionally a parameter (not derived internally here) so that
/// callers with different hint sources (e.g., OTAP's in-proto pushback field)
/// can pass their own `Option<Duration>` without duplicating the code
/// classification logic.
pub(crate) fn grpc_code_to_outcome(code: tonic::Code, hint: Option<Duration>) -> DeliveryOutcome {
    match code {
        // ── Accepted ──────────────────────────────────────────────────────
        // OK with no error path reaches here only in edge cases; the caller
        // normally handles OK separately to decode partial_success.
        tonic::Code::Ok => DeliveryOutcome::Accepted,

        // ── Retryable (unconditional) ─────────────────────────────────────
        tonic::Code::Cancelled
        | tonic::Code::DeadlineExceeded
        | tonic::Code::Aborted
        | tonic::Code::OutOfRange
        | tonic::Code::Unavailable
        | tonic::Code::DataLoss => DeliveryOutcome::Retryable { retry_after: hint },

        // ── RESOURCE_EXHAUSTED: retryable ONLY with a recoverability hint ─
        //
        // Spec: "RESOURCE_EXHAUSTED … only if the server signals retryability
        // via a `RetryInfo` detail or `grpc-retry-pushback-ms` header."
        // Without a hint the peer has given no signal that it will recover,
        // so we treat it as permanent to avoid hammering an overloaded endpoint.
        tonic::Code::ResourceExhausted => {
            if hint.is_some() {
                DeliveryOutcome::Retryable { retry_after: hint }
            } else {
                DeliveryOutcome::Permanent
            }
        }

        // ── Permanent (explicit) ──────────────────────────────────────────
        tonic::Code::InvalidArgument | tonic::Code::Internal | tonic::Code::Unimplemented => {
            DeliveryOutcome::Permanent
        }

        // ── Unauthorized ─────────────────────────────────────────────────
        //
        // Auth failures are NOT retried — the credential/config problem must
        // be fixed by an operator.  Distinct from `Permanent` only for its own
        // counter + a "check exporter credentials" log message.
        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => {
            DeliveryOutcome::Unauthorized
        }

        // ── All other codes → Permanent (conservative) ────────────────────
        //
        // Covers: Unknown, NotFound, AlreadyExists, FailedPrecondition,
        // OutOfRange (already above), and any future codes.  These are not
        // in the OTLP retryable spec set, so we do not retry them.
        _ => DeliveryOutcome::Permanent,
    }
}

// ── Top-level entry point ─────────────────────────────────────────────────────

/// Derive a [`DeliveryOutcome`] from a complete `tonic::Status` error.
///
/// This is the top-level adapter entry point called by the three `send*`
/// methods in `transport.rs` when the RPC returns an `Err(status)`.
///
/// It combines:
/// 1. Extract the retry hint (both `RetryInfo` detail + `grpc-retry-pushback-ms`).
/// 2. Call [`grpc_code_to_outcome`] with the extracted hint.
///
/// `pub(crate)` so unit tests in this module and `transport.rs` can exercise
/// the mapping table directly without a live gRPC server.
pub(crate) fn grpc_status_to_outcome(status: &tonic::Status) -> DeliveryOutcome {
    let hint = extract_grpc_retry_hint(status);
    grpc_code_to_outcome(status.code(), hint)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::{
        extract_grpc_retry_hint, extract_retry_info_from_details, grpc_code_to_outcome,
        grpc_status_to_outcome, proto_duration_to_std, ProtoAny, RetryInfo, RpcStatus,
    };
    use crate::transport::DeliveryOutcome;

    // ── proto_duration_to_std ─────────────────────────────────────────────

    #[test]
    fn s3_proto_duration_zero_returns_none() {
        assert_eq!(proto_duration_to_std(prost_types::Duration { seconds: 0, nanos: 0 }), None);
    }

    #[test]
    fn s3_proto_duration_negative_returns_none() {
        assert_eq!(proto_duration_to_std(prost_types::Duration { seconds: -1, nanos: 0 }), None);
    }

    #[test]
    fn s3_proto_duration_positive_seconds() {
        assert_eq!(
            proto_duration_to_std(prost_types::Duration { seconds: 5, nanos: 0 }),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn s3_proto_duration_subsecond_nanos() {
        assert_eq!(
            proto_duration_to_std(prost_types::Duration { seconds: 0, nanos: 500_000_000 }),
            Some(Duration::from_millis(500))
        );
    }

    // Non-normalized encoding where `nanos` carries the opposite sign to bring
    // a whole-second value back below a second. {seconds: 1, nanos: -900ms} is
    // 0.1s, NOT 1.0s. The previous nanos.clamp(0, ..) read this as 1.0s — a
    // ~10x over-estimate of the retry hint.
    #[test]
    fn s3_proto_duration_negative_nanos_below_one_second() {
        assert_eq!(
            proto_duration_to_std(prost_types::Duration { seconds: 1, nanos: -900_000_000 }),
            Some(Duration::from_millis(100))
        );
    }

    // 1.5s expressed as {seconds: 1, nanos: 500ms} round-trips exactly.
    #[test]
    fn s3_proto_duration_normalized_fractional_seconds() {
        assert_eq!(
            proto_duration_to_std(prost_types::Duration { seconds: 1, nanos: 500_000_000 }),
            Some(Duration::from_millis(1500))
        );
    }

    // A genuinely negative sub-second duration ({seconds: 0, nanos: -100ms})
    // remains "no useful hint".
    #[test]
    fn s3_proto_duration_negative_subsecond_returns_none() {
        assert_eq!(
            proto_duration_to_std(prost_types::Duration { seconds: 0, nanos: -100_000_000 }),
            None
        );
    }

    // ── grpc_code_to_outcome — basic per-class coverage ───────────────────

    #[test]
    fn s3_ok_code_yields_accepted() {
        assert_eq!(grpc_code_to_outcome(tonic::Code::Ok, None), DeliveryOutcome::Accepted);
    }

    #[test]
    fn s3_retryable_codes_no_hint() {
        for code in [
            tonic::Code::Cancelled,
            tonic::Code::DeadlineExceeded,
            tonic::Code::Aborted,
            tonic::Code::OutOfRange,
            tonic::Code::Unavailable,
            tonic::Code::DataLoss,
        ] {
            assert_eq!(
                grpc_code_to_outcome(code, None),
                DeliveryOutcome::Retryable { retry_after: None },
                "{code:?} with no hint must be Retryable{{None}}"
            );
        }
    }

    #[test]
    fn s3_retryable_codes_with_hint() {
        let hint = Some(Duration::from_secs(2));
        for code in [
            tonic::Code::Cancelled,
            tonic::Code::DeadlineExceeded,
            tonic::Code::Aborted,
            tonic::Code::OutOfRange,
            tonic::Code::Unavailable,
            tonic::Code::DataLoss,
        ] {
            assert_eq!(
                grpc_code_to_outcome(code, hint),
                DeliveryOutcome::Retryable { retry_after: hint },
                "{code:?} with hint must be Retryable{{hint}}"
            );
        }
    }

    #[test]
    fn s3_resource_exhausted_with_hint_retryable() {
        let hint = Some(Duration::from_millis(500));
        assert_eq!(
            grpc_code_to_outcome(tonic::Code::ResourceExhausted, hint),
            DeliveryOutcome::Retryable { retry_after: hint },
            "RESOURCE_EXHAUSTED with hint must be Retryable"
        );
    }

    #[test]
    fn s3_resource_exhausted_no_hint_permanent() {
        assert_eq!(
            grpc_code_to_outcome(tonic::Code::ResourceExhausted, None),
            DeliveryOutcome::Permanent,
            "RESOURCE_EXHAUSTED without hint must be Permanent"
        );
    }

    #[test]
    fn s3_permanent_codes() {
        for code in
            [tonic::Code::InvalidArgument, tonic::Code::Internal, tonic::Code::Unimplemented]
        {
            assert_eq!(
                grpc_code_to_outcome(code, None),
                DeliveryOutcome::Permanent,
                "{code:?} must be Permanent"
            );
        }
    }

    #[test]
    fn s3_unauthorized_codes() {
        for code in [tonic::Code::Unauthenticated, tonic::Code::PermissionDenied] {
            assert_eq!(
                grpc_code_to_outcome(code, None),
                DeliveryOutcome::Unauthorized,
                "{code:?} must be Unauthorized"
            );
        }
    }

    /// Pins the exact retryable set (unconditional + RESOURCE_EXHAUSTED-with-hint).
    /// Mirrors s2_retryable_set_exact from hyper_http.rs.
    #[test]
    fn s3_retryable_set_exact() {
        let hint = Some(Duration::from_secs(1));

        // Unconditionally retryable (even without a hint).
        for code in [
            tonic::Code::Cancelled,
            tonic::Code::DeadlineExceeded,
            tonic::Code::Aborted,
            tonic::Code::OutOfRange,
            tonic::Code::Unavailable,
            tonic::Code::DataLoss,
        ] {
            let outcome = grpc_code_to_outcome(code, None);
            assert!(
                matches!(outcome, DeliveryOutcome::Retryable { .. }),
                "{code:?} must be in the unconditional retryable set"
            );
        }

        // RESOURCE_EXHAUSTED: retryable only WITH hint.
        assert!(
            matches!(
                grpc_code_to_outcome(tonic::Code::ResourceExhausted, hint),
                DeliveryOutcome::Retryable { .. }
            ),
            "RESOURCE_EXHAUSTED + hint must be Retryable"
        );
        assert_eq!(
            grpc_code_to_outcome(tonic::Code::ResourceExhausted, None),
            DeliveryOutcome::Permanent,
            "RESOURCE_EXHAUSTED + no hint must NOT be Retryable"
        );

        // None of these must be Retryable (without hint).
        for code in [
            tonic::Code::InvalidArgument,
            tonic::Code::Internal,
            tonic::Code::Unimplemented,
            tonic::Code::Unauthenticated,
            tonic::Code::PermissionDenied,
            tonic::Code::ResourceExhausted, // re-checked: no hint → Permanent
        ] {
            let outcome = grpc_code_to_outcome(code, None);
            assert!(
                !matches!(outcome, DeliveryOutcome::Retryable { .. }),
                "{code:?} (no hint) must NOT be in the retryable set"
            );
        }
    }

    // ── extract_grpc_retry_hint: grpc-retry-pushback-ms ──────────────────

    #[test]
    fn s3_pushback_ms_is_parsed() {
        let mut meta = tonic::metadata::MetadataMap::new();
        meta.insert("grpc-retry-pushback-ms", "750".parse().unwrap());
        let status = tonic::Status::with_metadata(tonic::Code::Unavailable, "overloaded", meta);
        let hint = extract_grpc_retry_hint(&status);
        assert_eq!(hint, Some(Duration::from_millis(750)));
    }

    #[test]
    fn s3_pushback_ms_zero_returns_none() {
        let mut meta = tonic::metadata::MetadataMap::new();
        meta.insert("grpc-retry-pushback-ms", "0".parse().unwrap());
        let status = tonic::Status::with_metadata(tonic::Code::Unavailable, "overloaded", meta);
        let hint = extract_grpc_retry_hint(&status);
        assert_eq!(hint, None);
    }

    #[test]
    fn s3_pushback_ms_negative_returns_none() {
        let mut meta = tonic::metadata::MetadataMap::new();
        meta.insert("grpc-retry-pushback-ms", "-1".parse().unwrap());
        let status = tonic::Status::with_metadata(tonic::Code::Unavailable, "overloaded", meta);
        let hint = extract_grpc_retry_hint(&status);
        assert_eq!(hint, None);
    }

    #[test]
    fn s3_no_hint_returns_none() {
        let status = tonic::Status::new(tonic::Code::Unavailable, "no hint");
        assert_eq!(extract_grpc_retry_hint(&status), None);
    }

    // ── extract_retry_info_from_details ──────────────────────────────────

    /// Build a well-formed `google.rpc.Status` bytes blob with a `RetryInfo`
    /// detail and verify the Duration is decoded correctly.
    #[test]
    fn s3_retry_info_detail_is_parsed() {
        use prost::Message as _;

        // Build a RetryInfo with retry_delay = 3s.
        let ri = RetryInfo { retry_delay: Some(prost_types::Duration { seconds: 3, nanos: 0 }) };
        let ri_bytes = ri.encode_to_vec();

        // Wrap it in a ProtoAny.
        let any = ProtoAny {
            type_url: std::string::String::from("type.googleapis.com/google.rpc.RetryInfo"),
            value: ri_bytes,
        };

        // Wrap that in an RpcStatus (field 3 = repeated Any).
        let rpc_status = RpcStatus { details: std::vec![any] };
        let status_bytes = rpc_status.encode_to_vec();

        let result = extract_retry_info_from_details(&status_bytes);
        assert_eq!(result, Some(Duration::from_secs(3)));
    }

    /// `RetryInfo` with `type_url` using bare suffix (no `type.googleapis.com/`
    /// prefix) must also be accepted.
    #[test]
    fn s3_retry_info_bare_type_url_accepted() {
        use prost::Message as _;

        let ri = RetryInfo { retry_delay: Some(prost_types::Duration { seconds: 1, nanos: 0 }) };
        let any = ProtoAny {
            type_url: std::string::String::from("google.rpc.RetryInfo"),
            value: ri.encode_to_vec(),
        };
        let rpc_status = RpcStatus { details: std::vec![any] };
        let status_bytes = rpc_status.encode_to_vec();

        assert_eq!(extract_retry_info_from_details(&status_bytes), Some(Duration::from_secs(1)));
    }

    #[test]
    fn s3_retry_info_empty_details_returns_none() {
        assert_eq!(extract_retry_info_from_details(&[]), None);
    }

    #[test]
    fn s3_retry_info_garbage_bytes_returns_none() {
        // A `google.rpc.Status` blob that fails decode (invalid varint).
        assert_eq!(extract_retry_info_from_details(&[0xFF, 0xFF, 0x00]), None);
    }

    #[test]
    fn s3_retry_info_wrong_type_url_returns_none() {
        use prost::Message as _;

        let ri = RetryInfo { retry_delay: Some(prost_types::Duration { seconds: 5, nanos: 0 }) };
        let any = ProtoAny {
            type_url: std::string::String::from("type.googleapis.com/google.rpc.SomethingElse"),
            value: ri.encode_to_vec(),
        };
        let rpc_status = RpcStatus { details: std::vec![any] };
        assert_eq!(extract_retry_info_from_details(&rpc_status.encode_to_vec()), None);
    }

    // ── Priority: pushback wins over RetryInfo when both present ─────────

    #[test]
    fn s3_pushback_wins_over_retry_info() {
        use prost::Message as _;

        // RetryInfo says 10 s, pushback says 2 s — pushback must win.
        let ri = RetryInfo { retry_delay: Some(prost_types::Duration { seconds: 10, nanos: 0 }) };
        let any = ProtoAny {
            type_url: std::string::String::from("type.googleapis.com/google.rpc.RetryInfo"),
            value: ri.encode_to_vec(),
        };
        let rpc_status = RpcStatus { details: std::vec![any] };
        let details_bytes = rpc_status.encode_to_vec();

        let mut meta = tonic::metadata::MetadataMap::new();
        meta.insert("grpc-retry-pushback-ms", "2000".parse().unwrap());

        let status = tonic::Status::with_details_and_metadata(
            tonic::Code::ResourceExhausted,
            "overloaded",
            bytes::Bytes::from(details_bytes),
            meta,
        );

        let hint = extract_grpc_retry_hint(&status);
        assert_eq!(hint, Some(Duration::from_millis(2000)), "pushback must win");
    }

    // ── Full grpc_status_to_outcome integration ───────────────────────────

    #[test]
    fn s3_unavailable_no_hint_retryable_none() {
        let status = tonic::Status::new(tonic::Code::Unavailable, "down");
        assert_eq!(
            grpc_status_to_outcome(&status),
            DeliveryOutcome::Retryable { retry_after: None }
        );
    }

    #[test]
    fn s3_unavailable_with_pushback_retryable_hint() {
        let mut meta = tonic::metadata::MetadataMap::new();
        meta.insert("grpc-retry-pushback-ms", "1500".parse().unwrap());
        let status = tonic::Status::with_metadata(tonic::Code::Unavailable, "throttled", meta);
        assert_eq!(
            grpc_status_to_outcome(&status),
            DeliveryOutcome::Retryable { retry_after: Some(Duration::from_millis(1500)) }
        );
    }

    #[test]
    fn s3_invalid_argument_permanent() {
        let status = tonic::Status::new(tonic::Code::InvalidArgument, "bad proto");
        assert_eq!(grpc_status_to_outcome(&status), DeliveryOutcome::Permanent);
    }

    #[test]
    fn s3_internal_permanent() {
        let status = tonic::Status::new(tonic::Code::Internal, "internal");
        assert_eq!(grpc_status_to_outcome(&status), DeliveryOutcome::Permanent);
    }

    #[test]
    fn s3_unimplemented_permanent() {
        let status = tonic::Status::new(tonic::Code::Unimplemented, "not supported");
        assert_eq!(grpc_status_to_outcome(&status), DeliveryOutcome::Permanent);
    }

    #[test]
    fn s3_unauthenticated_unauthorized() {
        let status = tonic::Status::new(tonic::Code::Unauthenticated, "bad token");
        assert_eq!(grpc_status_to_outcome(&status), DeliveryOutcome::Unauthorized);
    }

    #[test]
    fn s3_permission_denied_unauthorized() {
        let status = tonic::Status::new(tonic::Code::PermissionDenied, "forbidden");
        assert_eq!(grpc_status_to_outcome(&status), DeliveryOutcome::Unauthorized);
    }

    #[test]
    fn s3_resource_exhausted_with_retry_info_retryable() {
        use prost::Message as _;

        let ri = RetryInfo { retry_delay: Some(prost_types::Duration { seconds: 2, nanos: 0 }) };
        let any = ProtoAny {
            type_url: std::string::String::from("type.googleapis.com/google.rpc.RetryInfo"),
            value: ri.encode_to_vec(),
        };
        let rpc_status = RpcStatus { details: std::vec![any] };
        let details_bytes = rpc_status.encode_to_vec();

        let status = tonic::Status::with_details(
            tonic::Code::ResourceExhausted,
            "rate limited",
            bytes::Bytes::from(details_bytes),
        );
        assert_eq!(
            grpc_status_to_outcome(&status),
            DeliveryOutcome::Retryable { retry_after: Some(Duration::from_secs(2)) }
        );
    }

    #[test]
    fn s3_resource_exhausted_via_outcome_no_hint_permanent() {
        let status = tonic::Status::new(tonic::Code::ResourceExhausted, "rate limited");
        assert_eq!(grpc_status_to_outcome(&status), DeliveryOutcome::Permanent);
    }

    // ── Golden-byte fixture (S6) ──────────────────────────────────────────────
    //
    // This test decodes a **hand-computed, statically-known byte fixture** that
    // represents a real `google.rpc.Status` proto carrying a `RetryInfo` detail.
    // Unlike the symmetric round-trip tests above (which encode via our own
    // structs and then decode — blind to field-number drift), this fixture is
    // computed from first principles against the public proto definitions and
    // does NOT use any of our encode helpers.  If a struct field number is
    // changed, this test fails, catching the drift.
    //
    // Wire layout (all lengths are single-byte varints here):
    //
    //   google.rpc.Status { details[0] = Any { ... } }
    //   ┌─────────────────────────────────────────────────────────┐
    //   │ 0x1a 0x30  → field 3 (details), wire type 2 (LEN), len=48
    //   │   ┌ google.protobuf.Any ─────────────────────────────── ┐
    //   │   │ 0x0a 0x28  → field 1 (type_url), LEN, len=40        │
    //   │   │   "type.googleapis.com/google.rpc.RetryInfo" (40 B)  │
    //   │   │ 0x12 0x04  → field 2 (value), LEN, len=4            │
    //   │   │   ┌ google.rpc.RetryInfo ──────────────────────── ┐  │
    //   │   │   │ 0x0a 0x02  → field 1 (retry_delay), LEN, len=2 │ │
    //   │   │   │   ┌ google.protobuf.Duration ──────────────┐   │  │
    //   │   │   │   │ 0x08 0x05  → field 1 (seconds), VARINT=5 │  │  │
    //   │   │   │   └────────────────────────────────────────┘   │  │
    //   │   │   └───────────────────────────────────────────────┘  │
    //   │   └──────────────────────────────────────────────────────┘
    //   └─────────────────────────────────────────────────────────┘
    //
    // Field numbers sourced from:
    //   google.rpc.Status.details    = 3  (google/rpc/status.proto)
    //   google.protobuf.Any.type_url = 1  (google/protobuf/any.proto)
    //   google.protobuf.Any.value    = 2  (google/protobuf/any.proto)
    //   google.rpc.RetryInfo.retry_delay = 1  (google/rpc/error_details.proto)
    //   google.protobuf.Duration.seconds = 1  (google/protobuf/duration.proto)
    #[test]
    fn s6_golden_byte_retry_info_fixture() {
        // 50-byte static fixture: google.rpc.Status { details[0] = RetryInfo{5s} }
        // Computed from proto wire format — NOT produced by our encode helpers.
        #[rustfmt::skip]
        const GOLDEN: &[u8] = &[
            // google.rpc.Status: field 3 (details), LEN, length=48
            0x1a, 0x30,
            // google.protobuf.Any: field 1 (type_url), LEN, length=40
            0x0a, 0x28,
            // "type.googleapis.com/google.rpc.RetryInfo" (40 bytes)
            0x74, 0x79, 0x70, 0x65, 0x2e, 0x67, 0x6f, 0x6f,
            0x67, 0x6c, 0x65, 0x61, 0x70, 0x69, 0x73, 0x2e,
            0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x6f, 0x6f, 0x67,
            0x6c, 0x65, 0x2e, 0x72, 0x70, 0x63, 0x2e, 0x52,
            0x65, 0x74, 0x72, 0x79, 0x49, 0x6e, 0x66, 0x6f,
            // google.protobuf.Any: field 2 (value), LEN, length=4
            0x12, 0x04,
            // google.rpc.RetryInfo: field 1 (retry_delay), LEN, length=2
            0x0a, 0x02,
            // google.protobuf.Duration: field 1 (seconds), VARINT, value=5
            0x08, 0x05,
        ];

        // Sanity: the type_url string embedded in the fixture is correct.
        assert_eq!(
            core::str::from_utf8(&GOLDEN[4..44]).unwrap(),
            "type.googleapis.com/google.rpc.RetryInfo",
            "fixture type_url bytes must spell out the canonical RetryInfo type URL"
        );

        // Decode through our production path and assert the expected retry delay.
        let result = extract_retry_info_from_details(GOLDEN);
        assert_eq!(
            result,
            Some(Duration::from_secs(5)),
            "golden-byte fixture must decode to a 5-second retry delay"
        );
    }
}
