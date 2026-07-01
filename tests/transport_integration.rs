// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Integration tests for `HyperHttpTransport` against the local OTel collector.
//!
//! # Prerequisites
//!
//! The OTel collector container must be running before executing these tests:
//!
//! ```sh
//! docker compose -f test-harness/docker-compose.yml ps
//! # Should show ngx-otel-test-collector as Up on 127.0.0.1:4318
//! ```
//!
//! # Running
//!
//! These tests are marked `#[ignore]` by default so they do not run in CI
//! without the collector container.  To run them:
//!
//! ```sh
//! NGINX_SOURCE_DIR=.../nginx \
//! NGINX_BUILD_DIR=.../nginx/objs \
//! cargo test --test transport_integration -- --ignored
//! ```
//!
//! # Verification
//!
//! After running, check that the payload arrived:
//!
//! ```sh
//! tail -5 test-harness/logs/metrics.json | grep ngx-otel-step8-test
//! ```

// Pull in NGINX stubs (needed by macOS flat-namespace linker) and the
// spin-loop block_on helper.
mod support;
use support::block_on;

use ngx_http_otel_module::data_model::{
    AggregationTemporality, AnyValue, Batch, HistogramData, HistogramDataPoint, KeyValue, Metric,
    MetricData, Resource, Scope,
};
use ngx_http_otel_module::encoder::{Encoder, OtlpHttpEncoder};
use ngx_http_otel_module::transport::{HyperHttpTransport, Transport};

/// OTLP endpoint for the local test-harness OTel collector.
const COLLECTOR_ENDPOINT: &str = "http://127.0.0.1:4318/v1/metrics";

/// Path to the collector JSONL log file (one JSON object per received batch).
const METRICS_LOG_PATH: &str =
    "/Users/c.vandesande/project-nginx-otel/test-harness/logs/metrics.json";

/// Returns the current time as Unix nanoseconds.
fn now_unix_nano() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Unique service name per test run: a microsecond nonce so the
/// "appended-since-snapshot" check in each test always sees *its own* service
/// name in the newly written log lines, even when tests run in parallel.
fn unique_service_name(test_fn: &str) -> std::string::String {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    std::format!("ngx-otel-step8-{}-{}", test_fn, nonce)
}

/// Construct a minimal OTLP batch with a recognisable service.name attribute.
/// Timestamps use real wall-clock time (10s window ending now) so collector
/// logs show sensible values rather than a hardcoded date.
fn make_test_batch(service_name: &str) -> Batch {
    let end_ns = now_unix_nano();
    let start_ns = end_ns.saturating_sub(10_000_000_000);

    Batch {
        resource: Resource {
            attributes: vec![KeyValue {
                key: "service.name".to_string(),
                value: AnyValue::String(service_name.to_string()),
            }],
        },
        scope: Scope { name: "ngx-otel-step8".to_string(), version: "0.1.0".to_string() },
        metrics: vec![Metric {
            name: "test.http.server.request.duration".to_string(),
            description: "transport integration test metric".to_string(),
            unit: "ms".to_string(),
            data: MetricData::Histogram(HistogramData {
                aggregation_temporality: AggregationTemporality::Delta,
                data_points: vec![HistogramDataPoint {
                    attributes: vec![KeyValue {
                        key: "http.response.status_code".to_string(),
                        value: AnyValue::Int(200),
                    }],
                    start_time_unix_nano: start_ns,
                    time_unix_nano: end_ns,
                    count: 7,
                    sum: 42.0,
                    bucket_counts: vec![1, 2, 3, 1],
                    explicit_bounds: vec![5.0, 10.0, 25.0],
                }],
            }),
        }],
    }
}

/// Happy-path test: send a real OTLP payload to the local collector, assert a
/// 2xx response, and confirm the payload arrived in the collector's JSONL log
/// (`test-harness/logs/metrics.json`). Requires the collector container.
#[test]
#[ignore = "requires the ngx-otel-test-collector container to be up"]
fn send_otlp_to_live_collector() {
    let service_name = unique_service_name("send-otlp");

    let batch = make_test_batch(&service_name);
    let encoder = OtlpHttpEncoder;
    let bytes = encoder.encode(&batch);
    assert!(!bytes.is_empty(), "encoded bytes must be non-empty");

    // Snapshot the log size BEFORE the send: the collector may flush its JSON
    // log synchronously, before the HTTP 200 response, so snapshotting after
    // the round-trip could miss or double-count this request's line.
    let pre_size = std::fs::metadata(METRICS_LOG_PATH).map(|m| m.len()).unwrap_or(0);

    let mut transport =
        HyperHttpTransport::new(COLLECTOR_ENDPOINT, vec![]).expect("endpoint must parse");

    let result = block_on(transport.send(bytes));
    assert!(result.is_ok(), "send must succeed against live collector: {:?}", result.err());

    // Give the collector a moment to flush if it writes asynchronously.
    std::thread::sleep(std::time::Duration::from_millis(300));

    let log_content =
        std::fs::read_to_string(METRICS_LOG_PATH).expect("metrics.json must be readable");

    // Slice to bytes appended since `pre_size`, then convert lossily: a byte
    // offset from Metadata::len() may split a UTF-8 codepoint, and lossy
    // conversion keeps the assertion message readable instead of panicking.
    let log_bytes = log_content.as_bytes();
    let new_bytes = if pre_size as usize <= log_bytes.len() {
        &log_bytes[pre_size as usize..]
    } else {
        log_bytes
    };
    let new_content = String::from_utf8_lossy(new_bytes);

    assert!(
        new_content.contains(&service_name),
        "newly appended metrics.json content must contain '{}'; new lines:\n{}",
        service_name,
        new_content
    );
}

/// Send twice in a row to the same transport to verify the reconnect path.
#[test]
#[ignore = "requires the ngx-otel-test-collector container to be up"]
fn send_twice_reconnects_cleanly() {
    let service_name = unique_service_name("reconnect");
    let batch = make_test_batch(&service_name);
    let encoder = OtlpHttpEncoder;
    let bytes = encoder.encode(&batch);

    let mut transport =
        HyperHttpTransport::new(COLLECTOR_ENDPOINT, vec![]).expect("endpoint must parse");

    let first = block_on(transport.send(bytes.clone()));
    assert!(first.is_ok(), "first send must succeed: {:?}", first.err());

    let second = block_on(transport.send(bytes));
    assert!(second.is_ok(), "second send must succeed: {:?}", second.err());
}

/// Verify that custom headers are accepted without error.
#[test]
#[ignore = "requires the ngx-otel-test-collector container to be up"]
fn send_with_custom_headers() {
    let service_name = unique_service_name("custom-headers");
    let batch = make_test_batch(&service_name);
    let encoder = OtlpHttpEncoder;
    let bytes = encoder.encode(&batch);

    let headers = vec![("x-test-header".to_string(), "step8".to_string())];
    let mut transport =
        HyperHttpTransport::new(COLLECTOR_ENDPOINT, headers).expect("endpoint must parse");

    let result = block_on(transport.send(bytes));
    assert!(result.is_ok(), "send with custom headers must succeed: {:?}", result.err());
}
