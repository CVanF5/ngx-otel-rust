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

// ──────────────────────────────────────────────────────────────────────────────
// Test constants
// ──────────────────────────────────────────────────────────────────────────────

/// OTLP endpoint for the local test-harness OTel collector.
const COLLECTOR_ENDPOINT: &str = "http://127.0.0.1:4318/v1/metrics";

/// Service name embedded in the test payload so we can grep for it in
/// `test-harness/logs/metrics.json` after the send.
const TEST_SERVICE_NAME: &str = "ngx-otel-step8-test";

/// Path to the collector JSONL log file (one JSON object per received batch).
const METRICS_LOG_PATH: &str =
    "/Users/c.vandesande/project-nginx-otel/test-harness/logs/metrics.json";

// ──────────────────────────────────────────────────────────────────────────────
// Test helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Construct a minimal OTLP batch with a recognisable service.name attribute.
fn make_test_batch() -> Batch {
    Batch {
        resource: Resource {
            attributes: vec![KeyValue {
                key: "service.name".to_string(),
                value: AnyValue::String(TEST_SERVICE_NAME.to_string()),
            }],
        },
        scope: Scope {
            name: "ngx-otel-step8".to_string(),
            version: "0.1.0".to_string(),
        },
        metrics: vec![Metric {
            name: "test.http.server.request.duration".to_string(),
            description: "Step 8 integration test metric".to_string(),
            unit: "ms".to_string(),
            data: MetricData::Histogram(HistogramData {
                aggregation_temporality: AggregationTemporality::Delta,
                data_points: vec![HistogramDataPoint {
                    attributes: vec![KeyValue {
                        key: "http.response.status_code".to_string(),
                        value: AnyValue::Int(200),
                    }],
                    start_time_unix_nano: 1_700_000_000_000_000_000,
                    time_unix_nano: 1_700_000_010_000_000_000,
                    count: 7,
                    sum: 42.0,
                    bucket_counts: vec![1, 2, 3, 1],
                    explicit_bounds: vec![5.0, 10.0, 25.0],
                }],
            }),
        }],
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Integration tests
// ──────────────────────────────────────────────────────────────────────────────

/// Happy-path test: send a real OTLP payload to the local collector.
///
/// Asserts a 2xx response AND checks that the payload arrived in the
/// collector's JSONL log (`test-harness/logs/metrics.json`).
///
/// Requires the collector container to be running.
#[test]
#[ignore = "requires the ngx-otel-test-collector container to be up"]
fn send_otlp_to_live_collector() {
    // ── Encode a batch ────────────────────────────────────────────────────
    let batch = make_test_batch();
    let encoder = OtlpHttpEncoder;
    let bytes = encoder.encode(&batch);
    assert!(!bytes.is_empty(), "encoded bytes must be non-empty");

    // ── Send via HyperHttpTransport ───────────────────────────────────────
    let mut transport = HyperHttpTransport::new(COLLECTOR_ENDPOINT, vec![])
        .expect("endpoint must parse");

    let result = block_on(transport.send(bytes));
    assert!(
        result.is_ok(),
        "send must succeed against live collector: {:?}",
        result.err()
    );

    // ── Verify the payload arrived in the collector log ───────────────────
    // The collector writes one JSON line per received export request.
    // Give the collector a moment to flush its JSON file log.
    std::thread::sleep(std::time::Duration::from_millis(300));

    let log_content = std::fs::read_to_string(METRICS_LOG_PATH)
        .expect("metrics.json must be readable");

    assert!(
        log_content.contains(TEST_SERVICE_NAME),
        "metrics.json must contain the test service name '{}'; last 3 lines:\n{}",
        TEST_SERVICE_NAME,
        log_content
            .lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Send twice in a row to the same transport to verify the reconnect path.
#[test]
#[ignore = "requires the ngx-otel-test-collector container to be up"]
fn send_twice_reconnects_cleanly() {
    let batch = make_test_batch();
    let encoder = OtlpHttpEncoder;
    let bytes = encoder.encode(&batch);

    let mut transport = HyperHttpTransport::new(COLLECTOR_ENDPOINT, vec![])
        .expect("endpoint must parse");

    let first = block_on(transport.send(bytes.clone()));
    assert!(first.is_ok(), "first send must succeed: {:?}", first.err());

    let second = block_on(transport.send(bytes));
    assert!(second.is_ok(), "second send must succeed: {:?}", second.err());
}

/// Verify that custom headers are accepted without error.
#[test]
#[ignore = "requires the ngx-otel-test-collector container to be up"]
fn send_with_custom_headers() {
    let batch = make_test_batch();
    let encoder = OtlpHttpEncoder;
    let bytes = encoder.encode(&batch);

    let headers = vec![("x-test-header".to_string(), "step8".to_string())];
    let mut transport =
        HyperHttpTransport::new(COLLECTOR_ENDPOINT, headers).expect("endpoint must parse");

    let result = block_on(transport.send(bytes));
    assert!(
        result.is_ok(),
        "send with custom headers must succeed: {:?}",
        result.err()
    );
}
