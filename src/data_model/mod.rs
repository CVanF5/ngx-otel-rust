// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Internal OTel-abstract data model.
//!
//! These types are **independent** of the OTLP protobuf schema.  The encoder
//! layer (Step 7) converts from these types into the OTLP proto types.
//!
//! Rule: do NOT `use opentelemetry_proto::*` anywhere in this module.

// ────────────────────────────────────────────────────────────────
// Primitive value types
// ────────────────────────────────────────────────────────────────

/// A key-value attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyValue {
    pub key: std::string::String,
    pub value: AnyValue,
}

/// Any OTel attribute value.
#[derive(Debug, Clone, PartialEq)]
pub enum AnyValue {
    String(std::string::String),
    Bool(bool),
    Int(i64),
    Double(f64),
    Bytes(std::vec::Vec<u8>),
    Array(std::vec::Vec<AnyValue>),
}

// ────────────────────────────────────────────────────────────────
// Resource & Scope
// ────────────────────────────────────────────────────────────────

/// OTel resource: set of attributes describing the entity producing telemetry.
#[derive(Debug, Clone, Default)]
pub struct Resource {
    pub attributes: std::vec::Vec<KeyValue>,
}

/// OTel instrumentation scope.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub name: std::string::String,
    pub version: std::string::String,
}

// ────────────────────────────────────────────────────────────────
// Metric types
// ────────────────────────────────────────────────────────────────

/// A single metric instrument.
#[derive(Debug, Clone)]
pub struct Metric {
    pub name: std::string::String,
    pub description: std::string::String,
    pub unit: std::string::String,
    pub data: MetricData,
}

/// The data payload of a metric — only histograms in Phase 1.1.
#[derive(Debug, Clone)]
pub enum MetricData {
    Histogram(HistogramData),
}

/// A histogram metric aggregation.
#[derive(Debug, Clone)]
pub struct HistogramData {
    pub aggregation_temporality: AggregationTemporality,
    pub data_points: std::vec::Vec<HistogramDataPoint>,
}

/// Aggregation temporality (DELTA or CUMULATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationTemporality {
    Unspecified = 0,
    Delta = 1,
    Cumulative = 2,
}

/// One data point in a histogram.
#[derive(Debug, Clone)]
pub struct HistogramDataPoint {
    /// Attributes for this data point (e.g. `http.response.status_code`).
    pub attributes: std::vec::Vec<KeyValue>,
    /// Start of the measurement window (Unix epoch, nanoseconds).
    pub start_time_unix_nano: u64,
    /// End of the measurement window (Unix epoch, nanoseconds).
    pub time_unix_nano: u64,
    /// Number of observations.
    pub count: u64,
    /// Sum of all observed values.
    pub sum: f64,
    /// Per-bucket cumulative counts (`bucket_counts[i]` = observations ≤ `explicit_bounds[i-1]`).
    pub bucket_counts: std::vec::Vec<u64>,
    /// Sorted bucket boundaries (length = `bucket_counts.len() - 1`).
    pub explicit_bounds: std::vec::Vec<f64>,
}

// ────────────────────────────────────────────────────────────────
// Batch — top-level export unit
// ────────────────────────────────────────────────────────────────

/// A batch of metrics ready for export.
///
/// Wraps a `Resource`, a `Scope`, and a list of `Metric`s — one per
/// metric instrument.
#[derive(Debug, Clone)]
pub struct Batch {
    pub resource: Resource,
    pub scope: Scope,
    pub metrics: std::vec::Vec<Metric>,
}

// ────────────────────────────────────────────────────────────────
// Unit tests
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct a Batch with one histogram metric, one resource attribute,
    /// and 8 explicit buckets; inspect the shape manually.
    #[test]
    fn batch_construction() {
        let resource = Resource {
            attributes: std::vec![KeyValue {
                key: "service.name".into(),
                value: AnyValue::String("my-nginx".into()),
            }],
        };

        let scope = Scope { name: "ngx-otel-rust".into(), version: "0.1.0".into() };

        let bounds = std::vec![5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0];
        let n_bounds = bounds.len();

        let point = HistogramDataPoint {
            attributes: std::vec![KeyValue {
                key: "http.response.status_code".into(),
                value: AnyValue::Int(200),
            }],
            start_time_unix_nano: 1_700_000_000_000_000_000,
            time_unix_nano: 1_700_000_010_000_000_000,
            count: 42,
            sum: 1234.5,
            bucket_counts: std::vec![0u64; n_bounds + 1],
            explicit_bounds: bounds,
        };

        let metric = Metric {
            name: "http.server.request.duration".into(),
            description: "Duration of HTTP server requests".into(),
            unit: "ms".into(),
            data: MetricData::Histogram(HistogramData {
                aggregation_temporality: AggregationTemporality::Delta,
                data_points: std::vec![point],
            }),
        };

        let batch = Batch { resource, scope, metrics: std::vec![metric] };

        // Structural assertions
        assert_eq!(batch.resource.attributes.len(), 1);
        assert_eq!(batch.resource.attributes[0].key, "service.name");
        assert_eq!(batch.metrics.len(), 1);
        assert_eq!(batch.metrics[0].name, "http.server.request.duration");

        let MetricData::Histogram(ref hist) = batch.metrics[0].data;
        assert_eq!(hist.data_points.len(), 1);

        let dp = &hist.data_points[0];
        assert_eq!(dp.count, 42);
        assert_eq!(dp.explicit_bounds.len(), 8);
        assert_eq!(dp.bucket_counts.len(), 9); // 8 boundaries + 1 overflow
        assert_eq!(dp.attributes[0].key, "http.response.status_code");
        assert_eq!(dp.attributes[0].value, AnyValue::Int(200));
    }
}
