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

/// The data payload of a metric.
///
/// Phase 1.1 carries three shapes: histograms for the request-duration /
/// upstream-latency surface, sums for monotonic counters (`ngx_otel.dropped_records`,
/// `ngx_otel.send_failures`), and gauges for non-monotonic instantaneous
/// readings (`ngx_otel.export_interval_seconds`).  Per OTLP semantics these
/// must be distinct variants — emitting a counter as a single-bucket histogram
/// causes downstream backends to misclassify the metric type.
///
/// Phase 2.2 DP-F adds `ExponentialHistogram` for the request-duration metric.
#[derive(Debug, Clone)]
pub enum MetricData {
    Histogram(HistogramData),
    ExponentialHistogram(ExponentialHistogramData),
    Sum(SumData),
    Gauge(GaugeData),
}

/// A histogram metric aggregation.
#[derive(Debug, Clone)]
pub struct HistogramData {
    pub aggregation_temporality: AggregationTemporality,
    pub data_points: std::vec::Vec<HistogramDataPoint>,
}

/// A sum metric aggregation (monotonic counter or non-monotonic gauge-summed).
///
/// Use `is_monotonic = true` for counters that only increase
/// (e.g. `ngx_otel.dropped_records`).
#[derive(Debug, Clone)]
pub struct SumData {
    pub aggregation_temporality: AggregationTemporality,
    pub is_monotonic: bool,
    pub data_points: std::vec::Vec<NumberDataPoint>,
}

/// A gauge metric — a non-aggregated instantaneous value.
#[derive(Debug, Clone)]
pub struct GaugeData {
    pub data_points: std::vec::Vec<NumberDataPoint>,
}

/// A scalar data point used by both Sum and Gauge metrics.
#[derive(Debug, Clone)]
pub struct NumberDataPoint {
    pub attributes: std::vec::Vec<KeyValue>,
    pub start_time_unix_nano: u64,
    pub time_unix_nano: u64,
    pub value: NumberValue,
}

/// The numeric value of a [`NumberDataPoint`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NumberValue {
    AsInt(i64),
    AsDouble(f64),
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

/// An OTel exponential histogram metric aggregation (Phase 2.2 DP-F).
#[derive(Debug, Clone)]
pub struct ExponentialHistogramData {
    pub aggregation_temporality: AggregationTemporality,
    pub data_points: std::vec::Vec<ExponentialHistogramDataPoint>,
}

/// An OTel exemplar attached to a histogram data point (Phase 2.2 Step 2.2.4).
///
/// Carries a representative observation with optional trace context.
#[derive(Debug, Clone)]
pub struct Exemplar {
    /// The observed value (ms for request duration).
    pub value: f64,
    /// Unix epoch nanoseconds when this observation was made.
    pub time_unix_nano: u64,
    /// W3C trace_id (16 bytes), present only when a `traceparent` header was sent.
    pub trace_id: [u8; 16],
    /// W3C span_id (8 bytes), present only when a `traceparent` header was sent.
    pub span_id: [u8; 8],
    /// Whether `trace_id` / `span_id` carry valid trace context.
    pub has_trace: bool,
    /// Per-exemplar high-cardinality attributes (url.path, client.address, user_agent).
    /// Added in Step 2.2.5; empty in Step 2.2.4.
    pub filtered_attributes: std::vec::Vec<KeyValue>,
}

/// One data point in an OTel exponential histogram metric.
///
/// The internal representation uses scale 0 (`EXP_HISTOGRAM_SCALE`), meaning
/// bucket `k` covers `[2^k, 2^(k+1))` ms.  All durations are non-negative so
/// `negative` is always empty.  Values 0 ms are counted in `zero_count`.
#[derive(Debug, Clone)]
pub struct ExponentialHistogramDataPoint {
    /// Attributes for this data point (method, status class, protocol, route, upstream zone).
    pub attributes: std::vec::Vec<KeyValue>,
    /// Start of the measurement window (Unix epoch, nanoseconds).
    pub start_time_unix_nano: u64,
    /// End of the measurement window (Unix epoch, nanoseconds).
    pub time_unix_nano: u64,
    /// Total observation count (= sum of all bucket counts + zero_count).
    pub count: u64,
    /// Sum of all observed values (in ms).
    pub sum: f64,
    /// OTel exponential histogram scale (EXP_HISTOGRAM_SCALE = 0).
    pub scale: i32,
    /// Count of values exactly 0 ms (or truncated to 0 from sub-ms latencies).
    pub zero_count: u64,
    /// Positive-range bucket counts.  Bucket k covers [2^k, 2^(k+1)) ms.
    /// `offset` is the index of the first entry (always 0 for scale 0 with our
    /// fixed-offset storage).
    pub positive_offset: i32,
    pub positive_bucket_counts: std::vec::Vec<u64>,
    // `negative` is always empty for request durations (non-negative).
    /// Exemplars sampled from the reservoir (Step 2.2.4).  One per representative
    /// observation for this histogram data point.  May be empty.
    pub exemplars: std::vec::Vec<Exemplar>,
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
// Log types (Phase 2.1)
// ────────────────────────────────────────────────────────────────

/// OTel severity number per the OTel Log Data Model spec.
///
/// Values mirror the `SeverityNumber` enum in `logs.proto`; only the
/// subset used by the nginx-level → OTel mapping is listed here.
/// Numeric values match the proto field numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SeverityNumber {
    Unspecified = 0,
    Trace = 1,
    Trace2 = 2,
    Trace3 = 3,
    Trace4 = 4,
    Debug = 5,
    Debug2 = 6,
    Debug3 = 7,
    Debug4 = 8,
    Info = 9,
    Info2 = 10,
    Info3 = 11,
    Info4 = 12,
    Warn = 13,
    Warn2 = 14,
    Warn3 = 15,
    Warn4 = 16,
    Error = 17,
    Error2 = 18,
    Error3 = 19,
    Error4 = 20,
    Fatal = 21,
    Fatal2 = 22,
    Fatal3 = 23,
    Fatal4 = 24,
}

/// A single OTel log record.
///
/// Mirrors the `LogRecord` proto message shape (Phase 2.1).
/// `trace_id` / `span_id` are left empty — Phase 3 will correlate with
/// spans.  `body` carries a short string for access logs; structured
/// attributes carry the HTTP semconv fields.
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// When the event occurred (Unix epoch, nanoseconds).
    pub time_unix_nano: u64,
    /// When the event was observed by the collector (Unix epoch, nanoseconds).
    pub observed_time_unix_nano: u64,
    /// Normalized severity level.
    pub severity_number: SeverityNumber,
    /// Severity text (e.g. `"info"`, `"error"`).
    pub severity_text: std::string::String,
    /// Log body — free-form string.  Empty for access logs (attributes carry
    /// the HTTP semconv fields).
    pub body: AnyValue,
    /// HTTP semconv and other structured attributes.
    pub attributes: std::vec::Vec<KeyValue>,
    /// Event name (e.g. `"http.access"` or `"nginx.error"`).
    pub event_name: std::string::String,
}

/// A batch of log records ready for export.
///
/// Parallels [`Batch`] for metrics.  Groups records from all workers
/// under a single `Resource` and `Scope` before sending to the collector.
#[derive(Debug, Clone)]
pub struct LogsBatch {
    pub resource: Resource,
    pub scope: Scope,
    pub logs: std::vec::Vec<LogRecord>,
}

// ────────────────────────────────────────────────────────────────
// Unit tests
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
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

        let MetricData::Histogram(ref hist) = batch.metrics[0].data else {
            panic!("expected Histogram variant");
        };
        assert_eq!(hist.data_points.len(), 1);

        let dp = &hist.data_points[0];
        assert_eq!(dp.count, 42);
        assert_eq!(dp.explicit_bounds.len(), 8);
        assert_eq!(dp.bucket_counts.len(), 9); // 8 boundaries + 1 overflow
        assert_eq!(dp.attributes[0].key, "http.response.status_code");
        assert_eq!(dp.attributes[0].value, AnyValue::Int(200));
    }

    /// Construct a LogsBatch with two LogRecords; inspect the shape manually.
    #[test]
    fn logs_batch_round_trip() {
        let resource = Resource {
            attributes: std::vec![KeyValue {
                key: "service.name".into(),
                value: AnyValue::String("test-nginx".into()),
            }],
        };
        let scope = Scope { name: "ngx-otel-rust".into(), version: "0.1.0".into() };

        let record1 = LogRecord {
            time_unix_nano: 1_700_000_000_000_000_000,
            observed_time_unix_nano: 1_700_000_000_000_000_001,
            severity_number: SeverityNumber::Info,
            severity_text: "info".into(),
            body: AnyValue::String(std::string::String::new()),
            attributes: std::vec![
                KeyValue { key: "http.request.method".into(), value: AnyValue::String("GET".into()) },
                KeyValue {
                    key: "http.response.status_code".into(),
                    value: AnyValue::Int(200),
                },
            ],
            event_name: "http.access".into(),
        };

        let record2 = LogRecord {
            time_unix_nano: 1_700_000_001_000_000_000,
            observed_time_unix_nano: 1_700_000_001_000_000_002,
            severity_number: SeverityNumber::Error,
            severity_text: "error".into(),
            body: AnyValue::String("upstream connect failed".into()),
            attributes: std::vec![],
            event_name: "nginx.error".into(),
        };

        let batch = LogsBatch { resource, scope, logs: std::vec![record1, record2] };

        assert_eq!(batch.resource.attributes.len(), 1);
        assert_eq!(batch.resource.attributes[0].key, "service.name");
        assert_eq!(batch.logs.len(), 2);
        assert_eq!(batch.logs[0].event_name, "http.access");
        assert_eq!(batch.logs[0].severity_number, SeverityNumber::Info);
        assert_eq!(batch.logs[0].severity_number as i32, 9);
        assert_eq!(batch.logs[1].event_name, "nginx.error");
        assert_eq!(batch.logs[1].severity_number, SeverityNumber::Error);
        assert_eq!(batch.logs[1].severity_number as i32, 17);
    }
}
