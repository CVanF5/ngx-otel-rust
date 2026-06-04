// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Step 7: `Encoder` trait + OTLP/HTTP protobuf encoder.
//!
//! Converts the internal [`crate::data_model::Batch`] into
//! `ExportMetricsServiceRequest` protobuf bytes via prost.

use prost::Message;

use crate::data_model::{AggregationTemporality, AnyValue, Batch, LogRecord, LogsBatch, MetricData, NumberValue};

// ── Generated protobuf types ─────────────────────────────────────────────────
// Include the files emitted by prost-build in the build script.

/// Generated protobuf types — module hierarchy mirrors the proto package path
/// so that the `super::super::...` cross-references inside the generated code
/// resolve correctly.  `pub(crate)` so other in-crate modules (e.g. the
/// gRPC smoke harness in `transport::grpc::smoke`) can use the same prost
/// types without duplicating the `include!` hierarchy.
///
/// Lints are broadly allowed on this module: it is prost/tonic-generated
/// code, regenerated on every build, with type naming and doc formatting
/// fixed by the OpenTelemetry `.proto` spec.  It is deliberately excluded
/// from this crate's lint gate (the one outer `#[allow]` covers all nested
/// `include!`s, since lint levels are lexically scoped).
#[allow(clippy::all, clippy::pedantic, clippy::nursery, dead_code, rustdoc::all)]
pub(crate) mod opentelemetry {
    pub mod proto {
        pub mod common {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/opentelemetry.proto.common.v1.rs"));
            }
        }
        pub mod resource {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/opentelemetry.proto.resource.v1.rs"));
            }
        }
        pub mod metrics {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/opentelemetry.proto.metrics.v1.rs"));
            }
        }
        pub mod logs {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/opentelemetry.proto.logs.v1.rs"));
            }
        }
        pub mod collector {
            pub mod metrics {
                pub mod v1 {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/opentelemetry.proto.collector.metrics.v1.rs"
                    ));
                }
            }
            pub mod logs {
                pub mod v1 {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/opentelemetry.proto.collector.logs.v1.rs"
                    ));
                }
            }
        }
    }
}

// Convenience re-exports so the rest of this file can use short paths.
use opentelemetry::proto::collector::logs::v1 as logs_collector;
use opentelemetry::proto::collector::metrics::v1 as collector;
use opentelemetry::proto::common::v1 as common;
use opentelemetry::proto::logs::v1 as logs_proto;
use opentelemetry::proto::metrics::v1 as metrics_proto;
use opentelemetry::proto::resource::v1 as resource_proto;

// ── Public trait ─────────────────────────────────────────────────────────────

/// Serialises a [`Batch`] to wire bytes.
pub trait Encoder {
    fn encode(&self, batch: &Batch) -> std::vec::Vec<u8>;
}

// ── OTLP/HTTP encoder ────────────────────────────────────────────────────────

/// Encodes a [`Batch`] as an OTLP `ExportMetricsServiceRequest`.
pub struct OtlpHttpEncoder;

impl Encoder for OtlpHttpEncoder {
    fn encode(&self, batch: &Batch) -> std::vec::Vec<u8> {
        // ── Convert attributes ────────────────────────────────────────────
        let resource_attrs: std::vec::Vec<common::KeyValue> =
            batch.resource.attributes.iter().map(convert_kv).collect();

        // ── Convert metrics ───────────────────────────────────────────────
        let proto_metrics: std::vec::Vec<metrics_proto::Metric> =
            batch.metrics.iter().map(convert_metric).collect();

        let request = collector::ExportMetricsServiceRequest {
            resource_metrics: std::vec![metrics_proto::ResourceMetrics {
                resource: Some(resource_proto::Resource {
                    attributes: resource_attrs,
                    dropped_attributes_count: 0,
                }),
                scope_metrics: std::vec![metrics_proto::ScopeMetrics {
                    scope: Some(common::InstrumentationScope {
                        name: batch.scope.name.clone(),
                        version: batch.scope.version.clone(),
                        attributes: std::vec![],
                        dropped_attributes_count: 0,
                    }),
                    metrics: proto_metrics,
                    schema_url: std::string::String::new(),
                }],
                schema_url: std::string::String::new(),
            }],
        };

        let mut buf = std::vec::Vec::with_capacity(request.encoded_len());
        // encode() only errors when the buffer runs out of space; Vec grows.
        request.encode(&mut buf).expect("encode to Vec never fails");
        buf
    }
}

// ── OTLP logs encoder ────────────────────────────────────────────────────────

/// Encodes a [`LogsBatch`] as an OTLP `ExportLogsServiceRequest`.
///
/// Mirrors [`OtlpHttpEncoder`] but operates on log records.  Reuses the
/// existing `convert_kv` / `convert_any_value` helpers.
pub struct OtlpLogsEncoder;

impl OtlpLogsEncoder {
    /// Encode a [`LogsBatch`] to wire bytes (protobuf).
    pub fn encode(&self, batch: &LogsBatch) -> std::vec::Vec<u8> {
        let resource_attrs: std::vec::Vec<common::KeyValue> =
            batch.resource.attributes.iter().map(convert_kv).collect();

        let proto_records: std::vec::Vec<logs_proto::LogRecord> =
            batch.logs.iter().map(convert_log_record).collect();

        let request = logs_collector::ExportLogsServiceRequest {
            resource_logs: std::vec![logs_proto::ResourceLogs {
                resource: Some(resource_proto::Resource {
                    attributes: resource_attrs,
                    dropped_attributes_count: 0,
                }),
                scope_logs: std::vec![logs_proto::ScopeLogs {
                    scope: Some(common::InstrumentationScope {
                        name: batch.scope.name.clone(),
                        version: batch.scope.version.clone(),
                        attributes: std::vec![],
                        dropped_attributes_count: 0,
                    }),
                    log_records: proto_records,
                    schema_url: std::string::String::new(),
                }],
                schema_url: std::string::String::new(),
            }],
        };

        let mut buf = std::vec::Vec::with_capacity(request.encoded_len());
        request.encode(&mut buf).expect("encode to Vec never fails");
        buf
    }
}

/// Convert a [`LogRecord`] into its protobuf equivalent.
fn convert_log_record(lr: &LogRecord) -> logs_proto::LogRecord {
    logs_proto::LogRecord {
        time_unix_nano: lr.time_unix_nano,
        observed_time_unix_nano: lr.observed_time_unix_nano,
        severity_number: lr.severity_number as i32,
        severity_text: lr.severity_text.clone(),
        body: Some(convert_any_value(&lr.body)),
        attributes: lr.attributes.iter().map(convert_kv).collect(),
        dropped_attributes_count: 0,
        flags: 0,
        trace_id: std::vec![],
        span_id: std::vec![],
        event_name: lr.event_name.clone(),
    }
}

// ── Conversion helpers ───────────────────────────────────────────────────────

fn convert_kv(kv: &crate::data_model::KeyValue) -> common::KeyValue {
    common::KeyValue { key: kv.key.clone(), value: Some(convert_any_value(&kv.value)) }
}

fn convert_any_value(v: &AnyValue) -> common::AnyValue {
    use common::any_value::Value as PV;
    let value = match v {
        AnyValue::String(s) => PV::StringValue(s.clone()),
        AnyValue::Bool(b) => PV::BoolValue(*b),
        AnyValue::Int(i) => PV::IntValue(*i),
        AnyValue::Double(d) => PV::DoubleValue(*d),
        AnyValue::Bytes(b) => PV::BytesValue(b.clone()),
        AnyValue::Array(arr) => PV::ArrayValue(common::ArrayValue {
            values: arr.iter().map(convert_any_value).collect(),
        }),
    };
    common::AnyValue { value: Some(value) }
}

fn convert_metric(m: &crate::data_model::Metric) -> metrics_proto::Metric {
    use metrics_proto::{metric::Data as PD, AggregationTemporality as ProtoAT};

    let proto_temporality = |t: AggregationTemporality| -> i32 {
        match t {
            AggregationTemporality::Unspecified => ProtoAT::Unspecified as i32,
            AggregationTemporality::Delta => ProtoAT::Delta as i32,
            AggregationTemporality::Cumulative => ProtoAT::Cumulative as i32,
        }
    };

    let data = match &m.data {
        MetricData::Histogram(h) => PD::Histogram(metrics_proto::Histogram {
            data_points: h.data_points.iter().map(convert_hdp).collect(),
            aggregation_temporality: proto_temporality(h.aggregation_temporality),
        }),
        MetricData::ExponentialHistogram(h) => {
            PD::ExponentialHistogram(metrics_proto::ExponentialHistogram {
                data_points: h.data_points.iter().map(convert_exp_hdp).collect(),
                aggregation_temporality: proto_temporality(h.aggregation_temporality),
            })
        }
        MetricData::Sum(s) => PD::Sum(metrics_proto::Sum {
            data_points: s.data_points.iter().map(convert_ndp).collect(),
            aggregation_temporality: proto_temporality(s.aggregation_temporality),
            is_monotonic: s.is_monotonic,
        }),
        MetricData::Gauge(g) => PD::Gauge(metrics_proto::Gauge {
            data_points: g.data_points.iter().map(convert_ndp).collect(),
        }),
    };

    metrics_proto::Metric {
        name: m.name.clone(),
        description: m.description.clone(),
        unit: m.unit.clone(),
        data: Some(data),
        metadata: std::vec![],
    }
}

fn convert_ndp(dp: &crate::data_model::NumberDataPoint) -> metrics_proto::NumberDataPoint {
    use metrics_proto::number_data_point::Value as PV;
    let value = match dp.value {
        NumberValue::AsInt(i) => PV::AsInt(i),
        NumberValue::AsDouble(d) => PV::AsDouble(d),
    };
    metrics_proto::NumberDataPoint {
        attributes: dp.attributes.iter().map(convert_kv).collect(),
        start_time_unix_nano: dp.start_time_unix_nano,
        time_unix_nano: dp.time_unix_nano,
        exemplars: std::vec![],
        flags: 0,
        value: Some(value),
    }
}

fn convert_hdp(dp: &crate::data_model::HistogramDataPoint) -> metrics_proto::HistogramDataPoint {
    metrics_proto::HistogramDataPoint {
        attributes: dp.attributes.iter().map(convert_kv).collect(),
        start_time_unix_nano: dp.start_time_unix_nano,
        time_unix_nano: dp.time_unix_nano,
        count: dp.count,
        sum: Some(dp.sum),
        bucket_counts: dp.bucket_counts.clone(),
        explicit_bounds: dp.explicit_bounds.clone(),
        exemplars: std::vec![],
        flags: 0,
        min: None,
        max: None,
    }
}

fn convert_exemplar(e: &crate::data_model::Exemplar) -> metrics_proto::Exemplar {
    use metrics_proto::exemplar::Value as EV;
    metrics_proto::Exemplar {
        filtered_attributes: e.filtered_attributes.iter().map(convert_kv).collect(),
        time_unix_nano: e.time_unix_nano,
        value: Some(EV::AsDouble(e.value)),
        span_id: if e.has_trace { e.span_id.to_vec() } else { std::vec![] },
        trace_id: if e.has_trace { e.trace_id.to_vec() } else { std::vec![] },
    }
}

fn convert_exp_hdp(
    dp: &crate::data_model::ExponentialHistogramDataPoint,
) -> metrics_proto::ExponentialHistogramDataPoint {
    use metrics_proto::exponential_histogram_data_point::Buckets;

    // Trim trailing zeros from the positive bucket counts — the proto spec
    // does not require trailing zeros, and they inflate the payload.
    let mut positive_counts = dp.positive_bucket_counts.clone();
    while positive_counts.last() == Some(&0) {
        positive_counts.pop();
    }

    metrics_proto::ExponentialHistogramDataPoint {
        attributes: dp.attributes.iter().map(convert_kv).collect(),
        start_time_unix_nano: dp.start_time_unix_nano,
        time_unix_nano: dp.time_unix_nano,
        count: dp.count,
        sum: if dp.count > 0 { Some(dp.sum) } else { None },
        scale: dp.scale,
        zero_count: dp.zero_count,
        positive: Some(Buckets {
            offset: dp.positive_offset,
            bucket_counts: positive_counts,
        }),
        negative: Some(Buckets {
            offset: 0,
            bucket_counts: std::vec![],
        }),
        exemplars: dp.exemplars.iter().map(convert_exemplar).collect(),
        flags: 0,
        min: None,
        max: None,
        zero_threshold: 0.0,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::collector::ExportMetricsServiceRequest;
    use super::logs_collector::ExportLogsServiceRequest;
    use super::metrics_proto;
    use super::*;
    use crate::data_model::{
        AggregationTemporality, AnyValue, Batch, ExponentialHistogramData,
        ExponentialHistogramDataPoint, HistogramData, HistogramDataPoint, KeyValue,
        LogRecord, LogsBatch, Metric, MetricData, Resource, Scope, SeverityNumber,
    };

    fn make_batch() -> Batch {
        Batch {
            resource: Resource {
                attributes: std::vec![KeyValue {
                    key: "service.name".into(),
                    value: AnyValue::String("test-nginx".into()),
                }],
            },
            scope: Scope { name: "ngx-otel-rust".into(), version: "0.1.0".into() },
            metrics: std::vec![Metric {
                name: "http.server.request.duration".into(),
                description: "HTTP server request duration".into(),
                unit: "ms".into(),
                data: MetricData::Histogram(HistogramData {
                    aggregation_temporality: AggregationTemporality::Cumulative,
                    data_points: std::vec![HistogramDataPoint {
                        attributes: std::vec![],
                        start_time_unix_nano: 1_699_999_990_000_000_000,
                        time_unix_nano: 1_700_000_000_000_000_000,
                        count: 42,
                        sum: 1234.5,
                        bucket_counts: std::vec![1, 2, 5, 10, 24],
                        explicit_bounds: std::vec![5.0, 10.0, 25.0, 50.0],
                    }],
                }),
            }],
        }
    }

    #[test]
    fn round_trip_produces_valid_protobuf() {
        let enc = OtlpHttpEncoder;
        let batch = make_batch();
        let bytes = enc.encode(&batch);

        // Must be non-empty.
        assert!(!bytes.is_empty(), "encoded bytes must be non-empty");

        // Must decode back without error.
        let decoded = ExportMetricsServiceRequest::decode(bytes.as_slice())
            .expect("must decode without error");

        // Structural assertions.
        assert_eq!(decoded.resource_metrics.len(), 1);
        let rm = &decoded.resource_metrics[0];

        // Resource attributes.
        let resource = rm.resource.as_ref().expect("resource present");
        assert_eq!(resource.attributes.len(), 1);
        assert_eq!(resource.attributes[0].key, "service.name");

        // Scope.
        assert_eq!(rm.scope_metrics.len(), 1);
        let sm = &rm.scope_metrics[0];
        let scope = sm.scope.as_ref().expect("scope present");
        assert_eq!(scope.name, "ngx-otel-rust");

        // Metric.
        assert_eq!(sm.metrics.len(), 1);
        let m = &sm.metrics[0];
        assert_eq!(m.name, "http.server.request.duration");
        assert_eq!(m.unit, "ms");

        // Histogram data point.
        let hist = match m.data.as_ref().expect("data present") {
            metrics_proto::metric::Data::Histogram(h) => h,
            _ => panic!("expected Histogram"),
        };
        assert_eq!(
            hist.aggregation_temporality,
            metrics_proto::AggregationTemporality::Cumulative as i32
        );
        assert_eq!(hist.data_points.len(), 1);
        let dp = &hist.data_points[0];
        assert_eq!(dp.count, 42);
        assert_eq!(dp.sum, Some(1234.5));
        assert_eq!(dp.bucket_counts, std::vec![1u64, 2, 5, 10, 24]);
        assert_eq!(dp.explicit_bounds, std::vec![5.0f64, 10.0, 25.0, 50.0]);
        assert_eq!(dp.start_time_unix_nano, 1_699_999_990_000_000_000);
        assert_eq!(dp.time_unix_nano, 1_700_000_000_000_000_000);
    }

    /// Encode a LogsBatch with two records, decode it, and assert structural
    /// equivalence.  Mirrors `round_trip_produces_valid_protobuf`.
    #[test]
    fn logs_round_trip() {
        let batch = LogsBatch {
            resource: Resource {
                attributes: std::vec![KeyValue {
                    key: "service.name".into(),
                    value: AnyValue::String("test-nginx".into()),
                }],
            },
            scope: Scope { name: "ngx-otel-rust".into(), version: "0.1.0".into() },
            logs: std::vec![
                LogRecord {
                    time_unix_nano: 1_700_000_000_000_000_000,
                    observed_time_unix_nano: 1_700_000_000_000_000_001,
                    severity_number: SeverityNumber::Info,
                    severity_text: "info".into(),
                    body: AnyValue::String(std::string::String::new()),
                    attributes: std::vec![
                        KeyValue {
                            key: "http.request.method".into(),
                            value: AnyValue::String("GET".into()),
                        },
                        KeyValue {
                            key: "http.response.status_code".into(),
                            value: AnyValue::Int(200),
                        },
                    ],
                    event_name: "http.access".into(),
                },
                LogRecord {
                    time_unix_nano: 1_700_000_001_000_000_000,
                    observed_time_unix_nano: 1_700_000_001_000_000_002,
                    severity_number: SeverityNumber::Error,
                    severity_text: "error".into(),
                    body: AnyValue::String("upstream connect failed".into()),
                    attributes: std::vec![],
                    event_name: "nginx.error".into(),
                },
            ],
        };

        let enc = OtlpLogsEncoder;
        let bytes = enc.encode(&batch);

        // Must be non-empty.
        assert!(!bytes.is_empty(), "encoded bytes must be non-empty");

        // Must decode back without error.
        let decoded = ExportLogsServiceRequest::decode(bytes.as_slice())
            .expect("must decode without error");

        assert_eq!(decoded.resource_logs.len(), 1);
        let rl = &decoded.resource_logs[0];

        // Resource attributes.
        let resource = rl.resource.as_ref().expect("resource present");
        assert_eq!(resource.attributes.len(), 1);
        assert_eq!(resource.attributes[0].key, "service.name");

        // Scope.
        assert_eq!(rl.scope_logs.len(), 1);
        let sl = &rl.scope_logs[0];
        let scope = sl.scope.as_ref().expect("scope present");
        assert_eq!(scope.name, "ngx-otel-rust");

        // Log records.
        assert_eq!(sl.log_records.len(), 2);

        let r0 = &sl.log_records[0];
        assert_eq!(r0.time_unix_nano, 1_700_000_000_000_000_000);
        assert_eq!(r0.severity_number, SeverityNumber::Info as i32);
        assert_eq!(r0.severity_text, "info");
        assert_eq!(r0.event_name, "http.access");
        assert_eq!(r0.attributes.len(), 2);
        assert_eq!(r0.attributes[0].key, "http.request.method");
        assert_eq!(r0.attributes[1].key, "http.response.status_code");

        let r1 = &sl.log_records[1];
        assert_eq!(r1.severity_number, SeverityNumber::Error as i32);
        assert_eq!(r1.event_name, "nginx.error");
        // body must be a string value
        let body = r1.body.as_ref().expect("body present");
        match body.value.as_ref().expect("body value present") {
            super::common::any_value::Value::StringValue(s) => {
                assert_eq!(s, "upstream connect failed");
            }
            other => panic!("expected StringValue body, got {other:?}"),
        }
    }

    /// Encode a Batch carrying an ExponentialHistogram data point, decode it,
    /// and verify scale / zero_count / positive buckets round-trip correctly.
    /// This is the Phase 2.2 DP-F verification gate.
    #[test]
    fn exp_histogram_roundtrips() {
        use crate::data_model::{
            ExponentialHistogramData, ExponentialHistogramDataPoint, MetricData,
        };
        use crate::shm::{EXP_HISTOGRAM_SCALE, EXP_HISTOGRAM_BUCKET_OFFSET, N_EXP_BUCKETS};

        // Bucket counts: simulate some observations.
        // bucket[6] = [64, 128)ms — 5 observations
        // bucket[8] = [256, 512)ms — 2 observations
        // zero_count = 3 (sub-ms latencies)
        let mut buckets = [0u64; N_EXP_BUCKETS];
        buckets[6] = 5;
        buckets[8] = 2;
        let dp = ExponentialHistogramDataPoint {
            attributes: std::vec![
                KeyValue {
                    key: "http.request.method".into(),
                    value: AnyValue::String("GET".into()),
                },
                KeyValue {
                    key: "http.route".into(),
                    value: AnyValue::String("/api".into()),
                },
            ],
            start_time_unix_nano: 1_700_000_000_000_000_000,
            time_unix_nano: 1_700_000_010_000_000_000,
            count: 10,   // 5 + 2 + 3 zero
            sum: 810.0,  // 5×96 + 2×384 + 3×0 = 480 + 768 = ... approximate
            scale: EXP_HISTOGRAM_SCALE,
            zero_count: 3,
            positive_offset: EXP_HISTOGRAM_BUCKET_OFFSET,
            positive_bucket_counts: buckets.to_vec(),
            exemplars: std::vec![],
        };

        let batch = Batch {
            resource: Resource::default(),
            scope: Scope { name: "test".into(), version: "0".into() },
            metrics: std::vec![Metric {
                name: "http.server.request.duration".into(),
                description: "test".into(),
                unit: "ms".into(),
                data: MetricData::ExponentialHistogram(ExponentialHistogramData {
                    aggregation_temporality: AggregationTemporality::Cumulative,
                    data_points: std::vec![dp],
                }),
            }],
        };

        let enc = OtlpHttpEncoder;
        let bytes = enc.encode(&batch);
        assert!(!bytes.is_empty(), "encoded bytes non-empty");

        let decoded = ExportMetricsServiceRequest::decode(bytes.as_slice())
            .expect("decode without error");

        assert_eq!(decoded.resource_metrics.len(), 1);
        let rm = &decoded.resource_metrics[0];
        assert_eq!(rm.scope_metrics.len(), 1);
        let metrics = &rm.scope_metrics[0].metrics;
        assert_eq!(metrics.len(), 1);

        // Must decode as ExponentialHistogram, not plain Histogram.
        let data = metrics[0].data.as_ref().expect("data present");
        match data {
            super::metrics_proto::metric::Data::ExponentialHistogram(eh) => {
                assert_eq!(eh.data_points.len(), 1);
                let ehdp = &eh.data_points[0];

                assert_eq!(ehdp.count, 10, "count round-trips");
                assert_eq!(ehdp.zero_count, 3, "zero_count round-trips");
                assert_eq!(ehdp.scale, EXP_HISTOGRAM_SCALE, "scale round-trips");
                assert!(ehdp.sum.is_some(), "sum present for non-zero count");

                let pos = ehdp.positive.as_ref().expect("positive buckets present");
                assert_eq!(pos.offset, EXP_HISTOGRAM_BUCKET_OFFSET, "offset round-trips");
                // After trailing-zero trim: buckets up to and including index 8 = [5, 0, 2]
                assert!(pos.bucket_counts.len() >= 9, "at least 9 positive buckets after trim");
                assert_eq!(pos.bucket_counts[6], 5, "bucket[6] = 5");
                assert_eq!(pos.bucket_counts[8], 2, "bucket[8] = 2");

                // Attributes round-trip.
                assert_eq!(ehdp.attributes.len(), 2);
                assert_eq!(ehdp.attributes[0].key, "http.request.method");
                assert_eq!(ehdp.attributes[1].key, "http.route");
            }
            other => panic!("expected ExponentialHistogram data, got {other:?}"),
        }
    }
}
