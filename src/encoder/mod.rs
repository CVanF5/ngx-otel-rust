// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Step 7: `Encoder` trait + OTLP/HTTP protobuf encoder.
//!
//! Converts the internal [`crate::data_model::Batch`] into
//! `ExportMetricsServiceRequest` protobuf bytes via prost.

use prost::Message;

use crate::data_model::{AggregationTemporality, AnyValue, Batch, MetricData, NumberValue};

// ── Generated protobuf types ─────────────────────────────────────────────────
// Include the files emitted by prost-build in the build script.

/// Generated protobuf types — module hierarchy mirrors the proto package path
/// so that the `super::super::...` cross-references inside the generated code
/// resolve correctly.
mod opentelemetry {
    pub mod proto {
        pub mod common {
            pub mod v1 {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/opentelemetry.proto.common.v1.rs"
                ));
            }
        }
        pub mod resource {
            pub mod v1 {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/opentelemetry.proto.resource.v1.rs"
                ));
            }
        }
        pub mod metrics {
            pub mod v1 {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/opentelemetry.proto.metrics.v1.rs"
                ));
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
        }
    }
}

// Convenience re-exports so the rest of this file can use short paths.
use opentelemetry::proto::collector::metrics::v1 as collector;
use opentelemetry::proto::common::v1 as common;
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

// ── Conversion helpers ───────────────────────────────────────────────────────

fn convert_kv(kv: &crate::data_model::KeyValue) -> common::KeyValue {
    common::KeyValue {
        key: kv.key.clone(),
        value: Some(convert_any_value(&kv.value)),
    }
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

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_model::{
        AggregationTemporality, AnyValue, Batch, HistogramData, HistogramDataPoint, KeyValue,
        Metric, MetricData, Resource, Scope,
    };
    use super::collector::ExportMetricsServiceRequest;
    use super::metrics_proto;

    fn make_batch() -> Batch {
        Batch {
            resource: Resource {
                attributes: std::vec![KeyValue {
                    key: "service.name".into(),
                    value: AnyValue::String("test-nginx".into()),
                }],
            },
            scope: Scope {
                name: "ngx-otel-rust".into(),
                version: "0.1.0".into(),
            },
            metrics: std::vec![Metric {
                name: "http.server.request.duration".into(),
                description: "HTTP server request duration".into(),
                unit: "ms".into(),
                data: MetricData::Histogram(HistogramData {
                    aggregation_temporality: AggregationTemporality::Delta,
                    data_points: std::vec![HistogramDataPoint {
                        attributes: std::vec![],
                        start_time_unix_nano: 0,
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
            metrics_proto::AggregationTemporality::Delta as i32
        );
        assert_eq!(hist.data_points.len(), 1);
        let dp = &hist.data_points[0];
        assert_eq!(dp.count, 42);
        assert_eq!(dp.sum, Some(1234.5));
        assert_eq!(dp.bucket_counts, std::vec![1u64, 2, 5, 10, 24]);
        assert_eq!(dp.explicit_bounds, std::vec![5.0f64, 10.0, 25.0, 50.0]);
        assert_eq!(dp.time_unix_nano, 1_700_000_000_000_000_000);
    }
}
