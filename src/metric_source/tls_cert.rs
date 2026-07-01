// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Serving-certificate metric source.
//!
//! Emits three int64 gauges per TLS serving certificate from the config-time
//! cert table built by [`crate::cert_table::build_cert_table`]:
//!
//!  - `ngx_otel.tls.certificate.not_after`           — notAfter, Unix epoch s
//!  - `ngx_otel.tls.certificate.not_before`          — notBefore, Unix epoch s
//!  - `ngx_otel.tls.certificate.time_to_expiration`  — notAfter − now, s
//!    (negative once the certificate has expired)
//!
//! The table is populated ONCE at `postconfiguration` (master process) and is
//! immutable afterwards; the exporter inherits it at fork. These metrics
//! therefore describe what nginx **serves**, not what is on disk: a renewed
//! certificate file does not change them until nginx reloads, because nginx
//! does not serve it until reload (deliberate contrast with file-watching
//! tools — see TELEMETRY_MODEL.md "Serving-certificate metrics").
//!
//! When the table is empty (nginx built without `http_ssl_module`, or no
//! `ssl_certificate` configured) the three series are **absent** from the
//! export entirely — not present-as-zero (matching how stub_status metrics are
//! absent rather than reported as zero).

use crate::cert_table::CertInfo;
use crate::data_model::{
    AnyValue, GaugeData, KeyValue, Metric, MetricData, NumberDataPoint, NumberValue,
};
use crate::metric_source::MetricSource;

/// Metric names (`ngx_otel.*` namespace — deliberately NOT
/// NGINX Agent's `nginx.certificate.time_to_expiration`).
pub const NOT_AFTER: &str = "ngx_otel.tls.certificate.not_after";
pub const NOT_BEFORE: &str = "ngx_otel.tls.certificate.not_before";
pub const TIME_TO_EXPIRATION: &str = "ngx_otel.tls.certificate.time_to_expiration";

/// A `MetricSource` over the config-time serving-certificate table.
///
/// Borrows `MainConfig::cert_table`; constructed per collection tick in
/// `drain::collect_all_sources`, exporter process only (never workers,
/// never the request hot path).
pub struct ServingCertSource<'a> {
    pub certs: &'a [CertInfo],
}

impl MetricSource for ServingCertSource<'_> {
    fn collect(&self) -> std::vec::Vec<Metric> {
        // Wall clock, deliberately: cert validity is wall time, so
        // `time_to_expiration` MUST be `notAfter − wall_now`. Do NOT switch to
        // `ngx_current_msec` (nginx's cached monotonic-ish ms-since-boot timer)
        // — mixing it with epoch values has bitten this project before
        // (error LogRecords stamped with it were rejected by Loki as 1970).
        let now_wall_secs = crate::util::now_unix_secs() as i64;
        self.collect_at(now_wall_secs, crate::util::now_unix_nano())
    }
}

impl ServingCertSource<'_> {
    /// Inner collection with an injectable clock (unit-testable arithmetic).
    fn collect_at(&self, now_wall_secs: i64, now_ns: u64) -> std::vec::Vec<Metric> {
        // Absent-not-zero: empty table → no metrics at all.
        if self.certs.is_empty() {
            return std::vec::Vec::new();
        }

        let points = |value_of: &dyn Fn(&CertInfo) -> i64| -> std::vec::Vec<NumberDataPoint> {
            self.certs
                .iter()
                .map(|c| NumberDataPoint {
                    attributes: cert_attrs(c),
                    start_time_unix_nano: 0,
                    time_unix_nano: now_ns,
                    value: NumberValue::AsInt(value_of(c)),
                })
                .collect()
        };

        std::vec![
            cert_gauge(
                NOT_AFTER,
                "Serving certificate notAfter (Unix epoch seconds); collected at \
                 startup/reload from the live SSL_CTX",
                points(&|c| c.not_after_unix),
            ),
            cert_gauge(
                NOT_BEFORE,
                "Serving certificate notBefore (Unix epoch seconds); collected at \
                 startup/reload from the live SSL_CTX",
                points(&|c| c.not_before_unix),
            ),
            cert_gauge(
                TIME_TO_EXPIRATION,
                "Seconds until the serving certificate expires (negative after \
                 expiry); recomputed against the wall clock each export interval",
                points(&|c| c.not_after_unix - now_wall_secs),
            ),
        ]
    }
}

/// The per-certificate attribute set.
///
/// Scope: EXACTLY these seven attributes — `tls.server.certificate.file_path`,
/// `tls.server.subject` (CN only), `tls.server.issuer` (CN only),
/// `tls.server.certificate.serial_number`, `tls.server.certificate.public_key_algorithm`,
/// `tls.server.certificate.signature_algorithm`, `server.address`.
/// Nothing else: no PEM, no keys, no fingerprints, no full DNs, no SANs, no key_bits.
fn cert_attrs(c: &CertInfo) -> std::vec::Vec<KeyValue> {
    let s = |key: &str, value: &str| KeyValue {
        key: key.into(),
        value: AnyValue::String(value.into()),
    };
    std::vec![
        s("tls.server.certificate.file_path", &c.file_path),
        s("tls.server.subject", &c.subject_cn),
        s("tls.server.issuer", &c.issuer_cn),
        s("tls.server.certificate.serial_number", &c.serial),
        s("tls.server.certificate.public_key_algorithm", &c.pubkey_alg),
        s("tls.server.certificate.signature_algorithm", &c.sig_alg),
        s("server.address", &c.server_name),
    ]
}

/// Build one int64 Gauge metric (unit: seconds) from pre-built data points.
fn cert_gauge(name: &str, desc: &str, data_points: std::vec::Vec<NumberDataPoint>) -> Metric {
    Metric {
        name: name.into(),
        description: desc.into(),
        unit: "s".into(),
        data: MetricData::Gauge(GaugeData { data_points }),
    }
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_cert(path: &str, cn: &str, not_before: i64, not_after: i64) -> CertInfo {
        CertInfo {
            file_path: path.into(),
            server_name: "www.example.test".into(),
            not_before_unix: not_before,
            not_after_unix: not_after,
            subject_cn: cn.into(),
            issuer_cn: "Test CA".into(),
            serial: "0A1B2C".into(),
            pubkey_alg: "RSA".into(),
            sig_alg: "RSA-SHA256".into(),
        }
    }

    /// The seven scope-guard attribute keys, in emission order.
    const ALLOWED_KEYS: [&str; 7] = [
        "tls.server.certificate.file_path",
        "tls.server.subject",
        "tls.server.issuer",
        "tls.server.certificate.serial_number",
        "tls.server.certificate.public_key_algorithm",
        "tls.server.certificate.signature_algorithm",
        "server.address",
    ];

    /// One cert → three int64 gauges with exact values, exact names, and
    /// EXACTLY the seven allowed attributes.
    #[test]
    fn three_gauges_exact_values_and_attribute_set() {
        let certs = [mock_cert("/etc/ssl/a.crt", "a.example.test", 1_700_000_000, 1_893_456_000)];
        let src = ServingCertSource { certs: &certs };
        let now_secs: i64 = 1_750_000_000;
        let now_ns: u64 = 1_750_000_000_000_000_000;
        let metrics = src.collect_at(now_secs, now_ns);

        assert_eq!(metrics.len(), 3, "expected exactly 3 cert metrics");
        let expected: [(&str, i64); 3] = [
            (NOT_AFTER, 1_893_456_000),
            (NOT_BEFORE, 1_700_000_000),
            (TIME_TO_EXPIRATION, 1_893_456_000 - 1_750_000_000),
        ];
        for (name, value) in expected {
            let m = metrics
                .iter()
                .find(|m| m.name == name)
                .unwrap_or_else(|| panic!("metric {name} missing"));
            assert_eq!(m.unit, "s", "{name} unit");
            let MetricData::Gauge(ref g) = m.data else {
                panic!("{name} must be a Gauge");
            };
            assert_eq!(g.data_points.len(), 1, "{name} #points");
            let dp = &g.data_points[0];
            assert_eq!(dp.value, NumberValue::AsInt(value), "{name} value");
            assert_eq!(dp.time_unix_nano, now_ns, "{name} timestamp");

            // Attribute set EXACT: the seven scope-guard keys, nothing more,
            // nothing fewer, with the CertInfo-sourced values.
            let keys: std::vec::Vec<&str> =
                dp.attributes.iter().map(|kv| kv.key.as_str()).collect();
            assert_eq!(keys, ALLOWED_KEYS, "{name} attribute keys must be exactly the 7 allowed");
            let val = |k: &str| -> &str {
                let kv = dp.attributes.iter().find(|kv| kv.key == k).unwrap();
                match &kv.value {
                    AnyValue::String(s) => s.as_str(),
                    other => panic!("attribute {k} must be a String, got {other:?}"),
                }
            };
            assert_eq!(val("tls.server.certificate.file_path"), "/etc/ssl/a.crt");
            assert_eq!(val("tls.server.subject"), "a.example.test");
            assert_eq!(val("tls.server.issuer"), "Test CA");
            assert_eq!(val("tls.server.certificate.serial_number"), "0A1B2C");
            assert_eq!(val("tls.server.certificate.public_key_algorithm"), "RSA");
            assert_eq!(val("tls.server.certificate.signature_algorithm"), "RSA-SHA256");
            assert_eq!(val("server.address"), "www.example.test");
        }

        // Our names live under ngx_otel.* ONLY — never NGINX
        // Agent's `nginx.certificate.*` namespace.
        for m in &metrics {
            assert!(
                !m.name.starts_with("nginx.certificate"),
                "must not emit Agent's nginx.certificate.* names, got {}",
                m.name
            );
        }
    }

    /// `time_to_expiration` goes NEGATIVE once `now` passes notAfter; exact
    /// arithmetic both sides of expiry.
    #[test]
    fn time_to_expiration_arithmetic_incl_negative() {
        let certs = [mock_cert("/etc/ssl/exp.crt", "exp.example.test", 1_000, 2_000)];
        let src = ServingCertSource { certs: &certs };

        let tte_at = |now: i64| -> i64 {
            let metrics = src.collect_at(now, 0);
            let m = metrics.iter().find(|m| m.name == TIME_TO_EXPIRATION).unwrap();
            let MetricData::Gauge(ref g) = m.data else { panic!("must be a Gauge") };
            match g.data_points[0].value {
                NumberValue::AsInt(v) => v,
                NumberValue::AsDouble(_) => panic!("must be AsInt"),
            }
        };

        assert_eq!(tte_at(1_500), 500, "before expiry");
        assert_eq!(tte_at(2_000), 0, "at expiry");
        assert_eq!(tte_at(2_750), -750, "after expiry: negative, exact");
    }

    /// Empty cert table → NO metrics at all (absent, not zero — matching how
    /// stub_status metrics are absent rather than reported as zero).
    #[test]
    fn absent_when_table_empty() {
        let src = ServingCertSource { certs: &[] };
        assert!(src.collect_at(1_750_000_000, 1).is_empty(), "empty table must yield NO metrics");
        assert!(src.collect().is_empty(), "production clock path must also yield NO metrics");
    }

    /// Two certs (the dual RSA+ECDSA block shape) → each of the three metrics
    /// carries two data points, distinguished by attributes.
    #[test]
    fn dual_certs_two_points_per_metric() {
        let mut rsa = mock_cert("/etc/ssl/rsa.crt", "dual.example.test", 1_000, 2_000);
        rsa.pubkey_alg = "RSA".into();
        let mut ec = mock_cert("/etc/ssl/ecdsa.crt", "dual.example.test", 1_100, 3_000);
        ec.pubkey_alg = "EC".into();
        let certs = [rsa, ec];
        let src = ServingCertSource { certs: &certs };

        let metrics = src.collect_at(1_500, 0);
        assert_eq!(metrics.len(), 3);
        for m in &metrics {
            let MetricData::Gauge(ref g) = m.data else { panic!("must be a Gauge") };
            assert_eq!(g.data_points.len(), 2, "{}: one point per cert", m.name);
            let algs: std::vec::Vec<&str> = g
                .data_points
                .iter()
                .map(|dp| {
                    match &dp
                        .attributes
                        .iter()
                        .find(|kv| kv.key == "tls.server.certificate.public_key_algorithm")
                        .unwrap()
                        .value
                    {
                        AnyValue::String(s) => s.as_str(),
                        _ => panic!("tls.server.certificate.public_key_algorithm must be a String"),
                    }
                })
                .collect();
            assert_eq!(algs, ["RSA", "EC"], "{}: both certs present in table order", m.name);
        }
        // Spot-check per-cert values on not_after.
        let m = metrics.iter().find(|m| m.name == NOT_AFTER).unwrap();
        let MetricData::Gauge(ref g) = m.data else { panic!() };
        assert_eq!(g.data_points[0].value, NumberValue::AsInt(2_000));
        assert_eq!(g.data_points[1].value, NumberValue::AsInt(3_000));
    }
}
