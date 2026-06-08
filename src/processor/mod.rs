// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Config-driven `Processor` trait for the exporter pipeline — Step U (signal-generic).
//!
//! # Pipeline position
//!
//! ```text
//! drain → [Processor::process(&mut Pdata)] → encode → send
//! ```
//!
//! The trait is **signal-generic**: it receives `&mut Pdata` and dispatches
//! on the variant internally, so one processor handles all three signals.
//! Processors are constructed once at exporter startup via [`Processor::from_config`].
//! The default processor is [`NoopProcessor`] — a zero-overhead passthrough.
//!
//! # Staged follow-on: remote reconfiguration
//!
//! **Static config only** in this phase — the processor config is read once at exporter
//! startup and never reloaded.  The bidi control loop (Phase 5 / §1.2) will deliver a
//! new config payload to the exporter via the control-shm channel (§1.3.3); the exporter
//! will call [`Processor::from_config`] with the new blob and swap the processor.
//! The `from_config` API is designed for this: it is a pure function returning a new value,
//! so the swap is a single assignment with no state migration.
//!
//! # Static dispatch
//!
//! [`Processor`] is a concrete enum over all built-in processor implementations.
//! This keeps dispatch static and matches the pattern used by [`crate::export`]'s
//! `ExportTransport` — the exporter is already on the heap; one enum avoids a
//! `Box<dyn ProcessorImpl>` indirection.

use crate::data_model::Pdata;

// ── `Processor` trait ────────────────────────────────────────────────────────

/// Exporter-side processing stage — signal-generic (Step U).
///
/// Receives `&mut Pdata` after drain and before encode. May filter,
/// transform, or enrich the payload in-place. Dispatches on the variant
/// internally so signal-specific logic stays inside the processor.
///
/// # Config-driven construction
///
/// Every implementation provides [`ProcessorImpl::from_config`] so the
/// exporter can instantiate processors from a JSON config blob (operator
/// directive, or — in a future phase — the bidi control channel).
///
/// # Static config only
///
/// This phase: static config, read once at exporter startup.
/// Remote reconfiguration (bidi + control-shm) is a staged follow-on.
pub trait ProcessorImpl {
    /// Construct a processor from a JSON config blob.
    ///
    /// Implementations should be permissive: unknown keys are ignored,
    /// missing required keys fall back to defaults.
    fn from_config(cfg: &serde_json::Value) -> Self
    where
        Self: Sized;

    /// Process the payload in-place. Dispatches on the [`Pdata`] variant
    /// internally; unknown variants are left unchanged (passthrough).
    fn process(&self, data: &mut Pdata);
}

// ── NoopProcessor ─────────────────────────────────────────────────────────────

/// Passthrough processor — leaves the payload unchanged.
///
/// This is the default [`Processor`] variant.  It adds no overhead beyond
/// a function call; no clone or move of the data.
pub struct NoopProcessor;

impl ProcessorImpl for NoopProcessor {
    fn from_config(_cfg: &serde_json::Value) -> Self {
        NoopProcessor
    }

    #[inline]
    fn process(&self, _data: &mut Pdata) {
        // Passthrough: nothing to do.
    }
}

// ── StatusFilterProcessor ─────────────────────────────────────────────────────

/// Drops spans based on their OTel status code.
///
/// Config JSON example:
/// ```json
/// {"type": "status_filter", "drop_errors": true}
/// ```
///
/// When `drop_errors` is `true`, spans with `status.code == Error` are dropped.
/// This is primarily a demonstration of the config-driven `from_config` pattern;
/// it is not the recommended production treatment for error spans (errors are
/// high-signal and should normally be shipped).
pub struct StatusFilterProcessor {
    /// Drop spans whose status code is `Error`.
    pub drop_errors: bool,
}

impl ProcessorImpl for StatusFilterProcessor {
    fn from_config(cfg: &serde_json::Value) -> Self {
        let drop_errors = cfg.get("drop_errors").and_then(|v| v.as_bool()).unwrap_or(false);
        StatusFilterProcessor { drop_errors }
    }

    fn process(&self, data: &mut Pdata) {
        if self.drop_errors {
            if let Pdata::Spans(batch) = data {
                use crate::data_model::StatusCode;
                batch.spans.retain(|span| span.status.code != StatusCode::Error);
            }
            // Metrics and Logs variants are passed through unchanged.
        }
    }
}

// ── ProbeDropProcessor ────────────────────────────────────────────────────────

/// Drops spans whose `url.path` attribute matches a probe/health-check path.
///
/// Health-check endpoints (`/healthz`, `/readyz`, `/livez`, `/ping`,
/// `/metrics`, etc.) generate high-frequency, zero-signal spans that waste
/// trace storage and inflate cardinality.  This processor filters them in the
/// exporter pipeline — after ring drain, before encode — so probe traffic
/// never leaves the nginx host.
///
/// The drop list is configurable to avoid hard-coding deployment-specific
/// paths; the default list covers the common Kubernetes health-check and
/// Prometheus scrape paths.
///
/// # Config JSON example
/// ```json
/// {
///   "type": "probe_drop",
///   "paths": ["/healthz", "/readyz", "/livez", "/ping", "/metrics"]
/// }
/// ```
///
/// `paths` absent ⇒ the default list `["/healthz", "/readyz", "/livez",
/// "/ping", "/metrics"]` is used.  An empty `[]` disables all dropping
/// (equivalent to Noop for `Pdata::Spans`).
///
/// Non-`Pdata::Spans` variants are always passed through unchanged.
pub struct ProbeDropProcessor {
    /// Exact `url.path` values to drop.
    pub paths: std::vec::Vec<std::string::String>,
}

impl ProbeDropProcessor {
    /// Default probe paths (Kubernetes health checks + Prometheus scrape).
    const DEFAULT_PATHS: &'static [&'static str] =
        &["/healthz", "/readyz", "/livez", "/ping", "/metrics"];
}

impl ProcessorImpl for ProbeDropProcessor {
    fn from_config(cfg: &serde_json::Value) -> Self {
        let paths = if let Some(arr) = cfg.get("paths").and_then(|v| v.as_array()) {
            arr.iter().filter_map(|v| v.as_str()).map(|s| s.into()).collect()
        } else {
            Self::DEFAULT_PATHS.iter().map(|s| (*s).into()).collect()
        };
        ProbeDropProcessor { paths }
    }

    fn process(&self, data: &mut Pdata) {
        if let Pdata::Spans(batch) = data {
            batch.spans.retain(|span| {
                // Look up the url.path attribute and check against the drop list.
                let url_path = span.attributes.iter().find_map(|kv| {
                    if kv.key == "url.path" {
                        if let crate::data_model::AnyValue::String(ref s) = kv.value {
                            return Some(s.as_str());
                        }
                    }
                    None
                });
                // Retain the span unless its url.path is in the drop list.
                match url_path {
                    Some(path) => !self.paths.iter().any(|p| p == path),
                    None => true, // no url.path attribute → keep (conservative)
                }
            });
        }
        // Metrics and Logs variants are passed through unchanged.
    }
}

// ── Processor enum (static dispatch) ─────────────────────────────────────────

/// Enum over all built-in processor implementations.
///
/// Constructed once at exporter startup via [`Processor::from_config`].
/// The default is [`Processor::Noop`] — a zero-overhead passthrough.
///
/// Config shape passed to `from_config`:
/// ```json
/// {}                                              // → Noop (default)
/// {"type": "noop"}                                // → Noop
/// {"type": "status_filter", "drop_errors": true}  // → StatusFilter
/// {"type": "probe_drop"}                          // → ProbeDrop (default paths)
/// {"type": "probe_drop", "paths": ["/healthz"]}   // → ProbeDrop (custom paths)
/// ```
pub enum Processor {
    /// Zero-overhead passthrough (default).
    Noop(NoopProcessor),
    /// Config-driven drop-by-status filter.
    StatusFilter(StatusFilterProcessor),
    /// Config-driven probe/health-check span drop filter.
    ProbeDrop(ProbeDropProcessor),
}

impl Processor {
    /// Build a `Processor` from a JSON config blob.
    ///
    /// Dispatches on `cfg["type"]` (default `"noop"`).
    pub fn from_config(cfg: &serde_json::Value) -> Self {
        match cfg.get("type").and_then(|v| v.as_str()).unwrap_or("noop") {
            "status_filter" => Processor::StatusFilter(StatusFilterProcessor::from_config(cfg)),
            "probe_drop" => Processor::ProbeDrop(ProbeDropProcessor::from_config(cfg)),
            _ => Processor::Noop(NoopProcessor),
        }
    }

    /// Apply the processor to the payload in-place.
    #[inline]
    pub fn process(&self, data: &mut Pdata) {
        match self {
            Processor::Noop(p) => p.process(data),
            Processor::StatusFilter(p) => p.process(data),
            Processor::ProbeDrop(p) => p.process(data),
        }
    }
}

impl Default for Processor {
    /// Returns a [`Processor::Noop`] — zero-overhead passthrough.
    fn default() -> Self {
        Processor::Noop(NoopProcessor)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_model::{
        Batch, LogsBatch, Resource, Scope, Span, SpanKind, SpanStatus, SpansBatch, StatusCode,
    };

    fn make_span(status_code: StatusCode) -> Span {
        make_span_with_path(status_code, "")
    }

    fn make_span_with_path(status_code: StatusCode, url_path: &str) -> Span {
        use crate::data_model::AnyValue;
        let mut attributes = std::vec![];
        if !url_path.is_empty() {
            attributes.push(crate::data_model::KeyValue {
                key: "url.path".into(),
                value: AnyValue::String(url_path.into()),
            });
        }
        Span {
            trace_id: std::vec![0u8; 16],
            span_id: std::vec![0u8; 8],
            parent_span_id: std::vec![0u8; 8],
            flags: 0,
            name: "test".into(),
            kind: SpanKind::Server,
            start_time_unix_nano: 0,
            end_time_unix_nano: 1_000,
            attributes,
            events: std::vec![],
            links: std::vec![],
            status: SpanStatus { code: status_code, message: std::string::String::new() },
        }
    }

    fn make_spans_batch(spans: std::vec::Vec<Span>) -> SpansBatch {
        SpansBatch {
            resource: Resource { attributes: std::vec![] },
            scope: Scope { name: "test".into(), version: "0.1".into() },
            spans,
        }
    }

    fn make_pdata_spans(spans: std::vec::Vec<Span>) -> Pdata {
        Pdata::Spans(make_spans_batch(spans))
    }

    fn unwrap_spans(pd: Pdata) -> SpansBatch {
        match pd {
            Pdata::Spans(b) => b,
            _ => panic!("expected Pdata::Spans"),
        }
    }

    fn make_pdata_metrics() -> Pdata {
        Pdata::Metrics(Batch {
            resource: Resource { attributes: std::vec![] },
            scope: Scope { name: "test".into(), version: "0.1".into() },
            metrics: std::vec![],
        })
    }

    fn make_pdata_logs() -> Pdata {
        Pdata::Logs(LogsBatch {
            resource: Resource { attributes: std::vec![] },
            scope: Scope { name: "test".into(), version: "0.1".into() },
            logs: std::vec![],
        })
    }

    /// Passthrough — Pdata::Spans is left unchanged.
    #[test]
    fn noop_processor_leaves_batch_unchanged() {
        let p = NoopProcessor;
        let mut pd = make_pdata_spans(std::vec![
            make_span(StatusCode::Ok),
            make_span(StatusCode::Error),
            make_span(StatusCode::Unset),
        ]);
        p.process(&mut pd);
        assert_eq!(unwrap_spans(pd).spans.len(), 3);
    }

    /// `from_config` with null — still constructs a valid Noop.
    #[test]
    fn noop_from_config_null_input() {
        let p = NoopProcessor::from_config(&serde_json::Value::Null);
        let mut pd = make_pdata_spans(std::vec![make_span(StatusCode::Ok)]);
        p.process(&mut pd);
        assert_eq!(unwrap_spans(pd).spans.len(), 1);
    }

    /// Noop is a true passthrough for Metrics and Logs variants too.
    #[test]
    fn noop_processor_passes_through_all_variants() {
        let p = NoopProcessor;
        let mut m = make_pdata_metrics();
        p.process(&mut m);
        assert!(matches!(m, Pdata::Metrics(_)));
        let mut l = make_pdata_logs();
        p.process(&mut l);
        assert!(matches!(l, Pdata::Logs(_)));
    }

    /// StatusFilter with `drop_errors: true` removes error spans.
    #[test]
    fn status_filter_drops_errors_when_configured() {
        let cfg = serde_json::json!({"drop_errors": true});
        let p = StatusFilterProcessor::from_config(&cfg);
        let mut pd = make_pdata_spans(std::vec![
            make_span(StatusCode::Ok),
            make_span(StatusCode::Error),
            make_span(StatusCode::Unset),
        ]);
        p.process(&mut pd);
        let result = unwrap_spans(pd);
        assert_eq!(result.spans.len(), 2, "Error span must be dropped");
        for span in &result.spans {
            assert_ne!(span.status.code, StatusCode::Error, "No Error spans should remain");
        }
    }

    /// StatusFilter with `drop_errors: false` is a passthrough.
    #[test]
    fn status_filter_passthrough_when_drop_errors_false() {
        let cfg = serde_json::json!({"drop_errors": false});
        let p = StatusFilterProcessor::from_config(&cfg);
        let mut pd =
            make_pdata_spans(std::vec![make_span(StatusCode::Error), make_span(StatusCode::Error)]);
        p.process(&mut pd);
        assert_eq!(unwrap_spans(pd).spans.len(), 2);
    }

    /// StatusFilter passes through Metrics and Logs variants unchanged.
    #[test]
    fn status_filter_passes_through_non_span_variants() {
        let cfg = serde_json::json!({"drop_errors": true});
        let p = StatusFilterProcessor::from_config(&cfg);
        let mut m = make_pdata_metrics();
        p.process(&mut m);
        assert!(matches!(m, Pdata::Metrics(_)));
        let mut l = make_pdata_logs();
        p.process(&mut l);
        assert!(matches!(l, Pdata::Logs(_)));
    }

    /// `Processor::default()` is a passthrough (Noop).
    #[test]
    fn processor_default_is_noop() {
        let p = Processor::default();
        let mut pd =
            make_pdata_spans(std::vec![make_span(StatusCode::Ok), make_span(StatusCode::Error)]);
        p.process(&mut pd);
        assert_eq!(unwrap_spans(pd).spans.len(), 2);
    }

    /// `from_config` with `type: noop` returns Noop.
    #[test]
    fn processor_from_config_noop() {
        let p = Processor::from_config(&serde_json::json!({"type": "noop"}));
        let mut pd = make_pdata_spans(std::vec![make_span(StatusCode::Error)]);
        p.process(&mut pd);
        assert_eq!(unwrap_spans(pd).spans.len(), 1);
    }

    /// `from_config` with `type: status_filter, drop_errors: true` filters errors.
    #[test]
    fn processor_from_config_status_filter() {
        let p = Processor::from_config(&serde_json::json!({
            "type": "status_filter",
            "drop_errors": true
        }));
        let mut pd =
            make_pdata_spans(std::vec![make_span(StatusCode::Ok), make_span(StatusCode::Error)]);
        p.process(&mut pd);
        let result = unwrap_spans(pd);
        assert_eq!(result.spans.len(), 1);
        assert_eq!(result.spans[0].status.code, StatusCode::Ok);
    }

    /// Unknown `type` key falls back to Noop (permissive).
    #[test]
    fn processor_unknown_type_falls_back_to_noop() {
        let p = Processor::from_config(&serde_json::json!({"type": "future_unknown_processor"}));
        let mut pd = make_pdata_spans(std::vec![make_span(StatusCode::Error)]);
        p.process(&mut pd);
        assert_eq!(unwrap_spans(pd).spans.len(), 1);
    }

    // ── ProbeDropProcessor tests ──────────────────────────────────────────────

    /// S4 spec: 3 spans (/api/v1/users, /healthz, /metrics) with probe_drop
    /// default paths → 1 span (/api/v1/users).
    #[test]
    fn probe_drop_drops_health_and_metrics_paths() {
        let p = ProbeDropProcessor::from_config(&serde_json::Value::Null);
        let mut pd = make_pdata_spans(std::vec![
            make_span_with_path(StatusCode::Ok, "/api/v1/users"),
            make_span_with_path(StatusCode::Ok, "/healthz"),
            make_span_with_path(StatusCode::Ok, "/metrics"),
        ]);
        p.process(&mut pd);
        let result = unwrap_spans(pd);
        assert_eq!(result.spans.len(), 1, "only /api/v1/users should survive");
        if let crate::data_model::AnyValue::String(ref path) = result.spans[0].attributes[0].value {
            assert_eq!(path, "/api/v1/users");
        } else {
            panic!("url.path attribute not a string");
        }
    }

    /// All default probe paths are dropped.
    #[test]
    fn probe_drop_drops_all_default_paths() {
        let p = ProbeDropProcessor::from_config(&serde_json::Value::Null);
        for path in ProbeDropProcessor::DEFAULT_PATHS {
            let mut pd = make_pdata_spans(std::vec![make_span_with_path(StatusCode::Ok, path)]);
            p.process(&mut pd);
            assert_eq!(unwrap_spans(pd).spans.len(), 0, "path {path} should be dropped by default");
        }
    }

    /// Config absent (null) ⇒ default paths used (not a passthrough).
    #[test]
    fn probe_drop_from_config_null_uses_defaults() {
        let p = ProbeDropProcessor::from_config(&serde_json::Value::Null);
        assert!(!p.paths.is_empty(), "default paths must be populated from null config");
    }

    /// Custom paths override the defaults.
    #[test]
    fn probe_drop_custom_paths_override_defaults() {
        let p = ProbeDropProcessor::from_config(&serde_json::json!({"paths": ["/custom-health"]}));
        // Default path /healthz is NOT in the custom list → kept.
        let mut pd = make_pdata_spans(std::vec![make_span_with_path(StatusCode::Ok, "/healthz")]);
        p.process(&mut pd);
        assert_eq!(unwrap_spans(pd).spans.len(), 1, "/healthz not in custom list → kept");
        // /custom-health IS in the custom list → dropped.
        let mut pd =
            make_pdata_spans(std::vec![make_span_with_path(StatusCode::Ok, "/custom-health")]);
        p.process(&mut pd);
        assert_eq!(unwrap_spans(pd).spans.len(), 0, "/custom-health in custom list → dropped");
    }

    /// Empty paths list ⇒ complete passthrough.
    #[test]
    fn probe_drop_empty_paths_is_passthrough() {
        let p = ProbeDropProcessor::from_config(&serde_json::json!({"paths": []}));
        let mut pd = make_pdata_spans(std::vec![
            make_span_with_path(StatusCode::Ok, "/healthz"),
            make_span_with_path(StatusCode::Ok, "/metrics"),
        ]);
        p.process(&mut pd);
        assert_eq!(unwrap_spans(pd).spans.len(), 2, "empty paths → passthrough");
    }

    /// Span with no url.path attribute is kept (conservative).
    #[test]
    fn probe_drop_keeps_spans_without_url_path() {
        let p = ProbeDropProcessor::from_config(&serde_json::Value::Null);
        let mut pd = make_pdata_spans(std::vec![make_span(StatusCode::Ok)]);
        p.process(&mut pd);
        assert_eq!(unwrap_spans(pd).spans.len(), 1, "no url.path attribute → keep");
    }

    /// Metrics and Logs variants are passed through unchanged.
    #[test]
    fn probe_drop_passes_through_non_span_variants() {
        let p = ProbeDropProcessor::from_config(&serde_json::Value::Null);
        let mut m = make_pdata_metrics();
        p.process(&mut m);
        assert!(matches!(m, Pdata::Metrics(_)));
        let mut l = make_pdata_logs();
        p.process(&mut l);
        assert!(matches!(l, Pdata::Logs(_)));
    }

    /// Processor enum dispatches to ProbeDropProcessor correctly.
    #[test]
    fn processor_from_config_probe_drop() {
        let p = Processor::from_config(&serde_json::json!({"type": "probe_drop"}));
        let mut pd = make_pdata_spans(std::vec![
            make_span_with_path(StatusCode::Ok, "/api/v1/users"),
            make_span_with_path(StatusCode::Ok, "/healthz"),
            make_span_with_path(StatusCode::Ok, "/metrics"),
        ]);
        p.process(&mut pd);
        assert_eq!(
            unwrap_spans(pd).spans.len(),
            1,
            "probe_drop via Processor enum must drop /healthz and /metrics"
        );
    }
}
