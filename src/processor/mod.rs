// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Config-driven `Processor` trait for the exporter's span pipeline — Phase 3.6.
//!
//! # Pipeline position
//!
//! ```text
//! collect_span_records → [SpanProcessor::process] → OtlpTracesEncoder → send
//! ```
//!
//! Processors are constructed once at exporter startup via [`SpanProcessor::from_config`].
//! The default processor is [`NoopProcessor`] — a zero-overhead passthrough.
//!
//! # Staged follow-on: remote reconfiguration
//!
//! **Static config only** in this phase — the processor config is read once at exporter
//! startup and never reloaded.  The bidi control loop (Phase 5 / §1.2) will deliver a
//! new config payload to the exporter via the control-shm channel (§1.3.3); the exporter
//! will call [`SpanProcessor::from_config`] with the new blob and swap the processor.
//! The `from_config` API is designed for this: it is a pure function returning a new value,
//! so the swap is a single assignment with no state migration.
//!
//! # Static dispatch
//!
//! [`SpanProcessor`] is a concrete enum over all built-in processor implementations.
//! This keeps dispatch static and matches the pattern used by [`crate::export`]'s
//! `ExportTransport` — the exporter is already on the heap; one enum avoids a
//! `Box<dyn Processor>` indirection.

use crate::data_model::SpansBatch;

// ── `Processor` trait ────────────────────────────────────────────────────────

/// Exporter-side processing stage in the span pipeline.
///
/// Receives a [`SpansBatch`] after drain and before encode.  May filter,
/// transform, or enrich spans.
///
/// # Config-driven construction
///
/// Every implementation provides [`Processor::from_config`] so the exporter
/// can instantiate processors from a JSON config blob (operator directive,
/// or — in a future phase — the bidi control channel).
///
/// # Static config only
///
/// This phase: static config, read once at exporter startup.
/// Remote reconfiguration (bidi + control-shm) is a staged follow-on.
pub trait Processor {
    /// Construct a processor from a JSON config blob.
    ///
    /// Implementations should be permissive: unknown keys are ignored,
    /// missing required keys fall back to defaults.
    fn from_config(cfg: &serde_json::Value) -> Self
    where
        Self: Sized;

    /// Process a batch of spans, returning the (possibly modified) batch.
    fn process(&self, batch: SpansBatch) -> SpansBatch;
}

// ── NoopProcessor ─────────────────────────────────────────────────────────────

/// Passthrough processor — returns the batch unchanged.
///
/// This is the default [`SpanProcessor`] variant.  It adds no overhead beyond
/// a function call and a move.
pub struct NoopProcessor;

impl Processor for NoopProcessor {
    fn from_config(_cfg: &serde_json::Value) -> Self {
        NoopProcessor
    }

    #[inline]
    fn process(&self, batch: SpansBatch) -> SpansBatch {
        batch
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

impl Processor for StatusFilterProcessor {
    fn from_config(cfg: &serde_json::Value) -> Self {
        let drop_errors = cfg.get("drop_errors").and_then(|v| v.as_bool()).unwrap_or(false);
        StatusFilterProcessor { drop_errors }
    }

    fn process(&self, mut batch: SpansBatch) -> SpansBatch {
        if self.drop_errors {
            use crate::data_model::StatusCode;
            batch.spans.retain(|span| span.status.code != StatusCode::Error);
        }
        batch
    }
}

// ── SpanProcessor enum (static dispatch) ─────────────────────────────────────

/// Enum over all built-in span processor implementations.
///
/// Constructed once at exporter startup via [`SpanProcessor::from_config`].
/// The default is [`SpanProcessor::Noop`] — a zero-overhead passthrough.
///
/// Config shape passed to `from_config`:
/// ```json
/// {}                                              // → Noop (default)
/// {"type": "noop"}                                // → Noop
/// {"type": "status_filter", "drop_errors": true}  // → StatusFilter
/// ```
pub enum SpanProcessor {
    /// Zero-overhead passthrough (default).
    Noop(NoopProcessor),
    /// Config-driven drop-by-status filter.
    StatusFilter(StatusFilterProcessor),
}

impl SpanProcessor {
    /// Build a `SpanProcessor` from a JSON config blob.
    ///
    /// Dispatches on `cfg["type"]` (default `"noop"`).
    pub fn from_config(cfg: &serde_json::Value) -> Self {
        match cfg.get("type").and_then(|v| v.as_str()).unwrap_or("noop") {
            "status_filter" => SpanProcessor::StatusFilter(StatusFilterProcessor::from_config(cfg)),
            _ => SpanProcessor::Noop(NoopProcessor),
        }
    }

    /// Apply the processor to a batch of spans.
    #[inline]
    pub fn process(&self, batch: SpansBatch) -> SpansBatch {
        match self {
            SpanProcessor::Noop(p) => p.process(batch),
            SpanProcessor::StatusFilter(p) => p.process(batch),
        }
    }
}

impl Default for SpanProcessor {
    /// Returns a [`SpanProcessor::Noop`] — zero-overhead passthrough.
    fn default() -> Self {
        SpanProcessor::Noop(NoopProcessor)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_model::{Resource, Scope, Span, SpanKind, SpanStatus, StatusCode};

    fn make_span(status_code: StatusCode) -> Span {
        Span {
            trace_id: std::vec![0u8; 16],
            span_id: std::vec![0u8; 8],
            parent_span_id: std::vec![0u8; 8],
            flags: 0,
            name: "test".into(),
            kind: SpanKind::Server,
            start_time_unix_nano: 0,
            end_time_unix_nano: 1_000,
            attributes: std::vec![],
            events: std::vec![],
            links: std::vec![],
            status: SpanStatus { code: status_code, message: std::string::String::new() },
        }
    }

    fn make_batch(spans: std::vec::Vec<Span>) -> SpansBatch {
        SpansBatch {
            resource: Resource { attributes: std::vec![] },
            scope: Scope { name: "test".into(), version: "0.1".into() },
            spans,
        }
    }

    /// Passthrough — batch is returned unchanged.
    #[test]
    fn noop_processor_leaves_batch_unchanged() {
        let p = NoopProcessor;
        let batch = make_batch(std::vec![
            make_span(StatusCode::Ok),
            make_span(StatusCode::Error),
            make_span(StatusCode::Unset),
        ]);
        let result = p.process(batch);
        assert_eq!(result.spans.len(), 3);
    }

    /// `from_config` with null — still constructs a valid Noop.
    #[test]
    fn noop_from_config_null_input() {
        let p = NoopProcessor::from_config(&serde_json::Value::Null);
        let batch = make_batch(std::vec![make_span(StatusCode::Ok)]);
        let result = p.process(batch);
        assert_eq!(result.spans.len(), 1);
    }

    /// StatusFilter with `drop_errors: true` removes error spans.
    #[test]
    fn status_filter_drops_errors_when_configured() {
        let cfg = serde_json::json!({"drop_errors": true});
        let p = StatusFilterProcessor::from_config(&cfg);
        let batch = make_batch(std::vec![
            make_span(StatusCode::Ok),
            make_span(StatusCode::Error),
            make_span(StatusCode::Unset),
        ]);
        let result = p.process(batch);
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
        let batch =
            make_batch(std::vec![make_span(StatusCode::Error), make_span(StatusCode::Error),]);
        let result = p.process(batch);
        assert_eq!(result.spans.len(), 2);
    }

    /// `SpanProcessor::default()` is a passthrough (Noop).
    #[test]
    fn span_processor_default_is_noop() {
        let p = SpanProcessor::default();
        let batch = make_batch(std::vec![make_span(StatusCode::Ok), make_span(StatusCode::Error),]);
        let result = p.process(batch);
        assert_eq!(result.spans.len(), 2);
    }

    /// `from_config` with `type: noop` returns Noop.
    #[test]
    fn span_processor_from_config_noop() {
        let p = SpanProcessor::from_config(&serde_json::json!({"type": "noop"}));
        let batch = make_batch(std::vec![make_span(StatusCode::Error)]);
        let result = p.process(batch);
        assert_eq!(result.spans.len(), 1);
    }

    /// `from_config` with `type: status_filter, drop_errors: true` filters errors.
    #[test]
    fn span_processor_from_config_status_filter() {
        let p = SpanProcessor::from_config(&serde_json::json!({
            "type": "status_filter",
            "drop_errors": true
        }));
        let batch = make_batch(std::vec![make_span(StatusCode::Ok), make_span(StatusCode::Error),]);
        let result = p.process(batch);
        assert_eq!(result.spans.len(), 1);
        assert_eq!(result.spans[0].status.code, StatusCode::Ok);
    }

    /// Unknown `type` key falls back to Noop (permissive).
    #[test]
    fn span_processor_unknown_type_falls_back_to_noop() {
        let p =
            SpanProcessor::from_config(&serde_json::json!({"type": "future_unknown_processor"}));
        let batch = make_batch(std::vec![make_span(StatusCode::Error)]);
        let result = p.process(batch);
        assert_eq!(result.spans.len(), 1);
    }
}
