// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Per-location module configuration.
//!
//! [`LocationConf`] is allocated by nginx at config-parse time via the
//! `create_loc_conf` / `merge_loc_conf` hooks (wired in `lib.rs`) and is
//! read-only on the request hot path.
//!
//! # Directives
//! - `otel_trace <complex-value>` — per-location enable/disable; complex value
//!   allows `split_clients` ratio sampling.  Absent → disabled.
//! - `otel_trace_context ignore|extract|inject|propagate` — W3C propagation
//!   mode.  Default: `extract` (read inbound `traceparent`, do not inject
//!   outbound).
//! - `otel_span_name <complex-value>` — per-location span name override.
//!   Absent → built-in `"METHOD route_name"` format.
//! - `otel_span_attr <key> <value>` — add a custom attribute to every span
//!   emitted from this location.
//! - `otel_log_export on|off|if=<cond>` — per-location selection of which
//!   requests have an exception-tail log record exported.  Absent → no export
//!   (privacy-safe default).  Mirrors core `access_log … if=`.

use core::ptr;

use nginx_sys::{ngx_http_complex_value_t, ngx_str_t};
use ngx::http::{Merge, MergeConfigError};

// ── LogExportMode ──────────────────────────────────────────────────────────────

/// Per-location selection state for `otel_log_export`.
///
/// Decides whether the LOG-phase handler exports an exception-tail log record
/// for a request.  Nothing is exported unless an operator opts in, so the
/// default state is [`LogExportMode::Unset`] (treated as "no export").
///
/// Forms map to the variants as follows:
/// - bare `otel_log_export;` / `otel_log_export on;` → [`LogExportMode::All`]
/// - `otel_log_export off;` → [`LogExportMode::Off`]
/// - `otel_log_export if=<cond>;` → [`LogExportMode::If`] (the compiled
///   complex value is held in [`LocationConf::log_export_cv`])
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LogExportMode {
    /// Directive not set at this level (inherit from parent; resolves to no
    /// export when no ancestor sets it).
    Unset = 0,
    /// Explicitly disabled — no export, overriding any inherited selection.
    Off = 1,
    /// Export the exception-tail record for every request at this location.
    All = 2,
    /// Export only when the `if=<cond>` complex value is truthy at request time.
    If = 3,
}

// ── TraceContextMode ──────────────────────────────────────────────────────────

/// Traceparent propagation mode for `otel_trace_context`.
///
/// Controls whether the REWRITE-phase span-start handler reads the inbound
/// W3C `traceparent` header and/or injects one into the proxied request headers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TraceContextMode {
    /// Do not read or write `traceparent` headers.
    Ignore = 0,
    /// Read the inbound `traceparent`; do not inject outbound.  **(Default)**
    Extract = 1,
    /// Inject a `traceparent` outbound; do not read inbound.
    Inject = 2,
    /// Read inbound `traceparent` **and** inject outbound (full W3C propagation).
    Propagate = 3,
}

/// Raw byte encoding for "not set" (`trace_context_raw` sentinel).
const TRACE_CONTEXT_UNSET: u8 = 0xFF;

/// Raw byte encoding for "not set" (`log_export_raw` sentinel).
const LOG_EXPORT_UNSET: u8 = LogExportMode::Unset as u8;

// ── LocationConf ─────────────────────────────────────────────────────────────

/// Per-location module configuration.
///
/// Allocated on the nginx location conf pool at config-parse time.
/// All fields are read-only after `merge_loc_conf` returns — no locking
/// needed on the hot path.
///
/// # Safety / layout
/// Contains raw pointers (`otel_trace`, `span_name_cv`) into nginx pool memory;
/// valid for the full process lifetime (conf pool is never freed while workers
/// are running).  The `span_attrs` Vec is heap-allocated and dropped when the
/// nginx pool cleanup fires (via `pool.allocate::<LocationConf>(..)`).
pub struct LocationConf {
    /// Complex value for `otel_trace <expr>`.
    ///
    /// `null` = directive not set for this location.  When null, tracing is
    /// **disabled** for this location (zero-cost — no REWRITE handler work
    /// beyond the null check).
    ///
    /// When non-null, evaluated at request time:
    /// - truthy (non-empty, not `"0"`, not `"off"`) → tracing enabled.
    /// - falsy → tracing disabled (REWRITE handler returns `NGX_DECLINED`).
    pub otel_trace: *mut ngx_http_complex_value_t,

    /// Raw encoding of `otel_trace_context` for this location.
    ///
    /// `0xFF` = directive not set (inherit from parent; resolved to
    /// `TraceContextMode::Extract` by [`LocationConf::trace_context()`]).
    /// 0 = ignore, 1 = extract, 2 = inject, 3 = propagate.
    trace_context_raw: u8,

    /// Complex value for `otel_span_name <expr>`.
    ///
    /// `null` = not set; use built-in `"METHOD route_name"` format.
    pub span_name_cv: *mut ngx_http_complex_value_t,

    /// Extra span attributes from `otel_span_attr <key> <value>`.
    ///
    /// Populated at config time (keys and values are `ngx_str_t` slices into
    /// the nginx config buffer — valid for process lifetime).
    /// Read on the hot path only for **sampled** requests.
    pub span_attrs: std::vec::Vec<(ngx_str_t, ngx_str_t)>,

    /// Raw encoding of `otel_log_export` mode for this location.
    ///
    /// 0 = unset (inherit from parent; resolves to no export), 1 = off,
    /// 2 = all, 3 = if.  Accessed via [`LocationConf::log_export_mode`].
    log_export_raw: u8,

    /// Complex value for `otel_log_export if=<cond>`.
    ///
    /// `null` unless the mode is [`LogExportMode::If`].  Evaluated at the LOG
    /// phase; truthy ⇒ export the exception-tail record (truthiness mirrors
    /// core nginx: falsy iff empty or the single byte `"0"`).
    pub log_export_cv: *mut ngx_http_complex_value_t,
}

impl LocationConf {
    /// Effective `otel_trace_context` mode, defaulting to `Extract`.
    #[inline]
    pub fn trace_context(&self) -> TraceContextMode {
        match self.trace_context_raw {
            0 => TraceContextMode::Ignore,
            1 => TraceContextMode::Extract,
            2 => TraceContextMode::Inject,
            3 => TraceContextMode::Propagate,
            _ => TraceContextMode::Extract, // UNSET → default Extract
        }
    }

    /// Record an explicit `otel_trace_context` value.
    #[inline]
    pub fn set_trace_context(&mut self, mode: TraceContextMode) {
        self.trace_context_raw = mode as u8;
    }

    /// Returns `true` if `otel_trace_context` was explicitly set for this
    /// location (as opposed to being the inherited default).
    #[inline]
    pub fn trace_context_is_set(&self) -> bool {
        self.trace_context_raw != TRACE_CONTEXT_UNSET
    }

    /// Effective `otel_log_export` mode for this location.
    #[inline]
    pub fn log_export_mode(&self) -> LogExportMode {
        match self.log_export_raw {
            1 => LogExportMode::Off,
            2 => LogExportMode::All,
            3 => LogExportMode::If,
            _ => LogExportMode::Unset,
        }
    }

    /// Record an explicit `otel_log_export` mode.
    #[inline]
    pub fn set_log_export_mode(&mut self, mode: LogExportMode) {
        self.log_export_raw = mode as u8;
    }

    /// Returns `true` if `otel_log_export` was explicitly set for this location
    /// (as opposed to being the inherited default).
    #[inline]
    pub fn log_export_is_set(&self) -> bool {
        self.log_export_raw != LOG_EXPORT_UNSET
    }
}

impl Default for LocationConf {
    fn default() -> Self {
        Self {
            otel_trace: ptr::null_mut(),
            trace_context_raw: TRACE_CONTEXT_UNSET, // inherit / default Extract
            span_name_cv: ptr::null_mut(),
            span_attrs: std::vec::Vec::new(),
            log_export_raw: LOG_EXPORT_UNSET, // inherit / no export
            log_export_cv: ptr::null_mut(),
        }
    }
}

impl Merge for LocationConf {
    fn merge(&mut self, prev: &LocationConf) -> Result<(), MergeConfigError> {
        // Inherit otel_trace from parent when not set at this level.
        if self.otel_trace.is_null() {
            self.otel_trace = prev.otel_trace;
        }
        // Inherit trace_context from parent when not set at this level.
        if !self.trace_context_is_set() {
            self.trace_context_raw = prev.trace_context_raw;
        }
        // Inherit span_name_cv from parent when not set at this level.
        if self.span_name_cv.is_null() {
            self.span_name_cv = prev.span_name_cv;
        }
        // Inherit otel_log_export from parent when not set at this level.
        // An explicit `off`/`on`/`if=` at this level wins over the inherited
        // value (mirrors core access_log inheritance).
        if !self.log_export_is_set() {
            self.log_export_raw = prev.log_export_raw;
            self.log_export_cv = prev.log_export_cv;
        }
        // span_attrs: each location defines its own independent set (child wins;
        // no inheritance — mirrors the C++ module's addSpanAttr accumulation at
        // each parse level).
        Ok(())
    }
}
