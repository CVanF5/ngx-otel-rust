// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! `MetricSource` trait and implementations.
//!
//! Two implementations:
//!  - `StubStatusSource`: reads `ngx_stat_*` atomics
//!  - `InstrumentedSource`: reads per-worker shm slots

pub mod instrumented;
pub mod location_conf;
pub mod span_start;
// In a no-flag nginx build (`NGX_STAT_STUB` undefined →
// no `ngx_feature = "stat_stub"`) the stub_status source is never registered or
// collected (see `export::collect_all_sources`), so its items are dead code.
// We keep the module compiled (type/API coherence) but suppress the dead-code
// warnings that would otherwise fire only in that build config.
#[cfg_attr(not(ngx_feature = "stat_stub"), allow(dead_code))]
pub mod stub_status;
pub mod tls_cert;

use crate::data_model::Metric;

/// A source of OTel metrics.
///
/// The export loop calls `collect()` once per interval to gather the current
/// metric snapshot and append the resulting `Metric` instances to `out`.
///
/// Implementations MUST NOT allocate on the hot path (in `collect`).
/// Allocations within `collect` are acceptable because it runs only on the
/// designated export worker, not on the request path.
pub trait MetricSource {
    fn collect(&self) -> std::vec::Vec<Metric>;
}
