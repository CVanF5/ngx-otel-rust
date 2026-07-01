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
// Without `ngx_feature = "stat_stub"` this source is never registered
// (see `drain::collect_all_sources`); keep it compiled for API coherence but
// suppress the resulting dead-code warnings.
#[cfg_attr(not(ngx_feature = "stat_stub"), allow(dead_code))]
pub mod stub_status;
pub mod tls_cert;

use crate::data_model::Metric;

/// A source of OTel metrics.
///
/// The export loop calls `collect()` once per interval to gather the current
/// metric snapshot.
///
/// `collect` runs only on the export worker, never on the request path, so it
/// may allocate; implementations must not allocate on the request path itself.
pub trait MetricSource {
    fn collect(&self) -> std::vec::Vec<Metric>;
}
