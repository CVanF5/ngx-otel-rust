// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! `MetricSource` trait and implementations.
//!
//! Phase 1.1 provides two implementations:
//!  - `StubStatusSource`: reads `ngx_stat_*` atomics (Step 5)
//!  - `InstrumentedSource`: reads per-worker shm slots (Step 6)

pub mod instrumented;
pub mod stub_status;

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
