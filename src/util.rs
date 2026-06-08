// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Shared utility helpers used across crate modules.

/// Return the current wall-clock time as Unix nanoseconds.
///
/// Used by the exporter and metric-source modules to stamp OTLP timestamps.
/// All callers run on the exporter process (not the hot request path), so
/// `std::time` is appropriate — `ngx_timeofday()` is not needed here.
///
/// Single-homed here so that a future change to the clock source (e.g.
/// switching to `ngx_cached_time` for monotonic-safety) is a one-place edit.
#[inline]
pub(crate) fn now_unix_nano() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}
