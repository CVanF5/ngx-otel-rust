// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Shared utility helpers used across crate modules.

/// Return the current wall-clock time as Unix nanoseconds (OTLP timestamps).
///
/// Callers run on the exporter process, not the hot request path, so `std::time`
/// is used rather than `ngx_timeofday()`.
#[inline]
pub(crate) fn now_unix_nano() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

/// Return the current wall-clock time as Unix seconds (crash-loop backoff window).
#[inline]
pub(crate) fn now_unix_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
