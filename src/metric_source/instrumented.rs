// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Per-request instrumented metric source (Step 6).
//!
//! Reads the per-worker shm slot counters aggregated across all workers.

// TODO(step-6): implement InstrumentedSource that sums WorkerSlots across all workers.
