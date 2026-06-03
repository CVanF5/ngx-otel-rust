// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! OTel Logs producer/consumer.
//!
//! This module is the top-level home for all log-emission infrastructure:
//!
//! - `severity` — nginx log level → OTel SeverityNumber mapping (Step 3).
//! - `ring`     — per-worker SPSC lock-free byte ring (Step 5 + FU3).
//! - `access`   — access-record formatter (Step 7).
//! - [`LogProducer`] trait — the platform-axis API for pushing records into
//!   the ring (Step 6).
//!
//! # Architecture
//! Workers push fixed-shape records into their own per-worker ring buffer
//! (no locks, no syscalls, no allocation on the hot path).  The central
//! `nginx: otel exporter` process drains all worker rings each tick,
//! encodes a [`crate::data_model::LogsBatch`], and sends it over the
//! selected transport.
//!
//! This is the **central dedicated-exporter model** (proposal §6.5); do
//! NOT pivot to per-worker export.
//!
//! # Future — MPSC concern
//! Phase 2 has two single-context producers (access: log-phase handler,
//! error: `ngx_log_writer_pt` callback).  Each producer writes to its own
//! ring.  Multi-module MPSC sharing (Phase N) would need a per-ring mutex
//! or a lock-free MPSC ring; that complexity is deferred.

pub mod access;
pub mod ring;
pub mod severity;

// ── LogProducer trait ────────────────────────────────────────────────────────

/// Canonical entry point for **all** log emission in this crate.
///
/// Implementors push one length-prefixed record into the calling worker's
/// per-worker logs ring using strictly atomic operations.
///
/// # Invariants
/// - The caller is on a worker thread (worker process or master).
/// - The caller does NOT hold any nginx mutex.
/// - The caller may be a re-entrant context (signal handler); producers
///   must use their own re-entrancy guard if relevant (mandatory for the
///   error-log writer; see Phase 2.2).
///
/// # Wire format per record
/// `[u8 ngx_level][u64 ts_unix_nano_be][u8 kind][payload...]`
/// where `kind = 0` is access, `kind = 1` is error.  The outer
/// [`ring::LogsWorkerRing`] prepends its own 4-byte length prefix.
pub trait LogProducer {
    /// Push a pre-formatted record into the ring for the current worker.
    ///
    /// Returns `true` on success, `false` if the ring was full (drop — the
    /// ring's `dropped` counter is incremented).
    fn push(&self, record: &[u8]) -> bool;
}

// ── WorkerRingProducer ───────────────────────────────────────────────────────

/// A thin [`LogProducer`] wrapper around a [`ring::LogsWorkerRing`].
///
/// Constructed by `LogPhaseHandler` on each request (Step 8) and by the
/// error-log writer on each error event (Phase 2.2).  Zero cost: just an
/// opaque view (raw pointer) into the ring in shm.
pub struct WorkerRingProducer {
    /// View of the calling worker's ring (a raw pointer into shm).
    pub ring: ring::LogsWorkerRing,
}

impl LogProducer for WorkerRingProducer {
    #[inline]
    fn push(&self, record: &[u8]) -> bool {
        self.ring.push(record)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirm `LogProducer` is dyn-compatible — future modules will use
    /// `Box<dyn LogProducer>` or `&dyn LogProducer`.
    #[test]
    fn log_producer_trait_object_safe() {
        // If this compiles, the trait is dyn-compatible.
        fn accepts_dyn(_producer: &dyn LogProducer) {}

        // Allocate a tiny ring and wrap it in WorkerRingProducer.
        let (_buf, ring) = ring::tests::make_ring_small();
        let producer = WorkerRingProducer { ring };
        accepts_dyn(&producer);
    }
}
