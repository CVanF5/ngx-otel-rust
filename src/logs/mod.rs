// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! OTel Logs producer/consumer.
//!
//! Top-level home for log-emission infrastructure: `severity` (level mapping),
//! `ring` (per-worker SPSC byte ring), `access`/`error_writer`/`coalesce`
//! (record producers), and the [`LogProducer`] trait — the API for pushing
//! records into the ring.
//!
//! Workers push fixed-shape records into their own per-worker ring (no locks,
//! no syscalls, no allocation on the hot path); the central exporter process
//! drains all rings each tick and encodes a [`crate::data_model::LogsBatch`].
//! This is the central dedicated-exporter model — do NOT pivot to per-worker
//! export.
//!
//! Each producer (access log-phase handler, error `ngx_log_writer_pt`) writes
//! to its own ring, so today there is no MPSC sharing; a future multi-module
//! producer would need a per-ring mutex or a lock-free MPSC ring.

pub mod access;
pub mod coalesce;
pub mod error_writer;
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
///   error-log writer).
///
/// # Wire format per record
/// `[u8 ngx_level][u64 ts_unix_nano_be][u8 kind][payload...]`; `kind = 0` is
/// access, `kind = 1` is error. The outer [`ring::WorkerSignalRing`] prepends
/// its own 4-byte length prefix.
pub trait LogProducer {
    /// Push a pre-formatted record into the ring for the current worker.
    ///
    /// Returns `true` on success, `false` if the ring was full (drop — the
    /// ring's `dropped` counter is incremented).
    fn push(&self, record: &[u8]) -> bool;
}

// ── WorkerRingProducer ───────────────────────────────────────────────────────

/// A thin [`LogProducer`] wrapper around a [`ring::WorkerSignalRing`].
///
/// Constructed by `LogPhaseHandler` on each request and by the error-log
/// writer on each error event. Zero cost: just a pointer view into shm.
pub struct WorkerRingProducer {
    /// View of the calling worker's ring (a raw pointer into shm).
    pub ring: ring::WorkerSignalRing,
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
