// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! OTel Logs producer/consumer.
//!
//! This module is the top-level home for all log-emission infrastructure:
//!
//! - `severity` — nginx log level → OTel SeverityNumber mapping (Step 3).
//! - `ring`     — per-worker SPSC lock-free byte ring (Step 5).
//! - `access`   — access-record formatter (Step 7).
//! - `LogProducer` trait — the platform-axis API for pushing records into
//!   the ring (Step 6).
//!
//! # Architecture
//! Workers push fixed-shape records into their own per-worker ring buffer
//! (no locks, no syscalls, no allocation on the hot path).  The central
//! `nginx: otel exporter` process drains all worker rings each tick,
//! encodes a `LogsBatch`, and sends it over the selected transport.
//!
//! This is the **central dedicated-exporter model** (proposal §6.5); do
//! NOT pivot to per-worker export.

pub mod severity;
