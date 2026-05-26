// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! gRPC bridge for OTLP over hyper h2 on ngx-rust's executor.  No Tokio
//! runtime.  Sub-modules: `executor`, `shim`.
//!
//! # Architecture
//!
//! ```text
//!               tonic::client::Grpc<Shim>          (codec + framing only;
//!                           ↓                       no transport feature)
//!                    Shim: tower::Service
//!                           ↓
//!               hyper::client::conn::http2::SendRequest<B>
//!                           ↓
//!                    Compat<NgxConnIo>             (hyper rt → tokio io)
//!                           ↓
//!               NgxConnIo: hyper::rt::Read + Write
//!                           ↓
//!               ngx_peer_connection_t              (NGINX C side)
//!                           ↓
//!               epoll/kqueue → C event handlers   (wake() via Waker, NO spin)
//! ```

pub mod executor;
pub mod shim;

// In-worker gRPC viability harness: gated behind `test-support` so it never
// compiles into production builds.  See `smoke.rs` for the rationale.
#[cfg(any(test, feature = "test-support"))]
pub mod smoke;
