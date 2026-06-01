// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! [`SendRequestService`]: adapts `hyper::client::conn::http2::SendRequest<B>`
//! into a `tower_service::Service<http::Request<B>>` that
//! `tonic::client::Grpc<T>` can consume.
//!
//! # Design
//!
//! `tonic::client::Grpc` requires a `GrpcService`, which is a blanket-impl'd
//! alias for `tower_service::Service<http::Request<B>, Response =
//! http::Response<ResBody>>`.  Hyper's HTTP/2 client provides exactly this
//! interface via `SendRequest`, but in a non-tower shape.  This shim bridges
//! the two.
//!
//! # Ownership
//!
//! `SendRequest<B>` is cheaply cloneable — it is a handle (channel sender)
//! over the underlying h2 connection, not the connection itself.  Cloning
//! `SendRequestService<B>` is therefore cheap.
//!
//! # Backpressure
//!
//! `poll_ready` forwards directly to `SendRequest::poll_ready`.  In hyper 1.x
//! h2 this always returns `Poll::Ready(Ok(()))` unless the connection is
//! closed.  See `SendRequest::poll_ready` docs for the current semantics.
//!
//! # Box allocation note
//!
//! The associated `Future` type is `Pin<Box<dyn Future<...>>>` because the
//! unnamed `impl Future` returned by `SendRequest::send_request` cannot be
//! named as an associated type on stable Rust 1.81.  This incurs one heap
//! allocation per gRPC call.  TODO(phase-1.2-item-N): revisit once TAIT is
//! stabilised if per-call allocation becomes a hot-path concern.

use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::body::Incoming;
use hyper::client::conn::http2::SendRequest;
use tower_service::Service;

/// Wraps a `hyper::client::conn::http2::SendRequest<B>` so that
/// `tonic::client::Grpc<T>` can drive gRPC calls through it.
///
/// See module-level documentation for ownership and backpressure semantics.
#[derive(Clone)]
pub struct SendRequestService<B> {
    inner: SendRequest<B>,
}

impl<B> SendRequestService<B> {
    /// Wrap an existing `SendRequest` handle.
    pub fn new(inner: SendRequest<B>) -> Self {
        Self { inner }
    }
}

impl<B> core::fmt::Debug for SendRequestService<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendRequestService").finish_non_exhaustive()
    }
}

/// The boxed future type returned by [`SendRequestService::call`].
///
/// One heap allocation per gRPC call — see module doc for discussion.
pub type ResponseFuture =
    Pin<Box<dyn Future<Output = Result<http::Response<Incoming>, hyper::Error>> + 'static>>;

impl<B> Service<http::Request<B>> for SendRequestService<B>
where
    B: hyper::body::Body + 'static,
{
    type Response = http::Response<Incoming>;
    type Error = hyper::Error;
    type Future = ResponseFuture;

    /// Forwards to `SendRequest::poll_ready`.
    ///
    /// In hyper 1.x HTTP/2 this returns `Ready(Ok(()))` whenever the
    /// connection is open.  A `Ready(Err(_))` signals that the connection
    /// is closed and no further requests should be sent.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Sends the request via the underlying `SendRequest` handle.
    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let fut = self.inner.send_request(req);
        Box::pin(fut)
    }
}

#[cfg(test)]
mod tests {
    use super::SendRequestService;
    use hyper::body::Incoming;

    /// Type-level check: `SendRequestService<B>` implements
    /// `tower_service::Service<http::Request<B>>` with the correct associated
    /// types, and satisfies `tonic::client::GrpcService<B>` — which is the
    /// bound that `tonic::client::Grpc::new` ultimately needs.
    ///
    /// No real I/O is performed; the test exists solely to catch compile-time
    /// type mismatches (wrong Response/Error types, missing trait impls, etc.).
    #[test]
    fn send_request_service_satisfies_grpc_service_bounds() {
        use bytes::Bytes;
        use http_body_util::Empty;

        // Compile-time assertion helper: T must implement tower_service::Service<Req>.
        fn assert_tower_service<T, Req>()
        where
            T: tower_service::Service<Req>,
        {
        }

        // Compile-time assertion helper: T must implement tonic GrpcService<B>.
        fn assert_grpc_service<T, B>()
        where
            T: tonic::client::GrpcService<B>,
        {
        }

        type Body = Empty<Bytes>;
        type Svc = SendRequestService<Body>;
        type Req = http::Request<Body>;

        // Verify tower::Service bound.
        assert_tower_service::<Svc, Req>();

        // Verify GrpcService bound (what tonic::client::Grpc<T> requires).
        assert_grpc_service::<Svc, Body>();

        // Verify that tonic::client::Grpc::new accepts our service type.
        // This will NOT be called at runtime but must compile.
        fn grpc_new_accepts_shim<B>()
        where
            B: hyper::body::Body + 'static,
            SendRequestService<B>: tonic::client::GrpcService<B>,
        {
            // If this function body compiles the type constraints are satisfied.
            let _type_check: fn(
                SendRequestService<B>,
            ) -> tonic::client::Grpc<SendRequestService<B>> = |svc| tonic::client::Grpc::new(svc);
        }

        grpc_new_accepts_shim::<Body>();

        // Verify Clone impl.
        fn assert_clone<T: Clone>() {}
        assert_clone::<SendRequestService<Empty<Bytes>>>();

        // Verify Debug impl.
        fn assert_debug<T: core::fmt::Debug>() {}
        assert_debug::<SendRequestService<Empty<Bytes>>>();

        // Verify the ResponseFuture associated type is correct.
        fn assert_response_future<T>()
        where
            T: tower_service::Service<
                http::Request<Empty<Bytes>>,
                Response = http::Response<Incoming>,
                Error = hyper::Error,
            >,
        {
        }
        assert_response_future::<SendRequestService<Empty<Bytes>>>();
    }
}
