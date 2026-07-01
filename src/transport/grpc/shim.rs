// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! [`SendRequestService`]: adapts `hyper::client::conn::http2::SendRequest<B>`
//! into a `tower_service::Service<http::Request<B>>` that
//! `tonic::client::Grpc<T>` can consume (tonic requires `GrpcService`, a
//! blanket alias for that `Service` bound; hyper's h2 client exposes the same
//! interface but in a non-tower shape).
//!
//! # Ownership
//! `SendRequest<B>` is a cheap handle (channel sender) over the h2
//! connection, not the connection itself — cloning is cheap.
//!
//! # Box allocation note
//! `Future` is `Pin<Box<dyn Future<...>>>` because the unnamed
//! `impl Future` from `SendRequest::send_request` can't be named as an
//! associated type on stable Rust 1.81 — one heap allocation per gRPC call.
//! TODO(phase-1.2-item-N): revisit once TAIT is stabilised.

use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::body::Incoming;
use hyper::client::conn::http2::SendRequest;
use tower_service::Service;

/// Wraps a `hyper::client::conn::http2::SendRequest<B>` so that
/// `tonic::client::Grpc<T>` can drive gRPC calls through it.
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
pub type ResponseFuture =
    Pin<Box<dyn Future<Output = Result<http::Response<Incoming>, hyper::Error>> + 'static>>;

impl<B> Service<http::Request<B>> for SendRequestService<B>
where
    B: hyper::body::Body + 'static,
{
    type Response = http::Response<Incoming>;
    type Error = hyper::Error;
    type Future = ResponseFuture;

    /// Forwards to `SendRequest::poll_ready`. `Ready(Err(_))` means the
    /// connection is closed and no further requests should be sent.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let fut = self.inner.send_request(req);
        Box::pin(fut)
    }
}

#[cfg(test)]
mod tests {
    use super::SendRequestService;
    use hyper::body::Incoming;

    /// Type-level check only: `SendRequestService<B>` satisfies the
    /// `tower_service::Service` + `tonic::client::GrpcService<B>` bounds that
    /// `tonic::client::Grpc::new` needs. No real I/O is performed.
    #[test]
    fn send_request_service_satisfies_grpc_service_bounds() {
        use bytes::Bytes;
        use http_body_util::Empty;

        fn assert_tower_service<T, Req>()
        where
            T: tower_service::Service<Req>,
        {
        }

        fn assert_grpc_service<T, B>()
        where
            T: tonic::client::GrpcService<B>,
        {
        }

        type Body = Empty<Bytes>;
        type Svc = SendRequestService<Body>;
        type Req = http::Request<Body>;

        assert_tower_service::<Svc, Req>();
        assert_grpc_service::<Svc, Body>();

        fn grpc_new_accepts_shim<B>()
        where
            B: hyper::body::Body + 'static,
            SendRequestService<B>: tonic::client::GrpcService<B>,
        {
            let _type_check: fn(
                SendRequestService<B>,
            ) -> tonic::client::Grpc<SendRequestService<B>> = |svc| tonic::client::Grpc::new(svc);
        }

        grpc_new_accepts_shim::<Body>();

        fn assert_clone<T: Clone>() {}
        assert_clone::<SendRequestService<Empty<Bytes>>>();

        fn assert_debug<T: core::fmt::Debug>() {}
        assert_debug::<SendRequestService<Empty<Bytes>>>();

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
