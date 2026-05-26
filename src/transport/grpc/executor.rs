// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! [`NgxExecutor`]: a `hyper::rt::Executor<F>` impl that drives futures on
//! ngx-rust's event-loop executor via `ngx::async_::spawn`.

/// `hyper::rt::Executor<F>` impl that drives futures on
/// `ngx::async_::spawn`.  The spawned `Task<T>` is `detach()`-ed
/// so it runs to completion independent of any handle.
///
/// # No Tokio
/// This executor does **not** use a Tokio runtime.  All wakeups go through
/// NGINX's `ngx_post_event` / `ngx_process_events_and_timers` machinery.
///
/// # Safety note
/// `ngx::async_::spawn` is single-thread-only (the NGINX worker).
/// `NgxExecutor` must only be used from within a running NGINX worker
/// process.
#[derive(Clone, Copy, Default, Debug)]
pub struct NgxExecutor;

impl<F> hyper::rt::Executor<F> for NgxExecutor
where
    F: core::future::Future + 'static,
{
    fn execute(&self, fut: F) {
        ngx::async_::spawn(async move {
            let _ = fut.await;
        })
        .detach();
    }
}

#[cfg(test)]
mod tests {
    use super::NgxExecutor;

    /// Type-level check: `NgxExecutor` must implement
    /// `hyper::rt::Executor<F>` for a concrete `F`.
    /// This test does **not** drive a NGINX event loop; it only checks that
    /// the impl compiles and that the trait constraint is satisfied.
    #[test]
    fn ngx_executor_implements_hyper_executor() {
        use core::future::Future;
        use core::pin::Pin;
        use core::task::{Context, Poll};

        /// A trivially-complete future that records whether it was polled.
        struct OneShotFuture {
            polled: bool,
        }

        impl Future for OneShotFuture {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
                self.polled = true;
                Poll::Ready(())
            }
        }

        // Type-level assertion: NgxExecutor implements Executor<OneShotFuture>.
        fn assert_executor<E, F>(_e: &E)
        where
            E: hyper::rt::Executor<F>,
            F: core::future::Future + 'static,
        {
        }

        let exec = NgxExecutor;
        assert_executor::<NgxExecutor, OneShotFuture>(&exec);

        // Also verify Clone / Copy / Default / Debug derive correctly.
        let _cloned = exec;
        let _default: NgxExecutor = Default::default();
        let _dbg = std::format!("{:?}", exec);
    }
}
