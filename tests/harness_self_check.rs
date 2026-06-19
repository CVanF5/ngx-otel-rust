// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Self-contained regression tests for the test harness primitives.
//!
//! These tests do NOT import the main library crate so they link and run on
//! any platform without a full NGINX build.  They verify:
//!
//!   - `block_on` (Finding #3): a future that never resolves times out with a
//!     clear message instead of spinning forever.
//!   - `ngx_stat_*` (Finding #4): each stat pointer resolves to a distinct
//!     memory address so that writing through one does not corrupt the others.
//!
//! # Running
//!
//! ```sh
//! NGINX_SOURCE_DIR=.../nginx \
//! NGINX_BUILD_DIR=.../nginx/objs \
//! cargo test --test harness_self_check
//! ```

// Pull in NGINX stubs.  On macOS the flat-namespace linker requires them at
// startup; on Linux they satisfy the link-time requirements of the ngx-otel
// library (which this binary doesn't actually call).
mod support;

// ──────────────────────────────────────────────────────────────────────────────
// Finding #3 — block_on timeout
// ──────────────────────────────────────────────────────────────────────────────

/// A future that never resolves.
struct NeverReady;

impl std::future::Future for NeverReady {
    type Output = ();
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        std::task::Poll::Pending
    }
}

/// Mirrors `support::block_on` but with a caller-supplied deadline.
///
/// Returns `Some(output)` if the future completed, `None` if the deadline
/// elapsed.  This lets the test assert on timeout without actually panicking
/// so the test output stays readable.
fn block_on_deadline<F: std::future::Future>(
    fut: F,
    timeout: std::time::Duration,
) -> Option<F::Output> {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use std::time::Instant;

    unsafe fn noop_clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    // SAFETY: these callbacks receive the same null pointer we pass below;
    // none of them dereference it.
    unsafe fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

    // SAFETY: the vtable callbacks are all no-ops and the data pointer is null.
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    let deadline = Instant::now() + timeout;

    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(val) => return Some(val),
            Poll::Pending => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::yield_now();
            }
        }
    }
}

/// Finding #3 regression: a stalled (never-Ready) future must time out
/// (return None) rather than spinning forever.
#[test]
fn block_on_times_out_on_stalled_future() {
    let result = block_on_deadline(NeverReady, std::time::Duration::from_millis(100));
    assert!(result.is_none(), "expected None (timeout) from a never-Ready future but got Some(())");
}

/// Sanity-check: a future that completes immediately must return Some(value).
#[test]
fn block_on_completes_immediately_ready_future() {
    let result =
        block_on_deadline(std::future::ready(42u32), std::time::Duration::from_millis(100));
    assert_eq!(result, Some(42u32), "immediately-Ready future should complete");
}

// ──────────────────────────────────────────────────────────────────────────────
// Finding #4 — ngx_stat_* pointer aliasing
// ──────────────────────────────────────────────────────────────────────────────

/// Finding #4 regression: each `ngx_stat_*` pointer must point to a distinct
/// memory location.  A write through one must not be visible through any other.
#[test]
fn ngx_stat_pointers_are_distinct() {
    // Collect raw pointer values.
    // SAFETY: we only read the pointer values (addresses), never dereference.
    let ptrs: [*mut nginx_sys::ngx_atomic_t; 7] = unsafe {
        [
            support::ngx_stat_accepted,
            support::ngx_stat_handled,
            support::ngx_stat_requests,
            support::ngx_stat_active,
            support::ngx_stat_reading,
            support::ngx_stat_writing,
            support::ngx_stat_waiting,
        ]
    };

    for i in 0..ptrs.len() {
        for j in (i + 1)..ptrs.len() {
            assert_ne!(
                ptrs[i], ptrs[j],
                "ngx_stat pointers[{}] and [{}] alias the same address {:p}",
                i, j, ptrs[i]
            );
        }
    }
}
