#!/usr/bin/env bash
# build/tsan-run.sh — executed inside the TSAN Docker container by `make tsan-test`.
#
# Runs inside build/Dockerfile.tsan.  Mount layout (all writable):
#   /work/ngx-otel-rust  ← project root
#   /work/nginx          ← sibling nginx source checkout
#   /work/ngx-rust       ← sibling ngx-rust checkout
#
# Design
# ──────
#   Step 1 – Compile sanity: `make build BUILD=tsan` builds nginx + the
#             module (staticlib via auto/rust) with all TSAN flags.  The
#             resulting nginx binary has the module statically linked
#             (--add-module) and is NOT used for integration tests because
#             nginx's ngx_load_module guard would reject a second load_module
#             of the same symbol table.  This step only verifies that all
#             TSAN flags are accepted by clang + rustc inside the container.
#
#   Step 2 – Plain TSAN nginx (no --add-module): configure + build a second
#             nginx binary WITHOUT --add-module.  This binary can load the
#             module dynamically via `load_module` in the integration scripts'
#             nginx.conf without hitting the "already loaded" guard.
#
#   Step 3 – TSAN RUSTFLAGS: export -Zsanitizer=thread (+ RUSTC_BOOTSTRAP=1,
#             -Zexternal-clangrt) so the integration scripts' own
#             `cargo build --release` produces a TSAN-instrumented cdylib at
#             target/release/ — the hardcoded MODULE_PATH both scripts use.
#             No -Zbuild-std / --target here because the scripts' cargo
#             invocation does not pass --target; the host std is unmodified
#             (acceptable — we instrument the module's own code).
#
#   Step 4 – Run both smoke scripts with NGINX_BINARY and NGINX_BUILD_DIR
#             pointing at the plain TSAN nginx.
#
#   Step 5 – Belt-and-suspenders scan: grep error.logs for any
#             "WARNING: ThreadSanitizer" lines.  With halt_on_error=1 a
#             real race would already have aborted the worker; this scan
#             catches any that slipped through.
#
# TSAN_OPTIONS must be set by the caller (done by `make tsan-test`):
#   halt_on_error=1:second_deadlock_stack=1:detect_deadlocks=1

set -euo pipefail

cd /work/ngx-otel-rust

TSAN_OBJS=/work/ngx-otel-rust/objs-tsan
PLAIN_OBJS=/work/ngx-otel-rust/objs-tsan-plain

# ── Step 1: Compile sanity check ─────────────────────────────────────────────

echo "[tsan-run] Step 1: Compile sanity check (make build BUILD=tsan)..."
NGINX_SOURCE_DIR=/work/nginx \
NGINX_BUILD_DIR="${TSAN_OBJS}" \
make build BUILD=tsan
echo "[tsan-run] Step 1: OK — TSAN flags accepted by clang + rustc."

# ── Step 2: Plain TSAN nginx (no --add-module) for integration tests ──────────

echo "[tsan-run] Step 2: Building plain TSAN nginx (no --add-module)..."
mkdir -p "${PLAIN_OBJS}"

# auto/configure unconditionally writes /work/nginx/Makefile even for out-of-
# tree builds.  Preserve the original and restore it afterwards.
cd /work/nginx
if [[ -f Makefile ]]; then
    cp -f Makefile Makefile.tsan-bak
fi

auto/configure \
    --with-compat \
    --with-http_stub_status_module \
    --with-cc=clang \
    --with-cc-opt="-O1 -fsanitize=thread -fno-omit-frame-pointer" \
    --with-ld-opt="-fsanitize=thread" \
    --with-debug \
    --builddir="${PLAIN_OBJS}"

# auto/configure regenerated /work/nginx/Makefile; remove it and restore backup.
rm -f /work/nginx/Makefile
if [[ -f /work/nginx/Makefile.tsan-bak ]]; then
    mv -f /work/nginx/Makefile.tsan-bak /work/nginx/Makefile
fi

# Build the plain TSAN nginx binary (must be run from nginx source dir).
make -f "${PLAIN_OBJS}/Makefile" binary

cd /work/ngx-otel-rust
echo "[tsan-run] Step 2: OK — plain TSAN nginx at ${PLAIN_OBJS}/nginx"

# ── Step 2.5: Pre-build bidi_echo_server example without TSAN ────────────────

# The bidi smoke script builds examples/bidi_echo_server (Tokio-based test-only
# gRPC echo server) before launching nginx.  Building it under TSAN fails to
# link: the example is a standalone binary so its TSAN runtime symbols
# (__tsan_func_entry, __tsan_read16, etc.) are unresolved — unlike the cdylib
# which inherits the TSAN runtime from nginx's -fsanitize=thread link line.
#
# More importantly we don't WANT the example TSAN-instrumented: it runs Tokio's
# multi-thread runtime, and TSAN findings inside tokio internals would be noise
# (upstream code, not module-under-test).  Pre-build it without TSAN now, then
# the script picks it up via the ECHO_BINARY env override.
echo "[tsan-run] Step 2.5: Pre-building bidi_echo_server example (no TSAN)..."
# nginx-sys is transitively required (its bindings live in the crate's build
# graph even though the example itself uses no nginx APIs).  Point at the
# plain TSAN nginx headers — bindgen only reads ngx_auto_config.h, doesn't
# link.
(
    cd /work/ngx-otel-rust
    NGINX_SOURCE_DIR=/work/nginx \
    NGINX_BUILD_DIR="${PLAIN_OBJS}" \
    cargo build --example bidi_echo_server
)
export ECHO_BINARY=/work/ngx-otel-rust/target/debug/examples/bidi_echo_server
echo "[tsan-run] Step 2.5: OK — example at ${ECHO_BINARY}"

# ── Step 3: Export TSAN env for integration scripts ──────────────────────────

echo "[tsan-run] Step 3: Exporting TSAN env for integration scripts..."
# The scripts run `cargo build --release --features test-support` themselves.
# Three env vars steer that cargo invocation into producing a TSAN-instrumented
# cdylib + stdlib without any change to the cargo command line:
#
#   RUSTFLAGS                  TSAN flags applied to every Rust crate.
#   -Zexternal-clangrt         use clang's TSAN runtime already linked into nginx
#                              rather than a Rust-bundled copy (avoids duplicate
#                              runtime init).
#   CARGO_BUILD_TARGET         equivalent of `--target=<triple>`; cargo writes
#                              output to target/<triple>/release/ when set.
#   CARGO_UNSTABLE_BUILD_STD   equivalent of `-Zbuild-std=std,panic_abort`;
#                              rebuilds stdlib under the same RUSTFLAGS so the
#                              crate's `-Zsanitizer=thread` doesn't clash with
#                              an un-instrumented host stdlib (rustc 1.95
#                              rejects this ABI mismatch).  RUSTC_BOOTSTRAP=1
#                              unlocks the unstable flag on a stable toolchain.
#
# Integration scripts gain a small CARGO_BUILD_TARGET-aware MODULE_PATH branch
# so they find the cdylib at target/<triple>/release/ when set, and at the
# original target/release/ when unset (non-TSAN runs unchanged).
export RUSTFLAGS="-Cforce-frame-pointers=yes -Zsanitizer=thread -Zexternal-clangrt"
export RUSTC_BOOTSTRAP=1
export CARGO_BUILD_TARGET="$(rustc -vV | awk '/^host: / { print $2 }')"
export CARGO_UNSTABLE_BUILD_STD="std,panic_abort"

# Point integration scripts at the plain TSAN nginx.
export NGINX_BINARY="${PLAIN_OBJS}/nginx"
export NGINX_SOURCE_DIR=/work/nginx
export NGINX_BUILD_DIR="${PLAIN_OBJS}"

echo "[tsan-run] TSAN nginx:  ${NGINX_BINARY}"
echo "[tsan-run] RUSTFLAGS:   ${RUSTFLAGS}"

# ── Step 4: Run integration scripts ──────────────────────────────────────────

echo ""
echo "[tsan-run] === Running run_grpc_smoke.sh under TSAN ==="
bash tests/integration/run_grpc_smoke.sh

echo ""
echo "[tsan-run] === Running run_grpc_bidi_smoke.sh under TSAN ==="
bash tests/integration/run_grpc_bidi_smoke.sh

echo ""
echo "[tsan-run] === Running run_grpc_export.sh under TSAN (production gRPC export path) ==="
# run_grpc_export.sh is a production-path test (no --features test-support).
# It exercises the persistent GrpcTransport connection under TSAN to confirm
# no data races on the production gRPC export loop.
bash tests/integration/run_grpc_export.sh

echo ""
echo "[tsan-run] === Running run_access_log.sh under TSAN (Phase 2.2 §6.6.1 rebalanced path) ==="
# Exercises the new Phase 2.2 shared state under TSAN:
#   - ExpHistogramSlot::record() — Relaxed fetch_add on exp-histogram buckets
#   - ExemplarReservoir::write() — Relaxed stores on exemplar entry fields
#   - route/upstream dimension writes (combo_index extended to 5 dims)
#   - SPSC logs ring (workers write is_interesting tail records)
#   - run_access_log.sh now sends 200 (histogram only) + 500 (ring + reservoir)
# All new shared-state paths from RALPH_PHASE_2_2.md steps 2.2.1–2.2.5.
bash tests/integration/run_access_log.sh

echo ""
echo "[tsan-run] === Running run_error_log.sh under TSAN (Phase 2.3 §6.6.2 error-log path) ==="
# Exercises Phase 2.3 shared state under TSAN:
#   - CoalesceSlot::count.fetch_add / .swap(0, AcqRel) — coalescer on writer path
#   - WorkerSlots::error_rate_counters[].fetch_add — error-rate metric bump
#   - SPSC error ring push (workers write verbatim samples)
#   - drain_coalesce_table / logs_error_ring drain in exporter
# Stage A (coalesce-on flood), Stage B (coalesce-off), Stage C (floor),
# Stage D (DP-C config-load guard).
bash tests/integration/run_error_log.sh

echo ""
echo "[tsan-run] === Running run_signal_storm.sh under TSAN (Phase 2.3 re-entrancy gate) ==="
# THE load-bearing safety gate: busy-flag + lock-free coalescer under
# SIGUSR1 signal delivery.  30-second flood + signal storm.
# Asserts: no crash, no panic, no torn records, drain progresses.
STORM_DURATION_S=30 bash tests/integration/run_signal_storm.sh

echo ""
echo "[tsan-run] === Running run_dns_dualstack.sh under TSAN (transport_dns async resolver path) ==="
# Exercises Items 2 + 3 of the transport_dns work under TSAN:
#   - NgxConnector::connect_dns: Resolver::resolve_name (UDP event-loop path)
#   - connect_first_reachable / pc.sockaddr+socklen wiring
#   - IPv6 literal connect path (build_ipv6_sockaddr, AF_INET6 socklen)
# TEST A resolves "ngx-otel-dns-test" via a local Python DNS stub → 127.0.0.1
# (real async resolver I/O under TSAN).  TEST B connects via a v6 literal.
bash tests/integration/run_dns_dualstack.sh

# ── Step 5: Belt-and-suspenders ThreadSanitizer warning scan ─────────────────

echo ""
echo "[tsan-run] Checking for ThreadSanitizer warnings in error logs..."
TSAN_WARNINGS=0
for log in /tmp/ngx-otel-grpc-smoke.*/logs/error.log \
           /tmp/ngx-otel-grpc-bidi-smoke.*/logs/error.log \
           /tmp/ngx-otel-grpc-export.*/logs/error.log \
           /tmp/ngx-otel-access-log.*/logs/error.log \
           /tmp/ngx-otel-error-log.*/logs/error.log \
           /tmp/ngx-otel-signal-storm.*/logs/error.log \
           /tmp/ngx-otel-dns-a.*/logs/error.log \
           /tmp/ngx-otel-dns-b.*/logs/error.log; do
    if [[ -f "${log}" ]]; then
        count=$(grep -c "WARNING: ThreadSanitizer" "${log}" 2>/dev/null || true)
        if [[ "${count}" -gt 0 ]]; then
            echo "[tsan-run] TSAN WARNING found in ${log}:" >&2
            grep "WARNING: ThreadSanitizer" "${log}" >&2
            TSAN_WARNINGS=$(( TSAN_WARNINGS + count ))
        fi
    fi
done

if [[ "${TSAN_WARNINGS}" -gt 0 ]]; then
    echo "[tsan-run] FAIL: ${TSAN_WARNINGS} ThreadSanitizer warning(s) detected." >&2
    echo "[tsan-run] STOP-AND-ASK: surface the full TSAN report for review." >&2
    exit 1
fi

echo "[tsan-run] Zero ThreadSanitizer warnings.  TSAN gate: PASS."
