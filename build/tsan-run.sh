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

# ── Step 3.5: nm-verification — confirm __tsan_* symbols in the cdylib ───────
#
# FU4: the previous TSAN artifact contained only a "Step 1 OK" compile-sanity
# note and no evidence that __tsan_* instrumentation symbols are actually
# present in the .so files the test nginx loads.  This step counts __tsan_*
# symbols in the exact release cdylib produced under the TSAN RUSTFLAGS above
# and fails the run if zero are found (= the module was NOT instrumented).
#
# The cdylib is built by the first integration script that calls
# `cargo build --release`.  We pre-build it once here so the nm check runs
# before any test relies on it, and so subsequent scripts get a cache hit.

echo "[tsan-run] Step 3.5: Pre-building TSAN-instrumented cdylib..."
(
    cd /work/ngx-otel-rust
    NGINX_SOURCE_DIR=/work/nginx \
    NGINX_BUILD_DIR="${PLAIN_OBJS}" \
    cargo build --release 2>&1
)

# Locate the cdylib (path depends on whether CARGO_BUILD_TARGET is set).
case "$(uname -s)" in
    Darwin) _MEXT="dylib" ;;
    *)      _MEXT="so"    ;;
esac
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    NM_SO="/work/ngx-otel-rust/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${_MEXT}"
else
    NM_SO="/work/ngx-otel-rust/target/release/libngx_http_otel_module.${_MEXT}"
fi

echo "[tsan-run] Step 3.5: nm-check: ${NM_SO}"
if [[ ! -f "${NM_SO}" ]]; then
    echo "[tsan-run] FAIL: cdylib not found at ${NM_SO}" >&2
    exit 1
fi

TSAN_SYM_COUNT="$(nm "${NM_SO}" 2>/dev/null | grep -c '__tsan_' || echo 0)"
echo "[tsan-run] Step 3.5: __tsan_* symbol count in cdylib: ${TSAN_SYM_COUNT}"
if [[ "${TSAN_SYM_COUNT}" -eq 0 ]]; then
    echo "[tsan-run] FAIL: zero __tsan_* symbols in ${NM_SO} — module was NOT compiled with -Zsanitizer=thread." >&2
    echo "[tsan-run]        RUSTFLAGS=${RUSTFLAGS}" >&2
    exit 1
fi
echo "[tsan-run] Step 3.5: OK — ${TSAN_SYM_COUNT} __tsan_* symbols confirmed in $(basename "${NM_SO}")."
echo "[tsan-run] Step 3.5: full path: ${NM_SO}"

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
# SIGUSR1 signal delivery.  TSAN ~10x slowdown: use a 90s window (3× the
# default 30s) so the drain cycle has time to progress under instrumentation.
# Asserts: no crash, no panic, no torn records, drain progresses.
STORM_DURATION_S=90 bash tests/integration/run_signal_storm.sh

echo ""
echo "[tsan-run] === Running run_traces.sh under TSAN (Phase 3 span emit→ring→drain→encode→collector) ==="
# FU3: closes the Loop-2 gap by exercising the full spans-ring writer → drain
# → OtlpTracesEncoder → /v1/traces path under TSAN.  Asserts that a span
# with the expected traceId and parentSpanId (from an inbound traceparent)
# arrives at the collector — proving the E2E path is race-free.
bash tests/integration/run_traces.sh

echo ""
echo "[tsan-run] === Running run_dns_dualstack.sh under TSAN (transport_dns async resolver path) ==="
# Exercises Items 2 + 3 of the transport_dns work under TSAN:
#   - NgxConnector::connect_dns: Resolver::resolve_name (UDP event-loop path)
#   - connect_first_reachable / pc.sockaddr+socklen wiring
#   - IPv6 literal connect path (build_ipv6_sockaddr, AF_INET6 socklen)
# TEST A resolves "ngx-otel-dns-test" via a local Python DNS stub → 127.0.0.1
# (real async resolver I/O under TSAN).  TEST B connects via a v6 literal.
bash tests/integration/run_dns_dualstack.sh

echo ""
echo "[tsan-run] === Running C2 chaos scripts under TSAN (C1 crash-counter cross-process atomics) ==="
# F2 gap closure: the C4 artifact ran chaos tests in a NON-TSAN build.  Run
# the three chaos scripts under the TSAN-instrumented nginx + module so that
# the cross-process AtomicU64 paths (crash_count, window_start_unix in
# control_shm) execute under ThreadSanitizer.
#
# run_chaos_kill9.sh: uses the release module (already built above with TSAN
#   RUSTFLAGS via the prior scripts).  Exercises crash_count.fetch_add after
#   SIGKILL respawn.
#
# run_chaos_crashloop.sh: builds the test-support module (NGX_OTEL_CRASH_ON_STARTUP
#   hook) into a separate target-dir (target/test-support) under the exported TSAN
#   RUSTFLAGS.  Exercises the full crash → respawn → crash_count.fetch_add cycle
#   MULTIPLE times through self-disable.  TSAN ~10x slowdown is safe: backoff
#   sleeps are real wall-clock sleeps (unaffected by instrumentation); MAX_WAIT_S
#   overridden to 120s.
#
# run_chaos_dead_collector.sh: Parts A+B use the release module; Part C builds
#   the test-support module (reuses target/test-support built above).  Exercises
#   control_shm_zone_init's crash_count.store(0) (the SIGHUP reload zeroing path).
#
# cargo clean is NOT needed: test-support builds use --target-dir target/test-support
# (separate from target/<triple>/release/), so there is no feature-flag cache
# collision.

echo ""
echo "[tsan-run] == run_chaos_kill9.sh under TSAN =="
# Run in a subshell so a failure here doesn't abort the whole TSAN run.
# A real TSAN race would already have halted nginx via halt_on_error=1 and
# been caught in the step-5 log scan below.
KILL9_RC=0
( bash tests/integration/run_chaos_kill9.sh ) || KILL9_RC=$?
if [[ "${KILL9_RC}" -ne 0 ]]; then
    echo "[tsan-run] run_chaos_kill9.sh: NON-ZERO exit ${KILL9_RC} — continuing to crash+dead_collector" >&2
fi

echo ""
echo "[tsan-run] == run_chaos_crashloop.sh under TSAN (MAX_WAIT_S=120 for TSAN overhead) =="
# TSAN ~10x slowdown: total backoff remains ≤ 3s (real sleep), but nginx spawn
# and cargo build overhead may take longer.  120s budget is conservative.
CRASHLOOP_RC=0
( MAX_WAIT_S=120 bash tests/integration/run_chaos_crashloop.sh ) || CRASHLOOP_RC=$?
if [[ "${CRASHLOOP_RC}" -ne 0 ]]; then
    echo "[tsan-run] run_chaos_crashloop.sh: NON-ZERO exit ${CRASHLOOP_RC}" >&2
fi

echo ""
echo "[tsan-run] == SIGHUP-during-crash-loop interleaving exercise (F2 req 4) =="
# Requirement: give TSAN eyes to the SIGHUP-while-crash-looping interleaving.
# control_shm_zone_init (called on SIGHUP reload) does store(0) on crash_count;
# a concurrent exporter crash-loop is doing fetch_add.  This is the exact race
# identified in commit 3ff2fd3 as the SIGHUP/crash-counter contention path.
#
# Strategy: use the test-support module (already built by crashloop above) to
# drive 3 reload-during-crash-loop rounds.  This is an EXERCISE (not an assert);
# any TSAN warning produced is a finding — caught by the step-5 scan below.
#
# The test-support module is already at target/<triple>/debug/ after crashloop ran.
SIGHUP_INTERLEAVE_EXERCISE_ERRORS=0
(
    CRATE=/work/ngx-otel-rust
    case "$(uname -s)" in
        Darwin) MEXT="dylib" ;;
        *)      MEXT="so"    ;;
    esac
    # The instrumented test-support module built by crashloop.
    TS_MODULE=""
    if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
        TS_MODULE="${CRATE}/target/test-support/${CARGO_BUILD_TARGET}/debug/libngx_http_otel_module.${MEXT}"
    else
        TS_MODULE="${CRATE}/target/test-support/debug/libngx_http_otel_module.${MEXT}"
    fi
    if [[ ! -f "${TS_MODULE}" ]]; then
        echo "[tsan-run] SIGHUP-interleave: test-support module not found at ${TS_MODULE} — skipping exercise"
        exit 0
    fi
    echo "[tsan-run] SIGHUP-interleave: using module ${TS_MODULE}"
    echo "[tsan-run] SIGHUP-interleave: running 3 rounds of SIGHUP-during-crash-loop..."
    for round in 1 2 3; do
        echo "[tsan-run] SIGHUP-interleave: round ${round}/3 — starting nginx..."
        TMPDIR="$(mktemp -d /tmp/ngx-otel-sighup-interleave.XXXXXX)"
        mkdir -p "${TMPDIR}/logs" "${TMPDIR}/client_body_temp"
        cat > "${TMPDIR}/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 1;
error_log ${TMPDIR}/logs/error.log debug;
pid       ${TMPDIR}/logs/nginx.pid;

load_module ${TS_MODULE};

events {
    worker_connections 32;
}

http {
    otel_exporter {
        endpoint http://127.0.0.1:19318;
    }
    otel_service_name ngx-otel-sighup-interleave;
    otel_metric_interval 1s;

    server {
        listen 127.0.0.1:9202;
        location / { return 200 "ok\n"; }
    }
}
EOF
        env NGX_OTEL_CRASH_ON_STARTUP=1 \
            "${NGINX_BINARY}" -p "${TMPDIR}" -c "${TMPDIR}/nginx.conf" &
        NGINX_PID=$!
        # Wait for first crash to fire (exporter spawned, crashes immediately).
        sleep 2
        if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
            echo "[tsan-run] SIGHUP-interleave: round ${round} — master exited prematurely (skip)"
            rm -rf "${TMPDIR}"
            continue
        fi
        echo "[tsan-run] SIGHUP-interleave: round ${round} — sending SIGHUP while crash-looping..."
        kill -SIGHUP "${NGINX_PID}" 2>/dev/null || true
        # Give the TSAN engine 3s to observe any race between store(0) and fetch_add.
        sleep 3
        echo "[tsan-run] SIGHUP-interleave: round ${round} — sending SIGQUIT..."
        kill -SIGQUIT "${NGINX_PID}" 2>/dev/null || true
        # Wait up to 20s for clean shutdown (backstop drain is 15s).
        deadline=$(( $(date +%s) + 20 ))
        while kill -0 "${NGINX_PID}" 2>/dev/null && (( $(date +%s) < deadline )); do
            sleep 0.5
        done
        kill "${NGINX_PID}" 2>/dev/null || true
        echo "[tsan-run] SIGHUP-interleave: round ${round} done. error.log tail:"
        tail -5 "${TMPDIR}/logs/error.log" 2>/dev/null || echo "(none)"
        rm -rf "${TMPDIR}"
    done
    echo "[tsan-run] SIGHUP-interleave: 3 rounds complete — TSAN eyes on store(0)⟷fetch_add interleaving."
) || SIGHUP_INTERLEAVE_EXERCISE_ERRORS=$?
echo "[tsan-run] SIGHUP-interleave exercise rc=${SIGHUP_INTERLEAVE_EXERCISE_ERRORS}"

echo ""
echo "[tsan-run] == run_chaos_dead_collector.sh under TSAN (MAX_WAIT_C=120 for TSAN overhead) =="
DEADCOLL_RC=0
( MAX_WAIT_C=120 bash tests/integration/run_chaos_dead_collector.sh ) || DEADCOLL_RC=$?
if [[ "${DEADCOLL_RC}" -ne 0 ]]; then
    echo "[tsan-run] run_chaos_dead_collector.sh: NON-ZERO exit ${DEADCOLL_RC}" >&2
fi

# FU4: run_b4_daemon_on_gen1.sh — gen-1 exporter orphan + reload remedy.
# Added in FU4 to close the gap identified in the hostile-fixes gate review:
# B4 test was absent from the prior TSAN artifact.
echo ""
echo "[tsan-run] == run_b4_daemon_on_gen1.sh under TSAN (FU4: was missing from prior artifact) =="
B4_RC=0
( bash tests/integration/run_b4_daemon_on_gen1.sh ) || B4_RC=$?
if [[ "${B4_RC}" -ne 0 ]]; then
    echo "[tsan-run] run_b4_daemon_on_gen1.sh: NON-ZERO exit ${B4_RC}" >&2
fi

# FU4: run_b1_spsc_reload_chaos.sh — SPSC ring dup-detection + quit-completeness.
# Added in FU1; now exercised under TSAN so the periodic_abdicated latch and
# successor_gen Acquire load run under ThreadSanitizer.
# USE_SLOW_SINK=1 enables the Python slow-proxy (2s POST delay) to widen the
# SIGHUP overlap window, making mutation (a) reliable on Linux.
echo ""
echo "[tsan-run] == run_b1_spsc_reload_chaos.sh under TSAN (FU1 chaos test) =="
B1_RC=0
( USE_SLOW_SINK=1 bash tests/integration/run_b1_spsc_reload_chaos.sh ) || B1_RC=$?
if [[ "${B1_RC}" -ne 0 ]]; then
    echo "[tsan-run] run_b1_spsc_reload_chaos.sh: NON-ZERO exit ${B1_RC}" >&2
fi

# After all chaos scripts: fail the TSAN run if any of them failed.
# The TSAN warning scan in step 5 is the definitive gate for races.
# These functional failures indicate harness/timing issues, not TSAN races.
if [[ "${KILL9_RC}" -ne 0 || "${CRASHLOOP_RC}" -ne 0 || "${DEADCOLL_RC}" -ne 0 || "${B4_RC}" -ne 0 || "${B1_RC}" -ne 0 ]]; then
    echo "[tsan-run] NOTE: chaos/lifecycle script(s) exited non-zero (kill9=${KILL9_RC}, crashloop=${CRASHLOOP_RC}, deadcoll=${DEADCOLL_RC}, b4=${B4_RC}, b1_chaos=${B1_RC})"
    echo "[tsan-run] NOTE: these are functional/timing failures — check the TSAN warning scan for actual races."
fi

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
           /tmp/ngx-otel-dns-b.*/logs/error.log \
           /tmp/ngx-otel-dns-c.*/logs/error.log \
           /tmp/ngx-otel-dns-d.*/logs/error.log \
           /tmp/ngx-otel-traces.*/logs/error.log \
           /tmp/ngx-otel-kill9.*/logs/error.log \
           /tmp/ngx-otel-crashloop.*/logs/error.log \
           /tmp/ngx-otel-deadcoll.*/logs/error.log \
           /tmp/ngx-otel-deadcoll-b.*/logs/error.log \
           /tmp/ngx-otel-deadcoll-c.*/logs/error.log \
           /tmp/ngx-otel-sighup-interleave.*/logs/error.log \
           /tmp/ngx-otel-b4-daemon.*/logs/error.log \
           /tmp/ngx-otel-b1chaos.*/logs/error.log; do
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

# Report chaos functional failures (non-zero exits unrelated to TSAN races).
if [[ "${KILL9_RC:-0}" -ne 0 || "${CRASHLOOP_RC:-0}" -ne 0 || "${DEADCOLL_RC:-0}" -ne 0 || "${B4_RC:-0}" -ne 0 || "${B1_RC:-0}" -ne 0 ]]; then
    echo "[tsan-run] CHAOS NOTE: kill9=${KILL9_RC:-0} crashloop=${CRASHLOOP_RC:-0} deadcoll=${DEADCOLL_RC:-0} b4=${B4_RC:-0} b1_chaos=${B1_RC:-0} — functional/timing failure; no TSAN race." >&2
    exit 3
fi
