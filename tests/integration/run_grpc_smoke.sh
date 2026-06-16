#!/usr/bin/env bash
# tests/integration/run_grpc_smoke.sh — in-worker gRPC viability harness.
#
# Builds the module with `--features test-support` so the
# `otel_grpc_smoke_endpoint` directive's init_process trigger is compiled
# in.  Starts nginx with the directive set to the local OTel collector's
# OTLP/gRPC port (127.0.0.1:4317).  Worker 0 fires exactly one unary
# `ExportMetricsServiceRequest` via NgxExecutor + SendRequestService +
# NgxConnIo — the real production-shape pipeline.
#
# Assertions:
#   1. error.log contains exactly 1 "grpc smoke: firing one unary" line
#      (proves the directive was parsed and the trigger logic ran on
#      Worker 0).
#   2. error.log contains exactly 1 "grpc smoke: export complete" line
#      (proves the gRPC call returned OK — fire_one_grpc_export reached
#      the Ok(()) branch).
#   3. error.log contains zero "grpc smoke: export failed" lines.
#   4. error.log contains zero panic / SIGSEGV / worker-respawn signals.
#   5. metrics.json delta contains a payload with
#      service.name = "ngx-otel-grpc-smoke" — i.e. the collector
#      actually received and persisted the metric.
#
# Prerequisites
# ─────────────
# - Docker available on PATH.  Collector auto-starts via
#   test-harness/lib.sh (or set OTEL_COLLECTOR_AUTOSTART=0 if managed
#   externally).
# - NGINX source + build dirs as set up by the project README.
#
# Exit codes
# ──────────
#   0  all assertions pass
#   1  pre-flight or build failure
#   2  a test assertion failed

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

# Pin NGINX_BINARY + NGINX_BUILD_DIR to the same non-debug flavor.
# This script must NOT pick objs-debug/nginx via lib.sh's resolver
# because (a) the module dylib is rebuilt below against NGINX_BUILD_DIR's
# ngx_auto_config.h, and (b) NGINX_BUILD_DIR's default is the non-debug
# ../nginx/objs.  Mixing NGX_DEBUG=1 nginx with a dylib built against
# non-debug headers is the ABI-mismatch class of bug we already
# documented in HANDOFF.md.  Both paths point at the sibling
# ../nginx/objs (the pre-built non-debug nginx) for this smoke test.
NGINX_BINARY="${NGINX_BINARY:-${REPO_ROOT}/nginx/objs/nginx}"
NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${REPO_ROOT}/nginx}"
NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${REPO_ROOT}/nginx/objs}"
export NGINX_SOURCE_DIR NGINX_BUILD_DIR

# Source the shared harness library.  Sets HARNESS_DIR, METRICS_LOG,
# COLLECTOR_HTTP_ENDPOINT, and exposes ensure_collector_running and
# resolve_nginx_binary.  We pre-set NGINX_BINARY above so resolve_nginx_binary
# accepts it without searching objs-debug/.
. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true   # missing-binary error produced by preflight below

# Detect module extension.
case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
# When CARGO_BUILD_TARGET is set (e.g., the TSAN gate uses --target so cargo
# can also -Zbuild-std), cargo writes its output to target/<triple>/release/
# rather than target/release/.  Backwards-compatible: unset → original path.
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi

SERVICE_NAME="ngx-otel-grpc-smoke"
GRPC_ENDPOINT="http://127.0.0.1:4317"

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }

FAILED=0

# ─── Pre-flight checks ───────────────────────────────────────────────────────

info "Pre-flight checks..."

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    exit 1
fi

ensure_collector_running || exit 1

# ─── Build the module WITH test-support feature ──────────────────────────────
#
# This is the critical difference from run.sh: the smoke trigger logic in
# src/lib.rs::init_process is gated `#[cfg(any(test, feature = "test-support"))]`,
# so we must build with --features test-support for the directive to do
# anything.

info "Building release module with --features test-support..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${REPO_ROOT}/nginx}" \
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${REPO_ROOT}/nginx/objs}" \
    cargo build --release --features test-support 2>&1
)
if [[ ! -f "${MODULE_PATH}" ]]; then
    echo "ERROR: module not found after build: ${MODULE_PATH}" >&2
    exit 1
fi
info "Module built: ${MODULE_PATH}"

# ─── Sandbox prefix directory ────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-grpc-smoke.XXXXXX)"
cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    echo ""
    echo "=== error.log: grpc / otel lines ==="
    grep -aE "grpc smoke|otel init_process|otel export|panicked|signal [0-9]+|exited" \
        "${PREFIX}/logs/error.log" 2>/dev/null | head -40 || echo "(not found)"
    info "Tearing down ${PREFIX} (skipped if KEEP_SANDBOX=1)"
    [[ "${KEEP_SANDBOX:-0}" == "1" ]] || rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"
mkdir -p "${PREFIX}/client_body_temp"

# Write the nginx config.  Note: this test uses a SEPARATE port (9101) from
# the other integration scripts to allow concurrent or back-to-back runs.
# `otel_metric_interval` is set high enough that the export loop won't fire
# during the test window — we only want the smoke gRPC trigger to do work.
cat > "${PREFIX}/nginx.conf" <<EOF
daemon off;
master_process on;
# Single worker keeps the smoke test focused: Worker 0 is the only
# worker and IS the designated worker.  Multi-worker behaviour will be
# revisited when the gRPC bridge becomes a real production transport
# rather than a one-shot smoke test.
worker_processes 1;
# Without this, a hanging async task can keep a worker alive forever after
# nginx -s quit; the script's wait-for-exit loop then times out and leaks
# the worker to the next run as a port-9103 conflict.
worker_shutdown_timeout 3s;
error_log ${PREFIX}/logs/error.log debug;
pid       ${PREFIX}/logs/nginx.pid;

load_module ${MODULE_PATH};

events {
    worker_connections 64;
}

http {
    # The OTLP/HTTP exporter — needs to be configured so the
    # is_configured() gate lets init_process run.  Long interval so the
    # HTTP exporter doesn't fire during this test window.
    otel_exporter {
        endpoint http://127.0.0.1:4318;
    }
    otel_service_name ngx-otel-grpc-smoke-http;
    otel_metric_interval 60s;

    # Unary gRPC smoke trigger: fire one unary OTLP/gRPC export via the
    # real NgxExecutor + SendRequestService + NgxConnIo stack.
    otel_grpc_smoke_endpoint ${GRPC_ENDPOINT};

    # Port 9103 chosen to avoid collision with run.sh (9100), the bench
    # configs + run_reload.sh (9101), and run_endpoint_change.sh (9102).
    server {
        listen 127.0.0.1:9103;
        location / {
            return 200 "ok\n";
        }
    }
}
EOF

info "Sandbox: ${PREFIX}"

# ─── Snapshot metrics.json BEFORE starting nginx ─────────────────────────────

PRE_SIZE=0
if [[ -f "${METRICS_LOG}" ]]; then
    PRE_SIZE=$(wc -c < "${METRICS_LOG}")
fi
info "metrics.json pre-size: ${PRE_SIZE} bytes"

# ─── Start nginx ─────────────────────────────────────────────────────────────

info "Starting nginx (worker_processes 4, with otel_grpc_smoke_endpoint)..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!

# Wait for nginx to bind + workers to spawn + smoke gRPC call to complete.
# 3 seconds is plenty: handshake is sub-100ms locally, unary call ~10ms.
sleep 3

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    fail "nginx exited unexpectedly during startup"
    exit 2
fi
info "nginx running (PID ${NGINX_PID})"

# ─── Wait for the gRPC call to complete ──────────────────────────────────────

info "Waiting up to 5s for 'grpc smoke: export complete' or 'failed' line..."
DEADLINE=$(( SECONDS + 5 ))
while (( SECONDS < DEADLINE )); do
    if grep -aq "grpc smoke: export \(complete\|failed\)" "${PREFIX}/logs/error.log" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

# ─── Graceful shutdown ───────────────────────────────────────────────────────

info "Sending nginx -s quit..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" -s quit 2>/dev/null || true

# Wait for nginx to exit cleanly.
for _ in $(seq 1 15); do
    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
        break
    fi
    sleep 0.5
done
NGINX_PID=""

# ─── Collect metrics.json delta ──────────────────────────────────────────────

NEW_CONTENT=""
if [[ -f "${METRICS_LOG}" ]]; then
    POST_SIZE=$(wc -c < "${METRICS_LOG}")
    if (( POST_SIZE > PRE_SIZE )); then
        NEW_CONTENT=$(tail -c "+$(( PRE_SIZE + 1 ))" "${METRICS_LOG}")
    fi
fi

# ─── Assertions ──────────────────────────────────────────────────────────────

info "Running assertions..."

# 1. Smoke trigger fired exactly once.
FIRING_COUNT=$(grep -c "grpc smoke: firing one unary" "${PREFIX}/logs/error.log" 2>/dev/null) || FIRING_COUNT=0
if [[ "${FIRING_COUNT}" -eq 1 ]]; then
    pass "error.log: exactly 1 'grpc smoke: firing one unary' line (Worker 0 only)"
else
    fail "error.log: expected 1 'grpc smoke: firing' line, got ${FIRING_COUNT}.
       Relevant lines:
$(grep -aE 'grpc smoke|otel init_process' "${PREFIX}/logs/error.log" | head -10)"
fi

# 2. gRPC export completed successfully.
COMPLETE_COUNT=$(grep -c "grpc smoke: export complete" "${PREFIX}/logs/error.log" 2>/dev/null) || COMPLETE_COUNT=0
if [[ "${COMPLETE_COUNT}" -eq 1 ]]; then
    pass "error.log: exactly 1 'grpc smoke: export complete' line (Ok(()) reached)"
else
    fail "error.log: expected 1 'grpc smoke: export complete' line, got ${COMPLETE_COUNT}.
       Failure lines (if any):
$(grep -aE 'grpc smoke: export failed' "${PREFIX}/logs/error.log" | head -5)"
fi

# 3. No gRPC export failure lines.
FAILURE_COUNT=$(grep -c "grpc smoke: export failed" "${PREFIX}/logs/error.log" 2>/dev/null) || FAILURE_COUNT=0
if [[ "${FAILURE_COUNT}" -eq 0 ]]; then
    pass "error.log: zero 'grpc smoke: export failed' lines"
else
    fail "error.log: ${FAILURE_COUNT} 'grpc smoke: export failed' lines.
       Failure details:
$(grep -aE 'grpc smoke: export failed' "${PREFIX}/logs/error.log")"
fi

# 4. No worker crashes / panics / unexpected exits.
PANIC_COUNT=$(grep -cE "panicked|signal 11|signal 6|exited on signal" "${PREFIX}/logs/error.log" 2>/dev/null) || PANIC_COUNT=0
if [[ "${PANIC_COUNT}" -eq 0 ]]; then
    pass "error.log: no panic / SIGSEGV / SIGABRT / unexpected worker exit signals"
else
    fail "error.log: ${PANIC_COUNT} crash/panic-related lines:
$(grep -aE 'panicked|signal 11|signal 6|exited on signal' "${PREFIX}/logs/error.log" | head -10)"
fi

# 5. metrics.json delta contains the gRPC payload.
if echo "${NEW_CONTENT}" | grep -q "${SERVICE_NAME}"; then
    pass "metrics.json delta contains service.name = ${SERVICE_NAME} (collector received the gRPC payload)"
else
    fail "metrics.json delta does NOT contain '${SERVICE_NAME}'.
       New content (first 5 lines):
$(echo "${NEW_CONTENT}" | head -5)"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All assertions passed.  In-worker unary gRPC smoke COMPLETE."
    exit 0
else
    echo -e "${RED}One or more assertions FAILED.${NC}" >&2
    exit 2
fi
