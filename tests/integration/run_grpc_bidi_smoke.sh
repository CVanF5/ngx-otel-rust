#!/usr/bin/env bash
# tests/integration/run_grpc_bidi_smoke.sh — bidi gRPC viability harness.
#
# Builds the module with `--features test-support` so BOTH smoke directives'
# init_process triggers are compiled in.  Starts the bidi echo server
# (examples/bidi_echo_server.rs, 127.0.0.1:4319) then nginx with BOTH the
# unary and bidi directives set.  Worker 0 fires:
#   - one unary  OTLP/gRPC export (regression gate for unary path)
#   - one bidi   Echo.BidiEcho call against the echo server
#
# Assertions:
#   1. error.log contains exactly 1 "grpc smoke: firing one unary" line.
#   2. error.log contains exactly 1 "grpc smoke: export complete" line.
#   3. error.log contains zero "grpc smoke: export failed" lines.
#   4. error.log contains zero panic / SIGSEGV / worker-respawn signals.
#   5. metrics.json delta contains a payload with
#      service.name = "ngx-otel-grpc-smoke" (collector received gRPC payload).
#   6. error.log contains exactly 1 "bidi smoke: firing one bidi stream" line.
#   7. error.log contains exactly 1 "bidi smoke: bidi complete (sent=10, received=10)" line.
#   8. error.log contains zero "bidi smoke: bidi failed" lines.
#
# Prerequisites
# ─────────────
# - Docker available on PATH.  Collector auto-starts via test-harness/lib.sh.
# - NGINX source + build dirs as set up by the project README.
# - nc (netcat) available on PATH for port readiness checks.
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

# Pin NGINX_BINARY + NGINX_BUILD_DIR to the non-debug flavor.
# See run_grpc_smoke.sh for the ABI-mismatch rationale.
NGINX_BINARY="${NGINX_BINARY:-${REPO_ROOT}/nginx/objs/nginx}"
NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${REPO_ROOT}/nginx}"
NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${REPO_ROOT}/nginx/objs}"
export NGINX_SOURCE_DIR NGINX_BUILD_DIR

# Source the shared harness library.
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
BIDI_ENDPOINT="http://127.0.0.1:4319"
ECHO_PORT=4319

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }

FAILED=0
ECHO_PID=""
NGINX_PID=""

# ─── Pre-flight checks ───────────────────────────────────────────────────────

info "Pre-flight checks..."

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    exit 1
fi

ensure_collector_running || exit 1

# ─── Build the module WITH test-support feature ──────────────────────────────

info "Building release module with --features test-support..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" \
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" \
    cargo build --release --features test-support 2>&1
)
if [[ ! -f "${MODULE_PATH}" ]]; then
    echo "ERROR: module not found after build: ${MODULE_PATH}" >&2
    exit 1
fi
info "Module built: ${MODULE_PATH}"

# ─── Build the echo server example ───────────────────────────────────────────

# ECHO_BINARY env override: the TSAN gate pre-builds the example without
# TSAN flags (Tokio runtime is upstream code; TSAN findings there are
# noise, not module-under-test bugs) and sets ECHO_BINARY so this script
# uses it instead of rebuilding under the caller's RUSTFLAGS.  Default
# path follows MODULE_PATH's CARGO_BUILD_TARGET-aware shape.
if [[ -z "${ECHO_BINARY:-}" ]]; then
    info "Building bidi echo server example..."
    (
        cd "${CRATE_DIR}"
        NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" \
        NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" \
        cargo build --example bidi_echo_server 2>&1
    )
    if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
        ECHO_BINARY="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/debug/examples/bidi_echo_server"
    else
        ECHO_BINARY="${CRATE_DIR}/target/debug/examples/bidi_echo_server"
    fi
else
    info "Using ECHO_BINARY override: ${ECHO_BINARY}"
fi
if [[ ! -x "${ECHO_BINARY}" ]]; then
    echo "ERROR: bidi_echo_server binary not found at ${ECHO_BINARY}" >&2
    exit 1
fi
info "Echo server built: ${ECHO_BINARY}"

# ─── Sandbox prefix directory ────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-grpc-bidi-smoke.XXXXXX)"
cleanup() {
    # Kill the bidi echo server.
    [[ -n "${ECHO_PID:-}" ]] && kill "${ECHO_PID}" 2>/dev/null || true
    # Kill nginx.
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    echo ""
    echo "=== error.log: grpc/bidi/otel lines ==="
    grep -aE "grpc smoke|bidi smoke|otel init_process|otel export|panicked|signal [0-9]+|exited" \
        "${PREFIX}/logs/error.log" 2>/dev/null | head -50 || echo "(not found)"
    info "Echo server log:"
    cat "${PREFIX}/logs/echo_server.log" 2>/dev/null | head -10 || echo "(not found)"
    info "Tearing down ${PREFIX} (skipped if KEEP_SANDBOX=1)"
    [[ "${KEEP_SANDBOX:-0}" == "1" ]] || rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"
mkdir -p "${PREFIX}/client_body_temp"

# ─── Start the bidi echo server ──────────────────────────────────────────────

# Ensure no leftover process on the echo port before starting.
if nc -z 127.0.0.1 "${ECHO_PORT}" 2>/dev/null; then
    info "Port ${ECHO_PORT} already in use; attempting to clear..."
    lsof -ti :"${ECHO_PORT}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 0.5
fi

info "Launching bidi echo server on 127.0.0.1:${ECHO_PORT}..."
BIDI_ECHO_BIND="127.0.0.1:${ECHO_PORT}" \
    "${ECHO_BINARY}" >"${PREFIX}/logs/echo_server.log" 2>&1 &
ECHO_PID=$!

# Wait for the echo server to bind (up to 4 seconds).
ECHO_READY=0
for _ in $(seq 1 20); do
    if nc -z 127.0.0.1 "${ECHO_PORT}" 2>/dev/null; then
        ECHO_READY=1
        break
    fi
    sleep 0.2
done
if [[ "${ECHO_READY}" -eq 0 ]]; then
    echo "ERROR: bidi echo server did not bind to port ${ECHO_PORT}" >&2
    exit 1
fi
info "Echo server listening (PID ${ECHO_PID})"

# ─── Write nginx config ───────────────────────────────────────────────────────

# Port 9104 chosen to avoid collision with:
#   run.sh (9100), run_reload.sh (9101), run_endpoint_change.sh (9102),
#   run_grpc_smoke.sh (9103).
cat > "${PREFIX}/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 1;
# Prevent hanging async tasks from blocking clean shutdown.
worker_shutdown_timeout 3s;
error_log ${PREFIX}/logs/error.log debug;
pid       ${PREFIX}/logs/nginx.pid;

load_module ${MODULE_PATH};

events {
    worker_connections 64;
}

http {
    # OTLP/HTTP exporter — keeps is_configured() gate open.
    # Long interval so it doesn't fire during the test window.
    otel_exporter {
        endpoint http://127.0.0.1:4318;
    }
    otel_service_name ngx-otel-grpc-bidi-smoke-http;
    otel_metric_interval 60s;

    # Unary gRPC smoke (regression gate): unary OTLP/gRPC export.
    otel_grpc_smoke_endpoint ${GRPC_ENDPOINT};

    # Bidi gRPC smoke: Echo.BidiEcho call against local echo server.
    otel_grpc_bidi_smoke_endpoint ${BIDI_ENDPOINT};

    server {
        listen 127.0.0.1:9104;
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

info "Starting nginx (1 worker, both smoke directives set)..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!

sleep 1

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    fail "nginx exited unexpectedly during startup"
    exit 2
fi
info "nginx running (PID ${NGINX_PID})"

# ─── Wait for both smoke calls to complete ───────────────────────────────────

info "Waiting up to 10s for both smoke calls to complete..."
DEADLINE=$(( SECONDS + 10 ))
while (( SECONDS < DEADLINE )); do
    UNARY_DONE=$(grep -ac "grpc smoke: export \(complete\|failed\)" "${PREFIX}/logs/error.log" 2>/dev/null || true)
    BIDI_DONE=$(grep -ac "bidi smoke: bidi \(complete\|bidi failed\)" "${PREFIX}/logs/error.log" 2>/dev/null || true)
    if [[ "${UNARY_DONE}" -ge 1 ]] && [[ "${BIDI_DONE}" -ge 1 ]]; then
        break
    fi
    sleep 0.2
done

# ─── Graceful shutdown ───────────────────────────────────────────────────────

info "Sending nginx -s quit..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" -s quit 2>/dev/null || true

# Wait for nginx to exit cleanly (up to 7.5 seconds).
for _ in $(seq 1 15); do
    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
        break
    fi
    sleep 0.5
done
NGINX_PID=""

# Stop the echo server.
[[ -n "${ECHO_PID:-}" ]] && kill "${ECHO_PID}" 2>/dev/null || true
ECHO_PID=""

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

# 1. Unary smoke trigger fired exactly once (regression gate: init-process unary path fires on startup).
FIRING_COUNT=$(grep -c "grpc smoke: firing one unary" "${PREFIX}/logs/error.log" 2>/dev/null) || FIRING_COUNT=0
if [[ "${FIRING_COUNT}" -eq 1 ]]; then
    pass "error.log: exactly 1 'grpc smoke: firing one unary' line"
else
    fail "error.log: expected 1 'grpc smoke: firing one unary' line, got ${FIRING_COUNT}.
       Relevant lines:
$(grep -aE 'grpc smoke|otel init_process' "${PREFIX}/logs/error.log" | head -10)"
fi

# 2. Unary gRPC export completed successfully.
COMPLETE_COUNT=$(grep -c "grpc smoke: export complete" "${PREFIX}/logs/error.log" 2>/dev/null) || COMPLETE_COUNT=0
if [[ "${COMPLETE_COUNT}" -eq 1 ]]; then
    pass "error.log: exactly 1 'grpc smoke: export complete' line"
else
    fail "error.log: expected 1 'grpc smoke: export complete' line, got ${COMPLETE_COUNT}.
       Failure lines (if any):
$(grep -aE 'grpc smoke: export failed' "${PREFIX}/logs/error.log" | head -5)"
fi

# 3. No unary gRPC export failure lines.
UNARY_FAIL=$(grep -c "grpc smoke: export failed" "${PREFIX}/logs/error.log" 2>/dev/null) || UNARY_FAIL=0
if [[ "${UNARY_FAIL}" -eq 0 ]]; then
    pass "error.log: zero 'grpc smoke: export failed' lines"
else
    fail "error.log: ${UNARY_FAIL} 'grpc smoke: export failed' lines:
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

# 5. metrics.json delta contains the unary gRPC payload (collector received it).
if echo "${NEW_CONTENT}" | grep -q "${SERVICE_NAME}"; then
    pass "metrics.json delta contains service.name = ${SERVICE_NAME}"
else
    fail "metrics.json delta does NOT contain '${SERVICE_NAME}'.
       New content (first 5 lines):
$(echo "${NEW_CONTENT}" | head -5)"
fi

# 6. Bidi smoke trigger fired exactly once.
BIDI_FIRING=$(grep -c "bidi smoke: firing one bidi stream" "${PREFIX}/logs/error.log" 2>/dev/null) || BIDI_FIRING=0
if [[ "${BIDI_FIRING}" -eq 1 ]]; then
    pass "error.log: exactly 1 'bidi smoke: firing one bidi stream' line"
else
    fail "error.log: expected 1 'bidi smoke: firing one bidi stream' line, got ${BIDI_FIRING}.
       Relevant lines:
$(grep -aE 'bidi smoke' "${PREFIX}/logs/error.log" | head -10)"
fi

# 7. Bidi smoke completed successfully with the exact counts.
BIDI_COMPLETE=$(grep -c "bidi smoke: bidi complete (sent=10, received=10)" "${PREFIX}/logs/error.log" 2>/dev/null) || BIDI_COMPLETE=0
if [[ "${BIDI_COMPLETE}" -eq 1 ]]; then
    pass "error.log: exactly 1 'bidi smoke: bidi complete (sent=10, received=10)' line"
else
    fail "error.log: expected 1 'bidi complete' line, got ${BIDI_COMPLETE}.
       Bidi lines:
$(grep -aE 'bidi smoke' "${PREFIX}/logs/error.log" | head -10)"
fi

# 8. No bidi smoke failure lines.
BIDI_FAIL=$(grep -c "bidi smoke: bidi failed" "${PREFIX}/logs/error.log" 2>/dev/null) || BIDI_FAIL=0
if [[ "${BIDI_FAIL}" -eq 0 ]]; then
    pass "error.log: zero 'bidi smoke: bidi failed' lines"
else
    fail "error.log: ${BIDI_FAIL} 'bidi smoke: bidi failed' lines:
$(grep -aE 'bidi smoke: bidi failed' "${PREFIX}/logs/error.log")"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All 8 assertions passed.  Bidi gRPC smoke COMPLETE."
    exit 0
else
    echo -e "${RED}One or more assertions FAILED.${NC}" >&2
    exit 2
fi
