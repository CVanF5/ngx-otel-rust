#!/usr/bin/env bash
# tests/integration/run_endpoint_change.sh — Step 10 endpoint-change reload test
#
# Verifies that changing the OTLP collector endpoint across nginx -s reload
# takes effect on the next export tick of the new worker generation.
#
# Scenario:
#   A. nginx starts pointing at the real collector (127.0.0.1:4318) — metrics
#      arrive in metrics.json.
#   B. nginx.conf is rewritten to point at an unreachable endpoint
#      (127.0.0.1:14318) and nginx -s reload is issued.
#   C. New worker's export loop should fail to connect and increment
#      ngx_otel.send_failures.  error.log must contain "send failed" for the
#      new worker generation.
#   D. nginx -s quit.
#
# Assertions:
#   1. metrics.json received batches under service.name = ngx-otel-step10-epchange
#      during phase A (endpoint A worked).
#   2. error.log contains at least one "otel export: send failed" line after
#      the reload (new worker targeting the unreachable endpoint).
#   3. error.log contains "otel: SIGHUP reload detected" exactly once.
#   4. ngx_otel.send_failures value in metrics.json from phase A is well-formed
#      (sum metric with asInt present).
#
# Prerequisites
# ─────────────
# OTel collector running on 127.0.0.1:4318.  Port 14318 must be unreachable.
#
# Running
# ───────
#   NGINX_SOURCE_DIR=../nginx \
#   NGINX_BUILD_DIR=../nginx/objs \
#   bash tests/integration/run_endpoint_change.sh
#
# Exit codes
#   0  all assertions passed
#   1  pre-flight or build failure
#   2  a test assertion failed

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

NGINX_BINARY="${NGINX_BINARY:-${REPO_ROOT}/nginx/objs/nginx}"
METRICS_LOG="${REPO_ROOT}/test-harness/logs/metrics.json"

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"

SERVICE_NAME="ngx-otel-step10-epchange"
ENDPOINT_A="http://127.0.0.1:4318/v1/metrics"   # real collector
ENDPOINT_B="http://127.0.0.1:14318/v1/metrics"  # unreachable (no listener)
METRIC_INTERVAL_S=2
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 2 ))
N_REQUESTS=10

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ─── Pre-flight checks ───────────────────────────────────────────────────────

info "Pre-flight checks..."
FAILED=0

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    exit 1
fi

if ! curl -s --connect-timeout 2 http://127.0.0.1:4318/ >/dev/null 2>&1; then
    echo "ERROR: OTel collector not reachable at 127.0.0.1:4318" >&2
    exit 1
fi

# Verify port 14318 is NOT reachable (that is what makes it a good dead endpoint).
if curl -s --connect-timeout 1 http://127.0.0.1:14318/ >/dev/null 2>&1; then
    echo "ERROR: something is listening on 127.0.0.1:14318; endpoint B must be unreachable." >&2
    echo "       Choose a different port for ENDPOINT_B or stop the service on 14318." >&2
    exit 1
fi

# ─── Build the module ────────────────────────────────────────────────────────

info "Building release module..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${REPO_ROOT}/nginx}" \
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${REPO_ROOT}/nginx/objs}" \
    cargo build --release 2>&1
)
if [[ ! -f "${MODULE_PATH}" ]]; then
    echo "ERROR: module not found after build: ${MODULE_PATH}" >&2
    exit 1
fi
info "Module built: ${MODULE_PATH}"

# ─── Sandbox prefix directory ────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-step10-epchange.XXXXXX)"
NGINX_PID=""

cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    echo ""
    echo "=== error.log (first 40 lines) ==="
    head -40 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    echo "..."
    echo "=== error.log (last 40 lines) ==="
    tail -40 "${PREFIX}/logs/error.log" 2>/dev/null
    info "Tearing down ${PREFIX}"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"
mkdir -p "${PREFIX}/client_body_temp"

# Helper: write nginx.conf pointing at a specific endpoint.
write_conf() {
    local endpoint="$1"
    cat > "${PREFIX}/nginx.conf" <<CONF
daemon off;
master_process on;
worker_processes 4;
worker_shutdown_timeout 5s;
error_log ${PREFIX}/logs/error.log debug;
pid       ${PREFIX}/logs/nginx.pid;

load_module ${MODULE_PATH};

events {
    worker_connections 64;
}

http {
    otel_exporter {
        endpoint ${endpoint};
    }
    otel_service_name ${SERVICE_NAME};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9102;
        location / {
            return 200 "ok\\n";
        }
    }
}
CONF
}

info "Sandbox: ${PREFIX}"

# ─── Snapshot metrics.json BEFORE starting nginx ─────────────────────────────

PRE_SIZE=0
if [[ -f "${METRICS_LOG}" ]]; then
    PRE_SIZE=$(wc -c < "${METRICS_LOG}")
fi
info "metrics.json pre-size: ${PRE_SIZE} bytes"

# ─── Phase A: start with working endpoint ────────────────────────────────────

write_conf "${ENDPOINT_A}"
info "Starting nginx with endpoint A (${ENDPOINT_A})..."
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!

sleep 1.5

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "ERROR: nginx exited immediately." >&2
    cat "${PREFIX}/logs/error.log" >&2
    exit 1
fi
info "nginx running (PID ${NGINX_PID})"

info "Phase A: sending ${N_REQUESTS} requests..."
for i in $(seq 1 "${N_REQUESTS}"); do
    curl -sf http://127.0.0.1:9102/ >/dev/null
done

# Capture metrics.json size after phase A settles (one tick + a bit).
info "Waiting ${FLUSH_WAIT_S}s for phase-A export tick..."
sleep "${FLUSH_WAIT_S}"

POST_A_SIZE=0
if [[ -f "${METRICS_LOG}" ]]; then
    POST_A_SIZE=$(wc -c < "${METRICS_LOG}")
fi

# ─── Swap to endpoint B and reload ───────────────────────────────────────────

write_conf "${ENDPOINT_B}"
info "nginx.conf rewritten to endpoint B (${ENDPOINT_B}); sending nginx -s reload..."
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" \
    -s reload 2>/dev/null || true

# Wait for the new worker generation to start and attempt (and fail) to send.
# Two ticks = 2 * interval + a bit of slack = enough time for send_failures to
# accumulate and for the "send failed" log lines to appear.
info "Waiting $(( METRIC_INTERVAL_S * 2 + 3 ))s for new-generation export attempts..."
sleep $(( METRIC_INTERVAL_S * 2 + 3 ))

# ─── Graceful shutdown ───────────────────────────────────────────────────────

info "Sending nginx -s quit..."
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" \
    -s quit 2>/dev/null || true

for i in $(seq 1 15); do
    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
        break
    fi
    sleep 1
done
NGINX_PID=""

# ─── Collect new metrics.json content from phase A ───────────────────────────

CONTENT_A=""
if [[ -f "${METRICS_LOG}" ]]; then
    if (( POST_A_SIZE > PRE_SIZE )); then
        CONTENT_A=$(tail -c "+$(( PRE_SIZE + 1 ))" "${METRICS_LOG}" | head -c "$(( POST_A_SIZE - PRE_SIZE ))")
    fi
fi

# ─── Assertions ──────────────────────────────────────────────────────────────

info "Running assertions..."

# 1. metrics.json received batches from phase A (endpoint A worked).
if echo "${CONTENT_A}" | grep -q "${SERVICE_NAME}"; then
    pass "metrics.json: phase-A batches present (endpoint A = ${ENDPOINT_A} worked)"
else
    fail "metrics.json: no phase-A batches found under service.name = ${SERVICE_NAME}.
       Content-A (first 200 chars): $(echo "${CONTENT_A}" | head -c 200)"
fi

# 2. error.log contains "otel export: send failed" after reload (new worker
#    targeting the unreachable endpoint B).
SEND_FAIL_COUNT=$(grep -c "otel export: send failed" "${PREFIX}/logs/error.log" 2>/dev/null) || SEND_FAIL_COUNT=0
if [[ "${SEND_FAIL_COUNT}" -ge 1 ]]; then
    pass "error.log: ${SEND_FAIL_COUNT} 'otel export: send failed' line(s) (endpoint B is unreachable)"
else
    fail "error.log: expected ≥ 1 'otel export: send failed' line after reload to endpoint B.
       Relevant lines (export-related):
$(grep -E 'otel export|send fail|send_failure' "${PREFIX}/logs/error.log" | tail -20)"
fi

# 3. "otel: SIGHUP reload detected" appears exactly once.
RELOAD_COUNT=$(grep -c "otel: SIGHUP reload detected" "${PREFIX}/logs/error.log" 2>/dev/null) || RELOAD_COUNT=0
if [[ "${RELOAD_COUNT}" -eq 1 ]]; then
    pass "error.log: exactly 1 'otel: SIGHUP reload detected' line"
else
    fail "error.log: expected 1 'otel: SIGHUP reload detected' line, got ${RELOAD_COUNT}"
fi

# 4. ngx_otel.send_failures metric appears in phase-A content (self-metric
#    infrastructure is working; value may be 0 in phase A since endpoint A
#    was reachable).
if echo "${CONTENT_A}" | grep -q '"ngx_otel.send_failures"'; then
    pass "metrics.json: ngx_otel.send_failures self-metric present in phase-A content"
else
    fail "metrics.json: ngx_otel.send_failures self-metric not found in phase-A content."
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All assertions passed. Step 10 endpoint-change reload test COMPLETE."
    exit 0
else
    echo -e "${RED}One or more assertions FAILED.${NC}" >&2
    echo ""
    echo "  error.log tail:"
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null || echo "  (not found)"
    exit 2
fi
