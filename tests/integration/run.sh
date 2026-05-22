#!/usr/bin/env bash
# tests/integration/run.sh — Step 9 end-to-end integration test
#
# Builds the NGINX otel module, starts NGINX with worker_processes 4,
# sends HTTP traffic, waits for a metrics flush, then checks that:
#   1. metrics.json contains entries with service.name = ngx-otel-step9-integration
#   2. At least one histogram data point for http.server.request.duration arrived
#   3. error.log contains exactly one "spawning export task" line (Worker 0 only)
#
# Prerequisites
# ─────────────
# 1. The OTel collector container must be running:
#      docker compose -f ../../test-harness/docker-compose.yml ps
#    should show ngx-otel-test-collector as Up on 127.0.0.1:4318.
#
# 2. Required environment variables (or sensible defaults will be used):
#      NGINX_BINARY   — path to the nginx binary (default: auto-detected)
#      NGINX_SOURCE_DIR — nginx source tree (for cargo build)
#      NGINX_BUILD_DIR  — nginx build dir   (for cargo build)
#
# Running
# ───────
#   # From the ngx-otel-rust directory:
#   NGINX_SOURCE_DIR=../nginx \
#   NGINX_BUILD_DIR=../nginx/objs \
#   bash tests/integration/run.sh
#
# Exit codes
# ──────────
#   0  all assertions passed
#   1  a pre-flight or build check failed
#   2  a test assertion failed

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

NGINX_BINARY="${NGINX_BINARY:-${REPO_ROOT}/nginx/objs/nginx}"
METRICS_LOG="${REPO_ROOT}/test-harness/logs/metrics.json"
CONF_TEMPLATE="${SCRIPT_DIR}/nginx.conf"

# Detect module extension (macOS = .dylib, Linux = .so)
case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"

SERVICE_NAME="ngx-otel-step9-integration"
METRIC_INTERVAL_S=2          # must match nginx.conf otel_metric_interval
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 2 ))
N_REQUESTS=20

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ─── Pre-flight checks ───────────────────────────────────────────────────────

info "Pre-flight checks..."

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    echo "       Set NGINX_BINARY to the correct path." >&2
    exit 1
fi

if ! curl -s --connect-timeout 2 http://127.0.0.1:4318/ >/dev/null 2>&1; then
    echo "ERROR: OTel collector not reachable at 127.0.0.1:4318" >&2
    echo "       Start it with: docker compose -f ${REPO_ROOT}/test-harness/docker-compose.yml up -d" >&2
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

PREFIX="$(mktemp -d /tmp/ngx-otel-step9.XXXXXX)"
cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    echo ""
    echo "=== error.log (first 40 lines) ==="
    head -40 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    echo "..."
    echo "=== error.log (last 30 lines) ==="
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null
    info "Tearing down ${PREFIX}"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"
mkdir -p "${PREFIX}/client_body_temp"

# Substitute placeholders and write nginx.conf into the sandbox.
sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX}|g" \
    "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

info "Sandbox: ${PREFIX}"

# ─── Snapshot metrics.json BEFORE starting nginx ─────────────────────────────

PRE_SIZE=0
if [[ -f "${METRICS_LOG}" ]]; then
    PRE_SIZE=$(wc -c < "${METRICS_LOG}")
fi
info "metrics.json pre-size: ${PRE_SIZE} bytes"

# ─── Start NGINX ─────────────────────────────────────────────────────────────

info "Starting nginx (worker_processes 4)..."
# Note: error_log is already set in nginx.conf; do NOT pass -g "error_log ..."
# here as that would create a second log target and double every line, causing
# the "exactly 1 spawning export task" assertion to fail.
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!

# Give nginx time to fork workers and run init_process.
sleep 1

# Verify nginx is still running.
if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "ERROR: nginx exited immediately. Check ${PREFIX}/logs/error.log" >&2
    cat "${PREFIX}/logs/error.log" >&2
    exit 1
fi
info "nginx running (PID ${NGINX_PID})"

# ─── Send HTTP traffic ───────────────────────────────────────────────────────

info "Sending ${N_REQUESTS} requests to http://127.0.0.1:9100/..."
for i in $(seq 1 "${N_REQUESTS}"); do
    curl -sf http://127.0.0.1:9100/ >/dev/null
done
info "Traffic sent."

# ─── Wait for flush ──────────────────────────────────────────────────────────

info "Waiting ${FLUSH_WAIT_S}s for metrics flush (interval=${METRIC_INTERVAL_S}s)..."
sleep "${FLUSH_WAIT_S}"

# ─── Graceful shutdown ───────────────────────────────────────────────────────

info "Sending nginx -s quit (graceful drain)..."
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" \
    -s quit 2>/dev/null || true

# Wait for nginx to exit (up to 10s).
for i in $(seq 1 10); do
    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
        break
    fi
    sleep 1
done
# Ensure the PID is gone before we inspect logs.
NGINX_PID=""

# ─── Assertions ──────────────────────────────────────────────────────────────

info "Running assertions..."
FAILED=0

# Read new content appended since the pre-flight snapshot.
NEW_CONTENT=""
if [[ -f "${METRICS_LOG}" ]]; then
    POST_SIZE=$(wc -c < "${METRICS_LOG}")
    if (( POST_SIZE > PRE_SIZE )); then
        NEW_CONTENT=$(tail -c "+$(( PRE_SIZE + 1 ))" "${METRICS_LOG}")
    fi
fi

# 1. service.name in new metrics
if echo "${NEW_CONTENT}" | grep -q "${SERVICE_NAME}"; then
    pass "metrics.json contains service.name = ${SERVICE_NAME}"
else
    fail "metrics.json does NOT contain '${SERVICE_NAME}' in newly appended content.
       New content:
$(echo "${NEW_CONTENT}" | head -5)"
    FAILED=1
fi

# 2. histogram metric name present
if echo "${NEW_CONTENT}" | grep -q "http.server.request.duration"; then
    pass "metrics.json contains http.server.request.duration"
else
    fail "metrics.json does NOT contain 'http.server.request.duration' in new content."
    FAILED=1
fi

# 3. Exactly one "spawning export task" in error.log (Worker 0 only)
SPAWN_COUNT=$(grep -c "spawning export task" "${PREFIX}/logs/error.log" 2>/dev/null || echo 0)
if [[ "${SPAWN_COUNT}" -eq 1 ]]; then
    pass "error.log contains exactly 1 'spawning export task' line (Worker 0 only)"
else
    fail "error.log contains ${SPAWN_COUNT} 'spawning export task' lines (expected 1).
       Relevant lines:
$(grep "spawning export task\|init_process" "${PREFIX}/logs/error.log" | head -20)"
    FAILED=1
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All assertions passed. Step 9 end-to-end test COMPLETE."
    echo ""
    echo "  New metrics.json tail:"
    echo "${NEW_CONTENT}" | tail -3
    exit 0
else
    echo -e "${RED}One or more assertions FAILED.${NC}" >&2
    echo ""
    echo "Diagnostics:"
    echo "  nginx error.log:"
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null || echo "  (not found)"
    exit 2
fi
