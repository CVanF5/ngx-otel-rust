#!/usr/bin/env bash
# tests/integration/run_reload.sh — SIGHUP reload integration test
#
# The otel exporter process (not Worker 0) owns the export task.
#
# Sends a SIGHUP to nginx, verifies a clean exporter-generation transition, and
# asserts that:
#   1. Exactly 2 "export loop started" lines appear in error.log
#      (one per exporter generation across the reload cycle).
#   2. At least 2 "graceful drain complete" lines appear (the exporter is not a worker
#      and is not subject to ngx_event_no_timers_left, so drain fires reliably on quit).
#   3. "otel: SIGHUP reload detected" appears exactly once (from
#      MainConfig::postconfiguration in the master on reload).
#   4. metrics.json shows service.name from the new exporter in new content.
#   5. metrics.json shows ≥ 2 unique startTimeUnixNano values for
#      ngx_otel.dropped_records (start_time advances on each new exporter
#      generation; start_time_unix_nano advances when a new exporter generation starts).
#   6. For every ngx_otel.dropped_records data point, timeUnixNano >=
#      startTimeUnixNano (cumulative semantics are honest across reload;
#      a backend computing rates by diffing same-stream samples will not
#      see a spurious decrement when exporter generations rotate).
#
# Prerequisites
# ─────────────
# 1. The OTel collector container must be running:
#      docker compose -f ../../test-harness/docker-compose.yml ps
#    should show ngx-otel-test-collector as Up on 127.0.0.1:4318.
# 2. jq must be installed.
# 3. NGINX_BINARY / NGINX_SOURCE_DIR / NGINX_BUILD_DIR env vars or defaults.
#
# Running
# ───────
#   NGINX_SOURCE_DIR=../nginx \
#   NGINX_BUILD_DIR=../nginx/objs \
#   bash tests/integration/run_reload.sh
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

# Source the shared harness library.  Sets HARNESS_DIR, METRICS_LOG,
# COLLECTOR_HTTP_ENDPOINT, and exposes ensure_collector_running and
# resolve_nginx_binary.
. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true   # missing-binary error is produced by the preflight below

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
# When CARGO_BUILD_TARGET is set (e.g., the TSAN gate uses --target so cargo
# can also -Zbuild-std), cargo writes its output to target/<triple>/release/
# rather than target/release/.  Backwards-compatible: unset -> original path.
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi

SERVICE_NAME="ngx-otel-step10-reload"
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

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    echo "       Set NGINX_BINARY to the correct path." >&2
    exit 1
fi

ensure_collector_running || exit 1

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required for metrics.json assertions." >&2
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

PREFIX="$(mktemp -d /tmp/ngx-otel-step10-reload.XXXXXX)"
NGINX_PID=""
FAILED=0

cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    echo ""
    echo "=== error.log (first 50 lines) ==="
    head -50 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    echo "..."
    echo "=== error.log (last 40 lines) ==="
    tail -40 "${PREFIX}/logs/error.log" 2>/dev/null
    info "Tearing down ${PREFIX}"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"
mkdir -p "${PREFIX}/client_body_temp"

# Write nginx.conf for the reload test.
# worker_shutdown_timeout ensures old workers don't linger past 5s on macOS
# where keepalive connections might otherwise hold them open indefinitely.
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
        endpoint http://127.0.0.1:4318;
    }
    otel_service_name ${SERVICE_NAME};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9101;
        location / {
            return 200 "ok\\n";
        }
    }
}
CONF

info "Sandbox: ${PREFIX}"

# ─── Snapshot metrics.json BEFORE starting nginx ─────────────────────────────

PRE_SIZE=0
if [[ -f "${METRICS_LOG}" ]]; then
    PRE_SIZE=$(wc -c < "${METRICS_LOG}")
fi
info "metrics.json pre-size: ${PRE_SIZE} bytes"

# ─── Start NGINX (generation 1) ──────────────────────────────────────────────

info "Starting nginx (worker_processes 4)..."
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!

# Give nginx time to fork workers and run init_process.
sleep 1.5

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "ERROR: nginx exited immediately. Check ${PREFIX}/logs/error.log" >&2
    cat "${PREFIX}/logs/error.log" >&2
    exit 1
fi
info "nginx running (PID ${NGINX_PID})"

# ─── Phase 1: send traffic, wait for first export tick ───────────────────────

info "Phase 1: sending ${N_REQUESTS} requests (generation 1)..."
for i in $(seq 1 "${N_REQUESTS}"); do
    curl -sf http://127.0.0.1:9101/ >/dev/null
done

info "Waiting ${FLUSH_WAIT_S}s for generation-1 export tick..."
sleep "${FLUSH_WAIT_S}"

# ─── Reload (send SIGHUP via nginx -s reload) ─────────────────────────────────

info "Sending nginx -s reload..."
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" \
    -s reload 2>/dev/null || true

# Wait for the old workers to drain and exit, and new workers to start.
# worker_shutdown_timeout 5s is the backstop; in practice this takes ~1-2s.
info "Waiting 5s for old workers to exit and new generation to stabilise..."
sleep 5

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "ERROR: nginx master exited after reload. Check ${PREFIX}/logs/error.log" >&2
    cat "${PREFIX}/logs/error.log" >&2
    exit 1
fi
info "nginx still running after reload (PID ${NGINX_PID})"

# ─── Phase 2: send traffic, wait for post-reload export tick ─────────────────

info "Phase 2: sending ${N_REQUESTS} requests (generation 2)..."
for i in $(seq 1 "${N_REQUESTS}"); do
    curl -sf http://127.0.0.1:9101/ >/dev/null
done

info "Waiting ${FLUSH_WAIT_S}s for generation-2 export tick..."
sleep "${FLUSH_WAIT_S}"

# ─── Graceful shutdown ───────────────────────────────────────────────────────

info "Sending nginx -s quit (graceful shutdown)..."
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" \
    -s quit 2>/dev/null || true

# Wait for nginx to exit (up to 15s; worker_shutdown_timeout provides the backstop).
for i in $(seq 1 15); do
    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
        break
    fi
    sleep 1
done
NGINX_PID=""

# Give the OTel collector time to flush its batch (batch.timeout: 1s) and for
# the exit_process sync flush batches to arrive and be written to metrics.json.
sleep 3

# ─── Collect new metrics.json content ────────────────────────────────────────

NEW_CONTENT=""
if [[ -f "${METRICS_LOG}" ]]; then
    POST_SIZE=$(wc -c < "${METRICS_LOG}")
    if (( POST_SIZE > PRE_SIZE )); then
        NEW_CONTENT=$(tail -c "+$(( PRE_SIZE + 1 ))" "${METRICS_LOG}")
    fi
fi

# ─── Assertions ──────────────────────────────────────────────────────────────

info "Running assertions..."

# 1. Exactly 2 "export loop started" lines (one per exporter generation).
# The export task runs in the otel exporter process, not Worker 0.
# One exporter per nginx generation → 2 export loop starts across a reload cycle.
SPAWN_COUNT=$(grep -c "export loop started" "${PREFIX}/logs/error.log" 2>/dev/null) || SPAWN_COUNT=0
if [[ "${SPAWN_COUNT}" -eq 2 ]]; then
    pass "error.log: exactly 2 'export loop started' lines (one per exporter generation)"
else
    fail "error.log: expected 2 'export loop started' lines, got ${SPAWN_COUNT}.
       Relevant lines:
$(grep 'export loop started\|otel exporter\|otel export' "${PREFIX}/logs/error.log" | head -20)"
fi

# 2. At least 2 "graceful drain complete" lines.
# Each exporter runs a graceful drain on ngx_quit (the exporter is not subject to
# ngx_event_no_timers_left so drain fires reliably).
# Drain complete from generation-1 exporter (SIGHUP quit) + generation-2 (final quit).
FLUSH_COUNT=$(grep -c "graceful drain complete" "${PREFIX}/logs/error.log" 2>/dev/null) || FLUSH_COUNT=0
if [[ "${FLUSH_COUNT}" -ge 2 ]]; then
    pass "error.log: ${FLUSH_COUNT} 'graceful drain complete' lines (≥ 2 expected)"
else
    fail "error.log: expected ≥ 2 'graceful drain complete' lines, got ${FLUSH_COUNT}.
       Note: the exporter is not subject to ngx_event_no_timers_left; drain fires reliably.
       Relevant lines:
$(grep 'graceful drain\|ngx_quit' "${PREFIX}/logs/error.log" | head -20)"
fi

# 3. "otel: SIGHUP reload detected" appears exactly once.
# This comes from MainConfig::postconfiguration (run in master on reload).
RELOAD_COUNT=$(grep -c "otel: SIGHUP reload detected" "${PREFIX}/logs/error.log" 2>/dev/null) || RELOAD_COUNT=0
if [[ "${RELOAD_COUNT}" -eq 1 ]]; then
    pass "error.log: exactly 1 'otel: SIGHUP reload detected' line"
else
    fail "error.log: expected 1 'otel: SIGHUP reload detected' line, got ${RELOAD_COUNT}.
       Relevant lines:
$(grep 'SIGHUP\|reload detected' "${PREFIX}/logs/error.log" | head -10)"
fi

# 4. metrics.json: service.name appears in new content.
# Note: grep -q (used historically) can fail with set -o pipefail on large
# NEW_CONTENT (SIGPIPE from echo when grep exits early after the first match).
# grep -c reads all stdin so the pipe drains cleanly.
SVC_COUNT=$(echo "${NEW_CONTENT}" | grep -c "${SERVICE_NAME}" 2>/dev/null || echo 0)
if [[ "${SVC_COUNT:-0}" -ge 1 ]]; then
    pass "metrics.json: service.name = ${SERVICE_NAME} present (${SVC_COUNT} lines)"
else
    fail "metrics.json: service.name '${SERVICE_NAME}' not found in new content."
fi

# 5. metrics.json: ≥ 2 unique startTimeUnixNano values for ngx_otel.dropped_records.
# Each worker generation starts with a fresh WORKER_START_NS, so the
# startTimeUnixNano advances on each reload.
UNIQUE_STARTS=$(echo "${NEW_CONTENT}" | \
    jq -r '.resourceMetrics[].scopeMetrics[].metrics[] |
           select(.name == "ngx_otel.dropped_records") |
           .sum.dataPoints[].startTimeUnixNano' 2>/dev/null | \
    sort -u | wc -l | tr -d ' ')
if [[ "${UNIQUE_STARTS:-0}" -ge 2 ]]; then
    pass "metrics.json: ${UNIQUE_STARTS} unique startTimeUnixNano values for ngx_otel.dropped_records (≥ 2 expected)"
else
    fail "metrics.json: expected ≥ 2 unique startTimeUnixNano values for ngx_otel.dropped_records, got ${UNIQUE_STARTS:-0}.
       New content (first 2 lines):
$(echo "${NEW_CONTENT}" | head -2 | cut -c1-200)"
fi

# 6. For every ngx_otel.dropped_records data point, time_unix_nano >= start_time_unix_nano.
#
# NOTE: Cumulative semantics across reload are honest. Backends that compute
# rates by diffing same-stream samples will not see a spurious decrement when
# worker generations rotate, because start_time_unix_nano advances on the new
# worker generation while time_unix_nano is always >= start_time_unix_nano.
BAD_POINTS=$(echo "${NEW_CONTENT}" | \
    jq -r '.resourceMetrics[].scopeMetrics[].metrics[] |
           select(.name == "ngx_otel.dropped_records") |
           .sum.dataPoints[] |
           select(.timeUnixNano < .startTimeUnixNano) |
           "BAD: start=\(.startTimeUnixNano) time=\(.timeUnixNano)"' 2>/dev/null | \
    wc -l | tr -d ' ')
if [[ "${BAD_POINTS:-0}" -eq 0 ]]; then
    pass "metrics.json: all ngx_otel.dropped_records data points have timeUnixNano >= startTimeUnixNano"
else
    fail "metrics.json: ${BAD_POINTS} ngx_otel.dropped_records data point(s) with timeUnixNano < startTimeUnixNano (cumulative semantics violated).
$(echo "${NEW_CONTENT}" | \
    jq -r '.resourceMetrics[].scopeMetrics[].metrics[] |
           select(.name == "ngx_otel.dropped_records") |
           .sum.dataPoints[] |
           select(.timeUnixNano < .startTimeUnixNano) |
           "  start=\(.startTimeUnixNano) time=\(.timeUnixNano)"' 2>/dev/null | head -5)"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All assertions passed. SIGHUP reload test COMPLETE."
    echo ""
    echo "  New metrics.json tail (last 2 lines):"
    echo "${NEW_CONTENT}" | tail -2 | cut -c1-120
    exit 0
else
    echo -e "${RED}One or more assertions FAILED.${NC}" >&2
    echo ""
    echo "  error.log tail:"
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null || echo "  (not found)"
    exit 2
fi
